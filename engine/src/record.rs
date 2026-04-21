// SPDX-License-Identifier: Apache-2.0
// event recording and replay.
//
// wire format (little-endian):
//   [0..8]   magic 0x4D454D5649535243
//   [8..12]  proto_version u32
//   [12..20] event_count u64 (backpatched on close)
//   [20..24] reserved u32
//   [24..]   packed events, 32 bytes each:
//            addr:u64 size:u32 tid:u16 seq:u16 value:u64 kind_flags:u32 rip_lo:u32

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::ring::Event;

const RECORD_MAGIC: u64 = 0x4D454D5649535243;
const PROTO_VERSION: u32 = 3;
const HEADER_SIZE: u64 = 24;

pub struct EventRecorder {
    writer: BufWriter<File>,
    count: u64,
}

impl EventRecorder {
    pub fn create(path: &Path) -> io::Result<Self> {
        let file = File::create(path)?;
        let mut writer = BufWriter::with_capacity(256 * 1024, file);
        writer.write_all(&RECORD_MAGIC.to_le_bytes())?;
        writer.write_all(&PROTO_VERSION.to_le_bytes())?;
        writer.write_all(&0u64.to_le_bytes())?;
        writer.write_all(&0u32.to_le_bytes())?;
        Ok(Self { writer, count: 0 })
    }

    pub fn record(&mut self, ev: &Event) -> io::Result<()> {
        self.writer.write_all(&ev.addr.to_le_bytes())?;
        self.writer.write_all(&ev.size.to_le_bytes())?;
        self.writer.write_all(&ev.thread_id.to_le_bytes())?;
        self.writer.write_all(&ev.seq.to_le_bytes())?;
        self.writer.write_all(&ev.value.to_le_bytes())?;
        self.writer.write_all(&ev.kind_flags.to_le_bytes())?;
        self.writer.write_all(&ev.rip_lo.to_le_bytes())?;
        self.count += 1;
        Ok(())
    }

    // header + 6 continuation events carrying 18 registers (3 per cont event).
    pub fn record_reg_snapshot(&mut self, header: &Event, regs: &[u64; 18]) -> io::Result<()> {
        self.record(header)?;
        for i in 0..6usize {
            let cont = Event {
                addr: regs[i * 3],
                size: regs[i * 3 + 1] as u32,
                thread_id: header.thread_id,
                seq: header.seq,
                value: regs[i * 3 + 2],
                kind_flags: header.kind_flags,
                rip_lo: 0,
            };
            self.record(&cont)?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<u64> {
        self.writer.flush()?;
        let file = self.writer.into_inner()?;
        let mut file = file;
        file.seek(SeekFrom::Start(12))?;
        file.write_all(&self.count.to_le_bytes())?;
        file.flush()?;
        Ok(self.count)
    }
}

pub struct EventPlayer {
    reader: BufReader<File>,
    remaining: u64,
}

const DISK_EVENT_SIZE: usize = 32;

impl EventPlayer {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::with_capacity(256 * 1024, file);

        let mut hdr = [0u8; HEADER_SIZE as usize];
        reader.read_exact(&mut hdr)?;

        let magic = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
        if magic != RECORD_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "bad recording magic: expected 0x{:X}, got 0x{:X}",
                    RECORD_MAGIC, magic
                ),
            ));
        }
        let proto = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        if proto != PROTO_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "proto version mismatch: expected {}, got {}",
                    PROTO_VERSION, proto
                ),
            ));
        }
        let count = u64::from_le_bytes(hdr[12..20].try_into().unwrap());

        Ok(Self {
            reader,
            remaining: count,
        })
    }

    pub fn event_count(&self) -> u64 {
        self.remaining
    }

    pub fn next_event(&mut self) -> io::Result<Option<Event>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let mut buf = [0u8; DISK_EVENT_SIZE];
        match self.reader.read_exact(&mut buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        self.remaining -= 1;
        Ok(Some(Event {
            addr: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            size: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            thread_id: u16::from_le_bytes(buf[12..14].try_into().unwrap()),
            seq: u16::from_le_bytes(buf[14..16].try_into().unwrap()),
            value: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            kind_flags: u32::from_le_bytes(buf[24..28].try_into().unwrap()),
            rip_lo: u32::from_le_bytes(buf[28..32].try_into().unwrap()),
        }))
    }

    pub fn read_batch(&mut self, buf: &mut Vec<Event>, max: usize) -> io::Result<usize> {
        let mut count = 0;
        for _ in 0..max {
            match self.next_event()? {
                Some(ev) => {
                    buf.push(ev);
                    count += 1;
                }
                None => break,
            }
        }
        Ok(count)
    }
}
