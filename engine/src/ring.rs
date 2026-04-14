// SPDX-License-Identifier: MIT
// multi-ring orchestrator. control shm discovery, N-way merge.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::{mem, ptr};

pub const CACHE_LINE: usize = 64;
pub const MEMVIS_MAGIC: u64 = 0x4D454D56495342;
pub const MEMVIS_CTL_MAGIC: u64 = 0x4D56435430303032;
pub const MEMVIS_PROTO_VERSION: u32 = 3;
pub const MAX_THREADS: usize = 256;
pub const RING_NAME_LEN: usize = 48;

#[derive(Clone, Copy)]
#[repr(C, align(32))]
pub struct Event {
    pub addr: u64,
    pub size: u32,
    pub thread_id: u16,
    pub seq: u16,
    pub value: u64,
    pub kind_flags: u64,
}
const _: () = assert!(mem::size_of::<Event>() == 32);

impl Event {
    #[inline(always)]
    pub fn kind(&self) -> u8 {
        (self.kind_flags & 0xFF) as u8
    }

    pub fn zero() -> Self {
        Self {
            addr: 0,
            size: 0,
            thread_id: 0,
            seq: 0,
            value: 0,
            kind_flags: 0,
        }
    }
}

#[repr(C)]
pub struct RingHeader {
    pub magic: u64,
    pub capacity: u32,
    pub entry_size: u32,
    pub flags: u64,
    pub backpressure: AtomicU32,
    pub proto_version: u32,
    _pad0: [u8; CACHE_LINE - 28 - mem::size_of::<AtomicU32>()],
    pub head: AtomicU64,
    _pad1: [u8; CACHE_LINE - mem::size_of::<AtomicU64>()],
    pub tail: AtomicU64,
    _pad2: [u8; CACHE_LINE - mem::size_of::<AtomicU64>()],
}
const _: () = assert!(mem::size_of::<RingHeader>() == 3 * CACHE_LINE);

impl RingHeader {
    /// # Safety
    /// Caller must ensure `self` points to a valid mapped ring with data region
    /// immediately following the header.
    pub unsafe fn data(&self) -> *const Event {
        (self as *const Self as *const u8).add(mem::size_of::<Self>()) as *const Event
    }
}

#[repr(C)]
struct ThreadEntry {
    state: AtomicU32,
    thread_id: u16,
    _reserved: u16,
    shm_name: [u8; RING_NAME_LEN],
}

const THREAD_STATE_EMPTY: u32 = 0;
const _THREAD_STATE_ACTIVE: u32 = 1;
const THREAD_STATE_DEAD: u32 = 2;

#[repr(C)]
struct CtlHeader {
    magic: u64,
    proto_version: u32,
    thread_count: AtomicU32,
    max_threads: u32,
    _pad0: u32,
    threads: [ThreadEntry; MAX_THREADS],
}

pub struct MappedShm {
    ptr: *mut u8,
    len: usize,
}
unsafe impl Send for MappedShm {}
unsafe impl Sync for MappedShm {}

impl MappedShm {
    fn open(name: &[u8]) -> Option<Self> {
        unsafe {
            let fd = libc::shm_open(name.as_ptr() as *const libc::c_char, libc::O_RDWR, 0o600);
            if fd < 0 {
                return None;
            }
            let mut st: libc::stat = mem::zeroed();
            if libc::fstat(fd, &mut st) != 0 {
                libc::close(fd);
                return None;
            }
            let len = st.st_size as usize;
            if len == 0 {
                libc::close(fd);
                return None;
            }
            let p = libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            libc::close(fd);
            if p == libc::MAP_FAILED {
                return None;
            }
            Some(Self {
                ptr: p as *mut u8,
                len,
            })
        }
    }
}
impl Drop for MappedShm {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}

pub struct ThreadRing {
    shm: MappedShm,
    pub thread_id: u16,
    pub alive: bool,
}

impl ThreadRing {
    fn from_shm(shm: MappedShm, thread_id: u16) -> Option<Self> {
        let hdr = unsafe { &*(shm.ptr as *const RingHeader) };
        if hdr.magic != MEMVIS_MAGIC {
            return None;
        }
        if hdr.proto_version != MEMVIS_PROTO_VERSION {
            eprintln!(
                "memvis: ring proto mismatch: expected {}, got {}",
                MEMVIS_PROTO_VERSION, hdr.proto_version
            );
            return None;
        }
        Some(Self {
            shm,
            thread_id,
            alive: true,
        })
    }

    pub fn header(&self) -> &RingHeader {
        unsafe { &*(self.shm.ptr as *const RingHeader) }
    }

    #[inline]
    pub fn pop_n(&self, n: u64, out: &mut [Event]) -> bool {
        debug_assert!(out.len() >= n as usize, "pop_n: out slice too small");
        let hdr = self.header();
        let mask = (hdr.capacity - 1) as u64;
        let data = unsafe { hdr.data() };
        let t = hdr.tail.load(Ordering::Relaxed);
        let h = hdr.head.load(Ordering::Acquire);
        if h.saturating_sub(t) < n {
            return false;
        }
        for i in 0..n {
            out[i as usize] = unsafe { ptr::read_volatile(data.add(((t + i) & mask) as usize)) };
        }
        hdr.tail.store(t + n, Ordering::Release);
        true
    }

    // pop up to `max` events. single head load, single tail store.
    pub fn batch_pop(&self, max: usize, out: &mut Vec<Event>) -> usize {
        let hdr = self.header();
        let mask = (hdr.capacity - 1) as u64;
        let data = unsafe { hdr.data() };
        let t = hdr.tail.load(Ordering::Relaxed);
        let h = hdr.head.load(Ordering::Acquire);
        let avail = h.saturating_sub(t).min(hdr.capacity as u64) as usize;
        let n = avail.min(max);
        if n == 0 {
            return 0;
        }
        for i in 0..n {
            out.push(unsafe { ptr::read_volatile(data.add(((t + i as u64) & mask) as usize)) });
        }
        hdr.tail.store(t + n as u64, Ordering::Release);
        n
    }
}

pub struct RingOrchestrator {
    ctl: Option<MappedShm>,
    pub rings: Vec<ThreadRing>,
    known_count: u32,
    rr_idx: usize, // round-robin index for batch_drain
}

impl RingOrchestrator {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            ctl: None,
            rings: Vec::new(),
            known_count: 0,
            rr_idx: 0,
        }
    }

    pub fn try_attach_ctl(&mut self) -> bool {
        if self.ctl.is_some() {
            return true;
        }
        let shm = match MappedShm::open(b"/memvis_ctl\0") {
            Some(s) => s,
            None => return false,
        };
        let hdr = unsafe { &*(shm.ptr as *const CtlHeader) };
        if hdr.magic != MEMVIS_CTL_MAGIC {
            return false;
        }
        if hdr.proto_version != MEMVIS_PROTO_VERSION {
            eprintln!(
                "memvis: ctl proto mismatch: expected {}, got {}",
                MEMVIS_PROTO_VERSION, hdr.proto_version
            );
            return false;
        }
        self.ctl = Some(shm);
        true
    }

    pub fn poll_new_rings(&mut self) {
        let ctl_ptr = match &self.ctl {
            Some(s) => s.ptr,
            None => return,
        };
        let hdr = unsafe { &*(ctl_ptr as *const CtlHeader) };
        let count = hdr.thread_count.load(Ordering::Acquire);

        while self.known_count < count {
            let idx = self.known_count as usize;
            self.known_count += 1;

            let entry = &hdr.threads[idx];
            let state = entry.state.load(Ordering::Acquire);
            if state == THREAD_STATE_EMPTY {
                continue;
            }

            let name_bytes = &entry.shm_name;
            let name_len = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(RING_NAME_LEN);
            if name_len == 0 {
                continue;
            }

            let mut shm_name = Vec::with_capacity(name_len + 1);
            shm_name.extend_from_slice(&name_bytes[..name_len]);
            shm_name.push(0);

            if let Some(shm) = MappedShm::open(&shm_name) {
                if let Some(ring) = ThreadRing::from_shm(shm, entry.thread_id) {
                    eprintln!(
                        "memvis: discovered ring for thread {} ({})",
                        entry.thread_id,
                        std::str::from_utf8(&name_bytes[..name_len]).unwrap_or("?")
                    );
                    self.rings.push(ring);
                }
            }

            if state == THREAD_STATE_DEAD {
                if let Some(r) = self
                    .rings
                    .iter_mut()
                    .find(|r| r.thread_id == entry.thread_id)
                {
                    r.alive = false;
                }
            }
        }

        // check for newly dead threads
        for entry_idx in 0..count as usize {
            let entry = &hdr.threads[entry_idx];
            if entry.state.load(Ordering::Relaxed) == THREAD_STATE_DEAD {
                if let Some(r) = self
                    .rings
                    .iter_mut()
                    .find(|r| r.thread_id == entry.thread_id && r.alive)
                {
                    r.alive = false;
                }
            }
        }
    }

    pub fn total_fill(&self) -> (u64, u32) {
        let mut total_used = 0u64;
        let mut total_cap = 0u64;
        for ring in &self.rings {
            let hdr = ring.header();
            let h = hdr.head.load(Ordering::Relaxed);
            let t = hdr.tail.load(Ordering::Relaxed);
            total_used += h.saturating_sub(t);
            total_cap += hdr.capacity as u64;
        }
        let pct = if total_cap > 0 {
            ((total_used * 100) / total_cap) as u32
        } else {
            0
        };
        (total_used, pct)
    }

    pub fn ring_count(&self) -> usize {
        self.rings.len()
    }
    pub fn active_count(&self) -> usize {
        self.rings.iter().filter(|r| r.alive).count()
    }

    // adaptive backpressure: shed reads when ring fill > 6/8, resume at < 3/8
    pub fn update_backpressure(&self) {
        const BP_HIGH: u32 = 6; // eighths
        const BP_LOW: u32 = 3;
        for ring in &self.rings {
            let hdr = ring.header();
            let h = hdr.head.load(Ordering::Relaxed);
            let t = hdr.tail.load(Ordering::Relaxed);
            let fill_eighths = (h.saturating_sub(t) << 3) / hdr.capacity as u64;
            let bp = hdr.backpressure.load(Ordering::Relaxed);
            if fill_eighths >= BP_HIGH as u64 && bp == 0 {
                hdr.backpressure.store(1, Ordering::Release);
            } else if fill_eighths < BP_LOW as u64 && bp != 0 {
                hdr.backpressure.store(0, Ordering::Release);
            }
        }
    }

    // batch drain: pop up to `per_ring` events from each ring, round-robin start.
    // returns total events drained. caller processes via callback.
    pub fn batch_drain(&mut self, per_ring: usize, buf: &mut Vec<(usize, Event)>) -> usize {
        let n = self.rings.len();
        if n == 0 {
            return 0;
        }
        let mut tmp: Vec<Event> = Vec::with_capacity(per_ring);
        let mut total = 0;
        for offset in 0..n {
            let i = (self.rr_idx + offset) % n;
            tmp.clear();
            let got = self.rings[i].batch_pop(per_ring, &mut tmp);
            for ev in tmp.drain(..) {
                buf.push((i, ev));
            }
            total += got;
        }
        self.rr_idx = (self.rr_idx + 1) % n.max(1);
        total
    }
}
