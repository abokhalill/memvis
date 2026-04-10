// SPDX-License-Identifier: MIT
// memvis-dump: terminal memory visualizer. reads spsc ring from shm.
// usage: memvis-dump [--once] <elf_path>

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use std::{env, mem, ptr, thread, time};

use memvis::dwarf::{self, DwarfInfo};
use memvis::index::{AddressIndex, FrameId, NodeId};
use memvis::world::{WorldState, WorldInner, REG_NAMES, REG_COUNT, LiveRegisterFile, CacheHeatmap};

const MEMVIS_MAGIC: u64 = 0x4D454D56495342;
const SHM_NAME: &[u8] = b"/memvis_ring\0";
const CACHE_LINE: usize = 64;

const EVENT_WRITE: u64    = 0;
const EVENT_CALL: u64     = 2;
const EVENT_RETURN: u64   = 3;
const EVENT_REG_SNAPSHOT: u64 = 5;
const EVENT_CACHE_MISS: u64   = 6;

#[derive(Clone, Copy)]
#[repr(C, align(32))]
struct Event { addr: u64, size: u64, value: u64, kind: u64 }
const _: () = assert!(mem::size_of::<Event>() == 32);

#[repr(C)]
struct RingHeader {
    magic: u64, capacity: u32, entry_size: u32, flags: u64,
    backpressure: AtomicU32,
    _pad0: [u8; CACHE_LINE - 24 - mem::size_of::<AtomicU32>()],
    head: AtomicU64,
    _pad1: [u8; CACHE_LINE - mem::size_of::<AtomicU64>()],
    tail: AtomicU64,
    _pad2: [u8; CACHE_LINE - mem::size_of::<AtomicU64>()],
}
const _: () = assert!(mem::size_of::<RingHeader>() == 3 * CACHE_LINE);

impl RingHeader {
    unsafe fn data(&self) -> *const Event {
        (self as *const Self as *const u8).add(mem::size_of::<Self>()) as *const Event
    }
}

struct MappedRing { ptr: *mut u8, len: usize }
unsafe impl Send for MappedRing {}
unsafe impl Sync for MappedRing {}

impl MappedRing {
    fn open() -> Option<Self> {
        unsafe {
            let fd = libc::shm_open(SHM_NAME.as_ptr() as *const libc::c_char, libc::O_RDWR, 0o600);
            if fd < 0 { return None; }
            let mut st: libc::stat = mem::zeroed();
            if libc::fstat(fd, &mut st) != 0 { libc::close(fd); return None; }
            let len = st.st_size as usize;
            let p = libc::mmap(ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd, 0);
            libc::close(fd);
            if p == libc::MAP_FAILED { return None; }
            Some(Self { ptr: p as *mut u8, len })
        }
    }
    fn header(&self) -> &RingHeader { unsafe { &*(self.ptr as *const RingHeader) } }
}
impl Drop for MappedRing {
    fn drop(&mut self) { unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len); } }
}

#[inline(always)]
unsafe fn pop(hdr: &RingHeader) -> Option<Event> {
    let mask = (hdr.capacity - 1) as u64;
    let data = hdr.data();
    let t = hdr.tail.load(Ordering::Relaxed);
    let h = hdr.head.load(Ordering::Acquire);
    if t == h { return None; }
    let idx = (t & mask) as usize;
    let ev = ptr::read_volatile(data.add(idx));
    hdr.tail.store(t + 1, Ordering::Release);
    Some(ev)
}

#[inline]
unsafe fn pop_n(hdr: &RingHeader, n: u64, out: &mut [Event]) -> bool {
    let mask = (hdr.capacity - 1) as u64;
    let data = hdr.data();
    let t = hdr.tail.load(Ordering::Relaxed);
    let h = hdr.head.load(Ordering::Acquire);
    if h - t < n { return false; }
    for i in 0..n { out[i as usize] = ptr::read_volatile(data.add(((t + i) & mask) as usize)); }
    hdr.tail.store(t + n, Ordering::Release);
    true
}

fn ring_fill(hdr: &RingHeader) -> (u64, u32) {
    let h = hdr.head.load(Ordering::Relaxed);
    let t = hdr.tail.load(Ordering::Relaxed);
    let used = h.wrapping_sub(t);
    let pct = ((used * 100) / hdr.capacity as u64) as u32;
    (used, pct)
}

const RST: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GRN: &str = "\x1b[32m";
const YLW: &str = "\x1b[33m";
const BLU: &str = "\x1b[34m";
const MAG: &str = "\x1b[35m";
const CYN: &str = "\x1b[36m";
const WHT: &str = "\x1b[37m";
const BGRED: &str = "\x1b[41m";
const CLEAR_SCREEN: &str = "\x1b[2J\x1b[H";

fn type_color(t: &str) -> &'static str {
    let l = t.to_ascii_lowercase();
    if l.starts_with('*') || l.contains("ptr") { return MAG; }
    if l.contains("char") { return GRN; }
    if l.contains("float") || l.contains("double") { return YLW; }
    if l.contains("int") || l.contains("long") || l.contains("short") { return BLU; }
    if l.contains("struct") || l.contains("vec") || l.contains("entity") { return CYN; }
    WHT
}

#[derive(Clone)]
struct JournalEntry { seq: u64, kind: u64, addr: u64, size: u64, value: u64 }

fn render(
    out: &mut impl Write,
    world: &WorldInner,
    reg_file: &LiveRegisterFile,
    cache_heat: &CacheHeatmap,
    journal: &VecDeque<JournalEntry>,
    total: u64,
    hdr: &RingHeader,
) {
    let _ = write!(out, "{}", CLEAR_SCREEN);

    let (used, pct) = ring_fill(hdr);
    let ring_color = if pct > 85 { RED } else if pct > 50 { YLW } else { GRN };
    let _ = writeln!(out,
        "{}MEMVIS{} │ insn {}{}{} │ events {}{}{} │ nodes {}{}{} │ edges {}{}{} │ ring {}{}%{} ({}/{})",
        DIM, RST,
        WHT, world.insn_counter, RST,
        WHT, total, RST,
        CYN, world.nodes.len(), RST,
        MAG, world.edges.len(), RST,
        ring_color, pct, RST, used, hdr.capacity,
    );
    let _ = writeln!(out, "{}{}{}", DIM, "─".repeat(100), RST);
    let _ = writeln!(out, "{}MEMORY MAP{}", BOLD, RST);

    let mut sorted: Vec<_> = world.nodes.iter().filter(|(_, n)| n.size > 0).collect();
    sorted.sort_by_key(|(_, n)| n.addr);

    let mut last_cl: u64 = u64::MAX;

    for (nid, node) in &sorted {
        let cl = node.addr / 64;

        // cache line boundary
        if cl != last_cl {
            let _ = writeln!(out, "  {}── cacheline 0x{:x} ──{}", DIM, cl * 64, RST);
            last_cl = cl;
        }

        // cache line crossing alert
        let crosses_cl = (node.addr % 64) + node.size > 64;
        let alert = if crosses_cl { format!("{}!CL{}", RED, RST) } else { "    ".into() };

        // pointer resolution
        let ptr_info = if node.type_info.is_pointer && node.raw_value != 0 {
            let target = world.nodes.values()
                .find(|t| node.raw_value >= t.addr && node.raw_value < t.addr + t.size.max(1));
            match target {
                Some(t) => format!(" {}→ {}{}", MAG, t.name, RST),
                None => format!(" {}→ 0x{:x}{}", MAG, node.raw_value, RST),
            }
        } else { String::new() };

        // miss count
        let miss_str = cache_heat.per_node.get(nid)
            .map(|e| format!(" {}[{} misses]{}", RED, e.count, RST))
            .unwrap_or_default();

        let _ = writeln!(out,
            "  {}{:>12x}{}  {:>4}B  {}{:<20}{} {}{:<14}{}  val={}{:>18x}{}{}{}{}",
            WHT, node.addr, RST,
            node.size,
            BOLD, node.name, RST,
            type_color(&node.type_info.name), node.type_info.name, RST,
            WHT, node.raw_value, RST,
            alert, ptr_info, miss_str,
        );

        // struct fields
        for f in &node.type_info.fields {
            if f.byte_size == 0 { continue; }
            let fa = node.addr + f.byte_offset;
            let fcross = (fa % 64) + f.byte_size > 64;
            let falert = if fcross { format!("{}!CL{}", RED, RST) } else { "    ".into() };
            let _ = writeln!(out,
                "    {}{:>12x}{}  {:>4}B  {}{:<20}{} {}{:<14}{}{}",
                DIM, fa, RST,
                f.byte_size,
                DIM, f.name, RST,
                type_color(&f.type_info.name), f.type_info.name, RST,
                falert,
            );
        }
    }

    let _ = writeln!(out);

    if !world.edges.is_empty() {
        let _ = writeln!(out, "{}POINTER EDGES{}", BOLD, RST);
        for (src, edge) in &world.edges {
            let src_name = world.nodes.get(src).map(|n| n.name.as_str()).unwrap_or("?");
            let tgt_name = world.nodes.get(&edge.target).map(|n| n.name.as_str()).unwrap_or("?");
            let dng = if edge.is_dangling { format!(" {}DANGLING{}", BGRED, RST) } else { String::new() };
            let _ = writeln!(out,
                "  {}{}{} {}──>{} {}{}{} (0x{:x}){}",
                CYN, src_name, RST, MAG, RST, CYN, tgt_name, RST, edge.ptr_value, dng,
            );
        }
        let _ = writeln!(out);
    }

    // ── registers ───────────────────────────────────────────────────
    let _ = writeln!(out, "{}REGISTERS{} (insn {})", BOLD, RST, reg_file.insn);
    let _ = write!(out, "  ");
    for (i, name) in REG_NAMES.iter().enumerate() {
        let val = reg_file.values[i];
        let changed = reg_file.values[i] != reg_file.prev[i];

        let matches_addr = val != 0 && world.nodes.values().any(|n| val >= n.addr && val < n.addr + n.size.max(1));

        let vclr = if matches_addr { YLW } else if changed { WHT } else { DIM };
        let nclr = if matches_addr { YLW } else { CYN };

        let _ = write!(out, "{}{:>4}{}={}{:>16x}{}", nclr, name, RST, vclr, val, RST);

        if (i + 1) % 6 == 0 {
            let _ = writeln!(out);
            if i + 1 < REG_NAMES.len() { let _ = write!(out, "  "); }
        } else {
            let _ = write!(out, "  ");
        }
    }
    let _ = writeln!(out);

    let tail_n = 12;
    let start = if journal.len() > tail_n { journal.len() - tail_n } else { 0 };
    let _ = writeln!(out, "{}EVENTS{} (last {})", BOLD, RST, tail_n);
    for i in start..journal.len() {
        let e = &journal[i];
        let (kind_str, kclr) = match e.kind {
            0 => ("W   ", WHT),
            1 => ("R   ", DIM),
            2 => ("CALL", BLU),
            3 => ("RET ", BLU),
            4 => ("OVF ", RED),
            5 => ("REG ", CYN),
            6 => ("CMIS", MAG),
            _ => ("?   ", DIM),
        };
        let _ = writeln!(out,
            "  {}{:>8}{} {}{}{} {:>12x}  {:>4}  {:>16x}",
            DIM, e.seq, RST, kclr, kind_str, RST, e.addr, e.size, e.value,
        );
    }
}

fn run(ring: MappedRing, dwarf_info: Option<DwarfInfo>, once: bool) {
    let hdr = ring.header();
    let mut addr_index = AddressIndex::new();
    let mut world = WorldState::new();
    let mut stack: Vec<(FrameId, String)> = Vec::with_capacity(256);
    let mut next_frame_id: FrameId = 1;
    let mut total: u64 = 0;
    let mut journal: VecDeque<JournalEntry> = VecDeque::with_capacity(1024);

    if let Some(ref info) = dwarf_info {
        for (i, g) in info.globals.iter().enumerate() {
            let nid = NodeId::Global(i as u32);
            addr_index.insert_global(g.addr, g.size, g.name.clone(), g.type_info.clone(), i as u32);
            world.ensure_node(nid, &g.name, &g.type_info, g.addr, g.size);
        }
        addr_index.finalize();
    }

    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let refresh = time::Duration::from_millis(100);
    let mut last_render = time::Instant::now();
    let mut rendered_once = false;

    loop {
        let mut drained = 0u64;
        loop {
            match unsafe { pop(hdr) } {
                Some(ev) => {
                    total += 1;
                    drained += 1;
                    world.inc_insn_counter();

                    journal.push_back(JournalEntry {
                        seq: total, kind: ev.kind, addr: ev.addr, size: ev.size, value: ev.value,
                    });
                    if journal.len() > 1000 { journal.pop_front(); }

                    match ev.kind {
                        EVENT_WRITE => {
                            if let Some(h) = addr_index.lookup(ev.addr) {
                                let nid = h.node_id;
                                world.ensure_node(nid, h.name, h.type_info, ev.addr, ev.size);
                                world.update_value(nid, ev.value, world.insn_counter());
                                if h.type_info.is_pointer && ev.size == 8 {
                                    let target = if ev.value == 0 { None }
                                        else { addr_index.lookup(ev.value).map(|t| t.node_id) };
                                    world.update_edge(nid, target, ev.value);
                                }
                            }
                        }
                        EVENT_CALL => {
                            if let Some(ref info) = dwarf_info {
                                if let Some(func) = info.functions.get(&ev.addr) {
                                    let fid = next_frame_id;
                                    next_frame_id += 1;
                                    stack.push((fid, func.name.clone()));
                                    for (li, l) in func.locals.iter().enumerate() {
                                        let addr = (ev.value as i64 + l.frame_offset) as u64;
                                        let nid = NodeId::Local(fid, li as u16);
                                        world.ensure_node(nid, &l.name, &l.type_info, addr, l.size);
                                    }
                                    let locals: Vec<_> = func.locals.iter().map(|l|
                                        (l.frame_offset, l.size, l.name.clone(), l.type_info.clone())
                                    ).collect();
                                    if !locals.is_empty() {
                                        addr_index.insert_frame_locals(fid, ev.value, &locals);
                                        addr_index.finalize();
                                    }
                                }
                            }
                        }
                        EVENT_RETURN => {
                            if let Some((fid, _)) = stack.pop() {
                                addr_index.remove_frame(fid);
                                world.remove_frame_nodes(fid);
                            }
                        }
                        EVENT_REG_SNAPSHOT => {
                            let mut cont = [Event { addr: 0, size: 0, value: 0, kind: 0 }; 6];
                            if unsafe { pop_n(hdr, 6, &mut cont) } {
                                let mut regs = [0u64; REG_COUNT];
                                for s in 0..6usize {
                                    regs[s * 3]     = cont[s].addr;
                                    regs[s * 3 + 1] = cont[s].size;
                                    regs[s * 3 + 2] = cont[s].value;
                                }
                                world.reg_file.update(regs, ev.addr);
                            }
                        }
                        EVENT_CACHE_MISS => {
                            if let Some(h) = addr_index.lookup(ev.addr) {
                                world.cache_heat.record_miss(h.node_id);
                            }
                        }
                        _ => {}
                    }

                    if drained > 10_000 { break; }
                }
                None => break,
            }
        }

        let now = time::Instant::now();
        if now.duration_since(last_render) >= refresh || (!rendered_once && total > 0) {
            let snap = world.snapshot();
            render(&mut out, &snap, &world.reg_file, &world.cache_heat, &journal, total, hdr);
            let _ = out.flush();
            last_render = now;
            rendered_once = true;

            if once && total > 0 {
                return;
            }
        }

        if drained == 0 {
            thread::sleep(time::Duration::from_millis(10));
        }

        if total & 0xFFF == 0 {
            world.cache_heat.tick();
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let once = args.iter().any(|a| a == "--once");
    let elf_path = args.iter().find(|a| !a.starts_with('-') && *a != &args[0]).map(|s| s.as_str());

    let dwarf_info: Option<DwarfInfo> = elf_path.and_then(|path| {
        eprintln!("memvis-dump: parsing DWARF from {}", path);
        match dwarf::parse_elf(path) {
            Ok(info) => {
                eprintln!("memvis-dump: {} globals, {} functions", info.globals.len(), info.functions.len());
                Some(info)
            }
            Err(e) => { eprintln!("memvis-dump: DWARF parse failed: {}", e); None }
        }
    });

    eprintln!("memvis-dump: waiting for shm ring...");
    loop {
        if let Some(ring) = MappedRing::open() {
            let hdr = ring.header();
            if hdr.magic == MEMVIS_MAGIC {
                eprintln!("memvis-dump: attached, capacity={}", hdr.capacity);
                run(ring, dwarf_info, once);
                return;
            }
        }
        thread::sleep(time::Duration::from_millis(500));
    }
}
