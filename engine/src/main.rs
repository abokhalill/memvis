// SPDX-License-Identifier: MIT

use std::collections::VecDeque;
use std::io::{self, Write};
use std::{env, thread, time};

use memvis::dwarf::{self, DwarfInfo};
use memvis::index::{AddressIndex, FrameId, NodeId};
use memvis::ring::{Event, RingOrchestrator};
use memvis::world::{WorldState, WorldInner, ShadowStack, REG_NAMES, REG_COUNT};

const EVENT_WRITE: u8    = 0;
const EVENT_CALL: u8     = 2;
const EVENT_RETURN: u8   = 3;
const EVENT_REG_SNAPSHOT: u8 = 5;
const EVENT_CACHE_MISS: u8   = 6;
const EVENT_MODULE_LOAD: u8  = 7;

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
struct JournalEntry { seq: u64, kind: u8, thread_id: u16, addr: u64, size: u32, value: u64 }

fn render(
    out: &mut impl Write,
    world: &WorldInner,
    journal: &VecDeque<JournalEntry>,
    total: u64,
    orch: &RingOrchestrator,
) {
    let _ = write!(out, "{}", CLEAR_SCREEN);

    let (used, pct) = orch.total_fill();
    let ring_color = if pct > 85 { RED } else if pct > 50 { YLW } else { GRN };
    let _ = writeln!(out,
        "{}MEMVIS{} │ insn {}{}{} │ events {}{}{} │ nodes {}{}{} │ edges {}{}{} │ rings {}{}{} │ fill {}{}%{} ({})",
        DIM, RST,
        WHT, world.insn_counter, RST,
        WHT, total, RST,
        CYN, world.nodes.len(), RST,
        MAG, world.edges.len(), RST,
        CYN, orch.ring_count(), RST,
        ring_color, pct, RST, used,
    );
    let _ = writeln!(out, "{}{}{}", DIM, "─".repeat(100), RST);
    let _ = writeln!(out, "{}MEMORY MAP{}", BOLD, RST);

    let mut sorted: Vec<_> = world.nodes.iter().filter(|(_, n)| n.size > 0).collect();
    sorted.sort_by_key(|(_, n)| n.addr);

    let mut last_cl: u64 = u64::MAX;

    for (nid, node) in &sorted {
        let cl = node.addr / 64;

        if cl != last_cl {
            let fs = world.cl_tracker.contention_score(node.addr);
            let fs_tag = if fs > 1 { format!(" {}FALSE_SHARE T={}{}", BGRED, fs, RST) } else { String::new() };
            let _ = writeln!(out, "  {}── cacheline 0x{:x} ──{}{}", DIM, cl * 64, RST, fs_tag);
            last_cl = cl;
        }

        let crosses_cl = (node.addr % 64) + node.size > 64;
        let alert = if crosses_cl { format!("{}!CL{}", RED, RST) } else { "    ".into() };

        let ptr_info = if node.type_info.is_pointer && node.raw_value != 0 {
            let target = world.nodes.values()
                .find(|t| node.raw_value >= t.addr && node.raw_value < t.addr + t.size.max(1));
            match target {
                Some(t) => format!(" {}→ {}{}", MAG, t.name, RST),
                None => format!(" {}→ 0x{:x}{}", MAG, node.raw_value, RST),
            }
        } else { String::new() };

        let miss_str = world.cache_heat.per_node.get(nid)
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

    let reg_file = &world.reg_file;
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
            "  {}{:>8}{} {}{}{} T{:<3} {:>12x}  {:>4}  {:>16x}",
            DIM, e.seq, RST, kclr, kind_str, RST, e.thread_id, e.addr, e.size, e.value,
        );
    }
}

#[inline]
fn process_event(
    ev: &Event,
    ring_idx: usize,
    orch: &RingOrchestrator,
    world: &mut WorldState,
    addr_index: &mut AddressIndex,
    dwarf_info: &Option<DwarfInfo>,
    stacks: &mut Vec<ShadowStack>,
    next_frame_id: &mut FrameId,
    relocation_delta: &mut Option<u64>,
) {
    let ev_kind = ev.kind();
    match ev_kind {
        EVENT_WRITE => {
            world.record_cl_write(ev.addr, ev.thread_id);
            if let Some(h) = addr_index.lookup(ev.addr) {
                let nid = h.node_id;
                world.ensure_node(nid, h.name, h.type_info, ev.addr, ev.size as u64);
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
                    let fid = *next_frame_id;
                    *next_frame_id += 1;
                    while stacks.len() <= ring_idx {
                        stacks.push(ShadowStack::new());
                    }
                    stacks[ring_idx].push_call(fid, ev.addr, func.name.clone());
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
            if ring_idx < stacks.len() {
                if let Some(frame) = stacks[ring_idx].pop_return() {
                    addr_index.remove_frame(frame.frame_id);
                    world.remove_frame_nodes(frame.frame_id);
                }
            }
        }
        EVENT_REG_SNAPSHOT => {
            let mut cont = [Event::zero(); 6];
            if orch.rings[ring_idx].pop_n(6, &mut cont) {
                let mut regs = [0u64; REG_COUNT];
                for s in 0..6usize {
                    regs[s * 3]     = cont[s].addr;
                    regs[s * 3 + 1] = cont[s].size as u64;
                    regs[s * 3 + 2] = cont[s].value;
                }
                world.update_regs(regs, ev.addr);
            }
        }
        EVENT_CACHE_MISS => {
            if let Some(h) = addr_index.lookup(ev.addr) {
                world.record_cache_miss(h.node_id);
            }
        }
        EVENT_MODULE_LOAD => {
            if relocation_delta.is_none() {
                if let Some(ref info) = dwarf_info {
                    let runtime_base = ev.addr;
                    let delta = runtime_base.wrapping_sub(info.elf_base_vaddr);
                    eprintln!("memvis: relocation delta=0x{:x} (runtime=0x{:x} elf=0x{:x})",
                              delta, runtime_base, info.elf_base_vaddr);
                    *relocation_delta = Some(delta);

                    // rebuild address index and world nodes with relocated addresses
                    *addr_index = AddressIndex::new();
                    for (i, g) in info.globals.iter().enumerate() {
                        let relocated_addr = g.addr.wrapping_add(delta);
                        let nid = NodeId::Global(i as u32);
                        addr_index.insert_global(
                            relocated_addr, g.size, g.name.clone(),
                            g.type_info.clone(), i as u32,
                        );
                        // force-update: remove old node at ELF addr, insert at runtime addr
                        world.remove_node(nid);
                        world.ensure_node(nid, &g.name, &g.type_info, relocated_addr, g.size);
                    }
                    addr_index.finalize();
                }
            }
        }
        _ => {}
    }
}

fn run(mut orch: RingOrchestrator, dwarf_info: Option<DwarfInfo>, once: bool, min_events: u64) {
    let mut addr_index = AddressIndex::new();
    let mut world = WorldState::new();
    let mut stacks: Vec<ShadowStack> = Vec::new();
    let mut next_frame_id: FrameId = 1;
    let mut total: u64 = 0;
    let mut journal: VecDeque<JournalEntry> = VecDeque::with_capacity(1024);
    let mut relocation_delta: Option<u64> = None;

    // insert globals with ELF vaddrs initially; they'll be relocated on MODULE_LOAD
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
    let mut last_discovery = time::Instant::now();

    loop {
        let now_disc = time::Instant::now();
        if now_disc.duration_since(last_discovery) >= time::Duration::from_millis(200) {
            orch.poll_new_rings();
            last_discovery = now_disc;
        }

        let mut drained = 0u64;
        while drained < 10_000 {
            match orch.merge_pop() {
                Some((ri, ev)) => {
                    total += 1;
                    drained += 1;
                    world.inc_insn_counter();

                    let ev_kind = ev.kind();
                    journal.push_back(JournalEntry {
                        seq: total, kind: ev_kind, thread_id: ev.thread_id,
                        addr: ev.addr, size: ev.size, value: ev.value,
                    });
                    if journal.len() > 1000 { journal.pop_front(); }

                    process_event(
                        &ev, ri, &orch, &mut world, &mut addr_index,
                        &dwarf_info, &mut stacks, &mut next_frame_id,
                        &mut relocation_delta,
                    );
                }
                None => break,
            }
        }

        let now = time::Instant::now();
        if now.duration_since(last_render) >= refresh || (!rendered_once && total > 0) {
            let snap = world.snapshot();
            render(&mut out, &snap, &journal, total, &orch);
            let _ = out.flush();
            last_render = now;
            rendered_once = true;

            if once && total >= min_events {
                return;
            }
        }

        if drained == 0 {
            thread::sleep(time::Duration::from_millis(10));
        }

        if total & 0xFFF == 0 {
            world.cache_heat_tick();
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let once = args.iter().any(|a| a == "--once");
    let min_events: u64 = args.windows(2)
        .find(|w| w[0] == "--min-events")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(1);
    let elf_path = args.iter().find(|a| !a.starts_with('-') && *a != &args[0] && !a.parse::<u64>().is_ok()).map(|s| s.as_str());

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

    let mut orch = RingOrchestrator::new();
    eprintln!("memvis-dump: waiting for control ring...");
    loop {
        if orch.try_attach_ctl() {
            orch.poll_new_rings();
            if orch.ring_count() > 0 {
                eprintln!("memvis-dump: attached, {} thread ring(s)", orch.ring_count());
                run(orch, dwarf_info, once, min_events);
                return;
            }
        }
        thread::sleep(time::Duration::from_millis(250));
    }
}
