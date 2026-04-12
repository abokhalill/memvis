// SPDX-License-Identifier: MIT

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicI32, AtomicBool, Ordering as AtomicOrdering};
use std::{env, thread, time};

use memvis::dwarf::{self, DwarfInfo};
use memvis::index::{AddressIndex, FrameId, NodeId};
use memvis::ring::{Event, RingOrchestrator};
use memvis::tui::{self, JournalEntry, AppState};
use memvis::world::{WorldState, ShadowStack, SnapshotRing, REG_COUNT};

const EVENT_WRITE: u8    = 0;
const EVENT_CALL: u8     = 2;
const EVENT_RETURN: u8   = 3;
const EVENT_REG_SNAPSHOT: u8 = 5;
const EVENT_CACHE_MISS: u8   = 6;
const EVENT_MODULE_LOAD: u8  = 7;


#[inline]
fn process_event(
    ev: &Event,
    ring_idx: usize,
    orch: &RingOrchestrator,
    world: &mut WorldState,
    addr_index: &mut AddressIndex,
    dwarf_info: &Option<DwarfInfo>,
    stacks: &mut HashMap<u16, ShadowStack>,
    next_frame_id: &mut FrameId,
    relocation_delta: &mut Option<u64>,
    returned_frames: &mut VecDeque<FrameId>,
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
                let elf_pc = match *relocation_delta {
                    Some(d) => ev.addr.wrapping_sub(d),
                    None => ev.addr,
                };
                if let Some(func) = info.functions.get(&elf_pc) {
                    let fid = *next_frame_id;
                    *next_frame_id += 1;
                    let tid = ev.thread_id;
                    stacks.entry(tid).or_insert_with(ShadowStack::new)
                        .push_call(fid, ev.addr, func.name.clone());
                    for (li, l) in func.locals.iter().enumerate() {
                        let addr = if !l.location.is_empty() {
                            match &l.location.entries[0].1 {
                                // simple cases: tracer-provided frame_base is authoritative
                                dwarf::LocationPiece::FrameBaseOffset(_)
                                | dwarf::LocationPiece::RegisterOffset(_, _) =>
                                    (ev.value as i64 + l.frame_offset) as u64,
                                // complex: try resolve with current regs, fallback to frame_offset
                                piece => {
                                    let regs = world.regs();
                                    dwarf::resolve_location(piece, &regs, ev.value, func.frame_base_is_cfa)
                                        .unwrap_or((ev.value as i64 + l.frame_offset) as u64)
                                }
                            }
                        } else {
                            (ev.value as i64 + l.frame_offset) as u64
                        };
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
            let tid = ev.thread_id;
            if let Some(stack) = stacks.get_mut(&tid) {
                if let Some(frame) = stack.pop_return() {
                    addr_index.remove_frame(frame.frame_id);
                    returned_frames.push_back(frame.frame_id);
                    // evict oldest retained frames to bound memory
                    while returned_frames.len() > 32 {
                        if let Some(old_fid) = returned_frames.pop_front() {
                            world.remove_frame_nodes(old_fid);
                        }
                    }
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
                    *addr_index = AddressIndex::new();
                    populate_globals(info, delta, addr_index, world);
                }
            }
        }
        _ => {}
    }
}

fn populate_globals(
    info: &DwarfInfo, delta: u64,
    addr_index: &mut AddressIndex, world: &mut WorldState,
) {
    for (i, g) in info.globals.iter().enumerate() {
        let base = g.addr.wrapping_add(delta);
        let gi = i as u32;
        addr_index.insert_global(base, g.size, g.name.clone(), g.type_info.clone(), gi);
        world.remove_node(NodeId::Global(gi));
        world.ensure_node(NodeId::Global(gi), &g.name, &g.type_info, base, g.size);
        // decompose struct fields into separate addressable nodes
        for (fi, f) in g.type_info.fields.iter().enumerate() {
            if f.byte_size == 0 { continue; }
            let faddr = base + f.byte_offset;
            let fid = NodeId::Field(gi, fi as u16);
            let qualified = format!("{}.{}", g.name, f.name);
            addr_index.insert_field(
                faddr, f.byte_size, qualified.clone(),
                f.type_info.clone(), gi, fi as u16,
            );
            world.remove_node(fid);
            world.ensure_node(fid, &qualified, &f.type_info, faddr, f.byte_size);
        }
    }
    addr_index.finalize();
}

fn run(mut orch: RingOrchestrator, dwarf_info: Option<DwarfInfo>, once: bool, min_events: u64) {
    let mut addr_index = AddressIndex::new();
    let mut world = WorldState::new();
    let mut stacks: HashMap<u16, ShadowStack> = HashMap::new();
    let mut next_frame_id: FrameId = 1;
    let mut total: u64 = 0;
    let mut journal: VecDeque<JournalEntry> = VecDeque::with_capacity(1024);
    let mut relocation_delta: Option<u64> = None;
    let mut returned_frames: VecDeque<FrameId> = VecDeque::with_capacity(64);
    let mut expected_seq: HashMap<u16, u16> = HashMap::new();
    let mut seq_gaps: u64 = 0;

    if let Some(ref info) = dwarf_info {
        populate_globals(info, 0, &mut addr_index, &mut world);
    }

    // --once mode: headless render to stdout (for E2E tests and scripting)
    if once {
        run_headless(
            &mut orch, &dwarf_info, min_events,
            &mut addr_index, &mut world, &mut stacks, &mut next_frame_id,
            &mut total, &mut journal, &mut relocation_delta, &mut returned_frames,
        );
        return;
    }

    // interactive ratatui mode
    let mut terminal = match tui::init_terminal() {
        Ok(t) => t,
        Err(e) => { eprintln!("memvis: failed to init terminal: {}", e); return; }
    };
    let mut app = AppState::new();
    let mut snap_ring = SnapshotRing::new(512);
    let mut tick: u64 = 0;
    let refresh = time::Duration::from_millis(50);
    let mut last_render = time::Instant::now();
    let mut last_discovery = time::Instant::now();

    loop {
        tui::handle_input(&mut app);
        if app.quit { break; }

        let now_disc = time::Instant::now();
        if now_disc.duration_since(last_discovery) >= time::Duration::from_millis(200) {
            orch.poll_new_rings();
            last_discovery = now_disc;
        }

        if !app.paused {
            let mut drained = 0u64;
            while drained < 100_000 {
                match orch.merge_pop() {
                    Some((ri, ev)) => {
                        total += 1;
                        drained += 1;
                        world.inc_insn_counter();

                        let ev_kind = ev.kind();
                        // per-thread seq gap detection (u16 modular)
                        let exp = expected_seq.entry(ev.thread_id).or_insert(ev.seq);
                        if ev.seq != *exp && ev_kind != EVENT_REG_SNAPSHOT {
                            seq_gaps += 1;
                        }
                        *exp = ev.seq.wrapping_add(1);

                        journal.push_back(JournalEntry {
                            seq: total, kind: ev_kind, thread_id: ev.thread_id,
                            addr: ev.addr, size: ev.size, value: ev.value,
                        });
                        if journal.len() > 1000 { journal.pop_front(); }

                        process_event(
                            &ev, ri, &orch, &mut world, &mut addr_index,
                            &dwarf_info, &mut stacks, &mut next_frame_id,
                            &mut relocation_delta, &mut returned_frames,
                        );
                    }
                    None => break,
                }
            }

            if total & 0xFFF == 0 {
                world.cache_heat_tick();
            }
            orch.update_backpressure();
        }

        let now = time::Instant::now();
        if now.duration_since(last_render) >= refresh {
            let live_snap = world.snapshot();
            tick += 1;
            snap_ring.push(live_snap.clone(), tick, total);

            // time-travel: use historical snapshot if scrubbing, else live
            let display_snap = match app.time_travel_idx {
                Some(idx) => snap_ring.get(idx)
                    .map(|sr| sr.snap.clone())
                    .unwrap_or(live_snap),
                None => live_snap,
            };

            let (fill_used, fill_pct) = orch.total_fill();
            let snap_total = snap_ring.len();
            tui::draw(
                &mut terminal, &display_snap, &journal, total,
                orch.ring_count(), fill_used, fill_pct, &mut app,
                snap_total, &stacks, seq_gaps,
            );
            last_render = now;
        }

        if !app.paused {
            thread::sleep(time::Duration::from_millis(5));
        } else {
            thread::sleep(time::Duration::from_millis(20));
        }
    }

    tui::restore_terminal(&mut terminal);
}

fn run_headless(
    orch: &mut RingOrchestrator,
    dwarf_info: &Option<DwarfInfo>,
    min_events: u64,
    addr_index: &mut AddressIndex,
    world: &mut WorldState,
    stacks: &mut HashMap<u16, ShadowStack>,
    next_frame_id: &mut FrameId,
    total: &mut u64,
    journal: &mut VecDeque<JournalEntry>,
    relocation_delta: &mut Option<u64>,
    returned_frames: &mut VecDeque<FrameId>,
) {
    use std::io::Write;
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
        while drained < 50_000 {
            match orch.merge_pop() {
                Some((ri, ev)) => {
                    *total += 1;
                    drained += 1;
                    world.inc_insn_counter();

                    let ev_kind = ev.kind();
                    journal.push_back(JournalEntry {
                        seq: *total, kind: ev_kind, thread_id: ev.thread_id,
                        addr: ev.addr, size: ev.size, value: ev.value,
                    });
                    if journal.len() > 1000 { journal.pop_front(); }

                    process_event(
                        &ev, ri, orch, world, addr_index,
                        dwarf_info, stacks, next_frame_id,
                        relocation_delta, returned_frames,
                    );
                }
                None => break,
            }
        }

        let now = time::Instant::now();
        if now.duration_since(last_render) >= refresh || (!rendered_once && *total > 0) {
            let snap = world.snapshot();
            headless_render(&mut out, &snap, journal, *total, orch);
            let _ = out.flush();
            last_render = now;
            rendered_once = true;

            if *total >= min_events {
                return;
            }
        }

        if drained == 0 {
            thread::sleep(time::Duration::from_millis(10));
        }

        orch.update_backpressure();

        if *total & 0xFFF == 0 {
            world.cache_heat_tick();
        }
    }
}

fn headless_render(
    out: &mut impl std::io::Write,
    world: &memvis::world::WorldInner,
    journal: &VecDeque<JournalEntry>,
    total: u64,
    orch: &RingOrchestrator,
) {
    let (used, pct) = orch.total_fill();
    let _ = writeln!(out,
        "MEMVIS │ insn {} │ events {} │ nodes {} │ edges {} │ rings {} │ fill {}% ({})",
        world.insn_counter, total, world.nodes.len(), world.edges.len(),
        orch.ring_count(), pct, used);
    let _ = writeln!(out, "{}", "─".repeat(100));
    let _ = writeln!(out, "MEMORY MAP");

    let mut sorted: Vec<_> = world.nodes.iter().filter(|(_, n)| n.size > 0).collect();
    sorted.sort_by_key(|(_, n)| (n.addr, std::cmp::Reverse(n.last_write_insn)));
    sorted.dedup_by(|a, b| {
        matches!(a.0, NodeId::Local(..)) && matches!(b.0, NodeId::Local(..))
            && a.1.addr == b.1.addr && a.1.name == b.1.name
    });

    let mut last_cl: u64 = u64::MAX;
    for (nid, node) in &sorted {
        if matches!(nid, NodeId::Field(..)) { continue; }
        let cl = node.addr / 64;
        if cl != last_cl {
            let fs = world.cl_tracker.contention_score(node.addr);
            let fs_tag = if fs > 1 { format!(" FALSE_SHARE T={}", fs) } else { String::new() };
            let _ = writeln!(out, "  ── cacheline 0x{:x} ──{}", cl * 64, fs_tag);
            last_cl = cl;
        }
        let ptr_info = if node.type_info.is_pointer && node.raw_value != 0 {
            let target = world.nodes.values()
                .find(|t| node.raw_value >= t.addr && node.raw_value < t.addr + t.size.max(1));
            match target {
                Some(t) => format!("  → {}", t.name),
                None => format!("  → 0x{:x}", node.raw_value),
            }
        } else { String::new() };
        let _ = writeln!(out, "  {:>12x}  {:>4}B  {:<20} {:<14}  val={:>18x}{}",
            node.addr, node.size, node.name, node.type_info.name, node.raw_value, ptr_info);
        if let NodeId::Global(gi) = nid {
            for (fi, f) in node.type_info.fields.iter().enumerate() {
                if f.byte_size == 0 { continue; }
                let fa = node.addr + f.byte_offset;
                let fid = NodeId::Field(*gi, fi as u16);
                let fval = world.nodes.get(&fid).map(|n| n.raw_value).unwrap_or(0);
                let _ = writeln!(out, "    {:>12x}  {:>4}B  {:<20} {:<14}  val={:>18x}",
                    fa, f.byte_size, f.name, f.type_info.name, fval);
            }
        }
    }

    if !world.edges.is_empty() {
        let _ = writeln!(out, "\nPOINTER EDGES");
        let mut seen: std::collections::HashSet<(String, u64)> = std::collections::HashSet::new();
        for (src, edge) in &world.edges {
            let src_name = world.nodes.get(src).map(|n| n.name.clone()).unwrap_or_default();
            let key = (src_name.clone(), edge.ptr_value);
            if !seen.insert(key) { continue; }
            let tgt_name = world.nodes.get(&edge.target).map(|n| n.name.as_str()).unwrap_or("?");
            let _ = writeln!(out, "  {} ──> {} (0x{:x})", src_name, tgt_name, edge.ptr_value);
        }
    }

    let tail_n = 12usize;
    let start = if journal.len() > tail_n { journal.len() - tail_n } else { 0 };
    let _ = writeln!(out, "\nEVENTS (last {})", tail_n);
    for i in start..journal.len() {
        let e = &journal[i];
        let kind_str = match e.kind { 0=>"W", 1=>"R", 2=>"CALL", 3=>"RET", 4=>"OVF", 5=>"REG", 6=>"CMIS", 7=>"MLOAD", _=>"?" };
        let _ = writeln!(out, "  {:>8} {:<5} T{:<3} {:>12x}  {:>4}  {:>16x}",
            e.seq, kind_str, e.thread_id, e.addr, e.size, e.value);
    }
}

fn cleanup_shm() {
    // remove ctl ring
    unsafe { libc::shm_unlink(b"/memvis_ctl\0".as_ptr() as *const libc::c_char); }
    // remove per-thread rings (best effort, up to 256)
    for i in 0..256u32 {
        let name = format!("/memvis_ring_{}\0", i);
        unsafe { libc::shm_unlink(name.as_ptr() as *const libc::c_char); }
    }
}

fn find_drrun() -> Option<std::path::PathBuf> {
    // 1. MEMVIS_DRRUN env var (explicit override)
    if let Ok(p) = env::var("MEMVIS_DRRUN") {
        let path = std::path::PathBuf::from(&p);
        if path.exists() { return Some(path); }
    }
    // 2. DYNAMORIO_HOME env var
    if let Ok(home) = env::var("DYNAMORIO_HOME") {
        let path = std::path::PathBuf::from(&home).join("bin64/drrun");
        if path.exists() { return Some(path); }
    }
    // 3. PATH lookup
    if let Ok(output) = std::process::Command::new("which").arg("drrun").output() {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !s.is_empty() { return Some(std::path::PathBuf::from(s)); }
        }
    }
    None
}

fn find_tracer() -> Option<std::path::PathBuf> {
    // 1. MEMVIS_TRACER env var
    if let Ok(p) = env::var("MEMVIS_TRACER") {
        let path = std::path::PathBuf::from(&p);
        if path.exists() { return Some(path); }
    }
    // 2. relative to the current exe
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            // release binary is at engine/target/release/memvis
            // tracer is at build/libmemvis_tracer.so
            for candidate in &[
                dir.join("../../build/libmemvis_tracer.so"),
                dir.join("../../../build/libmemvis_tracer.so"),
                dir.join("libmemvis_tracer.so"),
            ] {
                if let Ok(canon) = candidate.canonicalize() {
                    if canon.exists() { return Some(canon); }
                }
            }
        }
    }
    None
}

static TRACER_PID: AtomicI32 = AtomicI32::new(0);
static GOT_SIGNAL: AtomicBool = AtomicBool::new(false);

extern "C" fn signal_handler(_sig: libc::c_int) {
    GOT_SIGNAL.store(true, AtomicOrdering::SeqCst);
    let pid = TRACER_PID.load(AtomicOrdering::SeqCst);
    if pid > 0 {
        unsafe { libc::kill(pid, libc::SIGTERM); }
    }
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGINT, signal_handler as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_handler as libc::sighandler_t);
    }
}

fn run_consumer(elf_path: Option<&str>, once: bool, min_events: u64) {
    let dwarf_info: Option<DwarfInfo> = elf_path.and_then(|path| {
        eprintln!("memvis: parsing DWARF from {}", path);
        match dwarf::parse_elf(path) {
            Ok(info) => {
                eprintln!("memvis: {} globals, {} functions", info.globals.len(), info.functions.len());
                Some(info)
            }
            Err(e) => { eprintln!("memvis: DWARF parse failed: {}", e); None }
        }
    });

    let mut orch = RingOrchestrator::new();
    eprintln!("memvis: waiting for tracer...");
    let deadline = time::Instant::now() + time::Duration::from_secs(30);
    loop {
        if GOT_SIGNAL.load(AtomicOrdering::Relaxed) {
            eprintln!("memvis: interrupted while waiting for tracer");
            return;
        }
        if time::Instant::now() > deadline {
            eprintln!("memvis: timeout waiting for tracer (30s). Is DynamoRIO running?");
            return;
        }
        if orch.try_attach_ctl() {
            orch.poll_new_rings();
            if orch.ring_count() > 0 {
                eprintln!("memvis: attached, {} thread ring(s)", orch.ring_count());
                run(orch, dwarf_info, once, min_events);
                return;
            }
        }
        thread::sleep(time::Duration::from_millis(100));
    }
}

fn launch(target: &str, target_args: &[String], once: bool, min_events: u64) {
    let drrun = match find_drrun() {
        Some(p) => p,
        None => {
            eprintln!("memvis: error: cannot find drrun.");
            eprintln!("  Set DYNAMORIO_HOME or MEMVIS_DRRUN environment variable.");
            std::process::exit(1);
        }
    };
    let tracer = match find_tracer() {
        Some(p) => p,
        None => {
            eprintln!("memvis: error: cannot find libmemvis_tracer.so.");
            eprintln!("  Set MEMVIS_TRACER or build with: cd build && cmake --build .");
            std::process::exit(1);
        }
    };

    eprintln!("memvis: drrun  = {}", drrun.display());
    eprintln!("memvis: tracer = {}", tracer.display());
    eprintln!("memvis: target = {}", target);

    // clean stale shm from previous runs
    cleanup_shm();

    install_signal_handlers();

    // fork the tracer as a child process
    let mut cmd = std::process::Command::new(&drrun);
    cmd.arg("-c").arg(&tracer).arg("--").arg(target);
    for a in target_args {
        cmd.arg(a);
    }
    // redirect tracer stdout/stderr to /dev/null in TUI mode, keep in headless
    if !once {
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
    }

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("memvis: failed to launch tracer: {}", e);
            cleanup_shm();
            std::process::exit(1);
        }
    };

    let child_pid = child.id() as i32;
    TRACER_PID.store(child_pid, AtomicOrdering::SeqCst);
    eprintln!("memvis: tracer pid={}", child_pid);

    // run consumer in this process
    run_consumer(Some(target), once, min_events);

    // cleanup: kill tracer if still running, reap
    unsafe {
        libc::kill(child_pid, libc::SIGTERM);
        let mut status: libc::c_int = 0;
        libc::waitpid(child_pid, &mut status, 0);
    }
    cleanup_shm();
    eprintln!("memvis: done.");
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  memvis <target> [args...]        Launch target under tracer + TUI");
    eprintln!("  memvis --once <target> [args...]  Headless mode (print to stdout, exit)");
    eprintln!("  memvis --consumer-only [--once] [--min-events N] <target.elf>");
    eprintln!("                                    Consumer-only (tracer started separately)");
    eprintln!("");
    eprintln!("Environment:");
    eprintln!("  DYNAMORIO_HOME   Path to DynamoRIO installation");
    eprintln!("  MEMVIS_DRRUN     Explicit path to drrun binary");
    eprintln!("  MEMVIS_TRACER    Explicit path to libmemvis_tracer.so");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        std::process::exit(if args.len() < 2 { 1 } else { 0 });
    }

    // --consumer-only: legacy mode (tracer started separately)
    if args.iter().any(|a| a == "--consumer-only") {
        let once = args.iter().any(|a| a == "--once");
        let min_events: u64 = args.windows(2)
            .find(|w| w[0] == "--min-events")
            .and_then(|w| w[1].parse().ok())
            .unwrap_or(1);
        let elf_path = args.iter()
            .filter(|a| !a.starts_with('-') && *a != &args[0])
            .find(|a| a.parse::<u64>().is_err())
            .map(|s| s.as_str());
        run_consumer(elf_path, once, min_events);
        return;
    }

    // launcher mode: memvis [--once] [--min-events N] <target> [target_args...]
    let once = args.iter().any(|a| a == "--once");
    let min_events: u64 = args.windows(2)
        .find(|w| w[0] == "--min-events")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(1);

    // find the target: first positional arg that isn't a flag or flag value
    let mut skip_next = false;
    let mut target_idx = None;
    for (i, a) in args.iter().enumerate().skip(1) {
        if skip_next { skip_next = false; continue; }
        if a == "--min-events" { skip_next = true; continue; }
        if a.starts_with('-') { continue; }
        target_idx = Some(i);
        break;
    }

    let target_idx = match target_idx {
        Some(i) => i,
        None => {
            eprintln!("memvis: error: no target specified");
            print_usage();
            std::process::exit(1);
        }
    };

    let target = &args[target_idx];
    let target_args: Vec<String> = args[target_idx + 1..].to_vec();

    launch(target, &target_args, once, min_events);
}
