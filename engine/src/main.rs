// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering as AtomicOrdering};
use std::{env, thread, time};

use memvis::dwarf::{self, DwarfInfo};
use memvis::heap_graph::{HeapGraph, HeapOracle};
use memvis::index::{AddressIndex, FrameId, NodeId};
use memvis::reconciler::{self, EVENT_CALL, EVENT_REG_SNAPSHOT};
use memvis::record::{EventPlayer, EventRecorder};
use memvis::ring::{Event, RingOrchestrator};
use memvis::shadow_regs::ShadowRegisterFile;
use memvis::topology::TopologyStream;
use memvis::tui::{self, AppState, JournalEntry};
use memvis::world::{ShadowStack, SnapshotRing, WorldState};

// process_event and populate_globals are in memvis::reconciler (library crate).
// this file is just a thin CLI shell over the library.

fn run(
    mut orch: RingOrchestrator,
    mut dwarf_info: Option<DwarfInfo>,
    once: bool,
    min_events: u64,
    record_path: Option<String>,
    topo_path: Option<String>,
    heatmap_path: Option<String>,
) {
    let mut addr_index = AddressIndex::new();
    let mut world = WorldState::new();
    let mut stacks: HashMap<u16, ShadowStack> = HashMap::new();
    let mut next_frame_id: FrameId = 1;
    let mut total: u64 = 0;
    let mut journal: VecDeque<JournalEntry> = VecDeque::with_capacity(1024);
    let mut relocation_delta: Option<u64> = None;
    let mut returned_frames: VecDeque<FrameId> = VecDeque::with_capacity(64);
    let mut expected_seq: HashMap<u16, u32> = HashMap::new();
    let mut seq_gaps: u64 = 0;
    let mut shadow_regs: HashMap<u16, ShadowRegisterFile> = HashMap::new();
    let mut heap_graph = HeapGraph::new();
    let mut heap_oracle = HeapOracle::new();

    if let Some(ref info) = dwarf_info {
        reconciler::populate_globals(info, 0, &mut addr_index, &mut world);
        heap_graph.init_candidates(info);
    }

    let mut recorder: Option<EventRecorder> =
        record_path
            .as_ref()
            .and_then(|p| match EventRecorder::create(std::path::Path::new(p)) {
                Ok(r) => {
                    eprintln!("memvis: recording to {}", p);
                    Some(r)
                }
                Err(e) => {
                    eprintln!("memvis: failed to create recording: {}", e);
                    None
                }
            });

    let mut topo: Option<TopologyStream> =
        topo_path
            .as_ref()
            .and_then(|p| match TopologyStream::create(std::path::Path::new(p)) {
                Ok(t) => {
                    eprintln!("memvis: topology stream → {}", p);
                    Some(t)
                }
                Err(e) => {
                    eprintln!("memvis: failed to create topology stream: {}", e);
                    None
                }
            });

    if once {
        run_headless(
            &mut orch,
            &mut dwarf_info,
            min_events,
            &mut addr_index,
            &mut world,
            &mut stacks,
            &mut next_frame_id,
            &mut total,
            &mut journal,
            &mut relocation_delta,
            &mut returned_frames,
            &mut shadow_regs,
            &mut heap_graph,
            &mut heap_oracle,
            &mut recorder,
            &mut topo,
        );
        if let Some(ref mut ts) = topo {
            ts.emit_summary(
                total,
                world.node_count(),
                world.edge_count(),
                world.stm.len(),
                world.heap_allocs.live_count(),
                world.hazards.len(),
            );
        }
        if let Some(rec) = recorder {
            match rec.finish() {
                Ok(n) => eprintln!("memvis: recorded {} events", n),
                Err(e) => eprintln!("memvis: recording finalize error: {}", e),
            }
        }
        if let Some(ts) = topo {
            match ts.finish() {
                Ok(n) => eprintln!("memvis: topology: {} lines", n),
                Err(e) => eprintln!("memvis: topology finalize error: {}", e),
            }
        }
        if let Some(ref hp) = heatmap_path {
            match world.field_heatmap.export_tsv(std::path::Path::new(hp)) {
                Ok(()) => eprintln!("memvis: heatmap exported to {}", hp),
                Err(e) => eprintln!("memvis: heatmap export error: {}", e),
            }
        }
        return;
    }

    let mut terminal = match tui::init_terminal() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("memvis: failed to init terminal: {}", e);
            return;
        }
    };
    let mut app = AppState::new();
    let mut snap_ring = SnapshotRing::new(512);
    let mut tick: u64 = 0;
    let refresh = time::Duration::from_millis(50);
    let mut last_render = time::Instant::now();
    let mut last_discovery = time::Instant::now();
    let mut batch_buf: Vec<(usize, memvis::ring::Event)> = Vec::with_capacity(128_000);
    let mut warm_scan_done = false;
    let mut warm_idle_rounds: u32 = 0;

    loop {
        tui::handle_input(&mut app);
        if app.quit {
            break;
        }

        let now_disc = time::Instant::now();
        if now_disc.duration_since(last_discovery) >= time::Duration::from_millis(200) {
            orch.poll_new_rings();
            last_discovery = now_disc;
        }

        if !app.paused {
            let mut need_finalize = false;
            let mut tick_events = 0usize;
            const TICK_BUDGET: usize = 200_000;
            while tick_events < TICK_BUDGET {
                batch_buf.clear();
                let got = orch.batch_drain(4096, &mut batch_buf);
                if got == 0 {
                    break;
                }
                tick_events += got;

                let mut i = 0;
                while i < batch_buf.len() {
                    let (ri, ev) = batch_buf[i];
                    let ev_kind = ev.kind();

                    // snapshots live fully inside batch_buf; ring side pop_n raced.
                    if ev_kind == EVENT_REG_SNAPSHOT {
                        let slice_end = (i + 7).min(batch_buf.len());
                        let mut events7: [memvis::ring::Event; 7] =
                            [memvis::ring::Event::zero(); 7];
                        let take = slice_end - i;
                        for s in 0..take {
                            events7[s] = batch_buf[i + s].1;
                        }
                        let consumed = reconciler::apply_reg_snapshot(
                            &events7[..take],
                            &mut world,
                            &mut shadow_regs,
                        )
                        .max(1);
                        if let Some(ref mut rec) = recorder {
                            let _ = rec.record_reg_snapshot(&ev, &world.regs());
                        }
                        total += consumed as u64;
                        world.inc_insn_counter();
                        let s32 = ev.seq32();
                        let exp = expected_seq.entry(ev.thread_id).or_insert(s32);
                        *exp = s32.wrapping_add(1);
                        i += consumed;
                        continue;
                    }

                    total += 1;
                    world.inc_insn_counter();

                    let s32 = ev.seq32();
                    let exp = expected_seq.entry(ev.thread_id).or_insert(s32);
                    if s32 != *exp {
                        seq_gaps += 1;
                    }
                    *exp = s32.wrapping_add(1);

                    let interesting = reconciler::process_event(
                        &ev,
                        ri,
                        &orch,
                        &mut world,
                        &mut addr_index,
                        &mut dwarf_info,
                        &mut stacks,
                        &mut next_frame_id,
                        &mut relocation_delta,
                        &mut returned_frames,
                        &mut shadow_regs,
                        &mut heap_graph,
                        &mut heap_oracle,
                        &mut topo,
                    );
                    if let Some(ref mut rec) = recorder {
                        let _ = rec.record(&ev);
                    }
                    if interesting {
                        journal.push_back(JournalEntry {
                            seq: total,
                            kind: ev_kind,
                            thread_id: ev.thread_id,
                            addr: ev.addr,
                            size: ev.size,
                            value: ev.value,
                        });
                        if journal.len() > 1000 {
                            journal.pop_front();
                        }
                    }
                    if ev_kind == EVENT_CALL {
                        need_finalize = true;
                    }
                    i += 1;
                }
            } // while tick_events < TICK_BUDGET

            if need_finalize {
                addr_index.finalize();
            }
            if total & 0xFFF == 0 {
                world.cache_heat_tick();
                world.cl_tracker_tick();
            }
            if total & 0xFFFF == 0 {
                heap_graph.gc_stale(total, 500_000);
            }
            orch.update_backpressure();

            if tick_events == 0 {
                warm_idle_rounds += 1;
            } else {
                warm_idle_rounds = 0;
            }
            if !warm_scan_done
                && relocation_delta.is_some()
                && total > 2_000_000
                && warm_idle_rounds >= 10
            {
                if let (Some(ref info), Some(pid), Some(delta)) =
                    (&dwarf_info, orch.target_pid(), relocation_delta)
                {
                    match reconciler::warm_scan(info, pid, delta, &mut world, &heap_oracle, &mut topo, 10_000, 8) {
                        Ok(s) => eprintln!(
                            "memvis: warm-scan: globals={} reads={} null={} missing_ti={} enqueued={} stamps={} depth={} errors={} not_heap={}",
                            s.globals_scanned, s.reads, s.null_ptrs, s.missing_pointee_ti,
                            s.enqueued, s.stamps_applied, s.max_depth_reached, s.read_errors, s.not_heap),
                        Err(e) => eprintln!("memvis: warm-scan failed: {}", e),
                    }
                }
                warm_scan_done = true;
            }
        }

        let now = time::Instant::now();
        if now.duration_since(last_render) >= refresh {
            let live_snap = world.snapshot();
            tick += 1;
            snap_ring.push(live_snap.clone(), tick, total);

            let display_snap = match app.time_travel_idx {
                Some(idx) => snap_ring
                    .get(idx)
                    .map(|sr| sr.snap.clone())
                    .unwrap_or(live_snap),
                None => live_snap,
            };

            let (fill_used, fill_pct) = orch.total_fill();
            let snap_total = snap_ring.len();
            tui::draw(
                &mut terminal,
                &display_snap,
                &world.cl_tracker,
                &world.stm,
                &journal,
                total,
                orch.ring_count(),
                fill_used,
                fill_pct,
                &mut app,
                snap_total,
                &stacks,
                seq_gaps,
                &shadow_regs,
                &heap_graph,
            );
            last_render = now;
        }

        if !app.paused {
            thread::sleep(time::Duration::from_millis(5));
        } else {
            thread::sleep(time::Duration::from_millis(20));
        }
    }

    if let Some(ref mut ts) = topo {
        ts.emit_summary(
            total,
            world.node_count(),
            world.edge_count(),
            world.stm.len(),
            world.heap_allocs.live_count(),
            world.hazards.len(),
        );
    }
    if let Some(rec) = recorder {
        match rec.finish() {
            Ok(n) => eprintln!("memvis: recorded {} events", n),
            Err(e) => eprintln!("memvis: recording finalize error: {}", e),
        }
    }
    if let Some(ts) = topo {
        match ts.finish() {
            Ok(n) => eprintln!("memvis: topology: {} lines", n),
            Err(e) => eprintln!("memvis: topology finalize error: {}", e),
        }
    }
    tui::restore_terminal(&mut terminal);
}

#[allow(clippy::too_many_arguments)]
fn run_headless(
    orch: &mut RingOrchestrator,
    dwarf_info: &mut Option<DwarfInfo>,
    _min_events: u64,
    addr_index: &mut AddressIndex,
    world: &mut WorldState,
    stacks: &mut HashMap<u16, ShadowStack>,
    next_frame_id: &mut FrameId,
    total: &mut u64,
    journal: &mut VecDeque<JournalEntry>,
    relocation_delta: &mut Option<u64>,
    returned_frames: &mut VecDeque<FrameId>,
    shadow_regs: &mut HashMap<u16, ShadowRegisterFile>,
    heap_graph: &mut HeapGraph,
    heap_oracle: &mut HeapOracle,
    recorder: &mut Option<EventRecorder>,
    recorder_topo: &mut Option<TopologyStream>,
) {
    use std::io::Write;
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let mut last_discovery = time::Instant::now();
    let mut batch_buf: Vec<(usize, memvis::ring::Event)> = Vec::with_capacity(128_000);
    let mut idle_rounds: u32 = 0;
    let mut warm_scan_done = false;

    loop {
        let now_disc = time::Instant::now();
        if now_disc.duration_since(last_discovery) >= time::Duration::from_millis(200) {
            orch.poll_new_rings();
            last_discovery = now_disc;
        }

        let mut need_finalize = false;
        let mut drained = 0usize;
        let mut tick_events = 0usize;
        const HEADLESS_BUDGET: usize = 500_000;
        while tick_events < HEADLESS_BUDGET {
            batch_buf.clear();
            let got = orch.batch_drain(4096, &mut batch_buf);
            if got == 0 {
                break;
            }
            tick_events += got;
            drained += got;

            let mut i = 0;
            while i < batch_buf.len() {
                let (ri, ev) = batch_buf[i];
                let ev_kind = ev.kind();

                if ev_kind == EVENT_REG_SNAPSHOT {
                    let slice_end = (i + 7).min(batch_buf.len());
                    let mut events7: [memvis::ring::Event; 7] = [memvis::ring::Event::zero(); 7];
                    let take = slice_end - i;
                    for s in 0..take {
                        events7[s] = batch_buf[i + s].1;
                    }
                    let consumed =
                        reconciler::apply_reg_snapshot(&events7[..take], world, shadow_regs).max(1);
                    if let Some(ref mut rec) = recorder {
                        let _ = rec.record_reg_snapshot(&ev, &world.regs());
                    }
                    *total += consumed as u64;
                    world.inc_insn_counter();
                    i += consumed;
                    continue;
                }

                *total += 1;
                world.inc_insn_counter();

                let interesting = reconciler::process_event(
                    &ev,
                    ri,
                    orch,
                    world,
                    addr_index,
                    &mut *dwarf_info,
                    stacks,
                    next_frame_id,
                    relocation_delta,
                    returned_frames,
                    shadow_regs,
                    heap_graph,
                    heap_oracle,
                    recorder_topo,
                );
                if let Some(ref mut rec) = recorder {
                    let _ = rec.record(&ev);
                }
                if interesting {
                    journal.push_back(JournalEntry {
                        seq: *total,
                        kind: ev_kind,
                        thread_id: ev.thread_id,
                        addr: ev.addr,
                        size: ev.size,
                        value: ev.value,
                    });
                    if journal.len() > 1000 {
                        journal.pop_front();
                    }
                }
                if ev_kind == EVENT_CALL {
                    need_finalize = true;
                }
                i += 1;
            }
        }

        if need_finalize {
            addr_index.finalize();
        }

        if drained == 0 {
            idle_rounds += 1;
            // after seeing events, if the ring stays empty for 50 consecutive
            // rounds (~500ms), the target has finished. render final snapshot.
            if *total > 0 && idle_rounds >= 50 {
                let snap = world.snapshot();
                headless_render(
                    &mut out,
                    &snap,
                    &world.cl_tracker,
                    &world.stm,
                    &world.heap_allocs,
                    &world.hazards,
                    &world.field_heatmap,
                    journal,
                    *total,
                    orch,
                    heap_graph,
                );
                let _ = out.flush();
                return;
            }
            thread::sleep(time::Duration::from_millis(10));
        } else {
            idle_rounds = 0;
        }

        orch.update_backpressure();

        if *total & 0xFFF == 0 {
            world.cache_heat_tick();
            world.cl_tracker_tick();
        }

        if !warm_scan_done
            && relocation_delta.is_some()
            && *total > 2_000_000
            && drained == 0
            && idle_rounds >= 10
        {
            if let (Some(ref info), Some(pid), Some(delta)) =
                (&*dwarf_info, orch.target_pid(), *relocation_delta)
            {
                match reconciler::warm_scan(info, pid, delta, world, heap_oracle, recorder_topo, 10_000, 8) {
                    Ok(s) => eprintln!(
                        "memvis: warm-scan: globals={} reads={} null={} missing_ti={} enqueued={} stamps={} depth={} errors={} not_heap={}",
                        s.globals_scanned, s.reads, s.null_ptrs, s.missing_pointee_ti,
                        s.enqueued, s.stamps_applied, s.max_depth_reached, s.read_errors, s.not_heap),
                    Err(e) => eprintln!("memvis: warm-scan failed: {}", e),
                }
            }
            warm_scan_done = true;
        }

        // safety valve: if we've been running a long time with no tracer, bail
        if GOT_SIGNAL.load(AtomicOrdering::Relaxed) {
            break;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn headless_render(
    out: &mut impl std::io::Write,
    world: &memvis::world::WorldInner,
    cl_tracker: &memvis::world::CacheLineTracker,
    stm: &memvis::world::ShadowTypeMap,
    heap_allocs: &memvis::world::HeapAllocTracker,
    hazards: &[memvis::world::HeapHazard],
    field_heatmap: &memvis::world::FieldHeatmap,
    journal: &VecDeque<JournalEntry>,
    total: u64,
    orch: &RingOrchestrator,
    heap_graph: &HeapGraph,
) {
    let (lag, _) = orch.total_fill();
    let lag_str = if lag >= 1_000_000 {
        format!("{}M", lag / 1_000_000)
    } else if lag >= 1_000 {
        format!("{}K", lag / 1_000)
    } else {
        format!("{}", lag)
    };
    let _ = writeln!(
        out,
        "MEMVIS │ insn {} │ events {} │ nodes {} │ edges {} │ rings {} │ LAG {} │ allocs {}/{} live {}{}",
        world.insn_counter,
        total,
        world.nodes.len(),
        world.edges.len(),
        orch.ring_count(),
        lag_str,
        heap_allocs.total_allocs,
        heap_allocs.total_frees,
        heap_allocs.live_count(),
        if heap_allocs.orphan_frees > 0 {
            format!(" orphan_free={}", heap_allocs.orphan_frees)
        } else {
            String::new()
        },
    );
    let _ = writeln!(out, "{}", "─".repeat(100));
    let _ = writeln!(out, "MEMORY MAP");

    let mut sorted: Vec<_> = world.nodes.iter().filter(|(_, n)| n.size > 0).collect();
    sorted.sort_by_key(|(_, n)| (n.addr, std::cmp::Reverse(n.last_write_insn)));
    sorted.dedup_by(|a, b| {
        matches!(a.0, NodeId::Local(..))
            && matches!(b.0, NodeId::Local(..))
            && a.1.addr == b.1.addr
            && a.1.name == b.1.name
    });

    let mut by_pri: Vec<_> = world.nodes.iter().collect();
    by_pri.sort_by_key(|(nid, _)| match nid {
        NodeId::Field(..) => 0u8,
        NodeId::Global(_) => 1,
        NodeId::Local(..) => 2,
    });
    let mut addr_names: HashMap<u64, String> = HashMap::with_capacity(by_pri.len());
    for (_, n) in &by_pri {
        addr_names.insert(n.addr, n.name.clone());
    }
    let resolve = |val: u64| -> String {
        if val == 0 {
            return String::new();
        }
        match addr_names.get(&val) {
            Some(name) => format!("  → {}", name),
            None => format!("  → 0x{:x}", val),
        }
    };

    let mut last_cl: u64 = u64::MAX;
    for (nid, node) in &sorted {
        if matches!(nid, NodeId::Field(..)) {
            continue;
        }
        let cl = node.addr / 64;
        if cl != last_cl {
            let fs = cl_tracker.contention_score(node.addr);
            let fs_tag = if fs > 1 {
                format!(" FALSE_SHARE T={}", fs)
            } else {
                String::new()
            };
            let _ = writeln!(out, "  ── cacheline 0x{:x} ──{}", cl * 64, fs_tag);
            last_cl = cl;
        }
        let ptr_info = if node.type_info.is_pointer && node.raw_value != 0 {
            resolve(node.raw_value)
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "  {:>12x}  {:>4}B  {:<20} {:<14}  val={:>18x}{}",
            node.addr, node.size, node.name, node.type_info.name, node.raw_value, ptr_info
        );
        if let NodeId::Global(gi) = nid {
            if !node.type_info.is_pointer {
                for (fi, f) in node.type_info.fields.iter().enumerate() {
                    if f.byte_size == 0 || f.name == "<pointee>" {
                        continue;
                    }
                    let fa = node.addr + f.byte_offset;
                    let fid = NodeId::Field(*gi, fi as u16);
                    let fval = world.nodes.get(&fid).map(|n| n.raw_value).unwrap_or(0);
                    let fptr = if f.type_info.is_pointer && fval != 0 {
                        resolve(fval)
                    } else {
                        String::new()
                    };
                    let _ = writeln!(
                        out,
                        "    {:>12x}  {:>4}B  {:<20} {:<14}  val={:>18x}{}",
                        fa, f.byte_size, f.name, f.type_info.name, fval, fptr
                    );
                }
            }
        }
    }

    if !stm.is_empty() {
        let _ = writeln!(
            out,
            "\nHEAP TYPES (Shadow Type Map: {} projections)",
            stm.len()
        );
        let mut stm_sorted: Vec<_> = stm.iter().collect();
        stm_sorted.sort_by_key(|(addr, _)| *addr);
        for (&base, proj) in &stm_sorted {
            let _ = writeln!(
                out,
                "  {:>12x}  {:>4}B  {:<20} (via {})",
                base, proj.type_info.byte_size, proj.type_info.name, proj.source_name
            );
            for f in &proj.type_info.fields {
                if f.byte_size == 0 {
                    continue;
                }
                let fa = base + f.byte_offset;
                let ptr_tag = if f.type_info.is_pointer {
                    if let Some(tgt) = stm.lookup(fa) {
                        format!("  → {} (0x{:x})", tgt.type_info.name, tgt.base_addr)
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                let _ = writeln!(
                    out,
                    "    {:>12x}  {:>4}B  {:<20} {:<14}{}",
                    fa, f.byte_size, f.name, f.type_info.name, ptr_tag
                );
            }
        }
    }

    if !heap_allocs.size_mismatches.is_empty() {
        let _ = writeln!(
            out,
            "\n⚠ HEAP SIZE MISMATCHES ({} detected)",
            heap_allocs.size_mismatches.len()
        );
        for m in &heap_allocs.size_mismatches {
            let _ = writeln!(
                out,
                "  0x{:x}: type {} needs {}B but alloc only {}B",
                m.addr, m.type_name, m.type_size, m.alloc_size
            );
        }
    }

    {
        let objs = heap_graph.objects();
        let typed = objs.values().filter(|o| o.inferred_type.is_some()).count();
        let _ = writeln!(
            out,
            "\nHEAP GRAPH: {} objects, {} typed, {} rescores, {} contradictions",
            objs.len(),
            typed,
            heap_graph.rescores,
            heap_graph.contradictions
        );
        for obj in objs.values().filter(|o| o.inferred_type.is_some()) {
            let _ = writeln!(
                out,
                "  {:>12x}  {:>4}B  {:<30} conf={:.2}  fields={}  writes={}",
                obj.base_addr,
                obj.inferred_size,
                obj.inferred_type.as_deref().unwrap_or("?"),
                obj.type_confidence,
                obj.fields.len(),
                obj.fields
                    .values()
                    .map(|f| f.write_count as u64)
                    .sum::<u64>(),
            );
        }
    }

    if !hazards.is_empty() {
        use memvis::world::HazardKind;
        let oob = hazards
            .iter()
            .filter(|h| matches!(h.kind, HazardKind::OutOfBounds))
            .count();
        let hole = hazards.len() - oob;
        let _ = writeln!(out, "\n🛑 HEAP HAZARDS ({} OOB, {} heap-hole)", oob, hole);
        for h in hazards {
            match h.kind {
                HazardKind::OutOfBounds => {
                    let sym = match (&h.type_name, &h.field_name) {
                        (Some(t), Some(f)) => format!(" (intended for {}.{})", t, f),
                        (Some(t), None) => format!(" (within {})", t),
                        _ => String::new(),
                    };
                    let _ = writeln!(
                        out,
                        "  OOB  0x{:x} +{}B exceeds alloc [0x{:x}..+{}] by {}B{}",
                        h.write_addr,
                        h.write_size,
                        h.alloc_base,
                        h.alloc_size,
                        h.overflow_bytes,
                        sym
                    );
                }
                HazardKind::HeapHole => {
                    let sym = h
                        .type_name
                        .as_ref()
                        .map(|t| format!(" (stale {} projection)", t))
                        .unwrap_or_default();
                    let _ = writeln!(
                        out,
                        "  HOLE 0x{:x} +{}B not in any live allocation{}",
                        h.write_addr, h.write_size, sym
                    );
                }
            }
        }
    }

    // field heatmap: top writes + contention report
    if !field_heatmap.is_empty() {
        let _ = writeln!(
            out,
            "\n FIELD WRITE HEATMAP ({} distinct entries)",
            field_heatmap.len()
        );
        let _ = writeln!(
            out,
            "  Top 20 hottest fields (thread, type.field, offset, writes):"
        );
        for (key, count) in field_heatmap.top_entries(20) {
            let _ = writeln!(
                out,
                "    T{:<3} {}.{:<24} +0x{:<4x} {:>10} writes",
                key.thread_id, key.type_name, key.field_name, key.field_offset, count
            );
        }
        let contention = field_heatmap.contention_report(cl_tracker);
        if !contention.is_empty() {
            let _ = writeln!(
                out,
                "\n CROSS-THREAD FIELD CONTENTION ({} fields written by multiple threads):",
                contention.len()
            );
            for ce in contention.iter().take(20) {
                let thread_detail: Vec<String> = ce
                    .threads
                    .iter()
                    .map(|(tid, cnt)| format!("T{}={}", tid, cnt))
                    .collect();
                let _ = writeln!(
                    out,
                    "    {}.{:<24} +0x{:<4x} total={:<10} [{}]",
                    ce.type_name,
                    ce.field_name,
                    ce.field_offset,
                    ce.total_writes,
                    thread_detail.join(", ")
                );
            }
        }
    }

    if field_heatmap.read_len() > 0 {
        let _ = writeln!(
            out,
            "\n FIELD READ HEATMAP ({} distinct entries)",
            field_heatmap.read_len()
        );
        let _ = writeln!(
            out,
            "  Top 20 hottest reads (thread, type.field, offset, reads):"
        );
        for (key, count) in field_heatmap.top_read_entries(20) {
            let _ = writeln!(
                out,
                "    T{:<3} {}.{:<24} +0x{:<4x} {:>10} reads",
                key.thread_id, key.type_name, key.field_name, key.field_offset, count
            );
        }
    }

    if !world.edges.is_empty() {
        let _ = writeln!(out, "\nPOINTER EDGES");
        let mut seen: std::collections::HashSet<(String, u64)> = std::collections::HashSet::new();
        for (src, edge) in &world.edges {
            let src_name = world
                .nodes
                .get(src)
                .map(|n| n.name.clone())
                .unwrap_or_default();
            let key = (src_name.clone(), edge.ptr_value);
            if !seen.insert(key) {
                continue;
            }
            let tgt_name = addr_names
                .get(&edge.ptr_value)
                .map(|s| s.as_str())
                .unwrap_or("?");
            let _ = writeln!(
                out,
                "  {} ──> {} (0x{:x})",
                src_name, tgt_name, edge.ptr_value
            );
        }
    }

    let tail_n = 12usize;
    let start = if journal.len() > tail_n {
        journal.len() - tail_n
    } else {
        0
    };
    let _ = writeln!(out, "\nEVENTS (last {})", tail_n);
    for e in journal.iter().skip(start) {
        let kind_str = match e.kind {
            0 => "W",
            1 => "R",
            2 => "CALL",
            3 => "RET",
            4 => "OVF",
            5 => "REG",
            6 => "CMIS",
            7 => "MLOAD",
            8 => "TCALL",
            12 => "RLOAD",
            _ => "?",
        };
        let _ = writeln!(
            out,
            "  {:>8} {:<5} T{:<3} {:>12x}  {:>4}  {:>16x}",
            e.seq, kind_str, e.thread_id, e.addr, e.size, e.value
        );
    }
}

fn run_replay(replay_path: &str, elf_path: Option<&str>, _once: bool, topo_path: Option<String>) {
    use std::io::Write;

    let mut dwarf_info: Option<DwarfInfo> = elf_path.and_then(|path| {
        eprintln!("memvis: parsing DWARF from {}", path);
        match dwarf::parse_elf(path) {
            Ok(info) => {
                eprintln!(
                    "memvis: {} globals, {} functions",
                    info.globals.len(),
                    info.functions.len()
                );
                Some(info)
            }
            Err(e) => {
                eprintln!("memvis: DWARF parse failed: {}", e);
                None
            }
        }
    });

    let mut player = match EventPlayer::open(std::path::Path::new(replay_path)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("memvis: failed to open recording: {}", e);
            return;
        }
    };
    eprintln!(
        "memvis: replaying {} events from {}",
        player.event_count(),
        replay_path
    );

    let mut addr_index = AddressIndex::new();
    let mut world = WorldState::new();
    let mut stacks: HashMap<u16, ShadowStack> = HashMap::new();
    let mut next_frame_id: FrameId = 1;
    let mut total: u64 = 0;
    let mut journal: VecDeque<JournalEntry> = VecDeque::with_capacity(1024);
    let mut relocation_delta: Option<u64> = None;
    let mut returned_frames: VecDeque<FrameId> = VecDeque::with_capacity(64);
    let mut shadow_regs: HashMap<u16, ShadowRegisterFile> = HashMap::new();
    let mut heap_graph = HeapGraph::new();
    let mut heap_oracle = HeapOracle::new();
    if let Some(ref info) = dwarf_info {
        heap_graph.init_candidates(info);
    }
    // dummy orchestrator for headless_render (LAG will be 0)
    let orch = RingOrchestrator::new();

    let mut topo: Option<TopologyStream> =
        topo_path
            .as_ref()
            .and_then(|p| match TopologyStream::create(std::path::Path::new(p)) {
                Ok(t) => {
                    eprintln!("memvis: topology stream → {}", p);
                    Some(t)
                }
                Err(e) => {
                    eprintln!("memvis: failed to create topology stream: {}", e);
                    None
                }
            });

    if let Some(ref info) = dwarf_info {
        reconciler::populate_globals(info, 0, &mut addr_index, &mut world);
    }

    let mut event_buf: Vec<Event> = Vec::with_capacity(4096);
    loop {
        event_buf.clear();
        let got = match player.read_batch(&mut event_buf, 4096) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("memvis: replay read error: {}", e);
                break;
            }
        };
        if got == 0 {
            break;
        }

        let mut need_finalize = false;
        let mut i = 0;
        while i < event_buf.len() {
            let ev = &event_buf[i];
            let ev_kind = ev.kind();

            if ev_kind == EVENT_REG_SNAPSHOT {
                let consumed =
                    reconciler::apply_reg_snapshot(&event_buf[i..], &mut world, &mut shadow_regs)
                        .max(1);
                total += consumed as u64;
                world.inc_insn_counter();
                i += consumed;
                continue;
            }

            total += 1;
            world.inc_insn_counter();

            let interesting = reconciler::process_event(
                ev,
                0,
                &orch,
                &mut world,
                &mut addr_index,
                &mut dwarf_info,
                &mut stacks,
                &mut next_frame_id,
                &mut relocation_delta,
                &mut returned_frames,
                &mut shadow_regs,
                &mut heap_graph,
                &mut heap_oracle,
                &mut topo,
            );
            if interesting {
                journal.push_back(JournalEntry {
                    seq: total,
                    kind: ev_kind,
                    thread_id: ev.thread_id,
                    addr: ev.addr,
                    size: ev.size,
                    value: ev.value,
                });
                if journal.len() > 1000 {
                    journal.pop_front();
                }
            }
            if ev_kind == EVENT_CALL {
                need_finalize = true;
            }
            i += 1;
        }
        if need_finalize {
            addr_index.finalize();
        }
        if total & 0xFFF == 0 {
            world.cache_heat_tick();
            world.cl_tracker_tick();
        }
        if total & 0xFFFF == 0 {
            heap_graph.gc_stale(total, 500_000);
        }
    }

    if let Some(ref mut ts) = topo {
        ts.emit_summary(
            total,
            world.node_count(),
            world.edge_count(),
            world.stm.len(),
            world.heap_allocs.live_count(),
            world.hazards.len(),
        );
    }
    if let Some(ts) = topo {
        match ts.finish() {
            Ok(n) => eprintln!("memvis: topology: {} lines", n),
            Err(e) => eprintln!("memvis: topology finalize error: {}", e),
        }
    }

    eprintln!("memvis: replay complete, {} events processed", total);
    let snap = world.snapshot();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    headless_render(
        &mut out,
        &snap,
        &world.cl_tracker,
        &world.stm,
        &world.heap_allocs,
        &world.hazards,
        &world.field_heatmap,
        &journal,
        total,
        &orch,
        &heap_graph,
    );
    let _ = out.flush();
}

fn cleanup_shm() {
    // remove ctl ring
    unsafe {
        libc::shm_unlink(c"/memvis_ctl".as_ptr());
    }
    // remove per-thread rings (best effort, up to 256)
    for i in 0..256u32 {
        let name = format!("/memvis_ring_{}\0", i);
        unsafe {
            libc::shm_unlink(name.as_ptr() as *const libc::c_char);
        }
    }
}

fn find_drrun() -> Option<std::path::PathBuf> {
    // 1. MEMVIS_DRRUN env var (explicit override)
    if let Ok(p) = env::var("MEMVIS_DRRUN") {
        let path = std::path::PathBuf::from(&p);
        if path.exists() {
            return Some(path);
        }
    }
    // 2. DYNAMORIO_HOME env var
    if let Ok(home) = env::var("DYNAMORIO_HOME") {
        let path = std::path::PathBuf::from(&home).join("bin64/drrun");
        if path.exists() {
            return Some(path);
        }
    }
    // 3. PATH lookup
    if let Ok(output) = std::process::Command::new("which").arg("drrun").output() {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(std::path::PathBuf::from(s));
            }
        }
    }
    None
}

fn find_tracer() -> Option<std::path::PathBuf> {
    // 1. MEMVIS_TRACER env var
    if let Ok(p) = env::var("MEMVIS_TRACER") {
        let path = std::path::PathBuf::from(&p);
        if path.exists() {
            return Some(path);
        }
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
                    if canon.exists() {
                        return Some(canon);
                    }
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
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGINT,
            signal_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            signal_handler as *const () as libc::sighandler_t,
        );
    }
}

fn run_consumer(
    elf_path: Option<&str>,
    once: bool,
    min_events: u64,
    record_path: Option<String>,
    topo_path: Option<String>,
    heatmap_path: Option<String>,
) {
    let dwarf_info: Option<DwarfInfo> = elf_path.and_then(|path| {
        eprintln!("memvis: parsing DWARF from {}", path);
        match dwarf::parse_elf(path) {
            Ok(info) => {
                eprintln!(
                    "memvis: {} globals, {} functions",
                    info.globals.len(),
                    info.functions.len()
                );
                Some(info)
            }
            Err(e) => {
                eprintln!("memvis: DWARF parse failed: {}", e);
                None
            }
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
                run(
                    orch,
                    dwarf_info,
                    once,
                    min_events,
                    record_path,
                    topo_path,
                    heatmap_path,
                );
                return;
            }
        }
        thread::sleep(time::Duration::from_millis(100));
    }
}

fn launch(
    target: &str,
    target_args: &[String],
    once: bool,
    min_events: u64,
    record_path: Option<String>,
    topo_path: Option<String>,
    heatmap_path: Option<String>,
) {
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

    // run consumer on a thread with 64MB stack (DWARF parsing of complex
    // struct types like kernel sched.c can overflow the default 8MB stack)
    let target_owned = target.to_string();
    let handle = thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            run_consumer(
                Some(&target_owned),
                once,
                min_events,
                record_path,
                topo_path,
                heatmap_path,
            )
        })
        .expect("memvis: failed to spawn consumer thread");
    let _ = handle.join();

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
    eprintln!("  memvis --record <file> [--once] <target>  Record events to file");
    eprintln!("  memvis --replay <file> [--once] <target.elf>  Replay recorded events");
    eprintln!("  memvis --export-topology <file.jsonl> [--once] <target>  Stream graph deltas");
    eprintln!("  memvis --export-heatmap <file.tsv> [--once] <target>  Export field write heatmap");
    eprintln!("  memvis --consumer-only [--once] <target.elf>");
    eprintln!("                                    Consumer-only (tracer started separately)");
    eprintln!();
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

    let once = args.iter().any(|a| a == "--once");
    let min_events: u64 = args
        .windows(2)
        .find(|w| w[0] == "--min-events")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(1);
    let record_path: Option<String> = args
        .windows(2)
        .find(|w| w[0] == "--record")
        .map(|w| w[1].clone());
    let replay_path: Option<String> = args
        .windows(2)
        .find(|w| w[0] == "--replay")
        .map(|w| w[1].clone());
    let topo_path: Option<String> = args
        .windows(2)
        .find(|w| w[0] == "--export-topology")
        .map(|w| w[1].clone());
    let heatmap_path: Option<String> = args
        .windows(2)
        .find(|w| w[0] == "--export-heatmap")
        .map(|w| w[1].clone());

    // --replay mode: read events from file, no tracer needed
    if let Some(ref rp) = replay_path {
        let tp_ref = topo_path.as_deref().unwrap_or("");
        let elf_path: Option<String> = args
            .iter()
            .filter(|a| !a.starts_with('-') && *a != &args[0] && *a != rp && a.as_str() != tp_ref)
            .find(|a| a.parse::<u64>().is_err())
            .cloned();
        let rp_owned = rp.clone();
        let tp_owned = topo_path.clone();
        let handle = thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || run_replay(&rp_owned, elf_path.as_deref(), once, tp_owned))
            .expect("memvis: failed to spawn replay thread");
        let _ = handle.join();
        return;
    }

    // --consumer-only: legacy mode (tracer started separately)
    if args.iter().any(|a| a == "--consumer-only") {
        let elf_path: Option<String> = args
            .iter()
            .filter(|a| !a.starts_with('-') && *a != &args[0])
            .find(|a| a.parse::<u64>().is_err())
            .cloned();
        let handle = thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                run_consumer(
                    elf_path.as_deref(),
                    once,
                    min_events,
                    record_path,
                    topo_path,
                    heatmap_path,
                )
            })
            .expect("memvis: failed to spawn consumer thread");
        let _ = handle.join();
        return;
    }

    let mut skip_next = false;
    let mut target_idx = None;
    for (i, a) in args.iter().enumerate().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if a == "--min-events"
            || a == "--record"
            || a == "--replay"
            || a == "--export-topology"
            || a == "--export-heatmap"
        {
            skip_next = true;
            continue;
        }
        if a.starts_with('-') {
            continue;
        }
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

    launch(
        target,
        &target_args,
        once,
        min_events,
        record_path,
        topo_path,
        heatmap_path,
    );
}
