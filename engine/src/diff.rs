// SPDX-License-Identifier: Apache-2.0
// memvis-diff: Replay two .bin recordings, diff ASLR-invariant topology at checkpoints.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io::{self, Write};
use std::path::Path;
use std::process;

use memvis::dwarf::{self, DwarfInfo};
use memvis::heap_graph::{HeapGraph, HeapOracle};
use memvis::index::{AddressIndex, FrameId};
use memvis::record::EventPlayer;
use memvis::reconciler;
use memvis::shadow_regs::ShadowRegisterFile;
use memvis::world::{HazardKind, ShadowStack, WorldState};

struct Args {
    baseline: String,
    subject: String,
    dwarf_path: String,
    interval: u64,
    output: Option<String>,
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut baseline = None;
    let mut subject = None;
    let mut dwarf_path = None;
    let mut interval = 100_000u64;
    let mut output = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--baseline" | "-a" => { i += 1; baseline = Some(args[i].clone()); }
            "--subject" | "-b" => { i += 1; subject = Some(args[i].clone()); }
            "--dwarf" | "-d" => { i += 1; dwarf_path = Some(args[i].clone()); }
            "--interval" | "-n" => { i += 1; interval = args[i].parse().unwrap_or(100_000); }
            "--output" | "-o" => { i += 1; output = Some(args[i].clone()); }
            "--help" | "-h" => {
                eprintln!("memvis-diff: compare two recorded traces");
                eprintln!("  --baseline/-a <file>  baseline recording (.bin)");
                eprintln!("  --subject/-b <file>   subject recording (.bin)");
                eprintln!("  --dwarf/-d <file>     ELF binary with debug info");
                eprintln!("  --interval/-n <N>     checkpoint every N events (default: 100000)");
                eprintln!("  --output/-o <file>    output JSONL divergence report");
                process::exit(0);
            }
            other => {
                eprintln!("memvis-diff: unknown argument: {}", other);
                process::exit(1);
            }
        }
        i += 1;
    }

    Args {
        baseline: baseline.unwrap_or_else(|| { eprintln!("memvis-diff: --baseline required"); process::exit(1); }),
        subject: subject.unwrap_or_else(|| { eprintln!("memvis-diff: --subject required"); process::exit(1); }),
        dwarf_path: dwarf_path.unwrap_or_else(|| { eprintln!("memvis-diff: --dwarf required"); process::exit(1); }),
        interval,
        output,
    }
}

// address-stripped topology primitives

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct CanonicalStamp {
    source: String,
    type_name: String,
    type_size: u64,
    field_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct CanonicalAlloc {
    size: u64,
    type_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct CanonicalHazard {
    kind: String,
    write_size: u32,
    type_name: Option<String>,
    field_name: Option<String>,
    pc: u64,
}

// register context at hazard time (not part of hazard identity)
#[derive(Debug, Clone)]
struct HazardRegContext {
    pc: u64,
    rax: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rsp: u64,
}

#[derive(Debug, Clone)]
struct TopologyCheckpoint {
    seq: u64,
    stamps: BTreeSet<CanonicalStamp>,
    type_histogram: BTreeMap<String, u64>,
    alloc_histogram: BTreeMap<u64, u64>,
    hazards: Vec<CanonicalHazard>,
    hazard_regs: Vec<Option<HazardRegContext>>,
    stamp_count: usize,
    alloc_count: usize,
    hazard_count: usize,
}

fn take_checkpoint(seq: u64, world: &WorldState) -> TopologyCheckpoint {
    let mut stamps = BTreeSet::new();
    for (_, proj) in world.stm.iter() {
        stamps.insert(CanonicalStamp {
            source: proj.source_name.clone(),
            type_name: proj.type_info.name.clone(),
            type_size: proj.type_info.byte_size,
            field_count: proj.type_info.fields.len(),
        });
    }

    let mut type_histogram: BTreeMap<String, u64> = BTreeMap::new();
    for s in &stamps {
        *type_histogram.entry(s.type_name.clone()).or_insert(0) += 1;
    }

    let mut alloc_histogram: BTreeMap<u64, u64> = BTreeMap::new();
    for (_, &size) in world.heap_allocs.allocs_iter() {
        *alloc_histogram.entry(size).or_insert(0) += 1;
    }

    let mut hazards = Vec::new();
    let mut hazard_regs = Vec::new();
    for h in &world.hazards {
        hazards.push(CanonicalHazard {
            kind: match h.kind { HazardKind::OutOfBounds => "OOB".into(), HazardKind::HeapHole => "HOLE".into() },
            write_size: h.write_size,
            type_name: h.type_name.clone(),
            field_name: h.field_name.clone(),
            pc: h.pc,
        });
        hazard_regs.push(h.reg_snapshot.map(|r| HazardRegContext {
            pc: h.pc,
            rax: r[0], rdi: r[5], rsi: r[4], rdx: r[3], rsp: r[7],
        }));
    }

    let stamp_count = stamps.len();
    let alloc_count = world.heap_allocs.live_count();
    let hazard_count = hazards.len();

    TopologyCheckpoint {
        seq,
        stamps,
        type_histogram,
        alloc_histogram,
        hazards,
        hazard_regs,
        stamp_count,
        alloc_count,
        hazard_count,
    }
}

fn replay_to_checkpoints(
    recording_path: &str,
    dwarf_info: &Option<DwarfInfo>,
    interval: u64,
) -> io::Result<Vec<TopologyCheckpoint>> {
    let mut player = EventPlayer::open(Path::new(recording_path))?;
    let total_events = player.event_count();
    eprintln!("  replaying {} ({} events)", recording_path, total_events);

    let mut world = WorldState::new();
    let mut addr_index = AddressIndex::new();
    let mut stacks: HashMap<u16, ShadowStack> = HashMap::new();
    let mut next_frame_id: FrameId = 0;
    let mut relocation_delta: Option<u64> = None;
    let mut returned_frames: VecDeque<FrameId> = VecDeque::new();
    let mut shadow_regs: HashMap<u16, ShadowRegisterFile> = HashMap::new();
    let mut heap_graph = HeapGraph::new();
    let mut heap_oracle = HeapOracle::new();
    let mut topo: Option<memvis::topology::TopologyStream> = None;

    if let Some(ref info) = dwarf_info {
        reconciler::populate_globals(info, 0, &mut addr_index, &mut world);
    }

    let mut checkpoints = Vec::new();
    let mut seq: u64 = 0;
    let mut next_checkpoint = interval;
    let mut batch = Vec::with_capacity(4096);
    let mut need_finalize = false;

    let orch = memvis::ring::RingOrchestrator::new_offline();

    loop {
        batch.clear();
        let got = player.read_batch(&mut batch, 4096)?;
        if got == 0 { break; }

        let mut i = 0;
        while i < batch.len() {
            let ev = &batch[i];
            seq += 1;
            let ev_kind = ev.kind();

            if ev_kind == reconciler::EVENT_REG_SNAPSHOT {
                // reconstruct register array from header + 6 continuations
                if i + 6 < batch.len() {
                    let mut regs = [0u64; 18];
                    for s in 0..6usize {
                        let c = &batch[i + 1 + s];
                        regs[s * 3] = c.addr;
                        regs[s * 3 + 1] = c.size as u64;
                        regs[s * 3 + 2] = c.value;
                    }
                    world.update_regs(regs, ev.addr);
                    let srf = shadow_regs.entry(ev.thread_id).or_default();
                    srf.apply_snapshot(&regs, ev.seq as u64, ev.addr);
                    seq += 6;
                    i += 7;
                } else {
                    i += 1;
                }
                continue;
            }

            reconciler::process_event(
                ev, 0, &orch,
                &mut world, &mut addr_index, dwarf_info,
                &mut stacks, &mut next_frame_id,
                &mut relocation_delta, &mut returned_frames,
                &mut shadow_regs, &mut heap_graph, &mut heap_oracle,
                &mut topo,
            );

            if ev_kind == reconciler::EVENT_CALL {
                need_finalize = true;
            }

            if seq >= next_checkpoint {
                if need_finalize {
                    addr_index.finalize();
                    need_finalize = false;
                }
                checkpoints.push(take_checkpoint(seq, &world));
                next_checkpoint += interval;
            }
            i += 1;
        }
    }

    if need_finalize {
        addr_index.finalize();
    }
    checkpoints.push(take_checkpoint(seq, &world));
    eprintln!("  {} checkpoints, final seq={}", checkpoints.len(), seq);

    Ok(checkpoints)
}

#[derive(Debug)]
struct CheckpointDiff {
    seq_a: u64,
    seq_b: u64,
    stamps_only_a: Vec<CanonicalStamp>,
    stamps_only_b: Vec<CanonicalStamp>,
    hazards_only_a: Vec<(CanonicalHazard, Option<HazardRegContext>)>,
    hazards_only_b: Vec<(CanonicalHazard, Option<HazardRegContext>)>,
    alloc_count_a: usize,
    alloc_count_b: usize,
    stamp_count_a: usize,
    stamp_count_b: usize,
    identical: bool,
}

fn diff_checkpoints(
    a: &TopologyCheckpoint,
    b: &TopologyCheckpoint,
    common_mask: Option<&BTreeSet<CanonicalStamp>>,
) -> CheckpointDiff {
    let raw_only_a: BTreeSet<CanonicalStamp> = a.stamps.difference(&b.stamps).cloned().collect();
    let raw_only_b: BTreeSet<CanonicalStamp> = b.stamps.difference(&a.stamps).cloned().collect();

    // filter out stamps that converge in the final state (discovery-order noise)
    let (stamps_only_a, stamps_only_b): (Vec<CanonicalStamp>, Vec<CanonicalStamp>) =
        if let Some(mask) = common_mask {
            (
                raw_only_a.difference(mask).cloned().collect(),
                raw_only_b.difference(mask).cloned().collect(),
            )
        } else {
            (raw_only_a.into_iter().collect(), raw_only_b.into_iter().collect())
        };

    let hazards_a: BTreeSet<&CanonicalHazard> = a.hazards.iter().collect();
    let hazards_b: BTreeSet<&CanonicalHazard> = b.hazards.iter().collect();

    let hazards_only_a: Vec<(CanonicalHazard, Option<HazardRegContext>)> = hazards_a.difference(&hazards_b)
        .map(|&h| {
            let idx = a.hazards.iter().position(|x| x == h);
            let ctx = idx.and_then(|i| a.hazard_regs.get(i).cloned().flatten());
            (h.clone(), ctx)
        }).collect();
    let hazards_only_b: Vec<(CanonicalHazard, Option<HazardRegContext>)> = hazards_b.difference(&hazards_a)
        .map(|&h| {
            let idx = b.hazards.iter().position(|x| x == h);
            let ctx = idx.and_then(|i| b.hazard_regs.get(i).cloned().flatten());
            (h.clone(), ctx)
        }).collect();


    let identical = stamps_only_a.is_empty()
        && stamps_only_b.is_empty()
        && hazards_only_a.is_empty()
        && hazards_only_b.is_empty();

    CheckpointDiff {
        seq_a: a.seq,
        seq_b: b.seq,
        stamps_only_a,
        stamps_only_b,
        hazards_only_a,
        hazards_only_b,
        alloc_count_a: a.alloc_count,
        alloc_count_b: b.alloc_count,
        stamp_count_a: a.stamp_count,
        stamp_count_b: b.stamp_count,
        identical,
    }
}

fn emit_diff_jsonl(out: &mut impl Write, diff: &CheckpointDiff) -> io::Result<()> {
    if diff.identical {
        writeln!(out,
            r#"{{"checkpoint_a":{},"checkpoint_b":{},"status":"identical","stamps_a":{},"stamps_b":{},"allocs_a":{},"allocs_b":{}}}"#,
            diff.seq_a, diff.seq_b, diff.stamp_count_a, diff.stamp_count_b,
            diff.alloc_count_a, diff.alloc_count_b)?;
    } else {
        for s in &diff.stamps_only_a {
            writeln!(out,
                r#"{{"checkpoint_a":{},"checkpoint_b":{},"status":"diverged","side":"baseline_only","source":"{}","type":"{}","type_size":{},"fields":{}}}"#,
                diff.seq_a, diff.seq_b, s.source, s.type_name, s.type_size, s.field_count)?;
        }
        for s in &diff.stamps_only_b {
            writeln!(out,
                r#"{{"checkpoint_a":{},"checkpoint_b":{},"status":"diverged","side":"subject_only","source":"{}","type":"{}","type_size":{},"fields":{}}}"#,
                diff.seq_a, diff.seq_b, s.source, s.type_name, s.type_size, s.field_count)?;
        }
        for (h, ctx) in &diff.hazards_only_a {
            let reg_str = ctx.as_ref().map(|r| format!(
                r#","pc":"0x{:x}","rax":"0x{:x}","rdi":"0x{:x}","rsi":"0x{:x}","rdx":"0x{:x}","rsp":"0x{:x}""#,
                r.pc, r.rax, r.rdi, r.rsi, r.rdx, r.rsp)).unwrap_or_default();
            writeln!(out,
                r#"{{"checkpoint_a":{},"checkpoint_b":{},"status":"diverged","side":"baseline_only","hazard":"{}","write_size":{},"type":"{}","field":"{}"{}}}"#,
                diff.seq_a, diff.seq_b, h.kind, h.write_size,
                h.type_name.as_deref().unwrap_or("?"),
                h.field_name.as_deref().unwrap_or("?"), reg_str)?;
        }
        for (h, ctx) in &diff.hazards_only_b {
            let reg_str = ctx.as_ref().map(|r| format!(
                r#","pc":"0x{:x}","rax":"0x{:x}","rdi":"0x{:x}","rsi":"0x{:x}","rdx":"0x{:x}","rsp":"0x{:x}""#,
                r.pc, r.rax, r.rdi, r.rsi, r.rdx, r.rsp)).unwrap_or_default();
            writeln!(out,
                r#"{{"checkpoint_a":{},"checkpoint_b":{},"status":"diverged","side":"subject_only","hazard":"{}","write_size":{},"type":"{}","field":"{}"{}}}"#,
                diff.seq_a, diff.seq_b, h.kind, h.write_size,
                h.type_name.as_deref().unwrap_or("?"),
                h.field_name.as_deref().unwrap_or("?"), reg_str)?;
        }
    }
    Ok(())
}

fn print_steady_state(a: &TopologyCheckpoint, b: &TopologyCheckpoint) {
    eprintln!("\n── Steady-State (final checkpoint) ──────────────");
    eprintln!("  baseline: seq={} stamps={} allocs={} hazards={}",
        a.seq, a.stamp_count, a.alloc_count, a.hazards.len());
    eprintln!("  subject:  seq={} stamps={} allocs={} hazards={}",
        b.seq, b.stamp_count, b.alloc_count, b.hazards.len());

    // type histogram delta: immune to discovery order and ASLR
    let mut delta: BTreeMap<&str, (i64, i64)> = BTreeMap::new();
    for (name, &count) in &a.type_histogram {
        delta.entry(name).or_insert((0, 0)).0 = count as i64;
    }
    for (name, &count) in &b.type_histogram {
        delta.entry(name).or_insert((0, 0)).1 = count as i64;
    }
    let mut diffs_found = false;
    for (name, (ca, cb)) in &delta {
        if ca != cb {
            if !diffs_found {
                eprintln!("  type histogram delta (A vs B):");
                diffs_found = true;
            }
            eprintln!("    {:+4} {:+4}  {}", ca, cb, name);
        }
    }
    if !diffs_found {
        eprintln!("  type histograms identical");
    }

    let ha: BTreeSet<&CanonicalHazard> = a.hazards.iter().collect();
    let hb: BTreeSet<&CanonicalHazard> = b.hazards.iter().collect();
    let only_a: Vec<_> = ha.difference(&hb).collect();
    let only_b: Vec<_> = hb.difference(&ha).collect();
    if !only_a.is_empty() || !only_b.is_empty() {
        eprintln!("  hazard delta:");
        for h in &only_a {
            let idx = a.hazards.iter().position(|x| x == **h);
            let ctx = idx.and_then(|i| a.hazard_regs.get(i).cloned().flatten());
            eprint!("    - [baseline] {} type={} field={}",
                h.kind, h.type_name.as_deref().unwrap_or("?"),
                h.field_name.as_deref().unwrap_or("?"));
            if let Some(r) = ctx { eprint!(" pc=0x{:x} rax=0x{:x}", r.pc, r.rax); }
            eprintln!();
        }
        for h in &only_b {
            let idx = b.hazards.iter().position(|x| x == **h);
            let ctx = idx.and_then(|i| b.hazard_regs.get(i).cloned().flatten());
            eprint!("    + [subject]  {} type={} field={}",
                h.kind, h.type_name.as_deref().unwrap_or("?"),
                h.field_name.as_deref().unwrap_or("?"));
            if let Some(r) = ctx { eprint!(" pc=0x{:x} rax=0x{:x}", r.pc, r.rax); }
            eprintln!();
        }
    }
}

fn print_summary(diffs: &[CheckpointDiff]) {
    let total = diffs.len();
    let identical = diffs.iter().filter(|d| d.identical).count();
    let diverged = total - identical;

    eprintln!("\n══════════════════════════════════════════════════");
    eprintln!("  memvis-diff: {} checkpoints compared", total);
    eprintln!("  identical: {}  diverged: {}", identical, diverged);

    if diverged == 0 {
        eprintln!("  ✓ topologies are identical across all checkpoints");
        eprintln!("══════════════════════════════════════════════════");
        return;
    }

    if let Some(first) = diffs.iter().find(|d| !d.identical) {
        eprintln!("  first divergence at seq A={} / B={}", first.seq_a, first.seq_b);
        if !first.stamps_only_a.is_empty() {
            eprintln!("    baseline-only stamps:");
            for s in first.stamps_only_a.iter().take(10) {
                eprintln!("      {} → {} ({}B, {} fields)", s.source, s.type_name, s.type_size, s.field_count);
            }
        }
        if !first.stamps_only_b.is_empty() {
            eprintln!("    subject-only stamps:");
            for s in first.stamps_only_b.iter().take(10) {
                eprintln!("      {} → {} ({}B, {} fields)", s.source, s.type_name, s.type_size, s.field_count);
            }
        }
        if !first.hazards_only_a.is_empty() {
            eprintln!("    baseline-only hazards:");
            for (h, ctx) in &first.hazards_only_a {
                eprint!("      {} write_size={} type={} field={}",
                    h.kind, h.write_size,
                    h.type_name.as_deref().unwrap_or("?"),
                    h.field_name.as_deref().unwrap_or("?"));
                if let Some(r) = ctx {
                    eprint!(" pc=0x{:x} rax=0x{:x} rdi=0x{:x}", r.pc, r.rax, r.rdi);
                }
                eprintln!();
            }
        }
        if !first.hazards_only_b.is_empty() {
            eprintln!("    subject-only hazards:");
            for (h, ctx) in &first.hazards_only_b {
                eprint!("      {} write_size={} type={} field={}",
                    h.kind, h.write_size,
                    h.type_name.as_deref().unwrap_or("?"),
                    h.field_name.as_deref().unwrap_or("?"));
                if let Some(r) = ctx {
                    eprint!(" pc=0x{:x} rax=0x{:x} rdi=0x{:x}", r.pc, r.rax, r.rdi);
                }
                eprintln!();
            }
        }
    }

    let mut all_only_a: BTreeMap<String, usize> = BTreeMap::new();
    let mut all_only_b: BTreeMap<String, usize> = BTreeMap::new();
    for d in diffs.iter().filter(|d| !d.identical) {
        for s in &d.stamps_only_a { *all_only_a.entry(s.type_name.clone()).or_insert(0) += 1; }
        for s in &d.stamps_only_b { *all_only_b.entry(s.type_name.clone()).or_insert(0) += 1; }
    }
    if !all_only_a.is_empty() {
        eprintln!("  type distribution (baseline-only across all checkpoints):");
        for (name, count) in all_only_a.iter().take(10) {
            eprintln!("    {}×  {}", count, name);
        }
    }
    if !all_only_b.is_empty() {
        eprintln!("  type distribution (subject-only across all checkpoints):");
        for (name, count) in all_only_b.iter().take(10) {
            eprintln!("    {}×  {}", count, name);
        }
    }

    eprintln!("══════════════════════════════════════════════════");
}

fn main() {
    let args = parse_args();

    eprintln!("memvis-diff: baseline={} subject={}", args.baseline, args.subject);
    eprintln!("  dwarf={} interval={}", args.dwarf_path, args.interval);

    let dwarf_info = match dwarf::parse_elf(&args.dwarf_path) {
        Ok(info) => Some(info),
        Err(e) => {
            eprintln!("memvis-diff: DWARF parse failed: {}", e);
            None
        }
    };

    eprintln!("\n── Baseline ────────────────────────────────────");
    let checkpoints_a = match replay_to_checkpoints(&args.baseline, &dwarf_info, args.interval) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("memvis-diff: failed to replay baseline: {}", e);
            process::exit(1);
        }
    };

    eprintln!("\n── Subject ─────────────────────────────────────");
    let checkpoints_b = match replay_to_checkpoints(&args.subject, &dwarf_info, args.interval) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("memvis-diff: failed to replay subject: {}", e);
            process::exit(1);
        }
    };

    // common stamp mask: stamps present in both final checkpoints are noise
    let common_mask: Option<BTreeSet<CanonicalStamp>> =
        match (checkpoints_a.last(), checkpoints_b.last()) {
            (Some(fa), Some(fb)) => {
                let mask: BTreeSet<CanonicalStamp> = fa.stamps.intersection(&fb.stamps).cloned().collect();
                if mask.is_empty() { None } else {
                    eprintln!("  common stamp mask: {} stamps filtered from intermediate diffs", mask.len());
                    Some(mask)
                }
            }
            _ => None,
        };

    let pairs = checkpoints_a.len().min(checkpoints_b.len());
    let mut diffs: Vec<CheckpointDiff> = Vec::with_capacity(pairs);
    for i in 0..pairs {
        let is_final = i == pairs - 1;
        let mask = if is_final { None } else { common_mask.as_ref() };
        diffs.push(diff_checkpoints(&checkpoints_a[i], &checkpoints_b[i], mask));
    }

    if checkpoints_a.len() > pairs {
        eprintln!("  note: baseline has {} extra checkpoints beyond subject", checkpoints_a.len() - pairs);
    }
    if checkpoints_b.len() > pairs {
        eprintln!("  note: subject has {} extra checkpoints beyond baseline", checkpoints_b.len() - pairs);
    }

    if let Some(ref path) = args.output {
        match std::fs::File::create(path) {
            Ok(file) => {
                let mut out = io::BufWriter::new(file);
                for d in &diffs {
                    let _ = emit_diff_jsonl(&mut out, d);
                }
                let _ = out.flush();
                eprintln!("  wrote divergence report to {}", path);
            }
            Err(e) => eprintln!("  failed to create output file: {}", e),
        }
    } else {
        let stdout = io::stdout();
        let mut out = io::BufWriter::new(stdout.lock());
        for d in &diffs {
            let _ = emit_diff_jsonl(&mut out, d);
        }
        let _ = out.flush();
    }

    // steady-state: compare final checkpoints (order-invariant type histogram)
    if let (Some(final_a), Some(final_b)) = (checkpoints_a.last(), checkpoints_b.last()) {
        print_steady_state(final_a, final_b);
    }

    print_summary(&diffs);
}
