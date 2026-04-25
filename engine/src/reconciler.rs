// SPDX-License-Identifier: Apache-2.0

// Core event reconciler: process_event + populate_globals, extracted for library consumers.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

use crate::dwarf::{self, DwarfInfo, TypeInfo};
use crate::heap_graph::{HeapGraph, HeapOracle};
use crate::index::{AddressIndex, FrameId, NodeId};
use crate::ring::{Event, RingOrchestrator};
use crate::shadow_regs::ShadowRegisterFile;
use crate::topology::TopologyStream;
use crate::world::{HazardKind, ShadowStack, WorldState, REG_COUNT};

pub const EVENT_WRITE: u8 = 0;
pub const EVENT_READ: u8 = 1;
pub const EVENT_CALL: u8 = 2;
pub const EVENT_RETURN: u8 = 3;
pub const EVENT_REG_SNAPSHOT: u8 = 5;
pub const EVENT_CACHE_MISS: u8 = 6;
pub const EVENT_MODULE_LOAD: u8 = 7;
pub const EVENT_ALLOC: u8 = 9;
pub const EVENT_FREE: u8 = 10;
pub const EVENT_BB_ENTRY: u8 = 11;
pub const EVENT_RELOAD: u8 = 12;

/// REG_SNAPSHOT is 7 contiguous ring slots (header + 6 continuations carrying
/// regs[0..18] packed 3/slot). returns slots consumed: 7 on success, 1 on
/// short/corrupt tail so callers advance past the header.
pub fn apply_reg_snapshot(
    events: &[Event],
    world: &mut WorldState,
    shadow_regs: &mut HashMap<u16, ShadowRegisterFile>,
) -> usize {
    if events.is_empty() || events[0].kind() != EVENT_REG_SNAPSHOT {
        return 0;
    }
    if events.len() < 7 {
        return 1;
    }
    let cont = &events[1..7];
    if !cont.iter().all(|c| c.kind() == EVENT_REG_SNAPSHOT) {
        return 1;
    }
    let header = &events[0];
    let mut regs = [0u64; REG_COUNT];
    for s in 0..6usize {
        regs[s * 3] = cont[s].addr;
        regs[s * 3 + 1] = cont[s].size as u64;
        regs[s * 3 + 2] = cont[s].value;
    }
    world.update_regs(regs, header.addr);
    let srf = shadow_regs.entry(header.thread_id).or_default();
    srf.apply_snapshot(&regs, header.seq as u64, header.addr);
    7
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn process_event(
    ev: &Event,
    ring_idx: usize,
    orch: &RingOrchestrator,
    world: &mut WorldState,
    addr_index: &mut AddressIndex,
    dwarf_info: &mut Option<DwarfInfo>,
    stacks: &mut HashMap<u16, ShadowStack>,
    next_frame_id: &mut FrameId,
    relocation_delta: &mut Option<u64>,
    returned_frames: &mut VecDeque<FrameId>,
    shadow_regs: &mut HashMap<u16, ShadowRegisterFile>,
    heap_graph: &mut HeapGraph,
    heap_oracle: &mut HeapOracle,
    topo: &mut Option<TopologyStream>,
) -> bool {
    let ev_kind = ev.kind();
    match ev_kind {
        EVENT_WRITE => {
            let cl_writers = world.record_cl_write(ev.addr, ev.thread_id);
            if let Some(ref info) = dwarf_info {
                if addr_index.in_universe(ev.addr) {
                    let elf_pc = match *relocation_delta {
                        Some(d) => ev.addr.wrapping_sub(d),
                        None => ev.addr,
                    };
                    let func = info.func_containing(elf_pc);
                    let srf = shadow_regs.entry(ev.thread_id).or_default();
                    srf.observe_write(ev.addr, ev.value, elf_pc, ev.seq32() as u64, func);
                }
            }
            if cl_writers.count_ones() > 1 {
                for (&tid, srf) in shadow_regs.iter_mut() {
                    if tid != ev.thread_id {
                        srf.check_coherence(ev.addr, ev.value, ev.size, ev.seq32() as u64);
                    }
                }
            }
            if heap_oracle.is_heap(ev.addr) {
                heap_graph.process_write(
                    ev.addr,
                    ev.size,
                    ev.value,
                    ev.seq32() as u64,
                    heap_oracle,
                );
                // field heatmap: attribute this write to a typed field if STM covers it
                if let Some(covering) = world.stm.covering(ev.addr) {
                    let offset = ev.addr - covering.base_addr;
                    let tn = &covering.type_info.name;
                    if let Some(field) =
                        covering.type_info.fields.iter().find(|f| {
                            offset >= f.byte_offset && offset < f.byte_offset + f.byte_size
                        })
                    {
                        world.field_heatmap.record(
                            ev.thread_id,
                            tn,
                            &field.name,
                            field.byte_offset,
                        );
                    } else {
                        world
                            .field_heatmap
                            .record(ev.thread_id, tn, "<unresolved>", offset);
                    }
                }
                if ev.size == 8 && ev.value != 0 {
                    if let Some(ref mut ts) = topo {
                        if let Some(covering) = world.stm.covering(ev.addr) {
                            let offset = ev.addr - covering.base_addr;
                            if let Some(field) = covering
                                .type_info
                                .fields
                                .iter()
                                .find(|f| f.byte_offset == offset && f.type_info.is_pointer)
                            {
                                let pointee = field
                                    .type_info
                                    .name
                                    .strip_prefix('*')
                                    .unwrap_or(&field.type_info.name);
                                ts.emit_link(
                                    ev.seq32() as u64,
                                    &covering.type_info.name,
                                    ev.addr,
                                    ev.value,
                                    pointee,
                                    &field.name,
                                );
                            }
                        }
                    }
                }
                if let Some(ref info) = dwarf_info {
                    let before = world.stm.len();
                    world.stm.propagate_field_write(
                        ev.addr,
                        ev.value,
                        ev.size,
                        ev.seq32() as u64,
                        &info.type_registry,
                    );
                    let after = world.stm.len();
                    if after > before {
                        world.stm.retrospective_scan(
                            ev.value,
                            heap_graph,
                            &world.heap_allocs,
                            &info.type_registry,
                            ev.seq32() as u64,
                        );
                    }
                    if after > before {
                        if let Some(ref mut ts) = topo {
                            if let Some(proj) = world.stm.lookup(ev.value) {
                                ts.emit_stamp(
                                    ev.seq32() as u64,
                                    ev.value,
                                    &proj.type_info.name,
                                    proj.type_info.byte_size,
                                    &proj.source_name,
                                    proj.type_info.fields.len(),
                                );
                            }
                        }
                    }
                }
                if world.hazards.len() < 64 {
                    if let Some(mut h) = world
                        .heap_allocs
                        .check_write_bounds(ev.addr, ev.size, &world.stm)
                    {
                        let dominated = world
                            .hazards
                            .iter()
                            .any(|prev| prev.write_addr == h.write_addr);
                        if !dominated {
                            h.pc = ev.rip_lo as u64;
                            h.reg_snapshot = shadow_regs.get(&ev.thread_id).map(|srf| srf.values());
                            if let Some(ref mut ts) = topo {
                                let kind_str = match h.kind {
                                    HazardKind::OutOfBounds => "OOB",
                                    HazardKind::HeapHole => "HOLE",
                                };
                                ts.emit_hazard(
                                    ev.seq32() as u64,
                                    kind_str,
                                    h.write_addr,
                                    h.write_size,
                                    h.alloc_base,
                                    h.alloc_size,
                                    h.overflow_bytes,
                                    h.type_name.as_deref(),
                                    h.field_name.as_deref(),
                                );
                            }
                            world.hazards.push(h);
                        }
                    }
                }
            }
            if let Some(h) = addr_index.lookup(ev.addr) {
                let nid = h.node_id;
                let h_name = h.name.to_string();
                let h_type = h.type_info.clone();
                let is_ptr = h.type_info.is_pointer;
                world.ensure_node(nid, &h_name, &h_type, ev.addr, ev.size as u64);
                world.update_value(nid, ev.value, world.insn_counter());
                if is_ptr && ev.size == 8 {
                    let target = if ev.value == 0 {
                        None
                    } else {
                        addr_index.lookup(ev.value).map(|t| t.node_id)
                    };
                    world.update_edge(nid, target, ev.value);
                    if ev.value != 0 {
                        let is_heap = heap_oracle.is_heap(ev.value);
                        if is_heap {
                            if let Some(ref mut info) = dwarf_info {
                                let pointee_name =
                                    h_type.name.strip_prefix('*').unwrap_or("").to_string();
                                if info
                                    .type_registry
                                    .get(&pointee_name)
                                    .is_some_and(|ti| ti.shallow)
                                {
                                    info.resolve_deep(&pointee_name);
                                }
                                if let Some(pointee_ti) =
                                    info.type_registry.get(&pointee_name).cloned()
                                {
                                    let mut patched = pointee_ti;
                                    info.patch_shallow_fields(&mut patched);
                                    world.heap_allocs.check_size(ev.value, &patched);
                                    if world.stm.stamp_type(
                                        ev.value,
                                        &patched,
                                        &h_name,
                                        ev.seq32() as u64,
                                    ) {
                                        orch.bloom_insert(ev.value);
                                        world.stm.retrospective_scan(
                                            ev.value,
                                            heap_graph,
                                            &world.heap_allocs,
                                            &info.type_registry,
                                            ev.seq32() as u64,
                                        );
                                        if let Some(ref mut ts) = topo {
                                            ts.emit_stamp(
                                                ev.seq32() as u64,
                                                ev.value,
                                                &patched.name,
                                                patched.byte_size,
                                                &h_name,
                                                patched.fields.len(),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(ref mut ts) = topo {
                            let pointee_name =
                                h_type.name.strip_prefix('*').unwrap_or(&h_type.name);
                            ts.emit_link(
                                ev.seq32() as u64,
                                &h_name,
                                ev.addr,
                                ev.value,
                                pointee_name,
                                &h_name,
                            );
                        }
                    }
                }
                return true;
            }
            false
        }
        EVENT_CALL => {
            {
                let srf = shadow_regs.entry(ev.thread_id).or_default();
                srf.on_call(ev.addr, ev.value, ev.seq32() as u64);
            }
            heap_oracle.update_stack(ev.thread_id, ev.value);
            if let Some(ref info) = dwarf_info {
                let elf_pc = match *relocation_delta {
                    Some(d) => ev.addr.wrapping_sub(d),
                    None => ev.addr,
                };
                if let Some(func) = info.functions.get(&elf_pc) {
                    let fid = *next_frame_id;
                    *next_frame_id += 1;
                    let tid = ev.thread_id;
                    stacks
                        .entry(tid)
                        .or_insert_with(ShadowStack::new)
                        .push_call(fid, ev.addr, func.name.clone());
                    for (li, l) in func.locals.iter().enumerate() {
                        let piece = l
                            .location
                            .lookup(elf_pc)
                            .or_else(|| l.location.entries.first().map(|(_, p)| p));
                        let addr = match piece {
                            Some(dwarf::LocationPiece::FrameBaseOffset(_))
                            | Some(dwarf::LocationPiece::RegisterOffset(_, _))
                            | None => (ev.value as i64 + l.frame_offset) as u64,
                            Some(p) => {
                                let regs = world.regs();
                                dwarf::resolve_location(p, &regs, ev.value, func.frame_base_is_cfa)
                                    .unwrap_or((ev.value as i64 + l.frame_offset) as u64)
                            }
                        };
                        let nid = NodeId::Local(fid, li as u16);
                        world.ensure_node(nid, &l.name, &l.type_info, addr, l.size);
                    }
                    let locals: Vec<_> = func
                        .locals
                        .iter()
                        .map(|l| (l.frame_offset, l.size, l.name.clone(), l.type_info.clone()))
                        .collect();
                    if !locals.is_empty() {
                        addr_index.insert_frame_locals(fid, ev.value, &locals);
                    }
                }
            }
            true
        }
        EVENT_RETURN => {
            {
                let srf = shadow_regs.entry(ev.thread_id).or_default();
                if let Some(ref info) = dwarf_info {
                    let callee_pc = srf.callee_pc();
                    if let Some(saved) = callee_pc.and_then(|pc| info.cfi.saved_regs_at(pc)) {
                        srf.on_return_cfi(ev.seq32() as u64, ev.addr, saved);
                    } else {
                        srf.on_return(ev.seq32() as u64, ev.addr);
                    }
                } else {
                    srf.on_return(ev.seq32() as u64, ev.addr);
                }
            }
            let tid = ev.thread_id;
            if let Some(stack) = stacks.get_mut(&tid) {
                if let Some(frame) = stack.pop_return() {
                    addr_index.remove_frame(frame.frame_id);
                    returned_frames.push_back(frame.frame_id);
                    while returned_frames.len() > 32 {
                        if let Some(old_fid) = returned_frames.pop_front() {
                            world.remove_frame_nodes(old_fid);
                        }
                    }
                }
            }
            true
        }
        EVENT_REG_SNAPSHOT => {
            // handled by apply_reg_snapshot() on the drained batch; see note there.
            let _ = (orch, ring_idx);
            true
        }
        EVENT_CACHE_MISS => {
            if let Some(h) = addr_index.lookup(ev.addr) {
                world.record_cache_miss(h.node_id);
            }
            true
        }
        EVENT_RELOAD => {
            let reg_idx = ((ev.kind_flags >> 8) & 0xFF) as usize;
            let srf = shadow_regs.entry(ev.thread_id).or_default();
            srf.on_reload(
                reg_idx,
                ev.value,
                ev.addr,
                ev.size,
                ev.seq32() as u64,
                ev.addr,
            );
            true
        }
        EVENT_ALLOC => {
            let ptr = ev.addr;
            let size = ev.size as u64;
            if let Some(old_size) = world.heap_allocs.on_alloc(ptr, size) {
                world.stm.purge_range(ptr, old_size);
                heap_graph.on_free(ptr, old_size);
            }
            if let Some(ref mut ts) = topo {
                ts.emit_alloc(ev.seq32() as u64, ev.thread_id, ptr, size);
            }
            true
        }
        EVENT_FREE => {
            let ptr = ev.addr;
            let freed_size = world.heap_allocs.on_free(ptr);
            if let Some(old_size) = freed_size {
                world.stm.purge_range(ptr, old_size);
                heap_graph.on_free(ptr, old_size);
                if let Some(ref mut ts) = topo {
                    ts.emit_free(ev.seq32() as u64, ev.thread_id, ptr, old_size);
                }
            }
            true
        }
        EVENT_READ => {
            world.inc_insn_counter();
            if heap_oracle.is_heap(ev.addr) && ev.value != 0 {
                if let Some(covering) = world.stm.covering(ev.addr) {
                    let offset = ev.addr - covering.base_addr;
                    let tn = &covering.type_info.name;
                    if let Some(field) =
                        covering.type_info.fields.iter().find(|f| {
                            offset >= f.byte_offset && offset < f.byte_offset + f.byte_size
                        })
                    {
                        world.field_heatmap.record_read(
                            ev.thread_id,
                            tn,
                            &field.name,
                            field.byte_offset,
                        );
                    }
                }
            }
            true
        }
        EVENT_BB_ENTRY => {
            world.record_bb_entry(ev.rip_lo);
            true
        }
        EVENT_MODULE_LOAD => {
            heap_oracle.add_module(ev.addr, ev.value);
            if relocation_delta.is_none() {
                if let Some(ref info) = dwarf_info {
                    let runtime_base = ev.addr;
                    let delta = runtime_base.wrapping_sub(info.elf_base_vaddr);
                    eprintln!(
                        "memvis: relocation delta=0x{:x} (runtime=0x{:x} elf=0x{:x})",
                        delta, runtime_base, info.elf_base_vaddr
                    );
                    *relocation_delta = Some(delta);
                    *addr_index = AddressIndex::new();
                    populate_globals(info, delta, addr_index, world);
                }
            }
            true
        }
        _ => false,
    }
}

pub fn populate_globals(
    info: &DwarfInfo,
    delta: u64,
    addr_index: &mut AddressIndex,
    world: &mut WorldState,
) {
    for (i, g) in info.globals.iter().enumerate() {
        let base = g.addr.wrapping_add(delta);
        let gi = i as u32;
        addr_index.insert_global(base, g.size, g.name.clone(), g.type_info.clone(), gi);
        world.remove_node(NodeId::Global(gi));
        world.ensure_node(NodeId::Global(gi), &g.name, &g.type_info, base, g.size);
        if g.type_info.is_pointer {
            continue;
        }
        let mut fi_counter: u16 = 0;
        register_fields_recursive(
            &g.name,
            base,
            &g.type_info,
            gi,
            &mut fi_counter,
            addr_index,
            world,
            0,
        );
    }
    addr_index.finalize();
}

#[allow(clippy::too_many_arguments)]
fn register_fields_recursive(
    parent_name: &str,
    parent_base: u64,
    parent_type: &crate::dwarf::TypeInfo,
    gi: u32,
    fi_counter: &mut u16,
    addr_index: &mut AddressIndex,
    world: &mut WorldState,
    depth: u32,
) {
    if depth > 6 {
        return;
    }
    for f in &parent_type.fields {
        if f.byte_size == 0 || f.name == "<pointee>" {
            continue;
        }
        let faddr = parent_base + f.byte_offset;
        let fi = *fi_counter;
        if fi == u16::MAX {
            return;
        }
        *fi_counter = fi + 1;
        let fid = NodeId::Field(gi, fi);
        let qualified = format!("{}.{}", parent_name, f.name);
        addr_index.insert_field(
            faddr,
            f.byte_size,
            qualified.clone(),
            f.type_info.clone(),
            gi,
            fi,
        );
        world.remove_node(fid);
        world.ensure_node(fid, &qualified, &f.type_info, faddr, f.byte_size);
        if !f.type_info.is_pointer && !f.type_info.fields.is_empty() && f.byte_size > 8 {
            register_fields_recursive(
                &qualified,
                faddr,
                &f.type_info,
                gi,
                fi_counter,
                addr_index,
                world,
                depth + 1,
            );
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct WarmScanStats {
    pub reads: u64,
    pub stamps_applied: u64,
    pub max_depth_reached: u32,
    pub read_errors: u64,
    pub queue_visits: u64,
    pub enqueued: u64,
    pub null_ptrs: u64,
    pub missing_pointee_ti: u64,
    pub not_heap: u64,
    pub globals_scanned: u64,
    pub container_of_stamps: u64,
}

pub struct WarmScanner {
    mem: File,
    queue: VecDeque<(u64, TypeInfo, String, u32)>,
    visited: HashSet<u64>,
    pub stats: WarmScanStats,
    pub passes: u32,
    max_depth: u32,
    pub seeded: bool,
}

impl WarmScanner {
    pub fn new(pid: u32, max_depth: u32) -> io::Result<Self> {
        let mem = File::open(format!("/proc/{}/mem", pid))?;
        Ok(Self {
            mem,
            queue: VecDeque::new(),
            visited: HashSet::new(),
            stats: WarmScanStats::default(),
            passes: 0,
            max_depth,
            seeded: false,
        })
    }

    #[cfg(test)]
    pub fn from_file(mem: File, max_depth: u32) -> Self {
        Self {
            mem,
            queue: VecDeque::new(),
            visited: HashSet::new(),
            stats: WarmScanStats::default(),
            passes: 0,
            max_depth,
            seeded: false,
        }
    }

    pub fn is_idle(&self) -> bool {
        self.seeded && self.queue.is_empty()
    }

    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    // seed queue from globals; call before first step or to re-scan.
    pub fn seed(
        &mut self,
        info: &DwarfInfo,
        delta: u64,
        heap_oracle: &HeapOracle,
        topo: &mut Option<TopologyStream>,
    ) {
        for g in &info.globals {
            let base = g.addr.wrapping_add(delta);
            self.stats.globals_scanned += 1;
            scan_ptr_fields(
                &self.mem,
                base,
                &g.type_info,
                &g.name,
                1,
                &mut self.queue,
                &mut self.stats,
                heap_oracle,
                &info.type_registry,
                &info.container_of_map,
                topo,
                u64::MAX,
            );
        }
        self.seeded = true;
        self.passes += 1;
    }

    // process up to `budget` reads from the queue. returns stamps applied this step.
    pub fn step(
        &mut self,
        budget: u64,
        info: &DwarfInfo,
        world: &mut WorldState,
        heap_oracle: &HeapOracle,
        topo: &mut Option<TopologyStream>,
    ) -> u64 {
        let start_reads = self.stats.reads;
        let mut stamps_this_step = 0u64;

        while let Some((target_addr, pointee_ti, source_name, depth)) = self.queue.pop_front() {
            if self.stats.reads - start_reads >= budget {
                self.queue
                    .push_front((target_addr, pointee_ti, source_name, depth));
                break;
            }
            if depth > self.max_depth {
                continue;
            }
            if !self.visited.insert(target_addr) {
                continue;
            }
            self.stats.queue_visits += 1;
            self.stats.max_depth_reached = self.stats.max_depth_reached.max(depth);

            if heap_oracle.is_heap(target_addr) {
                world.heap_allocs.check_size(target_addr, &pointee_ti);
            } else {
                self.stats.not_heap += 1;
            }
            if world
                .stm
                .stamp_type(target_addr, &pointee_ti, &source_name, 0)
            {
                self.stats.stamps_applied += 1;
                stamps_this_step += 1;
                if let Some(ref mut ts) = topo {
                    ts.emit_cold_stamp(
                        target_addr,
                        &pointee_ti.name,
                        pointee_ti.byte_size,
                        &source_name,
                        pointee_ti.fields.len(),
                        depth,
                    );
                }
            }
            scan_ptr_fields(
                &self.mem,
                target_addr,
                &pointee_ti,
                &source_name,
                depth + 1,
                &mut self.queue,
                &mut self.stats,
                heap_oracle,
                &info.type_registry,
                &info.container_of_map,
                topo,
                u64::MAX,
            );
        }
        stamps_this_step
    }
}

// one-shot BFS (retained for replay and backward compat)
#[allow(clippy::too_many_arguments)]
pub fn warm_scan(
    info: &DwarfInfo,
    pid: u32,
    delta: u64,
    world: &mut WorldState,
    heap_oracle: &HeapOracle,
    topo: &mut Option<TopologyStream>,
    max_reads: u64,
    max_depth: u32,
) -> io::Result<WarmScanStats> {
    let mem_path = format!("/proc/{}/mem", pid);
    let mem = File::open(&mem_path)?;
    let mut stats = WarmScanStats::default();
    let mut visited: HashSet<u64> = HashSet::new();
    let mut queue: VecDeque<(u64, TypeInfo, String, u32)> = VecDeque::new();

    for g in &info.globals {
        if stats.reads >= max_reads {
            break;
        }
        let base = g.addr.wrapping_add(delta);
        stats.globals_scanned += 1;
        scan_ptr_fields(
            &mem,
            base,
            &g.type_info,
            &g.name,
            1,
            &mut queue,
            &mut stats,
            heap_oracle,
            &info.type_registry,
            &info.container_of_map,
            topo,
            max_reads,
        );
    }

    while let Some((target_addr, pointee_ti, source_name, depth)) = queue.pop_front() {
        if stats.reads >= max_reads {
            break;
        }
        if depth > max_depth {
            continue;
        }
        if !visited.insert(target_addr) {
            continue;
        }
        stats.queue_visits += 1;
        stats.max_depth_reached = stats.max_depth_reached.max(depth);

        let on_heap = heap_oracle.is_heap(target_addr);
        if on_heap {
            world.heap_allocs.check_size(target_addr, &pointee_ti);
        } else {
            stats.not_heap += 1;
        }
        if world
            .stm
            .stamp_type(target_addr, &pointee_ti, &source_name, 0)
        {
            stats.stamps_applied += 1;
            if let Some(ref mut ts) = topo {
                ts.emit_cold_stamp(
                    target_addr,
                    &pointee_ti.name,
                    pointee_ti.byte_size,
                    &source_name,
                    pointee_ti.fields.len(),
                    depth,
                );
            }
        }
        scan_ptr_fields(
            &mem,
            target_addr,
            &pointee_ti,
            &source_name,
            depth + 1,
            &mut queue,
            &mut stats,
            heap_oracle,
            &info.type_registry,
            &info.container_of_map,
            topo,
            max_reads,
        );
    }

    Ok(stats)
}

#[allow(clippy::only_used_in_recursion, clippy::too_many_arguments)]
fn scan_ptr_fields(
    mem: &File,
    base: u64,
    ti: &TypeInfo,
    source: &str,
    depth: u32,
    queue: &mut VecDeque<(u64, TypeInfo, String, u32)>,
    stats: &mut WarmScanStats,
    heap_oracle: &HeapOracle,
    type_registry: &HashMap<String, TypeInfo>,
    container_of_map: &HashMap<String, Vec<dwarf::ContainerOfEntry>>,
    topo: &mut Option<TopologyStream>,
    max_reads: u64,
) {
    for f in &ti.fields {
        if stats.reads >= max_reads {
            return;
        }
        if f.name == "<pointee>" {
            continue;
        }
        let faddr = base.wrapping_add(f.byte_offset);
        if f.type_info.is_pointer && f.byte_size == 8 {
            let mut buf = [0u8; 8];
            match mem.read_at(&mut buf, faddr) {
                Ok(8) => {
                    stats.reads += 1;
                    let ptr = u64::from_le_bytes(buf);
                    if ptr == 0 {
                        stats.null_ptrs += 1;
                        continue;
                    }
                    let pointee_name = f.type_info.name.strip_prefix('*').unwrap_or("");
                    let qualified = format!("{}.{}", source, f.name);
                    let pointee_ti_opt = type_registry.get(pointee_name).cloned().or_else(|| {
                        f.type_info
                            .fields
                            .iter()
                            .find(|sf| sf.name == "<pointee>")
                            .map(|sf| sf.type_info.clone())
                    });
                    match pointee_ti_opt {
                        Some(pointee_ti) if pointee_ti.byte_size > 0 => {
                            if let Some(ref mut ts) = topo {
                                ts.emit_cold_link(source, faddr, ptr, pointee_name, &f.name);
                            }
                            // container_of: if this pointee type is embedded inside
                            // a larger struct at a non-zero offset, also enqueue the
                            // container base (ptr - offset) with the container type.
                            if let Some(containers) = container_of_map.get(pointee_name) {
                                for entry in containers {
                                    let container_base = ptr.wrapping_sub(entry.field_offset);
                                    if container_base != 0 && heap_oracle.is_plausible_ptr(container_base) {
                                        if let Some(container_ti) = type_registry.get(&entry.container_type) {
                                            let cof_source = format!("{}->container_of({}.{})",
                                                qualified, entry.container_type, entry.field_name);
                                            queue.push_back((container_base, container_ti.clone(), cof_source, depth));
                                            stats.container_of_stamps += 1;
                                            stats.enqueued += 1;
                                        }
                                    }
                                }
                            }
                            queue.push_back((ptr, pointee_ti, qualified, depth));
                            stats.enqueued += 1;
                        }
                        _ => {
                            stats.missing_pointee_ti += 1;
                        }
                    }
                }
                Ok(_) | Err(_) => stats.read_errors += 1,
            }
        } else if !f.type_info.is_pointer && !f.type_info.fields.is_empty() && depth <= 6 {
            scan_ptr_fields(
                mem,
                faddr,
                &f.type_info,
                &format!("{}.{}", source, f.name),
                depth + 1,
                queue,
                stats,
                heap_oracle,
                type_registry,
                container_of_map,
                topo,
                max_reads,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap_graph::{HeapGraph, HeapOracle};
    use crate::index::AddressIndex;
    use crate::ring::{Event, RingOrchestrator};
    use crate::shadow_regs::ShadowRegisterFile;
    use crate::world::{ShadowStack, WorldState};
    use std::collections::{HashMap, VecDeque};

    fn make_bb_entry_event(rip_lo: u32) -> Event {
        Event {
            addr: 0x4000_0000 + rip_lo as u64,
            size: 0,
            thread_id: 0,
            seq: 1,
            value: 0,
            kind_flags: EVENT_BB_ENTRY as u32,
            rip_lo,
        }
    }

    fn make_unknown_event() -> Event {
        Event {
            addr: 0,
            size: 0,
            thread_id: 0,
            seq: 0,
            value: 0,
            kind_flags: 0xFF,
            rip_lo: 0,
        }
    }

    #[test]
    fn test_process_event_bb_entry() {
        let orch = RingOrchestrator::new();
        let mut world = WorldState::new();
        let mut addr_index = AddressIndex::new();
        let mut dwarf_info: Option<DwarfInfo> = None;
        let mut stacks: HashMap<u16, ShadowStack> = HashMap::new();
        let mut next_frame_id: u64 = 0;
        let mut relocation_delta: Option<u64> = None;
        let mut returned_frames: VecDeque<u64> = VecDeque::new();
        let mut shadow_regs: HashMap<u16, ShadowRegisterFile> = HashMap::new();
        let mut heap_graph = HeapGraph::new();
        let mut heap_oracle = HeapOracle::new();
        let mut topo: Option<TopologyStream> = None;

        let ev = make_bb_entry_event(0xABCD);
        let accepted = process_event(
            &ev,
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
        assert!(
            accepted,
            "BB_ENTRY must return true, not fall through to _ => false"
        );
        assert_eq!(world.insn_counter(), 1);
        assert_eq!(world.bb_hits[&0xABCD], 1);

        // second hit to same BB
        let ev2 = make_bb_entry_event(0xABCD);
        let accepted2 = process_event(
            &ev2,
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
        assert!(accepted2);
        assert_eq!(world.insn_counter(), 2);
        assert_eq!(world.bb_hits[&0xABCD], 2);

        // different BB
        let ev3 = make_bb_entry_event(0x1234);
        process_event(
            &ev3,
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
        assert_eq!(world.bb_hits.len(), 2);
        assert_eq!(world.bb_hits[&0x1234], 1);
    }

    #[test]
    fn test_process_event_read() {
        let orch = RingOrchestrator::new();
        let mut world = WorldState::new();
        let mut addr_index = AddressIndex::new();
        let mut dwarf_info: Option<DwarfInfo> = None;
        let mut stacks: HashMap<u16, ShadowStack> = HashMap::new();
        let mut next_frame_id: u64 = 0;
        let mut relocation_delta: Option<u64> = None;
        let mut returned_frames: VecDeque<u64> = VecDeque::new();
        let mut shadow_regs: HashMap<u16, ShadowRegisterFile> = HashMap::new();
        let mut heap_graph = HeapGraph::new();
        let mut heap_oracle = HeapOracle::new();
        let mut topo: Option<TopologyStream> = None;

        let ev = Event {
            addr: 0x5555_0000_1000,
            size: 8,
            thread_id: 0,
            seq: 1,
            value: 0xDEAD_BEEF,
            kind_flags: EVENT_READ as u32,
            rip_lo: 0,
        };
        let accepted = process_event(
            &ev,
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
        assert!(accepted, "EVENT_READ must be accepted");
        assert_eq!(world.insn_counter(), 1, "read must increment insn_counter");
    }

    #[test]
    fn test_abi_event_kind_parity() {
        // these must match memvis_bridge.h MEMVIS_EVENT_* defines exactly.
        // any drift here is a silent data corruption bug.
        assert_eq!(EVENT_WRITE, 0, "EVENT_WRITE != MEMVIS_EVENT_WRITE");
        assert_eq!(EVENT_READ, 1, "EVENT_READ != MEMVIS_EVENT_READ");
        assert_eq!(EVENT_CALL, 2, "EVENT_CALL != MEMVIS_EVENT_CALL");
        assert_eq!(EVENT_RETURN, 3, "EVENT_RETURN != MEMVIS_EVENT_RETURN");
        assert_eq!(
            EVENT_REG_SNAPSHOT, 5,
            "EVENT_REG_SNAPSHOT != MEMVIS_EVENT_REG_SNAPSHOT"
        );
        assert_eq!(
            EVENT_CACHE_MISS, 6,
            "EVENT_CACHE_MISS != MEMVIS_EVENT_CACHE_MISS"
        );
        assert_eq!(
            EVENT_MODULE_LOAD, 7,
            "EVENT_MODULE_LOAD != MEMVIS_EVENT_MODULE_LOAD"
        );
        assert_eq!(EVENT_ALLOC, 9, "EVENT_ALLOC != MEMVIS_EVENT_ALLOC");
        assert_eq!(EVENT_FREE, 10, "EVENT_FREE != MEMVIS_EVENT_FREE");
        assert_eq!(
            EVENT_BB_ENTRY, 11,
            "EVENT_BB_ENTRY != MEMVIS_EVENT_BB_ENTRY"
        );
        assert_eq!(EVENT_RELOAD, 12, "EVENT_RELOAD != MEMVIS_EVENT_RELOAD");
    }

    #[test]
    fn test_abi_event_struct_size() {
        // Event must be 32 bytes to match memvis_event_v3_t
        assert_eq!(
            std::mem::size_of::<Event>(),
            32,
            "Event struct size drift — ABI mismatch with memvis_event_v3_t"
        );
    }

    #[test]
    fn test_process_event_unknown_kind_rejected() {
        let orch = RingOrchestrator::new();
        let mut world = WorldState::new();
        let mut addr_index = AddressIndex::new();
        let mut dwarf_info: Option<DwarfInfo> = None;
        let mut stacks: HashMap<u16, ShadowStack> = HashMap::new();
        let mut next_frame_id: u64 = 0;
        let mut relocation_delta: Option<u64> = None;
        let mut returned_frames: VecDeque<u64> = VecDeque::new();
        let mut shadow_regs: HashMap<u16, ShadowRegisterFile> = HashMap::new();
        let mut heap_graph = HeapGraph::new();
        let mut heap_oracle = HeapOracle::new();
        let mut topo: Option<TopologyStream> = None;

        let ev = make_unknown_event();
        let accepted = process_event(
            &ev,
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
        assert!(!accepted, "unknown kind must return false");
        assert_eq!(world.insn_counter(), 0);
        assert!(world.bb_hits.is_empty());
    }

    // a→b→c pointer chain in a synthetic pread-able file
    fn make_synthetic_mem() -> (std::fs::File, dwarf::DwarfInfo) {
        use std::collections::BTreeMap;
        use std::os::unix::fs::FileExt;
        let path = &format!("/tmp/memvis_test_synth_mem_{:?}", std::thread::current().id());
        let f = std::fs::File::create(path).unwrap();
        let mut buf = vec![0u8; 0x4000];
        buf[0x1000..0x1008].copy_from_slice(&0x2000u64.to_le_bytes());
        buf[0x2000..0x2008].copy_from_slice(&0x3000u64.to_le_bytes());
        buf[0x3000..0x3004].copy_from_slice(&42u32.to_le_bytes());
        f.write_all_at(&buf, 0).unwrap();

        let mk = |name: &str, sz: u64, ptr: bool, fields: Vec<dwarf::FieldInfo>| dwarf::TypeInfo {
            name: name.into(),
            byte_size: sz,
            is_pointer: ptr,
            is_volatile: false,
            is_atomic: false,
            shallow: false,
            fields,
        };
        let loc = dwarf::LocationTable { entries: vec![] };
        let ti_c = mk(
            "struct_c",
            4,
            false,
            vec![dwarf::FieldInfo {
                name: "val".into(),
                byte_offset: 0,
                byte_size: 4,
                type_info: mk("int", 4, false, vec![]),
                alignment: 0,
            }],
        );
        let ti_b = mk(
            "struct_b",
            8,
            false,
            vec![dwarf::FieldInfo {
                name: "ptr_to_c".into(),
                byte_offset: 0,
                byte_size: 8,
                type_info: mk(
                    "*struct_c",
                    8,
                    true,
                    vec![dwarf::FieldInfo {
                        name: "<pointee>".into(),
                        byte_offset: 0,
                        byte_size: 4,
                        type_info: ti_c.clone(),
                        alignment: 0,
                    }],
                ),
                alignment: 0,
            }],
        );
        let ti_a = mk(
            "struct_a",
            8,
            false,
            vec![dwarf::FieldInfo {
                name: "ptr_to_b".into(),
                byte_offset: 0,
                byte_size: 8,
                type_info: mk(
                    "*struct_b",
                    8,
                    true,
                    vec![dwarf::FieldInfo {
                        name: "<pointee>".into(),
                        byte_offset: 0,
                        byte_size: 8,
                        type_info: ti_b.clone(),
                        alignment: 0,
                    }],
                ),
                alignment: 0,
            }],
        );

        let mut type_registry: HashMap<String, dwarf::TypeInfo> = HashMap::new();
        type_registry.insert("struct_a".into(), ti_a.clone());
        type_registry.insert("struct_b".into(), ti_b);
        type_registry.insert("struct_c".into(), ti_c);

        let info = dwarf::DwarfInfo {
            globals: vec![dwarf::GlobalVar {
                name: "global_a".into(),
                addr: 0x1000,
                size: 8,
                type_info: ti_a,
                location: loc,
            }],
            functions: BTreeMap::new(),
            elf_base_vaddr: 0,
            type_registry,
            container_of_map: HashMap::new(),
            cfi: dwarf::CfiTable::default(),
            elf_path: String::new(),
        };
        let f = std::fs::File::open(path).unwrap();
        (f, info)
    }

    #[test]
    fn test_warm_scanner_full_traversal() {
        let (mem, info) = make_synthetic_mem();
        let mut scanner = WarmScanner::from_file(mem, 8);
        let mut world = WorldState::new();
        let oracle = HeapOracle::new();
        let mut topo: Option<TopologyStream> = None;

        assert!(!scanner.seeded);
        scanner.seed(&info, 0, &oracle, &mut topo);
        assert!(scanner.seeded);
        assert!(!scanner.is_idle());

        let stamps = scanner.step(1000, &info, &mut world, &oracle, &mut topo);
        assert!(stamps > 0);
        assert!(scanner.is_idle());
        assert_eq!(scanner.passes, 1);
        assert!(scanner.stats.reads > 0);
    }

    #[test]
    fn test_warm_scanner_budget_exhaustion_and_resume() {
        let (mem, info) = make_synthetic_mem();
        let mut scanner = WarmScanner::from_file(mem, 8);
        let mut world = WorldState::new();
        let oracle = HeapOracle::new();
        let mut topo: Option<TopologyStream> = None;

        scanner.seed(&info, 0, &oracle, &mut topo);
        let mut total_stamps = 0u64;
        let mut steps = 0u32;
        while !scanner.is_idle() {
            total_stamps += scanner.step(1, &info, &mut world, &oracle, &mut topo);
            steps += 1;
            assert!(steps < 100, "runaway BFS");
        }

        // parity: step-by-step == one-shot
        let (mem2, info2) = make_synthetic_mem();
        let mut sc2 = WarmScanner::from_file(mem2, 8);
        let mut w2 = WorldState::new();
        sc2.seed(&info2, 0, &oracle, &mut topo);
        let oneshot = sc2.step(1000, &info2, &mut w2, &oracle, &mut topo);

        assert_eq!(
            total_stamps, oneshot,
            "step-by-step stamps != one-shot stamps"
        );
        assert_eq!(
            scanner.stats.reads, sc2.stats.reads,
            "step-by-step reads != one-shot reads"
        );
    }

    #[test]
    fn test_warm_scanner_reseed() {
        let (mem, info) = make_synthetic_mem();
        let mut scanner = WarmScanner::from_file(mem, 8);
        let mut world = WorldState::new();
        let oracle = HeapOracle::new();
        let mut topo: Option<TopologyStream> = None;

        scanner.seed(&info, 0, &oracle, &mut topo);
        scanner.step(1000, &info, &mut world, &oracle, &mut topo);
        assert!(scanner.is_idle());
        assert_eq!(scanner.passes, 1);
        let r1 = scanner.stats.reads;

        scanner.seed(&info, 0, &oracle, &mut topo);
        assert_eq!(scanner.passes, 2);
        scanner.step(1000, &info, &mut world, &oracle, &mut topo);
        assert!(scanner.is_idle());
        assert!(scanner.stats.reads >= r1);
    }
}
