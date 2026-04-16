// SPDX-License-Identifier: MIT

// Core event reconciler: process_event + populate_globals, extracted for library consumers.

use std::collections::{HashMap, VecDeque};

use crate::dwarf::{self, DwarfInfo};
use crate::heap_graph::{HeapGraph, HeapOracle};
use crate::index::{AddressIndex, FrameId, NodeId};
use crate::ring::{Event, RingOrchestrator};
use crate::shadow_regs::ShadowRegisterFile;
use crate::topology::TopologyStream;
use crate::world::{HazardKind, ShadowStack, WorldState, REG_COUNT};

pub const EVENT_WRITE: u8 = 0;
pub const EVENT_CALL: u8 = 2;
pub const EVENT_RETURN: u8 = 3;
pub const EVENT_REG_SNAPSHOT: u8 = 5;
pub const EVENT_CACHE_MISS: u8 = 6;
pub const EVENT_MODULE_LOAD: u8 = 7;
pub const EVENT_ALLOC: u8 = 9;
pub const EVENT_FREE: u8 = 10;
pub const EVENT_RELOAD: u8 = 12;

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn process_event(
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
                    srf.observe_write(ev.addr, ev.value, elf_pc, ev.seq as u64, func);
                }
            }
            if cl_writers.count_ones() > 1 {
                for (&tid, srf) in shadow_regs.iter_mut() {
                    if tid != ev.thread_id {
                        srf.check_coherence(ev.addr, ev.value, ev.size, ev.seq as u64);
                    }
                }
            }
            if heap_oracle.is_heap(ev.addr) {
                heap_graph.process_write(ev.addr, ev.size, ev.value, ev.seq as u64, heap_oracle);
                if ev.size == 8 && ev.value != 0 {
                    if let Some(ref mut ts) = topo {
                        if let Some(covering) = world.stm.covering(ev.addr) {
                            let offset = ev.addr - covering.base_addr;
                            if let Some(field) = covering.type_info.fields.iter().find(|f| f.byte_offset == offset && f.type_info.is_pointer) {
                                let pointee = field.type_info.name.strip_prefix('*').unwrap_or(&field.type_info.name);
                                ts.emit_link(ev.seq as u64, &covering.type_info.name, ev.addr, ev.value, pointee, &field.name);
                            }
                        }
                    }
                }
                if let Some(ref info) = dwarf_info {
                    let before = world.stm.len();
                    world.stm.propagate_field_write(ev.addr, ev.value, ev.size, ev.seq as u64, &info.type_registry);
                    let after = world.stm.len();
                    if after > before {
                        world.stm.retrospective_scan(ev.value, heap_graph, &world.heap_allocs, &info.type_registry, ev.seq as u64);
                    }
                    if after > before {
                        if let Some(ref mut ts) = topo {
                            if let Some(proj) = world.stm.lookup(ev.value) {
                                ts.emit_stamp(ev.seq as u64, ev.value, &proj.type_info.name, proj.type_info.byte_size, &proj.source_name, proj.type_info.fields.len());
                            }
                        }
                    }
                }
                if world.hazards.len() < 64 {
                    if let Some(h) = world.heap_allocs.check_write_bounds(ev.addr, ev.size, &world.stm) {
                        let dominated = world.hazards.iter().any(|prev| prev.write_addr == h.write_addr);
                        if !dominated {
                            if let Some(ref mut ts) = topo {
                                let kind_str = match h.kind { HazardKind::OutOfBounds => "OOB", HazardKind::HeapHole => "HOLE" };
                                ts.emit_hazard(ev.seq as u64, kind_str, h.write_addr, h.write_size, h.alloc_base, h.alloc_size, h.overflow_bytes, h.type_name.as_deref(), h.field_name.as_deref());
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
                            if let Some(ref info) = dwarf_info {
                                let pointee_name = h_type.name.strip_prefix('*').unwrap_or("");
                                if let Some(pointee_ti) = info.type_registry.get(pointee_name) {
                                    world.heap_allocs.check_size(ev.value, pointee_ti);
                                    if world.stm.stamp_type(ev.value, pointee_ti, &h_name, ev.seq as u64) {
                                        world.stm.retrospective_scan(ev.value, heap_graph, &world.heap_allocs, &info.type_registry, ev.seq as u64);
                                        if let Some(ref mut ts) = topo {
                                            ts.emit_stamp(ev.seq as u64, ev.value, &pointee_ti.name, pointee_ti.byte_size, &h_name, pointee_ti.fields.len());
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(ref mut ts) = topo {
                            let pointee_name = h_type.name.strip_prefix('*').unwrap_or(&h_type.name);
                            ts.emit_link(ev.seq as u64, &h_name, ev.addr, ev.value, pointee_name, &h_name);
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
                srf.on_call(ev.addr, ev.value, ev.seq as u64);
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
                srf.on_return(ev.seq as u64, ev.addr);
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
            let mut cont = [Event::zero(); 6];
            if orch.rings[ring_idx].pop_n(6, &mut cont) {
                let valid = cont.iter().all(|c| c.kind() == EVENT_REG_SNAPSHOT);
                if valid {
                    let mut regs = [0u64; REG_COUNT];
                    for s in 0..6usize {
                        regs[s * 3] = cont[s].addr;
                        regs[s * 3 + 1] = cont[s].size as u64;
                        regs[s * 3 + 2] = cont[s].value;
                    }
                    world.update_regs(regs, ev.addr);
                    let srf = shadow_regs.entry(ev.thread_id).or_default();
                    srf.apply_snapshot(&regs, ev.seq as u64, ev.addr);
                }
            }
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
            srf.on_reload(reg_idx, ev.value, ev.addr, ev.size, ev.seq as u64, ev.addr);
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
                ts.emit_alloc(ev.seq as u64, ev.thread_id, ptr, size);
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
                    ts.emit_free(ev.seq as u64, ev.thread_id, ptr, old_size);
                }
            }
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
    if depth > 3 { return; }
    for f in &parent_type.fields {
        if f.byte_size == 0 || f.name == "<pointee>" {
            continue;
        }
        let faddr = parent_base + f.byte_offset;
        let fi = *fi_counter;
        // cap at u16::MAX fields to avoid overflow
        if fi == u16::MAX { return; }
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
        // recurse into non-pointer compound fields (structs, arrays of structs)
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
