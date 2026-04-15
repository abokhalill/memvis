// SPDX-License-Identifier: MIT
// heap graph: pointer-chasing type reconstructor, passive from write stream.

use std::collections::{BTreeMap, HashMap, VecDeque};

use crate::dwarf::{DwarfInfo, TypeInfo};

pub struct HeapOracle {
    module_ranges: Vec<(u64, u64)>,
    stack_bounds: HashMap<u16, (u64, u64)>,
}

impl Default for HeapOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl HeapOracle {
    pub fn new() -> Self {
        Self {
            module_ranges: Vec::new(),
            stack_bounds: HashMap::new(),
        }
    }

    pub fn add_module(&mut self, base: u64, size: u64) {
        if size == 0 {
            return;
        }
        let hi = base.saturating_add(size);
        if let Some(last) = self.module_ranges.last_mut() {
            if base <= last.1 {
                last.1 = last.1.max(hi);
                return;
            }
        }
        self.module_ranges.push((base, hi));
        self.module_ranges.sort_by_key(|r| r.0);
    }

    pub fn update_stack(&mut self, tid: u16, rsp: u64) {
        let entry = self.stack_bounds.entry(tid).or_insert((rsp, rsp));
        entry.0 = entry.0.min(rsp);
        entry.1 = entry.1.max(rsp.saturating_add(128 * 1024));
    }

    pub fn is_heap(&self, addr: u64) -> bool {
        if self
            .module_ranges
            .binary_search_by(|&(lo, hi)| {
                if addr < lo {
                    std::cmp::Ordering::Greater
                } else if addr >= hi {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
        {
            return false;
        }
        if self
            .stack_bounds
            .values()
            .any(|&(lo, hi)| addr >= lo && addr < hi)
        {
            return false;
        }
        (0x1000..0x0000_8000_0000_0000).contains(&addr)
    }

    fn is_plausible_ptr(&self, val: u64) -> bool {
        (0x1000..0x0000_8000_0000_0000).contains(&val)
    }
}

#[derive(Debug, Clone)]
pub struct HeapFieldInfo {
    pub size: u32,
    pub last_value: u64,
    pub is_pointer: bool,
    pub write_count: u32,
    pub last_seq: u64,
}

#[derive(Debug, Clone)]
pub struct HeapEdge {
    pub source_addr: u64,
    pub target_addr: u64,
    pub field_offset: u64,
    pub last_seq: u64,
    pub write_count: u32,
}

#[derive(Debug, Clone)]
pub struct HeapObject {
    pub base_addr: u64,
    pub inferred_size: u64,
    pub inferred_type: Option<String>,
    pub type_confidence: f32,
    pub fields: BTreeMap<u64, HeapFieldInfo>,
    pub outgoing_edges: Vec<HeapEdge>,
    pub first_seq: u64,
    pub last_seq: u64,
}

struct RecentWrite {
    addr: u64,
    size: u32,
    value: u64,
    seq: u64,
}

const CLUSTER_WINDOW: usize = 64;
const CLUSTER_RADIUS: u64 = 256;
const MIN_CLUSTER_WRITES: usize = 3;
const TYPE_INFERENCE_INTERVAL: u64 = 10_000;

pub struct HeapGraph {
    objects: BTreeMap<u64, HeapObject>,
    addr_to_base: BTreeMap<u64, u64>,
    recent_writes: VecDeque<RecentWrite>,
    events_since_inference: u64,
    total_events: u64,
}

impl Default for HeapGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl HeapGraph {
    pub fn new() -> Self {
        Self {
            objects: BTreeMap::new(),
            addr_to_base: BTreeMap::new(),
            recent_writes: VecDeque::with_capacity(CLUSTER_WINDOW + 16),
            events_since_inference: 0,
            total_events: 0,
        }
    }

    pub fn objects(&self) -> &BTreeMap<u64, HeapObject> {
        &self.objects
    }

    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    pub fn on_free(&mut self, addr: u64, size: u64) {
        let hi = addr.saturating_add(size);
        let to_remove: Vec<u64> = self.objects.range(addr..hi).map(|(&k, _)| k).collect();
        for base in to_remove {
            self.objects.remove(&base);
            self.addr_to_base.retain(|_, v| *v != base);
        }
    }

    pub fn edge_count(&self) -> usize {
        self.objects.values().map(|o| o.outgoing_edges.len()).sum()
    }

    fn find_object_base(&self, addr: u64) -> Option<u64> {
        if let Some(&base) = self.addr_to_base.get(&addr) {
            return Some(base);
        }
        use std::ops::Bound;
        self.objects
            .range((Bound::Unbounded, Bound::Included(&addr)))
            .next_back()
            .filter(|(_, obj)| addr < obj.base_addr + obj.inferred_size)
            .map(|(&base, _)| base)
    }

    pub fn process_write(
        &mut self,
        addr: u64,
        size: u32,
        value: u64,
        seq: u64,
        oracle: &HeapOracle,
    ) {
        self.total_events += 1;
        self.events_since_inference += 1;

        self.recent_writes.push_back(RecentWrite {
            addr,
            size,
            value,
            seq,
        });
        if self.recent_writes.len() > CLUSTER_WINDOW {
            self.recent_writes.pop_front();
        }

        if let Some(base) = self.find_object_base(addr) {
            let obj = self.objects.get_mut(&base).unwrap();
            let offset = addr - base;
            let field = obj.fields.entry(offset).or_insert(HeapFieldInfo {
                size,
                last_value: value,
                is_pointer: size == 8 && oracle.is_plausible_ptr(value),
                write_count: 0,
                last_seq: seq,
            });
            field.last_value = value;
            field.write_count += 1;
            field.last_seq = seq;
            field.is_pointer = size == 8 && oracle.is_plausible_ptr(value);
            obj.last_seq = seq;

            if field.is_pointer && value != 0 {
                self.update_edge(base, offset, addr, value, seq);
            }
            return;
        }

        let nearby: Vec<&RecentWrite> = self
            .recent_writes
            .iter()
            .filter(|w| {
                let d = w.addr.abs_diff(addr);
                d <= CLUSTER_RADIUS
            })
            .collect();

        if nearby.len() >= MIN_CLUSTER_WRITES {
            let base = nearby.iter().map(|w| w.addr).min().unwrap();
            let max_addr = nearby.iter().map(|w| w.addr + w.size as u64).max().unwrap();
            let inferred_size = (max_addr - base).max(8);

            if !self.objects.contains_key(&base) {
                let mut obj = HeapObject {
                    base_addr: base,
                    inferred_size,
                    inferred_type: None,
                    type_confidence: 0.0,
                    fields: BTreeMap::new(),
                    outgoing_edges: Vec::new(),
                    first_seq: nearby.iter().map(|w| w.seq).min().unwrap_or(seq),
                    last_seq: seq,
                };

                for w in &nearby {
                    let offset = w.addr - base;
                    self.addr_to_base.insert(w.addr, base);
                    let is_ptr = w.size == 8 && oracle.is_plausible_ptr(w.value);
                    let field = obj.fields.entry(offset).or_insert(HeapFieldInfo {
                        size: w.size,
                        last_value: w.value,
                        is_pointer: is_ptr,
                        write_count: 0,
                        last_seq: w.seq,
                    });
                    field.last_value = w.value;
                    field.write_count += 1;
                    field.last_seq = w.seq;
                    field.is_pointer = is_ptr;
                }

                for (&off, f) in &obj.fields {
                    if f.is_pointer && f.last_value != 0 {
                        obj.outgoing_edges.push(HeapEdge {
                            source_addr: base + off,
                            target_addr: f.last_value,
                            field_offset: off,
                            last_seq: f.last_seq,
                            write_count: 1,
                        });
                    }
                }

                self.objects.insert(base, obj);
            }
        }
    }

    fn update_edge(&mut self, obj_base: u64, offset: u64, source: u64, target: u64, seq: u64) {
        let obj = match self.objects.get_mut(&obj_base) {
            Some(o) => o,
            None => return,
        };
        if let Some(edge) = obj
            .outgoing_edges
            .iter_mut()
            .find(|e| e.field_offset == offset)
        {
            edge.target_addr = target;
            edge.last_seq = seq;
            edge.write_count += 1;
        } else {
            obj.outgoing_edges.push(HeapEdge {
                source_addr: source,
                target_addr: target,
                field_offset: offset,
                last_seq: seq,
                write_count: 1,
            });
        }
    }

    pub fn needs_type_inference(&self) -> bool {
        self.events_since_inference >= TYPE_INFERENCE_INTERVAL && !self.objects.is_empty()
    }

    pub fn run_type_inference(&mut self, dwarf: &DwarfInfo) {
        self.events_since_inference = 0;
        let candidates = collect_struct_types(dwarf);
        if candidates.is_empty() {
            return;
        }

        for obj in self.objects.values_mut() {
            if obj.fields.is_empty() {
                continue;
            }
            let (best_name, best_score) = match_struct_type(obj, &candidates);
            if best_score >= 0.5 {
                obj.inferred_type = Some(best_name);
                obj.type_confidence = best_score;
            }
        }
    }

    pub fn gc_stale(&mut self, current_seq: u64, max_age: u64) {
        let threshold = current_seq.saturating_sub(max_age);
        let stale: Vec<u64> = self
            .objects
            .iter()
            .filter(|(_, o)| o.last_seq < threshold)
            .map(|(&base, _)| base)
            .collect();
        for base in stale {
            if let Some(obj) = self.objects.remove(&base) {
                for offset in obj.fields.keys() {
                    self.addr_to_base.remove(&(base + offset));
                }
            }
        }
    }
}


struct StructCandidate {
    name: String,
    byte_size: u64,
    fields: Vec<(u64, u64, bool)>, // (offset, size, is_pointer)
}

fn collect_struct_types(dwarf: &DwarfInfo) -> Vec<StructCandidate> {
    let mut seen = std::collections::HashSet::new();
    let mut candidates = Vec::new();

    let mut collect_from_type = |ti: &TypeInfo| {
        if ti.fields.is_empty() || ti.byte_size == 0 {
            return;
        }
        if !seen.insert(ti.name.clone()) {
            return;
        }
        candidates.push(StructCandidate {
            name: ti.name.clone(),
            byte_size: ti.byte_size,
            fields: ti
                .fields
                .iter()
                .map(|f| (f.byte_offset, f.byte_size, f.type_info.is_pointer))
                .collect(),
        });
    };

    for g in &dwarf.globals {
        collect_from_type(&g.type_info);
        for f in &g.type_info.fields {
            collect_from_type(&f.type_info);
        }
    }
    for func in dwarf.functions.values() {
        for local in &func.locals {
            collect_from_type(&local.type_info);
            for f in &local.type_info.fields {
                collect_from_type(&f.type_info);
            }
        }
    }
    candidates
}

fn match_struct_type(obj: &HeapObject, candidates: &[StructCandidate]) -> (String, f32) {
    let mut best_name = String::new();
    let mut best_score: f32 = 0.0;

    for c in candidates {
        if c.fields.is_empty() {
            continue;
        }
        let mut matches = 0usize;
        let total = c.fields.len();

        for &(c_off, c_size, c_is_ptr) in &c.fields {
            if let Some(observed) = obj.fields.get(&c_off) {
                if observed.size as u64 == c_size || (c_is_ptr && observed.is_pointer) {
                    matches += 1;
                }
            }
        }

        let score = matches as f32 / total as f32;
        let size_bonus = if obj.inferred_size == c.byte_size {
            0.1
        } else {
            0.0
        };
        let final_score = (score + size_bonus).min(1.0);

        if final_score > best_score {
            best_score = final_score;
            best_name = c.name.clone();
        }
    }

    (best_name, best_score)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_oracle() -> HeapOracle {
        let mut o = HeapOracle::new();
        // simulate a module at 0x400000-0x500000
        o.add_module(0x400000, 0x100000);
        // simulate stack at 0x7fff_0000_0000
        o.update_stack(0, 0x7fff_0000_0000);
        o
    }

    #[test]
    fn test_oracle_classification() {
        let o = make_oracle();
        assert!(!o.is_heap(0x400100)); // module
        assert!(!o.is_heap(0x7fff_0000_1000)); // stack
        assert!(o.is_heap(0x5555_0000_0100)); // heap
        assert!(!o.is_heap(0x100)); // too low
    }

    #[test]
    fn test_clustering_creates_object() {
        let oracle = make_oracle();
        let mut graph = HeapGraph::new();
        let base = 0x5555_0000_1000u64;

        // 3 writes within CLUSTER_RADIUS → triggers object creation
        graph.process_write(base, 4, 42, 1, &oracle);
        graph.process_write(base + 4, 4, 99, 2, &oracle);
        graph.process_write(base + 8, 8, 0x5555_0000_2000, 3, &oracle);

        assert_eq!(graph.object_count(), 1);
        let obj = graph.objects.values().next().unwrap();
        assert_eq!(obj.base_addr, base);
        assert!(obj.fields.contains_key(&0));
        assert!(obj.fields.contains_key(&4));
        assert!(obj.fields.contains_key(&8));
        // field at +8 should be a pointer
        assert!(obj.fields.get(&8).unwrap().is_pointer);
    }

    #[test]
    fn test_pointer_edge_tracking() {
        let oracle = make_oracle();
        let mut graph = HeapGraph::new();
        let base = 0x5555_0000_3000u64;
        let target = 0x5555_0000_4000u64;

        // create object
        graph.process_write(base, 4, 1, 1, &oracle);
        graph.process_write(base + 4, 4, 2, 2, &oracle);
        graph.process_write(base + 8, 8, target, 3, &oracle);

        assert_eq!(graph.edge_count(), 1);
        let obj = graph.objects.values().next().unwrap();
        assert_eq!(obj.outgoing_edges[0].target_addr, target);

        // update the pointer
        graph.process_write(base + 8, 8, target + 0x100, 4, &oracle);
        let obj = graph.objects.values().next().unwrap();
        assert_eq!(obj.outgoing_edges[0].target_addr, target + 0x100);
        assert_eq!(obj.outgoing_edges[0].write_count, 2);
    }

    #[test]
    fn test_gc_stale() {
        let oracle = make_oracle();
        let mut graph = HeapGraph::new();
        let base = 0x5555_0000_5000u64;

        graph.process_write(base, 4, 1, 100, &oracle);
        graph.process_write(base + 4, 4, 2, 101, &oracle);
        graph.process_write(base + 8, 4, 3, 102, &oracle);
        assert_eq!(graph.object_count(), 1);

        // GC with current_seq far ahead
        graph.gc_stale(200_000, 100_000);
        assert_eq!(graph.object_count(), 0);
    }

    #[test]
    fn test_subsequent_writes_update_existing_object() {
        let oracle = make_oracle();
        let mut graph = HeapGraph::new();
        let base = 0x5555_0000_6000u64;

        // create
        graph.process_write(base, 4, 1, 1, &oracle);
        graph.process_write(base + 4, 4, 2, 2, &oracle);
        graph.process_write(base + 8, 4, 3, 3, &oracle);
        assert_eq!(graph.object_count(), 1);

        // subsequent write to same object
        graph.process_write(base, 4, 99, 4, &oracle);
        let obj = graph.objects.values().next().unwrap();
        assert_eq!(obj.fields.get(&0).unwrap().last_value, 99);
        assert_eq!(obj.fields.get(&0).unwrap().write_count, 2);
        assert_eq!(obj.last_seq, 4);
    }
}
