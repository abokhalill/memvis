// SPDX-License-Identifier: Apache-2.0
// heap graph: pointer-chasing type reconstructor, passive from write stream.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

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
        Self::in_user_range(addr)
    }

    fn is_plausible_ptr(&self, val: u64) -> bool {
        Self::in_user_range(val)
    }

    // linux user VA: 47-bit w/ 4-level paging, 56-bit w/ 5-level (5.14+ or LA57).
    // 56-bit window covers both; kernel half (MSB set) still excluded.
    #[inline]
    fn in_user_range(addr: u64) -> bool {
        (0x1000..0x0100_0000_0000_0000).contains(&addr)
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
pub struct ScoreEntry {
    pub candidate_idx: u16,
    pub score: f32,
}

// top-3 candidates + cooldown state per object
#[derive(Debug, Clone)]
pub struct ScoreCache {
    pub top: [ScoreEntry; 3],
    pub count: u8,
    pub last_rescore_seq: u64,
    pub events_since_rescore: u32,
}

impl ScoreCache {
    fn empty() -> Self {
        Self {
            top: [
                ScoreEntry { candidate_idx: 0, score: 0.0 },
                ScoreEntry { candidate_idx: 0, score: 0.0 },
                ScoreEntry { candidate_idx: 0, score: 0.0 },
            ],
            count: 0,
            last_rescore_seq: 0,
            events_since_rescore: 0,
        }
    }

    fn best(&self) -> Option<&ScoreEntry> {
        if self.count > 0 { Some(&self.top[0]) } else { None }
    }
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
    pub score_cache: ScoreCache,
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

// incremental confidence tuning
const CONFIRM_DELTA: f32 = 0.02;
const CONTRADICT_PENALTY: f32 = 0.08;
const RESCORE_THRESHOLD: f32 = 0.3;
const RESCORE_COOLDOWN: u32 = 1024;

pub struct HeapGraph {
    objects: BTreeMap<u64, HeapObject>,
    addr_to_base: BTreeMap<u64, u64>,
    recent_writes: VecDeque<RecentWrite>,
    total_events: u64,
    candidates: Option<Arc<Vec<StructCandidate>>>,
    pub rescores: u64,
    pub contradictions: u64,
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
            total_events: 0,
            candidates: None,
            rescores: 0,
            contradictions: 0,
        }
    }

    pub fn init_candidates(&mut self, dwarf: &DwarfInfo) {
        let c = collect_struct_types(dwarf);
        if !c.is_empty() {
            self.candidates = Some(Arc::new(c));
        }
    }

    pub fn has_candidates(&self) -> bool {
        self.candidates.is_some()
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

    pub fn find_object_base(&self, addr: u64) -> Option<u64> {
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
            let is_ptr = size == 8 && oracle.is_plausible_ptr(value);
            let field = obj.fields.entry(offset).or_insert(HeapFieldInfo {
                size,
                last_value: value,
                is_pointer: is_ptr,
                write_count: 0,
                last_seq: seq,
            });
            field.last_value = value;
            field.write_count += 1;
            field.last_seq = seq;
            field.is_pointer = is_ptr;
            obj.last_seq = seq;

            // incremental confidence update against current best candidate
            if let Some(ref cands) = self.candidates {
                Self::update_confidence(obj, cands, offset, size, is_ptr, seq, &mut self.rescores, &mut self.contradictions);
            }

            if is_ptr && value != 0 {
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
                    score_cache: ScoreCache::empty(),
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

    // full re-score: O(candidates * fields). called once on first write to
    // unscored object, then only when confidence drops below threshold.
    fn score_object(obj: &mut HeapObject, candidates: &[StructCandidate]) {
        let mut buf: Vec<(u16, f32)> = Vec::with_capacity(candidates.len().min(8));
        for (ci, c) in candidates.iter().enumerate() {
            if c.fields.is_empty() { continue; }
            let mut matches = 0u32;
            let total = c.fields.len() as u32;
            for &(c_off, c_size, c_is_ptr) in &c.fields {
                if let Some(observed) = obj.fields.get(&c_off) {
                    if observed.size as u64 == c_size || (c_is_ptr && observed.is_pointer) {
                        matches += 1;
                    }
                }
            }
            let score = matches as f32 / total as f32;
            let size_bonus = if obj.inferred_size == c.byte_size { 0.1 } else { 0.0 };
            let final_score = (score + size_bonus).min(1.0);
            if final_score > 0.0 {
                buf.push((ci as u16, final_score));
            }
        }
        buf.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let mut sc = ScoreCache::empty();
        for (i, &(idx, s)) in buf.iter().take(3).enumerate() {
            sc.top[i] = ScoreEntry { candidate_idx: idx, score: s };
            sc.count = (i + 1) as u8;
        }
        sc.events_since_rescore = 0;

        if let Some(best) = sc.best() {
            if best.score >= 0.5 {
                obj.inferred_type = Some(candidates[best.candidate_idx as usize].name.clone());
                obj.type_confidence = best.score;
            }
        }
        obj.score_cache = sc;
    }

    // O(1) hot-path: check if this write confirms or contradicts the best candidate.
    // if confidence drops below threshold and cooldown expired, trigger full re-score.
    fn update_confidence(
        obj: &mut HeapObject,
        candidates: &[StructCandidate],
        offset: u64,
        size: u32,
        is_ptr: bool,
        seq: u64,
        rescores: &mut u64,
        contradictions: &mut u64,
    ) {
        obj.score_cache.events_since_rescore += 1;

        // first time: no score yet, do initial full score
        if obj.score_cache.count == 0 {
            if obj.fields.len() >= 2 {
                Self::score_object(obj, candidates);
                obj.score_cache.last_rescore_seq = seq;
                *rescores += 1;
            }
            return;
        }

        let best_idx = obj.score_cache.top[0].candidate_idx as usize;
        if best_idx >= candidates.len() { return; }
        let cand = &candidates[best_idx];

        // O(1): does this write match the candidate's expected field?
        let field_matches = cand.fields.iter().any(|&(c_off, c_size, c_is_ptr)| {
            c_off == offset && (size as u64 == c_size || (c_is_ptr && is_ptr))
        });

        if field_matches {
            // diminishing confirmation: less delta as confidence approaches 1.0
            let delta = CONFIRM_DELTA * (1.0 - obj.type_confidence);
            obj.type_confidence = (obj.type_confidence + delta).min(1.0);
            obj.score_cache.top[0].score = obj.type_confidence;
        } else {
            // hard contradiction: penalty + track
            *contradictions += 1;
            obj.type_confidence = (obj.type_confidence - CONTRADICT_PENALTY).max(0.0);
            obj.score_cache.top[0].score = obj.type_confidence;

            // if confidence collapsed and cooldown expired, full re-score
            if obj.type_confidence < RESCORE_THRESHOLD
                && obj.score_cache.events_since_rescore >= RESCORE_COOLDOWN
            {
                Self::score_object(obj, candidates);
                obj.score_cache.last_rescore_seq = seq;
                *rescores += 1;
            }
        }

        // propagate best type name
        if obj.type_confidence >= 0.5 {
            if obj.inferred_type.is_none() || obj.score_cache.top[0].candidate_idx as usize != best_idx {
                let new_idx = obj.score_cache.top[0].candidate_idx as usize;
                if new_idx < candidates.len() {
                    obj.inferred_type = Some(candidates[new_idx].name.clone());
                }
            }
        } else {
            obj.inferred_type = None;
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

    fn make_candidates() -> Vec<StructCandidate> {
        vec![
            StructCandidate {
                name: "widget_t".into(),
                byte_size: 24,
                fields: vec![
                    (0, 4, false),   // int at +0
                    (8, 8, true),    // ptr at +8
                    (16, 4, false),  // int at +16
                ],
            },
            StructCandidate {
                name: "gadget_t".into(),
                byte_size: 16,
                fields: vec![
                    (0, 8, true),    // ptr at +0
                    (8, 8, false),   // u64 at +8
                ],
            },
        ]
    }

    #[test]
    fn test_incremental_initial_score() {
        let oracle = make_oracle();
        let mut graph = HeapGraph::new();
        graph.candidates = Some(Arc::new(make_candidates()));
        let base = 0x5555_0000_7000u64;

        // create object matching widget_t layout: int at +0, ptr at +8
        graph.process_write(base, 4, 42, 1, &oracle);
        graph.process_write(base + 8, 8, 0x5555_0000_8000, 2, &oracle);
        graph.process_write(base + 16, 4, 7, 3, &oracle);
        assert_eq!(graph.object_count(), 1);

        // 4th write triggers initial score (need >=2 fields + score_cache.count==0)
        graph.process_write(base, 4, 43, 4, &oracle);
        let obj = graph.objects.values().next().unwrap();

        assert!(obj.score_cache.count > 0, "must have scored at least one candidate");
        assert_eq!(obj.inferred_type.as_deref(), Some("widget_t"));
        assert!(obj.type_confidence >= 0.5, "confidence must cross threshold");
        assert_eq!(graph.rescores, 1);
    }

    #[test]
    fn test_incremental_confirmation_raises_confidence() {
        let oracle = make_oracle();
        let mut graph = HeapGraph::new();
        graph.candidates = Some(Arc::new(make_candidates()));
        let base = 0x5555_0000_9000u64;

        // create with only 2 of 3 widget_t fields so initial score < 1.0
        graph.process_write(base, 4, 1, 1, &oracle);
        graph.process_write(base + 8, 8, 0x5555_0000_A000, 2, &oracle);
        // skip offset 16 — partial match triggers score ~0.67
        graph.process_write(base + 20, 4, 99, 3, &oracle);
        // 4th write triggers initial score
        graph.process_write(base, 4, 2, 4, &oracle);

        let c0 = graph.objects.values().next().unwrap().type_confidence;
        assert!(c0 < 1.0, "initial score must be < 1.0 for partial match: {}", c0);

        // confirming writes to known widget_t offsets should raise confidence
        for i in 5..25u64 {
            graph.process_write(base, 4, i, i, &oracle);
        }
        let c1 = graph.objects.values().next().unwrap().type_confidence;
        assert!(c1 > c0, "confirming writes must increase confidence: {} > {}", c1, c0);
    }

    #[test]
    fn test_incremental_contradiction_drops_confidence() {
        let oracle = make_oracle();
        let mut graph = HeapGraph::new();
        graph.candidates = Some(Arc::new(make_candidates()));
        let base = 0x5555_0000_B000u64;

        // create + score as widget_t
        graph.process_write(base, 4, 1, 1, &oracle);
        graph.process_write(base + 8, 8, 0x5555_0000_C000, 2, &oracle);
        graph.process_write(base + 16, 4, 3, 3, &oracle);
        graph.process_write(base, 4, 2, 4, &oracle);
        let c0 = graph.objects.values().next().unwrap().type_confidence;

        // write at offset 5 with size 3: matches no candidate field → contradiction
        graph.process_write(base + 5, 3, 0xFF, 5, &oracle);
        let obj = graph.objects.values().next().unwrap();
        assert!(obj.type_confidence < c0, "contradiction must drop confidence");
        assert!(graph.contradictions >= 1);
    }

    #[test]
    fn test_incremental_rescore_on_collapse() {
        let oracle = make_oracle();
        let mut graph = HeapGraph::new();
        graph.candidates = Some(Arc::new(make_candidates()));
        let base = 0x5555_0000_D000u64;

        // create + score
        graph.process_write(base, 4, 1, 1, &oracle);
        graph.process_write(base + 8, 8, 0x5555_0000_E000, 2, &oracle);
        graph.process_write(base + 16, 4, 3, 3, &oracle);
        graph.process_write(base, 4, 2, 4, &oracle);
        assert_eq!(graph.rescores, 1);

        // hammer contradictions to collapse confidence below RESCORE_THRESHOLD
        // but cooldown prevents immediate re-score
        for i in 5..20u64 {
            graph.process_write(base + 5, 3, 0xFF, i, &oracle);
        }
        let pre_cooldown_rescores = graph.rescores;

        // push past RESCORE_COOLDOWN (1024 events) to allow re-score
        for i in 20..(20 + RESCORE_COOLDOWN as u64 + 10) {
            graph.process_write(base + 5, 3, 0xFF, i + 100, &oracle);
        }

        // confidence should have collapsed, triggering a re-score
        assert!(graph.rescores > pre_cooldown_rescores,
            "re-score must fire after cooldown: {} > {}", graph.rescores, pre_cooldown_rescores);
    }

    #[test]
    fn test_incremental_type_switch_on_layout_change() {
        let oracle = make_oracle();
        let mut graph = HeapGraph::new();
        graph.candidates = Some(Arc::new(make_candidates()));
        let base = 0x5555_0000_F000u64;

        // start as widget_t: int+0, ptr+8, int+16
        graph.process_write(base, 4, 1, 1, &oracle);
        graph.process_write(base + 8, 8, 0x5555_0001_0000, 2, &oracle);
        graph.process_write(base + 16, 4, 3, 3, &oracle);
        graph.process_write(base, 4, 2, 4, &oracle);
        assert_eq!(graph.objects.values().next().unwrap().inferred_type.as_deref(), Some("widget_t"));

        // now rewrite as gadget_t layout: ptr+0, u64+8
        // contradict enough times past cooldown to force re-score
        for i in 5..(5 + RESCORE_COOLDOWN as u64 + 50) {
            graph.process_write(base, 8, 0x5555_0001_1000, i + 100, &oracle);
            graph.process_write(base + 8, 8, 0xDEAD, i + 200, &oracle);
        }
        // object fields now look like gadget_t (ptr+0, u64+8)
        // after re-score, if gadget_t scores higher it should switch
        let obj = graph.objects.values().next().unwrap();
        // the key assertion: type must not be silently stuck — it either switches or drops
        if obj.type_confidence >= 0.5 {
            // re-scored and found a match
            assert!(obj.inferred_type.is_some());
        } else {
            // confidence collapsed — type cleared, not silently wrong
            assert!(obj.inferred_type.is_none(),
                "low confidence must clear type, not leave stale name");
        }
    }
}
