// SPDX-License-Identifier: Apache-2.0
// world state: variables, pointer edges, register file, cache miss tracking.
// arc-wrapped inner for cow snapshotting - mutation clones only when shared.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

/// Key for per-thread, per-field write heatmap.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FieldHeatKey {
    pub thread_id: u16,
    pub type_name: String,
    pub field_name: String,
    pub field_offset: u64,
}

/// Per-field write heatmap: tracks how many times each thread writes to each
/// typed field on STM-projected heap addresses. Used to produce symbolic
/// pressure maps for cacheline contention analysis.
#[derive(Debug, Clone)]
pub struct FieldHeatmap {
    counts: HashMap<FieldHeatKey, u64>,
    /// (cl_addr, thread_id, type_name, field_name) for fields on contended cachelines
    pub contention_hits: u64,
}

impl FieldHeatmap {
    pub fn new() -> Self {
        Self { counts: HashMap::with_capacity(512), contention_hits: 0 }
    }

    #[inline]
    pub fn record(&mut self, thread_id: u16, type_name: &str, field_name: &str, field_offset: u64) {
        let key = FieldHeatKey {
            thread_id,
            type_name: type_name.to_string(),
            field_name: field_name.to_string(),
            field_offset,
        };
        *self.counts.entry(key).or_insert(0) += 1;
    }

    pub fn len(&self) -> usize { self.counts.len() }

    // TSV export for divergence analysis: type\tfield\toffset\tthread\twrites
    pub fn export_tsv(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::io::BufWriter::new(std::fs::File::create(path)?);
        writeln!(f, "type\tfield\toffset\tthread\twrites")?;
        let mut entries: Vec<_> = self.counts.iter().collect();
        entries.sort_by(|a, b| a.0.type_name.cmp(&b.0.type_name)
            .then(a.0.field_offset.cmp(&b.0.field_offset))
            .then(a.0.thread_id.cmp(&b.0.thread_id)));
        for (k, &c) in &entries {
            writeln!(f, "{}\t{}\t{}\t{}\t{}", k.type_name, k.field_name, k.field_offset, k.thread_id, c)?;
        }
        f.flush()
    }

    /// Return all entries sorted by write count descending.
    pub fn top_entries(&self, limit: usize) -> Vec<(&FieldHeatKey, u64)> {
        let mut v: Vec<_> = self.counts.iter().map(|(k, &c)| (k, c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(limit);
        v
    }

    /// For a given cacheline address, find all fields written by different threads.
    /// Returns groups: type_name.field_name -> set of (thread_id, write_count).
    pub fn contention_report(
        &self,
        cl_tracker: &CacheLineTracker,
    ) -> Vec<ContentionEntry> {
        // group by (type_name, field_name, field_offset)
        let mut by_field: HashMap<(String, String, u64), Vec<(u16, u64)>> = HashMap::new();
        for (key, &count) in &self.counts {
            by_field.entry((key.type_name.clone(), key.field_name.clone(), key.field_offset))
                .or_default()
                .push((key.thread_id, count));
        }
        let mut result = Vec::new();
        for ((type_name, field_name, field_offset), threads) in &by_field {
            if threads.len() < 2 { continue; }
            // check if any address at this offset has CL contention
            // (we can't recover exact addresses here, so just report multi-thread fields)
            let total: u64 = threads.iter().map(|(_, c)| c).sum();
            let mut ts = threads.clone();
            ts.sort_by(|a, b| b.1.cmp(&a.1));
            result.push(ContentionEntry {
                type_name: type_name.clone(),
                field_name: field_name.clone(),
                field_offset: *field_offset,
                threads: ts,
                total_writes: total,
            });
        }
        // also check CL tracker for lines with multi-writer
        let _ = cl_tracker; // used for future refinement
        result.sort_by(|a, b| b.total_writes.cmp(&a.total_writes));
        result
    }
}

#[derive(Debug, Clone)]
pub struct ContentionEntry {
    pub type_name: String,
    pub field_name: String,
    pub field_offset: u64,
    pub threads: Vec<(u16, u64)>,
    pub total_writes: u64,
}

use crate::dwarf::TypeInfo;
use crate::index::NodeId;

pub const REG_NAMES: &[&str] = &[
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15", "rip", "rflags",
];
pub const REG_COUNT: usize = 18;

#[derive(Debug, Clone)]
pub struct LiveRegisterFile {
    pub values: [u64; REG_COUNT],
    pub prev: [u64; REG_COUNT],
    pub insn: u64,
}

impl LiveRegisterFile {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            values: [0; REG_COUNT],
            prev: [0; REG_COUNT],
            insn: 0,
        }
    }
    pub fn update(&mut self, regs: [u64; REG_COUNT], insn: u64) {
        self.prev = self.values;
        self.values = regs;
        self.insn = insn;
    }
}

const CL_SHIFT: u32 = 6;
const CL_SLOTS: usize = 16384;
const CL_MASK: usize = CL_SLOTS - 1;

#[derive(Debug, Clone, Copy, Default)]
pub struct ClSlot {
    pub cl_addr: u64,
    pub write_count: u16,
    pub writers: u16, // bitmask: bit i = thread i has written
}

#[derive(Debug, Clone)]
pub struct CacheLineTracker {
    pub slots: Box<[ClSlot; CL_SLOTS]>,
}

impl CacheLineTracker {
    pub fn new() -> Self {
        Self {
            slots: Box::new([ClSlot::default(); CL_SLOTS]),
        }
    }

    #[inline(always)]
    pub fn record_write(&mut self, addr: u64, thread_id: u16) -> u16 {
        let cl = addr >> CL_SHIFT;
        let idx = (cl as usize) & CL_MASK;
        let s = unsafe { self.slots.get_unchecked_mut(idx) };
        if s.cl_addr != cl {
            *s = ClSlot { cl_addr: cl, write_count: 1, writers: 1u16 << (thread_id & 15) };
            return s.writers;
        }
        s.write_count = s.write_count.saturating_add(1);
        s.writers |= 1u16 << (thread_id & 15);
        s.writers
    }

    pub fn contention_score(&self, addr: u64) -> u32 {
        let cl = addr >> CL_SHIFT;
        let idx = (cl as usize) & CL_MASK;
        let s = &self.slots[idx];
        if s.cl_addr == cl { s.writers.count_ones() } else { 0 }
    }

    pub fn tick(&mut self) {
        for s in self.slots.iter_mut() {
            s.write_count >>= 1;
            if s.write_count == 0 {
                s.writers = 0;
                s.cl_addr = 0;
            }
        }
    }
}

const DECAY_FACTOR: f32 = 0.95;

#[derive(Debug, Clone)]
pub struct CacheMissEntry {
    pub count: u32,
    pub heat: f32,
}

#[derive(Debug, Clone)]
pub struct CacheHeatmap {
    pub per_node: HashMap<NodeId, CacheMissEntry>,
}

impl CacheHeatmap {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            per_node: HashMap::new(),
        }
    }
    pub fn record_miss(&mut self, nid: NodeId) {
        let e = self.per_node.entry(nid).or_insert(CacheMissEntry {
            count: 0,
            heat: 0.0,
        });
        e.count += 1;
        e.heat = (e.heat + 1.0).min(1.0);
    }
    pub fn tick(&mut self) {
        self.per_node.retain(|_, e| {
            e.heat *= DECAY_FACTOR;
            e.heat > 0.01
        });
    }
}

#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,
    pub type_info: TypeInfo,
    pub addr: u64,
    pub size: u64,
    pub raw_value: u64,
    pub last_write_insn: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerEdge {
    pub source: NodeId,
    pub target: NodeId,
    pub ptr_value: u64,
    pub is_dangling: bool,
}

#[derive(Debug, Clone)]
pub struct WorldInner {
    pub nodes: BTreeMap<NodeId, Node>,
    pub edges: BTreeMap<NodeId, PointerEdge>,
    pub insn_counter: u64,
    pub reg_file: LiveRegisterFile,
    pub cache_heat: CacheHeatmap,
}

impl WorldInner {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            insn_counter: 0,
            reg_file: LiveRegisterFile::new(),
            cache_heat: CacheHeatmap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TypeProjection {
    pub base_addr: u64,
    pub type_info: TypeInfo,
    pub source_name: String,
    pub stamp_seq: u64,
}

pub struct ShadowTypeMap {
    map: HashMap<u64, TypeProjection>,
}

impl ShadowTypeMap {
    pub fn new() -> Self {
        Self { map: HashMap::with_capacity(256) }
    }

    pub fn stamp_type(
        &mut self,
        target_addr: u64,
        pointee_type: &TypeInfo,
        source_name: &str,
        seq: u64,
    ) -> bool {
        if target_addr == 0 || pointee_type.byte_size == 0 {
            return false;
        }
        let proj = TypeProjection {
            base_addr: target_addr,
            type_info: pointee_type.clone(),
            source_name: source_name.to_string(),
            stamp_seq: seq,
        };
        self.map.insert(target_addr, proj);
        true
    }

    /// resolve *T→T on pointer field writes within stamped regions
    pub fn propagate_field_write(
        &mut self,
        write_addr: u64,
        write_value: u64,
        write_size: u32,
        seq: u64,
        type_registry: &HashMap<String, TypeInfo>,
    ) {
        if write_size != 8 || write_value == 0 {
            return;
        }
        let covering = self.map.iter()
            .find(|(_, p)| {
                write_addr >= p.base_addr
                    && write_addr < p.base_addr + p.type_info.byte_size
            })
            .map(|(_, p)| (p.base_addr, p.type_info.clone()));

        let (base, ti) = match covering {
            Some(x) => x,
            None => return,
        };

        let offset = write_addr - base;
        if let Some(field) = ti.fields.iter().find(|f| f.byte_offset == offset && f.name != "<pointee>") {
            if field.type_info.is_pointer {
                let pointee_name = field.type_info.name.strip_prefix('*').unwrap_or("");
                if let Some(pointee_ti) = type_registry.get(pointee_name) {
                    self.stamp_type(write_value, pointee_ti, &field.name, seq);
                }
            }
        }
    }

    pub fn lookup(&self, addr: u64) -> Option<&TypeProjection> {
        self.map.get(&addr)
    }

    pub fn covering(&self, addr: u64) -> Option<&TypeProjection> {
        self.map.values().find(|p| {
            addr >= p.base_addr && addr < p.base_addr + p.type_info.byte_size
        })
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&u64, &TypeProjection)> {
        self.map.iter()
    }

    pub fn purge_range(&mut self, addr: u64, size: u64) -> usize {
        let hi = addr.saturating_add(size);
        let before = self.map.len();
        self.map.retain(|_, p| p.base_addr < addr || p.base_addr >= hi);
        before - self.map.len()
    }

    /// bounded BFS from a freshly stamped address. reads last known pointer
    /// values from HeapGraph fields to discover reachable typed structs.
    pub fn retrospective_scan(
        &mut self,
        seed_addr: u64,
        heap_graph: &crate::heap_graph::HeapGraph,
        allocs: &HeapAllocTracker,
        type_registry: &HashMap<String, TypeInfo>,
        seq: u64,
    ) -> usize {
        const FUEL: usize = 64;
        let mut queue: VecDeque<u64> = VecDeque::with_capacity(16);
        queue.push_back(seed_addr);
        let mut stamped = 0usize;

        while let Some(base) = queue.pop_front() {
            if stamped >= FUEL { break; }

            let proj = match self.map.get(&base) {
                Some(p) => p.type_info.clone(),
                None => continue,
            };

            let hg_base = match heap_graph.find_object_base(base) {
                Some(b) => b,
                None => continue,
            };
            let obj = match heap_graph.objects().get(&hg_base) {
                Some(o) => o,
                None => continue,
            };
            let delta = base.wrapping_sub(hg_base);

            // collect candidates, sort by field name for deterministic BFS order
            let mut candidates: Vec<(&str, u64, &TypeInfo)> = Vec::new();
            for f in &proj.fields {
                if !f.type_info.is_pointer || f.byte_size != 8 {
                    continue;
                }
                let hg_offset = delta + f.byte_offset;
                let field_val = match obj.fields.get(&hg_offset) {
                    Some(fi) if fi.last_value != 0 => fi.last_value,
                    _ => continue,
                };
                if self.map.contains_key(&field_val) {
                    continue;
                }
                if allocs.alloc_size(field_val).is_none() {
                    continue;
                }
                let pointee_name = f.type_info.name.strip_prefix('*').unwrap_or("");
                match type_registry.get(pointee_name) {
                    Some(ti) => candidates.push((&f.name, field_val, ti)),
                    None => continue,
                };
            }
            candidates.sort_by_key(|(name, _, _)| *name);
            for (name, field_val, pointee_ti) in &candidates {
                self.stamp_type(*field_val, pointee_ti, name, seq);
                stamped += 1;
                queue.push_back(*field_val);
            }
        }
        stamped
    }
}

#[derive(Debug, Clone)]
pub enum HazardKind {
    OutOfBounds,
    HeapHole,
}

#[derive(Debug, Clone)]
pub struct HeapHazard {
    pub kind: HazardKind,
    pub write_addr: u64,
    pub write_size: u32,
    pub alloc_base: u64,
    pub alloc_size: u64,
    pub overflow_bytes: u64,
    pub type_name: Option<String>,
    pub field_name: Option<String>,
    pub pc: u64,
    pub reg_snapshot: Option<[u64; REG_COUNT]>,
}

pub struct HeapAllocTracker {
    allocs: BTreeMap<u64, u64>,
    pub total_allocs: u64,
    pub total_frees: u64,
    pub orphan_frees: u64,
    pub size_mismatches: Vec<SizeMismatch>,
}

#[derive(Debug, Clone)]
pub struct SizeMismatch {
    pub addr: u64,
    pub alloc_size: u64,
    pub type_size: u64,
    pub type_name: String,
}

impl HeapAllocTracker {
    pub fn new() -> Self {
        Self {
            allocs: BTreeMap::new(),
            total_allocs: 0,
            total_frees: 0,
            orphan_frees: 0,
            size_mismatches: Vec::new(),
        }
    }

    /// returns Some(old_size) if the address was already tracked (allocator reuse)
    pub fn on_alloc(&mut self, addr: u64, size: u64) -> Option<u64> {
        let old = self.allocs.insert(addr, size);
        self.total_allocs += 1;
        old
    }

    pub fn on_free(&mut self, addr: u64) -> Option<u64> {
        self.total_frees += 1;
        let r = self.allocs.remove(&addr);
        if r.is_none() { self.orphan_frees += 1; }
        r
    }

    pub fn alloc_size(&self, addr: u64) -> Option<u64> {
        self.allocs.get(&addr).copied()
    }

    pub fn allocs_iter(&self) -> impl Iterator<Item = (&u64, &u64)> {
        self.allocs.iter()
    }

    pub fn live_count(&self) -> usize {
        self.allocs.len()
    }

    /// O(log N) lookup: find the allocation whose range covers `addr`
    pub fn containing_alloc(&self, addr: u64) -> Option<(u64, u64)> {
        use std::ops::Bound;
        self.allocs
            .range((Bound::Unbounded, Bound::Included(&addr)))
            .next_back()
            .filter(|(&base, &sz)| addr < base + sz)
            .map(|(&base, &sz)| (base, sz))
    }

    /// check if a write at [addr, addr+write_size) stays within a live allocation.
    /// returns Some(hazard) if OOB or heap-hole detected.
    pub fn check_write_bounds(
        &self,
        addr: u64,
        write_size: u32,
        stm: &ShadowTypeMap,
    ) -> Option<HeapHazard> {
        let end = addr + write_size as u64;
        if let Some((base, alloc_sz)) = self.containing_alloc(addr) {
            if end > base + alloc_sz {
                let overflow = end - (base + alloc_sz);
                let sym = stm.covering(addr).map(|p| {
                    let off = addr - p.base_addr;
                    let field = p.type_info.fields.iter()
                        .find(|f| f.byte_offset == off)
                        .map(|f| f.name.clone());
                    (p.type_info.name.clone(), field)
                });
                return Some(HeapHazard {
                    kind: HazardKind::OutOfBounds,
                    write_addr: addr,
                    write_size,
                    alloc_base: base,
                    alloc_size: alloc_sz,
                    overflow_bytes: overflow,
                    type_name: sym.as_ref().map(|(t, _)| t.clone()),
                    field_name: sym.and_then(|(_, f)| f),
                    pc: 0,
                    reg_snapshot: None,
                });
            }
            return None;
        }
        // only flag heap-hole if addr falls within the span of known allocations
        let lo = self.allocs.keys().next().copied().unwrap_or(u64::MAX);
        let hi = self.allocs.iter().next_back()
            .map(|(&b, &s)| b + s).unwrap_or(0);
        if addr >= lo && addr < hi {
            return Some(HeapHazard {
                kind: HazardKind::HeapHole,
                write_addr: addr,
                write_size,
                alloc_base: 0,
                alloc_size: 0,
                overflow_bytes: 0,
                type_name: stm.covering(addr).map(|p| p.type_info.name.clone()),
                field_name: None,
                pc: 0,
                reg_snapshot: None,
            });
        }
        None
    }

    pub fn check_size(&mut self, addr: u64, type_info: &TypeInfo) -> bool {
        if let Some(&alloc_sz) = self.allocs.get(&addr) {
            if type_info.byte_size > alloc_sz {
                self.size_mismatches.push(SizeMismatch {
                    addr,
                    alloc_size: alloc_sz,
                    type_size: type_info.byte_size,
                    type_name: type_info.name.clone(),
                });
                return false;
            }
        }
        true
    }
}

pub struct WorldState {
    inner: Arc<WorldInner>,
    pub cl_tracker: CacheLineTracker,
    pub stm: ShadowTypeMap,
    pub heap_allocs: HeapAllocTracker,
    pub hazards: Vec<HeapHazard>,
    pub field_heatmap: FieldHeatmap,
}

impl WorldState {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(WorldInner::new()),
            cl_tracker: CacheLineTracker::new(),
            stm: ShadowTypeMap::new(),
            heap_allocs: HeapAllocTracker::new(),
            hazards: Vec::new(),
            field_heatmap: FieldHeatmap::new(),
        }
    }

    pub fn snapshot(&self) -> Arc<WorldInner> {
        Arc::clone(&self.inner)
    }

    #[inline]
    fn cow(&mut self) -> &mut WorldInner {
        Arc::make_mut(&mut self.inner)
    }

    pub fn insn_counter(&self) -> u64 {
        self.inner.insn_counter
    }
    pub fn inc_insn_counter(&mut self) {
        self.cow().insn_counter += 1;
    }

    pub fn ensure_node(
        &mut self,
        id: NodeId,
        name: &str,
        type_info: &TypeInfo,
        addr: u64,
        size: u64,
    ) -> bool {
        let inner = self.cow();
        if inner.nodes.contains_key(&id) {
            return false;
        }
        inner.nodes.insert(
            id,
            Node {
                name: name.to_string(),
                type_info: type_info.clone(),
                addr,
                size,
                raw_value: 0,
                last_write_insn: 0,
            },
        );
        true
    }

    pub fn remove_node(&mut self, id: NodeId) {
        let inner = self.cow();
        inner.nodes.remove(&id);
        inner.edges.remove(&id);
    }

    #[inline]
    pub fn update_value(&mut self, id: NodeId, value: u64, insn: u64) {
        if let Some(node) = self.cow().nodes.get_mut(&id) {
            node.raw_value = value;
            node.last_write_insn = insn;
        }
    }

    pub fn remove_frame_nodes(&mut self, frame_id: crate::index::FrameId) {
        let inner = self.cow();
        let dead: Vec<NodeId> = inner
            .nodes
            .keys()
            .filter(|k| matches!(k, NodeId::Local(fid, _) if *fid == frame_id))
            .copied()
            .collect();
        for id in &dead {
            inner.nodes.remove(id);
            inner.edges.remove(id);
        }
        inner.edges.retain(|_, e| !dead.contains(&e.target));
    }

    // null ptr: remove edge. nonzero unresolved: dangling sentinel.
    pub fn update_edge(&mut self, source: NodeId, target: Option<NodeId>, ptr_value: u64) {
        let inner = self.cow();
        match target {
            Some(tgt) => {
                inner.edges.insert(
                    source,
                    PointerEdge {
                        source,
                        target: tgt,
                        ptr_value,
                        is_dangling: false,
                    },
                );
            }
            None if ptr_value == 0 => {
                inner.edges.remove(&source);
            }
            None => {
                inner.edges.insert(
                    source,
                    PointerEdge {
                        source,
                        target: NodeId::Global(u32::MAX),
                        ptr_value,
                        is_dangling: true,
                    },
                );
            }
        }
    }

    pub fn regs(&self) -> [u64; REG_COUNT] {
        self.inner.reg_file.values
    }

    pub fn update_regs(&mut self, regs: [u64; REG_COUNT], insn: u64) {
        self.cow().reg_file.update(regs, insn);
    }

    pub fn record_cache_miss(&mut self, nid: NodeId) {
        self.cow().cache_heat.record_miss(nid);
    }

    pub fn cache_heat_tick(&mut self) {
        self.cow().cache_heat.tick();
    }

    #[inline(always)]
    pub fn record_cl_write(&mut self, addr: u64, thread_id: u16) -> u16 {
        self.cl_tracker.record_write(addr, thread_id)
    }

    pub fn cl_tracker_tick(&mut self) {
        self.cl_tracker.tick();
    }

    pub fn node_count(&self) -> usize {
        self.inner.nodes.len()
    }
    pub fn edge_count(&self) -> usize {
        self.inner.edges.len()
    }
}

// per-thread shadow stack. validates CALL/RETURN pairing.
#[derive(Debug, Clone)]
pub struct ShadowFrame {
    pub frame_id: crate::index::FrameId,
    pub callee_pc: u64,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ShadowStack {
    pub frames: Vec<ShadowFrame>,
    pub mismatches: u64,
    pub max_depth: usize,
}

impl ShadowStack {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            frames: Vec::with_capacity(64),
            mismatches: 0,
            max_depth: 0,
        }
    }

    pub fn push_call(&mut self, frame_id: crate::index::FrameId, callee_pc: u64, name: String) {
        self.frames.push(ShadowFrame {
            frame_id,
            callee_pc,
            name,
        });
        if self.frames.len() > self.max_depth {
            self.max_depth = self.frames.len();
        }
    }

    // returns frame if matched, None + increments mismatch if stack empty
    pub fn pop_return(&mut self) -> Option<ShadowFrame> {
        match self.frames.pop() {
            Some(f) => Some(f),
            None => {
                self.mismatches += 1;
                None
            }
        }
    }

    pub fn depth(&self) -> usize {
        self.frames.len()
    }
}

// circular snapshot buffer with triple-index for time-travel
pub struct SnapshotRing {
    buf: Vec<SnapEntry>,
    cap: usize,
    write_pos: usize,
    len: usize,
}

struct SnapEntry {
    snap: Arc<WorldInner>,
    insn: u64,
    tick: u64,
    event_seq: u64,
}

pub struct SnapRef<'a> {
    pub snap: &'a Arc<WorldInner>,
    pub insn: u64,
    pub tick: u64,
    pub event_seq: u64,
}

impl SnapshotRing {
    pub fn new(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
            cap,
            write_pos: 0,
            len: 0,
        }
    }

    pub fn push(&mut self, snap: Arc<WorldInner>, tick: u64, event_seq: u64) {
        let insn = snap.insn_counter;
        let entry = SnapEntry {
            snap,
            insn,
            tick,
            event_seq,
        };
        if self.buf.len() < self.cap {
            self.buf.push(entry);
        } else {
            self.buf[self.write_pos] = entry;
        }
        self.write_pos = (self.write_pos + 1) % self.cap;
        self.len = (self.len + 1).min(self.cap);
    }

    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    // index 0 = oldest, len-1 = newest
    fn slot(&self, idx: usize) -> Option<&SnapEntry> {
        if idx >= self.len {
            return None;
        }
        let start = if self.len < self.cap {
            0
        } else {
            self.write_pos
        };
        let real = (start + idx) % self.cap;
        Some(&self.buf[real])
    }

    pub fn get(&self, idx: usize) -> Option<SnapRef<'_>> {
        self.slot(idx).map(|e| SnapRef {
            snap: &e.snap,
            insn: e.insn,
            tick: e.tick,
            event_seq: e.event_seq,
        })
    }

    pub fn latest(&self) -> Option<SnapRef<'_>> {
        if self.len == 0 {
            return None;
        }
        self.get(self.len - 1)
    }

    // binary search by insn counter, returns nearest <= target
    pub fn find_by_insn(&self, target_insn: u64) -> Option<usize> {
        if self.len == 0 {
            return None;
        }
        let mut lo = 0usize;
        let mut hi = self.len;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.slot(mid).unwrap().insn <= target_insn {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo > 0 {
            Some(lo - 1)
        } else {
            None
        }
    }

    pub fn find_by_tick(&self, target_tick: u64) -> Option<usize> {
        if self.len == 0 {
            return None;
        }
        let mut lo = 0usize;
        let mut hi = self.len;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.slot(mid).unwrap().tick <= target_tick {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo > 0 {
            Some(lo - 1)
        } else {
            None
        }
    }

    pub fn find_by_seq(&self, target_seq: u64) -> Option<usize> {
        if self.len == 0 {
            return None;
        }
        let mut lo = 0usize;
        let mut hi = self.len;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.slot(mid).unwrap().event_seq <= target_seq {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo > 0 {
            Some(lo - 1)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dwarf::TypeInfo;

    fn ti(name: &str, sz: u64, ptr: bool) -> TypeInfo {
        TypeInfo {
            name: name.into(),
            byte_size: sz,
            is_pointer: ptr,
            is_volatile: false,
            is_atomic: false,
            fields: Vec::new(),
        }
    }

    #[test]
    fn test_cow_snapshot() {
        let mut ws = WorldState::new();
        ws.ensure_node(NodeId::Global(0), "x", &ti("int", 4, false), 0x1000, 4);
        ws.update_value(NodeId::Global(0), 42, 1);
        let snap = ws.snapshot();
        assert_eq!(snap.nodes[&NodeId::Global(0)].raw_value, 42);
        ws.update_value(NodeId::Global(0), 99, 2);
        assert_eq!(ws.snapshot().nodes[&NodeId::Global(0)].raw_value, 99);
        assert_eq!(snap.nodes[&NodeId::Global(0)].raw_value, 42);
    }

    #[test]
    fn test_pointer_edge() {
        let mut ws = WorldState::new();
        ws.ensure_node(NodeId::Global(0), "p", &ti("*int", 8, true), 0x1000, 8);
        ws.ensure_node(NodeId::Global(1), "x", &ti("int", 4, false), 0x2000, 4);
        ws.update_edge(NodeId::Global(0), Some(NodeId::Global(1)), 0x2000);
        assert_eq!(ws.edge_count(), 1);
        assert!(!ws.snapshot().edges[&NodeId::Global(0)].is_dangling);
        ws.update_edge(NodeId::Global(0), None, 0);
        assert_eq!(ws.edge_count(), 0);
        ws.update_edge(NodeId::Global(0), None, 0xdeadbeef);
        assert!(ws.snapshot().edges[&NodeId::Global(0)].is_dangling);
    }

    #[test]
    fn test_frame_cleanup() {
        let mut ws = WorldState::new();
        ws.ensure_node(NodeId::Global(0), "g", &ti("int", 4, false), 0x1000, 4);
        ws.ensure_node(NodeId::Local(1, 0), "a", &ti("int", 4, false), 0x7000, 4);
        ws.ensure_node(NodeId::Local(1, 1), "p", &ti("*int", 8, true), 0x7008, 8);
        ws.update_edge(NodeId::Local(1, 1), Some(NodeId::Global(0)), 0x1000);
        assert_eq!(ws.node_count(), 3);
        ws.remove_frame_nodes(1);
        assert_eq!(ws.node_count(), 1);
        assert_eq!(ws.edge_count(), 0);
    }

    #[test]
    fn test_snapshot_ring() {
        let mut ws = WorldState::new();
        ws.ensure_node(NodeId::Global(0), "x", &ti("int", 4, false), 0x1000, 4);

        let mut ring = SnapshotRing::new(4);
        for i in 0..6u64 {
            ws.update_value(NodeId::Global(0), i * 10, i);
            ws.inc_insn_counter();
            ring.push(ws.snapshot(), i, i);
        }

        assert_eq!(ring.len(), 4);
        assert_eq!(ring.get(0).unwrap().event_seq, 2);
        assert_eq!(ring.get(3).unwrap().event_seq, 5);
        assert_eq!(ring.latest().unwrap().event_seq, 5);

        let idx = ring.find_by_insn(4).unwrap();
        let sr = ring.get(idx).unwrap();
        assert!(sr.insn <= 4);

        assert!(ring.find_by_insn(0).is_none());
    }
}
