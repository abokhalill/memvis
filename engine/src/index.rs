// SPDX-License-Identifier: Apache-2.0

// Two tier addr->variable index. statics: sorted vec, O(log N). dynamics: HashMap<FrameId>, O(1) removal.

use crate::dwarf::TypeInfo;
use std::collections::HashMap;

pub type FrameId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NodeId {
    Global(u32),
    Field(u32, u16),
    Local(FrameId, u16),
}

#[derive(Debug, Clone)]
struct VarMeta {
    name: String,
    type_info: TypeInfo,
    node_id: NodeId,
}

#[derive(Debug, Clone)]
struct Interval {
    lo: u64,
    hi: u64,
    meta: VarMeta,
}

#[derive(Debug)]
pub struct LookupResult<'a> {
    pub name: &'a str,
    pub type_info: &'a TypeInfo,
    pub node_id: NodeId,
    pub offset_in_var: u64,
}

const MRU_SLOTS: usize = 8;

#[derive(Clone, Copy)]
enum MruEntry {
    Static { lo: u64, hi: u64, idx: usize },
    Dynamic { lo: u64, hi: u64, frame_id: FrameId, local_idx: usize },
}

impl MruEntry {
    fn contains(&self, addr: u64) -> bool {
        let (lo, hi) = match self {
            MruEntry::Static { lo, hi, .. } => (*lo, *hi),
            MruEntry::Dynamic { lo, hi, .. } => (*lo, *hi),
        };
        addr >= lo && addr < hi
    }
    fn lo(&self) -> u64 {
        match self { MruEntry::Static { lo, .. } | MruEntry::Dynamic { lo, .. } => *lo }
    }
}

pub struct AddressIndex {
    statics: Vec<Interval>,
    statics_sorted: bool,
    dynamics: HashMap<FrameId, Vec<Interval>>,
    mru: [Option<MruEntry>; MRU_SLOTS],
    mru_len: usize,
    universe_lo: u64,
    universe_hi: u64,
}

impl Default for AddressIndex {
    fn default() -> Self {
        Self {
            statics: Vec::with_capacity(2048),
            statics_sorted: true,
            dynamics: HashMap::with_capacity(64),
            mru: [None; MRU_SLOTS],
            mru_len: 0,
            universe_lo: u64::MAX,
            universe_hi: 0,
        }
    }
}

fn node_rank(nid: &NodeId) -> u8 {
    match nid {
        NodeId::Local(..) => 2,
        NodeId::Field(..) => 1,
        NodeId::Global(..) => 0,
    }
}

impl AddressIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_global(
        &mut self,
        addr: u64,
        size: u64,
        name: String,
        type_info: TypeInfo,
        global_idx: u32,
    ) {
        if size == 0 {
            return;
        }
        self.statics.push(Interval {
            lo: addr,
            hi: addr + size,
            meta: VarMeta {
                name,
                type_info,
                node_id: NodeId::Global(global_idx),
            },
        });
        self.statics_sorted = false;
        self.mru_len = 0;
        self.widen_universe(addr, addr + size);
    }

    pub fn insert_field(
        &mut self,
        addr: u64,
        size: u64,
        name: String,
        type_info: TypeInfo,
        global_idx: u32,
        field_idx: u16,
    ) {
        if size == 0 {
            return;
        }
        self.statics.push(Interval {
            lo: addr,
            hi: addr + size,
            meta: VarMeta {
                name,
                type_info,
                node_id: NodeId::Field(global_idx, field_idx),
            },
        });
        self.statics_sorted = false;
        self.mru_len = 0;
        self.widen_universe(addr, addr + size);
    }

    pub fn insert_frame_locals(
        &mut self,
        frame_id: FrameId,
        frame_base: u64,
        locals: &[(i64, u64, String, TypeInfo)],
    ) {
        let mut frame_ivs = Vec::with_capacity(locals.len());
        for (li, (offset, size, name, type_info)) in locals.iter().enumerate() {
            if *size == 0 {
                continue;
            }
            let addr = (frame_base as i64 + offset) as u64;
            frame_ivs.push(Interval {
                lo: addr,
                hi: addr + size,
                meta: VarMeta {
                    name: name.clone(),
                    type_info: type_info.clone(),
                    node_id: NodeId::Local(frame_id, li as u16),
                },
            });
        }
        for iv in &frame_ivs {
            self.widen_universe(iv.lo, iv.hi);
        }
        if !frame_ivs.is_empty() {
            self.dynamics.insert(frame_id, frame_ivs);
        }
        self.mru_len = 0;
    }

    pub fn remove_frame(&mut self, frame_id: FrameId) {
        self.dynamics.remove(&frame_id);
        self.mru_len = 0;
    }

    pub fn finalize(&mut self) {
        if !self.statics_sorted {
            self.statics.sort_unstable_by_key(|iv| iv.lo);
            self.statics_sorted = true;
            self.mru_len = 0;
        }
    }

    #[inline(always)]
    pub fn in_universe(&self, addr: u64) -> bool {
        addr >= self.universe_lo && addr < self.universe_hi
    }

    #[inline(always)]
    pub fn lookup(&mut self, addr: u64) -> Option<LookupResult<'_>> {
        if addr < self.universe_lo || addr >= self.universe_hi {
            return None;
        }
        for slot in 0..self.mru_len {
            if let Some(ref entry) = self.mru[slot] {
                if entry.contains(addr) {
                    let lo = entry.lo();
                    if slot > 0 {
                        let e = self.mru[slot].take().unwrap();
                        self.mru.copy_within(0..slot, 1);
                        self.mru[0] = Some(e);
                    }
                    return self.resolve_mru(0, addr, lo);
                }
            }
        }

        let dyn_hit = self.lookup_dynamics(addr);
        if let Some((frame_id, local_idx, lo, hi)) = dyn_hit {
            self.push_mru(MruEntry::Dynamic { lo, hi, frame_id, local_idx });
            let iv = &self.dynamics[&frame_id][local_idx];
            return Some(LookupResult {
                name: &iv.meta.name,
                type_info: &iv.meta.type_info,
                node_id: iv.meta.node_id,
                offset_in_var: addr - iv.lo,
            });
        }

        let stat_hit = self.lookup_statics(addr);
        if let Some((idx, lo, hi)) = stat_hit {
            self.push_mru(MruEntry::Static { lo, hi, idx });
            let iv = &self.statics[idx];
            return Some(LookupResult {
                name: &iv.meta.name,
                type_info: &iv.meta.type_info,
                node_id: iv.meta.node_id,
                offset_in_var: addr - iv.lo,
            });
        }

        None
    }

    fn resolve_mru(&self, slot: usize, addr: u64, lo: u64) -> Option<LookupResult<'_>> {
        match self.mru[slot].as_ref()? {
            MruEntry::Static { idx, .. } => {
                let iv = self.statics.get(*idx)?;
                Some(LookupResult {
                    name: &iv.meta.name,
                    type_info: &iv.meta.type_info,
                    node_id: iv.meta.node_id,
                    offset_in_var: addr - lo,
                })
            }
            MruEntry::Dynamic { frame_id, local_idx, .. } => {
                let frame = self.dynamics.get(frame_id)?;
                let iv = frame.get(*local_idx)?;
                Some(LookupResult {
                    name: &iv.meta.name,
                    type_info: &iv.meta.type_info,
                    node_id: iv.meta.node_id,
                    offset_in_var: addr - lo,
                })
            }
        }
    }

    fn push_mru(&mut self, entry: MruEntry) {
        let len = self.mru_len.min(MRU_SLOTS - 1);
        self.mru.copy_within(0..len, 1);
        self.mru[0] = Some(entry);
        self.mru_len = (self.mru_len + 1).min(MRU_SLOTS);
    }

    #[inline(always)]
    fn widen_universe(&mut self, lo: u64, hi: u64) {
        if lo < self.universe_lo { self.universe_lo = lo; }
        if hi > self.universe_hi { self.universe_hi = hi; }
    }

    fn lookup_dynamics(&self, addr: u64) -> Option<(FrameId, usize, u64, u64)> {
        let mut best: Option<(FrameId, usize, u64, u64, u64)> = None;
        for (&fid, frame_ivs) in &self.dynamics {
            for (li, iv) in frame_ivs.iter().enumerate() {
                if addr >= iv.lo && addr < iv.hi {
                    let span = iv.hi - iv.lo;
                    let dominated = match best {
                        None => true,
                        Some((_, _, _, _, prev_span)) => span < prev_span,
                    };
                    if dominated {
                        best = Some((fid, li, iv.lo, iv.hi, span));
                    }
                }
            }
        }
        best.map(|(fid, li, lo, hi, _)| (fid, li, lo, hi))
    }

    fn lookup_statics(&self, addr: u64) -> Option<(usize, u64, u64)> {
        let idx = self.statics.partition_point(|iv| iv.lo <= addr);
        if idx == 0 {
            return None;
        }

        let mut best: Option<(usize, &Interval)> = None;
        let mut i = idx - 1;
        loop {
            let iv = &self.statics[i];
            if iv.lo > addr {
                break;
            }
            if addr < iv.hi {
                let dominated = match best {
                    None => true,
                    Some((_, prev)) => {
                        let iv_r = node_rank(&iv.meta.node_id);
                        let prev_r = node_rank(&prev.meta.node_id);
                        iv_r > prev_r
                            || (iv_r == prev_r && (iv.hi - iv.lo) < (prev.hi - prev.lo))
                    }
                };
                if dominated {
                    best = Some((i, iv));
                }
            }
            if i == 0 || self.statics[i - 1].lo < iv.lo {
                break;
            }
            i -= 1;
        }

        best.map(|(iv_idx, iv)| (iv_idx, iv.lo, iv.hi))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ti(name: &str, sz: u64) -> TypeInfo {
        TypeInfo {
            name: name.into(),
            byte_size: sz,
            is_pointer: false,
            is_volatile: false,
            is_atomic: false,
            fields: Vec::new(),
        }
    }

    #[test]
    fn test_global_lookup() {
        let mut idx = AddressIndex::new();
        idx.insert_global(0x1000, 4, "x".into(), ti("int", 4), 0);
        idx.insert_global(0x2000, 8, "y".into(), ti("long", 8), 1);
        idx.finalize();
        assert_eq!(idx.lookup(0x1000).unwrap().name, "x");
        assert_eq!(idx.lookup(0x1002).unwrap().offset_in_var, 2);
        assert!(idx.lookup(0x1004).is_none());
        assert!(idx.lookup(0x0FFF).is_none());
        assert_eq!(idx.lookup(0x2004).unwrap().name, "y");
    }

    #[test]
    fn test_frame_insert_remove() {
        let mut idx = AddressIndex::new();
        idx.insert_global(0x1000, 4, "g".into(), ti("int", 4), 0);
        let locals = vec![
            (-8i64, 4u64, "a".to_string(), ti("int", 4)),
            (-16, 8, "p".to_string(), ti("*int", 8)),
        ];
        idx.insert_frame_locals(1, 0x7fff0000, &locals);
        idx.finalize();
        assert_eq!(idx.lookup(0x7fff0000u64.wrapping_sub(8)).unwrap().name, "a");
        idx.remove_frame(1);
        assert!(idx.lookup(0x7fff0000u64.wrapping_sub(8)).is_none());
        assert_eq!(idx.lookup(0x1000).unwrap().name, "g");
    }

    #[test]
    fn test_local_shadows_global() {
        let mut idx = AddressIndex::new();
        idx.insert_global(0x5000, 16, "glob".into(), ti("struct", 16), 0);
        idx.insert_frame_locals(1, 0x5000, &[(0i64, 4u64, "loc".to_string(), ti("int", 4))]);
        idx.finalize();
        assert_eq!(idx.lookup(0x5000).unwrap().name, "loc");
        assert_eq!(idx.lookup(0x5008).unwrap().name, "glob");
    }

    #[test]
    fn test_mru_hit() {
        let mut idx = AddressIndex::new();
        idx.insert_global(0x1000, 4, "x".into(), ti("int", 4), 0);
        idx.finalize();
        // first lookup populates MRU
        assert_eq!(idx.lookup(0x1000).unwrap().name, "x");
        // second should hit MRU
        assert_eq!(idx.lookup(0x1002).unwrap().name, "x");
        assert_eq!(idx.lookup(0x1002).unwrap().offset_in_var, 2);
    }

    #[test]
    fn test_dynamic_frame_removal_o1() {
        let mut idx = AddressIndex::new();
        // insert 100 frames
        for fid in 0..100u64 {
            let base = 0x7fff0000 + fid * 0x100;
            let locals = vec![(0i64, 8u64, format!("v{}", fid), ti("long", 8))];
            idx.insert_frame_locals(fid, base, &locals);
        }
        // remove one — should be O(1), not O(N)
        idx.remove_frame(50);
        assert!(idx.lookup(0x7fff0000 + 50 * 0x100).is_none());
        // others still present
        assert_eq!(idx.lookup(0x7fff0000 + 49 * 0x100).unwrap().name, "v49");
    }
}
