// SPDX-License-Identifier: MIT
// flat sorted interval map. O(log N) point queries via partition_point.
// two tiers: static globals (inserted once) + dynamic stack locals (per frame).
// locals shadow globals on overlap. re-sorted after each call/return.

use crate::dwarf::TypeInfo;

pub type FrameId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NodeId {
    Global(u32),
    Field(u32, u16), // (global_idx, field_idx) — struct field decomposition
    Local(FrameId, u16),
}

#[derive(Debug, Clone)]
struct VarMeta {
    name: String,
    type_info: TypeInfo,
    node_id: NodeId,
    frame_id: Option<FrameId>,
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

pub struct AddressIndex {
    intervals: Vec<Interval>,
    needs_sort: bool,
}

impl AddressIndex {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            intervals: Vec::with_capacity(2048),
            needs_sort: false,
        }
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
        self.intervals.push(Interval {
            lo: addr,
            hi: addr + size,
            meta: VarMeta {
                name,
                type_info,
                node_id: NodeId::Global(global_idx),
                frame_id: None,
            },
        });
        self.needs_sort = true;
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
        self.intervals.push(Interval {
            lo: addr,
            hi: addr + size,
            meta: VarMeta {
                name,
                type_info,
                node_id: NodeId::Field(global_idx, field_idx),
                frame_id: None,
            },
        });
        self.needs_sort = true;
    }

    pub fn insert_frame_locals(
        &mut self,
        frame_id: FrameId,
        frame_base: u64,
        locals: &[(i64, u64, String, TypeInfo)],
    ) {
        for (li, (offset, size, name, type_info)) in locals.iter().enumerate() {
            if *size == 0 {
                continue;
            }
            let addr = (frame_base as i64 + offset) as u64;
            self.intervals.push(Interval {
                lo: addr,
                hi: addr + size,
                meta: VarMeta {
                    name: name.clone(),
                    type_info: type_info.clone(),
                    node_id: NodeId::Local(frame_id, li as u16),
                    frame_id: Some(frame_id),
                },
            });
        }
        self.needs_sort = true;
    }

    pub fn remove_frame(&mut self, frame_id: FrameId) {
        self.intervals
            .retain(|iv| iv.meta.frame_id != Some(frame_id));
    }

    pub fn finalize(&mut self) {
        if self.needs_sort {
            self.intervals.sort_unstable_by_key(|iv| iv.lo);
            self.needs_sort = false;
        }
    }

    // binary search for rightmost interval where lo <= addr, check hi.
    // on overlap (local shadows global), prefer dynamic entry.
    #[inline(always)]
    pub fn lookup(&self, addr: u64) -> Option<LookupResult<'_>> {
        let idx = self.intervals.partition_point(|iv| iv.lo <= addr);
        if idx == 0 {
            return None;
        }

        let mut best: Option<&Interval> = None;
        let mut i = idx - 1;
        loop {
            let iv = &self.intervals[i];
            if iv.lo > addr {
                break;
            }
            if addr < iv.hi {
                let dominated = match best {
                    None => true,
                    Some(prev) => {
                        // prefer: locals > fields > globals; narrower > wider on tie
                        let iv_rank = match iv.meta.node_id {
                            NodeId::Local(..) => 2,
                            NodeId::Field(..) => 1,
                            NodeId::Global(..) => 0,
                        };
                        let prev_rank = match prev.meta.node_id {
                            NodeId::Local(..) => 2,
                            NodeId::Field(..) => 1,
                            NodeId::Global(..) => 0,
                        };
                        iv_rank > prev_rank
                            || (iv_rank == prev_rank && (iv.hi - iv.lo) < (prev.hi - prev.lo))
                    }
                };
                if dominated {
                    best = Some(iv);
                }
            }
            if i == 0 || self.intervals[i - 1].lo < iv.lo {
                break;
            }
            i -= 1;
        }

        best.map(|iv| LookupResult {
            name: &iv.meta.name,
            type_info: &iv.meta.type_info,
            node_id: iv.meta.node_id,
            offset_in_var: addr - iv.lo,
        })
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
}
