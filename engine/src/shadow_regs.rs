// SPDX-License-Identifier: Apache-2.0
// shadow register file + DW_OP_piece assembler.

use crate::dwarf::{ExprStep, FunctionMeta, LocationPiece};
use crate::world::REG_COUNT;

// sysv amd64 abi classification (indices into reg_file)
const CALLEE_SAVED: [usize; 6] = [1, 6, 12, 13, 14, 15];
const CALLER_SAVED: [usize; 9] = [0, 2, 3, 4, 5, 8, 9, 10, 11];
const ARG_REGS: [usize; 6] = [5, 4, 3, 2, 8, 9]; // rdi,rsi,rdx,rcx,r8,r9

// dwarf reg# -> memvis reg_file index. note: dwarf 1=rdx(3), 2=rcx(2), 3=rbx(1)
const DWARF_TO_IDX: [Option<usize>; 17] = [
    Some(0),
    Some(3),
    Some(2),
    Some(1),
    Some(4),
    Some(5),
    Some(6),
    Some(7),
    Some(8),
    Some(9),
    Some(10),
    Some(11),
    Some(12),
    Some(13),
    Some(14),
    Some(15),
    Some(16),
];

fn dwarf_reg_to_idx(dwarf_reg: u16) -> Option<usize> {
    DWARF_TO_IDX.get(dwarf_reg as usize).copied().flatten()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Unknown = 0,
    Stale = 1,
    Speculative = 2,
    WriteBack = 3,
    AbiInferred = 4,
    Observed = 5,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Unknown => "???",
            Confidence::Stale => "STALE",
            Confidence::Speculative => "spec",
            Confidence::WriteBack => "wb",
            Confidence::AbiInferred => "abi",
            Confidence::Observed => "obs",
        }
    }

    pub fn bar_tenths(self) -> u8 {
        match self {
            Confidence::Unknown => 0,
            Confidence::Stale => 2,
            Confidence::Speculative => 5,
            Confidence::WriteBack => 7,
            Confidence::AbiInferred => 9,
            Confidence::Observed => 10,
        }
    }

    pub fn is_stale(self) -> bool {
        self == Confidence::Stale
    }
}

#[derive(Debug, Clone)]
pub enum Provenance {
    Observed { event_seq: u64 },
    CalleeSaved { since_seq: u64 },
    AbiArg { callee_pc: u64, arg_index: u8 },
    WriteBack { write_seq: u64, retroactive_pc: u64 },
    Reload { from_addr: u64, reload_seq: u64 },
    Copy { from_idx: usize, when_seq: u64 },
    ReturnValue { callee_pc: u64, ret_seq: u64 },
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ShadowReg {
    pub value: u64,
    pub provenance: Provenance,
    pub confidence: Confidence,
    pub last_seq: u64,
    pub last_pc: u64,
    pub mem_source: Option<u64>,
    pub mem_source_size: u32,
}

impl ShadowReg {
    fn unknown() -> Self {
        Self {
            value: 0,
            provenance: Provenance::Unknown,
            confidence: Confidence::Unknown,
            last_seq: 0,
            last_pc: 0,
            mem_source: None,
            mem_source_size: 0,
        }
    }

    fn set(&mut self, value: u64, prov: Provenance, conf: Confidence, seq: u64, pc: u64) {
        self.value = value;
        self.provenance = prov;
        self.confidence = conf;
        self.last_seq = seq;
        self.last_pc = pc;
        self.mem_source = None;
        self.mem_source_size = 0;
    }
}

#[derive(Debug, Clone)]
struct ShadowFrame {
    callee_pc: u64,
    saved_regs: [ShadowReg; REG_COUNT],
    _entry_seq: u64,
}

pub struct ShadowRegisterFile {
    regs: [ShadowReg; REG_COUNT],
    call_stack: Vec<ShadowFrame>,
}

impl Default for ShadowRegisterFile {
    fn default() -> Self {
        Self::new()
    }
}

impl ShadowRegisterFile {
    pub fn new() -> Self {
        Self {
            regs: std::array::from_fn(|_| ShadowReg::unknown()),
            call_stack: Vec::with_capacity(64),
        }
    }

    pub fn reg(&self, idx: usize) -> &ShadowReg {
        &self.regs[idx]
    }

    pub fn values(&self) -> [u64; REG_COUNT] {
        std::array::from_fn(|i| self.regs[i].value)
    }

    pub fn apply_snapshot(&mut self, values: &[u64; REG_COUNT], seq: u64, pc: u64) {
        for (i, &val) in values.iter().enumerate().take(REG_COUNT) {
            self.regs[i].set(
                val,
                Provenance::Observed { event_seq: seq },
                Confidence::Observed,
                seq,
                pc,
            );
        }
    }

    pub fn observe_write(
        &mut self,
        _addr: u64,
        value: u64,
        pc: u64,
        seq: u64,
        func: Option<&FunctionMeta>,
    ) {
        let Some(func) = func else { return };
        for local in &func.locals {
            let Some(piece) = local.location.lookup(pc) else {
                continue;
            };
            if let LocationPiece::Register(dwarf_reg) = piece {
                if let Some(idx) = dwarf_reg_to_idx(*dwarf_reg) {
                    self.regs[idx].set(
                        value,
                        Provenance::WriteBack {
                            write_seq: seq,
                            retroactive_pc: pc,
                        },
                        Confidence::WriteBack,
                        seq,
                        pc,
                    );
                }
            }
        }
    }

    pub fn on_call(&mut self, callee_pc: u64, rsp: u64, seq: u64) {
        self.call_stack.push(ShadowFrame {
            callee_pc,
            saved_regs: self.regs.clone(),
            _entry_seq: seq,
        });

        self.regs[7].set(
            rsp,
            Provenance::Observed { event_seq: seq },
            Confidence::Observed,
            seq,
            callee_pc,
        );

        for &idx in &CALLEE_SAVED {
            if self.regs[idx].confidence >= Confidence::Speculative {
                let prev_val = self.regs[idx].value;
                self.regs[idx].set(
                    prev_val,
                    Provenance::CalleeSaved { since_seq: seq },
                    Confidence::AbiInferred,
                    seq,
                    callee_pc,
                );
            }
        }

        for &idx in &CALLER_SAVED {
            self.regs[idx].set(
                self.regs[idx].value,
                Provenance::AbiArg {
                    callee_pc,
                    arg_index: ARG_REGS.iter().position(|&r| r == idx).unwrap_or(0xff) as u8,
                },
                Confidence::Speculative,
                seq,
                callee_pc,
            );
        }
    }

    pub fn on_return(&mut self, seq: u64, pc: u64) {
        let frame = match self.call_stack.pop() {
            Some(f) => f,
            None => return,
        };

        for &idx in &CALLEE_SAVED {
            self.regs[idx] = frame.saved_regs[idx].clone();
        }

        self.regs[0].set(
            self.regs[0].value,
            Provenance::ReturnValue {
                callee_pc: frame.callee_pc,
                ret_seq: seq,
            },
            Confidence::Speculative,
            seq,
            pc,
        );

        for &idx in &CALLER_SAVED {
            if idx == 0 {
                continue;
            }
            self.regs[idx] = frame.saved_regs[idx].clone();
        }
    }

    pub fn on_reload(
        &mut self,
        reg_idx: usize,
        value: u64,
        from_addr: u64,
        load_size: u32,
        seq: u64,
        pc: u64,
    ) {
        if reg_idx >= REG_COUNT {
            return;
        }
        self.regs[reg_idx].set(
            value,
            Provenance::Reload {
                from_addr,
                reload_seq: seq,
            },
            Confidence::Observed,
            seq,
            pc,
        );
        self.regs[reg_idx].mem_source = Some(from_addr);
        self.regs[reg_idx].mem_source_size = load_size;
    }

    // interval overlap coherence: [w, w+ws) ∩ [src, src+ss). wide writes (>8B) always stale.
    pub fn check_coherence(
        &mut self,
        written_addr: u64,
        written_value: u64,
        write_size: u32,
        _write_seq: u64,
    ) {
        let w_end = written_addr.saturating_add(write_size.max(1) as u64);
        for i in 0..REG_COUNT {
            if let Some(src) = self.regs[i].mem_source {
                let s_size = self.regs[i].mem_source_size.max(1) as u64;
                let s_end = src.saturating_add(s_size);
                if written_addr < s_end && src < w_end {
                    let definitely_changed = if write_size > 8 {
                        true
                    } else {
                        self.regs[i].value != written_value
                    };
                    if definitely_changed && self.regs[i].confidence > Confidence::Stale {
                        self.regs[i].confidence = Confidence::Stale;
                    }
                }
            }
        }
    }
}


#[derive(Debug, Clone)]
pub struct PieceFragment {
    pub var_offset: u64,
    pub byte_size: u64,
    pub source: PieceSource,
}

#[derive(Debug, Clone)]
pub enum PieceSource {
    Register(u16),
    RegisterOffset(u16, i64),
    Memory(u64),
    FrameBaseOffset(i64),
    Implicit(u64),
    Unknown,
}

#[derive(Debug)]
pub struct AssembledValue {
    pub bytes: Vec<u8>,
    pub confidence: Vec<Confidence>,
    pub min_confidence: Confidence,
    pub resolved_count: usize,
    pub total_count: usize,
}

pub struct PieceAssembler;

impl PieceAssembler {
    pub fn parse_pieces(steps: &[ExprStep]) -> Vec<PieceFragment> {
        let mut fragments = Vec::new();
        let mut var_offset: u64 = 0;
        let mut pending_source: Option<PieceSource> = None;

        for step in steps {
            match step {
                ExprStep::Piece(byte_size) => {
                    let source = pending_source.take().unwrap_or(PieceSource::Unknown);
                    fragments.push(PieceFragment {
                        var_offset,
                        byte_size: *byte_size,
                        source,
                    });
                    var_offset += byte_size;
                }
                ExprStep::Reg(dwarf_reg) => {
                    pending_source = Some(PieceSource::Register(*dwarf_reg));
                }
                ExprStep::BReg(dwarf_reg, offset) => {
                    pending_source = Some(PieceSource::RegisterOffset(*dwarf_reg, *offset));
                }
                ExprStep::Addr(a) => {
                    pending_source = Some(PieceSource::Memory(*a));
                }
                ExprStep::FrameBase(off) => {
                    pending_source = Some(PieceSource::FrameBaseOffset(*off));
                }
                ExprStep::StackValue => {
                    pending_source = Some(PieceSource::Implicit(0));
                }
                ExprStep::Lit(v) => {
                    pending_source = Some(PieceSource::Implicit(*v));
                }
                ExprStep::SignedLit(v) => {
                    pending_source = Some(PieceSource::Implicit(*v as u64));
                }
                _ => {
                    if pending_source.is_none() {
                        pending_source = Some(PieceSource::Unknown);
                    }
                }
            }
        }

        if fragments.is_empty() {
            if let Some(source) = pending_source {
                fragments.push(PieceFragment {
                    var_offset: 0,
                    byte_size: 0, // caller fills from type_info
                    source,
                });
            }
        }

        fragments
    }

    pub fn resolve_pieces(
        fragments: &[PieceFragment],
        total_byte_size: u64,
        srf: &ShadowRegisterFile,
        frame_base: u64,
        read_mem: &dyn Fn(u64, u64) -> Option<Vec<u8>>,
    ) -> AssembledValue {
        let total = total_byte_size as usize;
        let mut bytes = vec![0u8; total];
        let mut confidence = vec![Confidence::Unknown; total];
        let mut min_conf = Confidence::Observed;
        let mut resolved = 0usize;

        for frag in fragments {
            let off = frag.var_offset as usize;
            let sz = frag.byte_size as usize;
            if off + sz > total {
                continue;
            }

            let (frag_bytes, frag_conf) = match &frag.source {
                PieceSource::Register(dwarf_reg) => match dwarf_reg_to_idx(*dwarf_reg) {
                    Some(idx) => {
                        let sr = &srf.regs[idx];
                        let val_bytes = sr.value.to_le_bytes();
                        let take = sz.min(8);
                        (val_bytes[..take].to_vec(), sr.confidence)
                    }
                    None => (vec![0u8; sz], Confidence::Unknown),
                },

                PieceSource::RegisterOffset(dwarf_reg, offset) => {
                    match dwarf_reg_to_idx(*dwarf_reg) {
                        Some(idx) => {
                            let sr = &srf.regs[idx];
                            let addr = (sr.value as i64).wrapping_add(*offset) as u64;
                            match read_mem(addr, sz as u64) {
                                Some(mem_bytes) => (mem_bytes, sr.confidence),
                                None => (vec![0u8; sz], Confidence::Unknown),
                            }
                        }
                        None => (vec![0u8; sz], Confidence::Unknown),
                    }
                }

                PieceSource::Memory(addr) => match read_mem(*addr, sz as u64) {
                    Some(mem_bytes) => (mem_bytes, Confidence::Observed),
                    None => (vec![0u8; sz], Confidence::Unknown),
                },

                PieceSource::FrameBaseOffset(offset) => {
                    let addr = (frame_base as i64).wrapping_add(*offset) as u64;
                    match read_mem(addr, sz as u64) {
                        Some(mem_bytes) => (mem_bytes, Confidence::Observed),
                        None => (vec![0u8; sz], Confidence::Unknown),
                    }
                }

                PieceSource::Implicit(val) => {
                    let val_bytes = val.to_le_bytes();
                    let take = sz.min(8);
                    (val_bytes[..take].to_vec(), Confidence::Observed)
                }

                PieceSource::Unknown => (vec![0u8; sz], Confidence::Unknown),
            };

            let copy_len = frag_bytes.len().min(sz);
            bytes[off..off + copy_len].copy_from_slice(&frag_bytes[..copy_len]);
            for c in confidence.iter_mut().skip(off).take(copy_len) {
                *c = frag_conf;
            }

            if frag_conf > Confidence::Unknown {
                resolved += 1;
            }
            if frag_conf < min_conf {
                min_conf = frag_conf;
            }
        }

        AssembledValue {
            bytes,
            confidence,
            min_confidence: min_conf,
            resolved_count: resolved,
            total_count: fragments.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_two_register_pieces() {
        let steps = vec![
            ExprStep::Reg(3),
            ExprStep::Piece(4),
            ExprStep::Reg(12),
            ExprStep::Piece(4),
        ];
        let frags = PieceAssembler::parse_pieces(&steps);
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].var_offset, 0);
        assert_eq!(frags[0].byte_size, 4);
        assert!(matches!(frags[0].source, PieceSource::Register(3)));
        assert_eq!(frags[1].var_offset, 4);
        assert_eq!(frags[1].byte_size, 4);
        assert!(matches!(frags[1].source, PieceSource::Register(12)));
    }

    #[test]
    fn test_parse_reg_plus_memory_piece() {
        let steps = vec![
            ExprStep::Reg(5),
            ExprStep::Piece(4),
            ExprStep::BReg(6, -8),
            ExprStep::Piece(4),
        ];
        let frags = PieceAssembler::parse_pieces(&steps);
        assert_eq!(frags.len(), 2);
        assert!(matches!(frags[0].source, PieceSource::Register(5)));
        assert!(matches!(
            frags[1].source,
            PieceSource::RegisterOffset(6, -8)
        ));
    }

    #[test]
    fn test_resolve_two_register_pieces() {
        let mut srf = ShadowRegisterFile::new();
        srf.regs[1].set(
            0xAABBCCDD,
            Provenance::Observed { event_seq: 1 },
            Confidence::Observed,
            1,
            0x1000,
        );
        srf.regs[12].set(
            0x11223344,
            Provenance::Observed { event_seq: 2 },
            Confidence::Observed,
            2,
            0x1000,
        );

        let frags = vec![
            PieceFragment {
                var_offset: 0,
                byte_size: 4,
                source: PieceSource::Register(3),
            },
            PieceFragment {
                var_offset: 4,
                byte_size: 4,
                source: PieceSource::Register(12),
            },
        ];

        let result = PieceAssembler::resolve_pieces(&frags, 8, &srf, 0, &|_addr, _sz| None);

        assert_eq!(result.bytes.len(), 8);
        assert_eq!(result.resolved_count, 2);
        assert_eq!(result.min_confidence, Confidence::Observed);

        let x = u32::from_le_bytes(result.bytes[0..4].try_into().unwrap());
        assert_eq!(x, 0xAABBCCDD);
        let y = u32::from_le_bytes(result.bytes[4..8].try_into().unwrap());
        assert_eq!(y, 0x11223344);
    }

    #[test]
    fn test_mixed_confidence_pieces() {
        let mut srf = ShadowRegisterFile::new();
        srf.regs[1].set(
            42,
            Provenance::Observed { event_seq: 1 },
            Confidence::Observed,
            1,
            0x1000,
        );
        srf.regs[12].set(
            99,
            Provenance::CalleeSaved { since_seq: 0 },
            Confidence::Speculative,
            0,
            0x1000,
        );

        let frags = vec![
            PieceFragment {
                var_offset: 0,
                byte_size: 4,
                source: PieceSource::Register(3),
            },
            PieceFragment {
                var_offset: 4,
                byte_size: 4,
                source: PieceSource::Register(12),
            },
        ];

        let result = PieceAssembler::resolve_pieces(&frags, 8, &srf, 0, &|_addr, _sz| None);

        assert_eq!(result.min_confidence, Confidence::Speculative);
        assert_eq!(result.confidence[0], Confidence::Observed);
        assert_eq!(result.confidence[4], Confidence::Speculative);
    }

    #[test]
    fn test_call_return_callee_saved_persistence() {
        let mut srf = ShadowRegisterFile::new();
        let mut snapshot = [0u64; REG_COUNT];
        snapshot[1] = 0xDEADBEEF;
        snapshot[0] = 0x42;
        srf.apply_snapshot(&snapshot, 0, 0x1000);

        assert_eq!(srf.regs[1].confidence, Confidence::Observed);
        srf.on_call(0x2000, 0x7FFF0000, 1);
        assert_eq!(srf.regs[1].value, 0xDEADBEEF);
        assert_eq!(srf.regs[1].confidence, Confidence::AbiInferred);
        assert_eq!(srf.regs[0].confidence, Confidence::Speculative);
        srf.on_return(2, 0x1005);
        assert_eq!(srf.regs[1].value, 0xDEADBEEF);
        assert_eq!(srf.regs[1].confidence, Confidence::Observed);
    }

    #[test]
    fn test_no_pieces_single_register() {
        let steps = vec![ExprStep::Reg(3)];
        let frags = PieceAssembler::parse_pieces(&steps);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].var_offset, 0);
        assert!(matches!(frags[0].source, PieceSource::Register(3)));
    }

    #[test]
    fn test_reload_sets_observed_and_mem_source() {
        let mut srf = ShadowRegisterFile::new();
        // R12 = idx 12. load from 0x5555_0000_1000
        srf.on_reload(12, 0xCAFEBABE, 0x5555_0000_1000, 8, 100, 0x4000);
        assert_eq!(srf.regs[12].value, 0xCAFEBABE);
        assert_eq!(srf.regs[12].confidence, Confidence::Observed);
        assert_eq!(srf.regs[12].mem_source, Some(0x5555_0000_1000));
        assert!(matches!(srf.regs[12].provenance, Provenance::Reload { .. }));
    }

    #[test]
    fn test_coherence_marks_stale_on_foreign_write() {
        let mut srf = ShadowRegisterFile::new();
        // simulate reload: R12 loaded from 0x5555_0000_1000
        srf.on_reload(12, 0xAAAA, 0x5555_0000_1000, 8, 100, 0x4000);
        assert_eq!(srf.regs[12].confidence, Confidence::Observed);

        // foreign thread writes a *different* value to the same address
        srf.check_coherence(0x5555_0000_1000, 0xBBBB, 8, 200);
        assert_eq!(srf.regs[12].confidence, Confidence::Stale);
        assert!(srf.regs[12].confidence.is_stale());
    }

    #[test]
    fn test_coherence_no_stale_if_same_value() {
        let mut srf = ShadowRegisterFile::new();
        srf.on_reload(12, 0xAAAA, 0x5555_0000_1000, 8, 100, 0x4000);

        // write same value: no staleness
        srf.check_coherence(0x5555_0000_1000, 0xAAAA, 8, 200);
        assert_eq!(srf.regs[12].confidence, Confidence::Observed);
    }

    #[test]
    fn test_coherence_no_stale_if_unrelated_address() {
        let mut srf = ShadowRegisterFile::new();
        srf.on_reload(12, 0xAAAA, 0x5555_0000_1000, 8, 100, 0x4000);

        // write to unrelated address
        srf.check_coherence(0x5555_0000_2000, 0xBBBB, 8, 200);
        assert_eq!(srf.regs[12].confidence, Confidence::Observed);
    }

    #[test]
    fn test_reload_clears_stale() {
        let mut srf = ShadowRegisterFile::new();
        srf.on_reload(12, 0xAAAA, 0x5555_0000_1000, 8, 100, 0x4000);
        srf.check_coherence(0x5555_0000_1000, 0xBBBB, 8, 200);
        assert_eq!(srf.regs[12].confidence, Confidence::Stale);

        // fresh reload restores Observed
        srf.on_reload(12, 0xBBBB, 0x5555_0000_1000, 8, 300, 0x4010);
        assert_eq!(srf.regs[12].confidence, Confidence::Observed);
        assert_eq!(srf.regs[12].value, 0xBBBB);
    }

    #[test]
    fn test_adversarial_sse_unaligned_cross_cacheline() {
        let mut srf = ShadowRegisterFile::new();
        // R12 loaded 8 bytes from 0x103C (straddles cache-line at 0x1040)
        srf.on_reload(12, 0xDEAD_BEEF_CAFE_F00D, 0x103C, 8, 100, 0x4000);
        assert_eq!(srf.regs[12].confidence, Confidence::Observed);
        assert_eq!(srf.regs[12].mem_source_size, 8);

        // 16-byte SSE movups to 0x1038: covers [0x1038..0x1048)
        // value is 0 because safe_read_value clamps to 8B for size>8
        // overlap: [0x1038, 0x1048) ∩ [0x103C, 0x1044) = [0x103C, 0x1044) ≠ ∅
        srf.check_coherence(0x1038, 0 /* truncated */, 16, 200);
        assert_eq!(
            srf.regs[12].confidence,
            Confidence::Stale,
            "16B SSE write overlapping upper portion of 8B source must mark Stale"
        );
    }

    // Sub-case: SSE write where only the FIRST 4 bytes overlap the tail of
    // a register's source range. Tests the low-end boundary.
    #[test]
    fn test_adversarial_sse_partial_low_overlap() {
        let mut srf = ShadowRegisterFile::new();
        // R13 loaded 8B from 0x1000. source range: [0x1000..0x1008)
        srf.on_reload(13, 0x1111_2222_3333_4444, 0x1000, 8, 100, 0x4000);

        // 16-byte write to 0x0FF8: covers [0x0FF8..0x1008)
        // overlaps the last 8 bytes of the write with source
        srf.check_coherence(0x0FF8, 0, 16, 200);
        assert_eq!(
            srf.regs[13].confidence,
            Confidence::Stale,
            "16B write starting below source but overlapping it must trigger Stale"
        );
    }

    // Sub-case: 16-byte write that is completely BEFORE the source — no overlap.
    #[test]
    fn test_adversarial_sse_no_overlap() {
        let mut srf = ShadowRegisterFile::new();
        srf.on_reload(12, 0xAAAA, 0x1040, 8, 100, 0x4000);

        // 16-byte write to 0x1020: covers [0x1020..0x1030). No overlap with [0x1040..0x1048).
        srf.check_coherence(0x1020, 0, 16, 200);
        assert_eq!(
            srf.regs[12].confidence,
            Confidence::Observed,
            "16B write entirely before source must NOT trigger Stale"
        );
    }

    // The tracer-level bug (no RELOAD for atomic RMW) is a separate issue;
    // this test validates the coherence path works for the WRITE half.
    #[test]
    fn test_adversarial_atomic_rmw_write_coherence() {
        let mut srf_a = ShadowRegisterFile::new();
        // Thread A: R12 loaded counter value 41 from 0x2000
        srf_a.on_reload(12, 41, 0x2000, 8, 100, 0x4000);
        assert_eq!(srf_a.regs[12].confidence, Confidence::Observed);

        // Thread B does `lock xadd [0x2000], rcx` where rcx=1.
        // Tracer emits WRITE(addr=0x2000, value=42, size=8) — the post-increment value.
        // Cross-thread coherence check on thread A's SRF:
        srf_a.check_coherence(0x2000, 42, 8, 200);
        assert_eq!(
            srf_a.regs[12].confidence,
            Confidence::Stale,
            "lock xadd post-increment write must invalidate stale shadow of pre-increment value"
        );
        assert_eq!(
            srf_a.regs[12].value, 41,
            "Stale register must retain old value (not silently update to new)"
        );
    }

    // Sub-case: lock cmpxchg that FAILS (old value == expected).
    // The write still occurs (same value written back), so WRITE event fires
    // with the same value. coherence should NOT mark stale.
    #[test]
    fn test_adversarial_atomic_cmpxchg_fail_no_stale() {
        let mut srf_a = ShadowRegisterFile::new();
        srf_a.on_reload(12, 41, 0x2000, 8, 100, 0x4000);

        // lock cmpxchg fails: writes back the same value 41
        srf_a.check_coherence(0x2000, 41, 8, 200);
        assert_eq!(
            srf_a.regs[12].confidence,
            Confidence::Observed,
            "Failed cmpxchg (same value written back) must NOT trigger Stale"
        );
    }

    // Sub-case: ABA problem. lock cmpxchg succeeds, writes new value,
    // then another cmpxchg writes the ORIGINAL value back.
    // The register should be marked stale after the first write,
    // and should NOT be "healed" by the second write without a reload.
    #[test]
    fn test_adversarial_atomic_aba_sequence() {
        let mut srf_a = ShadowRegisterFile::new();
        srf_a.on_reload(12, 41, 0x2000, 8, 100, 0x4000);

        // step 1: cmpxchg succeeds, writes 42
        srf_a.check_coherence(0x2000, 42, 8, 200);
        assert_eq!(srf_a.regs[12].confidence, Confidence::Stale);

        // step 2: another thread writes 41 back (ABA)
        // BUT: once Stale, same-value writes don't heal it because
        // Stale <= Stale is false (confidence > Stale check fails).
        srf_a.check_coherence(0x2000, 41, 8, 300);
        assert_eq!(
            srf_a.regs[12].confidence,
            Confidence::Stale,
            "ABA write-back must NOT silently heal a stale register — only a RELOAD can"
        );
    }

    // Scenario: struct { uint64_t lo; uint64_t hi; } at address 0x3000.
    // DWARF says: lo → R12 (DW_OP_piece 8), hi → R13 (DW_OP_piece 8).
    // R12 loaded from 0x3000 (8B), R13 loaded from 0x3008 (8B).
    // Thread B does a 16-byte write to 0x3000 (e.g. SSE store of the whole struct).
    // BOTH registers must be invalidated.
    #[test]
    fn test_adversarial_false_sharing_adjacent_pieces() {
        let mut srf = ShadowRegisterFile::new();
        // R12 = lo, loaded from 0x3000, 8 bytes
        srf.on_reload(12, 0xAAAA_AAAA, 0x3000, 8, 100, 0x4000);
        // R13 = hi, loaded from 0x3008, 8 bytes
        srf.on_reload(13, 0xBBBB_BBBB, 0x3008, 8, 101, 0x4004);

        // 16-byte write to 0x3000: covers [0x3000..0x3010)
        // R12 source [0x3000..0x3008) — fully contained
        // R13 source [0x3008..0x3010) — fully contained
        srf.check_coherence(0x3000, 0, 16, 200);
        assert_eq!(
            srf.regs[12].confidence,
            Confidence::Stale,
            "Wide write covering lo piece must invalidate R12"
        );
        assert_eq!(
            srf.regs[13].confidence,
            Confidence::Stale,
            "Wide write covering hi piece must invalidate R13"
        );
    }

    // Sub-case: 8-byte write to 0x3000 should ONLY invalidate R12, not R13.
    #[test]
    fn test_adversarial_false_sharing_selective_invalidation() {
        let mut srf = ShadowRegisterFile::new();
        srf.on_reload(12, 0xAAAA, 0x3000, 8, 100, 0x4000);
        srf.on_reload(13, 0xBBBB, 0x3008, 8, 101, 0x4004);

        // 8-byte write to 0x3000: covers [0x3000..0x3008) only
        srf.check_coherence(0x3000, 0xCCCC, 8, 200);
        assert_eq!(
            srf.regs[12].confidence,
            Confidence::Stale,
            "8B write to lo must invalidate R12"
        );
        assert_eq!(
            srf.regs[13].confidence,
            Confidence::Observed,
            "8B write to lo must NOT invalidate R13 (false-sharing boundary)"
        );
    }

    // Sub-case: 4-byte write at offset +4 within R12's 8-byte source.
    // Partial overlap within a single register's source.
    #[test]
    fn test_adversarial_partial_intra_register_overlap() {
        let mut srf = ShadowRegisterFile::new();
        // R12 loaded 8B from 0x3000
        srf.on_reload(12, 0xDEADBEEF_CAFEBABE, 0x3000, 8, 100, 0x4000);

        // 4-byte write to 0x3004: covers [0x3004..0x3008), overlaps [0x3000..0x3008)
        srf.check_coherence(0x3004, 0xFFFF_FFFF, 4, 200);
        assert_eq!(
            srf.regs[12].confidence,
            Confidence::Stale,
            "4B write to upper half of 8B source must still invalidate"
        );
    }

    #[test]
    fn test_implicit_value_piece() {
        let steps = vec![
            ExprStep::Lit(0xFF),
            ExprStep::StackValue,
            ExprStep::Piece(1),
            ExprStep::Reg(3),
            ExprStep::Piece(4),
        ];
        let frags = PieceAssembler::parse_pieces(&steps);
        assert_eq!(frags.len(), 2);
        assert!(matches!(frags[0].source, PieceSource::Implicit(_)));
        assert_eq!(frags[0].byte_size, 1);
        assert!(matches!(frags[1].source, PieceSource::Register(3)));
    }
}
