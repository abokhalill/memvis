// SPDX-License-Identifier: MIT
// dwarf parser. extracts globals, subprograms, locals from elf.
// single pass over compilation units. all allocations at startup.

use gimli::{
    AttributeValue, DebuggingInformationEntry, Dwarf, EndianSlice, LittleEndian, Operation, Range,
    Unit, UnitOffset,
};
use object::{Object, ObjectSection, ObjectSegment};
use std::collections::BTreeMap;
use std::fs;

type R<'a> = EndianSlice<'a, LittleEndian>;

#[derive(Debug, Clone)]
pub enum LocationPiece {
    Address(u64),
    FrameBaseOffset(i64),
    Register(u16),
    RegisterOffset(u16, i64),
    ImplicitValue(u64),
    CFA,
    Expr(DwarfExprOp),
}

#[derive(Debug, Clone)]
pub enum DwarfExprOp {
    DerefRegOffset {
        reg: u16,
        offset: i64,
        deref_size: u8,
    },
    RegPlusReg {
        r1: u16,
        off1: i64,
        r2: u16,
        off2: i64,
    },
    StackMachine(Vec<ExprStep>),
}

#[derive(Debug, Clone)]
pub enum ExprStep {
    Lit(u64),
    SignedLit(i64),
    Reg(u16),
    BReg(u16, i64),
    FrameBase(i64),
    Addr(u64),
    CFA,
    Deref(u8),
    Plus,
    Minus,
    Mul,
    Div,
    Mod,
    Neg,
    Abs,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Shra,
    Not,
    Drop,
    Pick(u8),
    Swap,
    Rot,
    PlusConst(u64),
    StackValue,
    Piece(u64),
}

#[derive(Debug, Clone)]
pub struct LocationTable {
    pub entries: Vec<(Range, LocationPiece)>,
}

impl LocationTable {
    pub fn single(piece: LocationPiece) -> Self {
        Self {
            entries: vec![(
                Range {
                    begin: 0,
                    end: u64::MAX,
                },
                piece,
            )],
        }
    }

    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn lookup(&self, pc: u64) -> Option<&LocationPiece> {
        self.entries
            .iter()
            .find(|(r, _)| pc >= r.begin && pc < r.end)
            .map(|(_, p)| p)
    }
}

// x86-64 DWARF register number -> memvis reg_file index.
// DWARF reg 0=rax,1=rdx,2=rcx,3=rbx,4=rsi,5=rdi,6=rbp,7=rsp,8-15=r8-r15,16=rip
// our layout: 0=rax,1=rbx,2=rcx,3=rdx,4=rsi,5=rdi,6=rbp,7=rsp,8-15=r8-r15,16=rip
const DWARF_TO_REGFILE: [Option<usize>; 17] = [
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

fn dwarf_reg_to_index(dwarf_reg: u16) -> Option<usize> {
    DWARF_TO_REGFILE.get(dwarf_reg as usize).copied().flatten()
}

// x86-64: CFA = RSP + 8 (return addr pushed)
fn compute_cfa(regs: &[u64; 18]) -> u64 {
    regs[7].wrapping_add(8)
}

pub fn resolve_location(
    piece: &LocationPiece,
    regs: &[u64; 18],
    frame_base: u64,
    cfa: bool,
) -> Option<u64> {
    match piece {
        LocationPiece::Address(a) => Some(*a),
        LocationPiece::FrameBaseOffset(off) => {
            let base = if cfa { compute_cfa(regs) } else { frame_base };
            Some((base as i64).wrapping_add(*off) as u64)
        }
        LocationPiece::Register(r) => dwarf_reg_to_index(*r).map(|i| regs[i]),
        LocationPiece::RegisterOffset(r, off) => {
            dwarf_reg_to_index(*r).map(|i| (regs[i] as i64).wrapping_add(*off) as u64)
        }
        LocationPiece::ImplicitValue(_) => None,
        LocationPiece::CFA => Some(compute_cfa(regs)),
        LocationPiece::Expr(expr_op) => resolve_expr(expr_op, regs, frame_base, cfa),
    }
}

fn resolve_expr(expr: &DwarfExprOp, regs: &[u64; 18], frame_base: u64, cfa: bool) -> Option<u64> {
    match expr {
        DwarfExprOp::DerefRegOffset { reg, offset, .. } => {
            // no target memory access — return pre-deref address for index lookup
            dwarf_reg_to_index(*reg).map(|i| (regs[i] as i64).wrapping_add(*offset) as u64)
        }
        DwarfExprOp::RegPlusReg { r1, off1, r2, off2 } => {
            let v1 =
                dwarf_reg_to_index(*r1).map(|i| (regs[i] as i64).wrapping_add(*off1) as u64)?;
            let v2 =
                dwarf_reg_to_index(*r2).map(|i| (regs[i] as i64).wrapping_add(*off2) as u64)?;
            Some(v1.wrapping_add(v2))
        }
        DwarfExprOp::StackMachine(steps) => eval_stack_machine(steps, regs, frame_base, cfa),
    }
}

fn eval_stack_machine(
    steps: &[ExprStep],
    regs: &[u64; 18],
    frame_base: u64,
    cfa: bool,
) -> Option<u64> {
    let mut stack: Vec<u64> = Vec::with_capacity(8);
    let mut is_stack_value = false;

    for step in steps {
        match step {
            ExprStep::Lit(v) => stack.push(*v),
            ExprStep::SignedLit(v) => stack.push(*v as u64),
            ExprStep::Reg(r) => {
                let val = dwarf_reg_to_index(*r).map(|i| regs[i])?;
                stack.push(val);
            }
            ExprStep::BReg(r, off) => {
                let val =
                    dwarf_reg_to_index(*r).map(|i| (regs[i] as i64).wrapping_add(*off) as u64)?;
                stack.push(val);
            }
            ExprStep::FrameBase(off) => {
                let base = if cfa { compute_cfa(regs) } else { frame_base };
                stack.push((base as i64).wrapping_add(*off) as u64);
            }
            ExprStep::Addr(a) => stack.push(*a),
            ExprStep::CFA => stack.push(compute_cfa(regs)),
            ExprStep::Deref(_size) => {
                // can't read target memory — leave address on stack (best effort)
                if stack.is_empty() {
                    return None;
                }
            }
            ExprStep::Plus => {
                if stack.len() < 2 {
                    return None;
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a.wrapping_add(b));
            }
            ExprStep::Minus => {
                if stack.len() < 2 {
                    return None;
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a.wrapping_sub(b));
            }
            ExprStep::Mul => {
                if stack.len() < 2 {
                    return None;
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a.wrapping_mul(b));
            }
            ExprStep::Div => {
                if stack.len() < 2 {
                    return None;
                }
                let b = stack.pop().unwrap() as i64;
                let a = stack.pop().unwrap() as i64;
                if b == 0 {
                    return None;
                }
                stack.push((a / b) as u64);
            }
            ExprStep::Mod => {
                if stack.len() < 2 {
                    return None;
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                if b == 0 {
                    return None;
                }
                stack.push(a % b);
            }
            ExprStep::Neg => {
                let v = stack.last_mut()?;
                *v = (0u64).wrapping_sub(*v);
            }
            ExprStep::Abs => {
                let v = stack.last_mut()?;
                let sv = *v as i64;
                *v = sv.unsigned_abs();
            }
            ExprStep::And => {
                if stack.len() < 2 {
                    return None;
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a & b);
            }
            ExprStep::Or => {
                if stack.len() < 2 {
                    return None;
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a | b);
            }
            ExprStep::Xor => {
                if stack.len() < 2 {
                    return None;
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a ^ b);
            }
            ExprStep::Shl => {
                if stack.len() < 2 {
                    return None;
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a.wrapping_shl(b as u32));
            }
            ExprStep::Shr => {
                if stack.len() < 2 {
                    return None;
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap();
                stack.push(a.wrapping_shr(b as u32));
            }
            ExprStep::Shra => {
                if stack.len() < 2 {
                    return None;
                }
                let b = stack.pop().unwrap();
                let a = stack.pop().unwrap() as i64;
                stack.push((a >> (b as u32)) as u64);
            }
            ExprStep::Not => {
                let v = stack.last_mut()?;
                *v = !*v;
            }
            ExprStep::Drop => {
                stack.pop()?;
            }
            ExprStep::Pick(idx) => {
                let len = stack.len();
                if (*idx as usize) >= len {
                    return None;
                }
                stack.push(stack[len - 1 - *idx as usize]);
            }
            ExprStep::Swap => {
                let len = stack.len();
                if len < 2 {
                    return None;
                }
                stack.swap(len - 1, len - 2);
            }
            ExprStep::Rot => {
                let len = stack.len();
                if len < 3 {
                    return None;
                }
                // top three: [a, b, c] (c=TOS) -> [c, a, b]
                let c = stack[len - 1];
                stack[len - 1] = stack[len - 2];
                stack[len - 2] = stack[len - 3];
                stack[len - 3] = c;
            }
            ExprStep::PlusConst(c) => {
                let v = stack.last_mut()?;
                *v = v.wrapping_add(*c);
            }
            ExprStep::StackValue => {
                is_stack_value = true;
            }
            ExprStep::Piece(_) => break,
        }
    }

    // stack_value = result is value, not address — not indexable
    if is_stack_value {
        return None;
    }
    stack.last().copied()
}

#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub name: String,
    pub byte_offset: u64,
    pub byte_size: u64,
    pub type_info: TypeInfo,
}

#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub name: String,
    pub byte_size: u64,
    pub is_pointer: bool,
    pub fields: Vec<FieldInfo>,
}

#[derive(Debug, Clone)]
pub struct GlobalVar {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub type_info: TypeInfo,
    pub location: LocationTable,
}

#[derive(Debug, Clone)]
pub struct LocalVar {
    pub frame_offset: i64,
    pub name: String,
    pub size: u64,
    pub type_info: TypeInfo,
    pub location: LocationTable,
}

#[derive(Debug, Clone)]
pub struct FunctionMeta {
    pub name: String,
    pub low_pc: u64,
    pub high_pc: u64,
    pub frame_base_is_cfa: bool,
    pub locals: Vec<LocalVar>,
}

pub struct DwarfInfo {
    pub globals: Vec<GlobalVar>,
    pub functions: BTreeMap<u64, FunctionMeta>,
    pub elf_base_vaddr: u64, // lowest PT_LOAD vaddr (0 for PIE)
}

fn attr_name<'a>(
    dwarf: &Dwarf<R<'a>>,
    unit: &Unit<R<'a>>,
    entry: &DebuggingInformationEntry<R<'a>>,
) -> Option<String> {
    let val = entry.attr_value(gimli::DW_AT_name).ok().flatten()?;
    let r = dwarf.attr_string(unit, val).ok()?;
    Some(r.to_string_lossy().to_string())
}

pub fn parse_elf(path: &str) -> Result<DwarfInfo, Box<dyn std::error::Error>> {
    let file_data = fs::read(path)?;
    let obj = object::File::parse(&*file_data)?;

    let load_section = |id: gimli::SectionId| -> Result<R<'_>, gimli::Error> {
        let data = obj
            .section_by_name(id.name())
            .and_then(|s| s.data().ok())
            .unwrap_or(&[]);
        Ok(EndianSlice::new(data, LittleEndian))
    };

    // lowest PT_LOAD vaddr = ELF base (typically 0 for PIE)
    let elf_base_vaddr = obj
        .segments()
        .filter_map(|s| {
            let addr = s.address();
            if addr < u64::MAX {
                Some(addr)
            } else {
                None
            }
        })
        .min()
        .unwrap_or(0);

    let dw = Dwarf::load(&load_section)?;

    let mut globals = Vec::new();
    let mut functions = BTreeMap::new();

    let mut iter = dw.units();
    while let Some(header) = iter.next()? {
        let unit = dw.unit(header)?;
        let mut entries = unit.entries();

        while let Some((_, entry)) = entries.next_dfs()? {
            let tag = entry.tag();
            if tag == gimli::DW_TAG_variable {
                if let Some(g) = try_extract_global(&dw, &unit, entry) {
                    globals.push(g);
                }
            } else if tag == gimli::DW_TAG_subprogram {
                if let Some(f) = try_extract_function(&dw, &unit, entry) {
                    functions.insert(f.low_pc, f);
                }
            } else if tag == gimli::DW_TAG_inlined_subroutine {
                if let Some(f) = try_extract_inlined(&dw, &unit, entry) {
                    functions.insert(f.low_pc, f);
                }
            }
        }

        // second pass: attach locals to their parent subprograms and inlines
        extract_locals(&dw, &unit, &mut functions)?;
    }

    eprintln!(
        "dwarf: {} globals, {} functions extracted",
        globals.len(),
        functions.len()
    );

    Ok(DwarfInfo {
        globals,
        functions,
        elf_base_vaddr,
    })
}

fn op_to_steps(op: &Operation<R<'_>>, steps: &mut Vec<ExprStep>) -> bool {
    match op {
        Operation::Address { address } => {
            steps.push(ExprStep::Addr(*address));
            true
        }
        Operation::UnsignedConstant { value } => {
            steps.push(ExprStep::Lit(*value));
            true
        }
        Operation::SignedConstant { value } => {
            steps.push(ExprStep::SignedLit(*value));
            true
        }
        Operation::Register { register } => {
            steps.push(ExprStep::Reg(register.0));
            true
        }
        Operation::RegisterOffset {
            register, offset, ..
        } => {
            steps.push(ExprStep::BReg(register.0, *offset));
            true
        }
        Operation::FrameOffset { offset } => {
            steps.push(ExprStep::FrameBase(*offset));
            true
        }
        Operation::CallFrameCFA => {
            steps.push(ExprStep::CFA);
            true
        }
        Operation::Deref { size, space, .. } => {
            if *space {
                return false;
            } // xderef needs address space arg — unsupported
            steps.push(ExprStep::Deref(*size));
            true
        }
        Operation::Plus => {
            steps.push(ExprStep::Plus);
            true
        }
        Operation::Minus => {
            steps.push(ExprStep::Minus);
            true
        }
        Operation::Mul => {
            steps.push(ExprStep::Mul);
            true
        }
        Operation::Div => {
            steps.push(ExprStep::Div);
            true
        }
        Operation::Mod => {
            steps.push(ExprStep::Mod);
            true
        }
        Operation::Neg => {
            steps.push(ExprStep::Neg);
            true
        }
        Operation::Abs => {
            steps.push(ExprStep::Abs);
            true
        }
        Operation::And => {
            steps.push(ExprStep::And);
            true
        }
        Operation::Or => {
            steps.push(ExprStep::Or);
            true
        }
        Operation::Xor => {
            steps.push(ExprStep::Xor);
            true
        }
        Operation::Shl => {
            steps.push(ExprStep::Shl);
            true
        }
        Operation::Shr => {
            steps.push(ExprStep::Shr);
            true
        }
        Operation::Shra => {
            steps.push(ExprStep::Shra);
            true
        }
        Operation::Not => {
            steps.push(ExprStep::Not);
            true
        }
        Operation::PlusConstant { value } => {
            steps.push(ExprStep::PlusConst(*value));
            true
        }
        Operation::StackValue => {
            steps.push(ExprStep::StackValue);
            true
        }
        Operation::Piece { size_in_bits, .. } => {
            steps.push(ExprStep::Piece(size_in_bits / 8));
            true
        }
        Operation::ImplicitValue { data } => {
            let bytes: &[u8] = data.slice();
            let val = match bytes.len() {
                1 => bytes[0] as u64,
                2 => u16::from_le_bytes([bytes[0], bytes[1]]) as u64,
                4 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
                8 => u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]),
                _ => return false,
            };
            steps.push(ExprStep::Lit(val));
            steps.push(ExprStep::StackValue);
            true
        }
        Operation::Nop => true,
        Operation::Drop => {
            steps.push(ExprStep::Drop);
            true
        }
        Operation::Pick { index } => {
            steps.push(ExprStep::Pick(*index));
            true
        }
        Operation::Swap => {
            steps.push(ExprStep::Swap);
            true
        }
        Operation::Rot => {
            steps.push(ExprStep::Rot);
            true
        }
        _ => false,
    }
}

fn decode_expression(unit: &Unit<R<'_>>, expr: &gimli::Expression<R<'_>>) -> Option<LocationPiece> {
    let mut ops = expr.operations(unit.encoding());
    let mut steps: Vec<ExprStep> = Vec::new();

    loop {
        match ops.next() {
            Ok(Some(op)) => {
                if !op_to_steps(&op, &mut steps) {
                    return None;
                }
            }
            Ok(None) => break,
            Err(_) => return None,
        }
    }

    if steps.is_empty() {
        return None;
    }

    match steps.as_slice() {
        [ExprStep::Addr(a)] => Some(LocationPiece::Address(*a)),
        [ExprStep::FrameBase(off)] => Some(LocationPiece::FrameBaseOffset(*off)),
        [ExprStep::Reg(r)] => Some(LocationPiece::Register(*r)),
        [ExprStep::BReg(r, off)] => Some(LocationPiece::RegisterOffset(*r, *off)),
        [ExprStep::CFA] => Some(LocationPiece::CFA),
        [ExprStep::Lit(v), ExprStep::StackValue] => Some(LocationPiece::ImplicitValue(*v)),
        [ExprStep::SignedLit(v), ExprStep::StackValue] => {
            Some(LocationPiece::ImplicitValue(*v as u64))
        }
        [ExprStep::BReg(r, off), ExprStep::Deref(sz)] => {
            Some(LocationPiece::Expr(DwarfExprOp::DerefRegOffset {
                reg: *r,
                offset: *off,
                deref_size: *sz,
            }))
        }
        [ExprStep::BReg(r1, o1), ExprStep::BReg(r2, o2), ExprStep::Plus, ExprStep::StackValue] => {
            Some(LocationPiece::Expr(DwarfExprOp::RegPlusReg {
                r1: *r1,
                off1: *o1,
                r2: *r2,
                off2: *o2,
            }))
        }
        [ExprStep::Addr(a), ExprStep::StackValue] => Some(LocationPiece::ImplicitValue(*a)),
        _ => Some(LocationPiece::Expr(DwarfExprOp::StackMachine(steps))),
    }
}

fn decode_location<'a>(
    dwarf: &Dwarf<R<'a>>,
    unit: &Unit<R<'a>>,
    attr: &AttributeValue<R<'a>>,
) -> LocationTable {
    match attr {
        AttributeValue::Exprloc(expr) => match decode_expression(unit, expr) {
            Some(piece) => LocationTable::single(piece),
            None => LocationTable::empty(),
        },
        _ => {
            if let Ok(Some(offset)) = dwarf.attr_locations_offset(unit, *attr) {
                if let Ok(mut iter) = dwarf.locations(unit, offset) {
                    let mut entries = Vec::new();
                    while let Ok(Some(entry)) = iter.next() {
                        if let Some(piece) = decode_expression(unit, &entry.data) {
                            entries.push((entry.range, piece));
                        }
                    }
                    if !entries.is_empty() {
                        return LocationTable { entries };
                    }
                }
            }
            LocationTable::empty()
        }
    }
}

fn try_extract_global<'a>(
    dwarf: &Dwarf<R<'a>>,
    unit: &Unit<R<'a>>,
    entry: &DebuggingInformationEntry<R<'a>>,
) -> Option<GlobalVar> {
    let name = attr_name(dwarf, unit, entry)?;

    let loc_attr = entry.attr_value(gimli::DW_AT_location).ok().flatten()?;
    let location = decode_location(dwarf, unit, &loc_attr);
    if location.is_empty() {
        return None;
    }

    let addr = match &location.entries[0].1 {
        LocationPiece::Address(a) => *a,
        _ => return None,
    };

    let type_info = resolve_type(dwarf, unit, entry).unwrap_or(TypeInfo {
        name: "<unknown>".into(),
        byte_size: 0,
        is_pointer: false,
        fields: Vec::new(),
    });

    let size = type_info.byte_size;
    if size == 0 {
        return None;
    }

    Some(GlobalVar {
        name,
        addr,
        size,
        type_info,
        location,
    })
}

fn try_extract_function<'a>(
    dwarf: &Dwarf<R<'a>>,
    unit: &Unit<R<'a>>,
    entry: &DebuggingInformationEntry<R<'a>>,
) -> Option<FunctionMeta> {
    let name = attr_name(dwarf, unit, entry)?;

    let low_pc = match entry.attr_value(gimli::DW_AT_low_pc).ok().flatten()? {
        AttributeValue::Addr(a) => a,
        _ => return None,
    };

    let high_pc = match entry.attr_value(gimli::DW_AT_high_pc).ok().flatten()? {
        AttributeValue::Udata(len) => low_pc + len,
        AttributeValue::Addr(a) => a,
        _ => return None,
    };

    let frame_base_is_cfa = entry
        .attr_value(gimli::DW_AT_frame_base)
        .ok()
        .flatten()
        .map(|attr| match attr {
            AttributeValue::Exprloc(expr) => {
                let mut ops = expr.operations(unit.encoding());
                matches!(ops.next(), Ok(Some(Operation::CallFrameCFA)))
            }
            _ => false,
        })
        .unwrap_or(false);

    Some(FunctionMeta {
        name,
        low_pc,
        high_pc,
        frame_base_is_cfa,
        locals: Vec::new(),
    })
}

fn try_extract_inlined<'a>(
    dwarf: &Dwarf<R<'a>>,
    unit: &Unit<R<'a>>,
    entry: &DebuggingInformationEntry<R<'a>>,
) -> Option<FunctionMeta> {
    let origin_offset = match entry
        .attr_value(gimli::DW_AT_abstract_origin)
        .ok()
        .flatten()?
    {
        AttributeValue::UnitRef(off) => off,
        _ => return None,
    };
    let origin_entry = unit.entry(origin_offset).ok()?;
    let name = attr_name(dwarf, unit, &origin_entry)?;

    let low_pc = entry
        .attr_value(gimli::DW_AT_low_pc)
        .ok()
        .flatten()
        .and_then(|v| match v {
            AttributeValue::Addr(a) => Some(a),
            _ => None,
        })
        .or_else(|| {
            entry
                .attr_value(gimli::DW_AT_entry_pc)
                .ok()
                .flatten()
                .and_then(|v| match v {
                    AttributeValue::Addr(a) => Some(a),
                    _ => None,
                })
        })?;

    let high_pc = entry
        .attr_value(gimli::DW_AT_high_pc)
        .ok()
        .flatten()
        .and_then(|v| match v {
            AttributeValue::Udata(len) => Some(low_pc + len),
            AttributeValue::Addr(a) => Some(a),
            _ => None,
        })
        .unwrap_or(low_pc + 1);

    let frame_base_is_cfa = origin_entry
        .attr_value(gimli::DW_AT_frame_base)
        .ok()
        .flatten()
        .map(|attr| match attr {
            AttributeValue::Exprloc(expr) => {
                let mut ops = expr.operations(unit.encoding());
                matches!(ops.next(), Ok(Some(Operation::CallFrameCFA)))
            }
            _ => false,
        })
        .unwrap_or(false);

    Some(FunctionMeta {
        name: format!("[inlined] {}", name),
        low_pc,
        high_pc,
        frame_base_is_cfa,
        locals: Vec::new(),
    })
}

fn extract_locals<'a>(
    dwarf: &Dwarf<R<'a>>,
    unit: &Unit<R<'a>>,
    functions: &mut BTreeMap<u64, FunctionMeta>,
) -> Result<(), gimli::Error> {
    let mut entries = unit.entries();
    let mut current_fn_pc: Option<u64> = None;
    let mut depth: isize = 0;
    let mut fn_depth: isize = 0;

    while let Some((delta_depth, entry)) = entries.next_dfs()? {
        depth += delta_depth;
        if current_fn_pc.is_some() && depth <= fn_depth {
            current_fn_pc = None;
        }

        let tag = entry.tag();
        if tag == gimli::DW_TAG_subprogram || tag == gimli::DW_TAG_inlined_subroutine {
            let pc = entry
                .attr_value(gimli::DW_AT_low_pc)?
                .and_then(|v| match v {
                    AttributeValue::Addr(a) => Some(a),
                    _ => None,
                })
                .or_else(|| {
                    entry
                        .attr_value(gimli::DW_AT_entry_pc)
                        .ok()
                        .flatten()
                        .and_then(|v| match v {
                            AttributeValue::Addr(a) => Some(a),
                            _ => None,
                        })
                });
            if pc.is_some() {
                current_fn_pc = pc;
                fn_depth = depth;
            }
        } else if tag == gimli::DW_TAG_variable || tag == gimli::DW_TAG_formal_parameter {
            if let Some(fn_pc) = current_fn_pc {
                if let Some(local) = try_extract_local(dwarf, unit, entry) {
                    if let Some(func) = functions.get_mut(&fn_pc) {
                        func.locals.push(local);
                    }
                }
            }
        }
    }

    Ok(())
}

fn try_extract_local<'a>(
    dwarf: &Dwarf<R<'a>>,
    unit: &Unit<R<'a>>,
    entry: &DebuggingInformationEntry<R<'a>>,
) -> Option<LocalVar> {
    let name = attr_name(dwarf, unit, entry)?;

    let loc_attr = entry.attr_value(gimli::DW_AT_location).ok().flatten()?;
    let location = decode_location(dwarf, unit, &loc_attr);
    if location.is_empty() {
        return None;
    }

    let frame_offset = match &location.entries[0].1 {
        LocationPiece::FrameBaseOffset(off) => *off,
        LocationPiece::RegisterOffset(_, off) => *off,
        _ => 0,
    };

    let type_info = resolve_type(dwarf, unit, entry).unwrap_or(TypeInfo {
        name: "<unknown>".into(),
        byte_size: 0,
        is_pointer: false,
        fields: Vec::new(),
    });

    Some(LocalVar {
        frame_offset,
        name,
        size: type_info.byte_size,
        type_info,
        location,
    })
}

fn extract_struct_fields<'a>(
    dwarf: &Dwarf<R<'a>>,
    unit: &Unit<R<'a>>,
    struct_offset: UnitOffset,
    parent_depth: u32,
) -> Vec<FieldInfo> {
    // cap nested struct field extraction to avoid stack overflow on
    // deeply nested types (e.g. kernel sched.c: rq -> cfs_rq -> sched_entity)
    if parent_depth >= 2 {
        return Vec::new();
    }

    let mut fields = Vec::new();

    let mut tree = match unit.entries_tree(Some(struct_offset)) {
        Ok(t) => t,
        Err(_) => return fields,
    };
    let root = match tree.root() {
        Ok(r) => r,
        Err(_) => return fields,
    };
    let mut children = root.children();

    while let Ok(Some(child)) = children.next() {
        let entry = child.entry();
        if entry.tag() != gimli::DW_TAG_member {
            continue;
        }

        let name = attr_name(dwarf, unit, entry).unwrap_or_else(|| "<anon>".into());

        let byte_offset = entry
            .attr_value(gimli::DW_AT_data_member_location)
            .ok()
            .flatten()
            .and_then(|v| v.udata_value())
            .unwrap_or(0);

        // propagate depth through resolve_type_at, not resolve_type
        // (resolve_type resets depth to 0, causing unbounded recursion)
        let type_ref = entry
            .attr_value(gimli::DW_AT_type)
            .ok()
            .flatten()
            .and_then(|v| match v {
                AttributeValue::UnitRef(off) => Some(off),
                _ => None,
            });
        let type_info = type_ref
            .and_then(|off| resolve_type_at(dwarf, unit, off, parent_depth + 1))
            .unwrap_or(TypeInfo {
                name: "<unknown>".into(),
                byte_size: 0,
                is_pointer: false,
                fields: Vec::new(),
            });

        let byte_size = type_info.byte_size;

        fields.push(FieldInfo {
            name,
            byte_offset,
            byte_size,
            type_info,
        });
    }

    fields
}

// resolve DW_AT_type chain. peels typedef/const/volatile up to 8 levels.
fn resolve_type<'a>(
    dwarf: &Dwarf<R<'a>>,
    unit: &Unit<R<'a>>,
    entry: &DebuggingInformationEntry<R<'a>>,
) -> Option<TypeInfo> {
    let type_ref = match entry.attr_value(gimli::DW_AT_type).ok().flatten()? {
        AttributeValue::UnitRef(offset) => offset,
        _ => return None,
    };
    resolve_type_at(dwarf, unit, type_ref, 0)
}

fn resolve_type_at<'a>(
    dwarf: &Dwarf<R<'a>>,
    unit: &Unit<R<'a>>,
    offset: UnitOffset,
    depth: u32,
) -> Option<TypeInfo> {
    if depth > 8 {
        return None;
    }

    let entry = unit.entry(offset).ok()?;
    let tag = entry.tag();

    if tag == gimli::DW_TAG_base_type {
        let name = attr_name(dwarf, unit, &entry).unwrap_or_else(|| "<anon>".into());
        let byte_size = entry
            .attr_value(gimli::DW_AT_byte_size)
            .ok()
            .flatten()
            .and_then(|v| v.udata_value())
            .unwrap_or(0);

        Some(TypeInfo {
            name,
            byte_size,
            is_pointer: false,
            fields: Vec::new(),
        })
    } else if tag == gimli::DW_TAG_structure_type || tag == gimli::DW_TAG_union_type {
        let name = attr_name(dwarf, unit, &entry).unwrap_or_else(|| "<anon>".into());
        let byte_size = entry
            .attr_value(gimli::DW_AT_byte_size)
            .ok()
            .flatten()
            .and_then(|v| v.udata_value())
            .unwrap_or(0);

        let fields = extract_struct_fields(dwarf, unit, offset, depth);

        Some(TypeInfo {
            name,
            byte_size,
            is_pointer: false,
            fields,
        })
    } else if tag == gimli::DW_TAG_pointer_type {
        let byte_size = entry
            .attr_value(gimli::DW_AT_byte_size)
            .ok()
            .flatten()
            .and_then(|v| v.udata_value())
            .unwrap_or(8);

        let pointee_name = entry
            .attr_value(gimli::DW_AT_type)
            .ok()
            .flatten()
            .and_then(|v| match v {
                AttributeValue::UnitRef(off) => resolve_type_at(dwarf, unit, off, depth + 1),
                _ => None,
            })
            .map(|t| format!("*{}", t.name))
            .unwrap_or_else(|| "*void".into());

        Some(TypeInfo {
            name: pointee_name,
            byte_size,
            is_pointer: true,
            fields: Vec::new(),
        })
    } else if tag == gimli::DW_TAG_typedef
        || tag == gimli::DW_TAG_const_type
        || tag == gimli::DW_TAG_volatile_type
        || tag == gimli::DW_TAG_restrict_type
    {
        let typedef_name = attr_name(dwarf, unit, &entry);
        let inner_ref = match entry.attr_value(gimli::DW_AT_type).ok().flatten()? {
            AttributeValue::UnitRef(off) => off,
            _ => return None,
        };
        let mut resolved = resolve_type_at(dwarf, unit, inner_ref, depth + 1)?;
        // propagate typedef name to anonymous inner type
        if let Some(td_name) = typedef_name {
            if resolved.name == "<anon>" || resolved.name.is_empty() {
                resolved.name = td_name;
            }
        }
        Some(resolved)
    } else if tag == gimli::DW_TAG_array_type {
        let byte_size = entry
            .attr_value(gimli::DW_AT_byte_size)
            .ok()
            .flatten()
            .and_then(|v| v.udata_value())
            .unwrap_or(0);

        Some(TypeInfo {
            name: "[]".into(),
            byte_size,
            is_pointer: false,
            fields: Vec::new(),
        })
    } else {
        None
    }
}
