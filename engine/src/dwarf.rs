// SPDX-License-Identifier: MIT
// dwarf parser. extracts globals, subprograms, locals from elf.
// single pass over compilation units. all allocations at startup.

use gimli::{
    AttributeValue, DebuggingInformationEntry, Dwarf, EndianSlice, LittleEndian,
    Operation, Range, Unit, UnitOffset,
};
use object::{Object, ObjectSection, ObjectSegment};
use std::collections::BTreeMap;
use std::fs;

type R<'a> = EndianSlice<'a, LittleEndian>;

#[derive(Debug, Clone)]
pub enum LocationPiece {
    Address(u64),          // DW_OP_addr
    FrameBaseOffset(i64),  // DW_OP_fbreg
    Register(u16),         // DW_OP_reg*
    RegisterOffset(u16, i64), // DW_OP_breg*
    ImplicitValue(u64),    // const + DW_OP_stack_value
}

#[derive(Debug, Clone)]
pub struct LocationTable {
    pub entries: Vec<(Range, LocationPiece)>,
}

impl LocationTable {
    pub fn single(piece: LocationPiece) -> Self {
        Self {
            entries: vec![(Range { begin: 0, end: u64::MAX }, piece)],
        }
    }

    pub fn empty() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn lookup(&self, pc: u64) -> Option<&LocationPiece> {
        self.entries.iter()
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

/// resolve a location piece to a concrete address given register state.
pub fn resolve_location(
    piece: &LocationPiece,
    regs: &[u64; 18],
    frame_base: u64,
    cfa: bool,
) -> Option<u64> {
    match piece {
        LocationPiece::Address(a) => Some(*a),
        LocationPiece::FrameBaseOffset(off) => {
            let base = if cfa { regs[7].wrapping_add(8) } else { frame_base };
            Some((base as i64).wrapping_add(*off) as u64)
        }
        LocationPiece::Register(r) => {
            dwarf_reg_to_index(*r).map(|i| regs[i])
        }
        LocationPiece::RegisterOffset(r, off) => {
            dwarf_reg_to_index(*r).map(|i| (regs[i] as i64).wrapping_add(*off) as u64)
        }
        LocationPiece::ImplicitValue(_) => None, // not addressable
    }
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
    let elf_base_vaddr = obj.segments()
        .filter_map(|s| {
            let addr = s.address();
            if addr < u64::MAX { Some(addr) } else { None }
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
            }
        }

        // second pass: attach locals to their parent subprograms
        extract_locals(&dw, &unit, &mut functions)?;
    }

    eprintln!(
        "dwarf: {} globals, {} functions extracted",
        globals.len(),
        functions.len()
    );

    Ok(DwarfInfo { globals, functions, elf_base_vaddr })
}

// single expression --> piece. returns None for unsupported ops.
fn decode_expression(unit: &Unit<R<'_>>, expr: &gimli::Expression<R<'_>>) -> Option<LocationPiece> {
    let mut ops = expr.operations(unit.encoding());
    let first = match ops.next() {
        Ok(Some(op)) => op,
        _ => return None,
    };

    match first {
        Operation::Address { address } => Some(LocationPiece::Address(address)),
        Operation::FrameOffset { offset } => Some(LocationPiece::FrameBaseOffset(offset)),
        Operation::Register { register } => Some(LocationPiece::Register(register.0)),
        Operation::RegisterOffset { register, offset, .. } => {
            Some(LocationPiece::RegisterOffset(register.0, offset))
        }
        Operation::UnsignedConstant { value } => {
            match ops.next() {
                Ok(Some(Operation::StackValue)) => Some(LocationPiece::ImplicitValue(value)),
                _ => None,
            }
        }
        Operation::SignedConstant { value } => {
            match ops.next() {
                Ok(Some(Operation::StackValue)) => Some(LocationPiece::ImplicitValue(value as u64)),
                _ => None,
            }
        }
        _ => None,
    }
}

// exprloc --> single-entry table, loclist --> multi-entry table
fn decode_location<'a>(
    dwarf: &Dwarf<R<'a>>,
    unit: &Unit<R<'a>>,
    attr: &AttributeValue<R<'a>>,
) -> LocationTable {
    match attr {
        AttributeValue::Exprloc(expr) => {
            match decode_expression(unit, expr) {
                Some(piece) => LocationTable::single(piece),
                None => LocationTable::empty(),
            }
        }
        _ => {
            if let Ok(Some(offset)) = dwarf.attr_locations_offset(unit, attr.clone()) {
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
    if location.is_empty() { return None; }

    let addr = match &location.entries[0].1 {
        LocationPiece::Address(a) => *a,
        _ => 0,
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

    Some(GlobalVar { name, addr, size, type_info, location })
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

// second pass: attach locals to parent subprogram
fn extract_locals<'a>(
    dwarf: &Dwarf<R<'a>>,
    unit: &Unit<R<'a>>,
    functions: &mut BTreeMap<u64, FunctionMeta>,
) -> Result<(), gimli::Error> {
    let mut entries = unit.entries();
    let mut current_fn_pc: Option<u64> = None;

    while let Some((delta_depth, entry)) = entries.next_dfs()? {
        let tag = entry.tag();
        if tag == gimli::DW_TAG_subprogram {
            current_fn_pc = entry
                .attr_value(gimli::DW_AT_low_pc)?
                .and_then(|v| match v {
                    AttributeValue::Addr(a) => Some(a),
                    _ => None,
                });
        } else if tag == gimli::DW_TAG_variable || tag == gimli::DW_TAG_formal_parameter {
            if delta_depth <= 0 && tag == gimli::DW_TAG_variable {
                if delta_depth < 0 {
                    current_fn_pc = None;
                }
            }

            if let Some(fn_pc) = current_fn_pc {
                if let Some(local) = try_extract_local(dwarf, unit, entry) {
                    if let Some(func) = functions.get_mut(&fn_pc) {
                        func.locals.push(local);
                    }
                }
            }
        } else if delta_depth < 0 {
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
    if location.is_empty() { return None; }

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
    _parent_depth: u32,
) -> Vec<FieldInfo> {
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

        let name = attr_name(dwarf, unit, entry)
            .unwrap_or_else(|| "<anon>".into());

        let byte_offset = entry
            .attr_value(gimli::DW_AT_data_member_location)
            .ok()
            .flatten()
            .and_then(|v| v.udata_value())
            .unwrap_or(0);

        let type_info = resolve_type(dwarf, unit, entry).unwrap_or(TypeInfo {
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

        Some(TypeInfo { name, byte_size, is_pointer: false, fields: Vec::new() })
    } else if tag == gimli::DW_TAG_structure_type
        || tag == gimli::DW_TAG_union_type
    {
        let name = attr_name(dwarf, unit, &entry).unwrap_or_else(|| "<anon>".into());
        let byte_size = entry
            .attr_value(gimli::DW_AT_byte_size)
            .ok()
            .flatten()
            .and_then(|v| v.udata_value())
            .unwrap_or(0);

        let fields = extract_struct_fields(dwarf, unit, offset, depth);

        Some(TypeInfo { name, byte_size, is_pointer: false, fields })
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

        Some(TypeInfo { name: pointee_name, byte_size, is_pointer: true, fields: Vec::new() })
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

        Some(TypeInfo { name: "[]".into(), byte_size, is_pointer: false, fields: Vec::new() })
    } else {
        None
    }
}
