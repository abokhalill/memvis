// SPDX-License-Identifier: MIT
// dwarf parser. extracts globals, subprograms, locals from elf.
// single pass over compilation units. all allocations at startup.

use gimli::{
    AttributeValue, DebuggingInformationEntry, Dwarf, EndianSlice, LittleEndian,
    Operation, Unit, UnitOffset,
};
use object::{Object, ObjectSection};
use std::collections::BTreeMap;
use std::fs;

type R<'a> = EndianSlice<'a, LittleEndian>;

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
}

#[derive(Debug, Clone)]
pub struct LocalVar {
    pub frame_offset: i64,
    pub name: String,
    pub size: u64,
    pub type_info: TypeInfo,
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

    Ok(DwarfInfo { globals, functions })
}

fn try_extract_global<'a>(
    dwarf: &Dwarf<R<'a>>,
    unit: &Unit<R<'a>>,
    entry: &DebuggingInformationEntry<R<'a>>,
) -> Option<GlobalVar> {
    let name = attr_name(dwarf, unit, entry)?;

    let loc_attr = entry.attr_value(gimli::DW_AT_location).ok().flatten()?;
    let addr = eval_addr_location(unit, &loc_attr)?;

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

    Some(GlobalVar { name, addr, size, type_info })
}

fn eval_addr_location(unit: &Unit<R<'_>>, attr: &AttributeValue<R<'_>>) -> Option<u64> {
    match attr {
        AttributeValue::Exprloc(expr) => {
            let mut ops = expr.operations(unit.encoding());
            match ops.next() {
                Ok(Some(Operation::Address { address })) => Some(address),
                _ => None,
            }
        }
        _ => None,
    }
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
    let frame_offset = eval_fbreg_offset(unit, &loc_attr)?;

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
    })
}

fn eval_fbreg_offset(unit: &Unit<R<'_>>, attr: &AttributeValue<R<'_>>) -> Option<i64> {
    match attr {
        AttributeValue::Exprloc(expr) => {
            let mut ops = expr.operations(unit.encoding());
            match ops.next() {
                Ok(Some(Operation::FrameOffset { offset })) => Some(offset),
                _ => None,
            }
        }
        _ => None,
    }
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
