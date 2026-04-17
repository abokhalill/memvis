// SPDX-License-Identifier: Apache-2.0

// This binary reads DWARF, maps struct fields to cacheline boundaries, and warns on cross group sharing.

use memvis::dwarf::{parse_elf, FieldInfo, TypeInfo};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::process;

const DEFAULT_CACHELINE: u64 = 64;

// annotations: field_name = writer_group, one per line, '#' comments.
#[derive(Debug, Clone)]
struct Annotations {
    field_to_group: HashMap<String, String>,
}

impl Annotations {
    fn empty() -> Self {
        Self {
            field_to_group: HashMap::new(),
        }
    }

    fn from_file(path: &str) -> Result<Self, String> {
        let contents = fs::read_to_string(path).map_err(|e| format!("read {}: {}", path, e))?;
        let mut field_to_group = HashMap::new();
        for (i, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let parts: Vec<&str> = line.splitn(2, '=').collect();
            if parts.len() != 2 {
                return Err(format!("line {}: expected 'field = group', got '{}'", i + 1, line));
            }
            field_to_group.insert(parts[0].trim().to_string(), parts[1].trim().to_string());
        }
        Ok(Self { field_to_group })
    }

    // lookup tries exact match, then tries the leaf name (last segment after '.')
    // so "bstate.timeout" matches annotation "timeout" if no dotted key exists.
    fn group_for(&self, field: &str) -> Option<&str> {
        self.field_to_group.get(field).map(|s| s.as_str())
            .or_else(|| {
                let leaf = field.rsplit('.').next().unwrap_or(field);
                self.field_to_group.get(leaf).map(|s| s.as_str())
            })
    }

    fn has_annotations(&self) -> bool {
        !self.field_to_group.is_empty()
    }
}

#[derive(Debug, Clone)]
struct FieldLayout {
    name: String,       // dotted path: "bstate.target"
    offset: u64,        // absolute from struct base
    size: u64,
    type_name: String,
    cl_start: u64,
    cl_end: u64,
    // structural intent signals from DWARF
    is_pointer: bool,
    is_volatile: bool,  // DW_TAG_volatile_type in type chain
    is_atomic: bool,    // DW_TAG_atomic_type in type chain (C11 _Atomic)
    has_alignment: bool, // DW_AT_alignment on member — developer intended isolation
}

impl FieldLayout {
    fn cachelines(&self) -> impl Iterator<Item = u64> {
        self.cl_start..=self.cl_end
    }

    // true if DWARF proves this field is a concurrent write target
    fn is_write_hot(&self) -> bool {
        self.is_volatile || self.is_atomic
    }
}

// recursively flatten sub-structs into leaf fields with absolute offsets.
// unions: all variants emitted at the same offset (they physically overlap).
// depth-capped at 8 to match DWARF parser.
fn flatten_fields(
    fields: &[FieldInfo],
    base_offset: u64,
    prefix: &str,
    cl_size: u64,
    out: &mut Vec<FieldLayout>,
    depth: u32,
) {
    if depth > 8 { return; }
    for f in fields {
        let abs_offset = base_offset + f.byte_offset;
        let path = if prefix.is_empty() {
            f.name.clone()
        } else {
            format!("{}.{}", prefix, f.name)
        };

        if f.type_info.fields.is_empty() || f.type_info.is_pointer {
            let cl_start = abs_offset / cl_size;
            let cl_end = (abs_offset + f.byte_size.max(1) - 1) / cl_size;
            out.push(FieldLayout {
                name: path,
                offset: abs_offset,
                size: f.byte_size,
                type_name: f.type_info.name.clone(),
                cl_start,
                cl_end,
                is_pointer: f.type_info.is_pointer,
                is_volatile: f.type_info.is_volatile,
                is_atomic: f.type_info.is_atomic,
                has_alignment: f.alignment > 0 && f.alignment >= cl_size,
            });
        } else {
            flatten_fields(&f.type_info.fields, abs_offset, &path, cl_size, out, depth + 1);
        }
    }
}

#[derive(Debug)]
enum Severity { Warning, Info }

#[derive(Debug)]
struct Diagnostic {
    severity: Severity,
    cacheline: u64,
    message: String,
    fields: Vec<String>,
}

fn analyze_struct(
    type_info: &TypeInfo,
    cl_size: u64,
    annotations: &Annotations,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    let mut layouts = Vec::new();
    flatten_fields(&type_info.fields, 0, "", cl_size, &mut layouts, 0);
    layouts.sort_by_key(|f| f.offset);

    let mut cl_fields: BTreeMap<u64, Vec<&FieldLayout>> = BTreeMap::new();
    for layout in &layouts {
        for cl in layout.cachelines() {
            cl_fields.entry(cl).or_default().push(layout);
        }
    }

    for (&cl, fields) in &cl_fields {
        if fields.len() < 2 { continue; }

        if annotations.has_annotations() {
            let mut groups_on_cl: HashMap<&str, Vec<&str>> = HashMap::new();
            for f in fields {
                if let Some(group) = annotations.group_for(&f.name) {
                    groups_on_cl.entry(group).or_default().push(&f.name);
                }
            }
            if groups_on_cl.len() > 1 {
                let mut msg = format!(
                    "cacheline {} (bytes {:#x}-{:#x}): {} writer groups collide",
                    cl, cl * cl_size, (cl + 1) * cl_size - 1, groups_on_cl.len(),
                );
                for (group, gfields) in &groups_on_cl {
                    msg.push_str(&format!("\n    group '{}': {}", group, gfields.join(", ")));
                }
                diagnostics.push(Diagnostic {
                    severity: Severity::Warning,
                    cacheline: cl,
                    message: msg,
                    fields: fields.iter().map(|f| f.name.clone()).collect(),
                });
            }
        } else {
            // structural intent analysis — three tiers, no keyword guessing.
            //
            // tier 1: volatile/atomic from DWARF qualifiers (ground truth)
            let hot: Vec<&str> = fields.iter()
                .filter(|f| f.is_write_hot())
                .map(|f| f.name.as_str()).collect();
            let cold: Vec<&str> = fields.iter()
                .filter(|f| !f.is_write_hot())
                .map(|f| f.name.as_str()).collect();
            if !hot.is_empty() && !cold.is_empty() {
                diagnostics.push(Diagnostic {
                    severity: Severity::Warning,
                    cacheline: cl,
                    message: format!(
                        "CL{} ({:#x}-{:#x}): volatile/atomic [{}] shares line with [{}]",
                        cl, cl * cl_size, (cl + 1) * cl_size - 1,
                        hot.join(", "), cold.join(", "),
                    ),
                    fields: fields.iter().map(|f| f.name.clone()).collect(),
                });
                continue;
            }

            // tier 2: alignment-intent violation
            // if any field has cacheline-aligned DW_AT_alignment, everything
            // else on that line is a bug — the developer intended isolation.
            let aligned: Vec<&str> = fields.iter()
                .filter(|f| f.has_alignment)
                .map(|f| f.name.as_str()).collect();
            let unaligned: Vec<&str> = fields.iter()
                .filter(|f| !f.has_alignment)
                .map(|f| f.name.as_str()).collect();
            if !aligned.is_empty() && !unaligned.is_empty() {
                diagnostics.push(Diagnostic {
                    severity: Severity::Warning,
                    cacheline: cl,
                    message: format!(
                        "CL{} ({:#x}-{:#x}): aligned field(s) [{}] share line with [{}] — isolation intent violated",
                        cl, cl * cl_size, (cl + 1) * cl_size - 1,
                        aligned.join(", "), unaligned.join(", "),
                    ),
                    fields: fields.iter().map(|f| f.name.clone()).collect(),
                });
                continue;
            }

            // tier 3: scalar vs pointer adjacency + keyword backup
            // pointers are read-dereferenced; adjacent scalars are likely
            // mutated counters/state. also retain the lock-keyword catch.
            let lock_kw = ["lock", "rwlock", "mutex", "atomic", "spinlock"];
            let is_lock_name = |name: &str| {
                let lower = name.to_lowercase();
                lock_kw.iter().any(|kw| lower.contains(kw))
            };
            let has_ptrs = fields.iter().any(|f| f.is_pointer);
            let scalars: Vec<&str> = fields.iter()
                .filter(|f| !f.is_pointer && f.size <= 8)
                .map(|f| f.name.as_str()).collect();
            let lock_names: Vec<&str> = fields.iter()
                .filter(|f| is_lock_name(&f.name))
                .map(|f| f.name.as_str()).collect();
            let non_lock: Vec<&str> = fields.iter()
                .filter(|f| !is_lock_name(&f.name))
                .map(|f| f.name.as_str()).collect();

            if !lock_names.is_empty() && !non_lock.is_empty() {
                diagnostics.push(Diagnostic {
                    severity: Severity::Warning,
                    cacheline: cl,
                    message: format!(
                        "CL{} ({:#x}-{:#x}): lock/atomic [{}] shares line with [{}]",
                        cl, cl * cl_size, (cl + 1) * cl_size - 1,
                        lock_names.join(", "), non_lock.join(", "),
                    ),
                    fields: fields.iter().map(|f| f.name.clone()).collect(),
                });
            } else if has_ptrs && !scalars.is_empty() && scalars.len() < fields.len() {
                let ptrs: Vec<&str> = fields.iter()
                    .filter(|f| f.is_pointer)
                    .map(|f| f.name.as_str()).collect();
                diagnostics.push(Diagnostic {
                    severity: Severity::Info,
                    cacheline: cl,
                    message: format!(
                        "CL{} ({:#x}-{:#x}): scalar [{}] adjacent to pointer [{}] — potential write/read contention",
                        cl, cl * cl_size, (cl + 1) * cl_size - 1,
                        scalars.join(", "), ptrs.join(", "),
                    ),
                    fields: fields.iter().map(|f| f.name.clone()).collect(),
                });
            }
        }
    }

    // union overlap check: mixed volatile/atomic qualifiers at same offset
    diagnostics.extend(check_union_overlaps(&layouts, cl_size));

    diagnostics.push(Diagnostic {
        severity: Severity::Info,
        cacheline: 0,
        message: format_layout(type_info, &layouts, cl_size, annotations),
        fields: Vec::new(),
    });
    diagnostics
}

fn format_layout(
    type_info: &TypeInfo,
    layouts: &[FieldLayout],
    cl_size: u64,
    annotations: &Annotations,
) -> String {
    let mut out = format!(
        "struct {} ({} bytes, {} cachelines at {}B/line)\n",
        type_info.name, type_info.byte_size,
        (type_info.byte_size + cl_size - 1) / cl_size, cl_size,
    );
    let mut current_cl: Option<u64> = None;
    for f in layouts {
        let cl = f.offset / cl_size;
        if current_cl != Some(cl) {
            out.push_str(&format!("  --- cacheline {} ({:#x}) ---\n", cl, cl * cl_size));
            current_cl = Some(cl);
        }
        let group = annotations.group_for(&f.name)
            .map(|g| format!("  [{}]", g))
            .unwrap_or_default();
        out.push_str(&format!(
            "    {:<40} {:#06x}  CL{}+{:<3}  {:>4}B  {}{}\n",
            f.name, f.offset, cl, f.offset % cl_size, f.size, f.type_name, group,
        ));
    }
    out
}

fn diff_structs(
    old_info: &TypeInfo,
    new_info: &TypeInfo,
    struct_name: &str,
    cl_size: u64,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let old_fields: HashMap<&str, &FieldInfo> =
        old_info.fields.iter().map(|f| (f.name.as_str(), f)).collect();
    let new_fields: HashMap<&str, &FieldInfo> =
        new_info.fields.iter().map(|f| (f.name.as_str(), f)).collect();

    for (name, new_f) in &new_fields {
        if let Some(old_f) = old_fields.get(name) {
            let old_cl = old_f.byte_offset / cl_size;
            let new_cl = new_f.byte_offset / cl_size;
            if old_cl != new_cl {
                diagnostics.push(Diagnostic {
                    severity: Severity::Warning, cacheline: new_cl,
                    message: format!("{}.{} moved CL{} ({:#x}) -> CL{} ({:#x})",
                        struct_name, name, old_cl, old_f.byte_offset, new_cl, new_f.byte_offset),
                    fields: vec![name.to_string()],
                });
            }
        }
    }
    for name in new_fields.keys() {
        if !old_fields.contains_key(name) {
            let f = new_fields[name];
            diagnostics.push(Diagnostic {
                severity: Severity::Info, cacheline: f.byte_offset / cl_size,
                message: format!("{}.{} added at {:#x} (CL{})", struct_name, name, f.byte_offset, f.byte_offset / cl_size),
                fields: vec![name.to_string()],
            });
        }
    }
    for name in old_fields.keys() {
        if !new_fields.contains_key(name) {
            diagnostics.push(Diagnostic {
                severity: Severity::Info, cacheline: 0,
                message: format!("{}.{} removed", struct_name, name),
                fields: vec![name.to_string()],
            });
        }
    }
    if old_info.byte_size != new_info.byte_size {
        let old_cls = (old_info.byte_size + cl_size - 1) / cl_size;
        let new_cls = (new_info.byte_size + cl_size - 1) / cl_size;
        diagnostics.push(Diagnostic {
            severity: if new_cls > old_cls { Severity::Warning } else { Severity::Info },
            cacheline: 0,
            message: format!("{} size: {} -> {} bytes ({} -> {} CLs)",
                struct_name, old_info.byte_size, new_info.byte_size, old_cls, new_cls),
            fields: Vec::new(),
        });
    }
    diagnostics
}

// heatmap TSV row: type, field, offset, thread, writes
#[derive(Debug)]
struct HeatEntry {
    type_name: String,
    field_name: String,
    field_offset: u64,
    thread_id: u16,
    writes: u64,
}

fn parse_heatmap(path: &str) -> Result<Vec<HeatEntry>, String> {
    let contents = fs::read_to_string(path).map_err(|e| format!("{}: {}", path, e))?;
    let mut entries = Vec::new();
    for (i, line) in contents.lines().enumerate() {
        if i == 0 && line.starts_with("type") { continue; } // header
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 5 { continue; }
        entries.push(HeatEntry {
            type_name: cols[0].to_string(),
            field_name: cols[1].to_string(),
            field_offset: cols[2].parse().unwrap_or(0),
            thread_id: cols[3].parse().unwrap_or(0),
            writes: cols[4].parse().unwrap_or(0),
        });
    }
    Ok(entries)
}

// per-field observed thread write distribution from heatmap
#[derive(Debug, Default)]
struct ObservedField {
    threads: HashMap<u16, u64>,
}

impl ObservedField {
    fn is_multi_writer(&self) -> bool { self.threads.len() > 1 }
    fn total_writes(&self) -> u64 { self.threads.values().sum() }
    fn thread_summary(&self) -> String {
        let mut pairs: Vec<_> = self.threads.iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(a.1));
        pairs.iter().map(|(t, w)| format!("T{}={}", t, w)).collect::<Vec<_>>().join(", ")
    }
}

#[derive(Debug)]
enum DivergenceClass { Confirmed, SilentKiller, FalseAlarm }

fn divergence_report(
    type_info: &TypeInfo,
    struct_name: &str,
    cl_size: u64,
    heatmap: &[HeatEntry],
) {
    let mut layouts = Vec::new();
    flatten_fields(&type_info.fields, 0, "", cl_size, &mut layouts, 0);
    layouts.sort_by_key(|f| f.offset);

    // build observed field map from heatmap, keyed by (field_name, offset)
    let mut observed: HashMap<(String, u64), ObservedField> = HashMap::new();
    for e in heatmap {
        if e.type_name != struct_name { continue; }
        let of = observed.entry((e.field_name.clone(), e.field_offset)).or_default();
        *of.threads.entry(e.thread_id).or_insert(0) += e.writes;
    }

    // map lint fields to CL, check which CLs have lint warnings
    let mut cl_fields: BTreeMap<u64, Vec<&FieldLayout>> = BTreeMap::new();
    for layout in &layouts {
        for cl in layout.cachelines() {
            cl_fields.entry(cl).or_default().push(layout);
        }
    }

    // for each CL with 2+ fields: check lint prediction vs observed reality
    let mut confirmed = 0u32;
    let mut silent = 0u32;
    let mut false_alarm = 0u32;

    println!("DIVERGENCE REPORT: {} ({} bytes, {} CLs at {}B)\n",
        struct_name, type_info.byte_size,
        (type_info.byte_size + cl_size - 1) / cl_size, cl_size);

    for (&cl, fields) in &cl_fields {
        if fields.len() < 2 { continue; }

        // lint prediction: any write-hot or lock-keyword field on this line?
        let lint_flagged = fields.iter().any(|f| {
            f.is_write_hot() || f.has_alignment || {
                let lower = f.name.to_lowercase();
                ["lock", "rwlock", "mutex", "atomic", "spinlock"].iter().any(|kw| lower.contains(kw))
            }
        });

        // observed reality: any field on this CL written by multiple threads?
        let mut cl_writers: HashMap<u16, u64> = HashMap::new();
        let mut hot_fields: Vec<(&str, &ObservedField)> = Vec::new();
        for f in fields {
            if let Some(of) = observed.get(&(f.name.clone(), f.offset)) {
                for (&tid, &w) in &of.threads {
                    *cl_writers.entry(tid).or_insert(0) += w;
                }
                if of.is_multi_writer() {
                    hot_fields.push((&f.name, of));
                }
            }
        }
        let observed_contention = cl_writers.len() > 1;

        let class = match (lint_flagged, observed_contention) {
            (true, true) => { confirmed += 1; DivergenceClass::Confirmed }
            (false, true) => { silent += 1; DivergenceClass::SilentKiller }
            (true, false) => { false_alarm += 1; DivergenceClass::FalseAlarm }
            (false, false) => continue,
        };

        let icon = match class {
            DivergenceClass::Confirmed => "CONFIRMED",
            DivergenceClass::SilentKiller => "SILENT KILLER",
            DivergenceClass::FalseAlarm => "FALSE ALARM",
        };

        println!("  CL{} ({:#x}-{:#x}): {}", cl, cl * cl_size, (cl + 1) * cl_size - 1, icon);
        println!("    lint:     {}", if lint_flagged { "flagged" } else { "clean" });
        println!("    observed: {} writer thread(s), {} total writes",
            cl_writers.len(), cl_writers.values().sum::<u64>());
        if !hot_fields.is_empty() {
            for (name, of) in &hot_fields {
                println!("      {}: [{}]", name, of.thread_summary());
            }
        }
        let field_names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        println!("    fields:   {}", field_names.join(", "));
        println!();
    }

    // also scan for silent killers on CLs the lint didn't flag at all
    // (fields written by multiple threads but not on any lint-warning CL)
    let mut orphan_hot: Vec<(&str, u64, &ObservedField)> = Vec::new();
    for ((fname, foff), of) in &observed {
        if !of.is_multi_writer() { continue; }
        let cl = foff / cl_size;
        // check if we already reported this CL
        let already = cl_fields.get(&cl).map_or(false, |fs| fs.len() >= 2);
        if !already {
            orphan_hot.push((fname.as_str(), *foff, of));
        }
    }
    if !orphan_hot.is_empty() {
        println!("  ORPHAN FIELDS (multi-thread writes, not on shared CLs):");
        for (name, off, of) in &orphan_hot {
            println!("    {} (+{:#x}): [{}]", name, off, of.thread_summary());
        }
        println!();
    }

    println!("SUMMARY: {} confirmed, {} silent killers, {} false alarms",
        confirmed, silent, false_alarm);
    if silent > 0 {
        println!("  silent killers need annotations or volatile/atomic qualifiers");
    }
}

// check union fields for mixed-qualifier contention at the same offset
fn check_union_overlaps(layouts: &[FieldLayout], cl_size: u64) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let mut by_offset: BTreeMap<u64, Vec<&FieldLayout>> = BTreeMap::new();
    for f in layouts {
        by_offset.entry(f.offset).or_default().push(f);
    }
    for (&offset, fields) in &by_offset {
        if fields.len() < 2 { continue; }
        let has_hot = fields.iter().any(|f| f.is_write_hot());
        let has_cold = fields.iter().any(|f| !f.is_write_hot());
        if has_hot && has_cold {
            let hot: Vec<&str> = fields.iter().filter(|f| f.is_write_hot()).map(|f| f.name.as_str()).collect();
            let cold: Vec<&str> = fields.iter().filter(|f| !f.is_write_hot()).map(|f| f.name.as_str()).collect();
            diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                cacheline: offset / cl_size,
                message: format!(
                    "union at offset {:#x}: volatile/atomic [{}] overlaps with [{}] — type-confused contention",
                    offset, hot.join(", "), cold.join(", "),
                ),
                fields: fields.iter().map(|f| f.name.clone()).collect(),
            });
        }
    }
    diagnostics
}

fn usage() -> ! {
    eprintln!("usage: memvis-lint <binary> --struct <name> [--cacheline N] [--annotations file]");
    eprintln!("       [--all] [--diff] [--json] [--list] [--heatmap file.tsv]");
    process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }

    let mut binary_path: Option<String> = None;
    let mut binary_path2: Option<String> = None;
    let mut struct_name: Option<String> = None;
    let mut cl_size = DEFAULT_CACHELINE;
    let mut annotations_path: Option<String> = None;
    let mut heatmap_path: Option<String> = None;
    let mut diff_mode = false;
    let mut json_output = false;
    let mut list_mode = false;
    let mut all_mode = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--struct" => {
                i += 1;
                struct_name = Some(args.get(i).cloned().unwrap_or_else(|| {
                    eprintln!("--struct requires a value");
                    process::exit(1);
                }));
            }
            "--cacheline" => {
                i += 1;
                cl_size = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| {
                        eprintln!("--cacheline requires a numeric value");
                        process::exit(1);
                    });
            }
            "--annotations" => {
                i += 1;
                annotations_path = Some(args.get(i).cloned().unwrap_or_else(|| {
                    eprintln!("--annotations requires a file path");
                    process::exit(1);
                }));
            }
            "--heatmap" => {
                i += 1;
                heatmap_path = Some(args.get(i).cloned().unwrap_or_else(|| {
                    eprintln!("--heatmap requires a file path");
                    process::exit(1);
                }));
            }
            "--diff" => diff_mode = true,
            "--json" => json_output = true,
            "--list" => list_mode = true,
            "--all" => all_mode = true,
            arg if !arg.starts_with('-') => {
                if binary_path.is_none() {
                    binary_path = Some(arg.to_string());
                } else if binary_path2.is_none() {
                    binary_path2 = Some(arg.to_string());
                } else {
                    eprintln!("unexpected argument: {}", arg);
                    usage();
                }
            }
            other => {
                eprintln!("unknown option: {}", other);
                usage();
            }
        }
        i += 1;
    }

    let binary = binary_path.unwrap_or_else(|| {
        eprintln!("missing binary path");
        usage();
    });

    let info = match parse_elf(&binary) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("error: failed to parse {}: {}", binary, e);
            process::exit(1);
        }
    };

    if list_mode {
        let mut types: Vec<(&String, &TypeInfo)> = info
            .type_registry
            .iter()
            .filter(|(_, ti)| !ti.fields.is_empty() && ti.byte_size > 0)
            .collect();
        types.sort_by_key(|(name, _)| name.to_lowercase());

        println!("{} struct types found in {}:", types.len(), binary);
        println!();
        for (name, ti) in &types {
            let n_cls = (ti.byte_size + cl_size - 1) / cl_size;
            println!(
                "  {:<50} {:>6}B  {:>2} fields  {:>2} CLs",
                name,
                ti.byte_size,
                ti.fields.len(),
                n_cls,
            );
        }
        return;
    }

    if diff_mode {
        let binary2 = binary_path2.unwrap_or_else(|| {
            eprintln!("--diff requires two binary paths");
            usage();
        });
        let sname = struct_name.unwrap_or_else(|| {
            eprintln!("--diff requires --struct");
            usage();
        });

        let info2 = match parse_elf(&binary2) {
            Ok(info) => info,
            Err(e) => {
                eprintln!("error: failed to parse {}: {}", binary2, e);
                process::exit(1);
            }
        };

        let old_type = info.type_registry.get(&sname).unwrap_or_else(|| {
            eprintln!("struct '{}' not found in {}", sname, binary);
            process::exit(1);
        });
        let new_type = info2.type_registry.get(&sname).unwrap_or_else(|| {
            eprintln!("struct '{}' not found in {}", sname, binary2);
            process::exit(1);
        });

        let diags = diff_structs(old_type, new_type, &sname, cl_size);
        print_diagnostics(&diags, json_output);
        let warnings = diags.iter().filter(|d| matches!(d.severity, Severity::Warning)).count();
        if warnings > 0 {
            process::exit(1);
        }
        return;
    }

    // --heatmap: divergence report (lint predictions vs observed runtime)
    if let Some(ref hp) = heatmap_path {
        let sname = struct_name.unwrap_or_else(|| {
            eprintln!("--heatmap requires --struct");
            usage();
        });
        let ti = info.type_registry.get(&sname).unwrap_or_else(|| {
            eprintln!("struct '{}' not found in {}", sname, binary);
            process::exit(1);
        });
        let heatmap = match parse_heatmap(hp) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("error: {}", e);
                process::exit(1);
            }
        };
        eprintln!("lint: loaded {} heatmap entries from {}", heatmap.len(), hp);
        divergence_report(ti, &sname, cl_size, &heatmap);
        return;
    }

    let annotations = match annotations_path {
        Some(ref path) => match Annotations::from_file(path) {
            Ok(a) => {
                eprintln!(
                    "lint: loaded {} field annotations from {}",
                    a.field_to_group.len(),
                    path
                );
                a
            }
            Err(e) => {
                eprintln!("error: {}", e);
                process::exit(1);
            }
        },
        None => Annotations::empty(),
    };

    let sname = struct_name.unwrap_or_default();
    let structs_to_check: Vec<(&String, &TypeInfo)> = if all_mode {
        info.type_registry
            .iter()
            .filter(|(_, ti)| !ti.fields.is_empty() && ti.byte_size > 0)
            .collect()
    } else {
        if sname.is_empty() {
            eprintln!("specify --struct <name> or --all");
            usage();
        }
        match info.type_registry.get(&sname) {
            Some(ti) => vec![(&sname, ti)],
            None => {
                // try fuzzy match
                let matches: Vec<&String> = info
                    .type_registry
                    .keys()
                    .filter(|k| k.to_lowercase().contains(&sname.to_lowercase()))
                    .collect();
                if matches.is_empty() {
                    eprintln!("struct '{}' not found. use --list to see available types.", sname);
                    process::exit(1);
                } else {
                    eprintln!("struct '{}' not found. did you mean:", sname);
                    for m in &matches {
                        eprintln!("  {}", m);
                    }
                    process::exit(1);
                }
            }
        }
    };

    let mut total_warnings = 0;
    for (name, ti) in &structs_to_check {
        let diags = analyze_struct(ti, cl_size, &annotations);
        let warnings = diags
            .iter()
            .filter(|d| matches!(d.severity, Severity::Warning))
            .count();
        total_warnings += warnings;

        if all_mode && warnings == 0 {
            continue; // skip clean structs in --all mode
        }

        if all_mode {
            println!("\n━━━ {} ━━━", name);
        }
        print_diagnostics(&diags, json_output);
    }

    if all_mode {
        eprintln!(
            "\nlint: analyzed {} structs, {} warnings",
            structs_to_check.len(),
            total_warnings
        );
    }

    if total_warnings > 0 {
        process::exit(1);
    }
}

fn print_diagnostics(diags: &[Diagnostic], json: bool) {
    if json {
        print_diagnostics_json(diags);
    } else {
        for d in diags {
            match d.severity {
                Severity::Warning => {
                    println!("⚠  WARNING: {}", d.message);
                }
                Severity::Info => {
                    println!("{}", d.message);
                }
            }
        }
    }
}

fn print_diagnostics_json(diags: &[Diagnostic]) {
    println!("[");
    for (i, d) in diags.iter().enumerate() {
        let severity = match d.severity {
            Severity::Warning => "warning",
            Severity::Info => "info",
        };
        let fields_json: Vec<String> = d.fields.iter().map(|f| format!("\"{}\"", f)).collect();
        let msg_escaped = d.message.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
        println!(
            "  {{\"severity\":\"{}\",\"cacheline\":{},\"message\":\"{}\",\"fields\":[{}]}}{}",
            severity,
            d.cacheline,
            msg_escaped,
            fields_json.join(","),
            if i + 1 < diags.len() { "," } else { "" }
        );
    }
    println!("]");
}
