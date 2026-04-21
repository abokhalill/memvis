// SPDX-License-Identifier: Apache-2.0
// memvis-check: structural assertion engine for CI/CD pipelines.
// reads a JSONL topology file + .assertions file, evaluates invariants.

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{self, BufRead};
use std::process;

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct AllocEvent {
    seq: u64,
    addr: u64,
    size: u64,
    freed: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct StampEvent {
    seq: u64,
    addr: u64,
    type_name: String,
    type_size: u64,
    source: String,
    fields: usize,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct LinkEvent {
    seq: u64,
    from_name: String,
    from_addr: u64,
    to_addr: u64,
    pointee_type: String,
    edge: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct HazardEvent {
    seq: u64,
    kind: String,
    write_addr: u64,
    write_size: u32,
    alloc_base: u64,
    alloc_size: u64,
    overflow: u64,
    type_name: String,
    field_name: String,
}

#[allow(dead_code)]
#[derive(Debug, Default)]
struct Summary {
    total_events: u64,
    nodes: usize,
    edges: usize,
    stm_projections: usize,
    live_allocs: usize,
    hazards: usize,
}

#[derive(Debug, Default)]
struct TopoGraph {
    allocs: Vec<AllocEvent>,
    stamps: Vec<StampEvent>,
    links: Vec<LinkEvent>,
    hazards: Vec<HazardEvent>,
    summary: Summary,
    addr_type: HashMap<u64, String>,
    type_addrs: HashMap<String, HashSet<u64>>,
    edges: HashMap<(u64, String), u64>,
    source_targets: HashMap<String, u64>,
}

impl TopoGraph {
    fn build(path: &str) -> io::Result<Self> {
        let file = fs::File::open(path)?;
        let reader = io::BufReader::new(file);
        let mut g = TopoGraph::default();

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // minimal json parsing without serde
            let ty = json_str(line, "type");
            match ty.as_str() {
                "ALLOC" => {
                    g.allocs.push(AllocEvent {
                        seq: json_u64(line, "seq"),
                        addr: json_hex(line, "addr"),
                        size: json_u64(line, "size"),
                        freed: false,
                    });
                }
                "FREE" => {
                    let addr = json_hex(line, "addr");
                    if let Some(a) = g
                        .allocs
                        .iter_mut()
                        .rev()
                        .find(|a| a.addr == addr && !a.freed)
                    {
                        a.freed = true;
                    }
                    g.addr_type.remove(&addr);
                }
                "STAMP" => {
                    let addr = json_hex(line, "addr");
                    let type_name = json_str(line, "type_name");
                    let source = json_str(line, "source");
                    g.addr_type.insert(addr, type_name.clone());
                    g.type_addrs
                        .entry(type_name.clone())
                        .or_default()
                        .insert(addr);
                    g.source_targets.insert(source.clone(), addr);
                    g.stamps.push(StampEvent {
                        seq: json_u64(line, "seq"),
                        addr,
                        type_name,
                        type_size: json_u64(line, "type_size"),
                        source,
                        fields: json_u64(line, "fields") as usize,
                    });
                }
                "LINK" => {
                    let from_name = json_str(line, "from");
                    let from_addr = json_hex(line, "from_addr");
                    let to_addr = json_hex(line, "to_addr");
                    let edge = json_str(line, "edge");
                    let pointee_type = json_str(line, "pointee_type");
                    // resolve field addr to object base for chain traversal
                    let base = g.resolve_base(from_addr).unwrap_or(from_addr);
                    g.edges.insert((base, edge.clone()), to_addr);
                    g.links.push(LinkEvent {
                        seq: json_u64(line, "seq"),
                        from_name,
                        from_addr,
                        to_addr,
                        pointee_type,
                        edge,
                    });
                }
                "HAZARD" => {
                    g.hazards.push(HazardEvent {
                        seq: json_u64(line, "seq"),
                        kind: json_str(line, "kind"),
                        write_addr: json_hex(line, "write_addr"),
                        write_size: json_u64(line, "write_size") as u32,
                        alloc_base: json_hex(line, "alloc_base"),
                        alloc_size: json_u64(line, "alloc_size"),
                        overflow: json_u64(line, "overflow"),
                        type_name: json_str(line, "type_name"),
                        field_name: json_str(line, "field_name"),
                    });
                }
                "SUMMARY" => {
                    g.summary = Summary {
                        total_events: json_u64(line, "total_events"),
                        nodes: json_u64(line, "nodes") as usize,
                        edges: json_u64(line, "edges") as usize,
                        stm_projections: json_u64(line, "stm_projections") as usize,
                        live_allocs: json_u64(line, "live_allocs") as usize,
                        hazards: json_u64(line, "hazards") as usize,
                    };
                }
                _ => {}
            }
        }
        Ok(g)
    }

    fn resolve_base(&self, field_addr: u64) -> Option<u64> {
        // find the stamped object whose range covers field_addr
        self.stamps
            .iter()
            .rev()
            .find(|s| field_addr >= s.addr && field_addr < s.addr + s.type_size)
            .map(|s| s.addr)
    }

    fn chain_length(&self, start_type: &str, edge_field: &str) -> usize {
        let addrs: Vec<u64> = self
            .type_addrs
            .get(start_type)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        let mut max_len = 0usize;
        for start in &addrs {
            let mut visited = HashSet::new();
            let mut cur = *start;
            let mut len = 0;
            loop {
                if !visited.insert(cur) {
                    break;
                } // cycle
                len += 1;
                match self.edges.get(&(cur, edge_field.to_string())) {
                    Some(&next) if next != 0 => cur = next,
                    _ => break,
                }
            }
            max_len = max_len.max(len);
        }
        max_len
    }

    fn type_stable(&self, source_name: &str, expected_type: &str) -> bool {
        // check that every STAMP from this source has the expected type
        self.stamps
            .iter()
            .filter(|s| s.source == source_name)
            .all(|s| s.type_name == expected_type)
    }

    fn live_alloc_count(&self) -> usize {
        self.allocs.iter().filter(|a| !a.freed).count()
    }
}

#[derive(Debug)]
enum Assertion {
    NoHazards,
    LiveAllocsLt(usize),
    MaxChain {
        type_name: String,
        field: String,
        limit: usize,
    },
    TypeStable {
        source: String,
        expected_type: String,
    },
    NoFalseSharing {
        name_a: String,
        name_b: String,
    },
    StmProjectionsGt(usize),
    AllocBeforeStamp,
    NoUseAfterFree,
    MonotonicSeq,
    StampBeforeLink,
}

fn parse_assertions(path: &str) -> io::Result<Vec<(usize, Assertion)>> {
    let content = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for (lineno, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with("assert ") {
            eprintln!("  WARN line {}: unrecognized: {}", lineno + 1, line);
            continue;
        }
        let body = line[7..].trim();
        if let Some(a) = parse_one(body) {
            out.push((lineno + 1, a));
        } else {
            eprintln!("  WARN line {}: could not parse: {}", lineno + 1, body);
        }
    }
    Ok(out)
}

fn parse_one(s: &str) -> Option<Assertion> {
    if s == "no_hazards" {
        return Some(Assertion::NoHazards);
    }
    // live_allocs < N
    if s.starts_with("live_allocs") {
        let rest = s.strip_prefix("live_allocs")?.trim();
        let rest = rest.strip_prefix('<')?.trim();
        let n: usize = rest.parse().ok()?;
        return Some(Assertion::LiveAllocsLt(n));
    }
    // stm_projections > N
    if s.starts_with("stm_projections") {
        let rest = s.strip_prefix("stm_projections")?.trim();
        let rest = rest.strip_prefix('>')?.trim();
        let n: usize = rest.parse().ok()?;
        return Some(Assertion::StmProjectionsGt(n));
    }
    // max_chain(type("X"), "Y") < N
    if let Some(after) = s.strip_prefix("max_chain(") {
        // find the closing paren that matches the opening one after max_chain
        let mut depth = 1i32;
        let mut close_pos = None;
        for (i, c) in after.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close_pos = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close = close_pos?;
        let args_str = &after[..close]; // type("node"), "next"
        let limit_str = after[close + 1..].trim().strip_prefix('<')?.trim();
        let limit: usize = limit_str.parse().ok()?;
        let type_arg = extract_quoted_after(args_str, "type(")?;
        let comma_rest = args_str.split_once(',')?.1.trim();
        let field = extract_plain_quoted(comma_rest)?;
        return Some(Assertion::MaxChain {
            type_name: type_arg,
            field,
            limit,
        });
    }
    // type_stable(global("X"), "Y")
    if s.starts_with("type_stable(") {
        let inner = s.strip_prefix("type_stable(")?.strip_suffix(')')?;
        let source = extract_quoted_after(inner, "global(")?;
        let rest = inner.split_once(',')?.1.trim();
        let expected = extract_plain_quoted(rest)?;
        return Some(Assertion::TypeStable {
            source,
            expected_type: expected,
        });
    }
    if s == "alloc_before_stamp" {
        return Some(Assertion::AllocBeforeStamp);
    }
    if s == "no_use_after_free" {
        return Some(Assertion::NoUseAfterFree);
    }
    if s == "monotonic_seq" {
        return Some(Assertion::MonotonicSeq);
    }
    if s == "stamp_before_link" {
        return Some(Assertion::StampBeforeLink);
    }
    // no_false_sharing("X", "Y") - currently checks cacheline distance via stamps
    if s.starts_with("no_false_sharing(") {
        let inner = s.strip_prefix("no_false_sharing(")?.strip_suffix(')')?;
        let parts: Vec<&str> = inner.split(',').collect();
        if parts.len() == 2 {
            let a = extract_plain_quoted(parts[0].trim())?;
            let b = extract_plain_quoted(parts[1].trim())?;
            return Some(Assertion::NoFalseSharing {
                name_a: a,
                name_b: b,
            });
        }
    }
    None
}

fn extract_quoted_after(s: &str, prefix: &str) -> Option<String> {
    let rest = s.strip_prefix(prefix)?;
    let q1 = rest.find('"')? + 1;
    let q2 = q1 + rest[q1..].find('"')?;
    Some(rest[q1..q2].to_string())
}

fn extract_plain_quoted(s: &str) -> Option<String> {
    let q1 = s.find('"')? + 1;
    let q2 = q1 + s[q1..].find('"')?;
    Some(s[q1..q2].to_string())
}

fn evaluate(graph: &TopoGraph, assertions: &[(usize, Assertion)]) -> (usize, usize) {
    let mut pass = 0usize;
    let mut fail = 0usize;
    for (lineno, assertion) in assertions {
        let (ok, msg) = eval_one(graph, assertion);
        if ok {
            println!("  PASS  line {:>3}: {}", lineno, msg);
            pass += 1;
        } else {
            println!("  FAIL  line {:>3}: {}", lineno, msg);
            fail += 1;
        }
    }
    (pass, fail)
}

fn eval_one(g: &TopoGraph, a: &Assertion) -> (bool, String) {
    match a {
        Assertion::NoHazards => {
            let n = g.hazards.len();
            (n == 0, format!("no_hazards (found {})", n))
        }
        Assertion::LiveAllocsLt(limit) => {
            let n = g.live_alloc_count();
            (
                n < *limit,
                format!("live_allocs < {} (actual {})", limit, n),
            )
        }
        Assertion::StmProjectionsGt(min) => {
            let n = g.summary.stm_projections;
            (
                n > *min,
                format!("stm_projections > {} (actual {})", min, n),
            )
        }
        Assertion::MaxChain {
            type_name,
            field,
            limit,
        } => {
            let len = g.chain_length(type_name, field);
            (
                len < *limit,
                format!(
                    "max_chain(type(\"{}\"), \"{}\") < {} (actual {})",
                    type_name, field, limit, len
                ),
            )
        }
        Assertion::TypeStable {
            source,
            expected_type,
        } => {
            let ok = g.type_stable(source, expected_type);
            let actual: Vec<String> = g
                .stamps
                .iter()
                .filter(|s| s.source == *source)
                .map(|s| s.type_name.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            (
                ok,
                format!(
                    "type_stable(global(\"{}\"), \"{}\") (seen: {:?})",
                    source, expected_type, actual
                ),
            )
        }
        Assertion::AllocBeforeStamp => {
            let alloc_addrs: HashSet<u64> = g.allocs.iter().map(|a| a.addr).collect();
            let mut violations = 0usize;
            let mut skipped_non_heap = 0usize;
            let mut first_violation: Option<(u64, u64)> = None;
            for s in &g.stamps {
                if !alloc_addrs.contains(&s.addr) {
                    skipped_non_heap += 1;
                    continue;
                }
                let has_prior = g.allocs.iter().any(|a| a.addr == s.addr && a.seq <= s.seq);
                if !has_prior {
                    violations += 1;
                    if first_violation.is_none() {
                        first_violation = Some((s.seq, s.addr));
                    }
                }
            }
            let msg = if violations == 0 {
                format!("alloc_before_stamp (all heap stamps have preceding alloc, {} non-heap skipped)", skipped_non_heap)
            } else {
                let (seq, addr) = first_violation.unwrap();
                format!("alloc_before_stamp ({} violations, first at seq={} addr=0x{:x}, {} non-heap skipped)", violations, seq, addr, skipped_non_heap)
            };
            (violations == 0, msg)
        }
        Assertion::NoUseAfterFree => {
            let mut freed: HashMap<u64, u64> = HashMap::new();
            for a in &g.allocs {
                if a.freed {
                    freed.insert(a.addr, a.seq);
                }
            }
            let mut violations = 0usize;
            let mut first_violation: Option<(u64, &str, u64)> = None;
            for s in &g.stamps {
                if let Some(&free_seq) = freed.get(&s.addr) {
                    if s.seq > free_seq {
                        violations += 1;
                        if first_violation.is_none() {
                            first_violation = Some((s.seq, "STAMP", s.addr));
                        }
                    }
                }
            }
            for l in &g.links {
                if let Some(&free_seq) = freed.get(&l.to_addr) {
                    if l.seq > free_seq {
                        violations += 1;
                        if first_violation.is_none() {
                            first_violation = Some((l.seq, "LINK", l.to_addr));
                        }
                    }
                }
            }
            let msg = if violations == 0 {
                "no_use_after_free (0 violations)".to_string()
            } else {
                let (seq, kind, addr) = first_violation.unwrap();
                format!(
                    "no_use_after_free ({} violations, first {} at seq={} addr=0x{:x})",
                    violations, kind, seq, addr
                )
            };
            (violations == 0, msg)
        }
        Assertion::MonotonicSeq => {
            let mut violations = 0usize;
            let mut last_alloc_seq = 0u64;
            let mut last_stamp_seq = 0u64;
            let mut last_link_seq = 0u64;
            let mut first_violation: Option<(u64, u64, &str)> = None;
            for a in &g.allocs {
                if a.seq < last_alloc_seq {
                    violations += 1;
                    if first_violation.is_none() {
                        first_violation = Some((a.seq, last_alloc_seq, "ALLOC"));
                    }
                }
                last_alloc_seq = a.seq;
            }
            for s in &g.stamps {
                if s.seq < last_stamp_seq {
                    violations += 1;
                    if first_violation.is_none() {
                        first_violation = Some((s.seq, last_stamp_seq, "STAMP"));
                    }
                }
                last_stamp_seq = s.seq;
            }
            for l in &g.links {
                if l.seq < last_link_seq {
                    violations += 1;
                    if first_violation.is_none() {
                        first_violation = Some((l.seq, last_link_seq, "LINK"));
                    }
                }
                last_link_seq = l.seq;
            }
            let msg = if violations == 0 {
                "monotonic_seq (all event streams ordered)".to_string()
            } else {
                let (seq, prev, kind) = first_violation.unwrap();
                format!(
                    "monotonic_seq ({} violations, first {} seq={} < prev={})",
                    violations, kind, seq, prev
                )
            };
            (violations == 0, msg)
        }
        Assertion::StampBeforeLink => {
            let mut stamp_seqs: HashMap<u64, u64> = HashMap::new();
            for s in &g.stamps {
                stamp_seqs.entry(s.addr).or_insert(s.seq);
            }
            let mut violations = 0usize;
            let mut first_violation: Option<(u64, u64)> = None;
            for l in &g.links {
                if l.to_addr == 0 {
                    continue;
                }
                if let Some(&stamp_seq) = stamp_seqs.get(&l.to_addr) {
                    if l.seq < stamp_seq {
                        violations += 1;
                        if first_violation.is_none() {
                            first_violation = Some((l.seq, l.to_addr));
                        }
                    }
                }
            }
            let msg = if violations == 0 {
                "stamp_before_link (all link targets stamped before use)".to_string()
            } else {
                let (seq, addr) = first_violation.unwrap();
                format!(
                    "stamp_before_link ({} violations, first at seq={} to_addr=0x{:x})",
                    violations, seq, addr
                )
            };
            (violations == 0, msg)
        }
        Assertion::NoFalseSharing { name_a, name_b } => {
            let addr_a = g.source_targets.get(name_a.as_str()).or_else(|| {
                g.stamps
                    .iter()
                    .find(|s| s.source == *name_a || s.type_name == *name_a)
                    .map(|s| &s.addr)
            });
            let addr_b = g.source_targets.get(name_b.as_str()).or_else(|| {
                g.stamps
                    .iter()
                    .find(|s| s.source == *name_b || s.type_name == *name_b)
                    .map(|s| &s.addr)
            });
            match (addr_a, addr_b) {
                (Some(&a), Some(&b)) => {
                    let cl_a = a >> 6;
                    let cl_b = b >> 6;
                    let ok = cl_a != cl_b;
                    (
                        ok,
                        format!(
                            "no_false_sharing(\"{}\", \"{}\") cl_a=0x{:x} cl_b=0x{:x} {}",
                            name_a,
                            name_b,
                            cl_a * 64,
                            cl_b * 64,
                            if ok { "distinct" } else { "SHARED" }
                        ),
                    )
                }
                _ => (
                    true,
                    format!(
                        "no_false_sharing(\"{}\", \"{}\"): one or both not found (vacuously true)",
                        name_a, name_b
                    ),
                ),
            }
        }
    }
}

fn json_str(line: &str, key: &str) -> String {
    let needle = format!("\"{}\":\"", key);
    if let Some(start) = line.find(&needle) {
        let rest = &line[start + needle.len()..];
        if let Some(end) = rest.find('"') {
            return rest[..end].replace("\\\"", "\"").replace("\\n", "\n");
        }
    }
    String::new()
}

fn json_u64(line: &str, key: &str) -> u64 {
    let needle = format!("\"{}\":", key);
    if let Some(start) = line.find(&needle) {
        let rest = &line[start + needle.len()..];
        let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        return num_str.parse().unwrap_or(0);
    }
    0
}

fn json_hex(line: &str, key: &str) -> u64 {
    let s = json_str(line, key);
    let hex = s.strip_prefix("0x").unwrap_or(&s);
    u64::from_str_radix(hex, 16).unwrap_or(0)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: memvis-check <topology.jsonl> <assertions.txt>");
        eprintln!();
        eprintln!("Assertion DSL:");
        eprintln!("  assert no_hazards");
        eprintln!("  assert live_allocs < 100");
        eprintln!("  assert stm_projections > 0");
        eprintln!("  assert max_chain(type(\"node_t\"), \"next\") < 1000");
        eprintln!("  assert type_stable(global(\"g_head\"), \"node\")");
        eprintln!("  assert no_false_sharing(\"counter\", \"lock\")");
        eprintln!("  # temporal (lifecycle ordering)");
        eprintln!("  assert alloc_before_stamp");
        eprintln!("  assert no_use_after_free");
        eprintln!("  assert monotonic_seq");
        eprintln!("  assert stamp_before_link");
        process::exit(1);
    }

    let topo_path = &args[1];
    let assert_path = &args[2];

    eprintln!("memvis-check: loading topology from {}", topo_path);
    let graph = match TopoGraph::build(topo_path) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("memvis-check: failed to load topology: {}", e);
            process::exit(1);
        }
    };
    eprintln!(
        "memvis-check: {} allocs, {} stamps, {} links, {} hazards",
        graph.allocs.len(),
        graph.stamps.len(),
        graph.links.len(),
        graph.hazards.len()
    );

    eprintln!("memvis-check: loading assertions from {}", assert_path);
    let assertions = match parse_assertions(assert_path) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("memvis-check: failed to parse assertions: {}", e);
            process::exit(1);
        }
    };
    eprintln!("memvis-check: {} assertions loaded", assertions.len());

    println!();
    let (pass, fail) = evaluate(&graph, &assertions);
    println!();
    println!("memvis-check: {} passed, {} failed", pass, fail);

    if fail > 0 {
        process::exit(1);
    }
}
