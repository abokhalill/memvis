// SPDX-License-Identifier: Apache-2.0
// jsonl topology streamer: emits structural graph deltas for external consumption.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

pub struct TopologyStream {
    w: BufWriter<File>,
    lines: u64,
}

impl TopologyStream {
    pub fn create(path: &Path) -> io::Result<Self> {
        let f = File::create(path)?;
        Ok(Self {
            w: BufWriter::with_capacity(256 * 1024, f),
            lines: 0,
        })
    }

    pub fn lines(&self) -> u64 {
        self.lines
    }

    pub fn finish(mut self) -> io::Result<u64> {
        self.w.flush()?;
        Ok(self.lines)
    }

    pub fn emit_alloc(&mut self, seq: u64, tid: u16, addr: u64, size: u64) {
        let _ = writeln!(
            self.w,
            r#"{{"seq":{},"tid":{},"type":"ALLOC","addr":"0x{:x}","size":{}}}"#,
            seq, tid, addr, size
        );
        self.lines += 1;
    }

    pub fn emit_free(&mut self, seq: u64, tid: u16, addr: u64, size: u64) {
        let _ = writeln!(
            self.w,
            r#"{{"seq":{},"tid":{},"type":"FREE","addr":"0x{:x}","size":{}}}"#,
            seq, tid, addr, size
        );
        self.lines += 1;
    }

    pub fn emit_cold_stamp(
        &mut self,
        target_addr: u64,
        type_name: &str,
        type_size: u64,
        source_name: &str,
        field_count: usize,
        depth: u32,
    ) {
        let _ = writeln!(
            self.w,
            r#"{{"type":"COLD_STAMP","addr":"0x{:x}","type_name":"{}","type_size":{},"source":"{}","fields":{},"depth":{}}}"#,
            target_addr, esc(type_name), type_size, esc(source_name), field_count, depth
        );
        self.lines += 1;
    }

    pub fn emit_cold_link(
        &mut self,
        from_name: &str,
        from_addr: u64,
        to_addr: u64,
        pointee_type: &str,
        edge_field: &str,
    ) {
        let _ = writeln!(
            self.w,
            r#"{{"type":"COLD_LINK","from":"{}","from_addr":"0x{:x}","to_addr":"0x{:x}","pointee_type":"{}","edge":"{}"}}"#,
            esc(from_name), from_addr, to_addr, esc(pointee_type), esc(edge_field)
        );
        self.lines += 1;
    }

    pub fn emit_stamp(
        &mut self,
        seq: u64,
        target_addr: u64,
        type_name: &str,
        type_size: u64,
        source_name: &str,
        field_count: usize,
    ) {
        let _ = writeln!(
            self.w,
            r#"{{"seq":{},"type":"STAMP","addr":"0x{:x}","type_name":"{}","type_size":{},"source":"{}","fields":{}}}"#,
            seq, target_addr, esc(type_name), type_size, esc(source_name), field_count
        );
        self.lines += 1;
    }

    pub fn emit_link(
        &mut self,
        seq: u64,
        from_name: &str,
        from_addr: u64,
        to_addr: u64,
        pointee_type: &str,
        edge_field: &str,
    ) {
        let _ = writeln!(
            self.w,
            r#"{{"seq":{},"type":"LINK","from":"{}","from_addr":"0x{:x}","to_addr":"0x{:x}","pointee_type":"{}","edge":"{}"}}"#,
            seq, esc(from_name), from_addr, to_addr, esc(pointee_type), esc(edge_field)
        );
        self.lines += 1;
    }

    pub fn emit_hazard(
        &mut self,
        seq: u64,
        kind: &str,
        write_addr: u64,
        write_size: u32,
        alloc_base: u64,
        alloc_size: u64,
        overflow: u64,
        type_name: Option<&str>,
        field_name: Option<&str>,
    ) {
        let tn = type_name.unwrap_or("");
        let fn_ = field_name.unwrap_or("");
        let _ = writeln!(
            self.w,
            r#"{{"seq":{},"type":"HAZARD","kind":"{}","write_addr":"0x{:x}","write_size":{},"alloc_base":"0x{:x}","alloc_size":{},"overflow":{},"type_name":"{}","field_name":"{}"}}"#,
            seq, kind, write_addr, write_size, alloc_base, alloc_size, overflow, esc(tn), esc(fn_)
        );
        self.lines += 1;
    }

    pub fn emit_false_share(
        &mut self,
        seq: u64,
        cl_addr: u64,
        thread_count: u32,
        names: &[&str],
    ) {
        let names_json: String = names
            .iter()
            .map(|n| format!(r#""{}""#, esc(n)))
            .collect::<Vec<_>>()
            .join(",");
        let _ = writeln!(
            self.w,
            r#"{{"seq":{},"type":"FALSE_SHARE","cl_addr":"0x{:x}","threads":{},"names":[{}]}}"#,
            seq, cl_addr, thread_count, names_json
        );
        self.lines += 1;
    }

    pub fn emit_summary(
        &mut self,
        total_events: u64,
        nodes: usize,
        edges: usize,
        stm_projections: usize,
        live_allocs: usize,
        hazard_count: usize,
    ) {
        let _ = writeln!(
            self.w,
            r#"{{"type":"SUMMARY","total_events":{},"nodes":{},"edges":{},"stm_projections":{},"live_allocs":{},"hazards":{}}}"#,
            total_events, nodes, edges, stm_projections, live_allocs, hazard_count
        );
        self.lines += 1;
    }
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}
