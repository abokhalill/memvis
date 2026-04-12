// SPDX-License-Identifier: MIT
// ratatui interactive TUI for memvis

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;

use crossterm::event::{self, Event as CEvent, KeyCode, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use ratatui::prelude::*;
use ratatui::widgets::*;

use crate::index::NodeId;
use crate::world::{WorldInner, ShadowStack, REG_NAMES, REG_COUNT};

#[derive(Clone)]
pub struct JournalEntry {
    pub seq: u64,
    pub kind: u8,
    pub thread_id: u16,
    pub addr: u64,
    pub size: u32,
    pub value: u64,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Panel { Memory, Events, Registers }

pub struct EventFilter {
    pub thread_id: Option<u16>,    // None = all threads
    pub hide_reads: bool,
    pub writes_only: bool,
}

impl EventFilter {
    pub fn new() -> Self { Self { thread_id: None, hide_reads: false, writes_only: false } }
    pub fn is_active(&self) -> bool { self.thread_id.is_some() || self.hide_reads || self.writes_only }
    pub fn matches(&self, entry: &JournalEntry) -> bool {
        if let Some(tid) = self.thread_id {
            if entry.thread_id != tid { return false; }
        }
        if self.writes_only && entry.kind != 0 { return false; }
        if self.hide_reads && entry.kind == 1 { return false; }
        true
    }
}

pub struct AppState {
    pub mem_scroll: usize,
    pub evt_scroll: usize,
    pub focus: Panel,
    pub quit: bool,
    pub paused: bool,
    pub time_travel_idx: Option<usize>,
    pub snap_count: usize,
    pub filter: EventFilter,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            mem_scroll: 0, evt_scroll: 0, focus: Panel::Memory,
            quit: false, paused: false,
            time_travel_idx: None, snap_count: 0,
            filter: EventFilter::new(),
        }
    }
}

pub fn init_terminal() -> io::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

pub fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) {
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();
}

pub fn handle_input(state: &mut AppState) {
    while event::poll(std::time::Duration::ZERO).unwrap_or(false) {
        if let Ok(CEvent::Key(key)) = event::read() {
            match key.code {
                KeyCode::Char('q') => state.quit = true,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => state.quit = true,
                KeyCode::Tab => {
                    state.focus = match state.focus {
                        Panel::Memory => Panel::Events,
                        Panel::Events => Panel::Registers,
                        Panel::Registers => Panel::Memory,
                    };
                }
                KeyCode::Char(' ') => state.paused = !state.paused,
                KeyCode::Left | KeyCode::Char('h') => {
                    let max = state.snap_count.saturating_sub(1);
                    match state.time_travel_idx {
                        Some(idx) => {
                            if idx > 0 { state.time_travel_idx = Some(idx - 1); }
                        }
                        None if max > 0 => {
                            state.time_travel_idx = Some(max.saturating_sub(1));
                            state.paused = true;
                        }
                        _ => {}
                    }
                }
                KeyCode::Right | KeyCode::Char('l') => {
                    let max = state.snap_count.saturating_sub(1);
                    match state.time_travel_idx {
                        Some(idx) => {
                            if idx >= max {
                                state.time_travel_idx = None; // back to live
                            } else {
                                state.time_travel_idx = Some(idx + 1);
                            }
                        }
                        None => {} // already live
                    }
                }
                KeyCode::End => {
                    state.time_travel_idx = None; // jump to live
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    match state.focus {
                        Panel::Memory => state.mem_scroll = state.mem_scroll.saturating_sub(1),
                        Panel::Events => state.evt_scroll = state.evt_scroll.saturating_sub(1),
                        _ => {}
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    match state.focus {
                        Panel::Memory => state.mem_scroll += 1,
                        Panel::Events => state.evt_scroll += 1,
                        _ => {}
                    }
                }
                KeyCode::PageUp => {
                    match state.focus {
                        Panel::Memory => state.mem_scroll = state.mem_scroll.saturating_sub(20),
                        Panel::Events => state.evt_scroll = state.evt_scroll.saturating_sub(20),
                        _ => {}
                    }
                }
                KeyCode::PageDown => {
                    match state.focus {
                        Panel::Memory => state.mem_scroll += 20,
                        Panel::Events => state.evt_scroll += 20,
                        _ => {}
                    }
                }
                KeyCode::Home => {
                    match state.focus {
                        Panel::Memory => state.mem_scroll = 0,
                        Panel::Events => state.evt_scroll = 0,
                        _ => {}
                    }
                }
                // event filters (only when events panel focused)
                KeyCode::Char('w') if state.focus == Panel::Events => {
                    state.filter.writes_only = !state.filter.writes_only;
                    if state.filter.writes_only { state.filter.hide_reads = false; }
                }
                KeyCode::Char('r') if state.focus == Panel::Events => {
                    state.filter.hide_reads = !state.filter.hide_reads;
                    if state.filter.hide_reads { state.filter.writes_only = false; }
                }
                KeyCode::Char(c @ '0'..='9') if state.focus == Panel::Events => {
                    let tid = (c as u16) - ('0' as u16);
                    state.filter.thread_id = if state.filter.thread_id == Some(tid) { None } else { Some(tid) };
                }
                KeyCode::Char('x') if state.focus == Panel::Events => {
                    state.filter = EventFilter::new();
                }
                _ => {}
            }
        }
    }
}

fn type_color(t: &str) -> Color {
    let l = t.to_ascii_lowercase();
    if l.starts_with('*') || l.contains("ptr") { return Color::Magenta; }
    if l.contains("char") { return Color::Green; }
    if l.contains("float") || l.contains("double") { return Color::Yellow; }
    if l.contains("int") || l.contains("long") || l.contains("short") { return Color::Blue; }
    if l.contains("struct") || l.contains("vec") || l.contains("entity") { return Color::Cyan; }
    Color::White
}

fn recency_color(last_write: u64, current_insn: u64) -> Color {
    if last_write == 0 { return Color::DarkGray; }
    let age = current_insn.saturating_sub(last_write);
    if age < 100 { Color::Red }
    else if age < 1000 { Color::Yellow }
    else if age < 10000 { Color::White }
    else { Color::DarkGray }
}

struct MemLine {
    spans: Vec<Span<'static>>,
}

fn build_mem_lines(world: &WorldInner) -> Vec<MemLine> {
    let mut sorted: Vec<_> = world.nodes.iter().filter(|(_, n)| n.size > 0).collect();
    sorted.sort_by_key(|(_, n)| (n.addr, std::cmp::Reverse(n.last_write_insn)));
    sorted.dedup_by(|a, b| {
        matches!(a.0, NodeId::Local(..)) && matches!(b.0, NodeId::Local(..))
            && a.1.addr == b.1.addr && a.1.name == b.1.name
    });

    let mut lines = Vec::new();
    let mut last_cl: u64 = u64::MAX;
    let insn = world.insn_counter;

    for (nid, node) in &sorted {
        if matches!(nid, NodeId::Field(..)) { continue; }
        let cl = node.addr / 64;

        if cl != last_cl {
            let fs = world.cl_tracker.contention_score(node.addr);
            let mut spans: Vec<Span<'static>> = vec![
                Span::styled(format!("  ── CL 0x{:x} ──", cl * 64), Style::default().fg(Color::DarkGray)),
            ];
            if fs > 1 {
                spans.push(Span::styled(
                    format!("  FALSE_SHARE T={}", fs),
                    Style::default().fg(Color::White).bg(Color::Red).bold(),
                ));
            }
            lines.push(MemLine { spans });
            last_cl = cl;
        }

        let val_color = recency_color(node.last_write_insn, insn);
        let is_local = matches!(nid, NodeId::Local(..));
        let name_style = if is_local {
            Style::default().fg(Color::Green).italic()
        } else {
            Style::default().fg(Color::White).bold()
        };

        let mut spans: Vec<Span<'static>> = vec![
            Span::styled(format!("  {:>12x}", node.addr), Style::default().fg(Color::DarkGray)),
            Span::raw(format!(" {:>3}B ", node.size)),
            Span::styled(format!("{:<18}", node.name), name_style),
            Span::styled(format!("{:<12}", node.type_info.name), Style::default().fg(type_color(&node.type_info.name))),
            Span::styled(format!(" 0x{:<16x}", node.raw_value), Style::default().fg(val_color)),
        ];

        if node.type_info.is_pointer && node.raw_value != 0 {
            let target = world.nodes.values()
                .find(|t| node.raw_value >= t.addr && node.raw_value < t.addr + t.size.max(1));
            match target {
                Some(t) => spans.push(Span::styled(format!(" → {}", t.name), Style::default().fg(Color::Magenta))),
                None => spans.push(Span::styled(format!(" → 0x{:x}", node.raw_value), Style::default().fg(Color::Magenta))),
            }
        }

        lines.push(MemLine { spans });

        // struct field sub-lines
        if let NodeId::Global(gi) = nid {
            for (fi, f) in node.type_info.fields.iter().enumerate() {
                if f.byte_size == 0 { continue; }
                let fa = node.addr + f.byte_offset;
                let fid = NodeId::Field(*gi, fi as u16);
                let fval = world.nodes.get(&fid).map(|n| n.raw_value).unwrap_or(0);
                let fwrite = world.nodes.get(&fid).map(|n| n.last_write_insn).unwrap_or(0);
                let fvc = recency_color(fwrite, insn);
                lines.push(MemLine { spans: vec![
                    Span::styled(format!("    {:>12x}", fa), Style::default().fg(Color::DarkGray)),
                    Span::raw(format!(" {:>3}B ", f.byte_size)),
                    Span::styled(format!("{:<18}", f.name), Style::default().fg(Color::DarkGray)),
                    Span::styled(format!("{:<12}", f.type_info.name), Style::default().fg(type_color(&f.type_info.name))),
                    Span::styled(format!(" 0x{:<16x}", fval), Style::default().fg(fvc)),
                ]});
            }
        }
    }
    lines
}

fn build_event_lines(journal: &VecDeque<JournalEntry>, filter: &EventFilter) -> Vec<Line<'static>> {
    journal.iter().filter(|e| filter.matches(e)).map(|e| {
        let (kind_str, kclr) = match e.kind {
            0 => ("W   ", Color::White),
            1 => ("R   ", Color::DarkGray),
            2 => ("CALL", Color::Blue),
            3 => ("RET ", Color::Blue),
            4 => ("OVF ", Color::Red),
            5 => ("REG ", Color::Cyan),
            6 => ("CMIS", Color::Magenta),
            7 => ("MLOAD", Color::Yellow),
            _ => ("?   ", Color::DarkGray),
        };
        Line::from(vec![
            Span::styled(format!("{:>8} ", e.seq), Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{} ", kind_str), Style::default().fg(kclr)),
            Span::styled(format!("T{:<2} ", e.thread_id), Style::default().fg(Color::Cyan)),
            Span::styled(format!("{:>12x} ", e.addr), Style::default().fg(Color::White)),
            Span::styled(format!("{:>4} ", e.size), Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{:>16x}", e.value), Style::default().fg(Color::White)),
        ])
    }).collect()
}

pub fn draw(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    world: &WorldInner,
    journal: &VecDeque<JournalEntry>,
    total: u64,
    ring_count: usize,
    fill_used: u64,
    fill_pct: u32,
    state: &mut AppState,
    snap_total: usize,
    stacks: &HashMap<u16, ShadowStack>,
) {
    state.snap_count = snap_total;
    let mem_lines = build_mem_lines(world);
    let evt_lines = build_event_lines(journal, &state.filter);

    // clamp scrolls
    state.mem_scroll = state.mem_scroll.min(mem_lines.len().saturating_sub(1));
    state.evt_scroll = state.evt_scroll.min(evt_lines.len().saturating_sub(1));

    let _ = terminal.draw(|f| {
        let size = f.area();

        // main layout: header, body, footer
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // header
                Constraint::Min(10),    // body
                Constraint::Length(1),  // footer
            ])
            .split(size);

        // header
        let fill_color = if fill_pct > 85 { Color::Red } else if fill_pct > 50 { Color::Yellow } else { Color::Green };
        let time_indicator = match state.time_travel_idx {
            Some(idx) => format!(" ◀ {}/{}", idx + 1, snap_total),
            None => String::new(),
        };
        let pause_indicator = if state.paused && state.time_travel_idx.is_none() { " ⏸ PAUSED" } else { "" };
        let header = Paragraph::new(Line::from(vec![
            Span::styled("MEMVIS", Style::default().fg(Color::Cyan).bold()),
            Span::raw(format!(" │ insn {} │ events {} │ nodes {} │ edges {} │ rings {} │ fill ",
                world.insn_counter, total, world.nodes.len(), world.edges.len(), ring_count)),
            Span::styled(format!("{}%", fill_pct), Style::default().fg(fill_color)),
            Span::raw(format!(" ({}) ", fill_used)),
            Span::styled(time_indicator.clone(), Style::default().fg(Color::Magenta).bold()),
            Span::styled(pause_indicator.to_string(), Style::default().fg(Color::Yellow).bold()),
        ]))
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)));
        f.render_widget(header, chunks[0]);

        // body: left (memory + events) and right (regs + edges)
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(65),
                Constraint::Percentage(35),
            ])
            .split(chunks[1]);

        // left: memory map (top) and events (bottom)
        let left = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(55),
                Constraint::Percentage(45),
            ])
            .split(body[0]);

        // memory map panel
        let mem_border_style = if state.focus == Panel::Memory {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let mem_items: Vec<Line> = mem_lines.iter().map(|ml| Line::from(ml.spans.clone())).collect();
        let mem_widget = Paragraph::new(mem_items)
            .block(Block::default()
                .title(" Memory Map ")
                .title_style(Style::default().fg(Color::White).bold())
                .borders(Borders::ALL)
                .border_style(mem_border_style))
            .scroll((state.mem_scroll as u16, 0));
        f.render_widget(mem_widget, left[0]);

        // events panel
        let evt_border_style = if state.focus == Panel::Events {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        // auto-scroll to bottom unless user has scrolled
        let evt_area_h = left[1].height.saturating_sub(2) as usize;
        if state.focus != Panel::Events && evt_lines.len() > evt_area_h {
            state.evt_scroll = evt_lines.len().saturating_sub(evt_area_h);
        }
        let mut filter_parts: Vec<String> = Vec::new();
        if state.filter.writes_only { filter_parts.push("W only".into()); }
        if state.filter.hide_reads { filter_parts.push("no R".into()); }
        if let Some(tid) = state.filter.thread_id { filter_parts.push(format!("T{}", tid)); }
        let evt_title = if filter_parts.is_empty() {
            " Events ".to_string()
        } else {
            format!(" Events [{}] ", filter_parts.join(", "))
        };
        let evt_widget = Paragraph::new(evt_lines.clone())
            .block(Block::default()
                .title(evt_title)
                .title_style(Style::default().fg(if state.filter.is_active() { Color::Yellow } else { Color::White }).bold())
                .borders(Borders::ALL)
                .border_style(evt_border_style))
            .scroll((state.evt_scroll as u16, 0));
        f.render_widget(evt_widget, left[1]);

        // right: registers, call stacks, pointer edges
        let right = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(40),
                Constraint::Percentage(30),
                Constraint::Percentage(30),
            ])
            .split(body[1]);

        // registers panel
        let reg_border_style = if state.focus == Panel::Registers {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let reg_file = &world.reg_file;
        let mut reg_lines: Vec<Line> = Vec::new();
        for chunk in (0..REG_COUNT).collect::<Vec<_>>().chunks(3) {
            let mut spans: Vec<Span<'static>> = Vec::new();
            for &i in chunk {
                if i >= REG_NAMES.len() { break; }
                let val = reg_file.values[i];
                let changed = val != reg_file.prev[i];
                let matches_addr = val != 0 && world.nodes.values()
                    .any(|n| val >= n.addr && val < n.addr + n.size.max(1));
                let vclr = if matches_addr { Color::Yellow }
                    else if changed { Color::White }
                    else { Color::DarkGray };
                let nclr = if matches_addr { Color::Yellow } else { Color::Cyan };
                spans.push(Span::styled(format!("{:>4}", REG_NAMES[i]), Style::default().fg(nclr)));
                spans.push(Span::raw("="));
                spans.push(Span::styled(format!("{:>16x} ", val), Style::default().fg(vclr)));
            }
            reg_lines.push(Line::from(spans));
        }
        let reg_widget = Paragraph::new(reg_lines)
            .block(Block::default()
                .title(format!(" Registers (insn {}) ", reg_file.insn))
                .title_style(Style::default().fg(Color::White).bold())
                .borders(Borders::ALL)
                .border_style(reg_border_style));
        f.render_widget(reg_widget, right[0]);

        // call stack panel
        let mut stack_lines: Vec<Line> = Vec::new();
        let mut sorted_tids: Vec<u16> = stacks.keys().copied().collect();
        sorted_tids.sort();
        for tid in &sorted_tids {
            let stack = &stacks[tid];
            if stack.frames.is_empty() && stack.max_depth == 0 { continue; }
            let depth_str = if stack.frames.is_empty() {
                format!("T{} (idle, max={})", tid, stack.max_depth)
            } else {
                format!("T{} depth={}", tid, stack.frames.len())
            };
            stack_lines.push(Line::from(vec![
                Span::styled(format!("  {}", depth_str), Style::default().fg(Color::Cyan)),
            ]));
            // show top 4 frames (newest first)
            let start = stack.frames.len().saturating_sub(4);
            for fi in (start..stack.frames.len()).rev() {
                let f = &stack.frames[fi];
                let indent = if fi == stack.frames.len() - 1 { "  → " } else { "    " };
                stack_lines.push(Line::from(vec![
                    Span::styled(indent.to_string(), Style::default().fg(Color::Magenta)),
                    Span::styled(f.name.clone(), Style::default().fg(Color::White)),
                ]));
            }
        }
        let stack_widget = Paragraph::new(stack_lines)
            .block(Block::default()
                .title(" Call Stacks ")
                .title_style(Style::default().fg(Color::White).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)));
        f.render_widget(stack_widget, right[1]);

        // pointer edges panel
        let mut edge_lines: Vec<Line> = Vec::new();
        let mut seen: HashSet<(String, u64)> = HashSet::new();
        for (src, edge) in &world.edges {
            let src_name = world.nodes.get(src).map(|n| n.name.clone()).unwrap_or_default();
            let key = (src_name.clone(), edge.ptr_value);
            if !seen.insert(key) { continue; }
            let tgt_name = world.nodes.get(&edge.target).map(|n| n.name.as_str()).unwrap_or("?");
            let mut spans = vec![
                Span::styled(format!("  {}", src_name), Style::default().fg(Color::Cyan)),
                Span::styled(" ──> ", Style::default().fg(Color::Magenta)),
                Span::styled(tgt_name.to_string(), Style::default().fg(Color::Cyan)),
                Span::styled(format!(" (0x{:x})", edge.ptr_value), Style::default().fg(Color::DarkGray)),
            ];
            if edge.is_dangling {
                spans.push(Span::styled(" DANGLING", Style::default().fg(Color::White).bg(Color::Red)));
            }
            edge_lines.push(Line::from(spans));
        }
        let edge_widget = Paragraph::new(edge_lines)
            .block(Block::default()
                .title(" Pointer Edges ")
                .title_style(Style::default().fg(Color::White).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)));
        f.render_widget(edge_widget, right[2]);

        // footer
        let footer = Paragraph::new(Line::from(vec![
            Span::styled(" q", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" quit  "),
            Span::styled("Tab", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" focus  "),
            Span::styled("↑↓/jk", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" scroll  "),
            Span::styled("Space", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" pause  "),
            Span::styled("PgUp/PgDn", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" page  "),
            Span::styled("←→/hl", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" time-travel  "),
            Span::styled("End", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" live"),
        ]));
        f.render_widget(footer, chunks[2]);
    });
}
