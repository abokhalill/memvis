// SPDX-License-Identifier: Apache-2.0
// ratatui interactive TUI for memvis

use std::collections::{HashMap, VecDeque};
use std::io;

use crossterm::event::{self, Event as CEvent, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::prelude::*;
use ratatui::widgets::*;

use crate::heap_graph::HeapGraph;
use crate::index::NodeId;
use crate::shadow_regs::{Confidence, ShadowRegisterFile};
use crate::world::{CacheLineTracker, ShadowTypeMap, ShadowStack, WorldInner, REG_COUNT, REG_NAMES};

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
pub enum Panel {
    Memory,
    Events,
    Registers,
}

#[derive(Default)]
pub struct EventFilter {
    pub thread_id: Option<u16>, // None = all threads
    pub hide_reads: bool,
    pub writes_only: bool,
}

impl EventFilter {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn is_active(&self) -> bool {
        self.thread_id.is_some() || self.hide_reads || self.writes_only
    }
    pub fn matches(&self, entry: &JournalEntry) -> bool {
        if let Some(tid) = self.thread_id {
            if entry.thread_id != tid {
                return false;
            }
        }
        if self.writes_only && entry.kind != 0 {
            return false;
        }
        if self.hide_reads && entry.kind == 1 {
            return false;
        }
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
    pub search_mode: bool,
    pub search_query: String,
    pub search_matches: Vec<usize>,
    pub search_idx: usize,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            mem_scroll: 0,
            evt_scroll: 0,
            focus: Panel::Memory,
            quit: false,
            paused: false,
            time_travel_idx: None,
            snap_count: 0,
            filter: EventFilter::default(),
            search_mode: false,
            search_query: String::new(),
            search_matches: Vec::new(),
            search_idx: 0,
        }
    }
}

impl AppState {
    pub fn new() -> Self {
        Self::default()
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
            // search mode: capture query input
            if state.search_mode {
                match key.code {
                    KeyCode::Esc => {
                        state.search_mode = false;
                        state.search_query.clear();
                        state.search_matches.clear();
                    }
                    KeyCode::Enter => {
                        state.search_mode = false;
                        // jump to first match
                        if let Some(&line) = state.search_matches.first() {
                            state.mem_scroll = line;
                            state.search_idx = 0;
                            state.focus = Panel::Memory;
                        }
                    }
                    KeyCode::Backspace => {
                        state.search_query.pop();
                    }
                    KeyCode::Char(c) => {
                        state.search_query.push(c);
                    }
                    _ => {}
                }
                continue;
            }
            match key.code {
                KeyCode::Char('q') => state.quit = true,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    state.quit = true
                }
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
                            if idx > 0 {
                                state.time_travel_idx = Some(idx - 1);
                            }
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
                    if let Some(idx) = state.time_travel_idx {
                        if idx >= max {
                            state.time_travel_idx = None; // back to live
                        } else {
                            state.time_travel_idx = Some(idx + 1);
                        }
                    }
                }
                KeyCode::End => {
                    state.time_travel_idx = None; // jump to live
                }
                KeyCode::Up | KeyCode::Char('k') => match state.focus {
                    Panel::Memory => state.mem_scroll = state.mem_scroll.saturating_sub(1),
                    Panel::Events => state.evt_scroll = state.evt_scroll.saturating_sub(1),
                    _ => {}
                },
                KeyCode::Down | KeyCode::Char('j') => match state.focus {
                    Panel::Memory => state.mem_scroll += 1,
                    Panel::Events => state.evt_scroll += 1,
                    _ => {}
                },
                KeyCode::PageUp => match state.focus {
                    Panel::Memory => state.mem_scroll = state.mem_scroll.saturating_sub(20),
                    Panel::Events => state.evt_scroll = state.evt_scroll.saturating_sub(20),
                    _ => {}
                },
                KeyCode::PageDown => match state.focus {
                    Panel::Memory => state.mem_scroll += 20,
                    Panel::Events => state.evt_scroll += 20,
                    _ => {}
                },
                KeyCode::Home => match state.focus {
                    Panel::Memory => state.mem_scroll = 0,
                    Panel::Events => state.evt_scroll = 0,
                    _ => {}
                },
                // event filters (only when events panel focused)
                KeyCode::Char('w') if state.focus == Panel::Events => {
                    state.filter.writes_only = !state.filter.writes_only;
                    if state.filter.writes_only {
                        state.filter.hide_reads = false;
                    }
                }
                KeyCode::Char('r') if state.focus == Panel::Events => {
                    state.filter.hide_reads = !state.filter.hide_reads;
                    if state.filter.hide_reads {
                        state.filter.writes_only = false;
                    }
                }
                KeyCode::Char(c @ '0'..='9') if state.focus == Panel::Events => {
                    let tid = (c as u16) - ('0' as u16);
                    state.filter.thread_id = if state.filter.thread_id == Some(tid) {
                        None
                    } else {
                        Some(tid)
                    };
                }
                KeyCode::Char('x') if state.focus == Panel::Events => {
                    state.filter = EventFilter::new();
                }
                KeyCode::Char('/') => {
                    state.search_mode = true;
                    state.search_query.clear();
                    state.search_matches.clear();
                    state.search_idx = 0;
                }
                KeyCode::Char('n') if !state.search_matches.is_empty() => {
                    state.search_idx = (state.search_idx + 1) % state.search_matches.len();
                    state.mem_scroll = state.search_matches[state.search_idx];
                    state.focus = Panel::Memory;
                }
                KeyCode::Char('N') if !state.search_matches.is_empty() => {
                    state.search_idx = if state.search_idx == 0 {
                        state.search_matches.len() - 1
                    } else {
                        state.search_idx - 1
                    };
                    state.mem_scroll = state.search_matches[state.search_idx];
                    state.focus = Panel::Memory;
                }
                _ => {}
            }
        }
    }
}

fn type_color(t: &str) -> Color {
    let l = t.to_ascii_lowercase();
    if l.starts_with('*') || l.contains("ptr") {
        return Color::Magenta;
    }
    if l.contains("char") {
        return Color::Green;
    }
    if l.contains("float") || l.contains("double") {
        return Color::Yellow;
    }
    if l.contains("int") || l.contains("long") || l.contains("short") {
        return Color::Blue;
    }
    if l.contains("struct") || l.contains("vec") || l.contains("entity") {
        return Color::Cyan;
    }
    Color::White
}

fn recency_color(last_write: u64, current_insn: u64) -> Color {
    if last_write == 0 {
        return Color::DarkGray;
    }
    let age = current_insn.saturating_sub(last_write);
    if age < 100 {
        Color::Red
    } else if age < 1000 {
        Color::Yellow
    } else if age < 10000 {
        Color::White
    } else {
        Color::DarkGray
    }
}

struct MemLine {
    spans: Vec<Span<'static>>,
}

fn resolve_ptr_target<'a>(val: u64, addr_names: &'a HashMap<u64, (String, u64)>) -> Option<&'a str> {
    if val == 0 { return None; }
    if let Some((name, _)) = addr_names.get(&val) {
        return Some(name.as_str());
    }
    None
}

fn build_mem_lines(world: &WorldInner, cl_tracker: &CacheLineTracker, stm: &ShadowTypeMap) -> Vec<MemLine> {
    let mut sorted: Vec<_> = world.nodes.iter().filter(|(_, n)| n.size > 0).collect();
    sorted.sort_by_key(|(_, n)| (n.addr, std::cmp::Reverse(n.last_write_insn)));
    sorted.dedup_by(|a, b| {
        matches!(a.0, NodeId::Local(..))
            && matches!(b.0, NodeId::Local(..))
            && a.1.addr == b.1.addr
            && a.1.name == b.1.name
    });

    // addr->(name, size) reverse index. fields first (lowest priority), then globals, then locals.
    // at the same address, parent struct overwrites its first field (offset-0 alias).
    let mut by_priority: Vec<_> = world.nodes.iter().collect();
    by_priority.sort_by_key(|(nid, _)| match nid {
        NodeId::Field(..) => 0u8,
        NodeId::Global(_) => 1,
        NodeId::Local(..) => 2,
    });
    let mut addr_names: HashMap<u64, (String, u64)> = HashMap::with_capacity(by_priority.len());
    for (_, node) in &by_priority {
        addr_names.insert(node.addr, (node.name.clone(), node.size));
    }

    let mut lines = Vec::new();
    let mut last_cl: u64 = u64::MAX;
    let insn = world.insn_counter;

    for (nid, node) in &sorted {
        if matches!(nid, NodeId::Field(..)) {
            continue;
        }
        let cl = node.addr / 64;

        if cl != last_cl {
            let fs = cl_tracker.contention_score(node.addr);
            let mut spans: Vec<Span<'static>> = vec![Span::styled(
                format!("  ── CL 0x{:x} ──", cl * 64),
                Style::default().fg(Color::DarkGray),
            )];
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
            Span::styled(
                format!("  {:>12x}", node.addr),
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw(format!(" {:>3}B ", node.size)),
            Span::styled(format!("{:<18}", node.name), name_style),
            Span::styled(
                format!("{:<12}", node.type_info.name),
                Style::default().fg(type_color(&node.type_info.name)),
            ),
            Span::styled(
                format!(" 0x{:<16x}", node.raw_value),
                Style::default().fg(val_color),
            ),
        ];

        if node.type_info.is_pointer && node.raw_value != 0 {
            match resolve_ptr_target(node.raw_value, &addr_names) {
                Some(name) => spans.push(Span::styled(
                    format!(" → {}", name),
                    Style::default().fg(Color::Magenta),
                )),
                None => spans.push(Span::styled(
                    format!(" → 0x{:x}", node.raw_value),
                    Style::default().fg(Color::Magenta),
                )),
            }
        }

        lines.push(MemLine { spans });

        if let NodeId::Global(gi) = nid {
            if node.type_info.is_pointer { }
            else { for (fi, f) in node.type_info.fields.iter().enumerate() {
                if f.byte_size == 0 || f.name == "<pointee>" {
                    continue;
                }
                let fa = node.addr + f.byte_offset;
                let fid = NodeId::Field(*gi, fi as u16);
                let fval = world.nodes.get(&fid).map(|n| n.raw_value).unwrap_or(0);
                let fwrite = world
                    .nodes
                    .get(&fid)
                    .map(|n| n.last_write_insn)
                    .unwrap_or(0);
                let fvc = recency_color(fwrite, insn);
                lines.push(MemLine {
                    spans: vec![
                        Span::styled(
                            format!("    {:>12x}", fa),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::raw(format!(" {:>3}B ", f.byte_size)),
                        Span::styled(
                            format!("{:<18}", f.name),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(
                            format!("{:<12}", f.type_info.name),
                            Style::default().fg(type_color(&f.type_info.name)),
                        ),
                        Span::styled(format!(" 0x{:<16x}", fval), Style::default().fg(fvc)),
                    ],
                });
                if f.type_info.is_pointer && fval != 0 {
                    if let Some(tname) = resolve_ptr_target(fval, &addr_names) {
                        let last = lines.last_mut().unwrap();
                        last.spans.push(Span::styled(
                            format!(" → {}", tname),
                            Style::default().fg(Color::Magenta),
                        ));
                    } else {
                        let last = lines.last_mut().unwrap();
                        last.spans.push(Span::styled(
                            format!(" → 0x{:x}", fval),
                            Style::default().fg(Color::Magenta),
                        ));
                    }
                }
            }
        } }
    }
    if stm.len() > 0 {
        lines.push(MemLine {
            spans: vec![Span::styled(
                format!("  ── HEAP TYPES ({} projections) ──", stm.len()),
                Style::default().fg(Color::Yellow).bold(),
            )],
        });
        let mut stm_sorted: Vec<_> = stm.iter().collect();
        stm_sorted.sort_by_key(|(addr, _)| *addr);
        for (&base, proj) in &stm_sorted {
            lines.push(MemLine {
                spans: vec![
                    Span::styled(
                        format!("  {:>12x}", base),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw(format!(" {:>3}B ", proj.type_info.byte_size)),
                    Span::styled(
                        format!("{:<18}", proj.type_info.name),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::styled(
                        format!("via {}", proj.source_name),
                        Style::default().fg(Color::DarkGray).italic(),
                    ),
                ],
            });
            for f in &proj.type_info.fields {
                if f.byte_size == 0 || f.name == "<pointee>" { continue; }
                let fa = base + f.byte_offset;
                let mut fspans = vec![
                    Span::styled(
                        format!("    {:>12x}", fa),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw(format!(" {:>3}B ", f.byte_size)),
                    Span::styled(
                        format!("{:<18}", f.name),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("{:<12}", f.type_info.name),
                        Style::default().fg(type_color(&f.type_info.name)),
                    ),
                ];
                if f.type_info.is_pointer {
                    if let Some(tgt) = stm.lookup(fa) {
                        fspans.push(Span::styled(
                            format!(" → {} (0x{:x})", tgt.type_info.name, tgt.base_addr),
                            Style::default().fg(Color::Magenta),
                        ));
                    }
                }
                lines.push(MemLine { spans: fspans });
            }
        }
    }

    lines
}

fn build_event_lines(journal: &VecDeque<JournalEntry>, filter: &EventFilter) -> Vec<Line<'static>> {
    journal
        .iter()
        .filter(|e| filter.matches(e))
        .map(|e| {
            let (kind_str, kclr) = match e.kind {
                0 => ("W   ", Color::White),
                1 => ("R   ", Color::DarkGray),
                2 => ("CALL", Color::Blue),
                3 => ("RET ", Color::Blue),
                4 => ("OVF ", Color::Red),
                5 => ("REG ", Color::Cyan),
                6 => ("CMIS", Color::Magenta),
                7 => ("MLOAD", Color::Yellow),
                8 => ("TCAL", Color::Blue),
                12 => ("RLOD", Color::Green),
                _ => ("?   ", Color::DarkGray),
            };
            Line::from(vec![
                Span::styled(
                    format!("{:>8} ", e.seq),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(format!("{} ", kind_str), Style::default().fg(kclr)),
                Span::styled(
                    format!("T{:<2} ", e.thread_id),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(
                    format!("{:>12x} ", e.addr),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!("{:>4} ", e.size),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("{:>16x}", e.value),
                    Style::default().fg(Color::White),
                ),
            ])
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn draw(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    world: &WorldInner,
    cl_tracker: &CacheLineTracker,
    stm: &ShadowTypeMap,
    journal: &VecDeque<JournalEntry>,
    total: u64,
    ring_count: usize,
    fill_used: u64,
    _fill_pct: u32,
    state: &mut AppState,
    snap_total: usize,
    stacks: &HashMap<u16, ShadowStack>,
    seq_gaps: u64,
    shadow_regs: &HashMap<u16, ShadowRegisterFile>,
    heap_graph: &HeapGraph,
) {
    state.snap_count = snap_total;
    let mem_lines = build_mem_lines(world, cl_tracker, stm);
    let seq_gap_warn = seq_gaps; // capture for header
    let evt_lines = build_event_lines(journal, &state.filter);

    // live search: recompute matches from mem_lines text
    if !state.search_query.is_empty() {
        let q = state.search_query.to_ascii_lowercase();
        state.search_matches = mem_lines
            .iter()
            .enumerate()
            .filter(|(_, ml)| {
                let text: String = ml.spans.iter().map(|s| s.content.as_ref()).collect();
                text.to_ascii_lowercase().contains(&q)
            })
            .map(|(i, _)| i)
            .collect();
        if state.search_idx >= state.search_matches.len() {
            state.search_idx = 0;
        }
        // auto-scroll to current match while typing
        if state.search_mode {
            if let Some(&line) = state.search_matches.get(state.search_idx) {
                state.mem_scroll = line;
            }
        }
    } else {
        state.search_matches.clear();
    }

    // clamp scrolls
    state.mem_scroll = state.mem_scroll.min(mem_lines.len().saturating_sub(1));
    state.evt_scroll = state.evt_scroll.min(evt_lines.len().saturating_sub(1));

    let _ = terminal.draw(|f| {
        let size = f.area();

        // main layout: header, body, footer
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // header
                Constraint::Min(10),   // body
                Constraint::Length(1), // footer
            ])
            .split(size);

        // header
        let lag_color = if fill_used > 50_000 {
            Color::Red
        } else if fill_used > 1_000 {
            Color::Yellow
        } else {
            Color::Green
        };
        let lag_str = if fill_used >= 1_000_000 {
            format!("{}M", fill_used / 1_000_000)
        } else if fill_used >= 1_000 {
            format!("{}K", fill_used / 1_000)
        } else {
            format!("{}", fill_used)
        };
        let time_indicator = match state.time_travel_idx {
            Some(idx) => format!(" ◀ {}/{}", idx + 1, snap_total),
            None => String::new(),
        };
        let pause_indicator = if state.paused && state.time_travel_idx.is_none() {
            " ⏸ PAUSED"
        } else {
            ""
        };
        let header = Paragraph::new(Line::from(vec![
            Span::styled("MEMVIS", Style::default().fg(Color::Cyan).bold()),
            Span::raw(format!(
                " │ insn {} │ events {} │ nodes {} │ edges {} │ rings {} │ ",
                world.insn_counter,
                total,
                world.nodes.len(),
                world.edges.len(),
                ring_count
            )),
            Span::styled(
                format!("LAG {}", lag_str),
                Style::default().fg(lag_color).bold(),
            ),
            Span::styled(
                time_indicator.clone(),
                Style::default().fg(Color::Magenta).bold(),
            ),
            Span::styled(
                pause_indicator.to_string(),
                Style::default().fg(Color::Yellow).bold(),
            ),
            if seq_gap_warn > 0 {
                Span::styled(
                    format!(" GAPS:{}", seq_gap_warn),
                    Style::default().fg(Color::Red).bold(),
                )
            } else {
                Span::raw("")
            },
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(header, chunks[0]);

        // body: left (memory + events) and right (regs + edges)
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
            .split(chunks[1]);

        // left: memory map (top) and events (bottom)
        let left = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(body[0]);

        // memory map panel
        let mem_border_style = if state.focus == Panel::Memory {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let current_match_line = state.search_matches.get(state.search_idx).copied();
        let mem_items: Vec<Line> = mem_lines
            .iter()
            .enumerate()
            .map(|(i, ml)| {
                if Some(i) == current_match_line {
                    // current match: bright highlight
                    let styled: Vec<Span> = ml.spans.iter().map(|s| {
                        Span::styled(s.content.clone(), s.style.bg(Color::DarkGray))
                    }).collect();
                    Line::from(styled)
                } else if state.search_matches.contains(&i) {
                    // other matches: subtle highlight
                    let styled: Vec<Span> = ml.spans.iter().map(|s| {
                        Span::styled(s.content.clone(), s.style.bg(Color::Rgb(40, 40, 40)))
                    }).collect();
                    Line::from(styled)
                } else {
                    Line::from(ml.spans.clone())
                }
            })
            .collect();
        let mem_title = if state.search_mode {
            format!(" Memory Map  /{}▏ ", state.search_query)
        } else if !state.search_matches.is_empty() {
            format!(" Memory Map  [{}/{}] ", state.search_idx + 1, state.search_matches.len())
        } else {
            " Memory Map ".to_string()
        };
        let mem_widget = Paragraph::new(mem_items)
            .block(
                Block::default()
                    .title(mem_title)
                    .title_style(Style::default().fg(if state.search_mode || !state.search_matches.is_empty() {
                        Color::Yellow
                    } else {
                        Color::White
                    }).bold())
                    .borders(Borders::ALL)
                    .border_style(mem_border_style),
            )
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
        if state.filter.writes_only {
            filter_parts.push("W only".into());
        }
        if state.filter.hide_reads {
            filter_parts.push("no R".into());
        }
        if let Some(tid) = state.filter.thread_id {
            filter_parts.push(format!("T{}", tid));
        }
        let evt_title = if filter_parts.is_empty() {
            " Events ".to_string()
        } else {
            format!(" Events [{}] ", filter_parts.join(", "))
        };
        let evt_widget = Paragraph::new(evt_lines.clone())
            .block(
                Block::default()
                    .title(evt_title)
                    .title_style(
                        Style::default()
                            .fg(if state.filter.is_active() {
                                Color::Yellow
                            } else {
                                Color::White
                            })
                            .bold(),
                    )
                    .borders(Borders::ALL)
                    .border_style(evt_border_style),
            )
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

        // registers panel: shadow register file with confidence
        let reg_border_style = if state.focus == Panel::Registers {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let mut reg_lines: Vec<Line> = Vec::new();
        // pick first active thread's SRF (or fall back to raw reg_file)
        let active_srf = shadow_regs.values().next();
        for (i, reg_name) in REG_NAMES.iter().enumerate().take(REG_COUNT) {
            let (val, conf, conf_label) = if let Some(srf) = active_srf {
                let sr = srf.reg(i);
                (sr.value, sr.confidence, sr.confidence.label())
            } else {
                (world.reg_file.values[i], Confidence::Unknown, "???")
            };
            let bar_filled = conf.bar_tenths() as usize;
            let bar_empty = 10 - bar_filled;
            let bar_str: String = "\u{2588}".repeat(bar_filled) + &"\u{2591}".repeat(bar_empty);
            let conf_color = match conf {
                Confidence::Observed => Color::Green,
                Confidence::AbiInferred => Color::Cyan,
                Confidence::WriteBack => Color::Yellow,
                Confidence::Speculative => Color::Magenta,
                Confidence::Stale => Color::Red,
                Confidence::Unknown => Color::DarkGray,
            };
            let matches_addr = val != 0
                && world
                    .nodes
                    .values()
                    .any(|n| val >= n.addr && val < n.addr + n.size.max(1));
            let vclr = if matches_addr {
                Color::Yellow
            } else if conf >= Confidence::WriteBack {
                Color::White
            } else {
                Color::DarkGray
            };
            reg_lines.push(Line::from(vec![
                Span::styled(
                    format!("{:>4}", reg_name),
                    Style::default().fg(if matches_addr {
                        Color::Yellow
                    } else {
                        Color::Cyan
                    }),
                ),
                Span::raw("="),
                Span::styled(format!("{:>16x} ", val), Style::default().fg(vclr)),
                Span::styled(bar_str, Style::default().fg(conf_color)),
                Span::styled(
                    format!(" {:<5}", conf_label),
                    Style::default().fg(conf_color),
                ),
                if conf.is_stale() {
                    Span::styled(
                        " !! ",
                        Style::default().fg(Color::White).bg(Color::Red).bold(),
                    )
                } else {
                    Span::raw("")
                },
            ]));
        }
        let srf_title = if active_srf.is_some() {
            " Shadow Registers ".to_string()
        } else {
            format!(" Registers (insn {}) ", world.reg_file.insn)
        };
        let reg_widget = Paragraph::new(reg_lines).block(
            Block::default()
                .title(srf_title)
                .title_style(Style::default().fg(Color::White).bold())
                .borders(Borders::ALL)
                .border_style(reg_border_style),
        );
        f.render_widget(reg_widget, right[0]);

        // call stack panel
        let mut stack_lines: Vec<Line> = Vec::new();
        let mut sorted_tids: Vec<u16> = stacks.keys().copied().collect();
        sorted_tids.sort();
        for tid in &sorted_tids {
            let stack = &stacks[tid];
            if stack.frames.is_empty() && stack.max_depth == 0 {
                continue;
            }
            let depth_str = if stack.frames.is_empty() {
                format!("T{} (idle, max={})", tid, stack.max_depth)
            } else {
                format!("T{} depth={}", tid, stack.frames.len())
            };
            stack_lines.push(Line::from(vec![Span::styled(
                format!("  {}", depth_str),
                Style::default().fg(Color::Cyan),
            )]));
            // show top 4 frames (newest first)
            let start = stack.frames.len().saturating_sub(4);
            for fi in (start..stack.frames.len()).rev() {
                let f = &stack.frames[fi];
                let indent = if fi == stack.frames.len() - 1 {
                    "  → "
                } else {
                    "    "
                };
                stack_lines.push(Line::from(vec![
                    Span::styled(indent.to_string(), Style::default().fg(Color::Magenta)),
                    Span::styled(f.name.clone(), Style::default().fg(Color::White)),
                ]));
            }
        }
        let stack_widget = Paragraph::new(stack_lines).block(
            Block::default()
                .title(" Call Stacks ")
                .title_style(Style::default().fg(Color::White).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(stack_widget, right[1]);

        // heap objects panel
        let heap_objs = heap_graph.objects();
        let mut heap_lines: Vec<Line> = Vec::new();
        if heap_objs.is_empty() {
            heap_lines.push(Line::from(Span::styled(
                "  (no heap objects discovered)",
                Style::default().fg(Color::DarkGray),
            )));
        } else {
            heap_lines.push(Line::from(vec![
                Span::styled(
                    format!("  {} objects", heap_objs.len()),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(
                    format!("  {} edges", heap_graph.edge_count()),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
            // show up to 8 most recently written objects
            let mut sorted: Vec<_> = heap_objs.values().collect();
            sorted.sort_by(|a, b| b.last_seq.cmp(&a.last_seq));
            for obj in sorted.iter().take(8) {
                let type_str = obj.inferred_type.as_deref().unwrap_or("?");
                let conf_pct = (obj.type_confidence * 100.0) as u32;
                let conf_color = if conf_pct >= 80 {
                    Color::Green
                } else if conf_pct >= 50 {
                    Color::Yellow
                } else {
                    Color::DarkGray
                };
                heap_lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {:>12x}", obj.base_addr),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!(" {:>4}B", obj.inferred_size),
                        Style::default().fg(Color::White),
                    ),
                    Span::styled(
                        format!(" {:<16}", type_str),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(format!(" {}%", conf_pct), Style::default().fg(conf_color)),
                    Span::styled(
                        format!(" {}F", obj.fields.len()),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!(" {}E", obj.outgoing_edges.len()),
                        Style::default().fg(Color::Magenta),
                    ),
                ]));
            }
        }
        let heap_widget = Paragraph::new(heap_lines).block(
            Block::default()
                .title(" Heap Objects ")
                .title_style(Style::default().fg(Color::White).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(heap_widget, right[2]);

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
            Span::raw(" live  "),
            Span::styled("/", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" search  "),
            Span::styled("n/N", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" next/prev"),
        ]));
        f.render_widget(footer, chunks[2]);
    });
}
