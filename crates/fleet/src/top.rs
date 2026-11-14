// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ebpf-fleet top`: a small live/bundle TUI over process and file events.
//!
//! Bundle mode loads every event once so filters can be re-applied locally;
//! live mode counts events as they arrive (filters apply from the moment
//! they are set and reset the current view). Keys:
//!
//! `space` pause, `s` cycle sort, `p`/`f`/`k` filter by process/path/kind,
//! `x` clear filters, `w` save a JSON snapshot, `q`/`esc` quit.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::event::{self, Event as TermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use event_model::{Event, Stack};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Terminal;
use serde::Serialize;

use crate::Bundle;

const RECENT_LIMIT: usize = 12;
const TABLE_LIMIT: usize = 12;

/// Table ordering cycled by `s`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SortMode {
    /// Largest count first, then name.
    #[default]
    CountDesc,
    /// Name ascending, then count.
    NameAsc,
}

impl SortMode {
    fn label(self) -> &'static str {
        match self {
            Self::CountDesc => "count",
            Self::NameAsc => "name",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::CountDesc => Self::NameAsc,
            Self::NameAsc => Self::CountDesc,
        }
    }
}

/// Case-insensitive substring filters over one event kind/process/path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
struct Filters {
    #[serde(skip_serializing_if = "Option::is_none")]
    process: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
}

impl Filters {
    fn is_empty(&self) -> bool {
        self.process.is_none() && self.path.is_none() && self.kind.is_none()
    }

    fn matches(&self, event: &Event) -> bool {
        let process = event
            .process_exec
            .as_deref()
            .or(event.path.as_deref())
            .unwrap_or("");
        let path = event.path.as_deref().unwrap_or("");
        self.process
            .as_deref()
            .map(|needle| contains_ci(process, needle))
            .unwrap_or(true)
            && self
                .path
                .as_deref()
                .map(|needle| contains_ci(path, needle))
                .unwrap_or(true)
            && self
                .kind
                .as_deref()
                .map(|needle| contains_ci(&event.kind, needle))
                .unwrap_or(true)
    }

    fn describe(&self) -> String {
        if self.is_empty() {
            return "none".to_string();
        }
        let mut parts = Vec::new();
        if let Some(value) = &self.process {
            parts.push(format!("process~{value}"));
        }
        if let Some(value) = &self.path {
            parts.push(format!("path~{value}"));
        }
        if let Some(value) = &self.kind {
            parts.push(format!("kind~{value}"));
        }
        parts.join(" ")
    }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// Which filter a key prompt is currently editing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptField {
    Process,
    Path,
    Kind,
}

impl PromptField {
    fn label(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Path => "path",
            Self::Kind => "kind",
        }
    }
}

#[derive(Debug, Default)]
struct Counters {
    total: u64,
    decode_errors: u64,
    by_kind: BTreeMap<String, u64>,
    processes: BTreeMap<String, u64>,
    paths: BTreeMap<String, u64>,
    recent: VecDeque<String>,
    /// Resolved stacks in the bundle.
    stack_total: u64,
    /// Frames across all resolved stacks.
    stack_frames: u64,
    /// Frames that kept a raw address but no symbol.
    stack_missing_symbols: u64,
    /// Events that carry a `stack_id` (capture was enabled for them).
    events_with_stacks: u64,
    /// Top stack labels (innermost resolved symbol, else raw address).
    stacks: BTreeMap<String, u64>,
}

impl Counters {
    /// Reset only the event-derived counters (stack panes keep their data).
    fn reset_events(&mut self) {
        self.total = 0;
        self.decode_errors = 0;
        self.by_kind.clear();
        self.processes.clear();
        self.paths.clear();
        self.recent.clear();
        self.events_with_stacks = 0;
    }

    fn observe_events(&mut self, events: &[Event], filters: &Filters) {
        self.reset_events();
        for event in events {
            if filters.matches(event) {
                self.observe(event);
            }
        }
    }

    /// Fold one resolved stack into the counters. Called by bundle mode
    /// when `top` loads a bundle's `stacks` table.
    fn observe_stack(&mut self, stack: &Stack) {
        self.stack_total += 1;
        self.stack_frames += stack.frames.len() as u64;
        for frame in &stack.frames {
            if frame.symbol.is_none() {
                self.stack_missing_symbols += 1;
            }
        }
        let label = stack
            .frames
            .iter()
            .find_map(|frame| frame.symbol.clone())
            .unwrap_or_else(|| {
                stack
                    .frames
                    .first()
                    .map(|frame| format!("{:#x}", frame.addr))
                    .unwrap_or_else(|| "empty".to_string())
            });
        *self.stacks.entry(label).or_default() += 1;
    }

    fn observe(&mut self, event: &Event) {
        self.total += 1;
        if event.stack_id.is_some() {
            self.events_with_stacks += 1;
        }
        *self.by_kind.entry(event.kind.clone()).or_default() += 1;
        let process = event
            .process_exec
            .clone()
            .or_else(|| event.path.clone())
            .unwrap_or_else(|| "?".to_string());
        *self.processes.entry(process).or_default() += 1;
        if event.sensor == "file" {
            if let Some(path) = &event.path {
                *self.paths.entry(path.clone()).or_default() += 1;
            }
        }
        let detail = event
            .path
            .clone()
            .or_else(|| event.process_exec.clone())
            .unwrap_or_default();
        self.recent.push_front(format!("{} {}", event.kind, detail));
        while self.recent.len() > RECENT_LIMIT {
            self.recent.pop_back();
        }
    }

    fn top(map: &BTreeMap<String, u64>, sort: SortMode) -> Vec<(String, u64)> {
        let mut values: Vec<_> = map
            .iter()
            .map(|(key, value)| (key.clone(), *value))
            .collect();
        match sort {
            SortMode::CountDesc => {
                values
                    .sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
            }
            SortMode::NameAsc => {
                values
                    .sort_by(|left, right| left.0.cmp(&right.0).then_with(|| right.1.cmp(&left.1)));
            }
        }
        values.truncate(TABLE_LIMIT);
        values
    }
}

/// TUI state shared by bundle and live views.
#[derive(Debug, Default)]
struct Model {
    counters: Counters,
    filters: Filters,
    sort: SortMode,
    paused: bool,
    prompt: Option<(PromptField, String)>,
    status: Option<String>,
    title: String,
}

impl Model {
    fn new(title: String) -> Self {
        Self {
            title,
            ..Self::default()
        }
    }

    fn apply_prompt(&mut self) {
        if let Some((field, value)) = self.prompt.take() {
            let value = value.trim().to_string();
            let slot = match field {
                PromptField::Process => &mut self.filters.process,
                PromptField::Path => &mut self.filters.path,
                PromptField::Kind => &mut self.filters.kind,
            };
            *slot = (!value.is_empty()).then_some(value);
            self.status = Some(format!("filter: {}", self.filters.describe()));
        }
    }

    /// Serialize the current view to `top-snapshot-<epoch>.json` in the
    /// current directory. Returns the path written.
    fn save_snapshot(&self) -> io::Result<PathBuf> {
        #[derive(Serialize)]
        struct Snapshot<'a> {
            generated_at: u64,
            title: &'a str,
            sort: SortMode,
            paused: bool,
            filters: &'a Filters,
            events: u64,
            decode_errors: u64,
            stacks: u64,
            stack_frames: u64,
            stack_missing_symbols: u64,
            events_with_stacks: u64,
            top_processes: Vec<(String, u64)>,
            top_paths: Vec<(String, u64)>,
            top_stacks: Vec<(String, u64)>,
            event_kinds: BTreeMap<String, u64>,
        }
        let names = |map: &BTreeMap<String, u64>| -> Vec<(String, u64)> {
            Counters::top(map, SortMode::CountDesc)
        };
        let generated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let snapshot = Snapshot {
            generated_at,
            title: &self.title,
            sort: self.sort,
            paused: self.paused,
            filters: &self.filters,
            events: self.counters.total,
            decode_errors: self.counters.decode_errors,
            stacks: self.counters.stack_total,
            stack_frames: self.counters.stack_frames,
            stack_missing_symbols: self.counters.stack_missing_symbols,
            events_with_stacks: self.counters.events_with_stacks,
            top_processes: names(&self.counters.processes),
            top_paths: names(&self.counters.paths),
            top_stacks: names(&self.counters.stacks),
            event_kinds: self.counters.by_kind.clone(),
        };
        let path = PathBuf::from(format!("top-snapshot-{generated_at}.json"));
        let file = std::fs::File::create(&path)?;
        serde_json::to_writer_pretty(file, &snapshot)?;
        Ok(path)
    }

    /// Handle one key. `events` is `Some` in bundle mode (so filter changes
    /// can re-apply to already-loaded rows) and `None` in live mode (where
    /// a filter change resets the incremental view).
    fn handle_key(&mut self, key: KeyEvent, events: Option<&[Event]>) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }
        if let Some((_, value)) = self.prompt.as_mut() {
            match key.code {
                KeyCode::Enter => {
                    self.apply_prompt();
                    if let Some(events) = events {
                        self.counters.observe_events(events, &self.filters);
                    }
                }
                KeyCode::Esc => {
                    self.prompt = None;
                    self.status = Some("filter cancelled".to_string());
                }
                KeyCode::Backspace => {
                    value.pop();
                }
                KeyCode::Char(character) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    value.push(character);
                }
                _ => {}
            }
            return false;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
            KeyCode::Char(' ') => {
                self.paused = !self.paused;
                self.status = Some(if self.paused {
                    "paused".to_string()
                } else {
                    "resumed".to_string()
                });
                false
            }
            KeyCode::Char('s') => {
                self.sort = self.sort.next();
                self.status = Some(format!("sort: {}", self.sort.label()));
                false
            }
            KeyCode::Char('p') => {
                self.prompt = Some((PromptField::Process, String::new()));
                false
            }
            KeyCode::Char('f') => {
                self.prompt = Some((PromptField::Path, String::new()));
                false
            }
            KeyCode::Char('k') => {
                self.prompt = Some((PromptField::Kind, String::new()));
                false
            }
            KeyCode::Char('x') => {
                self.filters = Filters::default();
                if let Some(events) = events {
                    self.counters.observe_events(events, &self.filters);
                }
                self.status = Some("filters cleared".to_string());
                false
            }
            KeyCode::Char('w') => {
                self.status = Some(match self.save_snapshot() {
                    Ok(path) => format!("saved {}", path.display()),
                    Err(error) => format!("save failed: {error}"),
                });
                false
            }
            _ => false,
        }
    }
}

struct ScreenGuard;

impl ScreenGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for ScreenGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

pub async fn run(
    bundle: Option<PathBuf>,
    refresh_ms: u64,
    duration: Option<u64>,
) -> Result<(), String> {
    match bundle {
        Some(path) => run_bundle(path, refresh_ms).await,
        None => run_live(refresh_ms, duration),
    }
}

async fn run_bundle(path: PathBuf, refresh_ms: u64) -> Result<(), String> {
    let bundle = Bundle::open(&path).map_err(|error| error.to_string())?;
    let batches = bundle
        .query("select raw_json from events order by time_unix_ns, seq")
        .await
        .map_err(|error| error.to_string())?;
    let mut events = Vec::new();
    let mut decode_errors = 0u64;
    for batch in &batches {
        for row in 0..batch.num_rows() {
            let raw = arrow::util::display::array_value_to_string(batch.column(0).as_ref(), row)
                .map_err(|error| error.to_string())?;
            match serde_json::from_str::<Event>(&raw) {
                Ok(event) => events.push(event),
                Err(_) => decode_errors += 1,
            }
        }
    }

    let mut model = Model::new(format!("bundle {}", path.display()));
    model.counters.observe_events(&events, &model.filters);
    model.counters.decode_errors = decode_errors;
    for stack in bundle
        .read_stacks()
        .await
        .map_err(|error| error.to_string())?
    {
        model.counters.observe_stack(&stack);
    }

    if !io::stdout().is_terminal() {
        print_summary(&model.counters, &path);
        return Ok(());
    }

    let _guard = ScreenGuard::enter().map_err(|error| error.to_string())?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).map_err(|error| error.to_string())?;
    loop {
        terminal
            .draw(|frame| draw(frame, &model, 0.0))
            .map_err(|error| error.to_string())?;
        if event::poll(Duration::from_millis(refresh_ms.max(100)))
            .map_err(|error| error.to_string())?
        {
            if let TermEvent::Key(key) = event::read().map_err(|error| error.to_string())? {
                if model.handle_key(key, Some(&events)) {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn run_live(refresh_ms: u64, duration: Option<u64>) -> Result<(), String> {
    if !io::stdout().is_terminal() {
        return Err("live top needs a terminal; use `record` then `top <bundle>`".to_string());
    }

    let sensors = bpf_loader::load(&["process", "file"]).map_err(|error| error.to_string())?;
    if sensors.sensors.is_empty() {
        return Err("no sensor attached; run `ebpf-fleet doctor`".to_string());
    }
    let (ring, events) = sensors.ring_reader().map_err(|error| error.to_string())?;
    let clock = runtime::decode::Clock::new();
    let mut processes = runtime::process_table::ProcessTable::new();
    let mut model = Model::new("live".to_string());
    let mut last_draw = Instant::now();
    let mut last_total = 0u64;
    let deadline = duration.map(|seconds| Instant::now() + Duration::from_secs(seconds));

    let _guard = ScreenGuard::enter().map_err(|error| error.to_string())?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).map_err(|error| error.to_string())?;
    loop {
        if deadline
            .map(|deadline| Instant::now() >= deadline)
            .unwrap_or(false)
        {
            break;
        }
        ring.poll(Duration::from_millis(50))
            .map_err(|error| error.to_string())?;
        for sample in events.try_iter() {
            if model.paused {
                // Drain the ring while paused so the kernel does not drop,
                // but freeze the view.
                continue;
            }
            match runtime::decode::decode(&sample.sensor, &sample.bytes, &clock) {
                Ok(mut event) => {
                    processes.observe(&mut event);
                    if model.filters.matches(&event) {
                        model.counters.observe(&event);
                    }
                }
                Err(_) => model.counters.decode_errors += 1,
            }
        }

        if last_draw.elapsed() >= Duration::from_millis(refresh_ms.max(100)) {
            let elapsed = last_draw.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                (model.counters.total.saturating_sub(last_total)) as f64 / elapsed
            } else {
                0.0
            };
            terminal
                .draw(|frame| draw(frame, &model, rate))
                .map_err(|error| error.to_string())?;
            last_draw = Instant::now();
            last_total = model.counters.total;
        }

        if event::poll(Duration::from_millis(0)).map_err(|error| error.to_string())? {
            if let TermEvent::Key(key) = event::read().map_err(|error| error.to_string())? {
                let apply_filters = model.prompt.is_some();
                if model.handle_key(key, None) {
                    break;
                }
                if apply_filters && model.prompt.is_none() {
                    // A filter changed: restart the incremental view so the
                    // screen reflects only matching events from now on.
                    model.counters.reset_events();
                }
            }
        }
    }
    Ok(())
}

fn draw(frame: &mut ratatui::Frame, model: &Model, rate: f64) {
    let counters = &model.counters;
    let area = frame.area();
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(8),
            Constraint::Length(14),
            Constraint::Length(3),
        ])
        .split(area);
    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                "ebpf-fleet top",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("  {}  ", model.title)),
            Span::styled(
                format!("{} events", counters.total),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  {rate:.0}/s  {} decode errors  {} stacks ({} frames, {} unsymbolized)",
                counters.decode_errors,
                counters.stack_total,
                counters.stack_frames,
                counters.stack_missing_symbols
            )),
        ]),
        Line::from(vec![
            Span::styled(
                {
                    let filters = format!("filters: {}", model.filters.describe());
                    format!(
                        "sort:{}  {}{}",
                        model.sort.label(),
                        if model.paused { "PAUSED  " } else { "" },
                        filters
                    )
                },
                Style::default().fg(Color::Yellow),
            ),
            Span::styled(
                format!(
                    "   {}",
                    model.status.clone().unwrap_or_else(|| "ready".to_string())
                ),
                Style::default().fg(Color::Green),
            ),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL).title("state"));
    frame.render_widget(header, outer[0]);

    let middle = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(outer[1]);
    frame.render_widget(
        count_table(
            "Top processes",
            &Counters::top(&counters.processes, model.sort),
        ),
        middle[0],
    );
    frame.render_widget(
        count_table(
            "Top file paths",
            &Counters::top(&counters.paths, model.sort),
        ),
        middle[1],
    );

    let kinds: Vec<(String, u64)> = counters
        .by_kind
        .iter()
        .map(|(key, value)| (key.clone(), *value))
        .collect();
    let mut kind_text = String::new();
    for (kind, count) in kinds.iter().rev().take(10) {
        kind_text.push_str(&format!("{kind:<18} {count:>10}\n"));
    }
    let recent_text = counters
        .recent
        .iter()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(22),
            Constraint::Percentage(43),
            Constraint::Percentage(35),
        ])
        .split(outer[2]);
    frame.render_widget(
        Paragraph::new(kind_text)
            .block(Block::default().borders(Borders::ALL).title("Event kinds")),
        bottom[0],
    );
    frame.render_widget(
        Paragraph::new(recent_text).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Recent events"),
        ),
        bottom[1],
    );
    frame.render_widget(
        count_table("Top stacks", &Counters::top(&counters.stacks, model.sort)),
        bottom[2],
    );

    let footer = match &model.prompt {
        Some((field, value)) => Line::from(vec![
            Span::styled(
                format!("filter {}: ", field.label()),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(value.clone()),
            Span::styled("▌", Style::default().fg(Color::Yellow)),
            Span::styled(
                "  enter apply  esc cancel",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        None => Line::from(vec![
            Span::styled(
                " space pause  s sort  p process  f path  k kind  x clear  w save  q quit ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                model.status.clone().unwrap_or_default(),
                Style::default().fg(Color::Green),
            ),
        ]),
    };
    frame.render_widget(
        Paragraph::new(footer).block(Block::default().borders(Borders::ALL).title("keys")),
        outer[3],
    );
}

fn count_table<'a>(title: &'a str, rows: &'a [(String, u64)]) -> Table<'a> {
    let header = Row::new(["name", "count"]).style(
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );
    let rows = rows.iter().map(|(name, count)| {
        Row::new(vec![
            Cell::from(name.clone()),
            Cell::from(count.to_string()),
        ])
    });
    Table::new(
        rows,
        [Constraint::Percentage(80), Constraint::Percentage(20)],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title))
}

/// Non-terminal bundle summary, used by `top <bundle>` in pipes and tests.
fn print_summary(counters: &Counters, path: &Path) {
    println!(
        "{}: {} events ({} decode errors)",
        path.display(),
        counters.total,
        counters.decode_errors
    );
    println!("\ntop processes");
    for (name, count) in Counters::top(&counters.processes, SortMode::CountDesc) {
        println!("{count:>10}  {name}");
    }
    println!("\ntop file paths");
    for (name, count) in Counters::top(&counters.paths, SortMode::CountDesc) {
        println!("{count:>10}  {name}");
    }
    println!("\nevent kinds");
    for (kind, count) in counters.by_kind.iter().rev().take(10) {
        println!("{count:>10}  {kind}");
    }
    println!(
        "\nstacks: {} resolved, {} frames ({} without symbols), {} events carry a stack id",
        counters.stack_total,
        counters.stack_frames,
        counters.stack_missing_symbols,
        counters.events_with_stacks
    );
    if !counters.stacks.is_empty() {
        println!("\ntop stacks");
        for (name, count) in Counters::top(&counters.stacks, SortMode::CountDesc) {
            println!("{count:>10}  {name}");
        }
    }
    let _ = io::stdout().flush();
}
