// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ebpf-fleet top`: a small live/bundle TUI over process and file events.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event as TermEvent, KeyCode, KeyEventKind};
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

use crate::Bundle;

const RECENT_LIMIT: usize = 12;
const TABLE_LIMIT: usize = 12;

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

    fn top(map: &BTreeMap<String, u64>) -> Vec<(String, u64)> {
        let mut values: Vec<_> = map
            .iter()
            .map(|(key, value)| (key.clone(), *value))
            .collect();
        values.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        values.truncate(TABLE_LIMIT);
        values
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
    let mut counters = Counters::default();
    for batch in &batches {
        for row in 0..batch.num_rows() {
            let raw = arrow::util::display::array_value_to_string(batch.column(0).as_ref(), row)
                .map_err(|error| error.to_string())?;
            if let Ok(event) = serde_json::from_str::<Event>(&raw) {
                counters.observe(&event);
            } else {
                counters.decode_errors += 1;
            }
        }
    }

    for stack in bundle
        .read_stacks()
        .await
        .map_err(|error| error.to_string())?
    {
        counters.observe_stack(&stack);
    }

    if !io::stdout().is_terminal() {
        print_summary(&counters, &path);
        return Ok(());
    }

    let _guard = ScreenGuard::enter().map_err(|error| error.to_string())?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).map_err(|error| error.to_string())?;
    loop {
        terminal
            .draw(|frame| draw(frame, &counters, &format!("bundle {}", path.display()), 0.0))
            .map_err(|error| error.to_string())?;
        if event::poll(Duration::from_millis(refresh_ms.max(100)))
            .map_err(|error| error.to_string())?
        {
            if let TermEvent::Key(key) = event::read().map_err(|error| error.to_string())? {
                if key.kind == KeyEventKind::Press
                    && matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
                {
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
    let mut counters = Counters::default();
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
            match runtime::decode::decode(&sample.sensor, &sample.bytes, &clock) {
                Ok(mut event) => {
                    processes.observe(&mut event);
                    counters.observe(&event);
                }
                Err(_) => counters.decode_errors += 1,
            }
        }

        if last_draw.elapsed() >= Duration::from_millis(refresh_ms.max(100)) {
            let elapsed = last_draw.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                (counters.total.saturating_sub(last_total)) as f64 / elapsed
            } else {
                0.0
            };
            terminal
                .draw(|frame| draw(frame, &counters, "live", rate))
                .map_err(|error| error.to_string())?;
            last_draw = Instant::now();
            last_total = counters.total;
        }

        if event::poll(Duration::from_millis(0)).map_err(|error| error.to_string())? {
            if let TermEvent::Key(key) = event::read().map_err(|error| error.to_string())? {
                if key.kind == KeyEventKind::Press
                    && matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
                {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn draw(frame: &mut ratatui::Frame, counters: &Counters, title: &str, rate: f64) {
    let area = frame.area();
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(14),
        ])
        .split(area);
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            "ebpf-fleet top",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  {title}  ")),
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
        Span::styled("  q/esc quit", Style::default().fg(Color::DarkGray)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, outer[0]);

    let middle = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(outer[1]);
    frame.render_widget(
        count_table("Top processes", &Counters::top(&counters.processes)),
        middle[0],
    );
    frame.render_widget(
        count_table("Top file paths", &Counters::top(&counters.paths)),
        middle[1],
    );

    let kinds: Vec<(String, u64)> = counters
        .by_kind
        .iter()
        .map(|(k, v)| (k.clone(), *v))
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
        count_table("Top stacks", &Counters::top(&counters.stacks)),
        bottom[2],
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

fn print_summary(counters: &Counters, path: &std::path::Path) {
    println!(
        "{}: {} events ({} decode errors)",
        path.display(),
        counters.total,
        counters.decode_errors
    );
    println!("\ntop processes");
    for (name, count) in Counters::top(&counters.processes) {
        println!("{count:>10}  {name}");
    }
    println!("\ntop file paths");
    for (name, count) in Counters::top(&counters.paths) {
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
        for (name, count) in Counters::top(&counters.stacks) {
            println!("{count:>10}  {name}");
        }
    }
    let _ = io::stdout().flush();
}
