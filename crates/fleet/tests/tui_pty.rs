// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real PTY smoke test for the bundle TUI (`ebpf-fleet top BUNDLE`).
//!
//! The test runs the real binary against a PTY so the terminal/alternate-screen
//! path is exercised, then drives keys (pause, sort, kind filter, save, quit)
//! and validates the rendered output and the saved JSON snapshot. It never
//! loads BPF.

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use bundle::{BundleWriter, CaptureInfo, HostInfo};
use event_model::Event;
use nix::poll::{poll, PollFd, PollFlags};
use nix::pty::{openpty, Winsize};
use serde_json::Value;
use tempfile::TempDir;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_ebpf-fleet")
}

fn event(id: &str, kind: &str, sensor: &str, pid: u32, path: &str) -> Event {
    Event {
        event_id: id.to_string(),
        time: "2026-11-14T00:00:00.000000000Z".to_string(),
        sensor: sensor.to_string(),
        kind: kind.to_string(),
        pid,
        tgid: pid,
        process_exec: Some("cat".to_string()),
        path: Some(path.to_string()),
        ..Event::default()
    }
}

fn fixture() -> (TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("tui.fleet");
    let mut writer = BundleWriter::create(
        &root,
        HostInfo::default(),
        CaptureInfo {
            sensors: vec!["file".to_string(), "process".to_string()],
            duration_ms: 1_000,
            stack_mode: "off".to_string(),
        },
    )
    .expect("create bundle");
    writer
        .write_events(&[
            event("evt-1", "FileOpen", "file", 10, "/etc/shadow"),
            event("evt-2", "FileOpen", "file", 11, "/etc/passwd"),
            event("evt-3", "ProcessExec", "process", 12, "/bin/true"),
        ])
        .expect("write events");
    writer.finish().expect("finish");
    (directory, root)
}

/// Minimal virtual terminal: applies ratatui's cursor-position diffs so
/// needles can be matched against the final screen rather than raw escape
/// soup.
struct Screen {
    rows: Vec<Vec<char>>,
    row: usize,
    column: usize,
    width: usize,
    height: usize,
}

impl Screen {
    fn new(width: usize, height: usize) -> Self {
        Self {
            rows: vec![vec![' '; width]; height],
            row: 0,
            column: 0,
            width,
            height,
        }
    }

    fn feed(&mut self, text: &str) {
        let mut characters = text.chars().peekable();
        while let Some(character) = characters.next() {
            match character {
                '\x1b' => {
                    let Some('[') = characters.next() else {
                        continue;
                    };
                    let mut parameters = String::new();
                    let final_character = loop {
                        match characters.next() {
                            Some(next) if next.is_ascii_digit() || next == ';' || next == '?' => {
                                parameters.push(next)
                            }
                            Some(next) => break next,
                            None => return,
                        }
                    };
                    self.apply_escape(&parameters, final_character);
                }
                '\r' => self.column = 0,
                '\n' => {
                    self.row = (self.row + 1).min(self.height.saturating_sub(1));
                    self.column = 0;
                }
                character if character.is_control() => {}
                character => {
                    if self.row < self.height && self.column < self.width {
                        self.rows[self.row][self.column] = character;
                    }
                    self.column += 1;
                    if self.column >= self.width {
                        self.column = 0;
                        self.row += 1;
                        if self.row >= self.height {
                            self.row = self.height.saturating_sub(1);
                        }
                    }
                }
            }
        }
    }

    fn apply_escape(&mut self, parameters: &str, final_character: char) {
        let parameters = parameters.trim_start_matches('?');
        match final_character {
            'H' | 'f' => {
                let mut parts = parameters.split(';');
                let row = parts.next().unwrap_or("1").parse::<usize>().unwrap_or(1);
                let column = parts.next().unwrap_or("1").parse::<usize>().unwrap_or(1);
                self.row = row.saturating_sub(1).min(self.height.saturating_sub(1));
                self.column = column.saturating_sub(1).min(self.width.saturating_sub(1));
            }
            'G' => {
                self.column = parameters
                    .parse::<usize>()
                    .unwrap_or(1)
                    .saturating_sub(1)
                    .min(self.width.saturating_sub(1));
            }
            'd' => {
                self.row = parameters
                    .parse::<usize>()
                    .unwrap_or(1)
                    .saturating_sub(1)
                    .min(self.height.saturating_sub(1));
            }
            'J' if parameters == "2" || parameters == "3" => {
                for row in &mut self.rows {
                    row.fill(' ');
                }
            }
            'K' => {
                let start = self.column.min(self.width);
                for column in start..self.width {
                    self.rows[self.row][column] = ' ';
                }
            }
            _ => {}
        }
    }

    fn contains(&self, needle: &str) -> bool {
        self.rows
            .iter()
            .any(|row| row.iter().collect::<String>().contains(needle))
    }
}

struct PtyTop {
    master: std::fs::File,
    child: std::process::Child,
    output: Vec<u8>,
    screen: Screen,
}

impl PtyTop {
    fn spawn(bundle: &Path, working_dir: &Path) -> Self {
        let pty = openpty(
            Some(&Winsize {
                ws_row: 40,
                ws_col: 120,
                ws_xpixel: 0,
                ws_ypixel: 0,
            }),
            None,
        )
        .expect("openpty");
        let slave = pty.slave;
        let master = std::fs::File::from(pty.master);
        let child = Command::new(binary())
            .arg("top")
            .arg(bundle)
            .current_dir(working_dir)
            .env("TERM", "xterm-256color")
            .stdin(Stdio::from(
                slave.try_clone().expect("clone slave for stdin"),
            ))
            .stdout(Stdio::from(
                slave.try_clone().expect("clone slave for stdout"),
            ))
            .stderr(Stdio::from(slave))
            .spawn()
            .expect("spawn ebpf-fleet top");
        Self {
            master,
            child,
            output: Vec::new(),
            screen: Screen::new(120, 40),
        }
    }

    fn rendered(&self) -> String {
        plain_text(&String::from_utf8_lossy(&self.output))
    }

    fn pump(&mut self, timeout: Duration) {
        let mut descriptors = [PollFd::new(self.master.as_fd(), PollFlags::POLLIN)];
        let ready = poll(&mut descriptors, timeout.as_millis() as u16).unwrap_or(0);
        if ready <= 0 {
            return;
        }
        let mut buffer = [0u8; 16 * 1024];
        match self.master.read(&mut buffer) {
            Ok(0) => {}
            Ok(count) => {
                self.output.extend_from_slice(&buffer[..count]);
                self.screen.feed(&String::from_utf8_lossy(&buffer[..count]));
            }
            Err(_) => {}
        }
    }

    fn wait_for(&mut self, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.screen.contains(needle) {
                return true;
            }
            self.pump(Duration::from_millis(100));
        }
        self.screen.contains(needle)
    }

    fn send(&mut self, text: &str) {
        self.master
            .write_all(text.as_bytes())
            .expect("write to pty");
        self.master.flush().expect("flush pty");
    }

    fn finish(mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                self.pump(Duration::from_millis(50));
                return status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("TUI did not exit; output tail:\n{}", tail(&self.rendered()));
            }
            self.pump(Duration::from_millis(50));
        }
    }
}

/// Strip ANSI escape sequences so the test can search rendered text. The TUI
/// writes cursor-position escapes between words of block titles, so matching
/// raw bytes is unreliable.
fn plain_text(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(character) = chars.next() {
        if character == '\x1b' {
            // CSI (`ESC [ ... final`) covers every sequence ratatui writes
            // here; anything else is skipped one character at a time.
            if chars.next() == Some('[') {
                for next in chars.by_ref() {
                    if ('@'..='~').contains(&next) {
                        break;
                    }
                }
            }
        } else if character != '\r' && character != '\n' {
            plain.push(character);
        }
    }
    plain
}

fn tail(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    chars[chars.len().saturating_sub(3000)..].iter().collect()
}

#[test]
fn tui_pty_pause_sort_filter_save_and_quit() {
    let (_directory, bundle) = fixture();
    let working_dir = tempfile::tempdir().expect("working dir");
    let mut top = PtyTop::spawn(&bundle, working_dir.path());

    assert!(
        top.wait_for("ebpf-fleet top", Duration::from_secs(10)),
        "TUI did not render its header; output:\n{}",
        tail(&top.rendered())
    );
    assert!(
        top.wait_for("processes", Duration::from_secs(10)),
        "TUI did not render its panes; output:\n{}",
        tail(&top.rendered())
    );

    // Pause and sort cycle.
    top.send(" ");
    assert!(
        top.wait_for("PAUSED", Duration::from_secs(5)),
        "pause indicator missing; output:\n{}",
        tail(&top.rendered())
    );
    top.send("s");
    assert!(
        top.wait_for("sort:name", Duration::from_secs(5)),
        "sort indicator missing; output:\n{}",
        tail(&top.rendered())
    );

    // Filter by kind: k <text> <enter>.
    top.send("k");
    assert!(
        top.wait_for("filter kind:", Duration::from_secs(5)),
        "filter prompt missing; output:\n{}",
        tail(&top.rendered())
    );
    top.send("FileOpen");
    std::thread::sleep(Duration::from_millis(100));
    top.send("\r");
    assert!(
        top.wait_for("kind~FileOpen", Duration::from_secs(5)),
        "filter was not applied; output:\n{}",
        tail(&top.rendered())
    );

    // Save a JSON snapshot in the child's working directory.
    top.send("w");
    assert!(
        top.wait_for("saved top-snapshot-", Duration::from_secs(5)),
        "save status missing; output:\n{}",
        tail(&top.rendered())
    );
    top.send("q");
    let status = top.finish(Duration::from_secs(5));
    assert!(status.success(), "top exited with {status:?}");

    let snapshot_path = std::fs::read_dir(working_dir.path())
        .expect("read working dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.starts_with("top-snapshot-") && name.ends_with(".json"))
                .unwrap_or(false)
        })
        .expect("TUI must save a top-snapshot-*.json file");
    let snapshot: Value =
        serde_json::from_slice(&std::fs::read(&snapshot_path).expect("read snapshot"))
            .expect("snapshot JSON");
    assert_eq!(snapshot["filters"]["kind"], "FileOpen");
    assert_eq!(
        snapshot["events"], 2,
        "kind filter must keep the two FileOpen events: {snapshot}"
    );
    assert!(snapshot["title"]
        .as_str()
        .expect("title")
        .contains("bundle"));
    assert_eq!(snapshot["paused"], true);
    assert_eq!(snapshot["sort"], "name_asc");
}
