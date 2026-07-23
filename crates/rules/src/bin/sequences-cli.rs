// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `sequences-cli`: bounded temporal sequence correlation smoke-test CLI.
//!
//! Subcommands:
//! - `process <events.json> --sequences <sequences.json>`: process events
//!   against sequences and print matches as JSON.
//! - `replay <events.json> --sequences <sequences.json>`: replay events
//!   deterministically and print matches as JSON.
//! - `evict --now <timestamp> --capacity <capacity>`: evict expired and LRU
//!   sequences and print the count.

use std::process::ExitCode;

use rules::predicates::{default_budget, Event};
use rules::sequences::SequenceEvaluator;
use rules::Sequence;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        return ExitCode::from(2);
    }
    match args[1].as_str() {
        "process" => cmd_process(&args[2..]),
        "replay" => cmd_replay(&args[2..]),
        "evict" => cmd_evict(&args[2..]),
        other => {
            eprintln!("error: unknown command '{other}' (expected process|replay|evict)");
            usage();
            ExitCode::from(2)
        }
    }
}

fn usage() {
    eprintln!("usage: sequences-cli process <events.json> --sequences <sequences.json>");
    eprintln!("       sequences-cli replay <events.json> --sequences <sequences.json>");
    eprintln!("       sequences-cli evict --now <timestamp> --capacity <capacity>");
}

fn cmd_process(args: &[String]) -> ExitCode {
    let mut events_path = None;
    let mut sequences_path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--sequences" => {
                i += 1;
                sequences_path = args.get(i).cloned();
            }
            other if !other.starts_with("--") && events_path.is_none() => {
                events_path = Some(other.to_string());
            }
            other => {
                eprintln!("error: unexpected argument '{other}'");
                usage();
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let (Some(events_path), Some(sequences_path)) = (events_path, sequences_path) else {
        usage();
        return ExitCode::from(2);
    };

    let events: Vec<Event> = match read_json(&events_path) {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    let sequences: Vec<Sequence> = match read_json(&sequences_path) {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };

    let mut evaluator = SequenceEvaluator::new(default_budget());
    let mut all_matches = Vec::new();
    for event in &events {
        match evaluator.process_event(event, &sequences) {
            Ok(matches) => all_matches.extend(matches),
            Err(e) => return fail(&format!("{e}")),
        }
    }

    match serde_json::to_string_pretty(&all_matches) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("failed to serialize matches: {e}")),
    }
}

fn cmd_replay(args: &[String]) -> ExitCode {
    let mut events_path = None;
    let mut sequences_path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--sequences" => {
                i += 1;
                sequences_path = args.get(i).cloned();
            }
            other if !other.starts_with("--") && events_path.is_none() => {
                events_path = Some(other.to_string());
            }
            other => {
                eprintln!("error: unexpected argument '{other}'");
                usage();
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let (Some(events_path), Some(sequences_path)) = (events_path, sequences_path) else {
        usage();
        return ExitCode::from(2);
    };

    let events: Vec<Event> = match read_json(&events_path) {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    let sequences: Vec<Sequence> = match read_json(&sequences_path) {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };

    let mut evaluator = SequenceEvaluator::new(default_budget());
    match evaluator.replay(&events, &sequences) {
        Ok(matches) => match serde_json::to_string_pretty(&matches) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(e) => fail(&format!("failed to serialize matches: {e}")),
        },
        Err(e) => fail(&format!("{e}")),
    }
}

fn cmd_evict(args: &[String]) -> ExitCode {
    let mut now: Option<u64> = None;
    let mut capacity: Option<usize> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--now" => {
                i += 1;
                now = args.get(i).and_then(|s| s.parse().ok());
            }
            "--capacity" => {
                i += 1;
                capacity = args.get(i).and_then(|s| s.parse().ok());
            }
            other => {
                eprintln!("error: unexpected argument '{other}'");
                usage();
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let (Some(now), Some(capacity)) = (now, capacity) else {
        usage();
        return ExitCode::from(2);
    };

    let mut evaluator = SequenceEvaluator::with_capacity(default_budget(), capacity);
    let expired = evaluator.evict_expired(now);
    let lru = evaluator.evict_lru(capacity);
    let total = expired + lru;
    println!("{total}");
    ExitCode::SUCCESS
}

/// Read and parse a JSON file, mapping errors to a display string.
fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> std::result::Result<T, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("invalid JSON in {path}: {e}"))
}

/// Print an error to stderr and return a failure exit code.
fn fail(message: &str) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::FAILURE
}
