// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `predicates-cli`: bounded predicate evaluation smoke-test CLI.
//!
//! Subcommands:
//! - `evaluate <condition.json> --event <event.json> --lists <lists.json>`:
//!   evaluate a condition against an event (resolving list references) and
//!   print the [`rules::predicates::EvaluationResult`] as JSON.
//! - `budget --schema <rule-budget.v1.json>`: print the rule-evaluation budget
//!   read from the schema's property defaults as JSON.

use std::path::Path;
use std::process::ExitCode;

use rules::predicates::{default_budget, load_budget_from_schema, Event, PredicateEvaluator};
use rules::{Condition, List};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        return ExitCode::from(2);
    }
    match args[1].as_str() {
        "evaluate" => cmd_evaluate(&args[2..]),
        "budget" => cmd_budget(&args[2..]),
        other => {
            eprintln!("error: unknown command '{other}' (expected evaluate|budget)");
            usage();
            ExitCode::from(2)
        }
    }
}

fn usage() {
    eprintln!("usage: predicates-cli evaluate <condition.json> --event <event.json> --lists <lists.json>");
    eprintln!("       predicates-cli budget --schema <rule-budget.v1.json>");
}

fn cmd_evaluate(args: &[String]) -> ExitCode {
    let mut condition_path = None;
    let mut event_path = None;
    let mut lists_path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--event" => {
                i += 1;
                event_path = args.get(i).cloned();
            }
            "--lists" => {
                i += 1;
                lists_path = args.get(i).cloned();
            }
            other if !other.starts_with("--") && condition_path.is_none() => {
                condition_path = Some(other.to_string());
            }
            other => {
                eprintln!("error: unexpected argument '{other}'");
                usage();
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let (Some(condition_path), Some(event_path), Some(lists_path)) =
        (condition_path, event_path, lists_path)
    else {
        usage();
        return ExitCode::from(2);
    };

    let condition: Condition = match read_json(&condition_path) {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    let event: Event = match read_json(&event_path) {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };
    let lists: Vec<List> = match read_json(&lists_path) {
        Ok(v) => v,
        Err(e) => return fail(&e),
    };

    let evaluator = PredicateEvaluator::new(default_budget());
    match evaluator.evaluate_condition(&condition, &event, &lists) {
        Ok(result) => match serde_json::to_string_pretty(&result) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(e) => fail(&format!("failed to serialize result: {e}")),
        },
        Err(e) => fail(&format!("{e}")),
    }
}

fn cmd_budget(args: &[String]) -> ExitCode {
    let mut schema_path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--schema" => {
                i += 1;
                schema_path = args.get(i).cloned();
            }
            other => {
                eprintln!("error: unexpected argument '{other}'");
                usage();
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let Some(schema_path) = schema_path else {
        usage();
        return ExitCode::from(2);
    };
    match load_budget_from_schema(Path::new(&schema_path)) {
        Ok(budget) => match serde_json::to_string_pretty(&budget) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(e) => fail(&format!("failed to serialize budget: {e}")),
        },
        Err(e) => fail(&format!("{e}")),
    }
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
