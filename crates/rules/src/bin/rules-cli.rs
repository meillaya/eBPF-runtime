// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `rules-cli`: parse / validate / digest smoke-test CLI for the native rule schema.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: rules-cli <parse|validate|digest> <rules.yaml>");
        return ExitCode::from(2);
    }
    let path = &args[2];
    let yaml = match std::fs::read_to_string(path) {
        Ok(yaml) => yaml,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    match args[1].as_str() {
        "parse" => cmd_parse(&yaml),
        "validate" => cmd_validate(&yaml),
        "digest" => cmd_digest(&yaml),
        other => {
            eprintln!("error: unknown command '{other}' (expected parse|validate|digest)");
            ExitCode::from(2)
        }
    }
}

fn cmd_parse(yaml: &str) -> ExitCode {
    match rules::parse_ruleset(yaml) {
        Ok(ruleset) => match serde_json::to_string_pretty(&ruleset) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: failed to serialize parsed rule set: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_validate(yaml: &str) -> ExitCode {
    match rules::parse_ruleset(yaml) {
        Ok(_) => {
            println!("ok: rule set is valid");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("invalid: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_digest(yaml: &str) -> ExitCode {
    match rules::parse_ruleset(yaml).and_then(|ruleset| rules::canonical_digest(&ruleset)) {
        Ok(digest) => {
            println!("{digest}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
