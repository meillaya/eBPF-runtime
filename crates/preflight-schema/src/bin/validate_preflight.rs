//! `validate-preflight` — load a preflight JSON file, schema-validate it,
//! semantic-check it, and exit 0 on success / 1 on failure. Errors are
//! printed to stderr as a single line with the JSON pointer and message so
//! downstream tooling can grep / parse them.
//!
//! SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::Read;
use std::process::ExitCode;

use preflight_schema::ReportError;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let path = match args.next() {
        Some(p) => p,
        None => {
            eprintln!("usage: validate-preflight <path-to-preflight.json>");
            return ExitCode::from(2);
        }
    };
    if args.next().is_some() {
        eprintln!("usage: validate-preflight <path-to-preflight.json>");
        return ExitCode::from(2);
    }

    let mut bytes = Vec::new();
    if let Err(e) = std::fs::File::open(&path).and_then(|mut f| f.read_to_end(&mut bytes)) {
        eprintln!("{}: cannot read file: {}", path, e);
        return ExitCode::from(1);
    }

    match preflight_schema::parse(&bytes) {
        Ok(report) => {
            println!(
                "{}: schema_version={} status={} sensors_ok=true",
                path, report.schema_version, report.status
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            let r: ReportError = err;
            eprintln!("{}: invalid preflight: {}", r.pointer, r.message);
            ExitCode::from(1)
        }
    }
}
