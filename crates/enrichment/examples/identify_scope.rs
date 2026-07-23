// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Smoke-test example for the enrichment layer.
//!
//! Reads a `{"cgroup_path": "...", "cgroup_id": 12345}` JSON envelope from
//! stdin (or from a file path passed as the first argument) and prints the
//! inferred `AttributionScope` to stdout. The CLI binary owned by task 26
//! is the user-facing surface; this example exists so that task 22's
//! acceptance criteria can exercise the scope-derivation path without a
//! live runtime socket.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use enrichment::derive_scope_from_path;

#[derive(Debug, serde::Deserialize)]
struct IdentifyScopeInput {
    cgroup_path: String,
    #[serde(default)]
    _cgroup_id: Option<u64>,
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let raw = if args.len() > 1 {
        let path = PathBuf::from(&args[1]);
        let mut buf = String::new();
        std::fs::File::open(&path)
            .map_err(|err| format!("open {}: {err}", path.display()))?
            .read_to_string(&mut buf)
            .map_err(|err| format!("read {}: {err}", path.display()))?;
        buf
    } else {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|err| format!("read stdin: {err}"))?;
        buf
    };

    let input: IdentifyScopeInput =
        serde_json::from_str(&raw).map_err(|err| format!("invalid JSON input: {err}"))?;
    let scope = derive_scope_from_path(&input.cgroup_path);
    let envelope = serde_json::json!({
        "cgroup_path": input.cgroup_path,
        "scope": scope.to_string(),
    });
    println!("{envelope}");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("identify-scope: {err}");
            ExitCode::FAILURE
        }
    }
}
