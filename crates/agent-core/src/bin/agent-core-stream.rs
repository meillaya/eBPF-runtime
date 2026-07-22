// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Replay and stress surface for the bounded agent-core pipeline.

#![forbid(unsafe_code)]

use std::env;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use agent_core::{synthetic_record, AgentCore, AgentCoreOpts, ControlEvent};

const HELP: &str = "Usage: agent-core-stream --ring-bytes <path|synth> --schema <path> [--max-rate <ev/s>] [--duration <seconds>] --out <path>\n\nOptions:\n  --ring-bytes <path>   Length-prefixed ring dump, or 'synth'\n  --schema <path>       Supported-load schema\n  --max-rate <ev/s>     Synthetic event rate; 0 means unlimited\n  --duration <seconds>  Stress duration\n  --out <path>          JSON report destination\n  -h, --help            Print help\n";

#[derive(Debug)]
struct Args {
    ring_bytes: PathBuf,
    schema: PathBuf,
    max_rate: u64,
    duration: u64,
    out: PathBuf,
}

#[derive(Debug)]
struct Report {
    seq_gap_count: u64,
    drop_count: u64,
    event_count: u64,
    panic_count: u64,
    time_seconds: f64,
    verdict: &'static str,
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut args = env::args().skip(1);
    let mut ring_bytes = None;
    let mut schema = None;
    let mut max_rate = 1_000;
    let mut duration = 5;
    let mut out = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "-h" | "--help" => return Ok(None),
            "--ring-bytes" => ring_bytes = Some(PathBuf::from(next_value(&mut args, &flag)?)),
            "--schema" => schema = Some(PathBuf::from(next_value(&mut args, &flag)?)),
            "--max-rate" => max_rate = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
            "--duration" => duration = parse_u64(&next_value(&mut args, &flag)?, &flag)?,
            "--out" => out = Some(PathBuf::from(next_value(&mut args, &flag)?)),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if duration == 0 {
        return Err("--duration must be greater than zero".to_owned());
    }
    Ok(Some(Args {
        ring_bytes: ring_bytes.ok_or_else(|| "missing --ring-bytes".to_owned())?,
        schema: schema.ok_or_else(|| "missing --schema".to_owned())?,
        max_rate,
        duration,
        out: out.ok_or_else(|| "missing --out".to_owned())?,
    }))
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_u64(value: &str, flag: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|error| format!("invalid value for {flag}: {error}"))
}

fn supported_rate(path: &Path) -> Result<u64, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.len() > 65_536 {
        return Err("supported-load schema exceeds 64 KiB".to_owned());
    }
    let text = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let property = text
        .find("default_rate_events_per_sec_per_cpu")
        .ok_or_else(|| "schema lacks supported-rate property".to_owned())?;
    let tail = text
        .get(property..)
        .ok_or_else(|| "invalid schema offset".to_owned())?;
    let default = tail
        .find("\"default\"")
        .ok_or_else(|| "supported-rate property lacks default".to_owned())?;
    let value_tail = tail
        .get(default..)
        .ok_or_else(|| "invalid schema default offset".to_owned())?;
    let colon = value_tail
        .find(':')
        .ok_or_else(|| "invalid schema default".to_owned())?;
    let digits: String = value_tail
        .get(colon + 1..)
        .unwrap_or_default()
        .chars()
        .skip_while(|ch| ch.is_whitespace())
        .take_while(char::is_ascii_digit)
        .collect();
    parse_u64(&digits, "schema supported-rate default")
}

async fn synthetic(args: &Args, supported: u64) -> Result<Report, String> {
    let saturated = args.max_rate == 0 || args.max_rate > supported;
    let opts = AgentCoreOpts {
        data_capacity: if saturated { 256 } else { 8_192 },
        emit_delay: if saturated {
            Duration::from_millis(1)
        } else {
            Duration::ZERO
        },
        ..AgentCoreOpts::default()
    };
    let core = AgentCore::start_replay(opts)
        .await
        .map_err(|error| error.to_string())?;
    let started = Instant::now();
    let effective_rate = if args.max_rate == 0 {
        50_000
    } else {
        args.max_rate
    };
    let ticks = args.duration.saturating_mul(100);
    let mut emitted = 0_u64;
    let mut interval = tokio::time::interval(Duration::from_millis(10));
    for tick in 0..ticks {
        interval.tick().await;
        let target = effective_rate.saturating_mul(tick.saturating_add(1)) / 100;
        while emitted < target {
            emitted = emitted.saturating_add(1);
            core.ingest_bytes(&synthetic_record(emitted))
                .map_err(|error| error.to_string())?;
        }
        if tick % 100 == 0 {
            core.send_control(ControlEvent::Status);
        }
    }
    core.shutdown().await;
    let drops = core.drop_count();
    let gaps = core.seq_gap_count();
    let panics = core.panic_count();
    let verdict =
        if panics > 0 || (!saturated && (drops > 0 || gaps > 0)) || (saturated && drops == 0) {
            "failed"
        } else if saturated {
            "saturation-detected-no-critical-loss"
        } else {
            "passed"
        };
    Ok(Report {
        seq_gap_count: gaps,
        drop_count: drops,
        event_count: emitted,
        panic_count: panics,
        time_seconds: started.elapsed().as_secs_f64(),
        verdict,
    })
}

async fn replay(args: &Args, supported: u64) -> Result<Report, String> {
    let core = AgentCore::start_replay(AgentCoreOpts::default())
        .await
        .map_err(|error| error.to_string())?;
    let started = Instant::now();
    let file = File::open(&args.ring_bytes)
        .map_err(|error| format!("cannot open {}: {error}", args.ring_bytes.display()))?;
    let mut reader = BufReader::new(file);
    let mut count = 0_u64;
    let mut failures = 0_u64;
    loop {
        let mut length = [0_u8; 4];
        match reader.read_exact(&mut length) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(format!("cannot read ring record length: {error}")),
        }
        let length =
            usize::try_from(u32::from_le_bytes(length)).map_err(|error| error.to_string())?;
        if length > event_abi::HEADER_LEN + event_abi::PAYLOAD_MAX {
            return Err(format!("ring record length {length} exceeds ABI bound"));
        }
        let mut payload = vec![0_u8; length];
        reader
            .read_exact(&mut payload)
            .map_err(|error| format!("truncated ring record: {error}"))?;
        match core.ingest_bytes(&payload) {
            Ok(()) => count = count.saturating_add(1),
            Err(_) => failures = failures.saturating_add(1),
        }
    }
    core.shutdown().await;
    let panics = core.panic_count();
    let drops = core.drop_count();
    let gaps = core.seq_gap_count();
    let verdict =
        if failures == 0 && panics == 0 && drops == 0 && gaps == 0 && args.max_rate <= supported {
            "passed"
        } else {
            "failed"
        };
    Ok(Report {
        seq_gap_count: gaps,
        drop_count: drops,
        event_count: count,
        panic_count: panics,
        time_seconds: started.elapsed().as_secs_f64(),
        verdict,
    })
}

fn write_report(path: &Path, report: &Report) -> Result<(), String> {
    let json = format!("{{\n  \"seq_gap_count\": {},\n  \"drop_count\": {},\n  \"event_count\": {},\n  \"panic_count\": {},\n  \"time_seconds\": {:.6},\n  \"verdict\": \"{}\"\n}}\n", report.seq_gap_count, report.drop_count, report.event_count, report.panic_count, report.time_seconds, report.verdict);
    fs::write(path, json).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(Some(args)) => args,
        Ok(None) => {
            print!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("{error}\n\n{HELP}");
            return ExitCode::FAILURE;
        }
    };
    let result = async {
        let supported = supported_rate(&args.schema)?;
        let report = if matches!(args.ring_bytes.to_str(), Some("synth" | "<synth>")) {
            synthetic(&args, supported).await?
        } else {
            replay(&args, supported).await?
        };
        write_report(&args.out, &report)?;
        if report.verdict == "failed" {
            Err("pipeline verdict failed".to_owned())
        } else {
            Ok(())
        }
    }
    .await;
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
