// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ebpf-fleet`: local-first kernel recording, query, and replay.
//!
//! The local path deliberately does not depend on PostgreSQL, Kafka,
//! ClickHouse, OIDC, or the dashboard. `record` writes a self-contained
//! incident bundle; `query` runs SQL over its Parquet parts; `replay`
//! prints the recorded JSON stream; `doctor` explains the host preflight.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arrow::array::Array;
use bundle::{Bundle, BundleWriter, CaptureInfo, HostInfo, Manifest};
use clap::{Args, Parser, Subcommand};
use event_model::Event;
use runtime::decode::{decode, Clock};
use runtime::process_table::ProcessTable;
use serde::Serialize;
use sha2::{Digest, Sha256};
use signal_hook::consts::{SIGINT, SIGTERM};

#[derive(Debug, Parser)]
#[command(
    name = "ebpf-fleet",
    version,
    about = "Record Linux kernel activity once, query it locally, replay it anywhere"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Record sensors into a self-contained incident bundle.
    Record(RecordArgs),
    /// Run SQL over a recorded bundle.
    Query(QueryArgs),
    /// Print the recorded event stream as JSON lines.
    Replay(ReplayArgs),
    /// Check host prerequisites and explain what will fail.
    Doctor(DoctorArgs),
}

#[derive(Debug, Args)]
struct RecordArgs {
    /// Stop after this many seconds. Zero records until interrupted.
    #[arg(long = "for", default_value_t = 0)]
    duration: u64,
    /// Output bundle directory.
    #[arg(long)]
    out: PathBuf,
    /// Comma separated sensors. Default: process,file.
    #[arg(long, value_delimiter = ',', default_value = "process,file")]
    sensors: Vec<String>,
    /// Only record events for this pid or tgid.
    #[arg(long)]
    pid: Option<u32>,
    /// Stack mode. Only `off` is supported in this milestone.
    #[arg(long, default_value = "off")]
    stacks: String,
    /// Flush after this many events.
    #[arg(long, default_value_t = 1000)]
    batch_events: usize,
    /// Stop after this many events. Zero means unlimited.
    #[arg(long, default_value_t = 0)]
    max_events: u64,
}

#[derive(Debug, Args)]
struct QueryArgs {
    /// Bundle directory.
    bundle: PathBuf,
    /// SQL against the `events` table. Defaults to a kind summary.
    sql: Option<String>,
}

#[derive(Debug, Args)]
struct ReplayArgs {
    /// Bundle directory.
    bundle: PathBuf,
    /// Replay speed multiplier. Currently used for pacing only when non-zero.
    #[arg(long, default_value_t = 0.0)]
    speed: f64,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Serialize)]
struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Record(args) => record(args),
        Command::Query(args) => query(args).await,
        Command::Replay(args) => replay(args).await,
        Command::Doctor(args) => doctor(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ebpf-fleet: {error}");
            ExitCode::FAILURE
        }
    }
}

fn record(args: RecordArgs) -> Result<(), String> {
    if args.stacks != "off" {
        return Err(format!(
            "--stacks {} is not implemented yet; stack capture is a later milestone",
            args.stacks
        ));
    }
    if args.batch_events == 0 {
        return Err("--batch-events must be greater than zero".to_string());
    }

    let names: Vec<&str> = args.sensors.iter().map(String::as_str).collect();
    let sensors = bpf_loader::load(&names).map_err(|error| error.to_string())?;
    for sensor in &sensors.coverage.sensors {
        if sensor.status == bpf_loader::SensorStatus::Blocked {
            eprintln!(
                "warning: sensor {} is blocked: {}",
                sensor.name,
                sensor.errors.join("; ")
            );
        }
    }
    if sensors.sensors.is_empty() {
        return Err("no sensor attached; run `ebpf-fleet doctor` for host checks".to_string());
    }
    let (_ring, events) = sensors.ring_reader().map_err(|error| error.to_string())?;

    let host = host_info();
    let capture = CaptureInfo {
        sensors: args.sensors.clone(),
        duration_ms: args.duration.saturating_mul(1000),
        stack_mode: "off".to_string(),
    };
    let mut writer =
        BundleWriter::create(&args.out, host, capture).map_err(|error| error.to_string())?;

    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, shutdown.clone()).map_err(|error| error.to_string())?;
    signal_hook::flag::register(SIGTERM, shutdown.clone()).map_err(|error| error.to_string())?;

    let clock = Clock::new();
    let mut processes = ProcessTable::new();
    let deadline = (args.duration > 0).then(|| Instant::now() + Duration::from_secs(args.duration));
    let mut pending: Vec<Event> = Vec::with_capacity(args.batch_events);
    let mut event_count = 0u64;
    let mut decode_errors = 0u64;

    while !shutdown.load(Ordering::Relaxed) {
        if deadline
            .map(|deadline| Instant::now() >= deadline)
            .unwrap_or(false)
        {
            break;
        }
        if args.max_events > 0 && event_count >= args.max_events {
            break;
        }

        if let Err(error) = _ring.poll(Duration::from_millis(200)) {
            eprintln!("warning: ring buffer: {error}");
            break;
        }

        for sample in events.try_iter() {
            let mut event = match decode(&sample.sensor, &sample.bytes, &clock) {
                Ok(event) => event,
                Err(_) => {
                    decode_errors += 1;
                    continue;
                }
            };
            processes.observe(&mut event);
            if let Some(pid) = args.pid {
                if event.pid != pid && event.tgid != pid {
                    continue;
                }
            }
            pending.push(event);
            event_count += 1;
            if pending.len() >= args.batch_events {
                writer
                    .write_events(&pending)
                    .map_err(|error| error.to_string())?;
                pending.clear();
            }
            if args.max_events > 0 && event_count >= args.max_events {
                break;
            }
        }
    }

    if event_count == 0 {
        return Err(
            "recorded no events; check `ebpf-fleet doctor` and generate activity while recording"
                .to_string(),
        );
    }
    if !pending.is_empty() {
        writer
            .write_events(&pending)
            .map_err(|error| error.to_string())?;
    }
    let bundle = writer.finish().map_err(|error| error.to_string())?;
    eprintln!(
        "recorded {} events ({} decode errors) into {}",
        bundle.manifest().counts.events,
        decode_errors,
        bundle.root().display()
    );
    Ok(())
}

async fn query(args: QueryArgs) -> Result<(), String> {
    let bundle = Bundle::open(&args.bundle).map_err(|error| error.to_string())?;
    let sql = args.sql.unwrap_or_else(|| {
        "select kind, count(*) as n from events group by kind order by n desc".to_string()
    });
    let batches = bundle
        .query(&sql)
        .await
        .map_err(|error| error.to_string())?;
    if batches.iter().all(|batch| batch.num_rows() == 0) {
        eprintln!("no rows");
        return Ok(());
    }
    arrow::util::pretty::print_batches(&batches).map_err(|error| error.to_string())?;
    Ok(())
}

async fn replay(args: ReplayArgs) -> Result<(), String> {
    let bundle = Bundle::open(&args.bundle).map_err(|error| error.to_string())?;
    let batches = bundle
        .query("select raw_json from events order by time_unix_ns, seq")
        .await
        .map_err(|error| error.to_string())?;
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let mut count = 0u64;
    for batch in &batches {
        let column = batch.column(0);
        for row in 0..column.len() {
            if column.is_null(row) {
                continue;
            }
            let value = arrow::util::display::array_value_to_string(column.as_ref(), row)
                .map_err(|error| error.to_string())?;
            writeln!(out, "{value}").map_err(|error| error.to_string())?;
            count += 1;
        }
    }
    out.flush().map_err(|error| error.to_string())?;
    eprintln!("replayed {count} events");
    if args.speed > 0.0 {
        eprintln!("note: replay pacing is not implemented yet; events were emitted immediately");
    }
    Ok(())
}

fn doctor(args: DoctorArgs) -> Result<(), String> {
    let mut checks = vec![
        check_file(
            "kernel",
            "/proc/sys/kernel/osrelease",
            true,
            "kernel release",
        ),
        check_file(
            "btf",
            "/sys/kernel/btf/vmlinux",
            true,
            "BTF is required to load CO-RE sensors",
        ),
        check_file(
            "debugfs",
            "/sys/kernel/debug",
            false,
            "debugfs is used by some attach paths",
        ),
        check_file(
            "bpffs",
            "/sys/fs/bpf",
            false,
            "bpffs is used for pinned maps/programs",
        ),
        check_file(
            "lockdown",
            "/sys/kernel/security/lockdown",
            false,
            "lockdown can block BPF",
        ),
        check_file(
            "lsm",
            "/sys/kernel/security/lsm",
            false,
            "BPF LSM enables the file sensor's LSM path",
        ),
        check_file(
            "unprivileged_bpf_disabled",
            "/proc/sys/kernel/unprivileged_bpf_disabled",
            false,
            "unprivileged BPF state",
        ),
    ];

    let btf_hash = fs::read("/sys/kernel/btf/vmlinux")
        .ok()
        .map(|bytes| hex_sha256(&bytes))
        .unwrap_or_default();
    if !btf_hash.is_empty() {
        checks.push(Check {
            name: "btf_sha256",
            ok: true,
            detail: btf_hash,
        });
    }

    if args.json {
        let output = serde_json::to_string_pretty(&checks).map_err(|error| error.to_string())?;
        println!("{output}");
    } else {
        println!("{:<24} {:<6} detail", "check", "state");
        for check in &checks {
            println!(
                "{:<24} {:<6} {}",
                check.name,
                if check.ok { "ok" } else { "warn" },
                check.detail
            );
        }
    }

    let required_failed = checks
        .iter()
        .any(|check| !check.ok && matches!(check.name, "kernel" | "btf" | "debugfs" | "bpffs"));
    if required_failed {
        return Err("required host check failed".to_string());
    }
    Ok(())
}

fn check_file(name: &'static str, path: &str, required: bool, detail: &str) -> Check {
    let exists = Path::new(path).exists();
    let value = if exists {
        fs::read_to_string(path)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| detail.to_string())
    } else {
        format!("missing: {path}")
    };
    Check {
        name,
        ok: exists || !required,
        detail: value,
    }
}

fn host_info() -> HostInfo {
    HostInfo {
        arch: std::env::consts::ARCH.to_string(),
        kernel_release: read_trim("/proc/sys/kernel/osrelease"),
        btf_sha256: fs::read("/sys/kernel/btf/vmlinux")
            .ok()
            .map(|bytes| hex_sha256(&bytes))
            .unwrap_or_default(),
        boot_id: read_trim("/proc/sys/kernel/random/boot_id"),
        lockdown: read_trim("/sys/kernel/security/lockdown"),
        lsm: read_trim("/sys/kernel/security/lsm")
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect(),
        unprivileged_bpf_disabled: read_trim("/proc/sys/kernel/unprivileged_bpf_disabled")
            .parse()
            .unwrap_or(0),
    }
}

fn read_trim(path: &str) -> String {
    fs::read_to_string(path)
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[allow(dead_code)]
fn manifest_summary(manifest: &Manifest) -> String {
    format!(
        "{} events, {} files, complete={}",
        manifest.counts.events,
        manifest.files.len(),
        manifest.complete
    )
}
