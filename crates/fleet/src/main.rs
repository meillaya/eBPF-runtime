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
use bpf_loader::{LoadOptions, StackMode};
use bundle::{Bundle, BundleWriter, CaptureInfo, HostInfo, Manifest};
use clap::{Args, Parser, Subcommand};
use event_model::{Event, Stack};
use runtime::decode::{decode, Clock};
use runtime::process_table::ProcessTable;
use runtime::rules_engine::Engine;
use runtime::symbolize::Symbolizer;
use serde::Serialize;
use sha2::{Digest, Sha256};
use signal_hook::consts::{SIGINT, SIGTERM};

mod top;

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
    /// Pack a bundle into a zstd-compressed tar archive.
    Pack(PackArgs),
    /// Extract a packed bundle and validate it.
    Unpack(UnpackArgs),
    /// Compare event-kind counts between two bundles.
    Diff(DiffArgs),
    /// Show live or bundle top processes, files, and event kinds.
    Top(TopArgs),
    /// Build, verify, or explain custom C probes.
    Probe(ProbeArgs),
    /// Evaluate a rule pack against a recorded bundle.
    Policy(PolicyArgs),
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
    /// Stack capture mode.
    ///
    /// `events` (the 0.3 default) captures process exec and file
    /// open/create/truncate; `all` also captures process fork/exit and file
    /// unlink/rename; `off` keeps the minimum-overhead 0.2 path.
    #[arg(long, default_value = "events", value_parser = ["off", "events", "all"])]
    stacks: String,
    /// Print stack capture and symbolization statistics as JSON.
    #[arg(long)]
    stats: bool,
    /// Flush after this many events.
    #[arg(long, default_value_t = 1000)]
    batch_events: usize,
    /// Stop after this many events. Zero means unlimited.
    #[arg(long, default_value_t = 0)]
    max_events: u64,
}

/// Aggregated per-sensor stack capture counters for `record --stats`.
#[derive(Debug, Default, Serialize)]
struct StackCaptureStats {
    kernel_captures: u64,
    kernel_failures: u64,
    user_captures: u64,
    user_failures: u64,
}

impl StackCaptureStats {
    fn add(&mut self, counters: &bpf_loader::StackCounters) {
        self.kernel_captures = self
            .kernel_captures
            .saturating_add(counters.kernel_captures);
        self.kernel_failures = self
            .kernel_failures
            .saturating_add(counters.kernel_failures);
        self.user_captures = self.user_captures.saturating_add(counters.user_captures);
        self.user_failures = self.user_failures.saturating_add(counters.user_failures);
    }
}

#[derive(Debug, Args)]
struct QueryArgs {
    /// Bundle directory.
    bundle: PathBuf,
    /// SQL against the `events` and `stacks` tables. Defaults to a kind
    /// summary over `events` (or the stack table with `--table stacks`).
    ///
    /// The tables join on `(sensor, stack_id)`:
    /// `select e.kind, e.path, s.frames from events e join stacks s
    ///  on e.sensor = s.sensor and e.stack_id = s.stack_id`.
    sql: Option<String>,
    /// Default table for the generated SQL when no SQL is given.
    #[arg(long, value_parser = ["events", "stacks"])]
    table: Option<String>,
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

#[derive(Debug, Args)]
struct PackArgs {
    /// Bundle directory.
    bundle: PathBuf,
    /// Output archive. Defaults to `<bundle>.tar.zst`.
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct UnpackArgs {
    /// Packed `.tar.zst` archive.
    archive: PathBuf,
    /// Destination bundle directory. Defaults to the archive name without `.tar.zst`.
    #[arg(short, long)]
    dest: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct DiffArgs {
    /// Earlier bundle.
    before: PathBuf,
    /// Later bundle.
    after: PathBuf,
}

#[derive(Debug, Args)]
struct ProbeArgs {
    #[command(subcommand)]
    command: ProbeCommand,
}

#[derive(Debug, Subcommand)]
enum ProbeCommand {
    /// Compile a C probe into a CO-RE object.
    Build(ProbeBuildArgs),
    /// Load a probe object through the kernel verifier.
    Verify(ProbeVerifyArgs),
    /// Explain a captured verifier log.
    Explain(ProbeExplainArgs),
}

#[derive(Debug, Args)]
struct ProbeBuildArgs {
    /// C probe source.
    source: PathBuf,
    /// Output object. Defaults to target/probe-sdk/<source>.bpf.o.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Extra include directories, repeatable.
    #[arg(long = "include")]
    include: Vec<PathBuf>,
}

#[derive(Debug, Args)]
struct ProbeVerifyArgs {
    /// Compiled probe object.
    object: PathBuf,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ProbeExplainArgs {
    /// Verifier log file. Reads stdin when omitted or `-`.
    log: Option<PathBuf>,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct TopArgs {
    /// Bundle directory. Omit for the live view.
    bundle: Option<PathBuf>,
    /// Refresh interval in milliseconds.
    #[arg(long, default_value_t = 500)]
    refresh_ms: u64,
    /// Live view stop after this many seconds.
    #[arg(long)]
    duration: Option<u64>,
}

#[derive(Debug, Args)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Evaluate rules against a bundle without loading BPF.
    Test(PolicyTestArgs),
}

#[derive(Debug, Args)]
struct PolicyTestArgs {
    /// Bundle directory.
    bundle: PathBuf,
    /// Rule directory. Defaults to rules/default.
    #[arg(long, default_value = "rules/default")]
    rules: PathBuf,
    /// Optional expectation YAML: rule, min_matches, max_matches.
    #[arg(long)]
    expect: Option<PathBuf>,
    /// Print machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, serde::Deserialize)]
struct Expectation {
    rule: String,
    #[serde(default)]
    min_matches: Option<usize>,
    #[serde(default)]
    max_matches: Option<usize>,
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
        Command::Pack(args) => pack(args),
        Command::Unpack(args) => unpack(args),
        Command::Diff(args) => diff(args).await,
        Command::Top(args) => top::run(args.bundle, args.refresh_ms, args.duration).await,
        Command::Probe(args) => match args.command {
            ProbeCommand::Build(build) => probe_build(build),
            ProbeCommand::Verify(verify) => probe_verify(verify),
            ProbeCommand::Explain(explain) => probe_explain(explain),
        },
        Command::Policy(args) => match args.command {
            PolicyCommand::Test(test) => policy_test(test).await,
        },
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
    let stack_mode = StackMode::parse(&args.stacks).ok_or_else(|| {
        format!(
            "invalid --stacks {} (expected off, events, or all)",
            args.stacks
        )
    })?;
    if args.batch_events == 0 {
        return Err("--batch-events must be greater than zero".to_string());
    }

    let names: Vec<&str> = args.sensors.iter().map(String::as_str).collect();
    let sensors = bpf_loader::load_with_options(&names, LoadOptions::with_stack_mode(stack_mode))
        .map_err(|error| error.to_string())?;
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
        stack_mode: stack_mode.as_str().to_string(),
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
    // Record-time symbolization. Stacks are de-duplicated on
    // (sensor, kernel handle, user handle): identical stacks share one
    // recorder-assigned bundle id, so one symbolization covers many events
    // and the bundle key stays joinable on (sensor, stack_id).
    let mut symbolizer = stack_mode.enabled().then(Symbolizer::new);
    let mut stacks: Vec<Stack> = Vec::new();
    let mut stack_keys: std::collections::HashMap<(String, Option<i32>, Option<i32>), usize> =
        std::collections::HashMap::new();
    let mut stack_read_errors = 0u64;

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
            if let Some(symbolizer) = symbolizer.as_mut() {
                let kernel_id = event.stack_id;
                let user_id = event.user_stack_id;
                if kernel_id.is_some() || user_id.is_some() {
                    let key = (sample.sensor.clone(), kernel_id, user_id);
                    if let Some(index) = stack_keys.get(&key).copied() {
                        if let Some(existing) = stacks.get(index) {
                            event.stack_id = Some(existing.stack_id);
                        }
                    } else {
                        match sensors.read_stack(&sample.sensor, kernel_id, user_id) {
                            Ok(raw) => {
                                // Bundle stack ids are assigned by the
                                // recorder: the raw BPF handles only
                                // identify frames, and a kernel handle is
                                // shared by many distinct user stacks.
                                let bundle_id = stacks.len() as i32 + 1;
                                let stack = symbolizer.symbolize(
                                    &sample.sensor,
                                    bundle_id,
                                    event.tgid,
                                    &raw,
                                );
                                if stack.frames.is_empty() {
                                    // Every captured frame was unusable;
                                    // do not leave a dangling join key.
                                    event.stack_id = None;
                                    event.user_stack_id = None;
                                } else {
                                    event.stack_id = Some(bundle_id);
                                    stack_keys.insert(key, stacks.len());
                                    stacks.push(stack);
                                }
                            }
                            Err(error) => {
                                stack_read_errors += 1;
                                // A dangling reference is worse than no
                                // reference: clear the handles so the
                                // event never joins to an unrelated stack.
                                event.stack_id = None;
                                event.user_stack_id = None;
                                if stack_read_errors <= 3 {
                                    eprintln!("warning: cannot read stack: {error}");
                                }
                            }
                        }
                    }
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
    if !stacks.is_empty() {
        writer
            .write_stacks(&stacks)
            .map_err(|error| error.to_string())?;
    }
    let bundle = writer.finish().map_err(|error| error.to_string())?;
    eprintln!(
        "recorded {} events and {} distinct stacks ({} decode errors) into {}",
        bundle.manifest().counts.events,
        bundle.manifest().counts.stacks,
        decode_errors,
        bundle.root().display()
    );
    if args.stats {
        print_record_stats(
            &sensors,
            symbolizer
                .as_ref()
                .map(Symbolizer::stats)
                .unwrap_or_default(),
            &stack_mode,
            &bundle,
            decode_errors,
            stack_read_errors,
        )?;
    }
    Ok(())
}

/// Print `record --stats` as stable JSON: stack capture counters (including
/// stack-map drops), stack-map geometry, and symbolization coverage. Stack
/// capture failures are non-fatal; they show up here rather than as errors.
fn print_record_stats(
    sensors: &bpf_loader::LoadedSensors,
    symbolization: runtime::symbolize::SymbolizeStats,
    stack_mode: &StackMode,
    bundle: &Bundle,
    decode_errors: u64,
    stack_read_errors: u64,
) -> Result<(), String> {
    let mut capture = StackCaptureStats::default();
    for counters in sensors.stack_counters().values() {
        capture.add(counters);
    }
    let mut maps = serde_json::Map::new();
    for sensor in &sensors.sensors {
        if let Some(info) = sensors.stack_map_info(&sensor.name) {
            maps.insert(
                sensor.name.clone(),
                serde_json::to_value(info).map_err(|error| error.to_string())?,
            );
        }
    }
    let output = serde_json::json!({
        "stack_mode": stack_mode.as_str(),
        "events": bundle.manifest().counts.events,
        "decode_errors": decode_errors,
        "stacks_written": bundle.manifest().counts.stacks,
        "stack_map_drops": capture.kernel_failures,
        "stack_capture": capture,
        "stack_maps": maps,
        "symbolization": symbolization,
        "stack_read_errors": stack_read_errors,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|error| error.to_string())?
    );
    Ok(())
}

async fn query(args: QueryArgs) -> Result<(), String> {
    let bundle = Bundle::open(&args.bundle).map_err(|error| error.to_string())?;
    let default_sql = match args.table.as_deref() {
        Some("stacks") => {
            "select stack_id, sensor, frames, truncated from stacks order by sensor, stack_id"
        }
        _ => "select kind, count(*) as n from events group by kind order by n desc",
    };
    let sql = args.sql.unwrap_or_else(|| default_sql.to_string());
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

fn pack(args: PackArgs) -> Result<(), String> {
    let bundle = Bundle::open(&args.bundle).map_err(|error| error.to_string())?;
    let output = args
        .out
        .unwrap_or_else(|| PathBuf::from(format!("{}.tar.zst", args.bundle.display())));
    bundle.pack(&output).map_err(|error| error.to_string())?;
    println!("packed {} -> {}", bundle.root().display(), output.display());
    Ok(())
}

fn unpack(args: UnpackArgs) -> Result<(), String> {
    let destination = args.dest.unwrap_or_else(|| {
        let text = args.archive.to_string_lossy();
        let trimmed = text
            .strip_suffix(".tar.zst")
            .map(str::to_string)
            .unwrap_or_else(|| format!("{text}.fleet"));
        PathBuf::from(trimmed)
    });
    let bundle = Bundle::unpack(&args.archive, &destination).map_err(|error| error.to_string())?;
    println!(
        "unpacked {} -> {} ({} events)",
        args.archive.display(),
        bundle.root().display(),
        bundle.manifest().counts.events
    );
    Ok(())
}

async fn diff(args: DiffArgs) -> Result<(), String> {
    let before = Bundle::open(&args.before).map_err(|error| error.to_string())?;
    let after = Bundle::open(&args.after).map_err(|error| error.to_string())?;
    let before_counts = kind_counts(&before).await?;
    let after_counts = kind_counts(&after).await?;
    let mut kinds = std::collections::BTreeSet::new();
    kinds.extend(before_counts.keys().cloned());
    kinds.extend(after_counts.keys().cloned());
    println!(
        "{:<24} {:>10} {:>10} {:>10}",
        "kind", "before", "after", "delta"
    );
    for kind in kinds {
        let left = before_counts.get(&kind).copied().unwrap_or(0);
        let right = after_counts.get(&kind).copied().unwrap_or(0);
        println!(
            "{:<24} {:>10} {:>10} {:>10}",
            kind,
            left,
            right,
            right as i64 - left as i64
        );
    }
    Ok(())
}

async fn kind_counts(bundle: &Bundle) -> Result<std::collections::BTreeMap<String, u64>, String> {
    let batches = bundle
        .query("select kind, count(*) as n from events group by kind order by kind")
        .await
        .map_err(|error| error.to_string())?;
    let mut counts = std::collections::BTreeMap::new();
    for batch in &batches {
        for row in 0..batch.num_rows() {
            let kind = arrow::util::display::array_value_to_string(batch.column(0).as_ref(), row)
                .map_err(|error| error.to_string())?;
            let count = arrow::util::display::array_value_to_string(batch.column(1).as_ref(), row)
                .map_err(|error| error.to_string())?
                .parse::<u64>()
                .map_err(|error| error.to_string())?;
            counts.insert(kind, count);
        }
    }
    Ok(counts)
}

async fn policy_test(args: PolicyTestArgs) -> Result<(), String> {
    let bundle = Bundle::open(&args.bundle).map_err(|error| error.to_string())?;
    let mut engine =
        Engine::load(&args.rules).map_err(|error| format!("{}: {error}", args.rules.display()))?;
    for error in engine.errors() {
        eprintln!("warning: {error}");
    }
    let batches = bundle
        .query("select raw_json from events order by time_unix_ns, seq")
        .await
        .map_err(|error| error.to_string())?;
    let mut events = Vec::new();
    for batch in &batches {
        for row in 0..batch.num_rows() {
            let raw = arrow::util::display::array_value_to_string(batch.column(0).as_ref(), row)
                .map_err(|error| error.to_string())?;
            let event: Event = serde_json::from_str(&raw)
                .map_err(|error| format!("bundle event is not valid JSON: {error}"))?;
            events.push(event);
        }
    }
    events.sort_by(|left, right| {
        left.time
            .cmp(&right.time)
            .then_with(|| left.seq.cmp(&right.seq))
    });

    let mut matches = std::collections::BTreeMap::<String, usize>::new();
    let mut alert_count = 0usize;
    for event in &events {
        for alert in engine.evaluate(event) {
            alert_count += 1;
            *matches.entry(alert.rule).or_default() += 1;
        }
    }

    let mut expectation_result = None;
    if let Some(path) = &args.expect {
        let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
        let expectation: Expectation =
            serde_yaml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        let actual = matches.get(&expectation.rule).copied().unwrap_or(0);
        let min_ok = expectation
            .min_matches
            .map(|min| actual >= min)
            .unwrap_or(true);
        let max_ok = expectation
            .max_matches
            .map(|max| actual <= max)
            .unwrap_or(true);
        expectation_result = Some((expectation, actual, min_ok && max_ok));
    }

    if args.json {
        let output = serde_json::json!({
            "events": events.len(),
            "alerts": alert_count,
            "rules": engine.rule_count(),
            "skipped_sequence_rules": engine.skipped_sequences(),
            "matches": matches,
            "expectation": expectation_result.as_ref().map(|(expectation, actual, passed)| {
                serde_json::json!({
                    "rule": expectation.rule,
                    "actual": actual,
                    "min_matches": expectation.min_matches,
                    "max_matches": expectation.max_matches,
                    "passed": passed,
                })
            }),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|error| error.to_string())?
        );
    } else {
        println!(
            "{} events, {} alerts, {} rules ({} sequence rules skipped)",
            events.len(),
            alert_count,
            engine.rule_count(),
            engine.skipped_sequences()
        );
        for (rule, count) in &matches {
            println!("{:<40} {:>8}", rule, count);
        }
        if matches.is_empty() {
            println!("no rule matched");
        }
        if let Some((expectation, actual, passed)) = expectation_result {
            println!(
                "expectation {}: actual={} min={:?} max={:?} {}",
                expectation.rule,
                actual,
                expectation.min_matches,
                expectation.max_matches,
                if passed { "PASS" } else { "FAIL" }
            );
            if !passed {
                return Err("policy expectation failed".to_string());
            }
        }
    }
    Ok(())
}

fn probe_build(args: ProbeBuildArgs) -> Result<(), String> {
    let out = args.out.unwrap_or_else(|| {
        let name = args
            .source
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("probe");
        probe::default_out_dir().join(format!("{name}.bpf.o"))
    });
    let artifact =
        probe::build(&args.source, &out, &args.include).map_err(|error| error.to_string())?;
    println!(
        "built {} -> {} ({} bytes, clang {})",
        artifact.source.display(),
        artifact.object.display(),
        artifact.size_bytes,
        artifact.clang.display()
    );
    Ok(())
}

fn probe_verify(args: ProbeVerifyArgs) -> Result<(), String> {
    let report = probe::verify(&args.object).map_err(|error| error.to_string())?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        println!(
            "{}: {:?} ({} programs, {} maps)",
            report.object.display(),
            report.status,
            report.programs.len(),
            report.maps.len()
        );
        for program in &report.programs {
            println!("  program {} {}", program.section, program.name);
        }
        for map in &report.maps {
            println!(
                "  map {} {} max_entries={}",
                map.map_type, map.name, map.max_entries
            );
        }
        if let Some(error) = &report.error {
            eprintln!("{error}");
        }
        for hint in &report.hints {
            eprintln!("hint: {hint}");
        }
        if let Some(explanation) = report.explanation() {
            println!("{}", explanation.render());
        }
    }
    if report.loaded() {
        Ok(())
    } else {
        Err(format!("probe did not load: {:?}", report.status))
    }
}

fn probe_explain(args: ProbeExplainArgs) -> Result<(), String> {
    let text = match args.log {
        Some(path) if path != Path::new("-") => std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?,
        _ => {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
                .map_err(|error| error.to_string())?;
            text
        }
    };
    let explanation = probe::explain(&text);
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&explanation).map_err(|error| error.to_string())?
        );
    } else {
        println!("{}", explanation.render());
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
