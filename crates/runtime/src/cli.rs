// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Command line interface.
//!
//! `run` attaches the selected sensors and writes one JSON object per
//! event. `check` loads the sensors and prints what attached. `rules`
//! validates a rule directory without touching the kernel.

use std::collections::HashMap;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand};
use signal_hook::consts::{SIGINT, SIGTERM};

use crate::decode::{decode, Clock, DecodedEvent};
use crate::process_table::ProcessTable;
use crate::rules_engine::{Alert, Engine};

/// Default sensors for `run`. The other sensors are either incomplete or
/// need a kernel feature this build does not assume.
const DEFAULT_SENSORS: &str = "process,file";

#[derive(Debug, Parser)]
#[command(
    name = "ebpf-runtime",
    version,
    about = "Trace process and file activity with eBPF",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Attach sensors and print events.
    Run(RunArgs),
    /// Load the sensors and print what attached.
    Check(CheckArgs),
    /// Validate a rule directory.
    Rules(RulesArgs),
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Comma separated sensors. Default: process,file.
    #[arg(long, value_delimiter = ',', default_value = DEFAULT_SENSORS)]
    sensors: Vec<String>,
    /// Rule directory. Default: rules/default when it exists.
    #[arg(long)]
    rules: Option<PathBuf>,
    /// Do not load any rules.
    #[arg(long)]
    no_rules: bool,
    /// Human readable lines instead of JSON.
    #[arg(long)]
    pretty: bool,
    /// Stop after this many seconds. Zero runs until interrupted.
    #[arg(long, default_value_t = 0)]
    duration: u64,
    /// Only print events for this pid or tgid.
    #[arg(long)]
    pid: Option<u32>,
    /// Do not print the summary.
    #[arg(long)]
    quiet: bool,
}

#[derive(Debug, Args)]
struct CheckArgs {
    /// Comma separated sensors. Default: every embedded sensor.
    #[arg(long, value_delimiter = ',')]
    sensors: Vec<String>,
    /// Print the coverage matrix as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RulesArgs {
    #[command(subcommand)]
    command: RulesCommand,
}

#[derive(Debug, Subcommand)]
enum RulesCommand {
    /// Parse every rule file in a directory.
    Check {
        /// Directory with `.yaml` or `.yml` rule files.
        #[arg(default_value = "rules/default")]
        dir: PathBuf,
    },
}

/// Entry point used by `main`.
pub fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Run(args) => run(args),
        Command::Check(args) => check(args),
        Command::Rules(args) => match args.command {
            RulesCommand::Check { dir } => rules_check(&dir),
        },
    };

    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("ebpf-runtime: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: RunArgs) -> Result<ExitCode, String> {
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
        return Err("no sensor attached; run check for the failure reasons".to_string());
    }

    let (ring, events) = sensors.ring_reader().map_err(|error| error.to_string())?;

    let mut engine = load_engine(&args)?;
    if let Some(engine) = &engine {
        for error in engine.errors() {
            eprintln!("warning: rule file skipped: {error}");
        }
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, shutdown.clone()).map_err(|error| error.to_string())?;
    signal_hook::flag::register(SIGTERM, shutdown.clone()).map_err(|error| error.to_string())?;

    let clock = Clock::new();
    let mut processes = ProcessTable::new();
    let deadline = (args.duration > 0).then(|| Instant::now() + Duration::from_secs(args.duration));
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut recent_opens: HashMap<(u32, String), u64> = HashMap::new();
    let mut event_count = 0u64;
    let mut decode_errors = 0u64;
    let mut alerts = 0u64;

    while !shutdown.load(Ordering::Relaxed) {
        if deadline
            .map(|deadline| Instant::now() >= deadline)
            .unwrap_or(false)
        {
            break;
        }

        if let Err(error) = ring.poll(Duration::from_millis(200)) {
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
            if duplicate_open(&mut recent_opens, &event) {
                continue;
            }

            event_count += 1;
            if args.pretty {
                writeln!(out, "{}", pretty(&event)).map_err(|error| error.to_string())?;
            } else {
                let line = serde_json::to_string(&event).map_err(|error| error.to_string())?;
                writeln!(out, "{line}").map_err(|error| error.to_string())?;
            }

            if let Some(engine) = engine.as_mut() {
                for alert in engine.evaluate(&event) {
                    alerts += 1;
                    write_alert(&alert, args.pretty)?;
                }
            }
        }

        out.flush().map_err(|error| error.to_string())?;
    }

    out.flush().map_err(|error| error.to_string())?;
    drop(out);

    if !args.quiet {
        eprintln!(
            "{} events, {} decode errors, {} alerts",
            event_count, decode_errors, alerts
        );
    }

    Ok(ExitCode::SUCCESS)
}

fn check(args: CheckArgs) -> Result<ExitCode, String> {
    let names: Vec<&str> = args.sensors.iter().map(String::as_str).collect();
    let sensors = bpf_loader::load(&names).map_err(|error| error.to_string())?;

    if args.json {
        println!("{}", sensors.coverage_as_json());
    } else {
        println!(
            "{:<9} {:<9} {:>9} {:>7} {:>8}",
            "sensor", "status", "attached", "failed", "skipped"
        );
        for sensor in &sensors.coverage.sensors {
            println!(
                "{:<9} {:<9} {:>9} {:>7} {:>8}",
                sensor.name,
                status_name(sensor.status),
                sensor.programs.len(),
                sensor.errors.len(),
                sensor.skipped.len()
            );
            for error in &sensor.errors {
                eprintln!("  {}: {error}", sensor.name);
            }
        }
    }

    if sensors
        .coverage
        .sensors
        .iter()
        .any(|sensor| sensor.status != bpf_loader::SensorStatus::Blocked)
    {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}

fn rules_check(dir: &Path) -> Result<ExitCode, String> {
    let engine = Engine::load(dir).map_err(|error| error.to_string())?;
    for error in engine.errors() {
        eprintln!("{error}");
    }

    println!(
        "{} rules, {} sequence rules skipped",
        engine.rule_count(),
        engine.skipped_sequences()
    );

    if engine.errors().is_empty() && engine.rule_count() > 0 {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}

fn load_engine(args: &RunArgs) -> Result<Option<Engine>, String> {
    if args.no_rules {
        return Ok(None);
    }

    let directory = match &args.rules {
        Some(directory) => directory.clone(),
        None => {
            let default = PathBuf::from("rules/default");
            if !default.is_dir() {
                return Ok(None);
            }
            default
        }
    };

    if !directory.is_dir() {
        return Err(format!("{} is not a directory", directory.display()));
    }

    let engine = Engine::load(&directory).map_err(|error| error.to_string())?;
    Ok(Some(engine))
}

fn status_name(status: bpf_loader::SensorStatus) -> &'static str {
    match status {
        bpf_loader::SensorStatus::Capable => "capable",
        bpf_loader::SensorStatus::Degraded => "degraded",
        bpf_loader::SensorStatus::Blocked => "blocked",
    }
}

fn write_alert(alert: &Alert, pretty: bool) -> Result<(), String> {
    let stderr = std::io::stderr();
    let mut err = stderr.lock();
    if pretty {
        writeln!(
            err,
            "alert {} {}: {} (pid {} path {})",
            alert.severity,
            alert.rule,
            short_description(&alert.description),
            alert.event.pid,
            alert.event.path.as_deref().unwrap_or("-")
        )
        .map_err(|error| error.to_string())?;
    } else {
        let line = serde_json::to_string(alert).map_err(|error| error.to_string())?;
        writeln!(err, "{line}").map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn pretty(event: &DecodedEvent) -> String {
    let time = event.time.get(11..23).unwrap_or(&event.time);
    match event.kind.as_str() {
        "ProcessExec" => format!(
            "{time} process exec pid={} tgid={} path={}",
            event.pid,
            event.tgid,
            event.path.as_deref().unwrap_or("-")
        ),
        "ProcessFork" => format!(
            "{time} process fork parent={} child={}",
            event.parent_pid.unwrap_or(0),
            event.child_pid.unwrap_or(0)
        ),
        "ProcessExit" => format!(
            "{time} process exit pid={} code={}{}",
            event.pid,
            event.exit_code.unwrap_or(0),
            if event.thread == Some(true) {
                " thread"
            } else {
                ""
            }
        ),
        "FileOpen" | "FileCreate" | "FileUnlink" | "FileTruncate" => format!(
            "{time} file {} pid={} path={} process={}",
            event.kind.trim_start_matches("File").to_lowercase(),
            event.pid,
            event.path.as_deref().unwrap_or("-"),
            event.process_exec.as_deref().unwrap_or("-")
        ),
        "FileRename" => format!(
            "{time} file rename pid={} from={} to={}",
            event.pid,
            event.old_path.as_deref().unwrap_or("-"),
            event.path.as_deref().unwrap_or("-")
        ),
        "NetworkConnect" => format!(
            "{time} network connect pid={} dst={}",
            event.pid,
            network_target(event)
        ),
        "NetworkAccept" => format!(
            "{time} network accept pid={} peer={}",
            event.pid,
            network_target(event)
        ),
        "DnsPacket" => format!(
            "{time} dns pid={} qname={}",
            event.pid,
            event
                .dns
                .as_ref()
                .map(|dns| dns.qname.as_str())
                .unwrap_or("-")
        ),
        "SyscallEnter" | "SyscallExit" => format!(
            "{time} syscall pid={} nr={} name={} latency_ns={}",
            event.pid,
            event
                .syscall
                .as_ref()
                .map(|syscall| syscall.nr)
                .unwrap_or(0),
            event
                .syscall
                .as_ref()
                .map(|syscall| syscall.name.as_str())
                .unwrap_or("-"),
            event
                .syscall
                .as_ref()
                .map(|syscall| syscall.latency_ns)
                .unwrap_or(0)
        ),
        "Identity" => format!(
            "{time} identity pid={} uid={} cgroup={}",
            event.pid,
            event
                .identity
                .as_ref()
                .map(|identity| identity.uid)
                .unwrap_or(0),
            event.cgroup_id
        ),
        "LsmDecision" => format!(
            "{time} lsm pid={} hook={} decision={} selector={}",
            event.pid,
            event.lsm.as_ref().map(|lsm| lsm.hook).unwrap_or(0),
            event.lsm.as_ref().map(|lsm| lsm.decision).unwrap_or(0),
            event
                .lsm
                .as_ref()
                .map(|lsm| lsm.selector.as_str())
                .unwrap_or("-")
        ),
        other => format!("{time} {} pid={}", other, event.pid),
    }
}

fn duplicate_open(recent: &mut HashMap<(u32, String), u64>, event: &DecodedEvent) -> bool {
    if event.kind != "FileOpen" {
        return false;
    }
    let Some(path) = &event.path else {
        return false;
    };

    let key = (event.tgid, path.clone());
    if let Some(last) = recent.get(&key) {
        if event.monotonic_ns.saturating_sub(*last) < 50_000_000 {
            return true;
        }
    }

    if recent.len() >= 4096 {
        recent.clear();
    }
    recent.insert(key, event.monotonic_ns);
    false
}

fn short_description(description: &str) -> String {
    let first = description.split(". ").next().unwrap_or(description);
    if first.chars().count() <= 110 {
        first.to_string()
    } else {
        let mut short: String = first.chars().take(107).collect();
        short.push_str("...");
        short
    }
}

fn network_target(event: &DecodedEvent) -> String {
    match &event.network {
        Some(network) => format!(
            "{}:{}",
            network.address.as_deref().unwrap_or("-"),
            network.port.unwrap_or(0)
        ),
        None => "-".to_string(),
    }
}
