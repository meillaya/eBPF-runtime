// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ebpf-fleet inspect`: one-screen bundle summary and integrity check.
//!
//! Opening a bundle already validates the manifest, the path layout, and
//! every Parquet part SHA-256 (`Bundle::open`). `inspect` surfaces those
//! facts plus host/capture metadata, per-table row/part counts, stack
//! symbolization coverage, and custom-probe rows, as a table or JSON.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use bundle::{Bundle, Counts, HostInfo};
use clap::Args;
use serde::Serialize;

#[derive(Debug, Args)]
pub struct InspectArgs {
    /// Bundle directory.
    pub bundle: PathBuf,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Default, Serialize)]
struct PartSummary {
    files: u64,
    rows: u64,
    bytes: u64,
}

#[derive(Debug, Default, Serialize)]
struct StackCoverage {
    stacks: u64,
    frames: u64,
    kernel_frames: u64,
    user_frames: u64,
    kernel_symbolized: u64,
    user_symbolized: u64,
    missing_symbols: u64,
    truncated_stacks: u64,
    sensors: BTreeMap<String, u64>,
}

#[derive(Debug, Default, Serialize)]
struct ProbeSummary {
    rows: u64,
    probes: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize)]
struct ToolSummary {
    version: String,
    commit: String,
}

#[derive(Debug, Serialize)]
struct SchemaSummary {
    arrow_version: u32,
    arrow_sha256: String,
}

#[derive(Debug, Serialize)]
struct InspectReport {
    bundle: String,
    format: String,
    format_version: u32,
    complete: bool,
    created_at: String,
    integrity: String,
    tool: ToolSummary,
    schema: SchemaSummary,
    host: HostInfo,
    capture: bundle::CaptureInfo,
    counts: Counts,
    parts: BTreeMap<String, PartSummary>,
    total_bytes: u64,
    stack_coverage: StackCoverage,
    probe_events: ProbeSummary,
}

pub async fn run(args: InspectArgs) -> Result<(), String> {
    let bundle = Bundle::open(&args.bundle).map_err(|error| error.to_string())?;
    let report = build_report(&args.bundle, &bundle).await?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        print_text(&report);
    }
    Ok(())
}

async fn build_report(path: &std::path::Path, bundle: &Bundle) -> Result<InspectReport, String> {
    let manifest = bundle.manifest();
    let mut parts: BTreeMap<String, PartSummary> = BTreeMap::new();
    for table in Bundle::TABLES {
        parts.insert((*table).to_string(), PartSummary::default());
    }
    let mut total_bytes = 0u64;
    for file in &manifest.files {
        let table = if file.path.starts_with("probe_events/") {
            "probe_events"
        } else if file.path.starts_with("stacks/") {
            "stacks"
        } else if file.path.starts_with("events/") {
            "events"
        } else {
            continue;
        };
        let bytes = fs::metadata(bundle.root().join(&file.path))
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let summary = parts.entry(table.to_string()).or_default();
        summary.files += 1;
        summary.rows += file.rows;
        summary.bytes += bytes;
        total_bytes += bytes;
    }

    let stacks = bundle
        .read_stacks()
        .await
        .map_err(|error| error.to_string())?;
    let mut coverage = StackCoverage {
        stacks: stacks.len() as u64,
        ..StackCoverage::default()
    };
    for stack in &stacks {
        coverage.frames += stack.frames.len() as u64;
        if stack.truncated {
            coverage.truncated_stacks += 1;
        }
        *coverage.sensors.entry(stack.sensor.clone()).or_default() += 1;
        for frame in &stack.frames {
            if frame.is_kernel {
                coverage.kernel_frames += 1;
            } else {
                coverage.user_frames += 1;
            }
            if frame.symbol.is_some() {
                if frame.is_kernel {
                    coverage.kernel_symbolized += 1;
                } else {
                    coverage.user_symbolized += 1;
                }
            } else {
                coverage.missing_symbols += 1;
            }
        }
    }

    let probe_records = bundle
        .read_probe_events()
        .await
        .map_err(|error| error.to_string())?;
    let mut probe_events = ProbeSummary {
        rows: probe_records.len() as u64,
        ..ProbeSummary::default()
    };
    for record in &probe_records {
        *probe_events.probes.entry(record.probe.clone()).or_default() += 1;
    }

    Ok(InspectReport {
        bundle: path.display().to_string(),
        format: manifest.format.clone(),
        format_version: bundle.format_version(),
        complete: manifest.complete,
        created_at: manifest.created_at.clone(),
        integrity: format!(
            "ok (manifest, path layout, and {} part SHA-256 hashes validated)",
            manifest.files.len()
        ),
        tool: ToolSummary {
            version: manifest.tool.version.clone(),
            commit: manifest.tool.commit.clone(),
        },
        schema: SchemaSummary {
            arrow_version: manifest.schema.arrow_version,
            arrow_sha256: manifest.schema.arrow_sha256.clone(),
        },
        host: manifest.host.clone(),
        capture: manifest.capture.clone(),
        counts: manifest.counts.clone(),
        parts,
        total_bytes,
        stack_coverage: coverage,
        probe_events,
    })
}

fn print_text(report: &InspectReport) {
    println!("bundle:      {}", report.bundle);
    println!(
        "format:      {} (format v{}, arrow schema v{})",
        report.format, report.format_version, report.schema.arrow_version
    );
    println!("created:     {}", report.created_at);
    println!(
        "tool:        ebpf-fleet {} (commit {})",
        report.tool.version,
        if report.tool.commit.is_empty() {
            "-"
        } else {
            &report.tool.commit
        }
    );
    println!("complete:    {}", report.complete);
    println!("integrity:   {}", report.integrity);
    println!(
        "host:        {} kernel {} boot {} lockdown {} lsm {} btf {}",
        report.host.arch,
        display_or(&report.host.kernel_release, "-"),
        display_or(&report.host.boot_id, "-"),
        display_or(&report.host.lockdown, "-"),
        if report.host.lsm.is_empty() {
            "-".to_string()
        } else {
            report.host.lsm.join(",")
        },
        display_or(&report.host.btf_sha256, "-"),
    );
    println!(
        "capture:     sensors={} duration={}ms stack_mode={}",
        if report.capture.sensors.is_empty() {
            "-".to_string()
        } else {
            report.capture.sensors.join(",")
        },
        report.capture.duration_ms,
        display_or(&report.capture.stack_mode, "-"),
    );
    println!(
        "counts:      events={} stacks={} probe_events={} dropped={}",
        report.counts.events,
        report.counts.stacks,
        report.counts.probe_events,
        if report.counts.dropped.is_empty() {
            "-".to_string()
        } else {
            report
                .counts
                .dropped
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(",")
        }
    );
    println!("parts:       ({} bytes total)", report.total_bytes);
    for (table, summary) in &report.parts {
        println!(
            "  {:<14} {:>3} files {:>8} rows {:>12} bytes",
            table, summary.files, summary.rows, summary.bytes
        );
    }
    println!(
        "stack coverage: {} stacks, {} frames ({} kernel / {} user), \
         {} kernel symbolized, {} user symbolized, {} missing symbols, {} truncated",
        report.stack_coverage.stacks,
        report.stack_coverage.frames,
        report.stack_coverage.kernel_frames,
        report.stack_coverage.user_frames,
        report.stack_coverage.kernel_symbolized,
        report.stack_coverage.user_symbolized,
        report.stack_coverage.missing_symbols,
        report.stack_coverage.truncated_stacks,
    );
    if !report.stack_coverage.sensors.is_empty() {
        println!(
            "stack sensors: {}",
            report
                .stack_coverage
                .sensors
                .iter()
                .map(|(sensor, count)| format!("{sensor}={count}"))
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    println!(
        "probe events: {} rows{}",
        report.probe_events.rows,
        if report.probe_events.probes.is_empty() {
            String::new()
        } else {
            format!(
                " ({})",
                report
                    .probe_events
                    .probes
                    .iter()
                    .map(|(probe, count)| format!("{probe}={count}"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    );
}

fn display_or(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}
