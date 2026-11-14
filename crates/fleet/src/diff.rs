// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ebpf-fleet diff`: compare two bundles.
//!
//! The default (no `--by`) behaviour is the 0.2 kind-count table. `--by`
//! adds process, path, and stack keys; `--limit` keeps the largest absolute
//! deltas; `--json` emits a machine-readable report.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

use bundle::Bundle;
use clap::{Args, ValueEnum};
use serde::Serialize;

/// What to group event counts by when diffing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DiffBy {
    /// Event kind (the default, 0.2-compatible behaviour).
    Kind,
    /// Process executable (falls back to the event path, then `?`).
    Process,
    /// File path (falls back to the old path, then `?`).
    Path,
    /// Resolved stack label (first symbolized frame).
    Stack,
}

impl DiffBy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Kind => "kind",
            Self::Process => "process",
            Self::Path => "path",
            Self::Stack => "stack",
        }
    }
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Earlier bundle.
    pub before: PathBuf,
    /// Later bundle.
    pub after: PathBuf,
    /// Group counts by kind (default), process, path, or stack.
    #[arg(long, value_enum)]
    pub by: Option<DiffBy>,
    /// Keep only this many rows (the largest absolute deltas when `--by`
    /// is used; the alphabetically first keys for the default kind table).
    #[arg(long)]
    pub limit: Option<usize>,
    /// Print machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
struct DiffRow {
    key: String,
    before: u64,
    after: u64,
    delta: i64,
}

#[derive(Debug, Serialize)]
struct DiffTotals {
    before: u64,
    after: u64,
    delta: i64,
}

#[derive(Debug, Serialize)]
struct DiffReport<'a> {
    by: &'a str,
    limit: Option<usize>,
    before_bundle: String,
    after_bundle: String,
    rows: &'a [DiffRow],
    totals: DiffTotals,
}

pub async fn run(args: DiffArgs) -> Result<(), String> {
    let before = Bundle::open(&args.before).map_err(|error| error.to_string())?;
    let after = Bundle::open(&args.after).map_err(|error| error.to_string())?;
    let by = args.by.unwrap_or(DiffBy::Kind);
    let before_counts = grouped_counts(&before, by).await?;
    let after_counts = grouped_counts(&after, by).await?;

    let mut keys: BTreeSet<&String> = BTreeSet::new();
    keys.extend(before_counts.keys());
    keys.extend(after_counts.keys());
    let mut rows: Vec<DiffRow> = keys
        .into_iter()
        .map(|key| {
            let left = before_counts.get(key).copied().unwrap_or(0);
            let right = after_counts.get(key).copied().unwrap_or(0);
            DiffRow {
                key: key.clone(),
                before: left,
                after: right,
                delta: right as i64 - left as i64,
            }
        })
        .collect();

    // The default kind table keeps the 0.2 key ordering; `--by` modes sort
    // by the size of the change so `--limit` shows what moved most.
    if args.by.is_some() {
        rows.sort_by(|left, right| {
            right
                .delta
                .abs()
                .cmp(&left.delta.abs())
                .then_with(|| left.key.cmp(&right.key))
        });
    } else {
        rows.sort_by(|left, right| left.key.cmp(&right.key));
    }
    if let Some(limit) = args.limit {
        rows.truncate(limit);
    }

    let totals = DiffTotals {
        before: rows.iter().map(|row| row.before).sum(),
        after: rows.iter().map(|row| row.after).sum(),
        delta: rows.iter().map(|row| row.delta).sum(),
    };

    if args.json {
        let report = DiffReport {
            by: by.as_str(),
            limit: args.limit,
            before_bundle: args.before.display().to_string(),
            after_bundle: args.after.display().to_string(),
            rows: &rows,
            totals,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
        return Ok(());
    }

    // The default (no --by) table keeps the exact 0.2 column width so
    // scripts that parse it are unaffected; --by modes size to content.
    let width = if args.by.is_none() {
        24
    } else {
        rows.iter()
            .map(|row| row.key.len())
            .max()
            .unwrap_or(0)
            .max(by.as_str().len())
            .clamp(4, 80)
    };
    println!(
        "{:<width$} {:>10} {:>10} {:>10}",
        by.as_str(),
        "before",
        "after",
        "delta",
        width = width
    );
    for row in &rows {
        println!(
            "{:<width$} {:>10} {:>10} {:>10}",
            row.key,
            row.before,
            row.after,
            row.delta,
            width = width
        );
    }
    Ok(())
}

async fn grouped_counts(bundle: &Bundle, by: DiffBy) -> Result<BTreeMap<String, u64>, String> {
    match by {
        DiffBy::Kind => {
            two_column_counts(
                bundle,
                "select kind, count(*) as n from events group by kind order by kind",
            )
            .await
        }
        DiffBy::Process => {
            two_column_counts(
                bundle,
                "select coalesce(process_exec, path, '?') as k, count(*) as n \
                 from events group by k order by k",
            )
            .await
        }
        DiffBy::Path => {
            two_column_counts(
                bundle,
                "select coalesce(path, old_path, '?') as k, count(*) as n \
                 from events group by k order by k",
            )
            .await
        }
        DiffBy::Stack => stack_counts(bundle).await,
    }
}

async fn two_column_counts(bundle: &Bundle, sql: &str) -> Result<BTreeMap<String, u64>, String> {
    let batches = bundle.query(sql).await.map_err(|error| error.to_string())?;
    let mut counts = BTreeMap::new();
    for batch in &batches {
        for row in 0..batch.num_rows() {
            let key = arrow::util::display::array_value_to_string(batch.column(0).as_ref(), row)
                .map_err(|error| error.to_string())?;
            let count = arrow::util::display::array_value_to_string(batch.column(1).as_ref(), row)
                .map_err(|error| error.to_string())?
                .parse::<u64>()
                .map_err(|error| error.to_string())?;
            counts.insert(key, count);
        }
    }
    Ok(counts)
}

async fn stack_counts(bundle: &Bundle) -> Result<BTreeMap<String, u64>, String> {
    // A v1 (0.2) bundle has no stacks table and no `events.stack_id`
    // column; there is nothing to group.
    if bundle.format_version() < 2 {
        return Ok(BTreeMap::new());
    }
    // Bundle stack ids are recorder-assigned and join on
    // `(sensor, stack_id)`; map them to a human-readable label from the
    // first symbolized frame.
    let labels: HashMap<(String, i32), String> = bundle
        .read_stacks()
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|stack| {
            let label = stack
                .frames
                .iter()
                .find_map(|frame| frame.symbol.clone())
                .or_else(|| {
                    stack
                        .frames
                        .first()
                        .map(|frame| format!("{:#x}", frame.addr))
                })
                .unwrap_or_else(|| "empty".to_string());
            ((stack.sensor.clone(), stack.stack_id), label)
        })
        .collect();

    let batches = bundle
        .query(
            "select sensor, stack_id, count(*) as n from events \
             where stack_id is not null group by sensor, stack_id order by n desc",
        )
        .await
        .map_err(|error| error.to_string())?;
    let mut counts = BTreeMap::new();
    for batch in &batches {
        for row in 0..batch.num_rows() {
            let sensor = arrow::util::display::array_value_to_string(batch.column(0).as_ref(), row)
                .map_err(|error| error.to_string())?;
            let stack_id =
                arrow::util::display::array_value_to_string(batch.column(1).as_ref(), row)
                    .map_err(|error| error.to_string())?
                    .parse::<i32>()
                    .map_err(|error| error.to_string())?;
            let count = arrow::util::display::array_value_to_string(batch.column(2).as_ref(), row)
                .map_err(|error| error.to_string())?
                .parse::<u64>()
                .map_err(|error| error.to_string())?;
            let key = labels
                .get(&(sensor.clone(), stack_id))
                .cloned()
                .unwrap_or_else(|| format!("{sensor}#{stack_id}"));
            *counts.entry(key).or_default() += count;
        }
    }
    Ok(counts)
}
