// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ebpf-fleet query`: SQL over a bundle with streaming output formats.
//!
//! The default behaviour is unchanged: with no SQL the command prints a kind
//! summary table. `--format` selects the row encoding, `--out` writes to a
//! file instead of stdout, `--limit` stops the stream early, `--table`
//! chooses the default SQL/schema, `--schema` prints the Arrow schema of a
//! table, and `--explain` prints the DataFusion plan for the SQL.
//!
//! Formats:
//!
//! * `table` (default): aligned text table, collected before printing.
//! * `json`: **newline-delimited JSON**, one object per row (streamable).
//! * `csv`: RFC 4180 CSV with a header row (streamable).
//! * `parquet`: one Parquet file written with the Arrow writer; requires
//!   `--out` (streamable, bounded memory).

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use arrow::array::RecordBatch;
use arrow::csv::Writer as CsvWriter;
use arrow::json::LineDelimitedWriter;
use arrow::util::pretty::pretty_format_batches;
use bundle::Bundle;
use clap::{Args, ValueEnum};
use futures::StreamExt;
use parquet::arrow::ArrowWriter;

/// Output encoding of `query`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Aligned text table (default).
    Table,
    /// Newline-delimited JSON objects, one per row.
    Json,
    /// RFC 4180 CSV with a header row.
    Csv,
    /// Parquet file (requires `--out`).
    Parquet,
}

impl OutputFormat {
    /// Stable name used in diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Table => "table",
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Parquet => "parquet",
        }
    }
}

#[derive(Debug, Args)]
pub struct QueryArgs {
    /// Bundle directory.
    pub bundle: PathBuf,
    /// SQL against the `events`, `stacks`, and `probe_events` tables.
    /// Defaults to a kind summary over `events` (or the stack / probe-event
    /// table with `--table`).
    ///
    /// The tables join on `(sensor, stack_id)`:
    /// `select e.kind, e.path, s.frames from events e join stacks s
    ///  on e.sensor = s.sensor and e.stack_id = s.stack_id`.
    pub sql: Option<String>,
    /// Default table for the generated SQL (and the table `--schema` prints).
    #[arg(long, value_parser = ["events", "stacks", "probe_events"])]
    pub table: Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub format: OutputFormat,
    /// Write output to this file instead of stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Stop after this many rows (0 means no rows; omitted means all rows).
    #[arg(long)]
    pub limit: Option<usize>,
    /// Print the Arrow schema of `--table` (default `events`) and exit.
    #[arg(long)]
    pub schema: bool,
    /// Print the DataFusion plan for the SQL instead of executing it.
    #[arg(long)]
    pub explain: bool,
}

/// The generated SQL for `--table` when no explicit SQL is given. These are
/// the 0.2/0.3 defaults and must stay stable.
fn default_sql(table: &str) -> &'static str {
    match table {
        "stacks" => {
            "select stack_id, sensor, frames, truncated from stacks order by sensor, stack_id"
        }
        "probe_events" => {
            "select probe, kind, kind_name, count(*) as n from probe_events \
             group by probe, kind, kind_name order by n desc"
        }
        _ => "select kind, count(*) as n from events group by kind order by n desc",
    }
}

pub async fn run(args: QueryArgs) -> Result<(), String> {
    let bundle = Bundle::open(&args.bundle).map_err(|error| error.to_string())?;

    if args.schema {
        let table = args.table.as_deref().unwrap_or("events");
        let schema = bundle.table_schema(table).ok_or_else(|| {
            format!(
                "unknown table `{table}`; expected one of: {}",
                Bundle::TABLES.join(", ")
            )
        })?;
        let mut text = format!("# {table} ({} fields)\n", schema.fields().len());
        for field in schema.fields() {
            text.push_str(&format!(
                "{:<24} {:<32} {}\n",
                field.name(),
                format!("{:?}", field.data_type()),
                if field.is_nullable() {
                    "nullable"
                } else {
                    "not null"
                }
            ));
        }
        write_text_output(args.out.as_deref(), &text)?;
        return Ok(());
    }

    let table = args.table.as_deref().unwrap_or("events");
    let sql = args
        .sql
        .clone()
        .unwrap_or_else(|| default_sql(table).to_string());

    if args.explain {
        let explain = format!("EXPLAIN {sql}");
        let mut stream = bundle
            .query_stream(&explain)
            .await
            .map_err(|error| error.to_string())?;
        let mut batches = Vec::new();
        while let Some(batch) = stream.batches.next().await {
            batches.push(batch.map_err(|error| error.to_string())?);
        }
        let text = pretty_format_batches(&batches)
            .map_err(|error| error.to_string())?
            .to_string();
        write_text_output(args.out.as_deref(), &format!("{text}\n"))?;
        return Ok(());
    }

    let query = bundle
        .query_stream(&sql)
        .await
        .map_err(|error| error.to_string())?;
    let mut sink = Sink::new(args.format, args.out.as_deref(), &query.schema)?;
    let mut stream = query.batches;
    let mut emitted = 0usize;
    while let Some(batch) = stream.next().await {
        let batch = batch.map_err(|error| error.to_string())?;
        if batch.num_rows() == 0 {
            continue;
        }
        let take = match args.limit {
            Some(limit) => {
                if emitted >= limit {
                    break;
                }
                (limit - emitted).min(batch.num_rows())
            }
            None => batch.num_rows(),
        };
        let batch = if take < batch.num_rows() {
            batch.slice(0, take)
        } else {
            batch
        };
        sink.write(&batch)?;
        emitted += take;
        if args.limit.map(|limit| emitted >= limit).unwrap_or(false) {
            break;
        }
    }
    sink.finish(emitted)?;
    if let Some(path) = args.out.as_deref() {
        eprintln!(
            "query: wrote {emitted} rows as {} to {}",
            args.format.as_str(),
            path.display()
        );
    }
    Ok(())
}

/// Write plain text (table/explain/schema output) to a file or stdout.
fn write_text_output(out: Option<&Path>, text: &str) -> Result<(), String> {
    match out {
        Some(path) => {
            let mut file = File::create(path)
                .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
            file.write_all(text.as_bytes())
                .map_err(|error| format!("cannot write {}: {error}", path.display()))
        }
        None => {
            let mut stdout = io::stdout().lock();
            stdout
                .write_all(text.as_bytes())
                .map_err(|error| error.to_string())?;
            stdout.flush().map_err(|error| error.to_string())
        }
    }
}

fn boxed_writer(out: Option<&Path>) -> Result<Box<dyn Write>, String> {
    match out {
        Some(path) => {
            let file = File::create(path)
                .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
            Ok(Box::new(BufWriter::new(file)))
        }
        None => Ok(Box::new(BufWriter::new(io::stdout()))),
    }
}

/// One output sink per format. Text formats stream batch by batch; `table`
/// collects because alignment needs the full result.
enum Sink {
    Table {
        batches: Vec<RecordBatch>,
        out: Option<PathBuf>,
    },
    Json {
        writer: LineDelimitedWriter<Box<dyn Write>>,
    },
    Csv {
        writer: CsvWriter<Box<dyn Write>>,
    },
    Parquet {
        writer: ArrowWriter<File>,
    },
}

impl Sink {
    fn new(
        format: OutputFormat,
        out: Option<&Path>,
        schema: &arrow::datatypes::SchemaRef,
    ) -> Result<Self, String> {
        match format {
            OutputFormat::Table => Ok(Self::Table {
                batches: Vec::new(),
                out: out.map(Path::to_path_buf),
            }),
            OutputFormat::Json => Ok(Self::Json {
                writer: LineDelimitedWriter::new(boxed_writer(out)?),
            }),
            OutputFormat::Csv => {
                let mut writer = CsvWriter::new(boxed_writer(out)?);
                // Write the header even for an empty result by pushing an
                // empty batch first; the CSV writer only emits the header
                // from the first batch it sees.
                writer
                    .write(&RecordBatch::new_empty(schema.clone()))
                    .map_err(|error| error.to_string())?;
                Ok(Self::Csv { writer })
            }
            OutputFormat::Parquet => {
                let path = out.ok_or_else(|| {
                    "query --format parquet requires --out <file>; Parquet is a binary format"
                        .to_string()
                })?;
                let file = File::create(path)
                    .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
                let writer = ArrowWriter::try_new(file, schema.clone(), None)
                    .map_err(|error| error.to_string())?;
                Ok(Self::Parquet { writer })
            }
        }
    }

    fn write(&mut self, batch: &RecordBatch) -> Result<(), String> {
        match self {
            Self::Table { batches, .. } => {
                batches.push(batch.clone());
                Ok(())
            }
            Self::Json { writer } => writer.write(batch).map_err(|error| error.to_string()),
            Self::Csv { writer } => writer.write(batch).map_err(|error| error.to_string()),
            Self::Parquet { writer } => writer.write(batch).map_err(|error| error.to_string()),
        }
    }

    fn finish(self, emitted: usize) -> Result<(), String> {
        match self {
            Self::Table { batches, out } => {
                if emitted == 0 {
                    eprintln!("no rows");
                    if let Some(path) = out.as_deref() {
                        let _ = File::create(path);
                    }
                    return Ok(());
                }
                let text = pretty_format_batches(&batches)
                    .map_err(|error| error.to_string())?
                    .to_string();
                write_text_output(out.as_deref(), &format!("{text}\n"))
            }
            Self::Json { writer } => {
                let mut inner = writer.into_inner();
                inner.flush().map_err(|error| error.to_string())
            }
            Self::Csv { writer } => {
                let mut inner = writer.into_inner();
                inner.flush().map_err(|error| error.to_string())
            }
            Self::Parquet { writer } => {
                writer.close().map_err(|error| error.to_string())?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_sql_is_stable() {
        assert!(default_sql("events").contains("from events"));
        assert!(default_sql("stacks").contains("from stacks"));
        assert!(default_sql("probe_events").contains("from probe_events"));
    }

    #[test]
    fn format_names_are_stable() {
        assert_eq!(OutputFormat::Table.as_str(), "table");
        assert_eq!(OutputFormat::Json.as_str(), "json");
        assert_eq!(OutputFormat::Csv.as_str(), "csv");
        assert_eq!(OutputFormat::Parquet.as_str(), "parquet");
    }
}
