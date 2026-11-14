// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Self-contained incident bundles for local eBPF fleet recordings.
//!
//! A bundle is a directory with a manifest and columnar event files. The
//! writer is deliberately fail-closed: it writes into a hidden temporary
//! directory, hashes every Parquet part, and only renames the directory
//! into place after the manifest is complete. A crash therefore leaves an
//! unusable partial directory, never a bundle that looks valid.
//!
//! The reader validates the manifest, every file hash, and the path layout
//! before exposing a query. SQL is executed with DataFusion over the local
//! Parquet files; no server or network is involved.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use arrow_array::builder::{
    BooleanBuilder, Int32Builder, Int64Builder, ListBuilder, StringBuilder, StructBuilder,
    UInt16Builder, UInt32Builder, UInt64Builder,
};
use arrow_array::{
    Array, ArrayRef, BooleanArray, Int32Array, Int64Array, ListArray, RecordBatch, StringArray,
    StructArray, UInt16Array, UInt32Array, UInt64Array,
};
use arrow_schema::{DataType, Field, Fields, Schema, SchemaRef};
use chrono::{DateTime, SecondsFormat, Utc};
use datafusion::datasource::file_format::parquet::ParquetFormat;
use datafusion::datasource::listing::{
    ListingOptions, ListingTable, ListingTableConfig, ListingTableUrl,
};
use datafusion::datasource::memory::MemTable;
use datafusion::execution::context::SessionContext;
use event_model::{Event, Stack, StackFrame};
use futures::stream::{BoxStream, StreamExt};
use parquet::arrow::ArrowWriter;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Bundle manifest format version written by this crate (0.3: adds the
/// `stacks` table, `events.stack_id`, and the optional `probe_events`
/// table). A bundle written without `probe_events` still opens in this
/// build and exposes an empty `probe_events` table.
pub const FORMAT: &str = "ebpf-fleet.bundle/v2";
/// Frozen 0.2 bundle format. The reader still accepts it so old incident
/// bundles stay queryable (its `stacks` table is exposed empty).
pub const FORMAT_V1: &str = "ebpf-fleet.bundle/v1";
/// Arrow schema version written by this crate.
pub const ARROW_SCHEMA_VERSION: u32 = 2;
/// Frozen 0.2 Arrow schema version (events table without `stack_id`).
pub const ARROW_SCHEMA_VERSION_V1: u32 = 1;

/// Streaming record batches from [`Bundle::query_stream`].
///
/// Yields `Result` so a mid-stream execution error is surfaced to the
/// caller; stopping the stream early (for example at `--limit`) cancels
/// the underlying plan.
pub type BatchStream = BoxStream<'static, Result<RecordBatch, BundleError>>;

/// One streaming query: the result Arrow schema plus the batch stream.
///
/// The schema is available even when the query produces no rows, which is
/// what lets `query --format parquet` write a valid empty file.
pub struct QueryStream {
    /// Arrow schema of the result rows.
    pub schema: SchemaRef,
    /// Record batches, streamed.
    pub batches: BatchStream,
}

/// A complete, validated incident bundle.
#[derive(Debug, Clone)]
pub struct Bundle {
    root: PathBuf,
    manifest: Manifest,
    /// Bundle format version: 2 for the current writer, 1 for a 0.2
    /// bundle read through the compatibility path.
    format_version: u32,
}

/// Errors from creating, validating, or querying a bundle.
#[derive(Debug, Error)]
pub enum BundleError {
    /// Filesystem error.
    #[error("bundle I/O: {0}")]
    Io(#[from] std::io::Error),
    /// Manifest encoding error.
    #[error("bundle manifest: {0}")]
    Json(#[from] serde_json::Error),
    /// Arrow construction error.
    #[error("bundle arrow: {0}")]
    Arrow(#[from] arrow_schema::ArrowError),
    /// Parquet writer error.
    #[error("bundle parquet: {0}")]
    Parquet(#[from] parquet::errors::ParquetError),
    /// SQL/query error.
    #[error("bundle query: {0}")]
    DataFusion(#[from] datafusion::error::DataFusionError),
    /// The bundle is structurally invalid.
    #[error("invalid bundle: {0}")]
    Invalid(String),
    /// The bundle was not finalized.
    #[error("bundle is incomplete: {0}")]
    Incomplete(String),
}

/// Tool identity recorded in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolInfo {
    /// Crate/CLI version.
    pub version: String,
    /// Optional git commit.
    #[serde(default)]
    pub commit: String,
}

impl Default for ToolInfo {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: String::new(),
        }
    }
}

/// Host facts that make a bundle reproducible and explain missing symbols.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostInfo {
    /// Machine architecture.
    #[serde(default)]
    pub arch: String,
    /// Kernel release, for example `6.8.0-...`.
    #[serde(default)]
    pub kernel_release: String,
    /// SHA-256 of `/sys/kernel/btf/vmlinux`.
    #[serde(default)]
    pub btf_sha256: String,
    /// Kernel boot id.
    #[serde(default)]
    pub boot_id: String,
    /// Lockdown state: `none`, `integrity`, or `confidentiality`.
    #[serde(default)]
    pub lockdown: String,
    /// Active LSM names.
    #[serde(default)]
    pub lsm: Vec<String>,
    /// Value of `/proc/sys/kernel/unprivileged_bpf_disabled`.
    #[serde(default)]
    pub unprivileged_bpf_disabled: u32,
}

/// Capture parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureInfo {
    /// Sensors requested.
    #[serde(default)]
    pub sensors: Vec<String>,
    /// Requested duration in milliseconds.
    #[serde(default)]
    pub duration_ms: u64,
    /// Stack mode: `off`, `events`, or `all`.
    #[serde(default)]
    pub stack_mode: String,
}

/// Event/Arrow schema identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaInfo {
    /// Arrow schema version.
    pub arrow_version: u32,
    /// SHA-256 of the canonical Arrow schema JSON.
    pub arrow_sha256: String,
}

/// Counters recorded at finalization.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counts {
    /// Number of event rows written.
    pub events: u64,
    /// Number of alert rows written.
    pub alerts: u64,
    /// Number of stack rows written.
    pub stacks: u64,
    /// Number of custom-probe event rows written to `probe_events`.
    ///
    /// Defaulted so a bundle manifest written before the probe runtime (or a
    /// hand-built v1 fixture) deserializes with zero probe rows.
    #[serde(default)]
    pub probe_events: u64,
    /// Sensor/subsystem drop counters.
    pub dropped: std::collections::BTreeMap<String, u64>,
}

/// One Parquet part.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileInfo {
    /// Path relative to the bundle root.
    pub path: String,
    /// Number of rows in the part.
    pub rows: u64,
    /// SHA-256 of the part.
    pub sha256: String,
}

/// One decoded custom-probe event written to the `probe_events` table.
///
/// The runtime decodes the fixed `FPRB` SDK envelope and the probe manifest's
/// payload layout into `payload_json`; `raw` keeps the complete ring-buffer
/// record as lowercase hex so no captured byte is lost when the manifest
/// layout is incomplete or the decoder is stricter than a future probe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeEventRecord {
    /// Probe name from the manifest.
    pub probe: String,
    /// Probe-defined event kind (`FPRB` header field).
    pub kind: u16,
    /// Declared kind name, when the manifest declares this kind.
    pub kind_name: Option<String>,
    /// Wall-clock time in Unix nanoseconds (nullable, like `events`).
    pub time_unix_ns: Option<i64>,
    /// RFC 3339 wall-clock time (nullable, like `events`).
    pub time: Option<String>,
    /// Thread id.
    pub pid: u32,
    /// Thread group id.
    pub tgid: u32,
    /// Cgroup v2 id.
    pub cgroup_id: u64,
    /// Decoded payload as a JSON object.
    pub payload_json: String,
    /// Complete record bytes as lowercase hex.
    pub raw: Option<String>,
}

/// On-disk manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// Format identifier.
    pub format: String,
    /// True only after a successful finalize.
    pub complete: bool,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// Tool identity.
    pub tool: ToolInfo,
    /// Host facts.
    pub host: HostInfo,
    /// Capture parameters.
    pub capture: CaptureInfo,
    /// Arrow schema identity.
    pub schema: SchemaInfo,
    /// Counters.
    pub counts: Counts,
    /// Parquet event parts.
    pub files: Vec<FileInfo>,
}

impl Manifest {
    fn new(host: HostInfo, capture: CaptureInfo) -> Self {
        Self {
            format: FORMAT.to_string(),
            complete: false,
            created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            tool: ToolInfo::default(),
            host,
            capture,
            schema: SchemaInfo {
                arrow_version: ARROW_SCHEMA_VERSION,
                arrow_sha256: schema_sha256(),
            },
            counts: Counts::default(),
            files: Vec::new(),
        }
    }
}

/// Streaming bundle writer.
pub struct BundleWriter {
    final_path: PathBuf,
    temp_path: PathBuf,
    manifest: Manifest,
    next_part: u32,
    next_stack_part: u32,
    next_probe_part: u32,
    finished: bool,
}

impl BundleWriter {
    /// Create a new writer. The final path must not exist.
    pub fn create(
        path: impl AsRef<Path>,
        host: HostInfo,
        capture: CaptureInfo,
    ) -> Result<Self, BundleError> {
        let final_path = path.as_ref().to_path_buf();
        if final_path.exists() {
            return Err(BundleError::Invalid(format!(
                "bundle already exists: {}",
                final_path.display()
            )));
        }
        let parent = final_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let name = final_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| BundleError::Invalid("bundle path has no file name".to_string()))?;
        let temp_path = parent.join(format!(".{name}.tmp-{}", std::process::id()));
        if temp_path.exists() {
            fs::remove_dir_all(&temp_path)?;
        }
        fs::create_dir_all(temp_path.join("events"))?;
        fs::create_dir_all(temp_path.join("stacks"))?;
        fs::create_dir_all(temp_path.join("probe_events"))?;
        Ok(Self {
            final_path,
            temp_path,
            manifest: Manifest::new(host, capture),
            next_part: 0,
            next_stack_part: 0,
            next_probe_part: 0,
            finished: false,
        })
    }

    /// Append one Parquet part of decoded events.
    pub fn write_events(&mut self, events: &[Event]) -> Result<(), BundleError> {
        if events.is_empty() {
            return Ok(());
        }
        let relative = format!("events/part-{:05}.parquet", self.next_part);
        self.next_part += 1;
        let full = self.temp_path.join(&relative);
        let batch = events_to_batch(events)?;
        let file = File::create(&full)?;
        let mut writer = ArrowWriter::try_new(file, batch.schema(), None)?;
        writer.write(&batch)?;
        writer.close()?;
        let sha256 = sha256_file(&full)?;
        self.manifest.counts.events += events.len() as u64;
        self.manifest.files.push(FileInfo {
            path: relative,
            rows: events.len() as u64,
            sha256,
        });
        Ok(())
    }

    /// Append one Parquet part of symbolized stacks.
    ///
    /// Stacks are keyed by `(sensor, stack_id)`; events reference them
    /// through `events.stack_id`. Duplicate stack ids are allowed here (the
    /// recorder de-duplicates before writing) and the query layer joins on
    /// both columns.
    pub fn write_stacks(&mut self, stacks: &[Stack]) -> Result<(), BundleError> {
        if stacks.is_empty() {
            return Ok(());
        }
        let relative = format!("stacks/part-{:05}.parquet", self.next_stack_part);
        self.next_stack_part += 1;
        let full = self.temp_path.join(&relative);
        let batch = stacks_to_batch(stacks)?;
        let file = File::create(&full)?;
        let mut writer = ArrowWriter::try_new(file, batch.schema(), None)?;
        writer.write(&batch)?;
        writer.close()?;
        let sha256 = sha256_file(&full)?;
        self.manifest.counts.stacks += stacks.len() as u64;
        self.manifest.files.push(FileInfo {
            path: relative,
            rows: stacks.len() as u64,
            sha256,
        });
        Ok(())
    }

    /// Append one Parquet part of decoded custom-probe events.
    ///
    /// `probe_events` is an optional table: a bundle with no parts still opens
    /// and queries as an empty table, so a v1/v2 bundle recorded before the
    /// probe runtime stays readable.
    pub fn write_probe_events(&mut self, events: &[ProbeEventRecord]) -> Result<(), BundleError> {
        if events.is_empty() {
            return Ok(());
        }
        let relative = format!("probe_events/part-{:05}.parquet", self.next_probe_part);
        self.next_probe_part += 1;
        let full = self.temp_path.join(&relative);
        let batch = probe_events_to_batch(events)?;
        let file = File::create(&full)?;
        let mut writer = ArrowWriter::try_new(file, batch.schema(), None)?;
        writer.write(&batch)?;
        writer.close()?;
        let sha256 = sha256_file(&full)?;
        self.manifest.counts.probe_events += events.len() as u64;
        self.manifest.files.push(FileInfo {
            path: relative,
            rows: events.len() as u64,
            sha256,
        });
        Ok(())
    }

    /// Finalize the bundle atomically and return the open bundle.
    pub fn finish(mut self) -> Result<Bundle, BundleError> {
        self.manifest.complete = true;
        let manifest_path = self.temp_path.join("manifest.json");
        {
            let mut file = File::create(&manifest_path)?;
            serde_json::to_writer_pretty(&mut file, &self.manifest)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        fs::rename(&self.temp_path, &self.final_path)?;
        self.finished = true;
        Ok(Bundle {
            root: self.final_path.clone(),
            manifest: self.manifest.clone(),
            format_version: ARROW_SCHEMA_VERSION,
        })
    }

    /// Path of the final bundle while it is being written.
    pub fn path(&self) -> &Path {
        &self.final_path
    }
}

impl Drop for BundleWriter {
    fn drop(&mut self) {
        if !self.finished {
            let _ = fs::remove_dir_all(&self.temp_path);
        }
    }
}

impl Bundle {
    /// Open and validate an existing bundle.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BundleError> {
        let root = path.as_ref().to_path_buf();
        let metadata = fs::symlink_metadata(&root)?;
        if metadata.file_type().is_symlink() {
            return Err(BundleError::Invalid(
                "bundle root must not be a symlink".to_string(),
            ));
        }
        if !metadata.is_dir() {
            return Err(BundleError::Invalid(
                "bundle root must be a directory".to_string(),
            ));
        }
        let manifest_path = root.join("manifest.json");
        let manifest: Manifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        let format_version = match manifest.format.as_str() {
            FORMAT => 2,
            FORMAT_V1 => 1,
            other => {
                return Err(BundleError::Invalid(format!(
                    "unsupported bundle format: {other}"
                )))
            }
        };
        if !manifest.complete {
            return Err(BundleError::Incomplete(
                "manifest.complete is false".to_string(),
            ));
        }
        let expected_arrow = if format_version >= 2 {
            ARROW_SCHEMA_VERSION
        } else {
            ARROW_SCHEMA_VERSION_V1
        };
        if manifest.schema.arrow_version != expected_arrow {
            return Err(BundleError::Invalid(format!(
                "unsupported arrow schema: {} for bundle format {}",
                manifest.schema.arrow_version, manifest.format
            )));
        }
        for file in &manifest.files {
            validate_relative_path(&file.path)?;
            let path = root.join(&file.path);
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(BundleError::Invalid(format!(
                    "bundle file is a symlink: {}",
                    file.path
                )));
            }
            if !metadata.is_file() {
                return Err(BundleError::Invalid(format!(
                    "bundle file is not a regular file: {}",
                    file.path
                )));
            }
            if sha256_file(&path)? != file.sha256 {
                return Err(BundleError::Invalid(format!(
                    "bundle file hash mismatch: {}",
                    file.path
                )));
            }
        }
        Ok(Self {
            root,
            manifest,
            format_version,
        })
    }

    /// Bundle format version: 2 for current bundles, 1 for a 0.2 bundle.
    pub fn format_version(&self) -> u32 {
        self.format_version
    }

    /// Validated manifest.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Bundle root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Pack the bundle into a zstd-compressed tar archive.
    pub fn pack(&self, output: impl AsRef<Path>) -> Result<(), BundleError> {
        let output = output.as_ref().to_path_buf();
        if output.starts_with(&self.root) {
            return Err(BundleError::Invalid(
                "pack output must be outside the bundle directory".to_string(),
            ));
        }
        if output.exists() {
            return Err(BundleError::Invalid(format!(
                "pack output already exists: {}",
                output.display()
            )));
        }
        let parent = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let name = output
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| BundleError::Invalid("pack output has no file name".to_string()))?;
        let temp = parent.join(format!(".{name}.tmp-{}", std::process::id()));
        if temp.exists() {
            fs::remove_file(&temp)?;
        }
        let file = File::create(&temp)?;
        let encoder = zstd::Encoder::new(file, 3)?;
        let mut archive = tar::Builder::new(encoder.auto_finish());
        archive.append_path_with_name(self.root.join("manifest.json"), "manifest.json")?;
        for part in &self.manifest.files {
            validate_relative_path(&part.path)?;
            archive.append_path_with_name(self.root.join(&part.path), &part.path)?;
        }
        archive.finish()?;
        drop(archive);
        if let Err(error) = fs::rename(&temp, &output) {
            let _ = fs::remove_file(&temp);
            return Err(error.into());
        }
        Ok(())
    }

    /// Extract a packed bundle into a new directory and validate it.
    pub fn unpack(
        archive: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<Bundle, BundleError> {
        let archive = archive.as_ref();
        let destination = destination.as_ref().to_path_buf();
        if destination.exists() {
            return Err(BundleError::Invalid(format!(
                "unpack destination already exists: {}",
                destination.display()
            )));
        }
        let parent = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                BundleError::Invalid("unpack destination has no file name".to_string())
            })?;
        let temp = parent.join(format!(".{name}.tmp-{}", std::process::id()));
        if temp.exists() {
            fs::remove_dir_all(&temp)?;
        }
        fs::create_dir_all(&temp)?;
        let result = (|| -> Result<(), BundleError> {
            let file = File::open(archive)?;
            let decoder = zstd::Decoder::new(file)?;
            let mut tar = tar::Archive::new(decoder);
            for entry in tar.entries()? {
                let mut entry = entry?;
                let path = entry.path()?.to_path_buf();
                let path_text = path
                    .to_str()
                    .ok_or_else(|| BundleError::Invalid("archive path is not UTF-8".to_string()))?;
                validate_relative_path(path_text)?;
                if !entry.header().entry_type().is_file() {
                    return Err(BundleError::Invalid(format!(
                        "archive entry is not a regular file: {path_text}"
                    )));
                }
                let target = temp.join(&path);
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                entry.unpack(&target)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_dir_all(&temp);
            return Err(error);
        }
        let bundle = match Bundle::open(&temp) {
            Ok(bundle) => bundle,
            Err(error) => {
                let _ = fs::remove_dir_all(&temp);
                return Err(error);
            }
        };
        if let Err(error) = fs::rename(&temp, &destination) {
            let _ = fs::remove_dir_all(&temp);
            return Err(error.into());
        }
        Ok(Bundle {
            root: destination,
            manifest: bundle.manifest,
            format_version: bundle.format_version,
        })
    }

    /// Execute SQL against the bundle's `events`, `stacks`, and
    /// `probe_events` tables.
    ///
    /// Every table is always registered. A v1 (0.2) bundle is read with
    /// the frozen v1 event schema and exposes an empty `stacks` table, so
    /// the same join SQL keeps the same shape but returns no stack rows.
    /// A bundle written before the probe runtime exposes an empty
    /// `probe_events` table. v2 bundles join events and stacks on
    /// `(sensor, stack_id)`:
    ///
    /// ```sql
    /// select e.kind, e.path, s.frames
    /// from events e join stacks s
    ///   on e.sensor = s.sensor and e.stack_id = s.stack_id
    /// ```
    ///
    /// Custom-probe rows are queried directly:
    ///
    /// ```sql
    /// select probe, kind_name, count(*) as n from probe_events
    /// group by probe, kind_name order by n desc
    /// ```
    pub async fn query(&self, sql: &str) -> Result<Vec<RecordBatch>, BundleError> {
        self.execute(sql, true).await
    }

    /// Execute SQL and return a streaming record-batch stream instead of
    /// collecting every row in memory.
    ///
    /// This is the streaming counterpart of [`Bundle::query`]: the caller
    /// can stop early (for example at `query --limit N`) and only the Arrow
    /// writer buffers what it writes. The stream yields
    /// `Result<RecordBatch, BundleError>` so callers do not need a direct
    /// DataFusion dependency.
    pub async fn query_stream(&self, sql: &str) -> Result<QueryStream, BundleError> {
        self.query_stream_inner(sql, true).await
    }

    /// Arrow schema of one of the bundle tables (`events`, `stacks`,
    /// `probe_events`), matching what queries see for this bundle format.
    ///
    /// Returns `None` for an unknown table name. A v1 bundle reports the
    /// frozen v1 `events` schema (without `stack_id`).
    pub fn table_schema(&self, table: &str) -> Option<SchemaRef> {
        match table {
            "events" => Some(if self.format_version >= 2 {
                event_schema()
            } else {
                event_schema_v1()
            }),
            "stacks" => Some(stacks_schema()),
            "probe_events" => Some(probe_events_schema()),
            _ => None,
        }
    }

    /// Table names `query` accepts for `--table`.
    pub const TABLES: &'static [&'static str] = &["events", "stacks", "probe_events"];

    /// Read the whole `stacks` table back into typed [`Stack`] values.
    ///
    /// A v1 (0.2) bundle has no stack data and returns an empty vector.
    pub async fn read_stacks(&self) -> Result<Vec<Stack>, BundleError> {
        let batches = self
            .execute(
                "select stack_id, sensor, frames, truncated from stacks order by sensor, stack_id",
                false,
            )
            .await?;
        let mut stacks = Vec::new();
        for batch in &batches {
            let (Some(ids), Some(sensors), Some(frame_lists), Some(truncated)) = (
                batch.column(0).as_any().downcast_ref::<Int32Array>(),
                batch.column(1).as_any().downcast_ref::<StringArray>(),
                batch.column(2).as_any().downcast_ref::<ListArray>(),
                batch.column(3).as_any().downcast_ref::<BooleanArray>(),
            ) else {
                continue;
            };
            for row in 0..batch.num_rows() {
                let inner = frame_lists.value(row);
                let Some(structs) = inner.as_any().downcast_ref::<StructArray>() else {
                    continue;
                };
                let (Some(addrs), Some(symbols), Some(files), Some(lines), Some(kernel)) = (
                    structs.column(0).as_any().downcast_ref::<UInt64Array>(),
                    structs.column(1).as_any().downcast_ref::<StringArray>(),
                    structs.column(2).as_any().downcast_ref::<StringArray>(),
                    structs.column(3).as_any().downcast_ref::<UInt32Array>(),
                    structs.column(4).as_any().downcast_ref::<BooleanArray>(),
                ) else {
                    continue;
                };
                let mut frames = Vec::with_capacity(structs.len());
                for index in 0..structs.len() {
                    frames.push(StackFrame {
                        addr: addrs.value(index),
                        symbol: (!symbols.is_null(index)).then(|| symbols.value(index).to_string()),
                        file: (!files.is_null(index)).then(|| files.value(index).to_string()),
                        line: (!lines.is_null(index)).then(|| lines.value(index)),
                        is_kernel: kernel.value(index),
                    });
                }
                stacks.push(Stack {
                    stack_id: ids.value(row),
                    sensor: sensors.value(row).to_string(),
                    frames,
                    truncated: truncated.value(row),
                });
            }
        }
        Ok(stacks)
    }

    /// Read the whole `probe_events` table back into typed records.
    ///
    /// A bundle written before the probe runtime (or a plain sensor bundle)
    /// has no probe parts and returns an empty vector.
    pub async fn read_probe_events(&self) -> Result<Vec<ProbeEventRecord>, BundleError> {
        let batches = self
            .execute(
                "select probe, kind, kind_name, time_unix_ns, time, pid, tgid, cgroup_id, \
                 payload_json, raw from probe_events order by time_unix_ns, pid, kind",
                false,
            )
            .await?;
        let mut records = Vec::new();
        for batch in &batches {
            let (
                Some(probes),
                Some(kinds),
                Some(names),
                Some(times_unix),
                Some(times),
                Some(pids),
                Some(tgids),
                Some(cgroups),
                Some(payloads),
                Some(raws),
            ) = (
                batch.column(0).as_any().downcast_ref::<StringArray>(),
                batch.column(1).as_any().downcast_ref::<UInt16Array>(),
                batch.column(2).as_any().downcast_ref::<StringArray>(),
                batch.column(3).as_any().downcast_ref::<Int64Array>(),
                batch.column(4).as_any().downcast_ref::<StringArray>(),
                batch.column(5).as_any().downcast_ref::<UInt32Array>(),
                batch.column(6).as_any().downcast_ref::<UInt32Array>(),
                batch.column(7).as_any().downcast_ref::<UInt64Array>(),
                batch.column(8).as_any().downcast_ref::<StringArray>(),
                batch.column(9).as_any().downcast_ref::<StringArray>(),
            )
            else {
                continue;
            };
            for row in 0..batch.num_rows() {
                records.push(ProbeEventRecord {
                    probe: probes.value(row).to_string(),
                    kind: kinds.value(row),
                    kind_name: (!names.is_null(row)).then(|| names.value(row).to_string()),
                    time_unix_ns: (!times_unix.is_null(row)).then(|| times_unix.value(row)),
                    time: (!times.is_null(row)).then(|| times.value(row).to_string()),
                    pid: pids.value(row),
                    tgid: tgids.value(row),
                    cgroup_id: cgroups.value(row),
                    payload_json: payloads.value(row).to_string(),
                    raw: (!raws.is_null(row)).then(|| raws.value(row).to_string()),
                });
            }
        }
        Ok(records)
    }

    async fn query_stream_inner(
        &self,
        sql: &str,
        require_data: bool,
    ) -> Result<QueryStream, BundleError> {
        let ctx = self.session(require_data)?;
        let frame = ctx.sql(sql).await?;
        let schema = frame.schema().inner().clone();
        let stream = frame.execute_stream().await?;
        Ok(QueryStream {
            schema,
            batches: Box::pin(stream.map(|batch| batch.map_err(BundleError::from))),
        })
    }

    async fn execute(
        &self,
        sql: &str,
        require_data: bool,
    ) -> Result<Vec<RecordBatch>, BundleError> {
        let mut stream = self.query_stream_inner(sql, require_data).await?.batches;
        let mut batches = Vec::new();
        while let Some(batch) = stream.next().await {
            batches.push(batch?);
        }
        Ok(batches)
    }

    /// Build a session with `events`, `stacks`, and `probe_events`
    /// registered (real Parquet parts when present, empty tables
    /// otherwise).
    fn session(&self, require_data: bool) -> Result<SessionContext, BundleError> {
        let event_paths = self.parquet_paths("events/")?;
        let stack_paths = self.parquet_paths("stacks/")?;
        let probe_paths = self.parquet_paths("probe_events/")?;
        if require_data
            && event_paths.is_empty()
            && stack_paths.is_empty()
            && probe_paths.is_empty()
        {
            return Err(BundleError::Invalid("bundle has no data parts".to_string()));
        }
        let events = if self.format_version >= 2 {
            event_schema()
        } else {
            event_schema_v1()
        };
        let ctx = SessionContext::new();
        if event_paths.is_empty() {
            register_empty_table(&ctx, "events", events)?;
        } else {
            register_parquet_table(&ctx, "events", event_paths, events)?;
        }
        if stack_paths.is_empty() {
            register_empty_table(&ctx, "stacks", stacks_schema())?;
        } else {
            register_parquet_table(&ctx, "stacks", stack_paths, stacks_schema())?;
        }
        if probe_paths.is_empty() {
            register_empty_table(&ctx, "probe_events", probe_events_schema())?;
        } else {
            register_parquet_table(&ctx, "probe_events", probe_paths, probe_events_schema())?;
        }
        Ok(ctx)
    }

    /// Parquet part paths under one bundle subdirectory, in manifest order.
    fn parquet_paths(&self, prefix: &str) -> Result<Vec<ListingTableUrl>, BundleError> {
        let mut paths = Vec::new();
        for file in &self.manifest.files {
            if !file.path.starts_with(prefix) {
                continue;
            }
            let path = self.root.join(&file.path);
            let path = path
                .to_str()
                .ok_or_else(|| BundleError::Invalid("bundle path is not UTF-8".to_string()))?;
            paths.push(
                ListingTableUrl::parse(path)
                    .map_err(|error| BundleError::Invalid(error.to_string()))?,
            );
        }
        Ok(paths)
    }
}

/// Register a multi-file Parquet table with an explicit Arrow schema.
fn register_parquet_table(
    ctx: &SessionContext,
    name: &str,
    paths: Vec<ListingTableUrl>,
    schema: SchemaRef,
) -> Result<(), BundleError> {
    let options =
        ListingOptions::new(Arc::new(ParquetFormat::default())).with_file_extension(".parquet");
    let config = ListingTableConfig::new_with_multi_paths(paths)
        .with_listing_options(options)
        .with_schema(schema);
    let table =
        ListingTable::try_new(config).map_err(|error| BundleError::Invalid(error.to_string()))?;
    ctx.register_table(name, Arc::new(table))?;
    Ok(())
}

/// Register an empty in-memory table with `schema`.
fn register_empty_table(
    ctx: &SessionContext,
    name: &str,
    schema: SchemaRef,
) -> Result<(), BundleError> {
    let batch = RecordBatch::new_empty(schema.clone());
    let table = MemTable::try_new(schema, vec![vec![batch]])
        .map_err(|error| BundleError::Invalid(error.to_string()))?;
    ctx.register_table(name, Arc::new(table))?;
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), BundleError> {
    let path = Path::new(path);
    if path.is_absolute() || path.as_os_str().is_empty() {
        return Err(BundleError::Invalid(format!(
            "bundle file path is not relative: {path:?}"
        )));
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(BundleError::Invalid(format!(
            "bundle file path escapes the root: {path:?}"
        )));
    }
    Ok(())
}

fn events_to_batch(events: &[Event]) -> Result<RecordBatch, BundleError> {
    let schema = event_schema();
    let mut event_id = StringBuilder::new();
    let mut time = StringBuilder::new();
    let mut time_unix_ns = Int64Builder::new();
    let mut boot_id = StringBuilder::new();
    let mut seq = UInt64Builder::new();
    let mut sensor = StringBuilder::new();
    let mut kind = StringBuilder::new();
    let mut pid = UInt32Builder::new();
    let mut tgid = UInt32Builder::new();
    let mut cgroup_id = UInt64Builder::new();
    let mut process_exec = StringBuilder::new();
    let mut path = StringBuilder::new();
    let mut old_path = StringBuilder::new();
    let mut argv = ListBuilder::new(StringBuilder::new());
    let mut parent_pid = UInt32Builder::new();
    let mut child_pid = UInt32Builder::new();
    let mut exit_code = Int32Builder::new();
    let mut open_flags = UInt32Builder::new();
    let mut mode = UInt32Builder::new();
    let mut length = UInt64Builder::new();
    let mut redaction = StringBuilder::new();
    let mut raw_json = StringBuilder::new();
    let mut stack_id = Int32Builder::new();

    for event in events {
        event_id.append_value(&event.event_id);
        time.append_value(&event.time);
        time_unix_ns.append_option(rfc3339_to_unix_ns(&event.time));
        boot_id.append_value(&event.boot_id);
        seq.append_value(event.seq);
        sensor.append_value(&event.sensor);
        kind.append_value(&event.kind);
        pid.append_value(event.pid);
        tgid.append_value(event.tgid);
        cgroup_id.append_value(event.cgroup_id);
        append_opt(&mut process_exec, event.process_exec.as_deref());
        append_opt(&mut path, event.path.as_deref());
        append_opt(&mut old_path, event.old_path.as_deref());
        if let Some(args) = &event.argv {
            for arg in args {
                argv.values().append_value(arg);
            }
            argv.append(true);
        } else {
            argv.append(false);
        }
        append_opt_u32(&mut parent_pid, event.parent_pid);
        append_opt_u32(&mut child_pid, event.child_pid);
        if let Some(value) = event.exit_code {
            exit_code.append_value(value);
        } else {
            exit_code.append_null();
        }
        append_opt_u32(&mut open_flags, event.open_flags);
        append_opt_u32(&mut mode, event.mode);
        if let Some(value) = event.length {
            length.append_value(value);
        } else {
            length.append_null();
        }
        redaction.append_value(serde_json::to_string(&event.redaction).unwrap_or_default());
        raw_json.append_value(serde_json::to_string(event).unwrap_or_default());
        stack_id.append_option(event.stack_id);
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(event_id.finish()),
        Arc::new(time.finish()),
        Arc::new(time_unix_ns.finish()),
        Arc::new(boot_id.finish()),
        Arc::new(seq.finish()),
        Arc::new(sensor.finish()),
        Arc::new(kind.finish()),
        Arc::new(pid.finish()),
        Arc::new(tgid.finish()),
        Arc::new(cgroup_id.finish()),
        Arc::new(process_exec.finish()),
        Arc::new(path.finish()),
        Arc::new(old_path.finish()),
        Arc::new(argv.finish()),
        Arc::new(parent_pid.finish()),
        Arc::new(child_pid.finish()),
        Arc::new(exit_code.finish()),
        Arc::new(open_flags.finish()),
        Arc::new(mode.finish()),
        Arc::new(length.finish()),
        Arc::new(redaction.finish()),
        Arc::new(raw_json.finish()),
        Arc::new(stack_id.finish()),
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

/// Frozen 0.2 event schema (no `stack_id`). Kept so v1 bundles are read
/// with exactly the columns they were written with.
fn event_schema_v1() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("event_id", DataType::Utf8, false),
        Field::new("time", DataType::Utf8, false),
        Field::new("time_unix_ns", DataType::Int64, true),
        Field::new("boot_id", DataType::Utf8, false),
        Field::new("seq", DataType::UInt64, false),
        Field::new("sensor", DataType::Utf8, false),
        Field::new("kind", DataType::Utf8, false),
        Field::new("pid", DataType::UInt32, false),
        Field::new("tgid", DataType::UInt32, false),
        Field::new("cgroup_id", DataType::UInt64, false),
        Field::new("process_exec", DataType::Utf8, true),
        Field::new("path", DataType::Utf8, true),
        Field::new("old_path", DataType::Utf8, true),
        Field::new(
            "argv",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            true,
        ),
        Field::new("parent_pid", DataType::UInt32, true),
        Field::new("child_pid", DataType::UInt32, true),
        Field::new("exit_code", DataType::Int32, true),
        Field::new("open_flags", DataType::UInt32, true),
        Field::new("mode", DataType::UInt32, true),
        Field::new("length", DataType::UInt64, true),
        Field::new("redaction", DataType::Utf8, false),
        Field::new("raw_json", DataType::Utf8, false),
    ]))
}

/// Current event schema: the v1 columns plus a nullable `stack_id` that
/// points into the `stacks` table on `(sensor, stack_id)`.
fn event_schema() -> SchemaRef {
    let mut fields: Vec<Field> = event_schema_v1()
        .fields()
        .iter()
        .map(|field| field.as_ref().clone())
        .collect();
    fields.push(Field::new("stack_id", DataType::Int32, true));
    Arc::new(Schema::new(fields))
}

/// One frame of the `stacks.frames` list. `symbol`/`file`/`line` are
/// nullable: a null symbol is the "symbols unavailable" marker and the
/// raw `addr` is always present.
fn stack_frame_fields() -> Fields {
    vec![
        Field::new("addr", DataType::UInt64, false),
        Field::new("symbol", DataType::Utf8, true),
        Field::new("file", DataType::Utf8, true),
        Field::new("line", DataType::UInt32, true),
        Field::new("is_kernel", DataType::Boolean, false),
    ]
    .into()
}

/// Schema of the bundle `stacks` table.
fn stacks_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("stack_id", DataType::Int32, false),
        Field::new("sensor", DataType::Utf8, false),
        Field::new(
            "frames",
            DataType::List(Arc::new(Field::new(
                "item",
                DataType::Struct(stack_frame_fields()),
                true,
            ))),
            false,
        ),
        Field::new("truncated", DataType::Boolean, false),
    ]))
}

/// Schema of the bundle `probe_events` table.
fn probe_events_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("probe", DataType::Utf8, false),
        Field::new("kind", DataType::UInt16, false),
        Field::new("kind_name", DataType::Utf8, true),
        Field::new("time_unix_ns", DataType::Int64, true),
        Field::new("time", DataType::Utf8, true),
        Field::new("pid", DataType::UInt32, false),
        Field::new("tgid", DataType::UInt32, false),
        Field::new("cgroup_id", DataType::UInt64, false),
        Field::new("payload_json", DataType::Utf8, false),
        Field::new("raw", DataType::Utf8, true),
    ]))
}

fn probe_events_to_batch(events: &[ProbeEventRecord]) -> Result<RecordBatch, BundleError> {
    let schema = probe_events_schema();
    let mut probe = StringBuilder::new();
    let mut kind = UInt16Builder::new();
    let mut kind_name = StringBuilder::new();
    let mut time_unix_ns = Int64Builder::new();
    let mut time = StringBuilder::new();
    let mut pid = UInt32Builder::new();
    let mut tgid = UInt32Builder::new();
    let mut cgroup_id = UInt64Builder::new();
    let mut payload_json = StringBuilder::new();
    let mut raw = StringBuilder::new();

    for event in events {
        probe.append_value(&event.probe);
        kind.append_value(event.kind);
        append_opt(&mut kind_name, event.kind_name.as_deref());
        match event.time_unix_ns {
            Some(value) => time_unix_ns.append_value(value),
            None => time_unix_ns.append_null(),
        }
        append_opt(&mut time, event.time.as_deref());
        pid.append_value(event.pid);
        tgid.append_value(event.tgid);
        cgroup_id.append_value(event.cgroup_id);
        payload_json.append_value(&event.payload_json);
        append_opt(&mut raw, event.raw.as_deref());
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(probe.finish()),
        Arc::new(kind.finish()),
        Arc::new(kind_name.finish()),
        Arc::new(time_unix_ns.finish()),
        Arc::new(time.finish()),
        Arc::new(pid.finish()),
        Arc::new(tgid.finish()),
        Arc::new(cgroup_id.finish()),
        Arc::new(payload_json.finish()),
        Arc::new(raw.finish()),
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

fn stacks_to_batch(stacks: &[Stack]) -> Result<RecordBatch, BundleError> {
    let schema = stacks_schema();
    let mut stack_id = Int32Builder::new();
    let mut sensor = StringBuilder::new();
    let mut frames = ListBuilder::new(StructBuilder::from_fields(stack_frame_fields(), 0));
    let mut truncated = BooleanBuilder::new();

    for stack in stacks {
        stack_id.append_value(stack.stack_id);
        sensor.append_value(&stack.sensor);
        for frame in &stack.frames {
            let values = frames.values();
            values
                .field_builder::<UInt64Builder>(0)
                .expect("addr builder")
                .append_value(frame.addr);
            append_opt_string(
                values
                    .field_builder::<StringBuilder>(1)
                    .expect("symbol builder"),
                frame.symbol.as_deref(),
            );
            append_opt_string(
                values
                    .field_builder::<StringBuilder>(2)
                    .expect("file builder"),
                frame.file.as_deref(),
            );
            let line_builder = values
                .field_builder::<UInt32Builder>(3)
                .expect("line builder");
            match frame.line {
                Some(line) => line_builder.append_value(line),
                None => line_builder.append_null(),
            }
            values
                .field_builder::<BooleanBuilder>(4)
                .expect("is_kernel builder")
                .append_value(frame.is_kernel);
            // Close the struct row. StructBuilder tracks its own null
            // buffer; without this every child builder would outgrow it.
            values.append(true);
        }
        frames.append(true);
        truncated.append_value(stack.truncated);
    }

    let columns: Vec<ArrayRef> = vec![
        Arc::new(stack_id.finish()),
        Arc::new(sensor.finish()),
        Arc::new(frames.finish()),
        Arc::new(truncated.finish()),
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

fn append_opt_string(builder: &mut StringBuilder, value: Option<&str>) {
    match value {
        Some(value) => builder.append_value(value),
        None => builder.append_null(),
    }
}

fn schema_sha256() -> String {
    let schema = event_schema();
    let canonical = schema
        .fields()
        .iter()
        .map(|field| {
            format!(
                "{}:{:?}:{}",
                field.name(),
                field.data_type(),
                field.is_nullable()
            )
        })
        .collect::<Vec<_>>()
        .join("|");
    sha256_bytes(canonical.as_bytes())
}

/// Parse an RFC 3339 timestamp written by the recorder into Unix nanoseconds.
///
/// Returns `None` when the text is not RFC 3339 or the instant does not fit in
/// an `i64` nanosecond count.
pub fn rfc3339_to_unix_ns(value: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .and_then(|time| time.timestamp_nanos_opt())
}

fn append_opt(builder: &mut StringBuilder, value: Option<&str>) {
    match value {
        Some(value) => builder.append_value(value),
        None => builder.append_null(),
    }
}

fn append_opt_u32(builder: &mut UInt32Builder, value: Option<u32>) {
    match value {
        Some(value) => builder.append_value(value),
        None => builder.append_null(),
    }
}

fn sha256_file(path: &Path) -> Result<String, BundleError> {
    let bytes = fs::read(path)?;
    Ok(sha256_bytes(&bytes))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    use arrow_array::Int64Array;

    fn event(id: &str, kind: &str, pid: u32, path: Option<&str>) -> Event {
        Event {
            event_id: id.to_string(),
            time: "2026-11-13T18:00:00.000000000Z".to_string(),
            boot_id: "boot".to_string(),
            seq: pid as u64,
            sensor: "process".to_string(),
            kind: kind.to_string(),
            pid,
            tgid: pid,
            process_exec: Some("bash".to_string()),
            path: path.map(str::to_string),
            argv: Some(vec!["bash".to_string(), "-c".to_string()]),
            ..Event::default()
        }
    }

    fn probe_event(kind: u16, name: &str, pid: u32, payload_json: &str) -> ProbeEventRecord {
        ProbeEventRecord {
            probe: "hello".to_string(),
            kind,
            kind_name: Some(name.to_string()),
            time_unix_ns: Some(1_794_592_800_123_456_000),
            time: Some("2026-11-13T18:00:00.123456Z".to_string()),
            pid,
            tgid: pid,
            cgroup_id: 4242,
            payload_json: payload_json.to_string(),
            raw: Some("4650524201000100".to_string()),
        }
    }

    #[test]
    fn writes_and_validates_a_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("incident.fleet");
        let mut writer = BundleWriter::create(
            &root,
            HostInfo {
                arch: "x86_64".to_string(),
                kernel_release: "6.8.0-test".to_string(),
                ..HostInfo::default()
            },
            CaptureInfo {
                sensors: vec!["process".to_string(), "file".to_string()],
                duration_ms: 1_000,
                stack_mode: "off".to_string(),
            },
        )
        .unwrap();
        writer
            .write_events(&[
                event("a", "ProcessExec", 10, Some("/bin/bash")),
                event("b", "FileOpen", 10, Some("/etc/shadow")),
                event("c", "FileOpen", 11, Some("/etc/passwd")),
            ])
            .unwrap();
        let bundle = writer.finish().unwrap();
        assert_eq!(bundle.manifest().counts.events, 3);
        assert!(bundle.manifest().complete);
        assert_eq!(bundle.manifest().host.kernel_release, "6.8.0-test");
        assert_eq!(Bundle::open(&root).unwrap().manifest().counts.events, 3);
    }

    #[tokio::test]
    async fn packs_and_unpacks_a_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("incident.fleet");
        let mut writer =
            BundleWriter::create(&root, HostInfo::default(), CaptureInfo::default()).unwrap();
        writer
            .write_events(&[event("a", "ProcessExec", 10, Some("/bin/bash"))])
            .unwrap();
        writer
            .write_probe_events(&[probe_event(1, "exec", 10, r#"{"comm":"bash"}"#)])
            .unwrap();
        let bundle = writer.finish().unwrap();
        let archive = dir.path().join("incident.fleet.tar.zst");
        bundle.pack(&archive).unwrap();
        let extracted = dir.path().join("restored.fleet");
        let restored = Bundle::unpack(&archive, &extracted).unwrap();
        assert_eq!(restored.manifest().counts.events, 1);
        assert_eq!(restored.manifest().counts.probe_events, 1);
        assert_eq!(restored.root(), extracted);
        assert!(Bundle::open(&extracted).is_ok());
        assert_eq!(restored.read_probe_events().await.unwrap().len(), 1);
    }

    #[test]
    fn rejects_modified_parts() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("incident.fleet");
        let mut writer =
            BundleWriter::create(&root, HostInfo::default(), CaptureInfo::default()).unwrap();
        writer
            .write_events(&[event("a", "ProcessExec", 10, None)])
            .unwrap();
        writer.finish().unwrap();
        let part = root.join("events/part-00000.parquet");
        let mut bytes = fs::read(&part).unwrap();
        bytes.push(0);
        fs::write(&part, bytes).unwrap();
        assert!(matches!(
            Bundle::open(&root),
            Err(BundleError::Invalid(message)) if message.contains("hash mismatch")
        ));
    }

    #[test]
    fn incomplete_manifests_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("incident.fleet");
        let mut writer =
            BundleWriter::create(&root, HostInfo::default(), CaptureInfo::default()).unwrap();
        writer
            .write_events(&[event("a", "ProcessExec", 10, None)])
            .unwrap();
        // Simulate a crash: no finish(), so the temp directory is removed by
        // Drop and the final path never exists.
        drop(writer);
        assert!(!root.exists());
    }

    #[tokio::test]
    async fn queries_multiple_event_parts() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("incident.fleet");
        let mut writer =
            BundleWriter::create(&root, HostInfo::default(), CaptureInfo::default()).unwrap();
        writer
            .write_events(&[event("a", "ProcessExec", 10, Some("/bin/bash"))])
            .unwrap();
        writer
            .write_events(&[
                event("b", "FileOpen", 10, Some("/etc/shadow")),
                event("c", "FileOpen", 11, Some("/etc/passwd")),
            ])
            .unwrap();
        let bundle = writer.finish().unwrap();
        assert_eq!(bundle.manifest().files.len(), 2);
        let batches = bundle
            .query("select count(*) as n from events")
            .await
            .unwrap();
        let total: u64 = batches
            .iter()
            .map(|batch| {
                batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow_array::Int64Array>()
                    .unwrap()
                    .value(0) as u64
            })
            .sum();
        assert_eq!(total, 3);
    }

    fn frame(
        addr: u64,
        symbol: Option<&str>,
        file: Option<&str>,
        line: Option<u32>,
        kernel: bool,
    ) -> StackFrame {
        StackFrame {
            addr,
            symbol: symbol.map(str::to_string),
            file: file.map(str::to_string),
            line,
            is_kernel: kernel,
        }
    }

    fn stack(id: i32, sensor: &str, frames: Vec<StackFrame>, truncated: bool) -> Stack {
        Stack {
            stack_id: id,
            sensor: sensor.to_string(),
            frames,
            truncated,
        }
    }

    #[tokio::test]
    async fn writes_and_joins_v2_stacks() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("incident.fleet");
        let mut writer = BundleWriter::create(
            &root,
            HostInfo::default(),
            CaptureInfo {
                sensors: vec!["file".to_string()],
                duration_ms: 1_000,
                stack_mode: "events".to_string(),
            },
        )
        .unwrap();
        let mut with_stack = event("a", "FileOpen", 10, Some("/etc/shadow"));
        with_stack.sensor = "file".to_string();
        with_stack.stack_id = Some(7);
        let without_stack = event("b", "FileOpen", 11, Some("/etc/passwd"));
        writer.write_events(&[with_stack, without_stack]).unwrap();
        writer
            .write_stacks(&[stack(
                7,
                "file",
                vec![
                    frame(
                        0xffff_ffff_8100_0000,
                        Some("do_syscall_64"),
                        None,
                        None,
                        true,
                    ),
                    frame(
                        0x7f00_0000_1234,
                        Some("__libc_open64"),
                        Some("/usr/lib/libc.so.6"),
                        Some(42),
                        false,
                    ),
                ],
                false,
            )])
            .unwrap();
        let bundle = writer.finish().unwrap();
        assert_eq!(bundle.format_version(), 2);
        assert_eq!(bundle.manifest().counts.events, 2);
        assert_eq!(bundle.manifest().counts.stacks, 1);
        assert_eq!(bundle.manifest().capture.stack_mode, "events");

        let joined = bundle
            .query(
                "select e.event_id, e.stack_id, s.frames from events e \
                 join stacks s on e.sensor = s.sensor and e.stack_id = s.stack_id",
            )
            .await
            .unwrap();
        let rows: usize = joined.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(rows, 1, "join must only see the stack-carrying event");

        let stacks = bundle.read_stacks().await.unwrap();
        assert_eq!(stacks.len(), 1);
        assert_eq!(stacks[0].stack_id, 7);
        assert_eq!(stacks[0].sensor, "file");
        assert_eq!(stacks[0].frames.len(), 2);
        assert_eq!(stacks[0].frames[0].addr, 0xffff_ffff_8100_0000);
        assert_eq!(stacks[0].frames[0].symbol.as_deref(), Some("do_syscall_64"));
        assert!(stacks[0].frames[0].is_kernel);
        assert!(!stacks[0].frames[1].is_kernel);
        assert_eq!(stacks[0].frames[1].line, Some(42));
        assert_eq!(
            stacks[0].frames[1].file.as_deref(),
            Some("/usr/lib/libc.so.6")
        );
    }

    #[tokio::test]
    async fn unavailable_symbols_are_preserved_as_raw_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("incident.fleet");
        let mut writer =
            BundleWriter::create(&root, HostInfo::default(), CaptureInfo::default()).unwrap();
        writer
            .write_events(&[event("a", "ProcessExec", 10, Some("/bin/true"))])
            .unwrap();
        writer
            .write_stacks(&[stack(
                3,
                "process",
                vec![frame(0xffff_ffff_8123_4567, None, None, None, true)],
                true,
            )])
            .unwrap();
        let bundle = writer.finish().unwrap();
        let stacks = bundle.read_stacks().await.unwrap();
        assert_eq!(stacks.len(), 1);
        assert!(stacks[0].truncated);
        let frame = &stacks[0].frames[0];
        assert_eq!(frame.addr, 0xffff_ffff_8123_4567);
        assert_eq!(frame.symbol, None);
        assert_eq!(frame.file, None);
        assert_eq!(frame.line, None);
        assert!(frame.is_kernel);
        assert_eq!(stacks[0].missing_symbols(), 1);
    }

    #[tokio::test]
    async fn events_with_dangling_stack_ids_stay_queryable() {
        // Capture failures leave id -1, but a stack map entry can also
        // disappear between capture and read (or the stacks part can be
        // missing). Events must stay queryable and joins must simply skip
        // rows without a stack row: no corruption, no query failure.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("incident.fleet");
        let mut writer =
            BundleWriter::create(&root, HostInfo::default(), CaptureInfo::default()).unwrap();
        let mut dangling = event("a", "FileOpen", 10, Some("/etc/shadow"));
        dangling.sensor = "file".to_string();
        dangling.stack_id = Some(999);
        let mut resolved = event("b", "FileOpen", 11, Some("/etc/passwd"));
        resolved.sensor = "file".to_string();
        resolved.stack_id = Some(7);
        writer.write_events(&[dangling, resolved]).unwrap();
        writer
            .write_stacks(&[stack(
                7,
                "file",
                vec![frame(
                    0xffff_ffff_8100_0000,
                    Some("do_syscall_64"),
                    None,
                    None,
                    true,
                )],
                false,
            )])
            .unwrap();
        let bundle = writer.finish().unwrap();

        let counts = bundle
            .query("select count(*) as n from events")
            .await
            .unwrap();
        let rows: usize = counts.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(rows, 1);
        let count = counts[0]
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap()
            .value(0);
        assert_eq!(count, 2);

        let joined = bundle
            .query(
                "select e.event_id from events e join stacks s \
                 on e.sensor = s.sensor and e.stack_id = s.stack_id",
            )
            .await
            .unwrap();
        let rows: usize = joined.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(rows, 1, "dangling stack id must not join");
        assert_eq!(bundle.read_stacks().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn v1_bundles_remain_readable_with_an_empty_stacks_table() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("legacy-v1.fleet");
        write_v1_bundle(&root, &[event("a", "ProcessExec", 10, Some("/bin/bash"))]).await;

        let bundle = Bundle::open(&root).expect("v1 bundle must open");
        assert_eq!(bundle.format_version(), 1);
        assert_eq!(bundle.manifest().counts.events, 1);

        let counts = bundle
            .query("select count(*) as n from events")
            .await
            .unwrap();
        let rows: usize = counts.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(rows, 1);

        // Same SQL shape as v2, but the stacks table is empty.
        let empty = bundle
            .query("select count(*) as n from stacks")
            .await
            .unwrap();
        let rows: usize = empty.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(rows, 1);
        let count = empty[0]
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap()
            .value(0);
        assert_eq!(count, 0);
        assert!(bundle.read_stacks().await.unwrap().is_empty());
        assert!(bundle.read_probe_events().await.unwrap().is_empty());
        let probe_events = bundle
            .query("select count(*) as n from probe_events")
            .await
            .unwrap();
        assert_eq!(
            probe_events[0]
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .unwrap()
                .value(0),
            0
        );

        // Replay reads raw_json, which the v1 writer always wrote.
        let replay = bundle
            .query("select raw_json from events order by time_unix_ns, seq")
            .await
            .unwrap();
        assert!(!replay.is_empty());
    }

    /// Build a minimal 0.2-format bundle by hand: v1 manifest and a v1
    /// events part produced from the frozen `event_schema_v1`.
    async fn write_v1_bundle(root: &std::path::Path, events: &[Event]) {
        fs::create_dir_all(root.join("events")).unwrap();
        let batch = events_to_batch(events).expect("v2 batch");
        let v1_columns: Vec<ArrayRef> =
            batch.columns()[..event_schema_v1().fields().len()].to_vec();
        let v1_batch = RecordBatch::try_new(event_schema_v1(), v1_columns).expect("v1 batch");
        let part = root.join("events/part-00000.parquet");
        let file = File::create(&part).unwrap();
        let mut writer = ArrowWriter::try_new(file, v1_batch.schema(), None).unwrap();
        writer.write(&v1_batch).unwrap();
        writer.close().unwrap();

        let manifest = Manifest {
            format: FORMAT_V1.to_string(),
            complete: true,
            created_at: "2026-11-13T00:00:00Z".to_string(),
            tool: ToolInfo::default(),
            host: HostInfo::default(),
            capture: CaptureInfo::default(),
            schema: SchemaInfo {
                arrow_version: ARROW_SCHEMA_VERSION_V1,
                arrow_sha256: "frozen-v1".to_string(),
            },
            counts: Counts {
                events: events.len() as u64,
                ..Counts::default()
            },
            files: vec![FileInfo {
                path: "events/part-00000.parquet".to_string(),
                rows: events.len() as u64,
                sha256: sha256_file(&part).unwrap(),
            }],
        };
        let file = File::create(root.join("manifest.json")).unwrap();
        serde_json::to_writer_pretty(file, &manifest).unwrap();
    }

    #[tokio::test]
    async fn queries_events_with_sql() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("incident.fleet");
        let mut writer =
            BundleWriter::create(&root, HostInfo::default(), CaptureInfo::default()).unwrap();
        writer
            .write_events(&[
                event("a", "ProcessExec", 10, Some("/bin/bash")),
                event("b", "FileOpen", 10, Some("/etc/shadow")),
                event("c", "FileOpen", 11, Some("/etc/passwd")),
            ])
            .unwrap();
        let bundle = writer.finish().unwrap();
        let batches = bundle
            .query("select path, count(*) as n from events where kind='FileOpen' group by path order by n desc")
            .await
            .unwrap();
        assert_eq!(
            batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
            2
        );
    }
}

#[cfg(test)]
mod probe_event_tests {
    use super::*;

    fn probe_event(kind: u16, name: &str, pid: u32, payload_json: &str) -> ProbeEventRecord {
        ProbeEventRecord {
            probe: "hello".to_string(),
            kind,
            kind_name: Some(name.to_string()),
            time_unix_ns: Some(1_794_592_800_123_456_000),
            time: Some("2026-11-13T18:00:00.123456Z".to_string()),
            pid,
            tgid: pid,
            cgroup_id: 4242,
            payload_json: payload_json.to_string(),
            raw: Some("4650524201000100".to_string()),
        }
    }

    #[tokio::test]
    async fn writes_and_reads_probe_events() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("probe.fleet");
        let mut writer = BundleWriter::create(
            &root,
            HostInfo::default(),
            CaptureInfo {
                sensors: vec!["hello".to_string()],
                duration_ms: 2_000,
                stack_mode: "off".to_string(),
            },
        )
        .unwrap();
        writer
            .write_probe_events(&[
                probe_event(1, "exec", 10, r#"{"comm":"bash","task_start_ns":42}"#),
                probe_event(1, "exec", 11, r#"{"comm":"true","task_start_ns":43}"#),
            ])
            .unwrap();
        let bundle = writer.finish().unwrap();
        assert_eq!(bundle.manifest().counts.probe_events, 2);
        assert_eq!(bundle.manifest().counts.events, 0);
        assert_eq!(bundle.manifest().capture.sensors, vec!["hello"]);

        let records = bundle.read_probe_events().await.unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].probe, "hello");
        assert_eq!(records[0].kind, 1);
        assert_eq!(records[0].kind_name.as_deref(), Some("exec"));
        assert_eq!(
            records[0].payload_json,
            r#"{"comm":"bash","task_start_ns":42}"#
        );
        assert_eq!(records[0].cgroup_id, 4242);
        assert!(records[0]
            .raw
            .as_deref()
            .is_some_and(|raw| raw.starts_with("46505242")));

        let batches = bundle
            .query("select probe, kind, count(*) as n from probe_events group by probe, kind")
            .await
            .unwrap();
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 1);

        // A probe-only bundle has no sensor event parts; querying `events`
        // still works and simply returns no rows.
        let events = bundle
            .query("select count(*) as n from events")
            .await
            .unwrap();
        assert_eq!(
            events[0]
                .column(0)
                .as_any()
                .downcast_ref::<arrow_array::Int64Array>()
                .unwrap()
                .value(0),
            0
        );

        let reopened = Bundle::open(&root).unwrap();
        assert_eq!(reopened.read_probe_events().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn bundles_without_probe_events_expose_an_empty_table() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("sensor.fleet");
        let mut writer =
            BundleWriter::create(&root, HostInfo::default(), CaptureInfo::default()).unwrap();
        writer
            .write_events(&[Event {
                event_id: "evt-1".to_string(),
                time: "2026-11-13T18:00:00.000000000Z".to_string(),
                sensor: "process".to_string(),
                kind: "ProcessExec".to_string(),
                ..Event::default()
            }])
            .unwrap();
        let bundle = writer.finish().unwrap();
        assert_eq!(bundle.manifest().counts.probe_events, 0);
        assert!(bundle.read_probe_events().await.unwrap().is_empty());

        let counts = bundle
            .query("select count(*) as n from probe_events")
            .await
            .unwrap();
        assert_eq!(counts.len(), 1);
        assert_eq!(
            counts[0]
                .column(0)
                .as_any()
                .downcast_ref::<arrow_array::Int64Array>()
                .unwrap()
                .value(0),
            0
        );
    }

    #[test]
    fn rfc3339_conversion_is_public_and_lossless_for_micros() {
        assert_eq!(
            rfc3339_to_unix_ns("2026-11-13T18:00:00.123456Z"),
            Some(1_794_592_800_123_456_000)
        );
        assert_eq!(rfc3339_to_unix_ns("not a time"), None);
    }
}
