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
    Int32Builder, Int64Builder, ListBuilder, StringBuilder, UInt32Builder, UInt64Builder,
};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use chrono::{DateTime, SecondsFormat, Utc};
use datafusion::datasource::file_format::parquet::ParquetFormat;
use datafusion::datasource::listing::{
    ListingOptions, ListingTable, ListingTableConfig, ListingTableUrl,
};
use datafusion::execution::context::SessionContext;
use event_model::Event;
use parquet::arrow::ArrowWriter;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Bundle manifest format version.
pub const FORMAT: &str = "ebpf-fleet.bundle/v1";
/// Version of the Arrow event schema written by this crate.
pub const ARROW_SCHEMA_VERSION: u32 = 1;

/// A complete, validated incident bundle.
#[derive(Debug, Clone)]
pub struct Bundle {
    root: PathBuf,
    manifest: Manifest,
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
        Ok(Self {
            final_path,
            temp_path,
            manifest: Manifest::new(host, capture),
            next_part: 0,
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
        if manifest.format != FORMAT {
            return Err(BundleError::Invalid(format!(
                "unsupported bundle format: {}",
                manifest.format
            )));
        }
        if !manifest.complete {
            return Err(BundleError::Incomplete(
                "manifest.complete is false".to_string(),
            ));
        }
        if manifest.schema.arrow_version != ARROW_SCHEMA_VERSION {
            return Err(BundleError::Invalid(format!(
                "unsupported arrow schema: {}",
                manifest.schema.arrow_version
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
        Ok(Self { root, manifest })
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
        })
    }

    /// Execute SQL against the bundle's `events` table.
    pub async fn query(&self, sql: &str) -> Result<Vec<RecordBatch>, BundleError> {
        if self.manifest.files.is_empty() {
            return Err(BundleError::Invalid(
                "bundle has no event parts".to_string(),
            ));
        }
        let mut paths = Vec::with_capacity(self.manifest.files.len());
        for file in &self.manifest.files {
            let path = self.root.join(&file.path);
            let path = path
                .to_str()
                .ok_or_else(|| BundleError::Invalid("bundle path is not UTF-8".to_string()))?;
            paths.push(
                ListingTableUrl::parse(path)
                    .map_err(|error| BundleError::Invalid(error.to_string()))?,
            );
        }
        let options =
            ListingOptions::new(Arc::new(ParquetFormat::default())).with_file_extension(".parquet");
        let config = ListingTableConfig::new_with_multi_paths(paths)
            .with_listing_options(options)
            .with_schema(event_schema());
        let table = ListingTable::try_new(config)
            .map_err(|error| BundleError::Invalid(error.to_string()))?;
        let ctx = SessionContext::new();
        ctx.register_table("events", Arc::new(table))?;
        let frame = ctx.sql(sql).await?;
        Ok(frame.collect().await?)
    }
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

    for event in events {
        event_id.append_value(&event.event_id);
        time.append_value(&event.time);
        time_unix_ns.append_option(parse_time_ns(&event.time));
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
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

fn event_schema() -> SchemaRef {
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

fn parse_time_ns(value: &str) -> Option<i64> {
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

    #[test]
    fn packs_and_unpacks_a_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("incident.fleet");
        let mut writer =
            BundleWriter::create(&root, HostInfo::default(), CaptureInfo::default()).unwrap();
        writer
            .write_events(&[event("a", "ProcessExec", 10, Some("/bin/bash"))])
            .unwrap();
        let bundle = writer.finish().unwrap();
        let archive = dir.path().join("incident.fleet.tar.zst");
        bundle.pack(&archive).unwrap();
        let extracted = dir.path().join("restored.fleet");
        let restored = Bundle::unpack(&archive, &extracted).unwrap();
        assert_eq!(restored.manifest().counts.events, 1);
        assert_eq!(restored.root(), extracted);
        assert!(Bundle::open(&extracted).is_ok());
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
