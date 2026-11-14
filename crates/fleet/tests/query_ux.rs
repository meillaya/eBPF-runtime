// SPDX-License-Identifier: Apache-2.0 OR MIT
//! End-to-end tests for the 0.3 query/inspect/diff/completions UX.
//!
//! These exercise the real `ebpf-fleet` binary against bundles written with
//! `BundleWriter`; nothing here loads BPF, so the tests run unprivileged.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use arrow::array::StringArray;
use bundle::{
    BundleWriter, CaptureInfo, HostInfo, ProbeEventRecord, ARROW_SCHEMA_VERSION_V1, FORMAT_V1,
};
use event_model::{Event, Stack, StackFrame};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use serde_json::Value;
use tempfile::TempDir;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_ebpf-fleet")
}

fn event(
    id: &str,
    kind: &str,
    sensor: &str,
    pid: u32,
    process_exec: Option<&str>,
    path: Option<&str>,
) -> Event {
    Event {
        event_id: id.to_string(),
        time: "2026-11-14T00:00:00.000000000Z".to_string(),
        sensor: sensor.to_string(),
        kind: kind.to_string(),
        pid,
        tgid: pid,
        process_exec: process_exec.map(str::to_string),
        path: path.map(str::to_string),
        ..Event::default()
    }
}

fn stack(id: i32, sensor: &str) -> Stack {
    Stack {
        stack_id: id,
        sensor: sensor.to_string(),
        frames: vec![
            StackFrame {
                addr: 0xffff_ffff_8100_0000,
                symbol: Some("do_syscall_64".to_string()),
                file: None,
                line: None,
                is_kernel: true,
            },
            StackFrame {
                addr: 0x7f00_0000_1234,
                symbol: None,
                file: None,
                line: None,
                is_kernel: false,
            },
        ],
        truncated: false,
    }
}

fn probe_record() -> ProbeEventRecord {
    ProbeEventRecord {
        probe: "hello".to_string(),
        kind: 1,
        kind_name: Some("Start".to_string()),
        time_unix_ns: Some(1_700_000_000_000_000_000),
        time: Some("2026-11-14T00:00:00Z".to_string()),
        pid: 7,
        tgid: 7,
        cgroup_id: 42,
        payload_json: "{\"value\":1}".to_string(),
        raw: Some("abcd".to_string()),
    }
}

/// Write a 0.3 bundle with two events (one with a stack), one stack row, and
/// one custom-probe event. The file path contains a comma and a quote so the
/// CSV/JSON round-trip tests cover escaping.
fn fixture() -> (TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("incident.fleet");
    let mut writer = BundleWriter::create(
        &root,
        HostInfo {
            arch: "x86_64".to_string(),
            kernel_release: "6.8.0-test".to_string(),
            boot_id: "boot".to_string(),
            ..HostInfo::default()
        },
        CaptureInfo {
            sensors: vec!["process".to_string(), "file".to_string()],
            duration_ms: 1_000,
            stack_mode: "events".to_string(),
        },
    )
    .expect("create bundle");
    let mut with_stack = event("evt-1", "FileOpen", "file", 42, Some("cat"), Some("a,b\"c"));
    with_stack.stack_id = Some(1);
    let exec = event(
        "evt-2",
        "ProcessExec",
        "process",
        7,
        Some("/bin/true"),
        Some("/bin/true"),
    );
    writer.write_events(&[with_stack, exec]).expect("events");
    writer.write_stacks(&[stack(1, "file")]).expect("stacks");
    writer
        .write_probe_events(&[probe_record()])
        .expect("probe events");
    writer.finish().expect("finish");
    (directory, root)
}

fn run(args: &[&str]) -> Output {
    Command::new(binary())
        .args(args)
        .output()
        .expect("run ebpf-fleet")
}

fn run_ok(args: &[&str]) -> Output {
    let output = run(args);
    assert!(
        output.status.success(),
        "command {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

#[test]
fn query_formats_round_trip() {
    let (_directory, root) = fixture();
    let sql = "select kind, path from events order by kind";

    // Default table output keeps the 0.3 behaviour.
    let table = run_ok(&["query", path_str(&root), sql]);
    let text = stdout_text(&table);
    assert!(text.contains("FileOpen"), "table output: {text}");
    assert!(text.contains("a,b\"c"), "table output: {text}");

    // Newline-delimited JSON, one object per row, exact escaping.
    let json = run_ok(&["query", path_str(&root), sql, "--format", "json"]);
    let lines: Vec<Value> = stdout_text(&json)
        .lines()
        .map(|line| serde_json::from_str(line).expect("json line"))
        .collect();
    assert_eq!(lines.len(), 2, "json lines: {lines:?}");
    assert_eq!(lines[0]["kind"], "FileOpen");
    assert_eq!(lines[0]["path"], "a,b\"c");
    assert_eq!(lines[1]["kind"], "ProcessExec");

    // CSV RFC 4180 escaping plus header.
    let csv_output = run_ok(&["query", path_str(&root), sql, "--format", "csv"]);
    let mut reader = csv::Reader::from_reader(csv_output.stdout.as_slice());
    let headers: Vec<String> = reader
        .headers()
        .expect("csv headers")
        .iter()
        .map(str::to_string)
        .collect();
    assert_eq!(headers, vec!["kind", "path"]);
    let rows: Vec<csv::StringRecord> = reader.records().map(|row| row.expect("csv row")).collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(&rows[0][0], "FileOpen");
    assert_eq!(&rows[0][1], "a,b\"c");

    // Parquet is a real Arrow file.
    let parquet_path = root.with_extension("result.parquet");
    let parquet = run_ok(&[
        "query",
        path_str(&root),
        sql,
        "--format",
        "parquet",
        "--out",
        path_str(&parquet_path),
    ]);
    assert!(parquet.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&parquet.stderr).contains("wrote 2 rows"),
        "stderr: {}",
        String::from_utf8_lossy(&parquet.stderr)
    );
    let reader = ParquetRecordBatchReaderBuilder::try_new(
        std::fs::File::open(&parquet_path).expect("open parquet"),
    )
    .expect("parquet reader")
    .build()
    .expect("parquet build");
    let batches: Vec<_> = reader.collect::<Result<Vec<_>, _>>().expect("batches");
    let rows: usize = batches.iter().map(|batch| batch.num_rows()).sum();
    assert_eq!(rows, 2);
    let kinds = batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("kind column");
    assert_eq!(kinds.value(0), "FileOpen");

    // --limit stops the stream early.
    let limited = run_ok(&[
        "query",
        path_str(&root),
        sql,
        "--format",
        "json",
        "--limit",
        "1",
    ]);
    assert_eq!(stdout_text(&limited).lines().count(), 1);

    // Nested Parquet (stacks frames list<struct>) is writable/readable.
    let stacks_parquet = root.with_extension("stacks.parquet");
    run_ok(&[
        "query",
        path_str(&root),
        "--table",
        "stacks",
        "--format",
        "parquet",
        "--out",
        path_str(&stacks_parquet),
    ]);
    let reader = ParquetRecordBatchReaderBuilder::try_new(
        std::fs::File::open(&stacks_parquet).expect("open stacks parquet"),
    )
    .expect("stacks parquet reader")
    .build()
    .expect("stacks parquet build");
    let batches: Vec<_> = reader
        .collect::<Result<Vec<_>, _>>()
        .expect("stacks batches");
    assert_eq!(
        batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
        1
    );

    // Empty results keep the "no rows" stderr and produce zero JSON lines.
    let empty = run_ok(&[
        "query",
        path_str(&root),
        "select kind from events where kind = 'NoSuchKind'",
        "--format",
        "json",
    ]);
    assert!(stdout_text(&empty).is_empty());
    let empty_table = run_ok(&[
        "query",
        path_str(&root),
        "select kind from events where kind = 'NoSuchKind'",
    ]);
    assert!(
        String::from_utf8_lossy(&empty_table.stderr).contains("no rows"),
        "stderr: {}",
        String::from_utf8_lossy(&empty_table.stderr)
    );

    // --limit 0 emits nothing.
    let zero = run_ok(&[
        "query",
        path_str(&root),
        sql,
        "--format",
        "json",
        "--limit",
        "0",
    ]);
    assert!(stdout_text(&zero).is_empty());

    // --out for a text format writes the file instead of stdout.
    let table_path = root.with_extension("result.txt");
    let table_out = run_ok(&[
        "query",
        path_str(&root),
        sql,
        "--out",
        path_str(&table_path),
    ]);
    assert!(table_out.stdout.is_empty());
    assert!(std::fs::read_to_string(&table_path)
        .expect("table file")
        .contains("FileOpen"));
}

#[test]
fn query_schema_and_explain() {
    let (_directory, root) = fixture();
    let schema = run_ok(&["query", path_str(&root), "--schema"]);
    let text = stdout_text(&schema);
    assert!(text.contains("# events"), "schema: {text}");
    assert!(text.contains("stack_id"), "schema: {text}");

    let stacks = run_ok(&["query", path_str(&root), "--schema", "--table", "stacks"]);
    let text = stdout_text(&stacks);
    assert!(text.contains("# stacks"), "schema: {text}");
    assert!(text.contains("frames"), "schema: {text}");

    let probes = run_ok(&[
        "query",
        path_str(&root),
        "--schema",
        "--table",
        "probe_events",
    ]);
    assert!(stdout_text(&probes).contains("payload_json"));

    let explain = run_ok(&[
        "query",
        path_str(&root),
        "select count(*) as n from events",
        "--explain",
    ]);
    let text = stdout_text(&explain);
    assert!(text.contains("logical_plan"), "explain: {text}");
    assert!(text.contains("physical_plan"), "explain: {text}");
}

#[test]
fn inspect_reports_manifest_and_coverage() {
    let (_directory, root) = fixture();
    let output = run_ok(&["inspect", path_str(&root), "--json"]);
    let report: Value = serde_json::from_slice(&output.stdout).expect("inspect json");
    assert_eq!(report["format"], "ebpf-fleet.bundle/v2");
    assert_eq!(report["format_version"], 2);
    assert_eq!(report["complete"], true);
    assert_eq!(report["counts"]["events"], 2);
    assert_eq!(report["counts"]["stacks"], 1);
    assert_eq!(report["counts"]["probe_events"], 1);
    assert_eq!(report["capture"]["stack_mode"], "events");
    assert_eq!(report["host"]["kernel_release"], "6.8.0-test");
    assert_eq!(report["stack_coverage"]["stacks"], 1);
    assert_eq!(report["stack_coverage"]["frames"], 2);
    assert_eq!(report["stack_coverage"]["missing_symbols"], 1);
    assert_eq!(report["probe_events"]["rows"], 1);
    assert_eq!(report["probe_events"]["probes"]["hello"], 1);
    assert!(report["integrity"]
        .as_str()
        .expect("integrity")
        .contains("ok"));

    let text = stdout_text(&run_ok(&["inspect", path_str(&root)]));
    assert!(text.contains("integrity:"), "inspect: {text}");
    assert!(text.contains("stack coverage:"), "inspect: {text}");
    assert!(text.contains("hello"), "inspect: {text}");
}

#[test]
fn diff_default_kind_and_by_modes() {
    let (directory, before) = fixture();
    let after = directory.path().join("after.fleet");
    let mut writer = BundleWriter::create(&after, HostInfo::default(), CaptureInfo::default())
        .expect("create after");
    // One extra FileOpen and two paths so every --by mode has deltas.
    let mut first = event("evt-1", "FileOpen", "file", 42, Some("cat"), Some("a,b\"c"));
    first.stack_id = Some(1);
    let mut second = event(
        "evt-3",
        "FileOpen",
        "file",
        50,
        Some("bash"),
        Some("/etc/shadow"),
    );
    second.stack_id = Some(1);
    let third = event(
        "evt-4",
        "FileOpen",
        "file",
        51,
        Some("bash"),
        Some("/etc/passwd"),
    );
    writer
        .write_events(&[first, second, third])
        .expect("events");
    writer.write_stacks(&[stack(1, "file")]).expect("stacks");
    writer.finish().expect("finish");

    // Default behaviour: the 0.2 kind table with before/after/delta.
    let default = stdout_text(&run_ok(&["diff", path_str(&before), path_str(&after)]));
    assert!(default.starts_with("kind"), "default: {default}");
    assert!(default.contains("FileOpen"), "default: {default}");
    assert!(default.contains("ProcessExec"), "default: {default}");

    let json = run_ok(&[
        "diff",
        path_str(&before),
        path_str(&after),
        "--by",
        "kind",
        "--json",
    ]);
    let report: Value = serde_json::from_slice(&json.stdout).expect("diff json");
    assert_eq!(report["by"], "kind");
    let rows = report["rows"].as_array().expect("rows");
    let file_open = rows
        .iter()
        .find(|row| row["key"] == "FileOpen")
        .expect("FileOpen row");
    assert_eq!(file_open["before"], 1);
    assert_eq!(file_open["after"], 3);
    assert_eq!(file_open["delta"], 2);

    for by in ["process", "path", "stack"] {
        let output = run_ok(&[
            "diff",
            path_str(&before),
            path_str(&after),
            "--by",
            by,
            "--json",
        ]);
        let report: Value = serde_json::from_slice(&output.stdout).expect("diff json");
        assert_eq!(report["by"].as_str(), Some(by));
        let rows = report["rows"].as_array().expect("rows");
        assert!(!rows.is_empty(), "--by {by} must report rows");
    }

    // Stack labels come from the first symbolized frame.
    let stacks_diff: Value = serde_json::from_slice(
        &run_ok(&[
            "diff",
            path_str(&before),
            path_str(&after),
            "--by",
            "stack",
            "--json",
        ])
        .stdout,
    )
    .expect("stack diff");
    let stack_rows = stacks_diff["rows"].as_array().expect("rows");
    assert!(
        stack_rows
            .iter()
            .any(|row| row["key"].as_str().unwrap_or("").contains("do_syscall_64")),
        "stack rows: {stack_rows:?}"
    );

    // --limit keeps only the largest deltas.
    let limited = run_ok(&[
        "diff",
        path_str(&before),
        path_str(&after),
        "--by",
        "kind",
        "--json",
        "--limit",
        "1",
    ]);
    let report: Value = serde_json::from_slice(&limited.stdout).expect("json");
    assert_eq!(report["rows"].as_array().expect("rows").len(), 1);
    assert_eq!(report["rows"][0]["key"], "FileOpen");
}

#[test]
fn probe_events_table_is_queryable() {
    let (_directory, root) = fixture();
    let output = run_ok(&[
        "query",
        path_str(&root),
        "--table",
        "probe_events",
        "--format",
        "json",
    ]);
    let lines: Vec<Value> = stdout_text(&output)
        .lines()
        .map(|line| serde_json::from_str(line).expect("json line"))
        .collect();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["probe"], "hello");
    assert_eq!(lines[0]["kind_name"], "Start");
}

#[test]
fn completions_and_man_pages() {
    let completions = run_ok(&["completions", "bash"]);
    let text = stdout_text(&completions);
    assert!(text.contains("ebpf-fleet"), "completions: {text}");
    assert!(text.contains("query"), "completions: {text}");

    let man = run_ok(&["man"]);
    let text = stdout_text(&man);
    assert!(text.contains(".TH ebpf-fleet"), "man: {text}");
    assert!(text.contains("query"), "man: {text}");

    let directory = tempfile::tempdir().expect("tempdir");
    let out = directory.path().join("man");
    let listing = stdout_text(&run_ok(&["man", "--out", path_str(&out)]));
    assert!(listing.contains("ebpf-fleet.1"), "listing: {listing}");
    assert!(out.join("ebpf-fleet.1").is_file());
    assert!(out.join("ebpf-fleet-query.1").is_file());

    let help = stdout_text(&run_ok(&["record", "--help"]));
    assert!(help.contains("--json"), "record help: {help}");
    assert!(help.contains("--quiet"), "record help: {help}");
}

#[test]
fn empty_and_v1_bundles_stay_supported() {
    // An empty 0.3 bundle: `query` keeps the old "no data parts" error, but
    // `--schema` and `inspect` work without rows.
    let directory = tempfile::tempdir().expect("tempdir");
    let empty = directory.path().join("empty.fleet");
    BundleWriter::create(&empty, HostInfo::default(), CaptureInfo::default())
        .expect("create")
        .finish()
        .expect("finish");
    let error = run(&["query", path_str(&empty)]);
    assert!(!error.status.success());
    assert!(
        String::from_utf8_lossy(&error.stderr).contains("no data parts"),
        "stderr: {}",
        String::from_utf8_lossy(&error.stderr)
    );
    let schema = stdout_text(&run_ok(&["query", path_str(&empty), "--schema"]));
    assert!(schema.contains("# events"));
    let inspect = run_ok(&["inspect", path_str(&empty), "--json"]);
    let report: Value = serde_json::from_slice(&inspect.stdout).expect("inspect json");
    assert_eq!(report["counts"]["events"], 0);
    assert_eq!(report["parts"]["events"]["files"], 0);

    // A v1 (0.2) bundle is simulated by rewriting a v2 bundle's manifest to
    // the frozen v1 format/arrow version; the reader must accept it and use
    // the v1 event schema (no `stack_id`) with an empty stacks table.
    let (_directory, root) = fixture();
    let manifest_path = root.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("manifest")).expect("json");
    manifest["format"] = Value::String(FORMAT_V1.to_string());
    manifest["schema"]["arrow_version"] = Value::from(ARROW_SCHEMA_VERSION_V1);
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");

    let inspect = run_ok(&["inspect", path_str(&root), "--json"]);
    let report: Value = serde_json::from_slice(&inspect.stdout).expect("inspect json");
    assert_eq!(report["format_version"], 1);
    assert_eq!(report["format"], FORMAT_V1);

    let count = run_ok(&[
        "query",
        path_str(&root),
        "select count(*) as n from events",
        "--format",
        "json",
    ]);
    let row: Value = serde_json::from_str(stdout_text(&count).trim()).expect("count row");
    assert_eq!(row["n"], 2);
}
