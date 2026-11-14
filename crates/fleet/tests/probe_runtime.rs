// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CLI tests for the custom probe runtime (`fleet probe run`) and the
//! `probe_events` bundle table.
//!
//! The privileged attach/decode path is proven on a real VM and recorded in
//! `docs/verification/probe-runtime.md`; these tests cover the manifest,
//! pinning, and validation paths that must fail safely without privileges.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use bundle::{BundleWriter, CaptureInfo, HostInfo, ProbeEventRecord};
use sha2::{Digest, Sha256};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ebpf-fleet"))
}

fn run(args: &[&str]) -> Output {
    binary().args(args).output().expect("run ebpf-fleet")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The example probe compiled once per test process into the gitignored
/// probe output directory.
fn hello_object() -> &'static Path {
    static OBJECT: OnceLock<PathBuf> = OnceLock::new();
    OBJECT.get_or_init(|| {
        let root = probe::workspace_root();
        let source = root.join("sdk/examples/hello_probe.bpf.c");
        let object = probe::default_out_dir().join("fleet-tests/hello_probe.bpf.o");
        probe::build(&source, &object, &[])
            .expect("the example probe must compile with the project clang");
        object
    })
}

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).expect("read object");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    format!("{:x}", hasher.finalize())
}

fn manifest_yaml(
    object: &Path,
    sha256: Option<&str>,
    section: &str,
    attach: &str,
    ringbuf: &str,
) -> String {
    let pin = sha256
        .map(|digest| format!("sha256: \"{digest}\"\n"))
        .unwrap_or_default();
    format!(
        "version: 1\n\
         name: hello\n\
         description: Test manifest for the example probe.\n\
         object: \"{}\"\n\
         {pin}\
         section: {section}\n\
         attach: {attach}\n\
         ringbuf: {ringbuf}\n\
         supported_kernel: \">=5.8\"\n\
         events:\n\
         \x20 envelope: fprb\n\
         \x20 version: 1\n\
         \x20 kinds:\n\
         \x20   - kind: 1\n\
         \x20     name: exec\n\
         \x20     fields:\n\
         \x20       - {{ name: comm, type: string, size: 16 }}\n\
         \x20       - {{ name: task_start_ns, type: u64 }}\n",
        object.display()
    )
}

fn write_manifest(directory: &Path, contents: &str) -> PathBuf {
    let path = directory.join("hello_probe.manifest.yaml");
    fs::write(&path, contents).expect("write manifest");
    path
}

fn valid_manifest(directory: &Path) -> PathBuf {
    let object = hello_object();
    let sha256 = sha256_file(object);
    let yaml = manifest_yaml(
        object,
        Some(&sha256),
        "tracepoint/sched/sched_process_exec",
        "tracepoint",
        "hello_events",
    );
    write_manifest(directory, &yaml)
}

fn effective_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    line.split_whitespace().nth(2)?.parse().ok()
}

#[test]
fn probe_run_rejects_a_missing_manifest() {
    let output = run(&[
        "probe",
        "run",
        "--manifest",
        "/nonexistent/probe.manifest.yaml",
    ]);
    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(error.contains("cannot read probe manifest"), "{error}");
}

#[test]
fn probe_run_rejects_an_unsupported_manifest_version() {
    let directory = tempfile::tempdir().expect("temp dir");
    let object = hello_object();
    let sha256 = sha256_file(object);
    let yaml = manifest_yaml(
        object,
        Some(&sha256),
        "tracepoint/sched/sched_process_exec",
        "tracepoint",
        "hello_events",
    );
    let version_2 = yaml.replacen("version: 1\n", "version: 2\n", 1);
    let manifest = write_manifest(directory.path(), &version_2);
    let output = run(&["probe", "run", "--manifest", manifest.to_str().unwrap()]);
    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(error.contains("unsupported manifest version 2"), "{error}");
}

#[test]
fn probe_run_requires_a_sha256_pin_or_explicit_opt_in() {
    let directory = tempfile::tempdir().expect("temp dir");
    let object = directory.path().join("hello.bpf.o");
    fs::write(&object, b"not a real object, only hashed").expect("write object");
    let manifest = write_manifest(
        directory.path(),
        &manifest_yaml(
            &object,
            None,
            "tracepoint/sched/sched_process_exec",
            "tracepoint",
            "hello_events",
        ),
    );
    let output = run(&["probe", "run", "--manifest", manifest.to_str().unwrap()]);
    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(error.contains("--allow-unpinned"), "{error}");
    assert!(error.contains("no sha256 pin"), "{error}");
}

#[test]
fn probe_run_rejects_a_hash_mismatch() {
    let directory = tempfile::tempdir().expect("temp dir");
    let object = directory.path().join("hello.bpf.o");
    fs::write(&object, b"tampered object bytes").expect("write object");
    let manifest = write_manifest(
        directory.path(),
        &manifest_yaml(
            &object,
            Some(&"0".repeat(64)),
            "tracepoint/sched/sched_process_exec",
            "tracepoint",
            "hello_events",
        ),
    );
    let output = run(&["probe", "run", "--manifest", manifest.to_str().unwrap()]);
    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(error.contains("hash mismatch"), "{error}");
    assert!(error.contains("manifest pins"), "{error}");
}

#[test]
fn probe_run_reports_a_wrong_section_before_loading() {
    let directory = tempfile::tempdir().expect("temp dir");
    let object = hello_object();
    let sha256 = sha256_file(object);
    let manifest = write_manifest(
        directory.path(),
        &manifest_yaml(
            object,
            Some(&sha256),
            "kprobe/does_not_exist",
            "kprobe",
            "hello_events",
        ),
    );
    let output = run(&["probe", "run", "--manifest", manifest.to_str().unwrap()]);
    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(
        error.contains("is not in") && error.contains("kprobe/does_not_exist"),
        "{error}"
    );
    assert!(
        error.contains("tracepoint/sched/sched_process_exec"),
        "the error must list the sections the object does declare: {error}"
    );
}

#[test]
fn probe_run_reports_a_missing_ring_buffer_map() {
    let directory = tempfile::tempdir().expect("temp dir");
    let object = hello_object();
    let sha256 = sha256_file(object);
    let manifest = write_manifest(
        directory.path(),
        &manifest_yaml(
            object,
            Some(&sha256),
            "tracepoint/sched/sched_process_exec",
            "tracepoint",
            "not_the_map",
        ),
    );
    let output = run(&["probe", "run", "--manifest", manifest.to_str().unwrap()]);
    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(error.contains("not a ring buffer"), "{error}");
    assert!(error.contains("hello_events"), "{error}");
}

#[test]
fn probe_run_is_root_only() {
    if effective_uid() == Some(0) {
        // The privileged path is covered by the VM evidence in
        // docs/verification/probe-runtime.md; the CLI test suite is meant to
        // run unprivileged.
        return;
    }
    let directory = tempfile::tempdir().expect("temp dir");
    let manifest = valid_manifest(directory.path());
    let output = run(&["probe", "run", "--manifest", manifest.to_str().unwrap()]);
    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(error.contains("root-only"), "{error}");
    assert!(error.contains("sudo"), "{error}");
}

#[test]
fn query_reads_the_probe_events_table() {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = directory.path().join("hello.fleet");
    let mut writer = BundleWriter::create(
        &root,
        HostInfo::default(),
        CaptureInfo {
            sensors: vec!["hello".to_string()],
            duration_ms: 1_000,
            stack_mode: "off".to_string(),
        },
    )
    .expect("create bundle");
    writer
        .write_probe_events(&[ProbeEventRecord {
            probe: "hello".to_string(),
            kind: 1,
            kind_name: Some("exec".to_string()),
            time_unix_ns: Some(1_794_592_800_123_456_000),
            time: Some("2026-11-13T18:00:00.123456Z".to_string()),
            pid: 10,
            tgid: 10,
            cgroup_id: 4242,
            payload_json: r#"{"comm":"bash","task_start_ns":42}"#.to_string(),
            raw: Some("4650524201000100".to_string()),
        }])
        .expect("write probe events");
    writer.finish().expect("finish bundle");

    let summary = run(&["query", root.to_str().unwrap(), "--table", "probe_events"]);
    assert!(
        summary.status.success(),
        "query failed: {}",
        stderr(&summary)
    );
    let printed = stdout(&summary);
    assert!(printed.contains("hello"), "{printed}");
    assert!(printed.contains("exec"), "{printed}");

    let count = run(&[
        "query",
        root.to_str().unwrap(),
        "select count(*) as n from probe_events",
    ]);
    assert!(count.status.success(), "query failed: {}", stderr(&count));
    assert!(stdout(&count).contains('1'), "{}", stdout(&count));
}

#[test]
fn query_reads_a_sensor_bundle_with_an_empty_probe_events_table() {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = directory.path().join("sensor.fleet");
    let mut writer = BundleWriter::create(&root, HostInfo::default(), CaptureInfo::default())
        .expect("create bundle");
    writer
        .write_events(&[event_model::Event {
            event_id: "evt-1".to_string(),
            time: "2026-11-13T18:00:00.000000000Z".to_string(),
            sensor: "process".to_string(),
            kind: "ProcessExec".to_string(),
            ..event_model::Event::default()
        }])
        .expect("write event");
    writer.finish().expect("finish bundle");

    let output = run(&["query", root.to_str().unwrap(), "--table", "probe_events"]);
    assert!(output.status.success(), "query failed: {}", stderr(&output));
    assert!(stderr(&output).contains("no rows"), "{}", stderr(&output));
}
