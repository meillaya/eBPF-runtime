// SPDX-License-Identifier: Apache-2.0 OR MIT
//! End-to-end tests for the local bundle CLI, without loading BPF.

use std::process::Command;

use bundle::{BundleWriter, CaptureInfo, HostInfo};
use event_model::{Event, Stack, StackFrame};

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("incident.fleet");
    let mut writer =
        BundleWriter::create(&root, HostInfo::default(), CaptureInfo::default()).unwrap();
    let event = Event {
        event_id: "evt-1".to_string(),
        time: "2026-11-13T18:00:00.000000000Z".to_string(),
        sensor: "file".to_string(),
        kind: "FileOpen".to_string(),
        pid: 42,
        tgid: 42,
        process_exec: Some("cat".to_string()),
        path: Some("/etc/shadow".to_string()),
        ..Event::default()
    };
    writer.write_events(&[event]).unwrap();
    writer.finish().unwrap();
    dir
}

#[test]
fn query_and_replay_a_bundle() {
    let dir = fixture();
    let path = dir.path().join("incident.fleet");
    let binary = env!("CARGO_BIN_EXE_ebpf-fleet");

    let query = Command::new(binary)
        .args([
            "query",
            path.to_str().unwrap(),
            "select count(*) as n from events",
        ])
        .output()
        .unwrap();
    assert!(
        query.status.success(),
        "query failed: {}",
        String::from_utf8_lossy(&query.stderr)
    );
    let stdout = String::from_utf8_lossy(&query.stdout);
    assert!(stdout.contains('1'), "unexpected query output: {stdout}");

    let replay = Command::new(binary)
        .args(["replay", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "replay failed: {}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let stdout = String::from_utf8_lossy(&replay.stdout);
    assert!(
        stdout.contains("\"event_id\":\"evt-1\""),
        "missing event: {stdout}"
    );
}

#[test]
fn policy_simulation_matches_and_enforces_expectations() {
    let dir = fixture();
    let path = dir.path().join("incident.fleet");
    let binary = env!("CARGO_BIN_EXE_ebpf-fleet");
    let rules = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rules/default")
        .canonicalize()
        .unwrap();
    let expect = dir.path().join("expect.yaml");
    std::fs::write(
        &expect,
        "rule: sensitive-file-write-intent\nmin_matches: 1\nmax_matches: 1\n",
    )
    .unwrap();

    let out = Command::new(binary)
        .args([
            "policy",
            "test",
            path.to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
            "--expect",
            expect.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "policy test failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("sensitive-file-write-intent"));
    assert!(stdout.contains("PASS"));

    std::fs::write(
        &expect,
        "rule: sensitive-file-write-intent\nmin_matches: 2\n",
    )
    .unwrap();
    let failing = Command::new(binary)
        .args([
            "policy",
            "test",
            path.to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
            "--expect",
            expect.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!failing.status.success());
}

#[test]
fn top_summarizes_a_bundle_without_a_terminal() {
    let dir = fixture();
    let path = dir.path().join("incident.fleet");
    let binary = env!("CARGO_BIN_EXE_ebpf-fleet");
    let out = Command::new(binary)
        .args(["top", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "top failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("events"));
    assert!(stdout.contains("top processes"));
    assert!(stdout.contains("FileOpen"));
}

#[test]
fn probe_build_and_explain_work_without_privileges() {
    let dir = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_ebpf-fleet");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = root.join("sdk/examples/hello_probe.bpf.c");
    let object = dir.path().join("hello_probe.bpf.o");
    let build = Command::new(binary)
        .args([
            "probe",
            "build",
            source.to_str().unwrap(),
            "--out",
            object.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "probe build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    assert!(object.is_file());

    let log = dir.path().join("verifier.log");
    std::fs::write(
        &log,
        "invalid mem access\n; file.bpf.c:12: (79) r1 = *(u64 *)(r10 - 8)\nprocessed 19 insns\n",
    )
    .unwrap();
    let explain = Command::new(binary)
        .args(["probe", "explain", log.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        explain.status.success(),
        "probe explain failed: {}",
        String::from_utf8_lossy(&explain.stderr)
    );
    let stdout = String::from_utf8_lossy(&explain.stdout);
    assert!(stdout.contains("invalid memory access"));
    assert!(stdout.contains("full verifier log"));
}

fn stack_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("stacks.fleet");
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
    let event = Event {
        event_id: "evt-stack".to_string(),
        time: "2026-11-13T18:00:00.000000000Z".to_string(),
        sensor: "file".to_string(),
        kind: "FileOpen".to_string(),
        pid: 42,
        tgid: 42,
        path: Some("/etc/shadow".to_string()),
        stack_id: Some(11),
        ..Event::default()
    };
    writer.write_events(&[event]).unwrap();
    writer
        .write_stacks(&[Stack {
            stack_id: 11,
            sensor: "file".to_string(),
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
                    symbol: Some("__libc_open64".to_string()),
                    file: Some("/usr/lib/libc.so.6".to_string()),
                    line: Some(42),
                    is_kernel: false,
                },
            ],
            truncated: false,
        }])
        .unwrap();
    writer.finish().unwrap();
    dir
}

#[test]
fn query_joins_stacks_and_table_mode() {
    let dir = stack_fixture();
    let path = dir.path().join("stacks.fleet");
    let binary = env!("CARGO_BIN_EXE_ebpf-fleet");

    let join = Command::new(binary)
        .args([
            "query",
            path.to_str().unwrap(),
            "select e.kind, s.frames from events e join stacks s on e.sensor = s.sensor and e.stack_id = s.stack_id",
        ])
        .output()
        .unwrap();
    assert!(
        join.status.success(),
        "join failed: {}",
        String::from_utf8_lossy(&join.stderr)
    );
    let stdout = String::from_utf8_lossy(&join.stdout);
    assert!(stdout.contains("FileOpen"), "missing event kind: {stdout}");
    assert!(stdout.contains("do_syscall_64"), "missing frame: {stdout}");

    let stacks = Command::new(binary)
        .args(["query", path.to_str().unwrap(), "--table", "stacks"])
        .output()
        .unwrap();
    assert!(
        stacks.status.success(),
        "stack table query failed: {}",
        String::from_utf8_lossy(&stacks.stderr)
    );
    let stdout = String::from_utf8_lossy(&stacks.stdout);
    assert!(
        stdout.contains("stack_id"),
        "missing stack_id column: {stdout}"
    );
    assert!(
        stdout.contains("__libc_open64"),
        "missing user frame: {stdout}"
    );
}

#[test]
fn top_summarizes_bundle_stacks() {
    let dir = stack_fixture();
    let path = dir.path().join("stacks.fleet");
    let binary = env!("CARGO_BIN_EXE_ebpf-fleet");
    let out = Command::new(binary)
        .args(["top", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "top failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("top stacks"),
        "missing stack pane: {stdout}"
    );
    assert!(
        stdout.contains("do_syscall_64"),
        "missing stack label: {stdout}"
    );
    assert!(
        stdout.contains("1 resolved"),
        "missing stack count: {stdout}"
    );
}
