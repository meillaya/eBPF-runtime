// SPDX-License-Identifier: Apache-2.0 OR MIT
//! End-to-end tests for the local bundle CLI, without loading BPF.

use std::process::Command;

use bundle::{BundleWriter, CaptureInfo, HostInfo};
use event_model::Event;

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
