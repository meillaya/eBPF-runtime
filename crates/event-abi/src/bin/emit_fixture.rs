// src/bin/emit_fixture.rs: event-abi
//
// Emits two binary fixtures used by `tests/parse.rs`:
//   * `v1-happy.binpb`: a complete header and a 32-byte payload.
//   * `v1-truncated.binpb`: a header that claims `HEADER_LEN + 16`
//     bytes when the buffer holds `HEADER_LEN + 8`.
//
// Fixtures are written into
// `crates/event-abi/tests/fixtures/event-abi/`. The directory is
// checked in so a fresh clone can `cargo nextest run -p event-abi`
// without first running this binary; running the binary is part of the
// acceptance evidence (`cargo run -p event-abi --bin emit-fixture`).
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

use event_abi::{
    parse, EventKind, Header, Valid, EVENT_FLAG_TRUNC, HEADER_LEN, SCHEMA_MAJOR, SCHEMA_MINOR,
};

/// Build a `Header` value with all the test-friendly defaults.
fn build_header(kind: EventKind, payload_len: usize) -> Header {
    let mut boot_id = [0u8; 16];
    boot_id[0] = 0xDE;
    boot_id[1] = 0xAD;
    boot_id[14] = 0xBE;
    boot_id[15] = 0xEF;

    Header {
        schema_major: SCHEMA_MAJOR,
        schema_minor: SCHEMA_MINOR,
        header_len: HEADER_LEN as u32,
        record_len: (HEADER_LEN + payload_len) as u32,
        event_kind: kind as u8,
        _pad0: [0u8; 3],
        flags: 0,
        _pad1: [0u8; 3],
        seq: 0x0000_0001_0000_0002,
        ts_monotonic_ns: 0x0000_0003_0000_0004,
        boot_id,
        pid_tgid: 0x0000_0005_0000_0006,
        task_start_time_ns: 0x0000_0007_0000_0008,
        cgroup_id: 0x0000_0009_0000_000A,
        processor_id: 7,
        valids: Valid::BootId as u32
            | Valid::CgroupId as u32
            | Valid::PidTgid as u32
            | Valid::NsPid as u32
            | Valid::TaskStart as u32
            | Valid::Processor as u32,
        ns_pid: 0x0000_000B_0000_000C,
    }
}

/// Serialise a `Header` to a 96-byte buffer.
fn header_to_bytes(h: &Header) -> [u8; HEADER_LEN] {
    let bytes: [u8; HEADER_LEN] = unsafe {
        // SAFETY: `#[repr(C)]` and `size_of::<Header>() == 96` is
        // enforced by the const_assert in lib.rs. The cast is sound.
        core::ptr::read(core::ptr::addr_of!(*h) as *const [u8; HEADER_LEN])
    };
    bytes
}

fn fixtures_dir() -> io::Result<PathBuf> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("CARGO_MANIFEST_DIR: {e}")))?;
    let dir = PathBuf::from(manifest_dir).join("tests/fixtures/event-abi");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn write_fixture(name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
    let dir = fixtures_dir()?;
    let path = dir.join(name);
    fs::write(&path, bytes)?;
    Ok(path)
}

fn main() -> io::Result<()> {
    // ----- happy fixture: complete record, 32-byte payload -----
    let header = build_header(EventKind::ProcessExecResult, 32);
    let header_bytes = header_to_bytes(&header);
    let mut happy = Vec::with_capacity(HEADER_LEN + 32);
    happy.extend_from_slice(&header_bytes);
    happy.extend_from_slice(&[0xAA; 32]);
    let happy_path = write_fixture("v1-happy.binpb", &happy)?;

    // Verify the happy fixture round-trips through the parser.
    let ev = parse(&happy).expect("happy fixture must round-trip");
    assert_eq!(ev.header, header, "happy fixture header mismatch");
    assert_eq!(ev.payload.len(), 32, "happy fixture payload length");
    assert_eq!(ev.kind_name(), "PROCESS_EXEC_RESULT");

    // ----- truncated fixture: header says record_len=112, only 104 bytes -----
    let mut trunc_header = build_header(EventKind::FileOpen, 16);
    trunc_header.flags = EVENT_FLAG_TRUNC;
    trunc_header.valids |= Valid::PayloadTrunc as u32;
    let trunc_header_bytes = header_to_bytes(&trunc_header);
    let mut trunc = Vec::with_capacity(HEADER_LEN + 8);
    trunc.extend_from_slice(&trunc_header_bytes);
    trunc.extend_from_slice(&[0xBB; 8]);
    let trunc_path = write_fixture("v1-truncated.binpb", &trunc)?;

    // Verify the truncated fixture: parser sees record_len=112 but
    // only 104 bytes; the record is rejected as LengthMismatch (this
    // is the documented behaviour. `LengthMismatch` returns before
    // payload extraction, so the fixture is exercised by the
    // `record_len > buf_len` branch in `parse`).
    let res = parse(&trunc);
    assert!(
        matches!(res, Err(event_abi::DecodeError::LengthMismatch { .. })),
        "truncated fixture should fail with LengthMismatch, got: {res:?}"
    );

    println!(
        "emit-fixture: happy      -> {} ({} bytes)",
        happy_path.display(),
        happy.len()
    );
    println!(
        "emit-fixture: truncated  -> {} ({} bytes)",
        trunc_path.display(),
        trunc.len()
    );
    Ok(())
}
