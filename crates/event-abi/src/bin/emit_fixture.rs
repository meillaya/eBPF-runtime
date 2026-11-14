// src/bin/emit_fixture.rs: event-abi
//
// Emits the binary fixtures used by `tests/parse.rs`:
//   * `v1-happy.binpb`: a complete v1 header and a 32-byte payload.
//   * `v1-truncated.binpb`: a v1 header that claims `HEADER_LEN_V1 + 16`
//     bytes when the buffer holds `HEADER_LEN_V1 + 8`.
//   * `v2-happy.binpb`: a complete v2 (104-byte) header carrying a stack
//     id and a 32-byte payload.
//
// The v1 fixtures are byte-frozen: a future ABI bump must keep emitting
// them exactly as they are so the v1 compatibility tests never drift.
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
    parse, EventKind, Header, HeaderV2, Valid, EVENT_FLAG_TRUNC, HEADER_LEN, HEADER_LEN_V1,
    SCHEMA_MAJOR, SCHEMA_MINOR, SCHEMA_V1_MAJOR, STACK_ID_NONE,
};

/// Build a version-1 `Header` value with all the test-friendly defaults.
/// The v1 fixture bytes are frozen; do not derive them from the current
/// `SCHEMA_MAJOR`/`HEADER_LEN` constants.
fn build_header(kind: EventKind, payload_len: usize) -> Header {
    let mut boot_id = [0u8; 16];
    boot_id[0] = 0xDE;
    boot_id[1] = 0xAD;
    boot_id[14] = 0xBE;
    boot_id[15] = 0xEF;

    Header {
        schema_major: SCHEMA_V1_MAJOR,
        schema_minor: SCHEMA_MINOR,
        header_len: HEADER_LEN_V1 as u32,
        record_len: (HEADER_LEN_V1 + payload_len) as u32,
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

/// Serialise a version-1 `Header` to a 96-byte buffer.
fn header_to_bytes(h: &Header) -> [u8; HEADER_LEN_V1] {
    let bytes: [u8; HEADER_LEN_V1] = unsafe {
        // SAFETY: `#[repr(C)]` and `size_of::<Header>() == 96` is
        // enforced by the const_assert in lib.rs. The cast is sound.
        core::ptr::read(core::ptr::addr_of!(*h) as *const [u8; HEADER_LEN_V1])
    };
    bytes
}

/// Serialise a v2 `HeaderV2` to its 104-byte buffer.
fn header_v2_to_bytes(h: &HeaderV2) -> [u8; HEADER_LEN] {
    let bytes: [u8; HEADER_LEN] = unsafe {
        // SAFETY: `#[repr(C)]` and `size_of::<HeaderV2>() == 104` is
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
    let mut happy = Vec::with_capacity(HEADER_LEN_V1 + 32);
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
    let mut trunc = Vec::with_capacity(HEADER_LEN_V1 + 8);
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

    // ----- v2 happy fixture: complete record with a stack id -----
    let v1 = build_header(EventKind::ProcessExecResult, 32);
    let v2_header = HeaderV2 {
        v1: Header {
            schema_major: SCHEMA_MAJOR,
            schema_minor: SCHEMA_MINOR,
            header_len: HEADER_LEN as u32,
            record_len: (HEADER_LEN + 32) as u32,
            ..v1
        },
        stack_id: 7,
        user_stack_id: -1,
    };
    let v2_header_bytes = header_v2_to_bytes(&v2_header);
    let mut v2 = Vec::with_capacity(HEADER_LEN + 32);
    v2.extend_from_slice(&v2_header_bytes);
    v2.extend_from_slice(&[0xCC; 32]);
    let v2_path = write_fixture("v2-happy.binpb", &v2)?;

    let ev = parse(&v2).expect("v2 fixture must round-trip");
    assert_eq!(ev.header, v2_header.v1, "v2 fixture v1 prefix mismatch");
    assert_eq!(ev.stack_id, Some(7), "v2 fixture stack id");
    assert_eq!(ev.payload, &[0xCC; 32], "v2 fixture payload");

    // No-stack sentinel round-trips as None.
    let mut no_stack = v2_header;
    no_stack.stack_id = STACK_ID_NONE;
    let no_stack_bytes = header_v2_to_bytes(&no_stack);
    let mut buf = Vec::new();
    buf.extend_from_slice(&no_stack_bytes);
    buf.extend_from_slice(&[0xCC; 32]);
    let ev = parse(&buf).expect("no-stack v2 record must parse");
    assert_eq!(ev.stack_id, None, "stack id -1 must decode as none");

    println!(
        "emit-fixture: v2 happy   -> {} ({} bytes)",
        v2_path.display(),
        v2.len()
    );
    Ok(())
}
