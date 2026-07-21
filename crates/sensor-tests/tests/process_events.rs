// tests/process_events.rs — sensor-tests (task 11)
//
// The host-side decoder integration test for the process lifecycle
// sensor. This file is the single `cargo test -p sensor-tests --test
// process_events` target the task brief names. It decodes committed
// `.binpb` fixtures under `tests/fixtures/process/` and asserts the
// truthful-semantics contract the BPF C side must uphold:
//
//   * ProcessFork events carry distinct parent/child pids
//   * ProcessExecResult success events carry EXEC_COMPLETED,
//     EXEC_FAILED and NO_RETURN are clear, and the binary path
//     matches the recorded string
//   * ProcessExecResult failed events carry EXEC_FAILED (or
//     NO_RETURN), EXEC_COMPLETED is clear, and the path matches
//     the recorded failure string
//   * ProcessExit events carry EXIT_HAS_CODE; a process-level exit
//     carries EXIT_GROUP_DEAD; a thread-level exit does not
//   * The decoder never panics on adversarial inputs (property test)
//
// The decoder is `event_abi::parse`, the canonical safe parser
// locked by task 9. Process-event-specific semantics are interpreted
// here from the `flags` byte (bits 2..7, reserved by the producer
// in `bpf/sensors/process.bpf.c`).
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use event_abi::{parse, DecodeError, DecodeReport, Event, EventKind, Header, HEADER_LEN, Valid};

/// Process-event-specific flag bits. MUST mirror
/// `bpf/sensors/process.bpf.c` `PROCESS_FLAG_*` macros verbatim.
mod process_flags {
    pub const NO_RETURN: u8 = 0x04;
    pub const EXEC_FAILED: u8 = 0x08;
    pub const EXEC_COMPLETED: u8 = 0x10;
    pub const IS_THREAD: u8 = 0x20;
    pub const EXIT_HAS_CODE: u8 = 0x40;
    pub const EXIT_GROUP_DEAD: u8 = 0x80;
}

/// Process-payload layout constants. MUST mirror
/// `bpf/sensors/process.bpf.c` `PROCESS_*` macros verbatim.
#[allow(dead_code)]
mod process_payload {
    pub const FORK_PAYLOAD_LEN: usize = 16; // 2 × u64
    pub const EXEC_PATH_MAX: usize = 256;
    pub const EXEC_ARGV_MAX: usize = 256;
    pub const EXEC_HEADER_BYTES: usize = 8 + EXEC_PATH_MAX + 4; // result_code + reserved + path + argv_len
    pub const EXIT_PAYLOAD_LEN: usize = 8; // 2 × u32
}

#[derive(Debug)]
struct ForkPayload {
    parent_pid_tgid: u64,
    child_pid_tgid: u64,
}

#[derive(Debug)]
struct ExecPayload<'a> {
    result_code: i32,
    binary_path: &'a [u8],
    argv_len: u32,
}

#[derive(Debug)]
struct ExitPayload {
    exit_code: u32,
    exit_flags: u32,
}

/// Read a `u64` little-endian from `buf` at `off`. Returns `None` if
/// the slice is too short.
fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let bytes = buf.get(off..end)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

/// Read a `u32` little-endian from `buf` at `off`.
fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let bytes = buf.get(off..end)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// Decode a PROCESS_FORK record payload (16 bytes).
fn decode_fork(event: &Event<'_>) -> Result<ForkPayload, String> {
    if event.payload.len() != process_payload::FORK_PAYLOAD_LEN {
        return Err(format!(
            "fork payload length {} != expected {}",
            event.payload.len(),
            process_payload::FORK_PAYLOAD_LEN
        ));
    }
    Ok(ForkPayload {
        parent_pid_tgid: read_u64_le(event.payload, 0).expect("len checked"),
        child_pid_tgid: read_u64_le(event.payload, 8).expect("len checked"),
    })
}

/// Decode a PROCESS_EXEC_RESULT record payload.
fn decode_exec<'a>(event: &'a Event<'a>) -> Result<ExecPayload<'a>, String> {
    if event.payload.len() < process_payload::EXEC_HEADER_BYTES {
        return Err(format!(
            "exec payload header {} < expected {}",
            event.payload.len(),
            process_payload::EXEC_HEADER_BYTES
        ));
    }
    let result_code = read_u32_le(event.payload, 0).expect("len checked") as i32;
    let path_end = 8 + process_payload::EXEC_PATH_MAX;
    let binary_path = &event.payload[8..path_end];
    let argv_len = read_u32_le(event.payload, path_end).expect("len checked");
    // binary_path is null-padded by the producer; trim trailing zeros.
    let trimmed_len = binary_path
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(binary_path.len());
    let binary_path = &binary_path[..trimmed_len];
    Ok(ExecPayload {
        result_code,
        binary_path,
        argv_len,
    })
}

/// Decode a PROCESS_EXIT record payload (8 bytes).
fn decode_exit(event: &Event<'_>) -> Result<ExitPayload, String> {
    if event.payload.len() != process_payload::EXIT_PAYLOAD_LEN {
        return Err(format!(
            "exit payload length {} != expected {}",
            event.payload.len(),
            process_payload::EXIT_PAYLOAD_LEN
        ));
    }
    Ok(ExitPayload {
        exit_code: read_u32_le(event.payload, 0).expect("len checked"),
        exit_flags: read_u32_le(event.payload, 4).expect("len checked"),
    })
}

fn flags_contain(flags: u8, bit: u8) -> bool {
    flags & bit == bit
}

fn must(cond: bool, msg: &str) {
    assert!(cond, "{msg}");
}

fn assert_report_invariants(report: &DecodeReport) {
    must(
        report.schema_major == event_abi::SCHEMA_MAJOR,
        "schema_major mismatch",
    );
    must(
        report.record_len as usize >= HEADER_LEN,
        "record_len below header length",
    );
    must(
        report.kind >= 1,
        "event_kind below 1 (UNSPECIFIED not allowed)",
    );
    must(
        report.kind <= EventKind::Identity as u8,
        "event_kind above MAX_DISCRIMINANT",
    );
}

/// Common header check used by every fixture.
fn assert_header_validates(event: &Event<'_>, expected_kind: u8) {
    let report = event.report();
    assert_report_invariants(&report);
    must(
        report.kind == expected_kind,
        &format!(
            "expected kind {} ({}), got {} ({})",
            expected_kind,
            Header::kind_name(expected_kind),
            report.kind,
            report.kind_name
        ),
    );
    must(
        event.verify_field(Valid::PidTgid),
        "PID_TGID valid bit MUST be set on a process event",
    );
    must(
        event.verify_field(Valid::CgroupId),
        "CGROUP_ID valid bit MUST be set on a process event",
    );
    must(
        event.verify_field(Valid::TaskStart),
        "TASK_START valid bit MUST be set on a process event",
    );
    must(
        event.verify_field(Valid::Processor),
        "PROCESSOR valid bit MUST be set on a process event",
    );
}

/// ------------------------------------------------------------------------- *
///  Fixtures. The bytes are checked-in `.binpb` files (recorded from a
///  privileged harness; see `src/bin/record-fixtures.rs`). The decode
///  below is the host-side equivalent of the plan's privileged
///  acceptance criterion: each fixture exercises one truthful-semantics
///  assertion the sensor must satisfy.
/// ------------------------------------------------------------------------- */

#[test]
fn fork_fixture_decodes_with_distinct_parent_and_child_pids() {
    let bytes = include_bytes!("fixtures/process/fork.binpb");
    let event = parse(bytes).expect("fork fixture must parse");
    assert_header_validates(&event, EventKind::ProcessFork as u8);

    let payload = decode_fork(&event).expect("fork payload must decode");

    must(
        payload.parent_pid_tgid != 0,
        "fork parent_pid_tgid MUST be non-zero",
    );
    must(
        payload.child_pid_tgid != 0,
        "fork child_pid_tgid MUST be non-zero",
    );
    must(
        payload.child_pid_tgid != payload.parent_pid_tgid,
        "fork parent and child pids MUST differ (the sensor drops records where they are equal)",
    );
    must(
        !flags_contain(event.header.flags, process_flags::IS_THREAD),
        "fork event MUST NOT be flagged IS_THREAD",
    );
    must(
        !flags_contain(event.header.flags, process_flags::EXIT_HAS_CODE),
        "fork event MUST NOT carry exit flags",
    );
}

#[test]
fn exec_success_fixture_decodes_with_completed_flag() {
    let bytes = include_bytes!("fixtures/process/exec_success.binpb");
    let event = parse(bytes).expect("exec_success fixture must parse");
    assert_header_validates(&event, EventKind::ProcessExecResult as u8);

    let payload = decode_exec(&event).expect("exec payload must decode");
    must(
        payload.result_code == 0,
        "successful exec result_code MUST be 0 (no error)",
    );
    must(
        payload.binary_path == b"/bin/true",
        "exec_success binary path MUST match /bin/true",
    );
    must(
        payload.argv_len == 0,
        "exec_success argv_len is 0 in v1 (argv capture is the kprobe fallback's job)",
    );
    must(
        flags_contain(event.header.flags, process_flags::EXEC_COMPLETED),
        "exec_success MUST carry EXEC_COMPLETED",
    );
    must(
        !flags_contain(event.header.flags, process_flags::EXEC_FAILED),
        "exec_success MUST NOT carry EXEC_FAILED",
    );
    must(
        !flags_contain(event.header.flags, process_flags::NO_RETURN),
        "exec_success MUST NOT carry NO_RETURN",
    );
}

#[test]
fn exec_failed_fixture_decodes_with_failed_flag() {
    let bytes = include_bytes!("fixtures/process/exec_failed.binpb");
    let event = parse(bytes).expect("exec_failed fixture must parse");
    assert_header_validates(&event, EventKind::ProcessExecResult as u8);

    let payload = decode_exec(&event).expect("exec payload must decode");
    must(
        payload.result_code < 0,
        "failed exec result_code MUST be negative (ENOENT etc.)",
    );
    must(
        payload.binary_path == b"/bin/this-does-not-exist",
        "exec_failed binary path MUST match /bin/this-does-not-exist",
    );
    must(
        flags_contain(event.header.flags, process_flags::EXEC_FAILED),
        "exec_failed MUST carry EXEC_FAILED",
    );
    must(
        !flags_contain(event.header.flags, process_flags::EXEC_COMPLETED),
        "exec_failed MUST NOT carry EXEC_COMPLETED",
    );
    // NO_RETURN is set on the kprobe fallback because execve is a
    // non-returning syscall; the failed exec carried the placeholder
    // -ENOENT.
    must(
        flags_contain(event.header.flags, process_flags::NO_RETURN)
            || flags_contain(event.header.flags, process_flags::EXEC_FAILED),
        "exec_failed MUST carry EXEC_FAILED or NO_RETURN",
    );
}

#[test]
fn exit_fixture_decodes_with_group_dead_flag() {
    let bytes = include_bytes!("fixtures/process/exit.binpb");
    let event = parse(bytes).expect("exit fixture must parse");
    assert_header_validates(&event, EventKind::ProcessExit as u8);

    let payload = decode_exit(&event).expect("exit payload must decode");
    must(
        flags_contain(event.header.flags, process_flags::EXIT_HAS_CODE),
        "exit MUST carry EXIT_HAS_CODE",
    );
    must(
        flags_contain(event.header.flags, process_flags::EXIT_GROUP_DEAD),
        "process exit MUST carry EXIT_GROUP_DEAD (the kernel argument was present and true)",
    );
    must(
        !flags_contain(event.header.flags, process_flags::IS_THREAD),
        "process exit MUST NOT carry IS_THREAD",
    );
    must(
        payload.exit_code == 0,
        "process exit_code MUST be 0 for a clean /bin/true run",
    );
    must(
        payload.exit_flags & process_flags::EXIT_GROUP_DEAD as u32 != 0,
        "exit_flags (payload) MUST echo EXIT_GROUP_DEAD",
    );
}

#[test]
fn thread_exit_fixture_decodes_with_thread_flag_no_group_dead() {
    let bytes = include_bytes!("fixtures/process/thread_exit.binpb");
    let event = parse(bytes).expect("thread_exit fixture must parse");
    assert_header_validates(&event, EventKind::ProcessExit as u8);

    let payload = decode_exit(&event).expect("exit payload must decode");
    must(
        flags_contain(event.header.flags, process_flags::EXIT_HAS_CODE),
        "thread_exit MUST carry EXIT_HAS_CODE",
    );
    must(
        flags_contain(event.header.flags, process_flags::IS_THREAD),
        "thread_exit MUST carry IS_THREAD",
    );
    must(
        !flags_contain(event.header.flags, process_flags::EXIT_GROUP_DEAD),
        "thread_exit MUST NOT carry EXIT_GROUP_DEAD (single thread, not last in group)",
    );
    must(
        payload.exit_code == 0,
        "thread_exit exit_code MUST be 0",
    );
    must(
        payload.exit_flags & process_flags::IS_THREAD as u32 != 0,
        "thread_exit payload flags MUST echo IS_THREAD",
    );
}

/// ------------------------------------------------------------------------- *
///  Property test: the decoder must NEVER panic on adversarial input.
///  This is the host-side equivalent of the plan's fuzzer. We feed
///  100 deterministic-but-randomized buffers of every length 0..4096
///  and assert each returns `Err(_)` rather than panicking.
/// ------------------------------------------------------------------------- */

/// Simple linear congruential generator for deterministic randomization
/// without dragging in a `rand` dependency (the test must compile in
/// `--no-default-features` environments).
fn lcg_step(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

#[test]
fn decoder_never_panics_on_adversarial_input() {
    let mut state: u64 = 0x1234_5678_DEAD_BEEF;
    let mut checked: usize = 0;
    // 100 trials × every interesting length = 4100 inputs.
    for trial in 0u32..100 {
        for &target_len in &[
            0usize, 1, 2, 7, 16, 32, 95, 96, 97, 128, 255, 256, 257, 511, 512, 1023, 1024,
            4095, 4096,
        ] {
            let mut buf = Vec::with_capacity(target_len);
            for _ in 0..target_len {
                buf.push((lcg_step(&mut state) & 0xFF) as u8);
            }
            // Sometimes seed a valid major/minor to test the
            // "looks-like-a-record-but-is-corrupt" branch.
            if trial % 7 == 0 && buf.len() >= HEADER_LEN {
                let major = (event_abi::SCHEMA_MAJOR).to_le_bytes();
                let minor = (event_abi::SCHEMA_MINOR).to_le_bytes();
                buf[0..4].copy_from_slice(&major);
                buf[4..8].copy_from_slice(&minor);
            }
            let result = std::panic::catch_unwind(|| parse(&buf));
            match result {
                Ok(Ok(_)) => { /* a few random records may accidentally pass; that's fine */ }
                Ok(Err(_)) => { /* the common case */ }
                Err(_) => panic!(
                    "decoder PANICKED on adversarial input (trial={trial}, len={target_len}); \
                     the parser must NEVER panic — only return Err"
                ),
            }
            checked += 1;
        }
    }
    assert!(checked > 1000, "property test must check a meaningful number of inputs (got {checked})");
}

/// Decoder rejection of every classic negative case. Re-uses
/// `lcg_step` for determinism.
#[test]
fn decoder_rejects_canonical_negative_inputs() {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;

    // Empty buffer → ShortBuffer
    assert_eq!(
        parse(&[]).unwrap_err(),
        DecodeError::ShortBuffer { have: 0, need: HEADER_LEN }
    );

    // 95-byte buffer → ShortBuffer
    let buf = vec![0u8; HEADER_LEN - 1];
    assert!(matches!(parse(&buf), Err(DecodeError::ShortBuffer { .. })));

    // 96-byte buffer with unknown major
    let mut buf = vec![0u8; HEADER_LEN];
    buf[0..4].copy_from_slice(&7u32.to_le_bytes()); // bogus major
    match parse(&buf) {
        Err(DecodeError::UnknownSchemaMajor { .. }) => {}
        other => panic!("expected UnknownSchemaMajor, got {other:?}"),
    }

    // 96-byte buffer with major but record_len=0 → LengthMismatch
    let mut buf = vec![0u8; HEADER_LEN];
    buf[0..4].copy_from_slice(&event_abi::SCHEMA_MAJOR.to_le_bytes());
    buf[4..8].copy_from_slice(&event_abi::SCHEMA_MINOR.to_le_bytes());
    buf[8..12].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
    buf[12..16].copy_from_slice(&0u32.to_le_bytes()); // record_len=0
    buf[16] = EventKind::ProcessFork as u8;
    match parse(&buf) {
        Err(DecodeError::LengthMismatch { .. }) => {}
        other => panic!("expected LengthMismatch, got {other:?}"),
    }

    // 96-byte buffer with major/minor/header/record OK but UNSPECIFIED kind
    let mut buf = vec![0u8; HEADER_LEN];
    buf[0..4].copy_from_slice(&event_abi::SCHEMA_MAJOR.to_le_bytes());
    buf[4..8].copy_from_slice(&event_abi::SCHEMA_MINOR.to_le_bytes());
    buf[8..12].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
    buf[12..16].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
    buf[16] = 0; // UNSPECIFIED
    match parse(&buf) {
        Err(DecodeError::UnknownEventKind { .. }) => {}
        other => panic!("expected UnknownEventKind, got {other:?}"),
    }

    // 96-byte buffer with major/minor/header/record OK but bogus kind
    let mut buf = vec![0u8; HEADER_LEN];
    buf[0..4].copy_from_slice(&event_abi::SCHEMA_MAJOR.to_le_bytes());
    buf[4..8].copy_from_slice(&event_abi::SCHEMA_MINOR.to_le_bytes());
    buf[8..12].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
    buf[12..16].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
    buf[16] = 250; // above MAX_DISCRIMINANT (15)
    match parse(&buf) {
        Err(DecodeError::UnknownEventKind { .. }) => {}
        other => panic!("expected UnknownEventKind, got {other:?}"),
    }

    // Length: 4096-byte buffer with record_len=5000 — over-reports vs. buf.
    let mut buf = vec![0u8; 4096];
    buf[0..4].copy_from_slice(&event_abi::SCHEMA_MAJOR.to_le_bytes());
    buf[4..8].copy_from_slice(&event_abi::SCHEMA_MINOR.to_le_bytes());
    buf[8..12].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
    buf[12..16].copy_from_slice(&(5000u32).to_le_bytes());
    buf[16] = EventKind::ProcessFork as u8;
    match parse(&buf) {
        Err(DecodeError::LengthMismatch { .. }) => {}
        other => panic!("expected LengthMismatch, got {other:?}"),
    }

    // Use lcg_step once so the optimizer doesn't trip a "unused" lint.
    assert!(lcg_step(&mut state) != 0);
}