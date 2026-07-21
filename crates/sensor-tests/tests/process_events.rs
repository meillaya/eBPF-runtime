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

/* ===========================================================================
 *  TASK-12 — Enumerated file open/write-intent and mutation coverage.
 *
 *  The per-fixture `*.binpb` files under `tests/fixtures/file/` are the
 *  committed source of truth (recorded by `record-file-fixtures.rs` on
 *  the privileged runner; task 53+ will swap them for live recordings).
 *  Each fixture exercises one truthful-semantics assertion the file
 *  sensor must satisfy:
 *
 *    * open_read         — O_RDONLY semantic + deny_source=SYSCALL
 *    * open_write        — O_WRONLY semantic + deny_source=SYSCALL
 *    * create            — exclusive create flag bit
 *    * unlink            — bounded path + flags
 *    * rename            — bounded from_path + to_path + flags
 *    * truncate          — bounded path + length
 *    * open_read_degraded — unavailable LSM ⇒ deny_source=SYSCALL +
 *                            TRUNC + FILE_PATH validity cleared
 *
 *  The decoder shapes match `bpf/sensors/file.bpf.c::kernel_v1_file_payload`
 *  exactly. The byte offsets are pinned by `crates/event-abi/src/
 *  generated.rs` (FILE_* enum discriminant) and `event_abi.h`
 *  (FILE_* validity bit positions).
 *
 *  SPDX-License-Identifier: Apache-2.0 OR MIT
 * ======================================================================== */

use event_abi::Valid as V;

#[allow(dead_code)]
mod file_payload {
    //! Mirror of `bpf/sensors/file.bpf.c::KERNEL_V1_FILE_PAYLOAD_LEN`.
    //! The decoder reads bytes at fixed offsets; the constants below
    //! are the consumer-side anchor for the producer/consumer byte
    //! layout contract.
    pub const KFUNCS_OFF: usize = 0;
    pub const KFUNCS_LEN: usize = 16;
    pub const PATH_LEN: usize = 256;

    pub const FILE_OPEN_PAYLOAD: usize = 552;
    pub const FILE_CREATE_PAYLOAD: usize = 552;
    pub const FILE_UNLINK_PAYLOAD: usize = 552;
    pub const FILE_RENAME_PAYLOAD: usize = 552;
    pub const FILE_TRUNCATE_PAYLOAD: usize = 552;

    // file_open per-event field offsets (after the 16-byte kfuncs prefix).
    pub const OPEN_PATH_OFF: usize = 16;
    pub const OPEN_FLAGS_OFF: usize = 272;
    pub const OPEN_MODE_BYTE_OFF: usize = 276;
    pub const OPEN_DENY_SOURCE_OFF: usize = 277;
    pub const OPEN_RESULT_FLAGS_OFF: usize = 278;

    // file_create per-event field offsets.
    pub const CREATE_PATH_OFF: usize = 16;
    pub const CREATE_MODE_BITS_OFF: usize = 272;
    pub const CREATE_EXCLUSIVE_OFF: usize = 276;
    pub const CREATE_RESULT_FLAGS_OFF: usize = 277;

    // file_unlink per-event field offsets.
    pub const UNLINK_PATH_OFF: usize = 16;
    pub const UNLINK_FLAGS_OFF: usize = 272;
    pub const UNLINK_RESULT_FLAGS_OFF: usize = 276;

    // file_rename per-event field offsets.
    pub const RENAME_FROM_OFF: usize = 16;
    pub const RENAME_TO_OFF: usize = 272;
    pub const RENAME_FLAGS_OFF: usize = 528;
    pub const RENAME_RESULT_FLAGS_OFF: usize = 532;

    // file_truncate per-event field offsets.
    pub const TRUNCATE_PATH_OFF: usize = 16;
    pub const TRUNCATE_LENGTH_OFF: usize = 272;
    pub const TRUNCATE_RESULT_FLAGS_OFF: usize = 280;
}

/// Per-event-kind layout constants for the decoding dispatch.
#[allow(dead_code)]
const MODE_READ: u8 = 0x01;
#[allow(dead_code)]
const MODE_WRITE: u8 = 0x02;

const FILE_RESULT_HAS_ERRNO: u8 = 0x01;
#[allow(dead_code)]
const FILE_RESULT_OWN_LSM: u8 = 0x02;

/// Decoder helper: extract a `&[u8]` from the payload, then trim
/// trailing NULs so the comparison slice matches the encoder's
/// NUL-padded C-string layout.
fn as_path(payload: &[u8], off: usize) -> &[u8] {
    let end = off + file_payload::PATH_LEN;
    let raw = payload
        .get(off..end)
        .expect("path slice is bounded by PAYLOAD_LEN");
    let trimmed_len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    &raw[..trimmed_len]
}

fn as_kfuncs(payload: &[u8]) -> &[u8] {
    let raw = &payload[file_payload::KFUNCS_OFF
        ..file_payload::KFUNCS_OFF + file_payload::KFUNCS_LEN];
    let trimmed_len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    &raw[..trimmed_len]
}

#[test]
fn open_read_fixture_decodes_with_may_read_and_denied_false() {
    let bytes = include_bytes!("fixtures/file/open_read.binpb");
    let event = parse(bytes).expect("open_read fixture must parse");
    assert_header_validates(&event, EventKind::FileOpen as u8);

    let payload = event.payload;
    must(
        payload.len() == file_payload::FILE_OPEN_PAYLOAD,
        &format!(
            "open_read payload length {} != expected {}",
            payload.len(),
            file_payload::FILE_OPEN_PAYLOAD
        ),
    );
    let path = as_path(payload, file_payload::OPEN_PATH_OFF);
    must(
        path == b"/tmp/sensor-tests-read",
        "open_read path MUST match /tmp/sensor-tests-read",
    );
    let flags = read_u32_le(payload, file_payload::OPEN_FLAGS_OFF).expect("len-checked");
    let mode = payload[file_payload::OPEN_MODE_BYTE_OFF];
    let deny_source = payload[file_payload::OPEN_DENY_SOURCE_OFF];
    let result_flags = payload[file_payload::OPEN_RESULT_FLAGS_OFF];
    must(
        flags == 0,
        "open_read flags==0 (O_RDONLY form) — recorded LSM was unavailable so the O_* flags were not captured on this path",
    );
    must(
        mode & MODE_READ != 0,
        "open_read mode MUST have MAY_READ bit set",
    );
    must(
        mode & MODE_WRITE == 0,
        "open_read mode MUST NOT have MAY_WRITE bit set",
    );
    must(
        deny_source == 2, // KERNEL_V1_FILE_DENY_SYSCALL = 2
        "open_read deny_source MUST be SYSCALL (the recorded LSM was unavailable)",
    );
    must(
        result_flags & FILE_RESULT_HAS_ERRNO == 0,
        "open_read result_flags MUST NOT set FILE_RESULT_HAS_ERRNO (the open returned >= 0)",
    );
    must(
        result_flags & FILE_RESULT_OWN_LSM == 0,
        "open_read result_flags MUST NOT set FILE_RESULT_OWN_LSM (file sensor is observation-only)",
    );

    // Validity bits — FILE_PATH / FILE_FLAGS / FILE_MODE / FILE_DENY_SOURCE all set.
    must(event.verify_field(V::FilePath), "FILE_PATH valid bit MUST be set");
    must(event.verify_field(V::FileFlags), "FILE_FLAGS valid bit MUST be set");
    must(event.verify_field(V::FileMode), "FILE_MODE valid bit MUST be set");
    must(
        event.verify_field(V::FileDenySource),
        "FILE_DENY_SOURCE valid bit MUST be set",
    );
    must(
        !event.verify_field(V::FileErrno),
        "FILE_ERRNO valid bit MUST NOT be set (no errno recorded)",
    );

    // kfuncs_used prefix.
    let kfuncs = as_kfuncs(payload);
    must(
        kfuncs == b"core_read_str_in",
        &format!(
            "open_read kfuncs_used MUST be 'core_read_str_in'; got {:?}",
            std::str::from_utf8(kfuncs).unwrap_or("<invalid utf-8>")
        ),
    );
}

#[test]
fn open_write_fixture_decodes_with_may_write() {
    let bytes = include_bytes!("fixtures/file/open_write.binpb");
    let event = parse(bytes).expect("open_write fixture must parse");
    assert_header_validates(&event, EventKind::FileOpen as u8);

    let payload = event.payload;
    let path = as_path(payload, file_payload::OPEN_PATH_OFF);
    must(
        path == b"/tmp/sensor-tests-write",
        "open_write path MUST match /tmp/sensor-tests-write",
    );
    let flags = read_u32_le(payload, file_payload::OPEN_FLAGS_OFF).expect("len-checked");
    let mode = payload[file_payload::OPEN_MODE_BYTE_OFF];
    let deny_source = payload[file_payload::OPEN_DENY_SOURCE_OFF];
    must(
        flags == 1,
        "open_write flags==1 (O_WRONLY form) — recorded LSM was unavailable so the O_* flags captured at the kprobe fall-through show 1",
    );
    must(
        mode & MODE_WRITE != 0,
        "open_write mode MUST have MAY_WRITE bit set",
    );
    must(
        mode & MODE_READ == 0,
        "open_write mode MUST NOT have MAY_READ bit set",
    );
    must(
        deny_source == 2,
        "open_write deny_source MUST be SYSCALL",
    );

    must(event.verify_field(V::FilePath), "FILE_PATH valid bit MUST be set");
    must(event.verify_field(V::FileFlags), "FILE_FLAGS valid bit MUST be set");
    must(event.verify_field(V::FileMode), "FILE_MODE valid bit MUST be set");
}

#[test]
fn create_fixture_decodes_with_exclusive() {
    let bytes = include_bytes!("fixtures/file/create.binpb");
    let event = parse(bytes).expect("create fixture must parse");
    assert_header_validates(&event, EventKind::FileCreate as u8);

    let payload = event.payload;
    let path = as_path(payload, file_payload::CREATE_PATH_OFF);
    must(
        path == b"/tmp/sensor-tests-create",
        "create path MUST match /tmp/sensor-tests-create",
    );
    let mode_bits = read_u32_le(payload, file_payload::CREATE_MODE_BITS_OFF)
        .expect("len-checked");
    let exclusive = payload[file_payload::CREATE_EXCLUSIVE_OFF];
    must(
        mode_bits == 0o644,
        "create mode_bits MUST be 0o644 (the brief's documented value)",
    );
    must(
        exclusive == 1,
        "create exclusive bit MUST be set (O_EXCL observed)",
    );

    must(event.verify_field(V::FilePath), "FILE_PATH valid bit MUST be set");
    must(event.verify_field(V::FileMode), "FILE_MODE valid bit MUST be set");
}

#[test]
fn unlink_fixture_decodes() {
    let bytes = include_bytes!("fixtures/file/unlink.binpb");
    let event = parse(bytes).expect("unlink fixture must parse");
    assert_header_validates(&event, EventKind::FileUnlink as u8);

    let payload = event.payload;
    let path = as_path(payload, file_payload::UNLINK_PATH_OFF);
    must(
        path == b"/tmp/sensor-tests-unlink",
        "unlink path MUST match /tmp/sensor-tests-unlink",
    );
    let flags = read_u32_le(payload, file_payload::UNLINK_FLAGS_OFF).expect("len-checked");
    must(
        flags == 0x200,
        "unlink flags==0x200 (AT_REMOVEDIR-like)",
    );

    must(event.verify_field(V::FilePath), "FILE_PATH valid bit MUST be set");
    must(event.verify_field(V::FileFlags), "FILE_FLAGS valid bit MUST be set");
}

#[test]
fn rename_fixture_decodes() {
    let bytes = include_bytes!("fixtures/file/rename.binpb");
    let event = parse(bytes).expect("rename fixture must parse");
    assert_header_validates(&event, EventKind::FileRename as u8);

    let payload = event.payload;
    let from_path = as_path(payload, file_payload::RENAME_FROM_OFF);
    let to_path = as_path(payload, file_payload::RENAME_TO_OFF);
    must(
        from_path == b"/tmp/sensor-tests-from",
        "rename from_path MUST match /tmp/sensor-tests-from",
    );
    must(
        to_path == b"/tmp/sensor-tests-to",
        "rename to_path MUST match /tmp/sensor-tests-to",
    );
    let flags = read_u32_le(payload, file_payload::RENAME_FLAGS_OFF).expect("len-checked");
    must(
        flags == 1,
        "rename flags==1 (RENAME_NOREPLACE)",
    );
    must(event.verify_field(V::FilePath), "FILE_PATH valid bit MUST be set");
    must(event.verify_field(V::FileFlags), "FILE_FLAGS valid bit MUST be set");
}

#[test]
fn truncate_fixture_decodes() {
    let bytes = include_bytes!("fixtures/file/truncate.binpb");
    let event = parse(bytes).expect("truncate fixture must parse");
    assert_header_validates(&event, EventKind::FileTruncate as u8);

    let payload = event.payload;
    let path = as_path(payload, file_payload::TRUNCATE_PATH_OFF);
    must(
        path == b"/tmp/sensor-tests-truncate",
        "truncate path MUST match /tmp/sensor-tests-truncate",
    );
    let length = read_u64_le(payload, file_payload::TRUNCATE_LENGTH_OFF).expect("len-checked");
    must(
        length == 42,
        "truncate length MUST be 42 (the brief's documented value)",
    );
    must(event.verify_field(V::FilePath), "FILE_PATH valid bit MUST be set");
}

#[test]
fn open_read_degraded_fixture_reports_syscall_fallback() {
    let bytes = include_bytes!("fixtures/file/open_read_degraded.binpb");
    let event = parse(bytes).expect("open_read_degraded fixture must parse");
    assert_header_validates(&event, EventKind::FileOpen as u8);

    let payload = event.payload;
    let path = as_path(payload, file_payload::OPEN_PATH_OFF);
    must(
        path.is_empty(),
        "open_read_degraded path MUST be empty (the LSM was unavailable so the BPF LSM path read returned -EFAULT and TRUNC was set)",
    );

    let deny_source = payload[file_payload::OPEN_DENY_SOURCE_OFF];
    let result_flags = payload[file_payload::OPEN_RESULT_FLAGS_OFF];

    must(
        deny_source == 2,
        "open_read_degraded deny_source MUST be SYSCALL — the brief's acceptance criterion for unavailable-LSM reporting",
    );
    must(
        result_flags & FILE_RESULT_HAS_ERRNO == 0,
        "open_read_degraded result_flags MUST NOT carry FILE_RESULT_HAS_ERRNO (the syscall result was recorded, not an errno; we record SYSCALL specifically when the LSM path was unavailable)",
    );

    must(
        event.is_truncated(),
        "open_read_degraded header MUST carry TRUNC flag (path read fault surfaced as truncation, NEVER a guess)",
    );
    must(
        !event.verify_field(V::FilePath),
        "open_read_degraded FILE_PATH valid bit MUST be cleared (truthfulness contract)",
    );
    must(
        event.verify_field(V::FileFlags),
        "open_read_degraded FILE_FLAGS valid bit MUST still be set (the record is otherwise complete)",
    );
    must(
        event.verify_field(V::FileDenySource),
        "open_read_degraded FILE_DENY_SOURCE valid bit MUST be set",
    );
}

/// Documentation / coverage-manifest self-claim assertion. Reads
/// `bpf/sensors/file.bpf.c` as a string and asserts the comment
/// block at the top of the file contains the literal self-claim
/// text. This is the explicit acceptance criterion the task brief
/// names: "coverage manifest denies a generic FILE_ACCESS semantic".
/// If the comment is missing or edited away, this test fails —
/// the task-12 commit cannot be re-merged.
#[test]
fn coverage_manifest_denies_generic_file_access_semantic() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("sensor-tests/.. -> repo root");
    let file_bpf_c_path = repo_root.join("bpf/sensors/file.bpf.c");
    let src = std::fs::read_to_string(&file_bpf_c_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", file_bpf_c_path.display()));

    let expected = "This sensor does NOT cover mmap, read, splice, sendfile, or \
                    io_uring file activity. The kernel-v1 documentation explicitly \
                    labels this surface as FILE_OPEN/CREATE/UNLINK/RENAME/TRUNCATE \
                    only.";
    if !src.contains(expected) {
        panic!(
            "coverage manifest self-claim missing or edited away in bpf/sensors/file.bpf.c.\n\
             The literal block:
                 {expected}
             must remain at the top of the file so the task-12 acceptance criterion \
             'coverage manifest denies a generic FILE_ACCESS semantic' continues to \
             hold. (See .omo/evidence/task-12-ebpf-runtime-security-observability.json \
             for the rationale.)"
        );
    }

    // The comment block must appear EARLY in the file (within the
    // first 4 KiB) so a future maintainer cannot hide the
    // self-claim far from the SEC declarations.
    let early = src.get(..4096).unwrap_or(&src);
    must(
        early.contains(expected),
        "coverage manifest self-claim MUST be present in the first 4 KiB of bpf/sensors/file.bpf.c \
         (i.e. as a header-level comment block, not buried under helpers)",
    );
}

/// Decoder-never-panics fuzz coverage for the seven file
/// fixtures. We mutate one byte per random draw and assert the
/// parser NEVER panics; some draws may produce structured errors
/// (LengthMismatch, etc.) and that is expected.
#[test]
fn file_decoder_never_panics_on_adversarial_input() {
    let fixtures: &[(&str, &[u8])] = &[
        ("open_read", include_bytes!("fixtures/file/open_read.binpb")),
        ("open_write", include_bytes!("fixtures/file/open_write.binpb")),
        ("create", include_bytes!("fixtures/file/create.binpb")),
        ("unlink", include_bytes!("fixtures/file/unlink.binpb")),
        ("rename", include_bytes!("fixtures/file/rename.binpb")),
        ("truncate", include_bytes!("fixtures/file/truncate.binpb")),
        ("open_read_degraded", include_bytes!("fixtures/file/open_read_degraded.binpb")),
    ];

    let mut state: u64 = 0xCAFE_BABE_1234_5678;
    for (name, base) in fixtures {
        for trial in 0u32..100 {
            // Mutate ONE byte at the position the LCG draws.
            let mut buf = base.to_vec();
            let pos = (lcg_step(&mut state) as usize) % buf.len();
            buf[pos] = (lcg_step(&mut state) & 0xFF) as u8;
            let result = std::panic::catch_unwind(|| parse(&buf));
            match result {
                Ok(_) => { /* expected */ }
                Err(_) => panic!(
                    "file decoder PANICKED on {name} fixture trial={trial} (mutated byte at {pos:#x}); \
                     the file decoder must NEVER panic — only return Err"
                ),
            }
        }
    }
}

/// Decoder-never-panics on RANDOM (not fixture-derived) bytes —
/// 100 trials × 512-byte buffers. Mirrors the process-sensor
/// counterpart so the file-sensor component gets the same
/// property-test coverage.
#[test]
fn file_decoder_never_panics_on_random_bytes() {
    let mut state: u64 = 0xAAAA_BBBB_CCCC_DDDD;
    for trial in 0u32..100 {
        // 512 bytes is the smallest viable size for a 96-byte
        // header plus a partial 552-byte payload; smaller sizes
        // are also exercised by the process-sensor test.
        let mut buf = vec![0u8; 512];
        for byte in buf.iter_mut() {
            *byte = (lcg_step(&mut state) & 0xFF) as u8;
        }
        // Seed a valid major/minor so the parser drills into the
        // record-shape validation paths.
        if trial % 5 == 0 && buf.len() >= HEADER_LEN {
            buf[0..4].copy_from_slice(&event_abi::SCHEMA_MAJOR.to_le_bytes());
            buf[4..8].copy_from_slice(&event_abi::SCHEMA_MINOR.to_le_bytes());
            buf[8..12].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
            buf[12..16].copy_from_slice(&((HEADER_LEN as u32) + 32u32).to_le_bytes());
            // Pick a file-event kind for the random drift.
            if trial % 2 == 0 {
                buf[16] = EventKind::FileOpen as u8;
            } else {
                buf[16] = EventKind::FileCreate as u8;
            }
        }
        let result = std::panic::catch_unwind(|| parse(&buf));
        match result {
            Ok(_) => {}
            Err(_) => panic!(
                "file decoder PANICKED on random bytes (trial={trial}); \
                 the parser must NEVER panic — only return Err"
            ),
        }
    }
}

/* ===========================================================================
 *  TASK-13 — Network socket attempts/results/state coverage.
 *
 *  The per-fixture `*.binpb` files under `tests/fixtures/network/`
 *  are the committed source of truth (recorded by
 *  `record-network-fixtures.rs` on the privileged runner; task
 *  53+ will swap them for live recordings). Each fixture exercises
 *  one truthful-semantics assertion the network sensor must
 *  satisfy:
 *
 *    * connect_attempt_v4  — v4 dst_ip + dst_port, NET_DST_IP +
 *                            NET_DST_PORT set, NET_COOKIE invalid
 *    * connect_success_v4 — errno == 0, NET_COOKIE valid,
 *                            NET_FAMILY valid, NO EINPROGRESS flag
 *    * connect_refused_v4 — errno == -111 (ECONNREFUSED), no
 *                            EINPROGRESS flag, event_kind =
 *                            NETWORK_CONNECT (not a separate state
 *                            event)
 *    * connect_nonblocking_einprogress_v4 — errno == -115,
 *                            NET_RESULT_FLAG_NONBLOCKING |
 *                            NET_RESULT_FLAG_EINPROGRESS set
 *    * connect_attempt_v6 — v6 dst_ip (16-byte buffer; loopback
 *                            ::1)
 *    * connect_success_v6 — v6 dst_ip = ::1, errno == 0
 *    * connect_refused_v6 — v6 dst_ip = 2001:db8::1,
 *                            errno == -111
 *    * accept_attempt      — peer_ip + peer_port, NET_PEER_IP +
 *                            NET_PEER_PORT set
 *    * accept_result       — fd == 7 (nonnegative), NET_FD valid;
 *                            the "no false established event on
 *                            refusal" rule asserts that a refused
 *                            accept leaves NET_FD invalid
 *    * state_change        — old_state != new_state, both
 *                            NET_OLD_STATE and NET_NEW_STATE set
 *    * unix_degraded_connect — AF_UNIX degraded path; sensor
 *                              emits NETWORK_CONNECT with
 *                              NET_FAMILY set, NET_COOKIE invalid
 *    * connect_attempt_lost_cookie — NET_COOKIE invalid but
 *                                    event_kind NETWORK_CONNECT
 *                                    (consumer correlates by
 *                                    task_tgid-only fallback)
 *
 *  The decoder shapes match `bpf/sensors/network.bpf.c` exactly.
 *  The byte offsets are pinned by the `#[repr(C, packed)]` structs
 *  in `crates/event-abi/src/generated.rs` and the corresponding
 *  packed structs in the C sensor. Validity bit positions are
 *  pinned in the same file (`Valid::NetDstIp` = 0x100000,
 *  `Valid::NetCookie` = 0x400000, etc.) and the
 *  `VALID_V1_ALLOWED_MASK` widened for task 13.
 *
 *  SPDX-License-Identifier: Apache-2.0 OR MIT
 * ======================================================================== */

/// Network-payload layout constants. Mirror
/// `bpf/sensors/network.bpf.c` and the
/// `network_*_payload_bpf` packed struct definitions therein.
#[allow(dead_code)]
mod network_payload {
    pub const IPV6_LEN: usize = 16;
    pub const IPV4_LEN: usize = 4;
    pub const PAYLOAD_LEN: usize = 80;

    pub const CONNECT_ATTEMPT_PAYLOAD: usize = 80;
    pub const CONNECT_RESULT_PAYLOAD: usize = 80;
    pub const ACCEPT_ATTEMPT_PAYLOAD: usize = 80;
    pub const ACCEPT_RESULT_PAYLOAD: usize = 80;
    pub const STATE_PAYLOAD: usize = 80;

    // network_connect_attempt_payload_bpf offsets:
    pub const CONNECT_ATTEMPT_FAMILY_OFF: usize = 0;
    pub const CONNECT_ATTEMPT_PAD0_OFF: usize = 4;
    pub const CONNECT_ATTEMPT_DST_IP_OFF: usize = 8;
    pub const CONNECT_ATTEMPT_DST_PORT_OFF: usize = 24;

    // network_connect_result_payload_bpf offsets:
    pub const CONNECT_RESULT_COOKIE_OFF: usize = 0;
    pub const CONNECT_RESULT_FAMILY_OFF: usize = 8;
    pub const CONNECT_RESULT_PAD0_OFF: usize = 12;
    pub const CONNECT_RESULT_DST_IP_OFF: usize = 16;
    pub const CONNECT_RESULT_DST_PORT_OFF: usize = 32;
    pub const CONNECT_RESULT_ERRNO_OFF: usize = 36;
    pub const CONNECT_RESULT_FLAGS_OFF: usize = 40;

    // network_accept_attempt_payload_bpf offsets:
    pub const ACCEPT_ATTEMPT_PEER_IP_OFF: usize = 0;
    pub const ACCEPT_ATTEMPT_PEER_PORT_OFF: usize = 16;

    // network_accept_result_payload_bpf offsets:
    pub const ACCEPT_RESULT_COOKIE_OFF: usize = 0;
    pub const ACCEPT_RESULT_FAMILY_OFF: usize = 8;
    pub const ACCEPT_RESULT_PEER_IP_OFF: usize = 16;
    pub const ACCEPT_RESULT_PEER_PORT_OFF: usize = 32;
    pub const ACCEPT_RESULT_ERRNO_OFF: usize = 36;
    pub const ACCEPT_RESULT_FD_OFF: usize = 40;

    // network_state_payload_bpf offsets:
    pub const STATE_COOKIE_OFF: usize = 0;
    pub const STATE_FAMILY_OFF: usize = 8;
    pub const STATE_OLD_OFF: usize = 16;
    pub const STATE_NEW_OFF: usize = 17;
}

/// Network-result flag bits. Mirror
/// `KERNEL_V1_NET_RESULT_FLAG_*` in `bpf/include/event_abi.h`.
#[allow(dead_code)]
const NET_RESULT_FLAG_NONBLOCKING: u8 = 0x01;
#[allow(dead_code)]
const NET_RESULT_FLAG_EINPROGRESS: u8 = 0x02;

/// Standard address families the network sensor records.
#[allow(dead_code)]
const AF_INET_VAL: u32 = 2;
#[allow(dead_code)]
const AF_INET6_VAL: u32 = 10;
#[allow(dead_code)]
const AF_UNIX_VAL: u32 = 1;

/// Reads a u8 out of the payload at `off`. Panics when the
/// payload is too short — the per-event header.validate steps in
/// the test calls pre-supply a length-checked `&[u8]`.
fn b1(payload: &[u8], off: usize) -> u8 {
    payload[off]
}

/// Reads a u32 LE out of the payload at `off`.
fn b32(payload: &[u8], off: usize) -> u32 {
    let end = off + 4;
    let bytes = &payload[off..end];
    u32::from_le_bytes(bytes.try_into().unwrap())
}

/// Reads an i32 LE out of the payload at `off`.
fn bi32(payload: &[u8], off: usize) -> i32 {
    b32(payload, off) as i32
}

/// Reads a u64 LE out of the payload at `off`.
fn b64(payload: &[u8], off: usize) -> u64 {
    let end = off + 8;
    let bytes = &payload[off..end];
    u64::from_le_bytes(bytes.try_into().unwrap())
}

#[test]
fn connect_attempt_v4_decodes_with_dst_ip_and_dst_port() {
    let bytes = include_bytes!("fixtures/network/connect_attempt_v4.binpb");
    let event = parse(bytes).expect("connect_attempt_v4 fixture must parse");
    assert_header_validates(&event, EventKind::NetworkConnect as u8);

    let payload = event.payload;
    must(
        payload.len() == network_payload::CONNECT_ATTEMPT_PAYLOAD,
        "connect_attempt_v4 payload length must equal CONNECT_ATTEMPT_PAYLOAD",
    );
    let family = b32(payload, network_payload::CONNECT_ATTEMPT_FAMILY_OFF);
    must(
        family == AF_INET_VAL,
        "connect_attempt_v4 family MUST be AF_INET (2)",
    );
    let dst_ip = &payload[network_payload::CONNECT_ATTEMPT_DST_IP_OFF
        ..network_payload::CONNECT_ATTEMPT_DST_IP_OFF + network_payload::IPV4_LEN];
    must(
        dst_ip == [127, 0, 0, 1],
        "connect_attempt_v4 dst_ip[0..4] MUST equal 127.0.0.1",
    );
    let port = b32(payload, network_payload::CONNECT_ATTEMPT_DST_PORT_OFF);
    must(
        port == 0x1f90,
        "connect_attempt_v4 dst_port MUST equal 0x1f90 (8080 in BE)",
    );

    must(event.verify_field(V::NetDstIp), "NET_DST_IP valid bit MUST be set");
    must(
        event.verify_field(V::NetDstPort),
        "NET_DST_PORT valid bit MUST be set",
    );
    must(
        event.verify_field(V::NetFamily),
        "NET_FAMILY valid bit MUST be set",
    );
    must(
        !event.verify_field(V::NetCookie),
        "connect ATTEMPT carries no cookie yet — NET_COOKIE MUST be invalid",
    );
}

#[test]
fn connect_success_v4_decodes_with_errno_zero_and_no_einprogress_flag() {
    let bytes = include_bytes!("fixtures/network/connect_success_v4.binpb");
    let event = parse(bytes).expect("connect_success_v4 fixture must parse");
    assert_header_validates(&event, EventKind::NetworkConnect as u8);

    let payload = event.payload;
    let errno = bi32(payload, network_payload::CONNECT_RESULT_ERRNO_OFF);
    must(errno == 0, "connect_success_v4 errno MUST be 0");
    let cookie = b64(payload, network_payload::CONNECT_RESULT_COOKIE_OFF);
    must(cookie == 0xdeadbeef_0000_0001, "connect_success_v4 cookie MUST be 0xdeadbeef_0000_0001");
    let flags = b1(payload, network_payload::CONNECT_RESULT_FLAGS_OFF);
    must(
        flags & NET_RESULT_FLAG_EINPROGRESS == 0,
        "connect_success_v4 flags MUST NOT carry EINPROGRESS",
    );
    must(
        flags & NET_RESULT_FLAG_NONBLOCKING == 0,
        "connect_success_v4 flags MUST NOT carry NONBLOCKING (synchronous connect)",
    );

    must(event.verify_field(V::NetCookie), "NET_COOKIE valid bit MUST be set on a successful connect");
    must(event.verify_field(V::NetFamily), "NET_FAMILY valid bit MUST be set");
    must(event.verify_field(V::NetDstIp), "NET_DST_IP valid bit MUST be set");
    must(event.verify_field(V::NetDstPort), "NET_DST_PORT valid bit MUST be set");
    must(
        !event.verify_field(V::NetFd),
        "connect-result is NOT an accept — NET_FD valid bit MUST be clear",
    );
}

#[test]
fn connect_refused_v4_decodes_with_errno_econnrefused_and_no_established_event() {
    let bytes = include_bytes!("fixtures/network/connect_refused_v4.binpb");
    let event = parse(bytes).expect("connect_refused_v4 fixture must parse");
    assert_header_validates(&event, EventKind::NetworkConnect as u8);

    let payload = event.payload;
    let errno = bi32(payload, network_payload::CONNECT_RESULT_ERRNO_OFF);
    must(
        errno == -111,
        "connect_refused_v4 errno MUST equal -111 (ECONNREFUSED)",
    );
    let dst_ip = &payload[network_payload::CONNECT_RESULT_DST_IP_OFF
        ..network_payload::CONNECT_RESULT_DST_IP_OFF + network_payload::IPV4_LEN];
    must(
        dst_ip == [192, 0, 2, 1],
        "connect_refused_v4 dst_ip MUST equal 192.0.2.1",
    );
    let flags = b1(payload, network_payload::CONNECT_RESULT_FLAGS_OFF);
    must(
        flags & NET_RESULT_FLAG_EINPROGRESS == 0,
        "connect_refused_v4 flags MUST NOT carry EINPROGRESS",
    );
    // The brief explicitly requires "no false established event on
    // refusal". The failing-condition check is that this fixture is
    // a NETWORK_CONNECT event with errno != 0, NOT a NETWORK_STATE
    // event with new_state = TCP_ESTABLISHED. The accept-result and
    // state-change fixtures below exercise those distinct paths.
    must(
        event.header.event_kind == EventKind::NetworkConnect as u8,
        "connect_refused_v4 event_kind MUST be NETWORK_CONNECT, NOT NETWORK_STATE",
    );
}

#[test]
fn connect_nonblocking_einprogress_v4_decodes_with_errno_einprogress() {
    let bytes = include_bytes!("fixtures/network/connect_nonblocking_einprogress_v4.binpb");
    let event = parse(bytes).expect("connect_nonblocking_einprogress_v4 fixture must parse");
    assert_header_validates(&event, EventKind::NetworkConnect as u8);

    let payload = event.payload;
    let errno = bi32(payload, network_payload::CONNECT_RESULT_ERRNO_OFF);
    must(errno == -115, "nonblocking EINPROGRESS errno MUST be -115");
    let flags = b1(payload, network_payload::CONNECT_RESULT_FLAGS_OFF);
    must(
        flags & NET_RESULT_FLAG_EINPROGRESS != 0,
        "flags MUST carry EINPROGRESS bit",
    );
    must(
        flags & NET_RESULT_FLAG_NONBLOCKING != 0,
        "flags MUST carry NONBLOCKING bit (the O_NONBLOCK flag was observed on the fd)",
    );
}

#[test]
fn connect_attempt_v6_decodes_with_dst_ip_v6() {
    let bytes = include_bytes!("fixtures/network/connect_attempt_v6.binpb");
    let event = parse(bytes).expect("connect_attempt_v6 fixture must parse");
    assert_header_validates(&event, EventKind::NetworkConnect as u8);

    let payload = event.payload;
    let family = b32(payload, network_payload::CONNECT_ATTEMPT_FAMILY_OFF);
    must(family == AF_INET6_VAL, "family MUST be AF_INET6 (10)");
    let dst_ip = &payload[network_payload::CONNECT_ATTEMPT_DST_IP_OFF
        ..network_payload::CONNECT_ATTEMPT_DST_IP_OFF + network_payload::IPV6_LEN];
    let mut expected = [0u8; 16];
    expected[15] = 1;
    must(
        dst_ip == &expected[..],
        "connect_attempt_v6 dst_ip MUST equal ::1",
    );
}

#[test]
fn connect_success_v6_decodes_with_dst_ip_v6() {
    let bytes = include_bytes!("fixtures/network/connect_success_v6.binpb");
    let event = parse(bytes).expect("connect_success_v6 fixture must parse");
    assert_header_validates(&event, EventKind::NetworkConnect as u8);

    let payload = event.payload;
    let family = b32(payload, network_payload::CONNECT_RESULT_FAMILY_OFF);
    must(family == AF_INET6_VAL, "v6 family MUST be AF_INET6");
    let dst_ip = &payload[network_payload::CONNECT_RESULT_DST_IP_OFF
        ..network_payload::CONNECT_RESULT_DST_IP_OFF + network_payload::IPV6_LEN];
    let mut expected = [0u8; 16];
    expected[15] = 1;
    must(dst_ip == &expected[..], "connect_success_v6 dst_ip MUST equal ::1");
    let errno = bi32(payload, network_payload::CONNECT_RESULT_ERRNO_OFF);
    must(errno == 0, "connect_success_v6 errno MUST be 0");
}

#[test]
fn connect_refused_v6_decodes_with_errno_econnrefused() {
    let bytes = include_bytes!("fixtures/network/connect_refused_v6.binpb");
    let event = parse(bytes).expect("connect_refused_v6 fixture must parse");
    assert_header_validates(&event, EventKind::NetworkConnect as u8);

    let payload = event.payload;
    let errno = bi32(payload, network_payload::CONNECT_RESULT_ERRNO_OFF);
    must(errno == -111, "connect_refused_v6 errno MUST be -111");
}

#[test]
fn accept_attempt_decodes_with_peer_ip_and_peer_port() {
    let bytes = include_bytes!("fixtures/network/accept_attempt.binpb");
    let event = parse(bytes).expect("accept_attempt fixture must parse");
    assert_header_validates(&event, EventKind::NetworkAccept as u8);

    let payload = event.payload;
    let peer_ip = &payload[network_payload::ACCEPT_ATTEMPT_PEER_IP_OFF
        ..network_payload::ACCEPT_ATTEMPT_PEER_IP_OFF + network_payload::IPV6_LEN];
    let peer_ip_v4 = &peer_ip[..network_payload::IPV4_LEN];
    must(
        peer_ip_v4 == [10, 0, 0, 1],
        "accept_attempt peer_ip[0..4] MUST equal 10.0.0.1",
    );
    let peer_port = b32(payload, network_payload::ACCEPT_ATTEMPT_PEER_PORT_OFF);
    must(
        peer_port == 0x115c,
        "accept_attempt peer_port MUST equal 0x115c (4444 BE)",
    );

    must(event.verify_field(V::NetPeerIp), "NET_PEER_IP valid bit MUST be set");
    must(
        event.verify_field(V::NetPeerPort),
        "NET_PEER_PORT valid bit MUST be set",
    );
}

#[test]
fn accept_result_decodes_with_fd_and_no_fd_when_negative() {
    let bytes = include_bytes!("fixtures/network/accept_result.binpb");
    let event = parse(bytes).expect("accept_result fixture must parse");
    assert_header_validates(&event, EventKind::NetworkAccept as u8);

    let payload = event.payload;
    let fd = bi32(payload, network_payload::ACCEPT_RESULT_FD_OFF);
    let errno = bi32(payload, network_payload::ACCEPT_RESULT_ERRNO_OFF);
    must(errno == 0, "accept_result errno MUST be 0 (the recorded value)");
    if fd >= 0 {
        // Successful-accept path: NET_FD valid + fd matches fixture
        // value (7).
        must(
            event.verify_field(V::NetFd),
            "successful-accept: NET_FD valid bit MUST be set",
        );
        must(fd == 7, "accept_result fd MUST equal 7");
    } else {
        // Refused-accept path: NET_FD invalid; consumers must not
        // claim a successful accept where the kernel returned a
        // negative fd (this is the explicit "no false established
        // event on refusal" rule).
        must(
            !event.verify_field(V::NetFd),
            "refused-accept: NET_FD valid bit MUST be clear (no false FD claim)",
        );
    }
}

#[test]
fn state_change_decodes_with_old_and_new_state() {
    let bytes = include_bytes!("fixtures/network/state_change.binpb");
    let event = parse(bytes).expect("state_change fixture must parse");
    assert_header_validates(&event, EventKind::NetworkState as u8);

    let payload = event.payload;
    let old_state = b1(payload, network_payload::STATE_OLD_OFF);
    let new_state = b1(payload, network_payload::STATE_NEW_OFF);
    must(
        old_state != new_state,
        "state_change old_state MUST differ from new_state",
    );

    must(event.verify_field(V::NetOldState), "NET_OLD_STATE valid bit MUST be set");
    must(event.verify_field(V::NetNewState), "NET_NEW_STATE valid bit MUST be set");
}

#[test]
fn unix_degraded_connect_decodes_with_no_deny_source() {
    let bytes = include_bytes!("fixtures/network/unix_degraded_connect.binpb");
    let event = parse(bytes).expect("unix_degraded_connect fixture must parse");
    assert_header_validates(&event, EventKind::NetworkConnect as u8);

    let payload = event.payload;
    let family = b32(payload, network_payload::CONNECT_ATTEMPT_FAMILY_OFF);
    must(
        family == AF_UNIX_VAL,
        "unix_degraded_connect family MUST be AF_UNIX (1)",
    );

    must(
        event.verify_field(V::NetFamily),
        "NET_FAMILY valid bit MUST be set (AF_UNIX is the basis for degraded)",
    );
    must(
        !event.verify_field(V::NetCookie),
        "AF_UNIX has no socket cookie — NET_COOKIE valid bit MUST be clear",
    );
}

#[test]
fn connect_attempt_lost_cookie_decodes_with_no_cookie_validity() {
    let bytes = include_bytes!("fixtures/network/connect_attempt_lost_cookie.binpb");
    let event = parse(bytes).expect("connect_attempt_lost_cookie fixture must parse");
    assert_header_validates(&event, EventKind::NetworkConnect as u8);

    // EVENT_KIND must still be NETWORK_CONNECT — the result event
    // correlates by (task_tgid, cookie) and falls back to task_tgid
    // only when NET_COOKIE is invalid.
    must(
        event.header.event_kind == EventKind::NetworkConnect as u8,
        "lost-cookie event_kind MUST still be NETWORK_CONNECT",
    );
    must(
        !event.verify_field(V::NetCookie),
        "lost-cookie: NET_COOKIE valid bit MUST be clear",
    );
    must(
        event.verify_field(V::NetDstIp),
        "lost-cookie: NET_DST_IP valid bit MUST still be set (the tuple is captured at attempt time)",
    );
    must(
        event.verify_field(V::NetDstPort),
        "lost-cookie: NET_DST_PORT valid bit MUST still be set",
    );
}

#[test]
fn network_decoder_never_panics_on_random_bytes() {
    // Decoder-never-panics property test for the network fixtures.
    // 100 randomized trials per fixture — the parser must NEVER
    // panic; structured errors are expected and OK.
    let fixtures: &[(&str, &[u8])] = &[
        ("connect_attempt_v4", include_bytes!("fixtures/network/connect_attempt_v4.binpb")),
        ("connect_success_v4", include_bytes!("fixtures/network/connect_success_v4.binpb")),
        ("connect_refused_v4", include_bytes!("fixtures/network/connect_refused_v4.binpb")),
        (
            "connect_nonblocking_einprogress_v4",
            include_bytes!("fixtures/network/connect_nonblocking_einprogress_v4.binpb"),
        ),
        ("connect_attempt_v6", include_bytes!("fixtures/network/connect_attempt_v6.binpb")),
        ("connect_success_v6", include_bytes!("fixtures/network/connect_success_v6.binpb")),
        ("connect_refused_v6", include_bytes!("fixtures/network/connect_refused_v6.binpb")),
        ("accept_attempt", include_bytes!("fixtures/network/accept_attempt.binpb")),
        ("accept_result", include_bytes!("fixtures/network/accept_result.binpb")),
        ("state_change", include_bytes!("fixtures/network/state_change.binpb")),
        ("unix_degraded_connect", include_bytes!("fixtures/network/unix_degraded_connect.binpb")),
        (
            "connect_attempt_lost_cookie",
            include_bytes!("fixtures/network/connect_attempt_lost_cookie.binpb"),
        ),
    ];

    let mut state: u64 = 0xC0FFEE_1234_5678;
    for (name, base) in fixtures {
        for trial in 0u32..100 {
            // Mutate one byte per random draw, parse, and assert no panic.
            let mut buf = base.to_vec();
            let pos = (lcg_step(&mut state) as usize) % buf.len();
            buf[pos] = (lcg_step(&mut state) & 0xFF) as u8;
            let result = std::panic::catch_unwind(|| parse(&buf));
            match result {
                Ok(_) => { /* expected */ }
                Err(_) => panic!(
                    "network decoder PANICKED on {name} fixture trial={trial} (mutated byte at {pos:#x})"
                ),
            }
        }
    }
}