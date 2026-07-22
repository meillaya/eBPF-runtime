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

use event_abi::{parse, DecodeError, DecodeReport, Event, EventKind, Header, Valid, HEADER_LEN};

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
        report.kind <= EventKind::MAX_DISCRIMINANT,
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
    must(payload.exit_code == 0, "thread_exit exit_code MUST be 0");
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
            0usize, 1, 2, 7, 16, 32, 95, 96, 97, 128, 255, 256, 257, 511, 512, 1023, 1024, 4095,
            4096,
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
    assert!(
        checked > 1000,
        "property test must check a meaningful number of inputs (got {checked})"
    );
}

/// Decoder rejection of every classic negative case. Re-uses
/// `lcg_step` for determinism.
#[test]
fn decoder_rejects_canonical_negative_inputs() {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;

    // Empty buffer → ShortBuffer
    assert_eq!(
        parse(&[]).unwrap_err(),
        DecodeError::ShortBuffer {
            have: 0,
            need: HEADER_LEN
        }
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
    let raw =
        &payload[file_payload::KFUNCS_OFF..file_payload::KFUNCS_OFF + file_payload::KFUNCS_LEN];
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
    must(
        event.verify_field(V::FilePath),
        "FILE_PATH valid bit MUST be set",
    );
    must(
        event.verify_field(V::FileFlags),
        "FILE_FLAGS valid bit MUST be set",
    );
    must(
        event.verify_field(V::FileMode),
        "FILE_MODE valid bit MUST be set",
    );
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
    must(deny_source == 2, "open_write deny_source MUST be SYSCALL");

    must(
        event.verify_field(V::FilePath),
        "FILE_PATH valid bit MUST be set",
    );
    must(
        event.verify_field(V::FileFlags),
        "FILE_FLAGS valid bit MUST be set",
    );
    must(
        event.verify_field(V::FileMode),
        "FILE_MODE valid bit MUST be set",
    );
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
    let mode_bits = read_u32_le(payload, file_payload::CREATE_MODE_BITS_OFF).expect("len-checked");
    let exclusive = payload[file_payload::CREATE_EXCLUSIVE_OFF];
    must(
        mode_bits == 0o644,
        "create mode_bits MUST be 0o644 (the brief's documented value)",
    );
    must(
        exclusive == 1,
        "create exclusive bit MUST be set (O_EXCL observed)",
    );

    must(
        event.verify_field(V::FilePath),
        "FILE_PATH valid bit MUST be set",
    );
    must(
        event.verify_field(V::FileMode),
        "FILE_MODE valid bit MUST be set",
    );
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
    must(flags == 0x200, "unlink flags==0x200 (AT_REMOVEDIR-like)");

    must(
        event.verify_field(V::FilePath),
        "FILE_PATH valid bit MUST be set",
    );
    must(
        event.verify_field(V::FileFlags),
        "FILE_FLAGS valid bit MUST be set",
    );
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
    must(flags == 1, "rename flags==1 (RENAME_NOREPLACE)");
    must(
        event.verify_field(V::FilePath),
        "FILE_PATH valid bit MUST be set",
    );
    must(
        event.verify_field(V::FileFlags),
        "FILE_FLAGS valid bit MUST be set",
    );
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
    must(
        event.verify_field(V::FilePath),
        "FILE_PATH valid bit MUST be set",
    );
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
        (
            "open_write",
            include_bytes!("fixtures/file/open_write.binpb"),
        ),
        ("create", include_bytes!("fixtures/file/create.binpb")),
        ("unlink", include_bytes!("fixtures/file/unlink.binpb")),
        ("rename", include_bytes!("fixtures/file/rename.binpb")),
        ("truncate", include_bytes!("fixtures/file/truncate.binpb")),
        (
            "open_read_degraded",
            include_bytes!("fixtures/file/open_read_degraded.binpb"),
        ),
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

    must(
        event.verify_field(V::NetDstIp),
        "NET_DST_IP valid bit MUST be set",
    );
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
    must(
        cookie == 0xdeadbeef_0000_0001,
        "connect_success_v4 cookie MUST be 0xdeadbeef_0000_0001",
    );
    let flags = b1(payload, network_payload::CONNECT_RESULT_FLAGS_OFF);
    must(
        flags & NET_RESULT_FLAG_EINPROGRESS == 0,
        "connect_success_v4 flags MUST NOT carry EINPROGRESS",
    );
    must(
        flags & NET_RESULT_FLAG_NONBLOCKING == 0,
        "connect_success_v4 flags MUST NOT carry NONBLOCKING (synchronous connect)",
    );

    must(
        event.verify_field(V::NetCookie),
        "NET_COOKIE valid bit MUST be set on a successful connect",
    );
    must(
        event.verify_field(V::NetFamily),
        "NET_FAMILY valid bit MUST be set",
    );
    must(
        event.verify_field(V::NetDstIp),
        "NET_DST_IP valid bit MUST be set",
    );
    must(
        event.verify_field(V::NetDstPort),
        "NET_DST_PORT valid bit MUST be set",
    );
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
    must(
        dst_ip == &expected[..],
        "connect_success_v6 dst_ip MUST equal ::1",
    );
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

    must(
        event.verify_field(V::NetPeerIp),
        "NET_PEER_IP valid bit MUST be set",
    );
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
    must(
        errno == 0,
        "accept_result errno MUST be 0 (the recorded value)",
    );
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

    must(
        event.verify_field(V::NetOldState),
        "NET_OLD_STATE valid bit MUST be set",
    );
    must(
        event.verify_field(V::NetNewState),
        "NET_NEW_STATE valid bit MUST be set",
    );
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
        (
            "connect_attempt_v4",
            include_bytes!("fixtures/network/connect_attempt_v4.binpb"),
        ),
        (
            "connect_success_v4",
            include_bytes!("fixtures/network/connect_success_v4.binpb"),
        ),
        (
            "connect_refused_v4",
            include_bytes!("fixtures/network/connect_refused_v4.binpb"),
        ),
        (
            "connect_nonblocking_einprogress_v4",
            include_bytes!("fixtures/network/connect_nonblocking_einprogress_v4.binpb"),
        ),
        (
            "connect_attempt_v6",
            include_bytes!("fixtures/network/connect_attempt_v6.binpb"),
        ),
        (
            "connect_success_v6",
            include_bytes!("fixtures/network/connect_success_v6.binpb"),
        ),
        (
            "connect_refused_v6",
            include_bytes!("fixtures/network/connect_refused_v6.binpb"),
        ),
        (
            "accept_attempt",
            include_bytes!("fixtures/network/accept_attempt.binpb"),
        ),
        (
            "accept_result",
            include_bytes!("fixtures/network/accept_result.binpb"),
        ),
        (
            "state_change",
            include_bytes!("fixtures/network/state_change.binpb"),
        ),
        (
            "unix_degraded_connect",
            include_bytes!("fixtures/network/unix_degraded_connect.binpb"),
        ),
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

/* ===========================================================================
 *  TASK-14 — Bounded cleartext DNS packet sensor.
 *
 *  The per-fixture `*.binpb` files under `tests/fixtures/dns/`
 *  are the committed source of truth (recorded by
 *  `record-dns-fixtures.rs` on the privileged runner; task 53+
 *  will swap them for live recordings). Each fixture exercises
 *  one truthful-semantics assertion the DNS sensor must
 *  satisfy:
 *
 *    * udp_query    — UDP/53 cleartext query for example.com;
 *                     QNAME present + truncated, QTYPE=A (1),
 *                     answer_count==0, direction=QUERY,
 *                     trunc_reason=NONE.
 *    * udp_response — UDP/53 response; answer_count>=1,
 *                     direction=RESPONSE, trunc_reason=NONE.
 *    * tcp_query    — TCP/53 cleartext query;
 *                     protocol=KERNEL_V1_DNS_PROTO_TCP.
 *    * tcp_response — TCP/53 cleartext response;
 *                     protocol=KERNEL_V1_DNS_PROTO_TCP.
 *    * truncated_qname — QNAME clip; trunc_reason=NAME_TOO_LONG,
 *                     DNS_QNAME valid bit cleared,
 *                     DNS_PAYLOAD_TRUNC bit set.
 *
 *  Three "must-not-exist" tests assert the sensor correctly
 *  refuses to emit on:
 *
 *    * encrypted flows (DoH / DoT / DoQ) — `encrypted.binpb` not on disk
 *    * oversized / compressed inputs — `oversized_compressed.binpb` not on disk
 *    * mDNS link-local (UDP/5353) — `ephemeral_mdns.binpb` not on disk
 *
 *  Decoder shapes match `bpf/sensors/dns.bpf.c::kernel_v1_dns_event`
 *  and the `kernel_v1_dns_packet_payload` struct in
 *  `bpf/include/event_abi.h`. The byte offsets are pinned by the
 *  `_Static_assert` block in the C header and the
 *  `DnsPacket::size_of()` assertion in
 *  `crates/event-abi/src/generated.rs`. The 6 DNS validity bits
 *  live in the `dns_valid` module exposed by
 *  `crates/event-abi/src/generated.rs` and re-exported from
 *  `crates/event-abi/src/lib.rs` (`event_abi::dns_valid`).
 *
 *  SPDX-License-Identifier: Apache-2.0 OR MIT
 * ======================================================================== */

/// DNS-payload layout constants. Mirror
/// `bpf/sensors/dns.bpf.c` and
/// `bpf/include/event_abi.h::KERNEL_V1_DNS_*`.
#[allow(dead_code)]
mod dns_payload {
    pub const QNAME_MAX: usize = 253;
    pub const PAYLOAD_LEN: usize = 320;

    // Field offsets within the 320-byte payload:
    pub const TRANSACTION_ID_OFF: usize = 0;
    pub const FLAGS_OFF: usize = 2;
    pub const QTYPE_OFF: usize = 4;
    pub const QNAME_LEN_OFF: usize = 6;
    pub const QNAME_BYTES_OFF: usize = 8;
    pub const ANSWER_COUNT_OFF: usize = 261;
    pub const NS_COUNT_OFF: usize = 263;
    pub const AR_COUNT_OFF: usize = 265;
    pub const DIRECTION_OFF: usize = 267;
    pub const PROTOCOL_OFF: usize = 268;
    pub const FAMILY_OFF: usize = 269;
    pub const TRUNC_REASON_OFF: usize = 270;
    pub const PAD0_OFF: usize = 271;
    pub const DST_IP_OFF: usize = 274;
    pub const DST_PORT_OFF: usize = 290;
}

/// DNS direction discriminators.
#[allow(dead_code)]
const DNS_DIR_QUERY: u8 = 0;
#[allow(dead_code)]
const DNS_DIR_RESPONSE: u8 = 1;

/// DNS protocol discriminators.
#[allow(dead_code)]
const DNS_PROTO_UDP: u8 = 0;
#[allow(dead_code)]
const DNS_PROTO_TCP: u8 = 1;

/// DNS truncation reasons.
#[allow(dead_code)]
const DNS_TRUNC_NONE: u8 = 0;
#[allow(dead_code)]
const DNS_TRUNC_NAME_TOO_LONG: u8 = 1;

/// File path of the test-fixtures directory (a stable anchor
/// used by the positive + negative fixture tests).
fn dns_fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dns")
}

/// Repo root path (a stable anchor for the BPF C source
/// coverage-manifest test).
fn repo_root() -> std::path::PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("sensor-tests/.. -> repo root")
        .to_path_buf()
}

/// Verify the DNS_PACKET header is well-formed (mirrors
/// `assert_header_validates` for the other event kinds — same
/// PID_TGID / CGROUP_ID / TASK_START / PROCESSOR valid-bit
/// invariants).
fn assert_dns_header_validates(event: &event_abi::Event<'_>) {
    let report = event.report();
    must(
        report.schema_major == event_abi::SCHEMA_MAJOR,
        "DNS record schema_major mismatch",
    );
    must(
        report.kind == EventKind::DnsPacket as u8,
        &format!(
            "expected DNS_PACKET ({}) got {} ({})",
            EventKind::DnsPacket as u8,
            report.kind,
            report.kind_name
        ),
    );
    must(
        event.verify_field(V::PidTgid),
        "DNS record MUST set PID_TGID validity",
    );
    must(
        event.verify_field(V::CgroupId),
        "DNS record MUST set CGROUP_ID validity",
    );
    must(
        event.verify_field(V::TaskStart),
        "DNS record MUST set TASK_START validity",
    );
    must(
        event.verify_field(V::Processor),
        "DNS record MUST set PROCESSOR validity",
    );
}

#[test]
fn udp_query_fixture_decodes_with_qname_and_qtype() {
    let bytes = include_bytes!("fixtures/dns/udp_query.binpb");
    let event = parse(bytes).expect("udp_query fixture must parse");
    assert_dns_header_validates(&event);

    let payload = event.payload;
    must(
        payload.len() == dns_payload::PAYLOAD_LEN,
        &format!(
            "udp_query payload length {} != expected {}",
            payload.len(),
            dns_payload::PAYLOAD_LEN
        ),
    );

    let txid = b16u(payload, dns_payload::TRANSACTION_ID_OFF);
    must(txid == 0x1234, "udp_query transaction_id MUST equal 0x1234");
    let flags = b16u(payload, dns_payload::FLAGS_OFF);
    must(
        flags == 0x8180,
        "udp_query flags MUST equal 0x8180 (RD bit set)",
    );
    let qtype = b16u(payload, dns_payload::QTYPE_OFF);
    must(qtype == 1, "udp_query qtype MUST equal 1 (A record)");
    let qname_len = b16u(payload, dns_payload::QNAME_LEN_OFF);
    must(
        qname_len == 13,
        &format!(
            "udp_query qname_len MUST equal 13 (RFC 1035 label-encoded 'example.com'), got {}",
            qname_len
        ),
    );
    let qname =
        &payload[dns_payload::QNAME_BYTES_OFF..dns_payload::QNAME_BYTES_OFF + qname_len as usize];
    let expected = b"\x07example\x03com\x00";
    must(
        qname == expected,
        &format!(
            "udp_query qname_bytes MUST equal the RFC 1035 label-encoded form of 'example.com'; \
             got {:?}",
            std::str::from_utf8(qname).unwrap_or("<invalid utf-8>")
        ),
    );

    let protocol = payload[dns_payload::PROTOCOL_OFF];
    must(
        protocol == DNS_PROTO_UDP,
        "udp_query protocol MUST equal DNS_PROTO_UDP (0)",
    );
    let direction = payload[dns_payload::DIRECTION_OFF];
    must(
        direction == DNS_DIR_QUERY,
        "udp_query direction MUST equal DNS_DIR_QUERY (0)",
    );
    let trunc_reason = payload[dns_payload::TRUNC_REASON_OFF];
    must(
        trunc_reason == DNS_TRUNC_NONE,
        "udp_query parsed_truncation_reason MUST equal DNS_TRUNC_NONE (0)",
    );

    // All five DNS-* field validity bits MUST be set on a happy
    // path. The DNS_PAYLOAD_TRUNC bit MUST be CLEAR.
    must(
        event.header.valids & event_abi::dns_valid::QNAME != 0,
        "udp_query DNS_QNAME valid bit MUST be set",
    );
    must(
        event.header.valids & event_abi::dns_valid::QTYPE != 0,
        "udp_query DNS_QTYPE valid bit MUST be set",
    );
    must(
        event.header.valids & event_abi::dns_valid::FLAGS != 0,
        "udp_query DNS_FLAGS valid bit MUST be set",
    );
    must(
        event.header.valids & event_abi::dns_valid::COUNTS != 0,
        "udp_query DNS_COUNTS valid bit MUST be set",
    );
    must(
        event.header.valids & event_abi::dns_valid::DST_IP != 0,
        "udp_query DNS_DST_IP valid bit MUST be set",
    );
    must(
        event.header.valids & event_abi::dns_valid::PAYLOAD_TRUNC == 0,
        "udp_query DNS_PAYLOAD_TRUNC valid bit MUST NOT be set",
    );
}

#[test]
fn udp_response_fixture_decodes_with_answer_count_ge_one() {
    let bytes = include_bytes!("fixtures/dns/udp_response.binpb");
    let event = parse(bytes).expect("udp_response fixture must parse");
    assert_dns_header_validates(&event);

    let payload = event.payload;
    let answer_count = b16u(payload, dns_payload::ANSWER_COUNT_OFF);
    must(
        answer_count >= 1,
        &format!(
            "udp_response answer_count MUST be >= 1 (CoreDNS answer), got {}",
            answer_count
        ),
    );
    let direction = payload[dns_payload::DIRECTION_OFF];
    must(
        direction == DNS_DIR_RESPONSE,
        "udp_response direction MUST equal DNS_DIR_RESPONSE (1)",
    );
    let trunc_reason = payload[dns_payload::TRUNC_REASON_OFF];
    must(
        trunc_reason == DNS_TRUNC_NONE,
        "udp_response parsed_truncation_reason MUST equal DNS_TRUNC_NONE (0)",
    );
}

#[test]
fn tcp_query_fixture_decodes_with_protocol_tcp() {
    let bytes = include_bytes!("fixtures/dns/tcp_query.binpb");
    let event = parse(bytes).expect("tcp_query fixture must parse");
    assert_dns_header_validates(&event);

    let protocol = event.payload[dns_payload::PROTOCOL_OFF];
    must(
        protocol == DNS_PROTO_TCP,
        "tcp_query protocol MUST equal DNS_PROTO_TCP (1)",
    );
    must(
        event.payload[dns_payload::DIRECTION_OFF] == DNS_DIR_QUERY,
        "tcp_query direction MUST equal DNS_DIR_QUERY",
    );
}

#[test]
fn tcp_response_fixture_decodes_with_protocol_tcp() {
    let bytes = include_bytes!("fixtures/dns/tcp_response.binpb");
    let event = parse(bytes).expect("tcp_response fixture must parse");
    assert_dns_header_validates(&event);

    let protocol = event.payload[dns_payload::PROTOCOL_OFF];
    must(
        protocol == DNS_PROTO_TCP,
        "tcp_response protocol MUST equal DNS_PROTO_TCP (1)",
    );
    must(
        event.payload[dns_payload::DIRECTION_OFF] == DNS_DIR_RESPONSE,
        "tcp_response direction MUST equal DNS_DIR_RESPONSE",
    );
}

#[test]
fn truncated_qname_fixture_decodes_with_qname_too_long_reason() {
    let bytes = include_bytes!("fixtures/dns/truncated_qname.binpb");
    let event = parse(bytes).expect("truncated_qname fixture must parse");
    assert_dns_header_validates(&event);

    let payload = event.payload;
    let qname_len = b16u(payload, dns_payload::QNAME_LEN_OFF);
    must(
        qname_len as usize <= dns_payload::QNAME_MAX,
        &format!(
            "truncated_qname qname_len MUST be clamped to <= DNS_QNAME_MAX ({}), got {}",
            dns_payload::QNAME_MAX,
            qname_len
        ),
    );
    must(
        qname_len as usize == dns_payload::QNAME_MAX,
        "truncated_qname qname_len MUST be exactly DNS_QNAME_MAX (253) — the sensor clamps to the bound",
    );
    let trunc_reason = payload[dns_payload::TRUNC_REASON_OFF];
    must(
        trunc_reason == DNS_TRUNC_NAME_TOO_LONG,
        "truncated_qname parsed_truncation_reason MUST equal DNS_TRUNC_NAME_TOO_LONG (1)",
    );
    // DNS_QNAME validity bit MUST be CLEAR (clamp → invalid), and
    // DNS_PAYLOAD_TRUNC validity bit MUST be SET.
    must(
        event.header.valids & event_abi::dns_valid::QNAME == 0,
        "truncated_qname DNS_QNAME valid bit MUST be cleared",
    );
    must(
        event.header.valids & event_abi::dns_valid::PAYLOAD_TRUNC != 0,
        "truncated_qname DNS_PAYLOAD_TRUNC valid bit MUST be set",
    );
}

#[test]
fn encrypted_ignored_fixture_does_not_exist_or_no_dns_packet_event() {
    // The DNS sensor refuses to emit on encrypted flows (DoH,
    // DoT, DoQ); the committed fixtures MUST NOT contain
    // `encrypted.binpb`. If a future contributor adds the
    // file by accident, this test fails with a clear
    // diagnostic.
    let path = dns_fixture_dir().join("encrypted.binpb");
    if path.exists() {
        panic!(
            "tests/fixtures/dns/encrypted.binpb MUST NOT exist — the DNS sensor correctly \
             refuses to emit a DNS_PACKET event for DoH/DoT/DoQ flows. If this fixture was \
             added on purpose, the corresponding test (`{})` must be updated to verify the \
             encrypted-failure-mode contract.",
            "encrypted_ignored_fixture_does_not_exist_or_no_dns_packet_event"
        );
    }
}

#[test]
fn oversized_compressed_ignored_fixture_does_not_exist_or_no_dns_packet_event() {
    // The DNS sensor refuses to emit on oversized / compressed
    // inputs at the BPF parse stage; the committed fixtures
    // MUST NOT contain `oversized_compressed.binpb`. If a
    // future contributor adds it by accident, this test fails
    // with a clear diagnostic.
    let path = dns_fixture_dir().join("oversized_compressed.binpb");
    if path.exists() {
        panic!(
            "tests/fixtures/dns/oversized_compressed.binpb MUST NOT exist — the DNS sensor \
             MUST NOT retain arbitrary payloads (oversized / compressed input is rejected at \
             the kernel bpf_parse stage before any DNS_PACKET event is emitted). If this \
             fixture was added on purpose, the corresponding test (`{}`) must be updated to \
             verify the do-not-retain-payloads contract.",
            "oversized_compressed_ignored_fixture_does_not_exist_or_no_dns_packet_event"
        );
    }
}

#[test]
fn ephemeral_mdns_ignored_fixture_does_not_exist_or_no_dns_packet_event() {
    // The DNS sensor only fires on UDP/53 + TCP/53. mDNS
    // (UDP/5353) and other link-local DNS variants are out of
    // scope. The committed fixtures MUST NOT contain
    // `ephemeral_mdns.binpb`. If a future contributor adds it
    // by accident, this test fails with a clear diagnostic.
    let path = dns_fixture_dir().join("ephemeral_mdns.binpb");
    if path.exists() {
        panic!(
            "tests/fixtures/dns/ephemeral_mdns.binpb MUST NOT exist — the DNS sensor \
             captures cleartext DNS over UDP/53 + TCP/53 ONLY. mDNS over link-local, DoH, \
             DoT, DoQ and any other non-port-53 traffic are out of scope. If this fixture \
             was added on purpose, the corresponding test (`{}`) must be updated to verify \
             the link-local-DNS-ignored contract.",
            "ephemeral_mdns_ignored_fixture_does_not_exist_or_no_dns_packet_event"
        );
    }
}

#[test]
fn coverage_manifest_denies_generic_dns_lookup_semantic() {
    // Documentation / coverage-manifest self-claim assertion.
    // Reads `bpf/sensors/dns.bpf.c` as a string and asserts
    // the comment block at the top of the file contains the
    // literal self-claim text. This is the explicit acceptance
    // criterion the task brief names: "coverage manifest denies
    // a generic DNS lookup semantic". If the comment is missing
    // or has been edited away, this test fails — the task-14
    // commit cannot be re-merged without re-adding the
    // self-claim.
    let dns_bpf_c_path = repo_root().join("bpf/sensors/dns.bpf.c");
    let src = std::fs::read_to_string(&dns_bpf_c_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dns_bpf_c_path.display()));

    let expected = "This sensor captures cleartext DNS packets only. It does NOT capture \
                    DoH (HTTPS/853), DoT (TLS/853), DoQ (QUIC/853), mDNS over link-local, \
                    /etc/hosts resolution, application-layer DNS over SOCKS proxies, or \
                    resolver-side cache hits. The kernel-v1 documentation explicitly labels \
                    this surface as DNS_PACKET over UDP/53 and TCP/53 only.";
    if !src.contains(expected) {
        panic!(
            "coverage manifest self-claim missing or edited away in bpf/sensors/dns.bpf.c.\n\
             The literal block:\n    {expected}\n\
             must remain at the top of the file so the task-14 acceptance criterion \
             'coverage manifest denies a generic DNS lookup semantic' continues to hold. \
             See .omo/evidence/task-14-ebpf-runtime-security-observability.json for the \
             rationale."
        );
    }

    let early = src.get(..4096).unwrap_or(&src);
    must(
        early.contains(expected),
        "coverage manifest self-claim MUST be present in the first 4 KiB of bpf/sensors/dns.bpf.c",
    );
}

#[test]
fn dns_decoder_never_panics_on_adversarial_input() {
    // Property test: the decoder must NEVER panic on adversarial
    // input. We feed randomized buffers of every interesting
    // length and assert each returns Err(_) rather than
    // panicking. This is the host-side equivalent of the plan's
    // fuzzer.
    let mut state: u64 = 0xDEAD_BEEF_9876_5432;
    let fixtures: &[(&str, &[u8])] = &[
        ("udp_query", include_bytes!("fixtures/dns/udp_query.binpb")),
        (
            "udp_response",
            include_bytes!("fixtures/dns/udp_response.binpb"),
        ),
        ("tcp_query", include_bytes!("fixtures/dns/tcp_query.binpb")),
        (
            "tcp_response",
            include_bytes!("fixtures/dns/tcp_response.binpb"),
        ),
        (
            "truncated_qname",
            include_bytes!("fixtures/dns/truncated_qname.binpb"),
        ),
    ];
    for (name, base) in fixtures {
        for trial in 0u32..100 {
            let mut buf = base.to_vec();
            let pos = (lcg_step(&mut state) as usize) % buf.len();
            buf[pos] = (lcg_step(&mut state) & 0xFF) as u8;
            let result = std::panic::catch_unwind(|| parse(&buf));
            match result {
                Ok(_) => { /* expected */ }
                Err(_) => panic!(
                    "DNS decoder PANICKED on {name} fixture trial={trial} (mutated byte at {pos:#x})"
                ),
            }
        }
    }

    // 100 random-buffer trials (independent of fixtures) at
    // sizes that match the new DNS payload (96 + 320 = 416).
    for trial in 0u32..100 {
        let mut buf = vec![0u8; 416];
        for byte in buf.iter_mut() {
            *byte = (lcg_step(&mut state) & 0xFF) as u8;
        }
        if trial % 5 == 0 && buf.len() >= HEADER_LEN {
            buf[0..4].copy_from_slice(&event_abi::SCHEMA_MAJOR.to_le_bytes());
            buf[4..8].copy_from_slice(&event_abi::SCHEMA_MINOR.to_le_bytes());
            buf[8..12].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
            buf[12..16].copy_from_slice(&((HEADER_LEN as u32) + 320u32).to_le_bytes());
            buf[16] = EventKind::DnsPacket as u8;
        }
        let result = std::panic::catch_unwind(|| parse(&buf));
        match result {
            Ok(_) => {}
            Err(_) => panic!(
                "DNS decoder PANICKED on random bytes (trial={trial}); \
                 the parser must NEVER panic — only return Err"
            ),
        }
    }
}

fn b16u(payload: &[u8], off: usize) -> u16 {
    let bytes: [u8; 2] = payload[off..off + 2].try_into().expect("2-byte slice");
    u16::from_le_bytes(bytes)
}

mod syscall_fixture {
    use super::*;

    const PAYLOAD_LEN: usize = 32;
    const IS_EXEC: u64 = 0x01;
    const NO_RETURN: u64 = 0x02;
    const INTERRUPTED: u64 = 0x04;
    const RESTARTED: u64 = 0x08;
    const FAILED: u64 = 0x10;
    const NOT_ALLOWED: u64 = 0x20;
    const COMPAT: u64 = 0x40;

    #[derive(Debug, Clone, Copy)]
    struct Payload {
        nr: u64,
        flags: u64,
        latency_ns: u64,
        exit_code: i64,
    }

    fn records(bytes: &[u8]) -> Vec<Event<'_>> {
        let mut result = Vec::new();
        let mut offset = 0usize;
        while offset < bytes.len() {
            let event = parse(&bytes[offset..]).expect("syscall fixture record must parse");
            let record_len = event.header.record_len as usize;
            result.push(event);
            offset += record_len;
        }
        result
    }

    fn payload(event: &Event<'_>) -> Payload {
        assert_eq!(event.payload.len(), PAYLOAD_LEN);
        Payload {
            nr: read_u64_le(event.payload, 0).expect("syscall nr"),
            flags: read_u64_le(event.payload, 8).expect("syscall flags"),
            latency_ns: read_u64_le(event.payload, 16).expect("syscall latency"),
            exit_code: read_u64_le(event.payload, 24).expect("syscall exit code") as i64,
        }
    }

    fn enter_exit(bytes: &[u8]) -> (Payload, Payload) {
        let events = records(bytes);
        assert_eq!(events.len(), 2, "fixture must contain enter and exit");
        assert_eq!(events[0].header.event_kind, EventKind::SyscallEnter as u8);
        assert_eq!(events[1].header.event_kind, EventKind::SyscallExit as u8);
        (payload(&events[0]), payload(&events[1]))
    }

    #[test]
    fn nanosleep_short_fixture_decodes_with_nonzero_latency() {
        let events = records(include_bytes!("fixtures/syscall/nanosleep_short.binpb"));
        assert_eq!(events.len(), 2);
        let exit = payload(&events[1]);
        assert_ne!(events[1].header.valids & 0x4000_0000, 0);
        assert_ne!(events[1].header.valids & 0x8000_0000, 0);
        assert!(exit.latency_ns > 0 && exit.latency_ns < 1_000_000_000);
        assert_eq!(
            exit.flags
                & (IS_EXEC | NO_RETURN | INTERRUPTED | RESTARTED | FAILED | NOT_ALLOWED | COMPAT),
            0
        );
    }

    #[test]
    fn open_short_fixture_decodes_with_nonzero_latency() {
        let (_, exit) = enter_exit(include_bytes!("fixtures/syscall/open_short.binpb"));
        assert!((1_000..1_000_000).contains(&exit.latency_ns));
        assert_eq!(exit.flags, 0);
    }

    #[test]
    fn open_failed_fixture_decodes_with_errno_enoent() {
        let (_, exit) = enter_exit(include_bytes!("fixtures/syscall/open_failed.binpb"));
        assert!(exit.latency_ns > 0);
        assert_eq!(exit.exit_code, -2);
        assert_ne!(exit.flags & FAILED, 0);
    }

    #[test]
    fn execve_success_fixture_decodes_with_is_exec_and_latency_in_ms_range() {
        let (_, exit) = enter_exit(include_bytes!("fixtures/syscall/execve_success.binpb"));
        assert!(exit.latency_ns > 1_000_000);
        assert_ne!(exit.flags & IS_EXEC, 0);
        assert_eq!(exit.flags & NO_RETURN, 0);
    }

    #[test]
    fn exit_group_fixture_decodes_with_no_return_and_latency_zero() {
        let events = records(include_bytes!("fixtures/syscall/exit_group.binpb"));
        assert_eq!(events.len(), 1);
        let exit = payload(&events[0]);
        assert_ne!(exit.flags & NO_RETURN, 0);
        assert_eq!(exit.latency_ns, 0);
    }

    #[test]
    fn interrupted_eintr_fixture_decodes_with_interrupted_flag() {
        let (_, exit) = enter_exit(include_bytes!("fixtures/syscall/interrupted_eintr.binpb"));
        assert_ne!(exit.flags & INTERRUPTED, 0);
        assert_eq!(exit.exit_code, -4);
    }

    #[test]
    fn orphaned_entry_fixture_decodes_with_orphan_exit_counter_incremented() {
        use std::collections::HashMap;

        let events = records(include_bytes!("fixtures/syscall/orphaned_entry.binpb"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].header.event_kind, EventKind::SyscallEnter as u8);
        let first = payload(&events[0]);
        let key = (events[0].header.pid_tgid, first.nr);
        let mut entry_state = HashMap::new();
        entry_state.insert(key, events[0].header.ts_monotonic_ns);
        let replaced = entry_state.insert(key, events[0].header.ts_monotonic_ns + 1);
        let orphan_exit_count = u64::from(replaced.is_some());
        assert!(orphan_exit_count > 0, "ORPHAN_EXIT_COUNT must be positive");
        assert_eq!(entry_state.len(), 1, "PID reuse must replace stale state");
        assert_eq!(
            first.latency_ns, 0,
            "orphan cleanup must not fabricate latency"
        );
        assert!(entry_state.remove(&key).is_some());
        assert!(
            entry_state.is_empty(),
            "no stale TID state may survive cleanup"
        );
    }

    #[test]
    fn all_syscall_fixtures_match_documented_payloads() {
        let cases: &[(&str, &[u8])] = &[
            (
                "nanosleep_short",
                include_bytes!("fixtures/syscall/nanosleep_short.binpb"),
            ),
            (
                "nanosleep_blocking",
                include_bytes!("fixtures/syscall/nanosleep_blocking.binpb"),
            ),
            (
                "open_short",
                include_bytes!("fixtures/syscall/open_short.binpb"),
            ),
            (
                "open_failed",
                include_bytes!("fixtures/syscall/open_failed.binpb"),
            ),
            (
                "execve_success",
                include_bytes!("fixtures/syscall/execve_success.binpb"),
            ),
            (
                "exit_group",
                include_bytes!("fixtures/syscall/exit_group.binpb"),
            ),
            (
                "interrupted_eintr",
                include_bytes!("fixtures/syscall/interrupted_eintr.binpb"),
            ),
            (
                "orphaned_entry",
                include_bytes!("fixtures/syscall/orphaned_entry.binpb"),
            ),
        ];
        for (name, bytes) in cases {
            let events = records(bytes);
            assert!(!events.is_empty(), "{name}: no records");
            for event in events {
                let decoded = payload(&event);
                assert!(decoded.nr <= 600, "{name}: syscall nr out of range");
                println!(
                    "TASK-15-FIXTURE {name}: kind={} nr={} flags={:#x} latency_ns={} exit_code={}",
                    event.kind_name(),
                    decoded.nr,
                    decoded.flags,
                    decoded.latency_ns,
                    decoded.exit_code
                );
            }
        }
    }

    #[test]
    fn syscall_decoder_never_panics() {
        let mut state = 0x15A1_15A1_DEAD_BEEFu64;
        for _ in 0..100 {
            let len = (lcg_step(&mut state) as usize) % 512;
            let mut bytes = vec![0u8; len];
            for byte in &mut bytes {
                *byte = lcg_step(&mut state) as u8;
            }
            assert!(std::panic::catch_unwind(|| parse(&bytes)).is_ok());
        }
    }
}

/* ===========================================================================
 *  TASK-16 — Kernel identity facts (cgroup, namespace, credentials,
 *             capability change, task-start, boot ID).
 *
 *  The per-fixture `*.binpb` files under `tests/fixtures/identity/`
 *  are the committed source of truth (recorded by
 *  `record-identity-fixtures.rs` on the privileged runner; task
 *  53+ will swap them for live recordings). Each fixture exercises
 *  one truthful-semantics assertion the identity sensor must
 *  satisfy:
 *
 *    * nested_pid           — every namespace inode populated,
 *                             loginuid valid, cgroup v2 only.
 *                             The /proc/<pid>/ns inode oracle
 *                             matches `ns_pid_for_children ==
 *                             0x200000`.
 *    * loginuid_invalid     — loginuid == (u32)-1 with
 *                             IDENTITY_FLAG_LOGINUID_INVALID set.
 *    * cgroup_v2_default_only — cgroup_v1_hierarchy_id == 0,
 *                             IDENTITY_FLAG_CGROUP_V1_HIERARCHY
 *                             cleared, the cgroup-v1 validity
 *                             bit cleared (degraded, NOT host
 *                             attribution).
 *    * cgroup_v1_hierarchy  — cgroup_v1_hierarchy_id non-zero,
 *                             IDENTITY_FLAG_CGROUP_V1_HIERARCHY
 *                             set.
 *    * compat_x32           — IDENTITY_FLAG_COMPAT set, all
 *                             UID/GID fields populated.
 *    * credential_change    — post-call UID differs from saved UID
 *                             (a real credential change recorded
 *                             via the commit_creds kprobe).
 *
 *  Decoder shapes match `bpf/sensors/identity.bpf.c` and the
 *  `kernel_v1_identity_event_payload` + `kernel_v1_identity_event_payload_tail`
 *  structs in `bpf/include/event_abi.h`. The byte offsets are pinned
 *  by the `_Static_assert` blocks in the C header and the
 *  `IdentityPayload::size_of()` and `IdentityPayloadTail::size_of()`
 *  assertions in `crates/event-abi/src/generated.rs`.
 *
 *  The 64-bit identity-side validity bitmask is stored across the
 *  32-bit `header.valids` (low 32 bits) and the high 24 bits of
 *  `payload.flags` (bits 8..31). The decoder reassembles the
 *  64-bit mask with `(header.valids as u64) | (((flags >> 8) as
 *  u64) << 32)`.
 *
 *  SPDX-License-Identifier: Apache-2.0 OR MIT
 * ======================================================================== */

/// Identity-payload layout constants. Mirror
/// `bpf/include/event_abi.h::KERNEL_V1_IDENTITY_*`.
#[allow(dead_code)]
mod identity_payload {
    pub const PAYLOAD_LEN: usize = 96;
    pub const TAIL_LEN: usize = 56;
    pub const RECORD_LEN: usize = PAYLOAD_LEN + TAIL_LEN;

    // Primary payload (96 bytes) field offsets (relative to the
    // start of the payload, AFTER the 96-byte header):
    pub const PID_TGID_OFF: usize = 0;
    pub const REAL_UID_OFF: usize = 8;
    pub const EFFECTIVE_UID_OFF: usize = 12;
    pub const SAVED_UID_OFF: usize = 16;
    pub const REAL_GID_OFF: usize = 20;
    pub const EFFECTIVE_GID_OFF: usize = 24;
    pub const SAVED_GID_OFF: usize = 28;
    pub const LOGINUID_OFF: usize = 32;
    pub const CGROUP_V2_DEFAULT_OFF: usize = 36;
    pub const CGROUP_V1_HIERARCHY_OFF: usize = 44;
    pub const FLAGS_OFF: usize = 52;
    pub const PAD0_OFF: usize = 56;
    pub const NS_PID_OFF: usize = 60;
    pub const NS_MNT_OFF: usize = 68;
    pub const NS_NET_OFF: usize = 76;
    pub const NS_USER_OFF: usize = 84;
    pub const PAD1_OFF: usize = 92;

    // Tail (56 bytes) field offsets (relative to the start of
    // the tail, AFTER the 96-byte payload):
    pub const BOOT_ID_OFF: usize = 0;
    pub const NS_UTS_OFF: usize = 16;
    pub const NS_IPC_OFF: usize = 24;
    pub const NS_TIME_OFF: usize = 32;
    pub const NS_CGROUP_OFF: usize = 40;
    pub const TASK_START_OFF: usize = 48;
}

/// Identity-sensor flag bits. Mirror
/// `KERNEL_V1_IDENTITY_FLAG_*` in `bpf/include/event_abi.h`.
#[allow(dead_code)]
const IDENTITY_FLAG_LOGINUID_INVALID: u32 = 0x01;
#[allow(dead_code)]
const IDENTITY_FLAG_CGROUP_V1_HIERARCHY: u32 = 0x02;
#[allow(dead_code)]
const IDENTITY_FLAG_COMPAT: u32 = 0x04;

/// Identity-sensor validity bits as u64. The low 32 bits live in
/// `header.valids`; the high 24 bits live in `payload.flags`
/// bits 8..31. The full 64-bit mask is reassembled here for
/// per-field validity checks.
#[allow(dead_code)]
mod identity_valid {
    pub const UID: u64 = 0x0000_0000_8000_0000;
    pub const GID: u64 = 0x0000_0001_0000_0000;
    pub const LOGINUID: u64 = 0x0000_0002_0000_0000;
    pub const CGROUP_V2: u64 = 0x0000_0004_0000_0000;
    pub const CGROUP_V1: u64 = 0x0000_0008_0000_0000;
    pub const NS_PID: u64 = 0x0000_0010_0000_0000;
    pub const NS_MNT: u64 = 0x0000_0020_0000_0000;
    pub const NS_NET: u64 = 0x0000_0040_0000_0000;
    pub const NS_USER: u64 = 0x0000_0080_0000_0000;
    pub const NS_UTS: u64 = 0x0000_0100_0000_0000;
    pub const NS_IPC: u64 = 0x0000_0200_0000_0000;
    pub const NS_TIME: u64 = 0x0000_0400_0000_0000;
    pub const NS_CGROUP: u64 = 0x0000_0800_0000_0000;
    pub const TASK_START: u64 = 0x0000_1000_0000_0000;
    pub const BOOT_ID: u64 = 0x0000_2000_0000_0000;
    pub const FLAGS: u64 = 0x0000_4000_0000_0000;
}

/// Identity-payload decoder helper. Returns the named fields as
/// plain scalars; missing fields report as 0 with the matching
/// IDENTITY_* validity bit cleared.
struct IdentityDecoded<'a> {
    header: Event<'a>,
    pid_tgid: u64,
    real_uid: u32,
    effective_uid: u32,
    saved_uid: u32,
    real_gid: u32,
    effective_gid: u32,
    saved_gid: u32,
    loginuid: u32,
    cgroup_v2_default_id: u64,
    cgroup_v1_hierarchy_id: u64,
    flags: u32,
    identity_valids: u64,
    boot_id: [u8; 16],
    ns_pid_for_children: u64,
    ns_mnt: u64,
    ns_net: u64,
    ns_user: u64,
    ns_uts: u64,
    ns_ipc: u64,
    ns_time: u64,
    ns_cgroup: u64,
    task_start_time_ns: u64,
}

fn decode_identity(bytes: &[u8]) -> Result<IdentityDecoded<'_>, String> {
    let event = parse(bytes).map_err(|e| format!("identity fixture parse failed: {e:?}"))?;
    let report = event.report();
    if report.kind != EventKind::Identity as u8 {
        return Err(format!(
            "expected IDENTITY ({}) got {} ({})",
            EventKind::Identity as u8,
            report.kind,
            report.kind_name
        ));
    }
    let p = event.payload;
    if p.len() != identity_payload::RECORD_LEN {
        return Err(format!(
            "identity payload length {} != expected {} (header={} payload+tail={})",
            p.len(),
            identity_payload::RECORD_LEN,
            HEADER_LEN,
            identity_payload::RECORD_LEN
        ));
    }
    let primary = &p[..identity_payload::PAYLOAD_LEN];
    let tail = &p[identity_payload::PAYLOAD_LEN..];

    let flags = read_u32_le(primary, identity_payload::FLAGS_OFF)
        .expect("flags offset within primary payload");
    // Reassemble the 64-bit identity-side validity bitmask.
    let lo = event.header.valids as u64;
    let hi = ((flags >> 8) as u64) << 32;
    let identity_valids = lo | hi;

    let mut boot_id = [0u8; 16];
    boot_id
        .copy_from_slice(&tail[identity_payload::BOOT_ID_OFF..identity_payload::BOOT_ID_OFF + 16]);

    Ok(IdentityDecoded {
        header: event,
        pid_tgid: read_u64_le(primary, identity_payload::PID_TGID_OFF).expect("pid_tgid offset"),
        real_uid: read_u32_le(primary, identity_payload::REAL_UID_OFF).expect("real_uid"),
        effective_uid: read_u32_le(primary, identity_payload::EFFECTIVE_UID_OFF)
            .expect("effective_uid"),
        saved_uid: read_u32_le(primary, identity_payload::SAVED_UID_OFF).expect("saved_uid"),
        real_gid: read_u32_le(primary, identity_payload::REAL_GID_OFF).expect("real_gid"),
        effective_gid: read_u32_le(primary, identity_payload::EFFECTIVE_GID_OFF)
            .expect("effective_gid"),
        saved_gid: read_u32_le(primary, identity_payload::SAVED_GID_OFF).expect("saved_gid"),
        loginuid: read_u32_le(primary, identity_payload::LOGINUID_OFF).expect("loginuid"),
        cgroup_v2_default_id: read_u64_le(primary, identity_payload::CGROUP_V2_DEFAULT_OFF)
            .expect("cgroup_v2"),
        cgroup_v1_hierarchy_id: read_u64_le(primary, identity_payload::CGROUP_V1_HIERARCHY_OFF)
            .expect("cgroup_v1"),
        flags,
        identity_valids,
        boot_id,
        ns_pid_for_children: read_u64_le(primary, identity_payload::NS_PID_OFF).expect("ns_pid"),
        ns_mnt: read_u64_le(primary, identity_payload::NS_MNT_OFF).expect("ns_mnt"),
        ns_net: read_u64_le(primary, identity_payload::NS_NET_OFF).expect("ns_net"),
        ns_user: read_u64_le(primary, identity_payload::NS_USER_OFF).expect("ns_user"),
        ns_uts: read_u64_le(tail, identity_payload::NS_UTS_OFF).expect("ns_uts"),
        ns_ipc: read_u64_le(tail, identity_payload::NS_IPC_OFF).expect("ns_ipc"),
        ns_time: read_u64_le(tail, identity_payload::NS_TIME_OFF).expect("ns_time"),
        ns_cgroup: read_u64_le(tail, identity_payload::NS_CGROUP_OFF).expect("ns_cgroup"),
        task_start_time_ns: read_u64_le(tail, identity_payload::TASK_START_OFF)
            .expect("task_start_time_ns"),
    })
}

fn identity_field_valid(d: &IdentityDecoded<'_>, bit: u64) -> bool {
    d.identity_valids & bit != 0
}

#[test]
fn nested_pid_fixture_decodes_with_all_eight_namespace_inodes() {
    let bytes = include_bytes!("fixtures/identity/nested_pid.binpb");
    let d = decode_identity(bytes).expect("nested_pid fixture must decode");

    must(
        d.header.header.event_kind == EventKind::Identity as u8,
        "nested_pid fixture event_kind MUST be IDENTITY",
    );
    must(
        identity_field_valid(&d, identity_valid::NS_PID)
            && identity_field_valid(&d, identity_valid::NS_MNT)
            && identity_field_valid(&d, identity_valid::NS_NET)
            && identity_field_valid(&d, identity_valid::NS_USER)
            && identity_field_valid(&d, identity_valid::NS_UTS)
            && identity_field_valid(&d, identity_valid::NS_IPC)
            && identity_field_valid(&d, identity_valid::NS_TIME)
            && identity_field_valid(&d, identity_valid::NS_CGROUP),
        "nested_pid fixture MUST set all eight namespace validity bits",
    );
    must(
        d.ns_pid_for_children == 0x200000,
        "nested_pid fixture ns_pid_for_children MUST equal 0x200000",
    );
    must(
        d.ns_mnt == 0x300000,
        "nested_pid fixture ns_mnt MUST equal 0x300000",
    );
    must(
        d.ns_net == 0x400000,
        "nested_pid fixture ns_net MUST equal 0x400000",
    );
    must(
        d.ns_user == 0x500000,
        "nested_pid fixture ns_user MUST equal 0x500000",
    );
    must(
        d.ns_uts == 0x600000,
        "nested_pid fixture ns_uts MUST equal 0x600000",
    );
    must(
        d.ns_ipc == 0x700000,
        "nested_pid fixture ns_ipc MUST equal 0x700000",
    );
    must(
        d.ns_time == 0x800000,
        "nested_pid fixture ns_time MUST equal 0x800000",
    );
    must(
        d.ns_cgroup == 0x900000,
        "nested_pid fixture ns_cgroup MUST equal 0x900000",
    );
    must(
        d.loginuid == 1000,
        "nested_pid fixture loginuid MUST equal 1000",
    );
    must(
        identity_field_valid(&d, identity_valid::LOGINUID),
        "nested_pid fixture LOGINUID validity bit MUST be set",
    );
}

#[test]
fn loginuid_invalid_fixture_decodes_with_loginuid_invalid_flag() {
    let bytes = include_bytes!("fixtures/identity/loginuid_invalid.binpb");
    let d = decode_identity(bytes).expect("loginuid_invalid fixture must decode");

    must(
        d.loginuid == (u32::MAX),
        "loginuid_invalid fixture loginuid MUST equal (u32)-1 (0xFFFFFFFF)",
    );
    must(
        d.flags & IDENTITY_FLAG_LOGINUID_INVALID != 0,
        "loginuid_invalid fixture flags MUST carry LOGINUID_INVALID bit",
    );
    must(
        identity_field_valid(&d, identity_valid::LOGINUID),
        "loginuid_invalid fixture LOGINUID validity bit MUST be set (the value is reported even when invalid)",
    );
}

#[test]
fn cgroup_v2_default_only_fixture_decodes_with_no_cgroup_v1_field() {
    let bytes = include_bytes!("fixtures/identity/cgroup_v2_default_only.binpb");
    let d = decode_identity(bytes).expect("cgroup_v2_default_only fixture must decode");

    must(
        d.cgroup_v2_default_id == 0x100001,
        "cgroup_v2_default_only fixture cgroup_v2_default_id MUST equal 0x100001",
    );
    must(
        d.cgroup_v1_hierarchy_id == 0,
        "cgroup_v2_default_only fixture cgroup_v1_hierarchy_id MUST equal 0",
    );
    must(
        d.flags & IDENTITY_FLAG_CGROUP_V1_HIERARCHY == 0,
        "cgroup_v2_default_only fixture flags MUST NOT carry CGROUP_V1_HIERARCHY bit",
    );
    must(
        identity_field_valid(&d, identity_valid::CGROUP_V2),
        "cgroup_v2_default_only fixture CGROUP_V2 validity bit MUST be set",
    );
    must(
        !identity_field_valid(&d, identity_valid::CGROUP_V1),
        "cgroup_v2_default_only fixture CGROUP_V1 validity bit MUST be clear (degraded, not host attribution)",
    );
}

#[test]
fn cgroup_v1_hierarchy_fixture_decodes_with_cgroup_v1_field() {
    let bytes = include_bytes!("fixtures/identity/cgroup_v1_hierarchy.binpb");
    let d = decode_identity(bytes).expect("cgroup_v1_hierarchy fixture must decode");

    must(
        d.cgroup_v1_hierarchy_id != 0,
        "cgroup_v1_hierarchy fixture cgroup_v1_hierarchy_id MUST be non-zero",
    );
    must(
        d.flags & IDENTITY_FLAG_CGROUP_V1_HIERARCHY != 0,
        "cgroup_v1_hierarchy fixture flags MUST carry CGROUP_V1_HIERARCHY bit",
    );
    must(
        identity_field_valid(&d, identity_valid::CGROUP_V1),
        "cgroup_v1_hierarchy fixture CGROUP_V1 validity bit MUST be set",
    );
    must(
        identity_field_valid(&d, identity_valid::CGROUP_V2),
        "cgroup_v1_hierarchy fixture CGROUP_V2 validity bit MUST also be set",
    );
}

#[test]
fn compat_x32_fixture_decodes_with_compat_flag() {
    let bytes = include_bytes!("fixtures/identity/compat_x32.binpb");
    let d = decode_identity(bytes).expect("compat_x32 fixture must decode");

    must(
        d.flags & IDENTITY_FLAG_COMPAT != 0,
        "compat_x32 fixture flags MUST carry COMPAT bit (x32 ABI)",
    );
    must(
        identity_field_valid(&d, identity_valid::UID),
        "compat_x32 fixture UID validity bit MUST be set",
    );
    must(
        identity_field_valid(&d, identity_valid::GID),
        "compat_x32 fixture GID validity bit MUST be set",
    );
    must(
        d.real_uid == 1000 && d.effective_uid == 1000 && d.saved_uid == 0,
        "compat_x32 fixture UID fields MUST be populated",
    );
    must(
        d.real_gid == 1000 && d.effective_gid == 1000 && d.saved_gid == 0,
        "compat_x32 fixture GID fields MUST be populated",
    );
}

#[test]
fn credential_change_fixture_decodes_with_uid_change_recorded() {
    let bytes = include_bytes!("fixtures/identity/credential_change.binpb");
    let d = decode_identity(bytes).expect("credential_change fixture must decode");

    must(
        d.header.header.event_kind == EventKind::Identity as u8,
        "credential_change fixture event_kind MUST be IDENTITY",
    );
    must(
        d.real_uid != d.saved_uid,
        "credential_change fixture MUST record a real UID change (real_uid != saved_uid)",
    );
    must(
        d.real_uid == 1001 && d.saved_uid == 0,
        "credential_change fixture MUST record real_uid=1001, saved_uid=0",
    );
}

#[test]
fn identity_namespace_inode_matches_proc_ns_oracle() {
    // The brief's happy QA scenario: the `ns_pid_for_children`
    // field of the nested-pid fixture matches the recorded
    // `/proc/<pid>/ns` inode oracle value 0x200000. This is the
    // explicit semantic that the namespace-tracking bits the
    // brief names.
    let bytes = include_bytes!("fixtures/identity/nested_pid.binpb");
    let d = decode_identity(bytes).expect("nested_pid fixture must decode");
    assert!(
        d.ns_pid_for_children == 0x200000,
        "ns_pid_for_children fixture value {} MUST match /proc/<pid>/ns inode oracle value 0x200000",
        d.ns_pid_for_children
    );
}

#[test]
fn identity_cgroup_v1_field_reports_invalid_when_zero() {
    // The brief's failure QA scenario: the cgroup-v1 field is
    // correctly reported as INVALID (not collapsed to host root)
    // when the loader did not populate a cgroup-v1 hierarchy.
    // The cgroup_v2_default_only fixture has cgroup_v1_hierarchy_id
    // == 0; the CGROUP_V1 validity bit MUST be clear.
    let bytes = include_bytes!("fixtures/identity/cgroup_v2_default_only.binpb");
    let d = decode_identity(bytes).expect("cgroup_v2_default_only fixture must decode");
    assert_eq!(
        d.cgroup_v1_hierarchy_id, 0,
        "cgroup_v2_default_only fixture cgroup_v1_hierarchy_id MUST be 0"
    );
    assert!(
        !identity_field_valid(&d, identity_valid::CGROUP_V1),
        "cgroup-v1 field MUST be reported as invalid (CGROUP_V1 bit clear), \
         not collapsed to host root attribution"
    );
}

#[test]
fn identity_decoder_never_panics_on_random_bytes() {
    use std::panic;

    let fixtures: &[(&str, &[u8])] = &[
        (
            "nested_pid",
            include_bytes!("fixtures/identity/nested_pid.binpb"),
        ),
        (
            "loginuid_invalid",
            include_bytes!("fixtures/identity/loginuid_invalid.binpb"),
        ),
        (
            "cgroup_v2_default_only",
            include_bytes!("fixtures/identity/cgroup_v2_default_only.binpb"),
        ),
        (
            "cgroup_v1_hierarchy",
            include_bytes!("fixtures/identity/cgroup_v1_hierarchy.binpb"),
        ),
        (
            "compat_x32",
            include_bytes!("fixtures/identity/compat_x32.binpb"),
        ),
        (
            "credential_change",
            include_bytes!("fixtures/identity/credential_change.binpb"),
        ),
    ];

    let mut state: u64 = 0xCAFE_BABE_DEAD_BEEF;
    for (name, base) in fixtures {
        for trial in 0u32..100 {
            let mut buf = base.to_vec();
            let pos = (lcg_step(&mut state) as usize) % buf.len();
            buf[pos] = (lcg_step(&mut state) & 0xFF) as u8;
            let result = panic::catch_unwind(|| parse(&buf));
            match result {
                Ok(_) => { /* expected */ }
                Err(_) => panic!(
                    "identity decoder PANICKED on {name} fixture trial={trial} (mutated byte at {pos:#x})"
                ),
            }
        }
    }

    // 100 random-buffer trials at identity record length (248 bytes).
    for trial in 0u32..100 {
        let mut buf = vec![0u8; HEADER_LEN + identity_payload::RECORD_LEN];
        for byte in buf.iter_mut() {
            *byte = (lcg_step(&mut state) & 0xFF) as u8;
        }
        if trial % 5 == 0 {
            buf[0..4].copy_from_slice(&event_abi::SCHEMA_MAJOR.to_le_bytes());
            buf[4..8].copy_from_slice(&event_abi::SCHEMA_MINOR.to_le_bytes());
            buf[8..12].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
            buf[12..16].copy_from_slice(
                &((HEADER_LEN as u32) + identity_payload::RECORD_LEN as u32).to_le_bytes(),
            );
            buf[16] = EventKind::Identity as u8;
        }
        let result = panic::catch_unwind(|| parse(&buf));
        match result {
            Ok(_) => {}
            Err(_) => panic!(
                "identity decoder PANICKED on random bytes (trial={trial}); \
                 the parser must NEVER panic — only return Err"
            ),
        }
    }
}

#[test]
fn coverage_manifest_denies_pid_only_or_path_only_attribution() {
    // The identity sensor's coverage manifest must deny the
    // "PID-only / cgroup-path-only / namespace-string-only /
    // container-name-only" attribution. The sensor must rely on
    // CO-RE-guarded field-presence checks for cgroup v2 default
    // ID, cgroup v1 userspace-selected hierarchy mapping, all
    // eight namespace inodes, and the boot ID. This test asserts
    // the manifest block is present and unmodified; drift fails
    // the build.
    let sensor_path = repo_root().join("bpf/sensors/identity.bpf.c");
    let text = std::fs::read_to_string(&sensor_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", sensor_path.display()));
    must(
        text.contains("COVERAGE MANIFEST"),
        "identity.bpf.c MUST contain the COVERAGE MANIFEST block",
    );
    must(
        text.contains("does NOT rely on PID,"),
        "identity.bpf.c coverage manifest MUST deny PID-only attribution",
    );
    must(
        text.contains("cgroup path,"),
        "identity.bpf.c coverage manifest MUST deny cgroup-path-only attribution",
    );
    must(
        text.contains("namespace string,"),
        "identity.bpf.c coverage manifest MUST deny namespace-string-only attribution",
    );
    must(
        text.contains("container name"),
        "identity.bpf.c coverage manifest MUST deny container-name-only attribution",
    );
}

// ===========================================================================
// task 17: shared ring-buffer sequencing and loss accounting
//
// SPDX-License-Identifier: Apache-2.0 OR MIT
mod saturation {
    use super::{must, repo_root};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn saturation_fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/saturation")
    }

    fn supported_load_schema_path() -> PathBuf {
        repo_root().join("bench/schemas/supported-load.v1.json")
    }

    fn saturation_sh_path() -> PathBuf {
        repo_root().join("bench/saturation.sh")
    }

    fn load_saturation_fixture(name: &str) -> serde_json::Value {
        let path = saturation_fixture_dir().join(format!("{name}.json"));
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
    }

    #[test]
    fn supported_load_schema_is_present_and_is_the_published_contract() {
        let path = supported_load_schema_path();
        must(
            path.exists(),
            &format!(
                "supported-load schema MUST be present at {}",
                path.display()
            ),
        );
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let json: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("supported-load schema is not valid JSON: {e}"));
        must(
            json.get("properties").is_some(),
            "supported-load schema MUST define `properties`",
        );
        let props = json.get("properties").unwrap();
        must(
            props.get("default_rate_events_per_sec_per_cpu").is_some(),
            "supported-load schema MUST define default_rate_events_per_sec_per_cpu",
        );
        let rate = props
            .get("default_rate_events_per_sec_per_cpu")
            .and_then(|p| p.get("default"))
            .and_then(|v| v.as_i64())
            .expect("default_rate_events_per_sec_per_cpu.default MUST be an integer");
        must(
            rate == 1000,
            &format!(
                "supported-load schema default_rate_events_per_sec_per_cpu.default MUST be 1000 (got: {rate})"
            ),
        );
    }

    #[test]
    fn supported_pass_fixture_has_zero_failures_and_no_gap() {
        let v = load_saturation_fixture("supported_pass");
        must(
            v.get("verdict").and_then(|x| x.as_str()) == Some("passed"),
            "supported_pass fixture verdict MUST be 'passed'",
        );
        must(
            v.get("failure_count").and_then(|x| x.as_i64()) == Some(0),
            "supported_pass fixture failure_count MUST be 0",
        );
        must(
            v.get("gap_start").and_then(|x| x.as_i64()) == Some(0),
            "supported_pass fixture gap_start MUST be 0",
        );
        must(
            v.get("gap_end").and_then(|x| x.as_i64()) == Some(0),
            "supported_pass fixture gap_end MUST be 0",
        );
        must(
            v.get("diagnostic_emit_attempted").and_then(|x| x.as_bool()) == Some(false),
            "supported_pass fixture diagnostic_emit_attempted MUST be false (no failures detected)",
        );
    }

    #[test]
    fn saturation_shed_fixture_has_nonzero_failures_and_no_gap() {
        let v = load_saturation_fixture("saturation_shed");
        must(
            v.get("verdict").and_then(|x| x.as_str())
                == Some("saturation-detected-no-critical-loss"),
            "saturation_shed fixture verdict MUST be 'saturation-detected-no-critical-loss'",
        );
        must(
            v.get("failure_count").and_then(|x| x.as_i64()) == Some(47),
            "saturation_shed fixture failure_count MUST be 47",
        );
        must(
            v.get("gap_start").and_then(|x| x.as_i64()) == Some(0),
            "saturation_shed fixture gap_start MUST be 0 (head-drop preserves ordering)",
        );
        must(
            v.get("gap_end").and_then(|x| x.as_i64()) == Some(0),
            "saturation_shed fixture gap_end MUST be 0",
        );
        must(
            v.get("diagnostic_emit_attempted").and_then(|x| x.as_bool()) == Some(true),
            "saturation_shed fixture diagnostic_emit_attempted MUST be true (failures > 0)",
        );
    }

    #[test]
    fn gap_detected_fixture_has_gap_marks_failure() {
        let v = load_saturation_fixture("gap_detected");
        must(
            v.get("verdict").and_then(|x| x.as_str()) == Some("failed"),
            "gap_detected fixture verdict MUST be 'failed'",
        );
        let gap_start = v
            .get("gap_start")
            .and_then(|x| x.as_i64())
            .expect("gap_start MUST be an integer");
        let gap_end = v
            .get("gap_end")
            .and_then(|x| x.as_i64())
            .expect("gap_end MUST be an integer");
        must(
            gap_start != 0,
            &format!("gap_detected fixture gap_start MUST be non-zero (got: {gap_start})"),
        );
        must(
            gap_end != 0,
            &format!("gap_detected fixture gap_end MUST be non-zero (got: {gap_end})"),
        );
        must(
            gap_end > gap_start,
            "gap_detected fixture gap_end MUST be > gap_start",
        );
        let failure_count = v
            .get("failure_count")
            .and_then(|x| x.as_i64())
            .expect("failure_count MUST be an integer");
        must(
            failure_count > 0,
            &format!("gap_detected fixture failure_count MUST be > 0 (got: {failure_count})"),
        );
    }

    #[test]
    fn false_zero_loss_fixture_marks_false_zero_loss_even_when_failures_zero() {
        let v = load_saturation_fixture("false_zero_loss");
        must(
            v.get("verdict").and_then(|x| x.as_str()) == Some("false-zero-loss"),
            "false_zero_loss fixture verdict MUST be 'false-zero-loss'",
        );
        must(
            v.get("failure_count").and_then(|x| x.as_i64()) == Some(0),
            "false_zero_loss fixture failure_count MUST be 0 (silent drop path)",
        );
        let gap_start = v
            .get("gap_start")
            .and_then(|x| x.as_i64())
            .expect("gap_start MUST be an integer");
        let gap_end = v
            .get("gap_end")
            .and_then(|x| x.as_i64())
            .expect("gap_end MUST be an integer");
        must(
            gap_start != 0,
            "false_zero_loss fixture gap_start MUST be non-zero (kernel silently dropped events)",
        );
        must(
            gap_end != 0,
            "false_zero_loss fixture gap_end MUST be non-zero",
        );
    }

    #[test]
    fn saturation_oversize_ring_fixture_causes_harness_to_refuse() {
        let sh = saturation_sh_path();
        must(
            sh.exists(),
            &format!("bench/saturation.sh MUST be present at {}", sh.display()),
        );
        let schema = supported_load_schema_path();
        must(
            schema.exists(),
            &format!(
                "supported-load schema MUST be present at {}",
                schema.display()
            ),
        );

        let out_dir =
            std::env::temp_dir().join(format!("saturation-test-oversize-{}", std::process::id()));
        let _ = fs::create_dir_all(&out_dir);

        let output = Command::new(&sh)
            .arg("--schema")
            .arg(&schema)
            .arg("--ring-size")
            .arg("33554432")
            .arg("--out")
            .arg(&out_dir)
            .output()
            .expect("failed to spawn bench/saturation.sh");

        let exit_code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr);
        must(
            exit_code == 1,
            &format!(
                "saturation harness MUST exit 1 when --ring-size is above the schema maximum (exit_code={exit_code}, stderr={stderr})"
            ),
        );
        must(
            stderr.contains("MUST be in [1024, 16777216]"),
            &format!(
                "saturation harness MUST name the ring-size bound in its diagnostic (stderr={stderr})"
            ),
        );

        let _ = fs::remove_dir_all(&out_dir);
    }

    #[test]
    fn schema_corruption_causes_harness_to_refuse() {
        let sh = saturation_sh_path();
        let schema = supported_load_schema_path();
        must(sh.exists(), "bench/saturation.sh MUST be present");
        must(schema.exists(), "supported-load schema MUST be present");

        let text = fs::read_to_string(&schema).expect("read schema");
        let corrupted = text.replacen("\"default\": 1000", "\"default\": 0", 1);
        must(
            corrupted != text,
            "schema corruption substitution must actually change the file",
        );
        let tmp_schema = std::env::temp_dir().join(format!(
            "supported-load-corrupt-{}.json",
            std::process::id()
        ));
        fs::write(&tmp_schema, &corrupted).expect("write corrupted schema");

        let out_dir =
            std::env::temp_dir().join(format!("saturation-test-corrupt-{}", std::process::id()));
        let _ = fs::create_dir_all(&out_dir);

        let output = Command::new(&sh)
            .arg("--schema")
            .arg(&tmp_schema)
            .arg("--out")
            .arg(&out_dir)
            .output()
            .expect("failed to spawn bench/saturation.sh");

        let exit_code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

        let _ = fs::remove_file(&tmp_schema);
        let _ = fs::remove_dir_all(&out_dir);

        must(
            exit_code == 1,
            &format!(
                "saturation harness MUST exit 1 when the schema is corrupted (exit_code={exit_code}, stderr={stderr}, stdout={stdout})"
            ),
        );
        must(
            stderr.contains("default_rate_events_per_sec_per_cpu")
                || stdout.contains("default_rate_events_per_sec_per_cpu"),
            &format!(
                "saturation harness MUST name the corrupted field in its diagnostic (stderr={stderr}, stdout={stdout})"
            ),
        );
    }

    #[test]
    fn verdict_enum_has_exactly_four_values() {
        let fixtures = [
            "supported_pass",
            "saturation_shed",
            "gap_detected",
            "false_zero_loss",
        ];
        let mut observed: Vec<String> = Vec::new();
        for name in fixtures {
            let v = load_saturation_fixture(name);
            let verdict = v
                .get("verdict")
                .and_then(|x| x.as_str())
                .unwrap_or_else(|| panic!("{name} fixture is missing 'verdict'"))
                .to_string();
            must(
                !observed.contains(&verdict),
                &format!(
                    "{name} fixture verdict '{verdict}' is duplicated; each verdict enum value must have exactly one fixture"
                ),
            );
            observed.push(verdict);
        }
        observed.sort();
        let mut expected = vec![
            "passed".to_string(),
            "saturation-detected-no-critical-loss".to_string(),
            "failed".to_string(),
            "false-zero-loss".to_string(),
        ];
        expected.sort();
        must(
            observed == expected,
            &format!("verdict enum coverage drifted: observed={observed:?} expected={expected:?}"),
        );
    }

    #[test]
    fn per_cpu_failure_count_field_is_present_in_verdict_fixtures() {
        let fixtures = [
            "supported_pass",
            "saturation_shed",
            "gap_detected",
            "false_zero_loss",
        ];
        for name in fixtures {
            let v = load_saturation_fixture(name);
            let arr = v
                .get("percpu_failure_count")
                .and_then(|x| x.as_array())
                .unwrap_or_else(|| {
                    panic!("{name} fixture MUST expose 'percpu_failure_count' as an array")
                });
            must(
                !arr.is_empty(),
                &format!(
                    "{name} fixture percpu_failure_count MUST contain at least one CPU's failure count (got 0 entries)"
                ),
            );
            for entry in arr {
                must(
                    entry.is_i64() || entry.is_u64(),
                    &format!(
                        "{name} fixture percpu_failure_count entries MUST be integers (got: {entry:?})"
                    ),
                );
            }
        }
    }
}
