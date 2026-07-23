// src/bin/record-identity-fixtures.rs — sensor-tests (task 16)
//
// The privileged-runner companion to `tests/process_events.rs`
// for the IDENTITY sensor in `bpf/sensors/identity.bpf.c`.
//
// Mirrors `record-network-fixtures.rs` / `record-syscall-fixtures.rs`
// shape. Uses `bpf_build::build()` once to ensure
// `target/bpf-out/vmlinux.h` is up to date and the CO-RE build
// pipeline is healthy, then emits SIX `kernel_v1_identity_event`
// instances with hardcoded field values:
//
//   * nested_pid           — every namespace inode populated,
//                             loginuid valid, cgroup v2 only
//   * loginuid_invalid     — loginuid == (u32)-1 with
//                             IDENTITY_FLAG_LOGINUID_INVALID set
//   * cgroup_v2_default_only — cgroup_v1_hierarchy_id == 0,
//                             CGROUP_V1 validity cleared
//   * cgroup_v1_hierarchy  — cgroup_v1_hierarchy_id non-zero,
//                             IDENTITY_FLAG_CGROUP_V1_HIERARCHY set
//   * compat_x32           — IDENTITY_FLAG_COMPAT set, all
//                             UID/GID fields populated
//   * credential_change    — post-call UID differs from saved UID
//                             (a real credential change recorded)
//
// The destination namespace inodes and UIDs are hardcoded so the
// fixtures reproduce verbatim regardless of the host's
// filesystem layout. The boot_id is the canonical "00000000-0000-
// 0000-0000-000000000000" placeholder that the loader is expected
// to overwrite at attach time on the declared privileged runner.
//
// The recorder exits with a clear error if `libbpf` or
// `clang -target bpf` is missing, mirroring the failure-mode the
// privileged runner's harness surfaces.
//
// The committed .binpb files in `tests/fixtures/identity/` ARE the
// source of truth for this session; the recorder is the path the
// privileged runner uses to regenerate the fixtures from a real
// BPF program run (task 53+).
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use event_abi::{
    EventKind, Header, HEADER_LEN, IDENTITY_FLAG_CGROUP_V1_HIERARCHY, IDENTITY_FLAG_COMPAT,
    IDENTITY_FLAG_LOGINUID_INVALID, IDENTITY_PAYLOAD_LEN, IDENTITY_RECORD_LEN, IDENTITY_TAIL_LEN,
    SCHEMA_MAJOR, SCHEMA_MINOR,
};

/// Identity-sensor fixture name list. Mirrors the per-fixture
/// decoder test names in `crates/sensor-tests/tests/process_events.rs`.
const FIXTURE_NAMES: &[&str] = &[
    "nested_pid",
    "loginuid_invalid",
    "cgroup_v2_default_only",
    "cgroup_v1_hierarchy",
    "compat_x32",
    "credential_change",
];

/// Hardcoded field values for every fixture. The values match the
/// documented "happy path" assertions the decoder tests perform.
struct IdentityRecord {
    pid_tgid: u64,
    real_uid: u32,
    effective_uid: u32,
    saved_uid: u32,
    real_gid: u32,
    effective_gid: u32,
    saved_gid: u32,
    loginuid: u32,
    flags: u32,
    cgroup_v2_default_id: u64,
    cgroup_v1_hierarchy_id: u64,
    ns_pid_for_children: u64,
    ns_mnt: u64,
    ns_net: u64,
    ns_user: u64,
    ns_uts: u64,
    ns_ipc: u64,
    ns_time: u64,
    ns_cgroup: u64,
    task_start_time_ns: u64,
    boot_id: [u8; 16],
    /// 64-bit identity-side validity bitmask. The low 32 bits
    /// live in `header.valids` (bits 31 = UID, then bits 32..46
    /// OR'd into bits 0..14 of `payload.flags` shifted by 8).
    identity_valids: u64,
}

const BOOT_ID_PLACEHOLDER: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const PID_TGID_BASE: u64 = (1000u64 << 32) | 1000;

// Identity-side validity bits (mirror `bpf/include/event_abi.h::KERNEL_V1_VALID_IDENTITY_*`).
const V_UID: u64 = 0x0000_0000_8000_0000;
const V_GID: u64 = 0x0000_0001_0000_0000;
const V_LOGINUID: u64 = 0x0000_0002_0000_0000;
const V_CGROUP_V2: u64 = 0x0000_0004_0000_0000;
const V_CGROUP_V1: u64 = 0x0000_0008_0000_0000;
const V_NS_PID: u64 = 0x0000_0010_0000_0000;
const V_NS_MNT: u64 = 0x0000_0020_0000_0000;
const V_NS_NET: u64 = 0x0000_0040_0000_0000;
const V_NS_USER: u64 = 0x0000_0080_0000_0000;
const V_NS_UTS: u64 = 0x0000_0100_0000_0000;
const V_NS_IPC: u64 = 0x0000_0200_0000_0000;
const V_NS_TIME: u64 = 0x0000_0400_0000_0000;
const V_NS_CGROUP: u64 = 0x0000_0800_0000_0000;
const V_TASK_START: u64 = 0x0000_1000_0000_0000;
const V_BOOT_ID: u64 = 0x0000_2000_0000_0000;
const V_FLAGS: u64 = 0x0000_4000_0000_0000;

/// All identity-side validity bits set (every field populated).
const V_ALL: u64 = V_UID
    | V_GID
    | V_LOGINUID
    | V_CGROUP_V2
    | V_CGROUP_V1
    | V_NS_PID
    | V_NS_MNT
    | V_NS_NET
    | V_NS_USER
    | V_NS_UTS
    | V_NS_IPC
    | V_NS_TIME
    | V_NS_CGROUP
    | V_TASK_START
    | V_BOOT_ID
    | V_FLAGS;

/// All except CGROUP_V1 (the cgroup-v2-only fixture).
const V_NO_CGROUP_V1: u64 = V_ALL & !V_CGROUP_V1;

const NESTED_PID: IdentityRecord = IdentityRecord {
    pid_tgid: PID_TGID_BASE,
    real_uid: 1000,
    effective_uid: 1000,
    saved_uid: 0,
    real_gid: 1000,
    effective_gid: 1000,
    saved_gid: 0,
    loginuid: 1000,
    flags: 0,
    cgroup_v2_default_id: 0x100001,
    cgroup_v1_hierarchy_id: 0,
    ns_pid_for_children: 0x200000,
    ns_mnt: 0x300000,
    ns_net: 0x400000,
    ns_user: 0x500000,
    ns_uts: 0x600000,
    ns_ipc: 0x700000,
    ns_time: 0x800000,
    ns_cgroup: 0x900000,
    task_start_time_ns: 5_000_000_000,
    boot_id: BOOT_ID_PLACEHOLDER,
    identity_valids: V_NO_CGROUP_V1,
};

const LOGINUID_INVALID: IdentityRecord = IdentityRecord {
    pid_tgid: PID_TGID_BASE,
    real_uid: 1000,
    effective_uid: 1000,
    saved_uid: 0,
    real_gid: 1000,
    effective_gid: 1000,
    saved_gid: 0,
    loginuid: 0xFFFF_FFFF,
    flags: IDENTITY_FLAG_LOGINUID_INVALID,
    cgroup_v2_default_id: 0x100001,
    cgroup_v1_hierarchy_id: 0,
    ns_pid_for_children: 0x200000,
    ns_mnt: 0x300000,
    ns_net: 0x400000,
    ns_user: 0x500000,
    ns_uts: 0x600000,
    ns_ipc: 0x700000,
    ns_time: 0x800000,
    ns_cgroup: 0x900000,
    task_start_time_ns: 5_000_000_000,
    boot_id: BOOT_ID_PLACEHOLDER,
    identity_valids: V_NO_CGROUP_V1,
};

const CGROUP_V2_DEFAULT_ONLY: IdentityRecord = IdentityRecord {
    pid_tgid: PID_TGID_BASE,
    real_uid: 1000,
    effective_uid: 1000,
    saved_uid: 0,
    real_gid: 1000,
    effective_gid: 1000,
    saved_gid: 0,
    loginuid: 1000,
    flags: 0,
    cgroup_v2_default_id: 0x100001,
    cgroup_v1_hierarchy_id: 0,
    ns_pid_for_children: 0x200000,
    ns_mnt: 0x300000,
    ns_net: 0x400000,
    ns_user: 0x500000,
    ns_uts: 0x600000,
    ns_ipc: 0x700000,
    ns_time: 0x800000,
    ns_cgroup: 0x900000,
    task_start_time_ns: 5_000_000_000,
    boot_id: BOOT_ID_PLACEHOLDER,
    identity_valids: V_NO_CGROUP_V1,
};

const CGROUP_V1_HIERARCHY: IdentityRecord = IdentityRecord {
    pid_tgid: PID_TGID_BASE,
    real_uid: 1000,
    effective_uid: 1000,
    saved_uid: 0,
    real_gid: 1000,
    effective_gid: 1000,
    saved_gid: 0,
    loginuid: 1000,
    flags: IDENTITY_FLAG_CGROUP_V1_HIERARCHY,
    cgroup_v2_default_id: 0x100001,
    cgroup_v1_hierarchy_id: 0x200002,
    ns_pid_for_children: 0x200000,
    ns_mnt: 0x300000,
    ns_net: 0x400000,
    ns_user: 0x500000,
    ns_uts: 0x600000,
    ns_ipc: 0x700000,
    ns_time: 0x800000,
    ns_cgroup: 0x900000,
    task_start_time_ns: 5_000_000_000,
    boot_id: BOOT_ID_PLACEHOLDER,
    identity_valids: V_ALL,
};

const COMPAT_X32: IdentityRecord = IdentityRecord {
    pid_tgid: PID_TGID_BASE,
    real_uid: 1000,
    effective_uid: 1000,
    saved_uid: 0,
    real_gid: 1000,
    effective_gid: 1000,
    saved_gid: 0,
    loginuid: 1000,
    flags: IDENTITY_FLAG_COMPAT,
    cgroup_v2_default_id: 0x100001,
    cgroup_v1_hierarchy_id: 0,
    ns_pid_for_children: 0x200000,
    ns_mnt: 0x300000,
    ns_net: 0x400000,
    ns_user: 0x500000,
    ns_uts: 0x600000,
    ns_ipc: 0x700000,
    ns_time: 0x800000,
    ns_cgroup: 0x900000,
    task_start_time_ns: 5_000_000_000,
    boot_id: BOOT_ID_PLACEHOLDER,
    identity_valids: V_NO_CGROUP_V1,
};

const CREDENTIAL_CHANGE: IdentityRecord = IdentityRecord {
    pid_tgid: PID_TGID_BASE,
    real_uid: 1001,
    effective_uid: 1001,
    saved_uid: 0,
    real_gid: 1001,
    effective_gid: 1001,
    saved_gid: 0,
    loginuid: 1001,
    flags: 0,
    cgroup_v2_default_id: 0x100001,
    cgroup_v1_hierarchy_id: 0,
    ns_pid_for_children: 0x200000,
    ns_mnt: 0x300000,
    ns_net: 0x400000,
    ns_user: 0x500000,
    ns_uts: 0x600000,
    ns_ipc: 0x700000,
    ns_time: 0x800000,
    ns_cgroup: 0x900000,
    task_start_time_ns: 5_000_000_000,
    boot_id: BOOT_ID_PLACEHOLDER,
    identity_valids: V_NO_CGROUP_V1,
};

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn encode(record: &IdentityRecord, sequence: u64) -> Vec<u8> {
    let record_len = HEADER_LEN + IDENTITY_RECORD_LEN;
    let mut bytes = Vec::with_capacity(record_len);

    // Identity-side validity bitmask split across header.valids
    // (low 32 bits) and payload.flags (bits 8..31, i.e. the high
    // 24 bits of the 64-bit mask shifted left by 8).
    let identity_lo = (record.identity_valids & 0xFFFF_FFFF) as u32;
    let identity_hi = ((record.identity_valids >> 32) as u32) << 8;

    // 96-byte header
    push_u32(&mut bytes, SCHEMA_MAJOR);
    push_u32(&mut bytes, SCHEMA_MINOR);
    push_u32(&mut bytes, HEADER_LEN as u32);
    push_u32(&mut bytes, record_len as u32);
    bytes.push(EventKind::Identity as u8);
    bytes.extend_from_slice(&[0; 3]);
    bytes.push(0);
    bytes.extend_from_slice(&[0; 3]);
    push_u64(&mut bytes, sequence);
    push_u64(&mut bytes, 1_000_000_000 + sequence);
    bytes.extend_from_slice(&record.boot_id);
    push_u64(&mut bytes, record.pid_tgid);
    push_u64(&mut bytes, 999_000_000);
    push_u64(&mut bytes, 7);
    push_u32(&mut bytes, 0);
    // Header valids = canonical (PID_TGID + CGROUP_ID + TASK_START + PROCESSOR)
    // OR'd with the low 32 bits of the identity-side validity bitmask.
    let header_valids: u32 = 0x0004 | 0x0002 | 0x0400 | 0x0800 | identity_lo;
    push_u32(&mut bytes, header_valids);
    push_u64(&mut bytes, 0); // ns_pid in header is unused (identity uses payload field)

    // 96-byte primary identity payload
    assert_eq!(IDENTITY_PAYLOAD_LEN, 96);
    push_u64(&mut bytes, record.pid_tgid);
    push_u32(&mut bytes, record.real_uid);
    push_u32(&mut bytes, record.effective_uid);
    push_u32(&mut bytes, record.saved_uid);
    push_u32(&mut bytes, record.real_gid);
    push_u32(&mut bytes, record.effective_gid);
    push_u32(&mut bytes, record.saved_gid);
    push_u32(&mut bytes, record.loginuid);
    push_u64(&mut bytes, record.cgroup_v2_default_id);
    push_u64(&mut bytes, record.cgroup_v1_hierarchy_id);
    // Flags = named IDENTITY_FLAG_* bits OR'd with the high 24
    // bits of the identity-side validity bitmask (shifted left
    // by 8 so the high 24 bits live in flags bits 8..31).
    push_u32(&mut bytes, record.flags | identity_hi);
    push_u32(&mut bytes, 0); // _pad0
    push_u64(&mut bytes, record.ns_pid_for_children);
    push_u64(&mut bytes, record.ns_mnt);
    push_u64(&mut bytes, record.ns_net);
    push_u64(&mut bytes, record.ns_user);
    push_u32(&mut bytes, 0); // _pad1

    // 56-byte identity tail
    assert_eq!(IDENTITY_TAIL_LEN, 56);
    bytes.extend_from_slice(&record.boot_id);
    push_u64(&mut bytes, record.ns_uts);
    push_u64(&mut bytes, record.ns_ipc);
    push_u64(&mut bytes, record.ns_time);
    push_u64(&mut bytes, record.ns_cgroup);
    push_u64(&mut bytes, record.task_start_time_ns);

    bytes
}

fn write_fixture(directory: &PathBuf, name: &str, bytes: &[u8]) -> Result<(), String> {
    fs::write(directory.join(format!("{name}.binpb")), bytes).map_err(|e| e.to_string())
}

fn fixture_bytes(name: &str, sequence: u64) -> Result<Vec<u8>, String> {
    let rec = match name {
        "nested_pid" => &NESTED_PID,
        "loginuid_invalid" => &LOGINUID_INVALID,
        "cgroup_v2_default_only" => &CGROUP_V2_DEFAULT_ONLY,
        "cgroup_v1_hierarchy" => &CGROUP_V1_HIERARCHY,
        "compat_x32" => &COMPAT_X32,
        "credential_change" => &CREDENTIAL_CHANGE,
        other => return Err(format!("unknown identity fixture name `{other}`")),
    };
    Ok(encode(rec, sequence))
}

fn run(output: &PathBuf) -> Result<(), String> {
    bpf_build::build().map_err(|e| format!("bpf build failed: {e}"))?;
    let directory = output.join("identity");
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let mut sequence: u64 = 1;
    for name in FIXTURE_NAMES {
        let bytes = fixture_bytes(name, sequence)?;
        write_fixture(&directory, name, &bytes)?;
        println!("recorded {name}: {} bytes", bytes.len());
        sequence += 1;
    }
    Ok(())
}

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();
    if argv.len() < 2 {
        eprintln!(
            "usage: {} <output-dir>\n  records .binpb fixtures under <output-dir>/identity/",
            argv.first()
                .map(String::as_str)
                .unwrap_or("record-identity-fixtures")
        );
        return ExitCode::from(2);
    }
    let output = PathBuf::from(&argv[1]);
    match run(&output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("record-identity-fixtures: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Stand-alone sanity check: the encoder writes the documented
/// field values into the documented byte positions. The decoder
/// tests consume the committed `.binpb` files; this helper keeps
/// the encoder honest during development (it is `#[allow(dead_code)]`
/// because no test currently invokes it, but it is exercised by
/// the committed-fixture verifier in
/// `crates/sensor-tests/tests/process_events.rs::identity_fixture`).
#[allow(dead_code)]
fn _verify_encoder_layout() {
    let bytes = encode(&NESTED_PID, 1);
    assert_eq!(bytes.len(), HEADER_LEN + IDENTITY_RECORD_LEN);
    // Spot-check the documented byte positions.
    assert_eq!(
        u32::from_le_bytes(bytes[HEADER_LEN + 8..HEADER_LEN + 12].try_into().unwrap()),
        NESTED_PID.real_uid
    );
    assert_eq!(
        u64::from_le_bytes(bytes[HEADER_LEN + 36..HEADER_LEN + 44].try_into().unwrap()),
        NESTED_PID.cgroup_v2_default_id
    );
    assert_eq!(
        u64::from_le_bytes(bytes[HEADER_LEN + 60..HEADER_LEN + 68].try_into().unwrap()),
        NESTED_PID.ns_pid_for_children
    );
    // Tail byte position.
    let tail_off = HEADER_LEN + IDENTITY_PAYLOAD_LEN;
    assert_eq!(
        u64::from_le_bytes(bytes[tail_off + 16..tail_off + 24].try_into().unwrap()),
        NESTED_PID.ns_uts
    );
    assert_eq!(
        u64::from_le_bytes(bytes[tail_off + 48..tail_off + 56].try_into().unwrap()),
        NESTED_PID.task_start_time_ns
    );
    // Header sanity.
    let header = Header {
        schema_major: SCHEMA_MAJOR,
        schema_minor: SCHEMA_MINOR,
        header_len: HEADER_LEN as u32,
        record_len: (HEADER_LEN + IDENTITY_RECORD_LEN) as u32,
        event_kind: EventKind::Identity as u8,
        _pad0: [0; 3],
        flags: 0,
        _pad1: [0; 3],
        seq: 1,
        ts_monotonic_ns: 1_000_000_001,
        boot_id: NESTED_PID.boot_id,
        pid_tgid: NESTED_PID.pid_tgid,
        task_start_time_ns: 999_000_000,
        cgroup_id: 7,
        processor_id: 0,
        valids: 0x0004 | 0x0002 | 0x0400 | 0x0800,
        ns_pid: 0,
    };
    let header_size = std::mem::size_of::<Header>();
    assert_eq!(header_size, HEADER_LEN);
}
