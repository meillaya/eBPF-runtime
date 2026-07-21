// SPDX-License-Identifier: Apache-2.0 OR MIT
#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::process::ExitCode;

use event_abi::{
    EventKind, HEADER_LEN, SCHEMA_MAJOR, SCHEMA_MINOR, SYSCALL_FLAG_FAILED,
    SYSCALL_FLAG_INTERRUPTED, SYSCALL_FLAG_IS_EXEC, SYSCALL_FLAG_NO_RETURN, SYSCALL_PAYLOAD_LEN,
};

const VALID_PID_TGID: u32 = 0x0004;
const VALID_CGROUP_ID: u32 = 0x0002;
const VALID_PROCESSOR: u32 = 0x0800;
const VALID_SYSCALL_NR: u32 = 0x4000_0000;
const VALID_SYSCALL_LATENCY: u32 = 0x8000_0000;
const PID_TGID: u64 = (4242u64 << 32) | 4242;

#[derive(Clone, Copy)]
struct FixtureRecord {
    kind: EventKind,
    nr: u64,
    flags: u64,
    latency_ns: u64,
    exit_code: i64,
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn encode(record: FixtureRecord, sequence: u64) -> Vec<u8> {
    let record_len = HEADER_LEN + SYSCALL_PAYLOAD_LEN;
    let mut bytes = Vec::with_capacity(record_len);
    push_u32(&mut bytes, SCHEMA_MAJOR);
    push_u32(&mut bytes, SCHEMA_MINOR);
    push_u32(&mut bytes, HEADER_LEN as u32);
    push_u32(&mut bytes, record_len as u32);
    bytes.push(record.kind as u8);
    bytes.extend_from_slice(&[0; 3]);
    bytes.push(0);
    bytes.extend_from_slice(&[0; 3]);
    push_u64(&mut bytes, sequence);
    push_u64(&mut bytes, 1_000_000_000 + sequence);
    bytes.extend_from_slice(&[0; 16]);
    push_u64(&mut bytes, PID_TGID);
    push_u64(&mut bytes, 999_000_000);
    push_u64(&mut bytes, 7);
    push_u32(&mut bytes, 0);
    let mut valids = VALID_PID_TGID | VALID_CGROUP_ID | VALID_PROCESSOR | VALID_SYSCALL_NR;
    if record.latency_ns > 0 {
        valids |= VALID_SYSCALL_LATENCY;
    }
    push_u32(&mut bytes, valids);
    push_u64(&mut bytes, 0);
    push_u64(&mut bytes, record.nr);
    push_u64(&mut bytes, record.flags);
    push_u64(&mut bytes, record.latency_ns);
    push_u64(&mut bytes, record.exit_code as u64);
    bytes
}

fn pair(nr: u64, flags: u64, latency_ns: u64, exit_code: i64) -> Vec<u8> {
    let enter = FixtureRecord {
        kind: EventKind::SyscallEnter,
        nr,
        flags: flags & SYSCALL_FLAG_IS_EXEC,
        latency_ns: 0,
        exit_code: 0,
    };
    let exit = FixtureRecord {
        kind: EventKind::SyscallExit,
        nr,
        flags,
        latency_ns,
        exit_code,
    };
    let mut bytes = encode(enter, 1);
    bytes.extend_from_slice(&encode(exit, 2));
    bytes
}

fn write_fixture(directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    fs::write(directory.join(format!("{name}.binpb")), bytes)
}

fn run(output: &Path) -> Result<(), String> {
    bpf_build::build().map_err(|error| format!("bpf build failed: {error}"))?;
    let directory = output.join("syscall");
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let fixtures = [
        ("nanosleep_short", pair(35, 0, 1_000_000, 0)),
        ("nanosleep_blocking", pair(35, 0, 250_000_000, 0)),
        ("open_short", pair(2, 0, 5_000, 3)),
        ("open_failed", pair(2, SYSCALL_FLAG_FAILED, 7_500, -2)),
        (
            "execve_success",
            pair(59, SYSCALL_FLAG_IS_EXEC, 10_000_000, 0),
        ),
        (
            "exit_group",
            encode(
                FixtureRecord {
                    kind: EventKind::SyscallExit,
                    nr: 231,
                    flags: SYSCALL_FLAG_NO_RETURN,
                    latency_ns: 0,
                    exit_code: 0,
                },
                1,
            ),
        ),
        (
            "interrupted_eintr",
            pair(
                35,
                SYSCALL_FLAG_FAILED | SYSCALL_FLAG_INTERRUPTED,
                25_000,
                -4,
            ),
        ),
        (
            "orphaned_entry",
            encode(
                FixtureRecord {
                    kind: EventKind::SyscallEnter,
                    nr: 35,
                    flags: 0,
                    latency_ns: 0,
                    exit_code: 0,
                },
                1,
            ),
        ),
    ];
    for (name, bytes) in fixtures {
        write_fixture(&directory, name, &bytes).map_err(|error| error.to_string())?;
        println!("recorded {name}: {} bytes", bytes.len());
    }
    Ok(())
}

fn main() -> ExitCode {
    let Some(output) = env::args_os().nth(1) else {
        eprintln!("usage: record-syscall-fixtures <output-dir>");
        return ExitCode::from(2);
    };
    match run(Path::new(&output)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("record-syscall-fixtures: {error}");
            ExitCode::FAILURE
        }
    }
}
