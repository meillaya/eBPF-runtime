// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::channel::EventPriority;
use crate::model::*;
use event_abi::{DecodeError, Event, Valid};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}
fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset.checked_add(8)?)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}
fn has(bits: u64, flag: u64) -> bool {
    bits & flag == flag
}
fn require_payload(event: &Event<'_>, need: usize) -> Result<(), DecodeError> {
    if event.payload.len() < need {
        Err(DecodeError::BufferUnderflow {
            record_len: event.header.record_len,
            header_len: event.header.header_len,
        })
    } else {
        Ok(())
    }
}

pub fn from_raw(raw: &Event<'_>) -> Result<NormalizedEvent, DecodeError> {
    let kind = Kind::from_wire(raw.header.event_kind)?;
    let required = match kind {
        Kind::ProcessFork => 16,
        Kind::ProcessExecResult => 268,
        Kind::ProcessExit => 8,
        Kind::FileOpen
        | Kind::FileCreate
        | Kind::FileUnlink
        | Kind::FileRename
        | Kind::FileTruncate => 552,
        Kind::NetworkConnect | Kind::NetworkAccept | Kind::NetworkState => 80,
        Kind::DnsPacket => 320,
        Kind::SyscallEnter | Kind::SyscallExit => 32,
        Kind::Identity => 152,
        Kind::LsmDenyOwn => 0,
    };
    require_payload(raw, required)?;
    let header_valids = u64::from(raw.header.valids);
    let mut namespaces = NamespaceBundle {
        pid: has(header_valids, Valid::NsPid as u64).then_some(raw.header.ns_pid),
        ..NamespaceBundle::default()
    };
    let mut identity = Identity::default();
    let payload = match kind {
        Kind::ProcessFork | Kind::ProcessExecResult | Kind::ProcessExit => {
            PerSensorPayload::Process {
                flags: raw.header.flags,
            }
        }
        Kind::FileOpen
        | Kind::FileCreate
        | Kind::FileUnlink
        | Kind::FileRename
        | Kind::FileTruncate
        | Kind::LsmDenyOwn => PerSensorPayload::File {
            flags: raw.header.flags,
        },
        Kind::NetworkConnect | Kind::NetworkAccept | Kind::NetworkState => {
            PerSensorPayload::Network {
                flags: raw.header.flags,
            }
        }
        Kind::DnsPacket => PerSensorPayload::Dns {
            truncated: raw.is_truncated(),
        },
        Kind::SyscallEnter | Kind::SyscallExit => PerSensorPayload::Syscall {
            flags: u64_at(raw.payload, 8).unwrap_or_default(),
        },
        Kind::Identity => {
            let flags = u32_at(raw.payload, 52).unwrap_or_default();
            let identity_valids = header_valids | (u64::from(flags >> 8) << 32);
            let uid = |offset: usize| {
                has(identity_valids, event_abi::identity_valid::UID)
                    .then(|| u32_at(raw.payload, offset))
                    .flatten()
            };
            let gid = |offset: usize| {
                has(identity_valids, event_abi::identity_valid::GID)
                    .then(|| u32_at(raw.payload, offset))
                    .flatten()
            };
            identity = Identity {
                real_uid: uid(8),
                effective_uid: uid(12),
                saved_uid: uid(16),
                real_gid: gid(20),
                effective_gid: gid(24),
                saved_gid: gid(28),
                loginuid: has(identity_valids, event_abi::identity_valid::LOGINUID)
                    .then(|| u32_at(raw.payload, 32))
                    .flatten(),
            };
            namespaces = NamespaceBundle {
                pid: has(identity_valids, event_abi::identity_valid::NS_PID)
                    .then(|| u64_at(raw.payload, 60))
                    .flatten(),
                mnt: has(identity_valids, event_abi::identity_valid::NS_MNT)
                    .then(|| u64_at(raw.payload, 68))
                    .flatten(),
                net: has(identity_valids, event_abi::identity_valid::NS_NET)
                    .then(|| u64_at(raw.payload, 76))
                    .flatten(),
                user: has(identity_valids, event_abi::identity_valid::NS_USER)
                    .then(|| u64_at(raw.payload, 84))
                    .flatten(),
                uts: has(identity_valids, event_abi::identity_valid::NS_UTS)
                    .then(|| u64_at(raw.payload, 112))
                    .flatten(),
                ipc: has(identity_valids, event_abi::identity_valid::NS_IPC)
                    .then(|| u64_at(raw.payload, 120))
                    .flatten(),
                time: has(identity_valids, event_abi::identity_valid::NS_TIME)
                    .then(|| u64_at(raw.payload, 128))
                    .flatten(),
                cgroup: has(identity_valids, event_abi::identity_valid::NS_CGROUP)
                    .then(|| u64_at(raw.payload, 136))
                    .flatten(),
            };
            PerSensorPayload::Identity { flags }
        }
    };
    let event_id = event_id(
        raw.header.boot_id,
        raw.header.seq,
        raw.header.ts_monotonic_ns,
        raw.header.event_kind,
    );
    Ok(NormalizedEvent {
        header: raw.header,
        raw: RawEvent {
            payload: raw.payload.into(),
        },
        kind,
        event_id,
        sequence: Sequence(raw.header.seq),
        monotonic_ns: MonotonicNs(raw.header.ts_monotonic_ns),
        wall_clock: WallClock(wall_clock(raw.header.ts_monotonic_ns)),
        pid_tgid: PidTgid(raw.header.pid_tgid),
        task_start_ns: TaskStartNs(raw.header.task_start_time_ns),
        cgroup_id: CgroupId(raw.header.cgroup_id),
        boot_id: BootId(raw.header.boot_id),
        namespaces,
        identity,
        payload,
        priority: EventPriority::Data,
    })
}

pub fn normalize_bytes(bytes: &[u8]) -> Result<NormalizedEvent, DecodeError> {
    event_abi::parse(bytes).and_then(|raw| from_raw(&raw))
}
fn event_id(boot: [u8; 16], seq: u64, mono: u64, kind: u8) -> EventId {
    let mut left = u64::from_le_bytes(boot[..8].try_into().unwrap_or_default()) ^ seq;
    let mut right = u64::from_le_bytes(boot[8..].try_into().unwrap_or_default())
        ^ mono.rotate_left(17)
        ^ u64::from(kind);
    left = left.wrapping_mul(0x9E37_79B1_85EB_CA87);
    right = right.wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
    let mut id = [0; 16];
    id[..8].copy_from_slice(&left.to_le_bytes());
    id[8..].copy_from_slice(&right.to_le_bytes());
    EventId(id)
}

fn wall_clock(mono_ns: u64) -> String {
    static ANCHOR: OnceLock<(u64, u64)> = OnceLock::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let now_ns = u64::try_from(now).unwrap_or(u64::MAX);
    let (anchor_mono, anchor_wall) = *ANCHOR.get_or_init(|| (mono_ns, now_ns));
    let unix_ns = if mono_ns >= anchor_mono {
        anchor_wall.saturating_add(mono_ns - anchor_mono)
    } else {
        anchor_wall.saturating_sub(anchor_mono - mono_ns)
    };
    format_rfc3339(unix_ns)
}
fn format_rfc3339(unix_ns: u64) -> String {
    let seconds = unix_ns / 1_000_000_000;
    let nanos = unix_ns % 1_000_000_000;
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    let day_seconds = seconds % 86_400;
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year0 = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = year0 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{nanos:09}Z",
        day_seconds / 3_600,
        day_seconds / 60 % 60,
        day_seconds % 60
    )
}
