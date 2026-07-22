// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Simulated event source (ring buffer simulation for dev/testing).

use agent_core::{EventId, Kind, MonotonicNs, NormalizedEvent, PidTgid, RawEvent, Sequence};
use privacy::{DecodedDns, DecodedRecord, RedactionPolicy};
use storage_local::LocalStorage;
use tokio::sync::broadcast;

use super::{
    apply_redaction, normalize_bytes, synthetic_record, AgentError, SIMULATED_EVENT_COUNT,
};

// ---------------------------------------------------------------------------
// Simulated event source (this task only — the ring buffer is simulated)
// ---------------------------------------------------------------------------

/// Seed a bounded burst of simulated, redacted events into storage and publish
/// each to the live-event broadcaster.
pub fn seed_simulated_events(
    storage: &LocalStorage,
    broadcaster: &broadcast::Sender<String>,
    policy: &RedactionPolicy,
) -> Result<(), AgentError> {
    let base = normalize_bytes(&synthetic_record(0)).map_err(|e| {
        AgentError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("synthetic record failed to decode: {e}"),
        ))
    })?;
    for i in 0..SIMULATED_EVENT_COUNT {
        let ev = make_event(&base, i);
        let redacted = apply_redaction(&ev, policy);
        storage.insert_event(&redacted)?;
        let _ = broadcaster.send(serde_json::to_string(&redacted.to_json()).unwrap_or_default());
    }
    Ok(())
}

/// Build `count` simulated normalized events from a decoded base record.
pub fn simulated_events(base: &NormalizedEvent, count: usize) -> Vec<NormalizedEvent> {
    (0..count).map(|i| make_event(base, i)).collect()
}

/// Build a single simulated normalized event for index `i`, cycling through
/// event kinds and encoding a bounded [`DecodedRecord`] as the raw payload (the
/// shape [`privacy::decode_record`] consumes).
pub fn make_event(base: &NormalizedEvent, i: usize) -> NormalizedEvent {
    const KINDS: [Kind; 11] = [
        Kind::ProcessFork,
        Kind::ProcessExecResult,
        Kind::ProcessExit,
        Kind::FileOpen,
        Kind::FileCreate,
        Kind::FileUnlink,
        Kind::NetworkConnect,
        Kind::NetworkAccept,
        Kind::DnsPacket,
        Kind::SyscallEnter,
        Kind::SyscallExit,
    ];
    let mut e = base.clone();
    let kind = KINDS[i % KINDS.len()];
    e.kind = kind;
    e.sequence = Sequence(i as u64);
    e.monotonic_ns = MonotonicNs((i as u64).saturating_mul(1_000_000));
    // Unique kernel event id per simulated event (the cloned base record would
    // otherwise reuse a single event id for every event). Offset by one so no
    // event carries the degenerate all-zero id.
    let idx = (i as u64) + 1;
    let mut id_bytes = [0u8; 16];
    id_bytes[..8].copy_from_slice(&idx.to_le_bytes());
    id_bytes[8..].copy_from_slice(&(idx.wrapping_mul(0x9E37_79B1_85EB_CA87)).to_le_bytes());
    e.event_id = EventId(id_bytes);
    let pid = 1000 + (i as u64 % 8);
    e.namespaces.pid = Some(pid);
    e.pid_tgid = PidTgid((pid << 32) | pid);
    let record = decoded_for(kind, i);
    let payload = serde_json::to_vec(&record).unwrap_or_default();
    e.raw = RawEvent {
        payload: payload.into_boxed_slice(),
    };
    e
}

fn decoded_for(kind: Kind, i: usize) -> DecodedRecord {
    const SYSCALLS: [&str; 5] = ["read", "write", "openat", "close", "execve"];
    let mut r = DecodedRecord::default();
    match kind {
        Kind::ProcessFork | Kind::ProcessExecResult | Kind::ProcessExit => {
            let path = format!("/usr/bin/proc{}", i % 4);
            r.argv = vec![path.clone(), format!("--arg={i}")];
            r.path = path;
        }
        Kind::FileOpen
        | Kind::FileCreate
        | Kind::FileUnlink
        | Kind::FileRename
        | Kind::FileTruncate => {
            let path = format!("/var/data/file{}.txt", i % 5);
            r.arguments = vec![path.clone()];
            r.path = path;
        }
        Kind::NetworkConnect | Kind::NetworkAccept | Kind::NetworkState => {
            r.path = format!("10.0.0.{}:{}", (i % 5) + 1, 4000 + (i % 100));
            r.arguments = vec!["inet".to_string(), "established".to_string()];
        }
        Kind::DnsPacket => {
            r.dns = Some(DecodedDns {
                qname: format!("host{}.example.com", i % 3),
                qtype: 1,
                qclass: 1,
                an_count: 1,
                rdata: vec![format!("10.0.0.{}", (i % 5) + 1)],
            });
        }
        Kind::SyscallEnter | Kind::SyscallExit => {
            r.arguments = vec![SYSCALLS[i % SYSCALLS.len()].to_string()];
        }
        _ => {}
    }
    r.message = format!("simulated {kind:?} event {i}");
    r
}
