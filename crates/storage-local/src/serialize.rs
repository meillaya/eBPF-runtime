// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Serialization helpers for RedactedEvent <-> BLOB round-trip.

use agent_core::{
    BootId, CgroupId, EventId, EventPriority, Identity, Kind, MonotonicNs, NamespaceBundle,
    PidTgid, Sequence, TaskStartNs, WallClock,
};
use privacy::{RedactedEvent, TruncationFlags};

/// Serialize a RedactedEvent to JSON bytes for BLOB storage.
pub fn serialize_event(event: &RedactedEvent) -> Result<Vec<u8>, serde_json::Error> {
    event.to_json_bytes()
}

/// Deserialize a RedactedEvent from stored JSON bytes.
pub fn deserialize_event(bytes: &[u8]) -> Result<RedactedEvent, String> {
    let json: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    redacted_event_from_json(&json)
}

/// Reconstruct a RedactedEvent from a JSON value (as produced by
/// `RedactedEvent::to_json()`). Public for CLI use.
pub fn redacted_event_from_json_value(json: &serde_json::Value) -> Result<RedactedEvent, String> {
    redacted_event_from_json(json)
}

/// Reconstruct a RedactedEvent from its JSON representation (as produced
/// by `RedactedEvent::to_json()`).
fn redacted_event_from_json(json: &serde_json::Value) -> Result<RedactedEvent, String> {
    let kind = parse_kind(json.get("kind").and_then(|v| v.as_str()).unwrap_or(""))?;
    let event_id = parse_event_id(json.get("event_id").and_then(|v| v.as_str()).unwrap_or(""))?;
    let sequence = Sequence(json.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0));
    let monotonic_ns = MonotonicNs(
        json.get("monotonic_ns")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    );
    let wall_clock = WallClock(
        json.get("wall_clock")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    );
    let pid_tgid = PidTgid(json.get("pid_tgid").and_then(|v| v.as_u64()).unwrap_or(0));
    let task_start_ns = TaskStartNs(
        json.get("task_start_ns")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    );
    let cgroup_id = CgroupId(json.get("cgroup_id").and_then(|v| v.as_u64()).unwrap_or(0));
    let boot_id = parse_boot_id(json.get("boot_id").and_then(|v| v.as_str()).unwrap_or(""))?;
    let namespaces = parse_namespaces(json.get("namespaces"));
    let identity = parse_identity(json.get("identity"));
    let priority = parse_priority(json.get("priority").and_then(|v| v.as_str()).unwrap_or(""));
    let attribution_scope = json
        .get("attribution_scope")
        .and_then(|v| v.as_str())
        .map(String::from);
    let argv_bytes = json
        .get("argv")
        .and_then(|v| v.as_str())
        .map(|s| s.as_bytes().to_vec());
    let env = json
        .get("env")
        .and_then(|v| v.as_str())
        .map(|s| s.as_bytes().to_vec());
    let path = json.get("path").and_then(|v| v.as_str()).map(String::from);
    let arguments = json
        .get("arguments")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let dns_qname = json
        .get("dns_qname")
        .and_then(|v| v.as_str())
        .map(String::from);
    let dns_qtype = json
        .get("dns_qtype")
        .and_then(|v| v.as_u64())
        .map(|v| v as u16);
    let dns_qclass = json
        .get("dns_qclass")
        .and_then(|v| v.as_u64())
        .map(|v| v as u16);
    let dns_an_count = json
        .get("dns_an_count")
        .and_then(|v| v.as_u64())
        .map(|v| v as u16);
    let dns_rdata = json
        .get("dns_rdata")
        .and_then(|v| v.as_str())
        .map(|s| s.as_bytes().to_vec());
    let message = json
        .get("message")
        .and_then(|v| v.as_str())
        .map(String::from);
    let truncation_flags = parse_truncation_flags(json.get("truncation_flags"));

    Ok(RedactedEvent {
        kind,
        event_id,
        sequence,
        monotonic_ns,
        wall_clock,
        pid_tgid,
        task_start_ns,
        cgroup_id,
        boot_id,
        namespaces,
        identity,
        priority,
        attribution_scope,
        argv_bytes,
        env,
        path,
        arguments,
        dns_qname,
        dns_qtype,
        dns_qclass,
        dns_an_count,
        dns_rdata,
        message,
        truncation_flags,
    })
}

fn parse_kind(s: &str) -> Result<Kind, String> {
    match s {
        "ProcessFork" => Ok(Kind::ProcessFork),
        "ProcessExecResult" => Ok(Kind::ProcessExecResult),
        "ProcessExit" => Ok(Kind::ProcessExit),
        "FileOpen" => Ok(Kind::FileOpen),
        "FileCreate" => Ok(Kind::FileCreate),
        "FileUnlink" => Ok(Kind::FileUnlink),
        "FileRename" => Ok(Kind::FileRename),
        "FileTruncate" => Ok(Kind::FileTruncate),
        "NetworkConnect" => Ok(Kind::NetworkConnect),
        "NetworkAccept" => Ok(Kind::NetworkAccept),
        "NetworkState" => Ok(Kind::NetworkState),
        "DnsPacket" => Ok(Kind::DnsPacket),
        "LsmDenyOwn" => Ok(Kind::LsmDenyOwn),
        "SyscallEnter" => Ok(Kind::SyscallEnter),
        "SyscallExit" => Ok(Kind::SyscallExit),
        "Identity" => Ok(Kind::Identity),
        other => Err(format!("unknown kind: {other}")),
    }
}

fn parse_priority(s: &str) -> EventPriority {
    match s {
        "Control" => EventPriority::Control,
        _ => EventPriority::Data,
    }
}

fn parse_event_id(s: &str) -> Result<EventId, String> {
    let bytes = hex_decode(s)?;
    if bytes.len() != 16 {
        return Err(format!("event_id must be 16 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(EventId(arr))
}

fn parse_boot_id(s: &str) -> Result<BootId, String> {
    let bytes = hex_decode(s)?;
    if bytes.len() != 16 {
        return Err(format!("boot_id must be 16 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(BootId(arr))
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex string".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("hex decode error: {e}")))
        .collect()
}

fn parse_namespaces(v: Option<&serde_json::Value>) -> NamespaceBundle {
    let obj = v.and_then(|v| v.as_object());
    let get = |key: &str| -> Option<u64> { obj.and_then(|o| o.get(key)).and_then(|v| v.as_u64()) };
    NamespaceBundle {
        pid: get("pid"),
        mnt: get("mnt"),
        net: get("net"),
        user: get("user"),
        uts: get("uts"),
        ipc: get("ipc"),
        cgroup: get("cgroup"),
        time: get("time"),
    }
}

fn parse_identity(v: Option<&serde_json::Value>) -> Identity {
    let obj = v.and_then(|v| v.as_object());
    let get = |key: &str| -> Option<u32> {
        obj.and_then(|o| o.get(key))
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
    };
    Identity {
        real_uid: get("real_uid"),
        effective_uid: get("effective_uid"),
        saved_uid: get("saved_uid"),
        real_gid: get("real_gid"),
        effective_gid: get("effective_gid"),
        saved_gid: get("saved_gid"),
        loginuid: get("loginuid"),
    }
}

fn parse_truncation_flags(v: Option<&serde_json::Value>) -> TruncationFlags {
    let obj = v.and_then(|v| v.as_object());
    let get = |key: &str| -> bool {
        obj.and_then(|o| o.get(key))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    TruncationFlags {
        argv_truncated: get("argv_truncated"),
        path_truncated: get("path_truncated"),
        dns_truncated: get("dns_truncated"),
    }
}
