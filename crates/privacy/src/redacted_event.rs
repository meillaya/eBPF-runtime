// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The redacted event — the only shape that may cross a sink boundary.

use agent_core::{
    BootId, CgroupId, EventId, EventPriority, Identity, Kind, MonotonicNs, NamespaceBundle,
    PidTgid, Sequence, TaskStartNs, WallClock,
};

use super::policy::TruncationFlags;
use super::types::{DecodedDns, DecodedRecord};

fn opt_u64(v: Option<u64>) -> serde_json::Value {
    v.map(Into::into).unwrap_or(serde_json::Value::Null)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// The redacted event shape — the **only** object any sink may receive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedEvent {
    pub kind: Kind,
    pub event_id: EventId,
    pub sequence: Sequence,
    pub monotonic_ns: MonotonicNs,
    pub wall_clock: WallClock,
    pub pid_tgid: PidTgid,
    pub task_start_ns: TaskStartNs,
    pub cgroup_id: CgroupId,
    pub boot_id: BootId,
    pub namespaces: NamespaceBundle,
    pub identity: Identity,
    pub priority: EventPriority,
    pub attribution_scope: Option<String>,
    /// argv joined by NUL, secret-masked, truncated to `argv_max_bytes`.
    pub argv_bytes: Option<Vec<u8>>,
    /// environment joined by NUL, or `None` when `env_enabled` is false.
    pub env: Option<Vec<u8>>,
    /// file / exec path, redacted to `[REDACTED]` on a pattern match.
    pub path: Option<String>,
    /// argument tokens, each redacted / masked independently.
    pub arguments: Vec<String>,
    pub dns_qname: Option<String>,
    pub dns_qtype: Option<u16>,
    pub dns_qclass: Option<u16>,
    pub dns_an_count: Option<u16>,
    /// DNS rdata, masked to `[MASKED]` unless `rdata` is allowlisted.
    pub dns_rdata: Option<Vec<u8>>,
    /// generic log / line text, secret-masked.
    pub message: Option<String>,
    /// which fields were truncated / redacted.
    pub truncation_flags: TruncationFlags,
}

impl RedactedEvent {
    /// Serialize the redacted event to a stable JSON value.
    pub fn to_json(&self) -> serde_json::Value {
        let mut ns = serde_json::Map::new();
        ns.insert("pid".into(), opt_u64(self.namespaces.pid));
        ns.insert("mnt".into(), opt_u64(self.namespaces.mnt));
        ns.insert("net".into(), opt_u64(self.namespaces.net));
        ns.insert("user".into(), opt_u64(self.namespaces.user));
        ns.insert("uts".into(), opt_u64(self.namespaces.uts));
        ns.insert("ipc".into(), opt_u64(self.namespaces.ipc));
        ns.insert("cgroup".into(), opt_u64(self.namespaces.cgroup));
        ns.insert("time".into(), opt_u64(self.namespaces.time));

        let mut id = serde_json::Map::new();
        id.insert(
            "real_uid".into(),
            opt_u64(self.identity.real_uid.map(u64::from)),
        );
        id.insert(
            "effective_uid".into(),
            opt_u64(self.identity.effective_uid.map(u64::from)),
        );
        id.insert(
            "saved_uid".into(),
            opt_u64(self.identity.saved_uid.map(u64::from)),
        );
        id.insert(
            "real_gid".into(),
            opt_u64(self.identity.real_gid.map(u64::from)),
        );
        id.insert(
            "effective_gid".into(),
            opt_u64(self.identity.effective_gid.map(u64::from)),
        );
        id.insert(
            "saved_gid".into(),
            opt_u64(self.identity.saved_gid.map(u64::from)),
        );
        id.insert(
            "loginuid".into(),
            opt_u64(self.identity.loginuid.map(u64::from)),
        );

        let mut flags = serde_json::Map::new();
        flags.insert(
            "argv_truncated".into(),
            self.truncation_flags.argv_truncated.into(),
        );
        flags.insert(
            "path_truncated".into(),
            self.truncation_flags.path_truncated.into(),
        );
        flags.insert(
            "dns_truncated".into(),
            self.truncation_flags.dns_truncated.into(),
        );

        let mut map = serde_json::Map::new();
        map.insert("kind".into(), format!("{:?}", self.kind).into());
        map.insert("event_id".into(), hex(&self.event_id.0).into());
        map.insert("sequence".into(), self.sequence.0.into());
        map.insert("monotonic_ns".into(), self.monotonic_ns.0.into());
        map.insert("wall_clock".into(), self.wall_clock.0.clone().into());
        map.insert("pid_tgid".into(), self.pid_tgid.0.into());
        map.insert("task_start_ns".into(), self.task_start_ns.0.into());
        map.insert("cgroup_id".into(), self.cgroup_id.0.into());
        map.insert("boot_id".into(), hex(&self.boot_id.0).into());
        map.insert("namespaces".into(), serde_json::Value::Object(ns));
        map.insert("identity".into(), serde_json::Value::Object(id));
        map.insert("priority".into(), format!("{:?}", self.priority).into());
        map.insert(
            "attribution_scope".into(),
            self.attribution_scope
                .clone()
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "argv".into(),
            self.argv_bytes
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned().into())
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "env".into(),
            self.env
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned().into())
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "path".into(),
            self.path
                .clone()
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "arguments".into(),
            serde_json::Value::Array(self.arguments.iter().map(|a| a.clone().into()).collect()),
        );
        map.insert(
            "dns_qname".into(),
            self.dns_qname
                .clone()
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert("dns_qtype".into(), opt_u64(self.dns_qtype.map(u64::from)));
        map.insert("dns_qclass".into(), opt_u64(self.dns_qclass.map(u64::from)));
        map.insert(
            "dns_an_count".into(),
            opt_u64(self.dns_an_count.map(u64::from)),
        );
        map.insert(
            "dns_rdata".into(),
            self.dns_rdata
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned().into())
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "message".into(),
            self.message
                .clone()
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert("truncation_flags".into(), serde_json::Value::Object(flags));
        serde_json::Value::Object(map)
    }

    /// Serialize to compact JSON bytes (the form sinks persist / transmit).
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&self.to_json())
    }

    /// Project this redacted event back to a [`DecodedRecord`].
    pub fn to_decoded_record(&self) -> DecodedRecord {
        let split = |bytes: &Option<Vec<u8>>| -> Vec<String> {
            bytes
                .as_ref()
                .map(|b| {
                    if b.is_empty() {
                        Vec::new()
                    } else {
                        b.split(|c| *c == 0)
                            .map(|part| String::from_utf8_lossy(part).into_owned())
                            .collect()
                    }
                })
                .unwrap_or_default()
        };
        let dns = match (
            &self.dns_qname,
            self.dns_qtype,
            self.dns_qclass,
            self.dns_an_count,
            &self.dns_rdata,
        ) {
            (None, None, None, None, None) => None,
            (qname, qtype, qclass, an_count, rdata) => Some(DecodedDns {
                qname: qname.clone().unwrap_or_default(),
                qtype: qtype.unwrap_or(0),
                qclass: qclass.unwrap_or(0),
                an_count: an_count.unwrap_or(0),
                rdata: rdata
                    .as_ref()
                    .map(|b| {
                        if b.is_empty() {
                            Vec::new()
                        } else {
                            vec![String::from_utf8_lossy(b).into_owned()]
                        }
                    })
                    .unwrap_or_default(),
            }),
        };
        DecodedRecord {
            argv: split(&self.argv_bytes),
            env: split(&self.env),
            path: self.path.clone().unwrap_or_default(),
            arguments: self.arguments.clone(),
            dns,
            message: self.message.clone().unwrap_or_default(),
        }
    }
}
