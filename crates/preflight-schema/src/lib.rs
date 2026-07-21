//! Typed parser and validator for the kernel-v1 host compatibility preflight
//! report (schema v1).
//!
//! This crate exposes:
//!
//! * [`parse`] — parse + schema-validate + semantic-check a raw JSON byte
//!   slice into a strongly typed [`PreflightReport`].
//! * [`ReportError`] — error type with a JSON-pointer-like [`ReportError::pointer`]
//!   for machine-readable location reporting.
//!
//! The schema itself lives at `schemas/preflight-v1.schema.json`; the crate
//! embeds that file at build time and validates every input against it
//! before performing the semantic cross-checks.
//!
//! SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fmt;

use serde::{Deserialize, Serialize};

const SCHEMA_JSON: &str = include_str!("../../../schemas/preflight-v1.schema.json");

#[cfg(test)]
const CAPABLE_FIXTURE: &str =
    include_str!("../../../tests/fixtures/preflight/valid/host-capable-privileged.json");
#[cfg(test)]
const DEGRADED_FIXTURE: &str =
    include_str!("../../../tests/fixtures/preflight/valid/host-degraded-unprivileged.json");
#[cfg(test)]
const MISSING_BTF_FIXTURE: &str =
    include_str!("../../../tests/fixtures/preflight/invalid/missing-btf.json");
#[cfg(test)]
const EXTRA_FIELD_FIXTURE: &str =
    include_str!("../../../tests/fixtures/preflight/invalid/extra-field.json");

/// Top-level typed preflight report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightReport {
    pub schema_version: u32,
    pub status: Status,
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    pub blocked_reason: Option<String>,
    pub kernel: KernelFacts,
    pub features: Features,
    pub privilege: Privilege,
    pub container: Container,
    pub sensors: Sensors,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Capable,
    Degraded,
    Blocked,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Capable => "capable",
            Status::Degraded => "degraded",
            Status::Blocked => "blocked",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelFacts {
    pub release: String,
    pub version: String,
    pub arch: String,
    pub boot_id: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtfFacts {
    pub path: String,
    pub readable: bool,
    pub size: u64,
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsmFacts {
    pub active: String,
    pub bpf_in_list: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgroupFacts {
    pub mode: String,
    pub unified_mount: String,
    pub controllers: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountPath {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountsFacts {
    pub bpffs: MountPath,
    pub tracefs: MountPath,
    pub debugfs: MountPath,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfFacts {
    pub helpers: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Features {
    pub btf: BtfFacts,
    pub lsm: LsmFacts,
    pub cgroup: CgroupFacts,
    pub mounts: MountsFacts,
    pub bpf: BpfFacts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Privilege {
    pub effective: String,
    pub bounding: String,
    pub can_load: bool,
    pub unprivileged_bpf_disabled: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Container {
    pub runtime: String,
    pub in_container: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SensorStatus {
    Capable,
    Degraded,
    Blocked,
}

impl SensorStatus {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sensor {
    pub status: SensorStatus,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sensors {
    #[serde(rename = "process.bpf")]
    pub process_bpf: Sensor,
    #[serde(rename = "file.bpf")]
    pub file_bpf: Sensor,
    #[serde(rename = "network.bpf")]
    pub network_bpf: Sensor,
    #[serde(rename = "dns.bpf")]
    pub dns_bpf: Sensor,
    #[serde(rename = "syscall.bpf")]
    pub syscall_bpf: Sensor,
    #[serde(rename = "lsm.bpf")]
    pub lsm_bpf: Sensor,
    #[serde(rename = "identity.bpf")]
    pub identity_bpf: Sensor,
    #[serde(rename = "ringbuf.bpf")]
    pub ringbuf_bpf: Sensor,
    pub loader: Sensor,
}

impl Sensors {
    fn all(&self) -> [&Sensor; 9] {
        [
            &self.process_bpf,
            &self.file_bpf,
            &self.network_bpf,
            &self.dns_bpf,
            &self.syscall_bpf,
            &self.lsm_bpf,
            &self.identity_bpf,
            &self.ringbuf_bpf,
            &self.loader,
        ]
    }
}

/// Errors produced by [`parse`]. Each error carries a JSON-pointer-like
/// [`Self::pointer`] (RFC 6901 style, e.g. `/features/btf/readable`) plus a
/// human-readable [`Self::message`].
#[derive(Debug, Clone)]
pub struct ReportError {
    pub pointer: String,
    pub message: String,
}

impl ReportError {
    fn new(pointer: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            pointer: pointer.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.pointer, self.message)
    }
}

impl std::error::Error for ReportError {}

fn deserialize_optional_string<'de, D>(de: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = serde_json::Value::deserialize(de)?;
    match v {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) => Ok(Some(s)),
        other => Err(serde::de::Error::custom(format!(
            "expected string or null, got {}",
            other
        ))),
    }
}

/// Parse a preflight JSON byte slice, validate it against the embedded schema,
/// and run the semantic checks defined by task 3 of the plan.
pub fn parse(bytes: &[u8]) -> Result<PreflightReport, ReportError> {
    let raw: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| ReportError::new("", format!("invalid JSON: {e}")))?;

    validate_schema(&raw)?;
    let report: PreflightReport = serde_json::from_value(raw.clone()).map_err(|e| {
        ReportError::new("", format!("schema-valid value did not deserialize: {e}"))
    })?;
    semantic_check(&report)?;
    Ok(report)
}

/// Validate a JSON value against the embedded schema.
pub fn validate_schema(value: &serde_json::Value) -> Result<(), ReportError> {
    let schema_value: serde_json::Value = serde_json::from_str(SCHEMA_JSON)
        .map_err(|e| ReportError::new("", format!("embedded schema invalid: {e}")))?;
    let validator = jsonschema::validator_for(&schema_value)
        .map_err(|e| ReportError::new("", format!("schema compilation failed: {e}")))?;
    let mut errors: Vec<String> = Vec::new();
    for err in validator.iter_errors(value) {
        errors.push(format!("{} -> {}", err.instance_path(), err));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ReportError::new("/", errors.join("; ")))
    }
}

/// Run the semantic cross-checks. Each violation produces a [`ReportError`]
/// with the JSON pointer of the offending field.
pub fn semantic_check(report: &PreflightReport) -> Result<(), ReportError> {
    let sensors = report.sensors.all();
    let any_blocked = sensors
        .iter()
        .any(|s| matches!(s.status, SensorStatus::Blocked));
    let any_degraded = sensors
        .iter()
        .any(|s| matches!(s.status, SensorStatus::Degraded));

    match report.status {
        Status::Blocked if !any_blocked => {
            return Err(ReportError::new(
                "/status",
                "status='blocked' but no sensor reports status='blocked'",
            ));
        }
        Status::Degraded => {
            if any_blocked {
                return Err(ReportError::new(
                    "/status",
                    "status='degraded' but at least one sensor reports status='blocked'",
                ));
            }
            if !any_degraded {
                return Err(ReportError::new(
                    "/status",
                    "status='degraded' but no sensor reports status='degraded'",
                ));
            }
        }
        Status::Capable if any_blocked || any_degraded => {
            return Err(ReportError::new(
                "/status",
                "status='capable' but at least one sensor is 'degraded' or 'blocked'",
            ));
        }
        _ => {}
    }

    if !report.privilege.can_load {
        let have_no_cap_reason = sensors.iter().any(|s| {
            s.reason
                .as_deref()
                .map(|r| r.contains("no-cap-"))
                .unwrap_or(false)
        });
        if !have_no_cap_reason {
            return Err(ReportError::new(
                "/privilege/can_load",
                "can_load=false but no sensor reports a reason containing 'no-cap-'",
            ));
        }
    }

    if !report.features.btf.readable {
        if matches!(report.status, Status::Capable) {
            return Err(ReportError::new(
                "/features/btf/readable",
                "features.btf.readable=false but status='capable' is inconsistent",
            ));
        }
        let any_capable_sensor = sensors
            .iter()
            .any(|s| matches!(s.status, SensorStatus::Capable));
        if any_capable_sensor {
            return Err(ReportError::new(
                "/features/btf/readable",
                "features.btf.readable=false but at least one sensor reports 'capable'",
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_capable_fixture() {
        let r = parse(CAPABLE_FIXTURE.as_bytes()).expect("capable fixture must parse");
        assert_eq!(r.status, Status::Capable);
        assert_eq!(r.schema_version, 1);
        assert!(r.privilege.can_load);
        assert!(r.features.btf.readable);
        assert!(r.features.lsm.bpf_in_list);
        assert_eq!(r.kernel.arch, "x86_64");
    }

    #[test]
    fn parse_degraded_fixture() {
        let r = parse(DEGRADED_FIXTURE.as_bytes()).expect("degraded fixture must parse");
        assert_eq!(r.status, Status::Degraded);
        assert!(!r.privilege.can_load);
        let sensors = r.sensors.all();
        assert!(sensors
            .iter()
            .any(|s| matches!(s.status, SensorStatus::Degraded)));
        assert!(sensors.iter().any(|s| {
            s.reason
                .as_deref()
                .map(|r| r.contains("no-cap-"))
                .unwrap_or(false)
        }));
    }

    #[test]
    fn parse_missing_btf_fixture_fails_with_pointer() {
        let err = parse(MISSING_BTF_FIXTURE.as_bytes())
            .expect_err("missing-btf fixture must fail semantic check");
        assert!(
            err.pointer.starts_with("/features/btf/readable") || err.pointer.starts_with("/status"),
            "unexpected pointer {}",
            err.pointer
        );
    }

    #[test]
    fn parse_extra_field_fixture_fails_schema() {
        let err = parse(EXTRA_FIELD_FIXTURE.as_bytes())
            .expect_err("extra-field fixture must fail schema validation");
        assert_eq!(err.pointer, "/");
        assert!(err.message.contains("unexpected_extra_field"));
    }

    #[test]
    fn parse_garbage_bytes_fails() {
        let err = parse(b"not json at all").expect_err("non-JSON input must fail");
        assert_eq!(err.pointer, "");
        assert!(err.message.contains("invalid JSON"));
    }

    #[test]
    fn semantic_blocked_status_requires_a_blocked_sensor() {
        let mut report = parse(CAPABLE_FIXTURE.as_bytes()).expect("fixture");
        report.status = Status::Blocked;
        let err =
            semantic_check(&report).expect_err("blocked status with no blocked sensor must fail");
        assert_eq!(err.pointer, "/status");
    }

    #[test]
    fn semantic_degraded_status_with_blocked_sensor_fails() {
        let mut report = parse(DEGRADED_FIXTURE.as_bytes()).expect("fixture");
        let mut sensors = serde_json::to_value(&report.sensors).unwrap();
        sensors["process.bpf"]["status"] = serde_json::json!("blocked");
        report.sensors = serde_json::from_value(sensors).unwrap();
        let err = semantic_check(&report).expect_err("degraded with blocked sensor must fail");
        assert_eq!(err.pointer, "/status");
    }

    #[test]
    fn semantic_can_load_false_without_no_cap_reason_fails() {
        let mut report = parse(CAPABLE_FIXTURE.as_bytes()).expect("fixture");
        report.privilege.can_load = false;
        report.sensors.process_bpf.reason = Some("btf-unreadable".into());
        let err =
            semantic_check(&report).expect_err("can_load=false without no-cap- reason must fail");
        assert_eq!(err.pointer, "/privilege/can_load");
    }

    #[test]
    fn schema_only_validates_known_required_fields() {
        let value: serde_json::Value = serde_json::from_str(CAPABLE_FIXTURE).expect("fixture");
        validate_schema(&value).expect("schema must accept capable fixture");
        let invalid: serde_json::Value =
            serde_json::from_str(MISSING_BTF_FIXTURE).expect("fixture");
        validate_schema(&invalid)
            .expect("schema only checks shape; semantic check is what rejects missing-btf");
    }
}
