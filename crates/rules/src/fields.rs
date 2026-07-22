// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Event field catalog for the kernel-v1 native rule schema.
//!
//! The catalog is the single source of truth for which event fields a rule
//! condition may reference, what Rust type each field carries, which event
//! [`Source`] it belongs to, and — critically for enforcement — whether the
//! field is *kernel-observable*.
//!
//! Kernel-observable fields are facts the eBPF sensors read directly from the
//! kernel (process, file, network, DNS, syscall, and raw identity facts).
//! Non-kernel-observable fields live under the `enrichment.*` namespace: they
//! are attached asynchronously by the CRI / Kubernetes enrichment layer and may
//! be unknown, stale, or heuristic. A `deny` action may only reference
//! kernel-observable fields; denying on enrichment-only data is rejected by the
//! semantic validator (see [`crate::parse_ruleset`]).

use crate::Source;

/// The type of an event field's value.
///
/// This mirrors the canonical [`crate::Value`] variants a condition may carry
/// for a given field, and drives operator/field-type compatibility checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// A UTF-8 string (e.g. `file.path`, `process.exec_path`).
    String,
    /// A signed 64-bit integer (e.g. `process.pid`, `network.dst_port`).
    Integer,
    /// A 64-bit float. Reserved for future numeric telemetry; the current
    /// catalog has no float fields.
    Float,
    /// A boolean. Reserved for future flag telemetry; the current catalog has
    /// no boolean fields.
    Boolean,
    /// An array of strings (e.g. `process.argv`).
    Array,
}

/// A single event field definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDef {
    /// The fully-qualified field name (e.g. `file.path`).
    pub name: String,
    /// The field's value type.
    pub field_type: FieldType,
    /// The event source this field belongs to.
    pub source: Source,
    /// Whether the field is observed directly from the kernel.
    ///
    /// `true` for raw kernel facts; `false` for asynchronously attached
    /// enrichment metadata that may be unknown or heuristic.
    pub kernel_observable: bool,
}

/// The catalog of all event fields a rule may reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldCatalog {
    /// The field definitions, in a stable, deterministic order.
    pub fields: Vec<FieldDef>,
}

impl FieldCatalog {
    /// Look up a field definition by name.
    pub fn get(&self, name: &str) -> Option<&FieldDef> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Whether `name` is a known event field.
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Whether `name` is a known field that is kernel-observable.
    ///
    /// Returns `false` for unknown fields and for known enrichment-only
    /// (non-kernel-observable) fields.
    pub fn is_kernel_observable(&self, name: &str) -> bool {
        self.get(name).map(|f| f.kernel_observable).unwrap_or(false)
    }
}

/// Returns the default field catalog derived from the kernel-v1 event API.
///
/// The catalog covers every normalized event field emitted by the sensors and
/// the enrichment layer:
/// - process facts (`process.*`) — kernel-observable;
/// - file facts (`file.*`) — kernel-observable;
/// - network facts (`network.*`) — kernel-observable;
/// - DNS facts (`dns.*`) — kernel-observable;
/// - syscall facts (`syscall.*`) — kernel-observable;
/// - raw identity facts (`identity.*`) — kernel-observable;
/// - enrichment metadata (`enrichment.*`) — NOT kernel-observable.
pub fn default_field_catalog() -> FieldCatalog {
    let fields = vec![
        // process source (kernel-observable)
        FieldDef {
            name: "process.exec_path".into(),
            field_type: FieldType::String,
            source: Source::Process,
            kernel_observable: true,
        },
        FieldDef {
            name: "process.argv".into(),
            field_type: FieldType::Array,
            source: Source::Process,
            kernel_observable: true,
        },
        FieldDef {
            name: "process.pid".into(),
            field_type: FieldType::Integer,
            source: Source::Process,
            kernel_observable: true,
        },
        FieldDef {
            name: "process.tgid".into(),
            field_type: FieldType::Integer,
            source: Source::Process,
            kernel_observable: true,
        },
        FieldDef {
            name: "process.uid".into(),
            field_type: FieldType::Integer,
            source: Source::Process,
            kernel_observable: true,
        },
        FieldDef {
            name: "process.gid".into(),
            field_type: FieldType::Integer,
            source: Source::Process,
            kernel_observable: true,
        },
        // file source (kernel-observable)
        FieldDef {
            name: "file.path".into(),
            field_type: FieldType::String,
            source: Source::File,
            kernel_observable: true,
        },
        FieldDef {
            name: "file.kind".into(),
            field_type: FieldType::String,
            source: Source::File,
            kernel_observable: true,
        },
        // network source (kernel-observable)
        FieldDef {
            name: "network.dst_ip".into(),
            field_type: FieldType::String,
            source: Source::Network,
            kernel_observable: true,
        },
        FieldDef {
            name: "network.dst_port".into(),
            field_type: FieldType::Integer,
            source: Source::Network,
            kernel_observable: true,
        },
        FieldDef {
            name: "network.family".into(),
            field_type: FieldType::String,
            source: Source::Network,
            kernel_observable: true,
        },
        // dns source (kernel-observable)
        FieldDef {
            name: "dns.qname".into(),
            field_type: FieldType::String,
            source: Source::Dns,
            kernel_observable: true,
        },
        FieldDef {
            name: "dns.qtype".into(),
            field_type: FieldType::Integer,
            source: Source::Dns,
            kernel_observable: true,
        },
        // syscall source (kernel-observable)
        FieldDef {
            name: "syscall.nr".into(),
            field_type: FieldType::Integer,
            source: Source::Syscall,
            kernel_observable: true,
        },
        FieldDef {
            name: "syscall.latency_ns".into(),
            field_type: FieldType::Integer,
            source: Source::Syscall,
            kernel_observable: true,
        },
        // identity source (kernel-observable raw identity facts)
        FieldDef {
            name: "identity.cgroup_id".into(),
            field_type: FieldType::Integer,
            source: Source::Identity,
            kernel_observable: true,
        },
        FieldDef {
            name: "identity.ns_pid".into(),
            field_type: FieldType::Integer,
            source: Source::Identity,
            kernel_observable: true,
        },
        FieldDef {
            name: "identity.ns_mnt".into(),
            field_type: FieldType::Integer,
            source: Source::Identity,
            kernel_observable: true,
        },
        FieldDef {
            name: "identity.ns_net".into(),
            field_type: FieldType::Integer,
            source: Source::Identity,
            kernel_observable: true,
        },
        FieldDef {
            name: "identity.ns_user".into(),
            field_type: FieldType::Integer,
            source: Source::Identity,
            kernel_observable: true,
        },
        // enrichment metadata (NOT kernel-observable; async CRI/Kubernetes)
        FieldDef {
            name: "enrichment.container_id".into(),
            field_type: FieldType::String,
            source: Source::Identity,
            kernel_observable: false,
        },
        FieldDef {
            name: "enrichment.pod_uid".into(),
            field_type: FieldType::String,
            source: Source::Identity,
            kernel_observable: false,
        },
        FieldDef {
            name: "enrichment.pod_name".into(),
            field_type: FieldType::String,
            source: Source::Identity,
            kernel_observable: false,
        },
        FieldDef {
            name: "enrichment.namespace".into(),
            field_type: FieldType::String,
            source: Source::Identity,
            kernel_observable: false,
        },
    ];
    FieldCatalog { fields }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_24_fields() {
        assert_eq!(default_field_catalog().fields.len(), 24);
    }

    #[test]
    fn enrichment_fields_are_not_kernel_observable() {
        let cat = default_field_catalog();
        for f in &cat.fields {
            if f.name.starts_with("enrichment.") {
                assert!(
                    !f.kernel_observable,
                    "{} must not be kernel-observable",
                    f.name
                );
            } else {
                assert!(f.kernel_observable, "{} must be kernel-observable", f.name);
            }
        }
    }
}
