// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Canonical AST for the native rule schema.
//!
//! These types are the single, versioned in-memory representation a rule
//! document compiles to. Serde impls are split by concern: deserialization
//! lives in [`crate::parse`] and serialization in [`crate::serialize`]. The
//! `Value` and `Condition` types carry hand-written serde impls because their
//! wire shape is polymorphic; every other type derives.

use serde::{Deserialize, Serialize};

/// Rule severity. Serialized lowercase (`critical`..`info`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Most severe.
    Critical,
    /// High severity.
    High,
    /// Medium severity.
    Medium,
    /// Low severity.
    Low,
    /// Informational.
    Info,
}

/// Event source a rule applies to. Serialized lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Process lifecycle facts.
    Process,
    /// File operation facts.
    File,
    /// Network socket facts.
    Network,
    /// DNS packet facts.
    Dns,
    /// Syscall facts.
    Syscall,
    /// Raw identity facts (cgroup / namespaces).
    Identity,
}

/// Action taken on a rule match. Serialized lowercase.
///
/// `Deny` is only permitted when the condition references kernel-observable
/// fields; this is enforced by the semantic validator, not the type system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Emit an alert record.
    Alert,
    /// Emit an audit record.
    Audit,
    /// Deny the operation (kernel-observable facts only; audit-by-default).
    Deny,
}

/// Comparison operator. Serialized snake_case (`eq`, `not_in`, `starts_with`…).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Greater than (numeric fields only).
    Gt,
    /// Less than (numeric fields only).
    Lt,
    /// Greater than or equal (numeric fields only).
    Gte,
    /// Less than or equal (numeric fields only).
    Lte,
    /// Value is a member of the array value.
    In,
    /// Value is not a member of the array value.
    NotIn,
    /// String/array contains substring/element.
    Contains,
    /// String/array does not contain substring/element.
    NotContains,
    /// String starts with prefix.
    StartsWith,
    /// String ends with suffix.
    EndsWith,
    /// String matches bounded regex.
    Regex,
    /// String does not match bounded regex.
    NotRegex,
}

/// A typed match value.
///
/// Polymorphic on the wire; see [`crate::parse`] / [`crate::serialize`] for the
/// hand-written serde impls.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// A UTF-8 string.
    String(String),
    /// A signed 64-bit integer.
    Integer(i64),
    /// A 64-bit float.
    Float(f64),
    /// A boolean.
    Boolean(bool),
    /// An array of values.
    Array(Vec<Value>),
}

impl Value {
    /// Borrow the string payload, if this is a [`Value::String`].
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
}

/// A match condition: exactly one of a leaf field match, AND, OR, or NOT.
///
/// This is a sum type (mutually exclusive variants), mirrored by the JSON
/// Schema `oneOf`. Polymorphic on the wire; see [`crate::parse`] /
/// [`crate::serialize`].
#[derive(Debug, Clone, PartialEq)]
pub enum Condition {
    /// A leaf field match.
    Field {
        /// Event field name (must be in the field catalog).
        field: String,
        /// Comparison operator (must be valid for the field type).
        operator: Operator,
        /// Match value (type must match the field/operator).
        value: Value,
    },
    /// All children must match.
    And(Vec<Condition>),
    /// At least one child must match.
    Or(Vec<Condition>),
    /// The negated child.
    Not(Box<Condition>),
}

/// A scoped exception that suppresses a match.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    /// Event field name.
    pub field: String,
    /// Operator (scoped subset; no ordering operators).
    pub operator: Operator,
    /// Match value.
    pub value: Value,
}

/// A reusable, immutable string list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct List {
    /// Unique list name.
    pub name: String,
    /// Non-empty list items.
    pub items: Vec<String>,
}

/// A single ordered step in a temporal sequence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// Event field name.
    pub field: String,
    /// Operator (scoped subset; no ordering operators).
    pub operator: Operator,
    /// Match value.
    pub value: Value,
}

/// An ordered temporal sequence with a bounded correlation window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sequence {
    /// Unique sequence name.
    pub name: String,
    /// Non-empty ordered steps.
    pub steps: Vec<Step>,
    /// Correlation window in seconds (>= 1).
    pub window_seconds: u32,
}

/// A single rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Unique rule id.
    pub id: String,
    /// Rule version (>= 1).
    pub version: u32,
    /// Severity.
    pub severity: Severity,
    /// Optional tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Event source.
    pub source: Source,
    /// Non-empty human-readable description.
    pub description: String,
    /// Match condition.
    pub condition: Condition,
    /// Action.
    pub action: Action,
    /// Optional exceptions.
    #[serde(default)]
    pub exceptions: Vec<Exception>,
    /// Optional reusable lists.
    #[serde(default)]
    pub lists: Vec<List>,
    /// Optional temporal sequences.
    #[serde(default)]
    pub sequences: Vec<Sequence>,
}

/// A versioned rule set: the top-level document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    /// Rule schema version (must be 1).
    pub schema_version: u32,
    /// Compatible engine version (semver).
    pub engine_version: String,
    /// The rules (may be empty).
    pub rules: Vec<Rule>,
}
