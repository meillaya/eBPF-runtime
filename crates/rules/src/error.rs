// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed, path-aware diagnostics for the native rule schema.
//!
//! Every way a rule set can fail to parse or validate maps onto one
//! [`RuleError`] variant. Variants that originate from a specific node in the
//! rule tree carry a path-aware message (e.g. `rules[0].condition.field: ...`)
//! so an operator can locate the offending construct without re-reading the
//! whole document.

/// All failures produced by parsing and validating a native rule set.
///
/// This is a native YAML rule format. It is deliberately NOT Falco-compatible
/// and never claims Falco rule-syntax compatibility.
#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    /// The document is structurally invalid against the JSON Schema, or a
    /// semantic structural rule failed (empty condition, recursive list,
    /// condition nesting too deep). The message is path-aware.
    #[error("schema validation failed: {0}")]
    SchemaValidationError(String),

    /// `schema_version` is not the supported value (1).
    #[error("unsupported schema_version {0}: this engine only supports schema_version 1")]
    SchemaVersionMismatch(u32),

    /// `engine_version` is not compatible with the running engine (stale,
    /// newer-major, or malformed). The message names the offending version.
    #[error("incompatible engine_version: {0}")]
    EngineVersionMismatch(String),

    /// Two or more rules share the same `id`.
    #[error("duplicate rule id: {0}")]
    DuplicateRuleId(String),

    /// Two or more lists share the same `name`.
    #[error("duplicate list name: {0}")]
    DuplicateListName(String),

    /// Two or more sequences share the same `name`.
    #[error("duplicate sequence name: {0}")]
    DuplicateSequenceName(String),

    /// A condition/exception/step references an event field that is not in the
    /// field catalog. The message is path-aware.
    #[error("invalid event field: {0}")]
    InvalidField(String),

    /// An operator is not valid for the referenced field's type, or the value
    /// type does not match the field/operator. The message is path-aware.
    #[error("invalid operator: {0}")]
    InvalidOperator(String),

    /// A regex pattern failed to compile. The message is path-aware.
    #[error("invalid regex: {0}")]
    InvalidRegex(String),

    /// A regex pattern exceeds the 1024-byte bound. The message is path-aware.
    #[error("regex too large: {0}")]
    RegexTooLarge(String),

    /// A regex pattern is too complex: more than 64 capture groups, or it
    /// contains unbounded/nested quantifiers. The message is path-aware.
    #[error("regex too complex: {0}")]
    RegexTooComplex(String),

    /// A `deny` action references a non-kernel-observable (enrichment-only /
    /// heuristic) field. Deny must rest on kernel-observable facts only. The
    /// message is path-aware.
    #[error("deny on heuristic-only data: {0}")]
    DenyOnHeuristicOnly(String),

    /// The input is not valid YAML or could not be deserialized into the
    /// canonical AST.
    #[error("yaml error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    /// A JSON (de)serialization error (e.g. parsing the embedded schema).
    #[error("json error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// The embedded JSON Schema itself failed to compile. This indicates a
    /// programming error in the shipped schema, not a bad rule document.
    ///
    /// Note: jsonschema 0.17 reports compilation failures through its
    /// lifetime-borrowed `ValidationError<'a>`, which cannot be stored owned in
    /// this enum; we therefore retain the rendered diagnostic as a `String`.
    #[error("json schema compile error: {0}")]
    JsonSchemaError(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, RuleError>;
