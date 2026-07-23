// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JSON Schema compilation and structural validation.
//!
//! The structural contract (`schemas/rule-v1.schema.json`) is embedded at
//! compile time and compiled once. Structural validation rejects unknown
//! fields, wrong enums, empty required values, and out-of-range versions
//! BEFORE the semantic validator runs, so the semantic layer only ever sees a
//! well-shaped document.

use std::sync::OnceLock;

use jsonschema::JSONSchema;

use crate::error::{Result, RuleError};

/// The embedded structural schema (single source of truth, compiled in).
const SCHEMA_JSON: &str = include_str!("../../../schemas/rule-v1.schema.json");

/// Compile the embedded schema once and hand back a shared reference.
///
/// A failure here means the shipped schema document is broken (a programming
/// error), surfaced as [`RuleError::JsonSchemaError`] rather than a panic.
fn compiled_schema() -> Result<&'static JSONSchema> {
    static SCHEMA: OnceLock<std::result::Result<JSONSchema, String>> = OnceLock::new();
    let stored = SCHEMA.get_or_init(|| {
        let value: serde_json::Value = serde_json::from_str(SCHEMA_JSON)
            .map_err(|e| format!("embedded rule schema is not valid JSON: {e}"))?;
        JSONSchema::compile(&value)
            .map_err(|e| format!("embedded rule schema failed to compile: {e}"))
    });
    stored
        .as_ref()
        .map_err(|msg| RuleError::JsonSchemaError(msg.clone()))
}

/// Validate a parsed rule document against the embedded structural schema.
///
/// All structural violations are collected and joined into a single
/// path-aware [`RuleError::SchemaValidationError`] (JSON-pointer paths such as
/// `/rules/0/condition`).
pub fn validate_against_schema(instance: &serde_json::Value) -> Result<()> {
    let schema = compiled_schema()?;
    if let Err(errors) = schema.validate(instance) {
        let msgs: Vec<String> = errors
            .map(|e| format!("{}: {}", e.instance_path, e))
            .collect();
        return Err(RuleError::SchemaValidationError(msgs.join("; ")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_schema_compiles() {
        assert!(compiled_schema().is_ok());
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let doc = serde_json::json!({
            "schema_version": 1,
            "engine_version": "1.0.0",
            "rules": [],
            "bogus": true
        });
        assert!(matches!(
            validate_against_schema(&doc),
            Err(RuleError::SchemaValidationError(_))
        ));
    }

    #[test]
    fn empty_description_is_rejected() {
        let doc = serde_json::json!({
            "schema_version": 1,
            "engine_version": "1.0.0",
            "rules": [{
                "id": "r", "version": 1, "severity": "low", "source": "file",
                "description": "", "action": "alert",
                "condition": {"field": "file.path", "operator": "eq", "value": "/x"}
            }]
        });
        assert!(matches!(
            validate_against_schema(&doc),
            Err(RuleError::SchemaValidationError(_))
        ));
    }
}
