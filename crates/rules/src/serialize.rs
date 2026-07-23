// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Deterministic serialization and canonical digest for the rule AST.
//!
//! `serialize_ruleset` always emits the same bytes for the same AST (struct
//! field order is fixed; `Condition` and `Value` use hand-written `Serialize`
//! impls with a fixed key order). `canonical_digest` is the SHA-256 of that
//! canonical YAML, so identical rule sets always share a digest.

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::ast::{Condition, RuleSet, Value};
use crate::error::{Result, RuleError};

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Value::String(s) => serializer.serialize_str(s),
            Value::Integer(i) => serializer.serialize_i64(*i),
            Value::Float(f) => serializer.serialize_f64(*f),
            Value::Boolean(b) => serializer.serialize_bool(*b),
            Value::Array(items) => items.serialize(serializer),
        }
    }
}

impl Serialize for Condition {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Condition::Field {
                field,
                operator,
                value,
            } => {
                let mut map = serializer.serialize_map(Some(3))?;
                map.serialize_entry("field", field)?;
                map.serialize_entry("operator", operator)?;
                map.serialize_entry("value", value)?;
                map.end()
            }
            Condition::And(children) => single_key_map(serializer, "and", children),
            Condition::Or(children) => single_key_map(serializer, "or", children),
            Condition::Not(child) => single_key_map(serializer, "not", &**child),
        }
    }
}

/// Serialize a one-key map (`{key: value}`) with a deterministic key order.
fn single_key_map<S: Serializer, T: Serialize + ?Sized>(
    serializer: S,
    key: &str,
    value: &T,
) -> std::result::Result<S::Ok, S::Error> {
    let mut map = serializer.serialize_map(Some(1))?;
    map.serialize_entry(key, value)?;
    map.end()
}

/// Serialize a rule set to its canonical, deterministic YAML form.
pub fn serialize_ruleset(ruleset: &RuleSet) -> Result<String> {
    serde_yaml::to_string(ruleset).map_err(RuleError::YamlError)
}

/// Compute the canonical digest (SHA-256 hex) of a rule set.
///
/// The digest is over the canonical YAML serialization, so it is stable and
/// deterministic: the same rule set always yields the same digest.
pub fn canonical_digest(ruleset: &RuleSet) -> Result<String> {
    let yaml = serialize_ruleset(ruleset)?;
    let mut hasher = Sha256::new();
    hasher.update(yaml.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_ruleset;

    const DOC: &str = "schema_version: 1\nengine_version: \"1.0.0\"\nrules:\n  - id: r\n    version: 1\n    severity: low\n    source: file\n    description: d\n    condition:\n      field: file.path\n      operator: eq\n      value: /x\n    action: alert\n";

    #[test]
    fn serialize_is_deterministic() {
        let rs = parse_ruleset(DOC).unwrap();
        assert_eq!(
            serialize_ruleset(&rs).unwrap(),
            serialize_ruleset(&rs).unwrap()
        );
    }

    #[test]
    fn digest_is_stable() {
        let rs = parse_ruleset(DOC).unwrap();
        assert_eq!(
            canonical_digest(&rs).unwrap(),
            canonical_digest(&rs).unwrap()
        );
    }
}
