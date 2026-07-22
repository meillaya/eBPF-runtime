// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Parsing: YAML -> canonical AST, gated by structural then semantic checks.
//!
//! `parse_ruleset` is the single public entry point. It (1) parses the YAML to
//! a JSON value, (2) validates structure against the embedded JSON Schema, (3)
//! deserializes into the canonical AST, and (4) runs the semantic validator.
//! `Value` and `Condition` carry hand-written `Deserialize` impls because their
//! wire shape is polymorphic; `Condition` is a strict sum type (exactly one of
//! field/operator/value, and, or, not).

use serde::de::SeqAccess;
use serde::{Deserialize, Deserializer};

use crate::ast::{Condition, Operator, RuleSet, Value};
use crate::error::Result;

/// Parse and fully validate a native YAML rule set.
///
/// This is a native YAML rule format; it is NOT Falco-compatible and makes no
/// Falco rule-syntax compatibility claim.
pub fn parse_ruleset(yaml: &str) -> Result<RuleSet> {
    let json_value: serde_json::Value = serde_yaml::from_str(yaml)?;
    crate::schema::validate_against_schema(&json_value)?;
    let ruleset: RuleSet = serde_yaml::from_str(yaml)?;
    crate::validate::validate_ruleset(&ruleset)?;
    Ok(ruleset)
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct ValueVisitor;
        impl<'de> serde::de::Visitor<'de> for ValueVisitor {
            type Value = Value;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string, integer, float, boolean, or array")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Value, E> {
                Ok(Value::String(v.to_string()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> std::result::Result<Value, E> {
                Ok(Value::String(v))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Value, E> {
                Ok(Value::Integer(v))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Value, E> {
                i64::try_from(v)
                    .map(Value::Integer)
                    .map_err(serde::de::Error::custom)
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Value, E> {
                Ok(Value::Float(v))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<Value, E> {
                Ok(Value::Boolean(v))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Value, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Value::Array(items))
            }
        }
        deserializer.deserialize_any(ValueVisitor)
    }
}

/// Wire representation of a condition: every variant field is optional, and
/// exactly one variant must be present (enforced by `into_condition`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConditionRaw {
    #[serde(default)]
    field: Option<String>,
    #[serde(default)]
    operator: Option<Operator>,
    #[serde(default)]
    value: Option<Value>,
    #[serde(default)]
    and: Option<Vec<ConditionRaw>>,
    #[serde(default)]
    or: Option<Vec<ConditionRaw>>,
    #[serde(default)]
    not: Option<Box<ConditionRaw>>,
}

impl ConditionRaw {
    fn into_condition(self) -> std::result::Result<Condition, String> {
        let ConditionRaw {
            field,
            operator,
            value,
            and,
            or,
            not,
        } = self;
        match (field, operator, value, and, or, not) {
            (Some(field), Some(operator), Some(value), None, None, None) => {
                Ok(Condition::Field { field, operator, value })
            }
            (None, None, None, Some(and), None, None) => {
                let children = and
                    .into_iter()
                    .map(Self::into_condition)
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Ok(Condition::And(children))
            }
            (None, None, None, None, Some(or), None) => {
                let children = or
                    .into_iter()
                    .map(Self::into_condition)
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Ok(Condition::Or(children))
            }
            (None, None, None, None, None, Some(not)) => Ok(Condition::Not(Box::new((*not).into_condition()?))),
            (None, None, None, None, None, None) => {
                Err("empty condition: expected one of field/operator/value, and, or, not".to_string())
            }
            _ => Err(
                "ambiguous condition: exactly one of field/operator/value, and, or, not must be present"
                    .to_string(),
            ),
        }
    }
}

impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = ConditionRaw::deserialize(deserializer)?;
        raw.into_condition().map_err(serde::de::Error::custom)
    }
}
