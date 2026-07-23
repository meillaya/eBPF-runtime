// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Match explanations: a deterministic tree of why a condition matched or not.
//!
//! Every evaluation produces an [`Explanation`] mirroring the condition shape:
//! a leaf records its field/operator/value and whether it matched; a composite
//! (`and`/`or`/`not`) records its aggregate result and the explanations of its
//! children, in evaluation order. Composite nodes label themselves via `field`
//! (`"and"`/`"or"`/`"not"`) and carry the aggregate result in `value`
//! (`Boolean`); their `operator` is a placeholder (`eq`) since a composite has
//! no single comparison operator. The tree is serializable so the CLI and UI
//! can show exactly why an event matched.

use serde::Serialize;

use crate::ast::{Operator, Value};

/// The result of evaluating one condition against one event.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EvaluationResult {
    /// Whether the condition matched the event.
    pub matched: bool,
    /// The match-explanation tree.
    pub explanation: Explanation,
}

/// A node in the match-explanation tree.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Explanation {
    /// Leaf: the event field name. Composite: `"and"` / `"or"` / `"not"`.
    pub field: String,
    /// Leaf: the comparison operator. Composite: placeholder (`eq`).
    pub operator: Operator,
    /// Leaf: the condition value. Composite: `Boolean(matched)`.
    pub value: Value,
    /// Whether this node matched.
    pub matched: bool,
    /// Child explanations (empty for a leaf).
    pub children: Vec<Explanation>,
}

impl Explanation {
    /// Build a leaf explanation.
    pub fn leaf(field: &str, operator: Operator, value: Value, matched: bool) -> Self {
        Self {
            field: field.to_string(),
            operator,
            value,
            matched,
            children: Vec::new(),
        }
    }

    /// Build a composite (`and`/`or`/`not`) explanation from its children.
    pub fn node(label: &str, matched: bool, children: Vec<Explanation>) -> Self {
        Self {
            field: label.to_string(),
            operator: Operator::Eq,
            value: Value::Boolean(matched),
            matched,
            children,
        }
    }
}
