// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The evaluation event: a typed, deterministic field-value map.
//!
//! An [`Event`] carries the resolved field values a condition is evaluated
//! against. It distinguishes three states per field, which is the core of the
//! evaluator's typed null/validity handling:
//! - **present**: `fields` holds a typed [`Value`];
//! - **null**: the field is in `null_fields` (explicitly known to be
//!   null/invalid);
//! - **unknown**: the field is in neither (never observed).
//!
//! Both null and unknown resolve to "no value" via [`Event::lookup`], and a
//! leaf predicate over a missing value is a non-match (`false`) — the evaluator
//! never treats unknown as true. Field storage is a [`BTreeMap`] so iteration
//! order (and therefore evaluation) is deterministic.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::ast::Value;

use super::error::{Result, RuleError};

/// A typed event: present field values plus an explicit null-field set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Present, typed field values (deterministic order).
    #[serde(default)]
    pub fields: BTreeMap<String, Value>,
    /// Fields explicitly known to be null/invalid (typed null handling).
    #[serde(default)]
    pub null_fields: BTreeSet<String>,
}

impl Event {
    /// An empty event: every field is unknown.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set a present field value (clears any null marker).
    pub fn with_field(mut self, field: impl Into<String>, value: Value) -> Self {
        let field = field.into();
        self.null_fields.remove(&field);
        self.fields.insert(field, value);
        self
    }

    /// Builder: mark a field as explicitly null/invalid (removes any value).
    pub fn with_null(mut self, field: impl Into<String>) -> Self {
        let field = field.into();
        self.fields.remove(&field);
        self.null_fields.insert(field);
        self
    }

    /// Resolve a field value. Returns `None` for both null and unknown fields,
    /// so a leaf predicate over either is a non-match.
    pub fn lookup(&self, field: &str) -> Option<&Value> {
        if self.null_fields.contains(field) {
            return None;
        }
        self.fields.get(field)
    }

    /// Whether the field is explicitly null/invalid.
    pub fn is_null(&self, field: &str) -> bool {
        self.null_fields.contains(field)
    }

    /// Whether the field was never observed (neither present nor null).
    pub fn is_unknown(&self, field: &str) -> bool {
        !self.fields.contains_key(field) && !self.null_fields.contains(field)
    }

    /// Strict lookup: error if the field is null or unknown. Used by callers
    /// that require a value; ordinary evaluation uses [`Event::lookup`].
    pub fn require(&self, field: &str) -> Result<&Value> {
        self.lookup(field).ok_or_else(|| {
            RuleError::UnknownField(format!("'{field}' is unknown or null in the event"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_null_and_present_are_distinct() {
        let event = Event::new()
            .with_field("file.path", Value::String("/etc".into()))
            .with_null("dns.qname");
        assert!(event.lookup("file.path").is_some());
        assert!(event.is_null("dns.qname"));
        assert!(event.lookup("dns.qname").is_none());
        assert!(event.is_unknown("process.pid"));
        assert!(event.lookup("process.pid").is_none());
    }
}
