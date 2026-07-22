// SPDX-License-Identifier: Apache-2.0 OR MIT
//! kernel-v1 native versioned YAML rule schema.
//!
//! This crate defines the canonical AST, parser, semantic/type checker, field
//! catalog, deterministic canonical digest, and rich path-aware diagnostics for
//! the kernel-v1 native rule format (schema v1).
//!
//! # Contract
//!
//! - **Native, not Falco.** This is a purpose-built YAML rule DSL. It is NOT
//!   Falco-compatible and makes no Falco rule-syntax compatibility claim.
//! - **Closed world.** Unknown structural fields, unknown event fields, and
//!   unknown operators are rejected; the schema is a closed contract.
//! - **Bounded regex.** Patterns are bounded (<= 1024 bytes, <= 64 capture
//!   groups, must compile, no unbounded/nested quantifiers). No arbitrary
//!   code/regex without bounds.
//! - **Safe deny.** A `deny` action may only reference kernel-observable
//!   fields; deny on heuristic-only / enrichment-unknown data is rejected.
//! - **Deterministic.** `serialize_ruleset` and `canonical_digest` are stable:
//!   the same rule set always yields the same bytes and the same digest.
//!
//! # Entry points
//!
//! - [`parse_ruleset`]: YAML -> validated canonical [`RuleSet`].
//! - [`serialize_ruleset`]: [`RuleSet`] -> canonical YAML.
//! - [`canonical_digest`]: [`RuleSet`] -> SHA-256 hex digest.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod ast;
pub mod error;
pub mod fields;
pub mod lists;
pub mod parse;
pub mod regex_check;
pub mod schema;
pub mod serialize;
pub mod validate;
pub mod version;

pub use ast::{
    Action, Condition, Exception, List, Operator, Rule, RuleSet, Sequence, Severity, Source, Step,
    Value,
};
pub use error::{Result, RuleError};
pub use fields::{default_field_catalog, FieldCatalog, FieldDef, FieldType};
pub use parse::parse_ruleset;
pub use regex_check::{has_unbounded_nesting, validate_regex, MAX_CAPTURE_GROUPS, MAX_REGEX_BYTES};
pub use serialize::{canonical_digest, serialize_ruleset};
pub use validate::{operator_valid_for_type, value_valid_for, MAX_CONDITION_DEPTH};
pub use version::{
    is_engine_compatible, parse_semver, CURRENT_ENGINE_VERSION, SUPPORTED_SCHEMA_VERSION,
};

/// Generate a fresh, globally-unique rule id (UUID v4) for rule authors.
pub fn new_rule_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
