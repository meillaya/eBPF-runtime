// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Engine/schema version compatibility for the native rule schema.
//!
//! A rule set declares the `engine_version` it was written against. The engine
//! accepts a rule set only when that version is *compatible*: same major
//! version as the running engine and not newer than the engine itself. A stale
//! (older-major) or newer-major version is rejected with a path-aware
//! [`crate::RuleError::EngineVersionMismatch`].

/// The engine version this build evaluates rules against.
///
/// This is the source of truth for compatibility checking. Rule sets whose
/// `engine_version` shares this major version and does not exceed it are
/// accepted; everything else is rejected as stale or incompatible.
pub const CURRENT_ENGINE_VERSION: &str = "1.0.0";

/// The only `schema_version` this engine supports.
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Parse a `major.minor.patch` semver string into its three numeric components.
///
/// Returns `None` for any string that is not exactly three dot-separated
/// unsigned integers (no pre-release/build metadata is accepted).
pub fn parse_semver(version: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let major = parts[0].parse::<u32>().ok()?;
    let minor = parts[1].parse::<u32>().ok()?;
    let patch = parts[2].parse::<u32>().ok()?;
    Some((major, minor, patch))
}

/// Whether `version` is compatible with the running engine.
///
/// Compatibility policy (documented and tested):
/// - the version must parse as `major.minor.patch`;
/// - its major version must equal the engine's major version;
/// - it must not be newer than the engine's own version.
///
/// Thus `1.0.0` is compatible with engine `1.0.0`; `0.9.0` (stale, older
/// major) and `2.0.0` (newer major) are not; `1.5.0` (same major but newer
/// than the engine) is not.
pub fn is_engine_compatible(version: &str) -> bool {
    let Some(rule) = parse_semver(version) else {
        return false;
    };
    let Some(engine) = parse_semver(CURRENT_ENGINE_VERSION) else {
        return false;
    };
    if rule.0 != engine.0 {
        return false;
    }
    rule <= engine
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_version_is_compatible() {
        assert!(is_engine_compatible("1.0.0"));
    }

    #[test]
    fn stale_major_is_incompatible() {
        assert!(!is_engine_compatible("0.9.0"));
    }

    #[test]
    fn newer_major_is_incompatible() {
        assert!(!is_engine_compatible("2.0.0"));
    }

    #[test]
    fn newer_minor_is_incompatible() {
        assert!(!is_engine_compatible("1.5.0"));
    }

    #[test]
    fn malformed_is_incompatible() {
        assert!(!is_engine_compatible("garbage"));
        assert!(!is_engine_compatible("1.0"));
        assert!(!is_engine_compatible(""));
    }
}
