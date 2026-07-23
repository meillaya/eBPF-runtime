// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Content-addressed digest computation for policy versions.
//!
//! Every policy version is identified by the SHA-256 hex digest
//! of its content bytes. This module provides the digest
//! computation and verification functions used by the rollout
//! state machine and reconciliation logic.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

/// Compute the SHA-256 hex digest (lower-case, 64 chars) of the
/// given bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in result.iter() {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Verify that the SHA-256 of `content` matches `expected_hex`.
/// Returns `true` on match, `false` on mismatch.
pub fn verify_digest(content: &[u8], expected_hex: &str) -> bool {
    let actual = sha256_hex(content);
    actual == expected_hex.to_ascii_lowercase()
}

/// Compute the content digest for a policy version's content
/// bytes. This is the canonical digest used for content
/// addressing.
pub fn compute_policy_digest(content_bytes: &[u8]) -> String {
    sha256_hex(content_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty_string_is_well_known() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_of_abc_is_well_known() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn verify_digest_accepts_correct_hash() {
        let content = b"policy-content-v1";
        let hash = sha256_hex(content);
        assert!(verify_digest(content, &hash));
    }

    #[test]
    fn verify_digest_rejects_wrong_hash() {
        let content = b"policy-content-v1";
        assert!(!verify_digest(
            content,
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn verify_digest_is_case_insensitive() {
        let content = b"test";
        let hash = sha256_hex(content);
        let upper: String = hash.chars().map(|c| c.to_ascii_uppercase()).collect();
        assert!(verify_digest(content, &upper));
    }

    #[test]
    fn different_content_different_digest() {
        let d1 = sha256_hex(b"policy-a");
        let d2 = sha256_hex(b"policy-b");
        assert_ne!(d1, d2);
    }

    #[test]
    fn compute_policy_digest_matches_sha256() {
        let content = b"fleet-policy-v42";
        assert_eq!(compute_policy_digest(content), sha256_hex(content));
    }
}
