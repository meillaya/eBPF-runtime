// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn expected_sha256_is_well_formed() {
    // EXPECTED_SHA256 must be a 64-char lowercase hex string.
    // If this test fails, the pin has been corrupted and the
    // failure-QA scenario will diverge from the lockfile.
    assert_eq!(
        EXPECTED_SHA256.len(),
        64,
        "EXPECTED_SHA256 must be 64 hex chars"
    );
    assert!(
        EXPECTED_SHA256.chars().all(|c| c.is_ascii_hexdigit()),
        "EXPECTED_SHA256 must be hex"
    );
}

#[test]
fn default_out_dir_is_inside_workspace_target() {
    let p = default_out_dir();
    // The path always ends with target/bpf-out regardless of
    // the CARGO_MANIFEST_DIR value (workspace-relative).
    assert!(
        p.ends_with("target/bpf-out"),
        "default out_dir was {}",
        p.display()
    );
}

#[test]
fn json_escape_handles_quotes_and_backslashes() {
    let s = json_escape("a\"b\\c");
    assert_eq!(s, "a\\\"b\\\\c");
}

#[test]
fn manifest_path_is_inside_default_out_dir() {
    let p = manifest_path();
    assert!(p.ends_with("target/bpf-out/bpf-build.manifest.json"));
}
