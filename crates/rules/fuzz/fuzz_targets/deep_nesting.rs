// fuzz_targets/deep_nesting.rs — rules
//
// Deep-nesting fuzz target. Builds an AND-nested condition whose depth is
// derived from the first input byte (bounded to < 80, so iterations always
// terminate and stay under serde_yaml's recursion limit), wraps it in an
// otherwise-valid rule set expressed as JSON (a YAML subset), and parses it.
// Depths above the anchored max_nesting_depth (16) must be rejected with a
// typed nesting error (or a typed schema/YAML error), NEVER a stack overflow
// or panic. The condition is built by bounded string wrapping, so the target
// itself cannot infinite-loop. No unsafe.
//
// Run: cargo fuzz run deep_nesting -- -max_len=65536
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Bounded depth: 0..80. Spans below and above the nesting budget (16)
    // while staying safely under serde_yaml's deserialization recursion limit.
    let depth = data.first().map(|b| (*b as usize) % 80).unwrap_or(0);

    // Leaf condition (valid on its own).
    let mut cond = String::from(r#"{"field":"file.path","operator":"eq","value":"/x"}"#);
    for _ in 0..depth {
        cond = format!(r#"{{"and":[{cond}]}}"#);
    }

    // JSON is a subset of YAML, so this is a valid rule document.
    let yaml = format!(
        r#"{{"schema_version":1,"engine_version":"1.0.0","rules":[{{"id":"r","version":1,"severity":"low","source":"file","description":"d","condition":{cond},"action":"alert"}}]}}"#
    );

    // Deep nesting must be rejected typed (nesting-too-deep / schema / yaml),
    // never panic and never overflow the stack.
    let _ = rules::parse_ruleset(&yaml);
});
