// fuzz_targets/regex_boundary.rs — rules
//
// Catastrophic-regex fuzz target. Embeds the arbitrary input as the pattern of
// a `regex` condition inside an otherwise-valid rule set, then parses it. This
// drives the bounded-regex validator (size <= MAX_REGEX_BYTES, capture-group
// and unbounded/nested-quantifier rejection, compilation) with hostile
// patterns. `parse_ruleset` must reject too-large / too-complex patterns with
// a typed `RegexTooLarge`/`RegexTooComplex`/`InvalidRegex` error and NEVER
// panic or hang (the regex engine is linear-time; compilation is bounded).
// The pattern is YAML-escaped (single-quoted, `'` -> `''`); if the escaping
// yields invalid YAML for some input, that is a typed `YamlError`, still a
// valid no-panic outcome. No unsafe.
//
// Run: cargo fuzz run regex_boundary -- -max_len=65536
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let pattern = String::from_utf8_lossy(data);
    // YAML single-quoted scalar escape: a literal quote is doubled.
    let escaped = pattern.replace('\'', "''");
    let yaml = format!(
        "schema_version: 1
engine_version: \"1.0.0\"
rules:
  - id: r
    version: 1
    severity: low
    source: file
    description: d
    condition:
      field: file.path
      operator: regex
      value: '{escaped}'
    action: alert
"
    );
    // Must yield a typed result (regex bounds reject catastrophic patterns),
    // never panic and never hang.
    let _ = rules::parse_ruleset(&yaml);
});
