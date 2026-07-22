// fuzz_targets/parse_yaml.rs — rules
//
// Primary rule-parse fuzz target. Feeds arbitrary bytes (rendered lossily as
// UTF-8 so hostile YAML, YAML-injection attempts, malformed documents, and
// non-YAML garbage all reach the parser) into `rules::parse_ruleset`. The
// parser must be TOTAL: it returns a typed `Ok(RuleSet)` or a typed
// `RuleError` and NEVER panics. A panic here is a fuzzer-found bug. No unsafe.
//
// Run: cargo fuzz run parse_yaml -- -max_len=65536
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    // Must produce a typed result for any input, never panic.
    let _ = rules::parse_ruleset(&input);
});
