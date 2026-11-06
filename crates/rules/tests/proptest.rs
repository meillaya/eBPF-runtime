// tests/proptest.rs: rules
//
// Integration-test harness that wires the rules property-test modules under
// `crates/rules/proptest/` into the `cargo test` binary. The strategies and
// the `proptest!` blocks live in the `proptest/` directory (the canonical
// location for the rules property tests); this file only attaches them via
// `#[path]` so they run under `cargo test -p rules` / `cargo test --workspace`.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[path = "../proptest/strategies.rs"]
mod strategies;

#[path = "../proptest/determinism.rs"]
mod determinism;
