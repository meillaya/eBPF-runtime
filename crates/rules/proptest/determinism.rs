// proptest/determinism.rs — rules
//
// Property tests for the rules parser / predicate-evaluator boundaries
// (task: fuzz & property-test parser boundaries):
//
//   1. PREDICATE-EVALUATION DETERMINISM — evaluating the same condition + event
//      twice under the same budget yields an identical result (same input ->
//      same output), whether Ok or a typed Err.
//   2. PARSE DETERMINISM — `parse_ruleset` on the same arbitrary string yields
//      an identical outcome twice (YAML injection / malformed input never
//      diverges).
//   3. SERIALIZE/PARSE ROUNDTRIP — a valid rule set survives
//      serialize -> parse -> serialize byte-for-byte (encode -> decode ->
//      encode == same bytes) and the AST is unchanged.
//
// Results are compared by their `Debug` rendering because `RuleError` is
// intentionally not `PartialEq`; debug-equality still proves determinism.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use proptest::prelude::*;

use rules::predicates::{default_budget, PredicateEvaluator};
use rules::{parse_ruleset, serialize_ruleset};

use crate::strategies::{arb_condition, arb_event, arb_input_string, arb_valid_ruleset};

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1000, // anchored corpus_size default (bench/schemas/fuzz.v1.json)
        .. ProptestConfig::default()
    })]

    /// PREDICATE-EVALUATION DETERMINISM: same condition + event + budget ->
    /// identical result on repeated evaluation.
    #[test]
    fn predicate_evaluation_is_deterministic(cond in arb_condition(), event in arb_event()) {
        let evaluator = PredicateEvaluator::new(default_budget());
        let r1 = evaluator.evaluate_condition(&cond, &event, &[]);
        let r2 = evaluator.evaluate_condition(&cond, &event, &[]);
        prop_assert_eq!(
            format!("{r1:?}"),
            format!("{r2:?}"),
            "predicate evaluation must be deterministic"
        );
    }

    /// PARSE DETERMINISM: same arbitrary input string -> identical parse
    /// outcome (Ok AST or typed Err) on repeated parsing.
    #[test]
    fn parse_is_deterministic(input in arb_input_string()) {
        let r1 = parse_ruleset(&input);
        let r2 = parse_ruleset(&input);
        prop_assert_eq!(
            format!("{r1:?}"),
            format!("{r2:?}"),
            "parse_ruleset must be deterministic"
        );
    }

    /// SERIALIZE/PARSE ROUNDTRIP STABILITY: a valid rule set survives
    /// serialize -> parse -> serialize byte-for-byte, and the AST is unchanged.
    #[test]
    fn serialize_parse_roundtrip_is_stable(rs in arb_valid_ruleset()) {
        let yaml1 = serialize_ruleset(&rs).expect("valid rule set must serialize");
        let rs2 = parse_ruleset(&yaml1).expect("serialized valid rule set must re-parse");
        let yaml2 = serialize_ruleset(&rs2).expect("re-parsed rule set must serialize");
        prop_assert_eq!(yaml1, yaml2, "encode -> decode -> encode must be byte-stable");
        prop_assert_eq!(rs, rs2, "AST must be unchanged by the roundtrip");
    }
}
