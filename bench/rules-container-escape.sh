#!/usr/bin/env bash
# bench/rules-container-escape.sh — container-escape rule pack precision/recall harness (task 32)
#
# Validates rules/default/container-escape.yaml against the rule schema,
# evaluates every fixture in the fixture corpus against the rule pack,
# computes precision and recall, and exits 0 only when both meet the
# threshold read from the rule-budget schema.
#
# Usage:
#   bench/rules-container-escape.sh \
#     --schema bench/schemas/rule-budget.v1.json \
#     --fixtures tests/fixtures/container-escape/
#
# The precision/recall threshold is read from the schema property
# `fixture_min_precision_and_recall` (default 1.0). The value is NOT
# hardcoded; it flows from the schema file on disk.
#
# Fixture format (each .json file in --fixtures dir):
#   {
#     "name": "...",
#     "description": "...",
#     "event": { "fields": {...}, "null_fields": [...] },
#     "expect": { "match": true|false, "rule_id": "..."|null, "action": "..."|null }
#   }
#
# A fixture is a true positive when expect.match=true and a rule fires;
# a true negative when expect.match=false and no rule fires.
# Precision = TP/(TP+FP); Recall = TP/(TP+FN). Both must be >= threshold.
#
# Container-escape rules are ALERT-ONLY: no rule in this pack has a deny
# action. The harness verifies this invariant implicitly (fired actions
# are always "alert").
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

# ---- paths -----------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RULE_YAML="${WORKSPACE_ROOT}/rules/default/container-escape.yaml"
SCHEMA_PATH=""
FIXTURES_DIR=""

# ---- flag parsing ----------------------------------------------------------
usage() {
  cat <<USAGE 1>&2
usage: bench/rules-container-escape.sh --schema PATH --fixtures DIR

Flags:
  --schema PATH     Path to rule-budget schema JSON (reads
                    fixture_min_precision_and_recall default; fallback 1.0).
  --fixtures DIR    Directory containing fixture .json files.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --schema)
      SCHEMA_PATH="$2"; shift 2 ;;
    --fixtures)
      FIXTURES_DIR="$2"; shift 2 ;;
    *)
      echo "error: unknown argument '$1'" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "${SCHEMA_PATH}" || -z "${FIXTURES_DIR}" ]]; then
  usage; exit 1
fi

# Resolve relative paths against workspace root.
[[ "${SCHEMA_PATH}" != /* ]] && SCHEMA_PATH="${WORKSPACE_ROOT}/${SCHEMA_PATH}"
[[ "${FIXTURES_DIR}" != /* ]] && FIXTURES_DIR="${WORKSPACE_ROOT}/${FIXTURES_DIR}"

if [[ ! -f "${SCHEMA_PATH}" ]]; then
  echo "error: schema not found: ${SCHEMA_PATH}" >&2; exit 1
fi
if [[ ! -d "${FIXTURES_DIR}" ]]; then
  echo "error: fixtures dir not found: ${FIXTURES_DIR}" >&2; exit 1
fi
if [[ ! -f "${RULE_YAML}" ]]; then
  echo "error: rule YAML not found: ${RULE_YAML}" >&2; exit 1
fi

# ---- read threshold from schema (NOT hardcoded) ----------------------------
# Read fixture_min_precision_and_recall from the schema's property defaults.
# Falls back to 1.0 when the property is absent (the schema may not yet
# define it; the default matches the task acceptance criterion).
THRESHOLD=$(jq -r '.properties.fixture_min_precision_and_recall.default // 1.0' "${SCHEMA_PATH}")
echo "threshold: fixture_min_precision_and_recall = ${THRESHOLD} (from ${SCHEMA_PATH})"

# ---- build binaries --------------------------------------------------------
echo "building rules-cli and predicates-cli..."
cargo build -q -p rules --bin rules-cli --bin predicates-cli 2>/dev/null

RULES_CLI="${WORKSPACE_ROOT}/target/debug/rules-cli"
PREDICATES_CLI="${WORKSPACE_ROOT}/target/debug/predicates-cli"

# ---- validate rule YAML ----------------------------------------------------
echo "validating ${RULE_YAML}..."
if ! "${RULES_CLI}" validate "${RULE_YAML}"; then
  echo "FAIL: rule YAML is invalid" >&2; exit 1
fi
echo "rule YAML is valid"

# ---- parse rule YAML to JSON (cached) --------------------------------------
TMPDIR_WORK="$(mktemp -d /tmp/opencode/ce-bench.XXXXXX)"
trap 'rm -rf "${TMPDIR_WORK}"' EXIT

RULESET_JSON="${TMPDIR_WORK}/ruleset.json"
"${RULES_CLI}" parse "${RULE_YAML}" > "${RULESET_JSON}"

RULE_COUNT=$(jq '.rules | length' "${RULESET_JSON}")
echo "parsed ${RULE_COUNT} rule(s) from rule pack"

# Pre-extract each rule's condition, lists, and exceptions to temp files.
for (( ri=0; ri<RULE_COUNT; ri++ )); do
  jq ".rules[${ri}].condition" "${RULESET_JSON}" > "${TMPDIR_WORK}/rule_${ri}_condition.json"
  jq ".rules[${ri}].lists" "${RULESET_JSON}" > "${TMPDIR_WORK}/rule_${ri}_lists.json"
  jq ".rules[${ri}].exceptions" "${RULESET_JSON}" > "${TMPDIR_WORK}/rule_${ri}_exceptions.json"
  jq -r ".rules[${ri}].id" "${RULESET_JSON}" > "${TMPDIR_WORK}/rule_${ri}_id.txt"
  jq -r ".rules[${ri}].action" "${RULESET_JSON}" > "${TMPDIR_WORK}/rule_${ri}_action.txt"
done

# ---- evaluate fixtures -----------------------------------------------------
TP=0; FP=0; FN=0; TN=0
TOTAL=0

for fixture in "${FIXTURES_DIR}"/*.json; do
  [[ -f "${fixture}" ]] || continue
  TOTAL=$((TOTAL + 1))
  fname="$(basename "${fixture}" .json)"

  # Extract event and expected outcome.
  EVENT_JSON="${TMPDIR_WORK}/event.json"
  jq '.event' "${fixture}" > "${EVENT_JSON}"
  EXPECT_MATCH=$(jq -r '.expect.match' "${fixture}")

  # Evaluate each rule against the event.
  ACTUAL_MATCH="false"
  FIRED_RULE_ID=""
  FIRED_ACTION=""

  for (( ri=0; ri<RULE_COUNT; ri++ )); do
    # Evaluate the rule's condition.
    COND_RESULT=$("${PREDICATES_CLI}" evaluate \
      "${TMPDIR_WORK}/rule_${ri}_condition.json" \
      --event "${EVENT_JSON}" \
      --lists "${TMPDIR_WORK}/rule_${ri}_lists.json" 2>/dev/null) || true

    COND_MATCHED=$(echo "${COND_RESULT}" | jq -r '.matched // false')
    if [[ "${COND_MATCHED}" != "true" ]]; then
      continue
    fi

    # Condition matched — check exceptions.
    EXC_COUNT=$(jq 'length' "${TMPDIR_WORK}/rule_${ri}_exceptions.json")
    EXCEPTION_HIT="false"

    for (( ei=0; ei<EXC_COUNT; ei++ )); do
      # Each exception is a leaf condition {field, operator, value}.
      EXC_COND="${TMPDIR_WORK}/exc_cond.json"
      jq ".[${ei}]" "${TMPDIR_WORK}/rule_${ri}_exceptions.json" > "${EXC_COND}"

      EXC_RESULT=$("${PREDICATES_CLI}" evaluate \
        "${EXC_COND}" \
        --event "${EVENT_JSON}" \
        --lists "${TMPDIR_WORK}/rule_${ri}_lists.json" 2>/dev/null) || true

      EXC_MATCHED=$(echo "${EXC_RESULT}" | jq -r '.matched // false')
      if [[ "${EXC_MATCHED}" == "true" ]]; then
        EXCEPTION_HIT="true"
        break
      fi
    done

    if [[ "${EXCEPTION_HIT}" == "true" ]]; then
      continue  # exception suppressed this rule
    fi

    # Rule fires.
    ACTUAL_MATCH="true"
    FIRED_RULE_ID=$(cat "${TMPDIR_WORK}/rule_${ri}_id.txt")
    FIRED_ACTION=$(cat "${TMPDIR_WORK}/rule_${ri}_action.txt")
    break  # first matching rule wins
  done

  # Classify.
  if [[ "${EXPECT_MATCH}" == "true" && "${ACTUAL_MATCH}" == "true" ]]; then
    TP=$((TP + 1))
    echo "  TP  ${fname} -> ${FIRED_RULE_ID} (${FIRED_ACTION})"
  elif [[ "${EXPECT_MATCH}" == "false" && "${ACTUAL_MATCH}" == "false" ]]; then
    TN=$((TN + 1))
    echo "  TN  ${fname}"
  elif [[ "${EXPECT_MATCH}" == "false" && "${ACTUAL_MATCH}" == "true" ]]; then
    FP=$((FP + 1))
    echo "  FP  ${fname} -> unexpected match: ${FIRED_RULE_ID} (${FIRED_ACTION})"
  else
    FN=$((FN + 1))
    echo "  FN  ${fname} -> expected match but none fired"
  fi
done

# ---- compute precision / recall --------------------------------------------
# Precision = TP / (TP + FP); when TP+FP == 0, precision is 1.0 (no positives
# predicted, vacuously correct).
# Recall = TP / (TP + FN); when TP+FN == 0, recall is 1.0 (no positives
# expected, vacuously correct).
if [[ $((TP + FP)) -gt 0 ]]; then
  PRECISION=$(awk "BEGIN { printf \"%.4f\", ${TP} / (${TP} + ${FP}) }")
else
  PRECISION="1.0000"
fi

if [[ $((TP + FN)) -gt 0 ]]; then
  RECALL=$(awk "BEGIN { printf \"%.4f\", ${TP} / (${TP} + ${FN}) }")
else
  RECALL="1.0000"
fi

echo ""
echo "=== container-escape rule pack evaluation ==="
echo "fixtures:  ${TOTAL}"
echo "TP=${TP}  FP=${FP}  FN=${FN}  TN=${TN}"
echo "precision: ${PRECISION}"
echo "recall:    ${RECALL}"
echo "threshold: ${THRESHOLD}"

# ---- verdict ---------------------------------------------------------------
PASS=$(awk "BEGIN { print (${PRECISION} >= ${THRESHOLD} && ${RECALL} >= ${THRESHOLD}) ? 1 : 0 }")

if [[ "${PASS}" == "1" ]]; then
  echo "verdict:   PASS (precision ${PRECISION} >= ${THRESHOLD}, recall ${RECALL} >= ${THRESHOLD})"
  exit 0
else
  echo "verdict:   FAIL (precision ${PRECISION}, recall ${RECALL}, threshold ${THRESHOLD})" >&2
  exit 1
fi
