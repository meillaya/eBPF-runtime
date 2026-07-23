#!/usr/bin/env bash
# bench/rules-reverse-shell.sh — reverse-shell rule pack precision/recall harness (task 31)
#
# Validates rules/default/reverse-shell.yaml against the rule schema, then
# evaluates every fixture in the fixture corpus against the rule pack using the
# BOUNDED TEMPORAL SEQUENCE engine (task 29) for shell-exec -> socket-connect ->
# stdio-dup correlation, the deterministic PREDICATE engine (task 28) for the
# per-event shell-exec condition and the safe exceptions, computes precision and
# recall, and exits 0 only when both meet the threshold read from the
# rule-budget schema.
#
# Usage:
#   bench/rules-reverse-shell.sh \
#     --schema bench/schemas/rule-budget.v1.json \
#     --fixtures tests/fixtures/reverse-shell/
#
# The precision/recall threshold is read from the schema property
# `fixture_min_precision_and_recall` (default 1.0). The value is NOT hardcoded;
# it flows from the schema file on disk.
#
# A reverse-shell rule FIRES on a fixture when ALL of:
#   (1) SEQUENCE: the rule's bounded temporal sequence completes cleanly —
#       a SequenceMatch with completed=true AND uncertain=false (an uncertain
#       sequence, i.e. a missing/late/out-of-order step, NEVER fires);
#   (2) CONDITION: the deterministic shell-exec condition matches at least one
#       event in the correlated stream;
#   (3) NO EXCEPTION: none of the safe exceptions (SSH/admin port, debug tools,
#       admin/session tools, interactive login-shell argv) matches any event.
# Action is alert/audit only — this harness never produces a deny.
#
# Fixture format (each .json file in --fixtures dir):
#   {
#     "name": "...",
#     "description": "...",
#     "events": [ {"fields": {...}, "null_fields": [...]}, ... ],
#     "expect": { "match": true|false, "rule_id": "..."|null, "action": "..."|null }
#   }
#
# A fixture is a true positive when expect.match=true and a rule fires;
# a true negative when expect.match=false and no rule fires.
# Precision = TP/(TP+FP); Recall = TP/(TP+FN). Both must be >= threshold.
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

# ---- paths -----------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RULE_YAML="${WORKSPACE_ROOT}/rules/default/reverse-shell.yaml"
SCHEMA_PATH=""
FIXTURES_DIR=""

# ---- flag parsing ----------------------------------------------------------
usage() {
  cat <<USAGE 1>&2
usage: bench/rules-reverse-shell.sh --schema PATH --fixtures DIR

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
echo "building rules-cli, predicates-cli, sequences-cli..."
cargo build -q -p rules --bin rules-cli --bin predicates-cli --bin sequences-cli 2>/dev/null

RULES_CLI="${WORKSPACE_ROOT}/target/debug/rules-cli"
PREDICATES_CLI="${WORKSPACE_ROOT}/target/debug/predicates-cli"
SEQUENCES_CLI="${WORKSPACE_ROOT}/target/debug/sequences-cli"

# ---- validate rule YAML ----------------------------------------------------
echo "validating ${RULE_YAML}..."
if ! "${RULES_CLI}" validate "${RULE_YAML}"; then
  echo "FAIL: rule YAML is invalid" >&2; exit 1
fi
echo "rule YAML is valid"

# ---- parse rule YAML to JSON (cached) --------------------------------------
TMPDIR_WORK="$(mktemp -d /tmp/opencode/rs-bench.XXXXXX)"
trap 'rm -rf "${TMPDIR_WORK}"' EXIT

RULESET_JSON="${TMPDIR_WORK}/ruleset.json"
"${RULES_CLI}" parse "${RULE_YAML}" > "${RULESET_JSON}"

RULE_COUNT=$(jq '.rules | length' "${RULESET_JSON}")
echo "parsed ${RULE_COUNT} rule(s) from rule pack"

# Combined sequence definitions from every rule, fed to the sequence engine.
ALL_SEQUENCES="${TMPDIR_WORK}/all_sequences.json"
jq '[.rules[].sequences[]]' "${RULESET_JSON}" > "${ALL_SEQUENCES}"
SEQ_DEF_COUNT=$(jq 'length' "${ALL_SEQUENCES}")
echo "loaded ${SEQ_DEF_COUNT} sequence definition(s) for temporal correlation"

# Pre-extract each rule's condition, lists, exceptions, sequence names, id, action.
for (( ri=0; ri<RULE_COUNT; ri++ )); do
  jq ".rules[${ri}].condition"   "${RULESET_JSON}" > "${TMPDIR_WORK}/rule_${ri}_condition.json"
  jq ".rules[${ri}].lists"       "${RULESET_JSON}" > "${TMPDIR_WORK}/rule_${ri}_lists.json"
  jq ".rules[${ri}].exceptions"  "${RULESET_JSON}" > "${TMPDIR_WORK}/rule_${ri}_exceptions.json"
  jq -c "[.rules[${ri}].sequences[].name]" "${RULESET_JSON}" > "${TMPDIR_WORK}/rule_${ri}_seqnames.json"
  jq -r ".rules[${ri}].id"       "${RULESET_JSON}" > "${TMPDIR_WORK}/rule_${ri}_id.txt"
  jq -r ".rules[${ri}].action"   "${RULESET_JSON}" > "${TMPDIR_WORK}/rule_${ri}_action.txt"
done

# ---- evaluate fixtures -----------------------------------------------------
TP=0; FP=0; FN=0; TN=0
TOTAL=0

for fixture in "${FIXTURES_DIR}"/*.json; do
  [[ -f "${fixture}" ]] || continue
  TOTAL=$((TOTAL + 1))
  fname="$(basename "${fixture}" .json)"

  # Materialize the event stream and each individual event.
  EVENTS_JSON="${TMPDIR_WORK}/events.json"
  jq '.events' "${fixture}" > "${EVENTS_JSON}"
  EVENT_COUNT=$(jq 'length' "${EVENTS_JSON}")
  for (( ei=0; ei<EVENT_COUNT; ei++ )); do
    jq ".[${ei}]" "${EVENTS_JSON}" > "${TMPDIR_WORK}/event_${ei}.json"
  done
  EXPECT_MATCH=$(jq -r '.expect.match' "${fixture}")

  # Correlate the whole event stream against every sequence definition once.
  MATCHES_JSON="${TMPDIR_WORK}/matches.json"
  if ! "${SEQUENCES_CLI}" replay "${EVENTS_JSON}" --sequences "${ALL_SEQUENCES}" > "${MATCHES_JSON}" 2>/dev/null; then
    echo "[]" > "${MATCHES_JSON}"
  fi

  # Evaluate each rule against the correlated stream.
  ACTUAL_MATCH="false"
  FIRED_RULE_ID=""
  FIRED_ACTION=""
  FIRED_EVIDENCE=""

  for (( ri=0; ri<RULE_COUNT; ri++ )); do
    # (1) SEQUENCE: did any of this rule's sequences complete cleanly?
    #     completed=true AND uncertain=false. Uncertain (gap/late/out-of-order)
    #     sequences never fire.
    SEQ_NAMES=$(cat "${TMPDIR_WORK}/rule_${ri}_seqnames.json")
    SEQ_COUNT=$(jq 'length' "${TMPDIR_WORK}/rule_${ri}_seqnames.json")
    if [[ "${SEQ_COUNT}" -gt 0 ]]; then
      SEQ_FIRED=$(jq --argjson names "${SEQ_NAMES}" \
        '[.[] | select(.completed==true and .uncertain==false and ((.sequence_name) as $n | ($names | index($n)) != null))] | length > 0' \
        "${MATCHES_JSON}")
    else
      # No sequences declared: condition-only rule (sequence gate vacuously met).
      SEQ_FIRED="true"
    fi
    if [[ "${SEQ_FIRED}" != "true" ]]; then
      continue
    fi

    # (2) CONDITION: does the deterministic shell-exec condition match any event?
    COND_MATCHED="false"
    for (( ei=0; ei<EVENT_COUNT; ei++ )); do
      COND_RESULT=$("${PREDICATES_CLI}" evaluate \
        "${TMPDIR_WORK}/rule_${ri}_condition.json" \
        --event "${TMPDIR_WORK}/event_${ei}.json" \
        --lists "${TMPDIR_WORK}/rule_${ri}_lists.json" 2>/dev/null) || true
      COND_M=$(echo "${COND_RESULT}" | jq -r '.matched // false')
      if [[ "${COND_M}" == "true" ]]; then
        COND_MATCHED="true"
        break
      fi
    done
    if [[ "${COND_MATCHED}" != "true" ]]; then
      continue
    fi

    # (3) EXCEPTIONS: does any safe exception match any event? If so, suppress.
    EXC_COUNT=$(jq 'length' "${TMPDIR_WORK}/rule_${ri}_exceptions.json")
    EXCEPTION_HIT="false"
    for (( xi=0; xi<EXC_COUNT; xi++ )); do
      EXC_COND="${TMPDIR_WORK}/exc_cond.json"
      jq ".[${xi}]" "${TMPDIR_WORK}/rule_${ri}_exceptions.json" > "${EXC_COND}"
      for (( ei=0; ei<EVENT_COUNT; ei++ )); do
        EXC_RESULT=$("${PREDICATES_CLI}" evaluate \
          "${EXC_COND}" \
          --event "${TMPDIR_WORK}/event_${ei}.json" \
          --lists "${TMPDIR_WORK}/rule_${ri}_lists.json" 2>/dev/null) || true
        EXC_M=$(echo "${EXC_RESULT}" | jq -r '.matched // false')
        if [[ "${EXC_M}" == "true" ]]; then
          EXCEPTION_HIT="true"
          break 2
        fi
      done
    done
    if [[ "${EXCEPTION_HIT}" == "true" ]]; then
      continue  # exception suppressed this rule
    fi

    # Rule fires. Capture evidence (the completed sequence's matched step ids).
    ACTUAL_MATCH="true"
    FIRED_RULE_ID=$(cat "${TMPDIR_WORK}/rule_${ri}_id.txt")
    FIRED_ACTION=$(cat "${TMPDIR_WORK}/rule_${ri}_action.txt")
    FIRED_EVIDENCE=$(jq -r --argjson names "${SEQ_NAMES}" \
      '[.[] | select(.completed==true and .uncertain==false and ((.sequence_name) as $n | ($names | index($n)) != null))][0]
       | .steps | map(.event_id // "?") | join(" -> ")' \
      "${MATCHES_JSON}" 2>/dev/null || echo "")
    break  # first matching rule wins
  done

  # Classify.
  if [[ "${EXPECT_MATCH}" == "true" && "${ACTUAL_MATCH}" == "true" ]]; then
    TP=$((TP + 1))
    echo "  TP  ${fname} -> ${FIRED_RULE_ID} (${FIRED_ACTION})  [${FIRED_EVIDENCE}]"
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
echo "=== reverse-shell rule pack evaluation ==="
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
