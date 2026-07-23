#!/usr/bin/env bash
# bench/enforcement-audit.sh — audit-first LSM deny engine harness (task 33)
#
# Validates the audit-first BPF LSM deny decision logic (bpf/sensors/
# lsm.bpf.c::lsm_decide) against the synthetic fixture corpus in
# tests/fixtures/enforcement/ WITHOUT requiring a privileged BPF load.
# This host cannot load BPF programs (unprivileged_bpf_disabled=2,
# CapEff=0), so the harness reimplements the kernel-side decision
# function deterministically in jq and proves, per fixture, that:
#
#   * audit mode NEVER changes the syscall result (returned == 0);
#   * a supported deny returns the expected errno ONLY for an exact
#     (prefix) authoritative-selector match;
#   * a nonzero prior BPF-program ret is preserved unchanged and is
#     recorded as prior_lsm, NEVER own_lsm;
#   * unsupported/unknown context, a missing map, an empty selector,
#     a family mismatch, and an unknown mode all FAIL OPEN (returned 0)
#     and never produce a false own-denial;
#   * the kill-switch degrades a deny-mode match to audit-only;
#   * the recorded deny source is own program ONLY when the engine
#     returns an errno (decision == deny).
#
# The harness then computes precision/recall over the own-denial class
# (positive = own_denial_recorded) and exits 0 only when both meet the
# threshold read from the schema (NOT hardcoded). The privileged half
# of the acceptance criteria (real syscall-result change, real errno
# delivery, kill-switch p99 latency) is reported as BLOCKED pending the
# declared self-hosted runner.
#
# Usage:
#   bench/enforcement-audit.sh \
#     --schema bench/schemas/enforcement.v1.json \
#     [--fixtures tests/fixtures/enforcement/]
#
# Fixture format (each .json file in --fixtures dir): see the corpus in
# tests/fixtures/enforcement/ — {"name","description","input","expect"}.
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

# ---- paths -----------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SCHEMA_PATH=""
FIXTURES_DIR=""

usage() {
  cat <<USAGE 1>&2
usage: bench/enforcement-audit.sh --schema PATH [--fixtures DIR]

Flags:
  --schema PATH     Path to enforcement schema JSON (reads
                    fixture_min_precision_and_recall, kill_switch_max_ms,
                    kill_switch_benchmark_pairs, audit_first_default_mode).
  --fixtures DIR    Directory containing fixture .json files
                    (default: tests/fixtures/enforcement/).
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --schema)   SCHEMA_PATH="$2"; shift 2 ;;
    --fixtures) FIXTURES_DIR="$2"; shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "error: unknown argument '$1'" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "${SCHEMA_PATH}" ]]; then
  usage; exit 1
fi
[[ "${SCHEMA_PATH}" != /* ]] && SCHEMA_PATH="${WORKSPACE_ROOT}/${SCHEMA_PATH}"
[[ -z "${FIXTURES_DIR}" ]] && FIXTURES_DIR="${WORKSPACE_ROOT}/tests/fixtures/enforcement"
[[ "${FIXTURES_DIR}" != /* ]] && FIXTURES_DIR="${WORKSPACE_ROOT}/${FIXTURES_DIR}"

if [[ ! -f "${SCHEMA_PATH}" ]]; then
  echo "error: schema not found: ${SCHEMA_PATH}" >&2; exit 1
fi
if [[ ! -d "${FIXTURES_DIR}" ]]; then
  echo "error: fixtures dir not found: ${FIXTURES_DIR}" >&2; exit 1
fi

# ---- read constants from schema (NOT hardcoded) ----------------------------
THRESHOLD=$(jq -r '.properties.fixture_min_precision_and_recall.default // 1.0' "${SCHEMA_PATH}")
KILL_MAX_MS=$(jq -r '.properties.kill_switch_max_ms.default // 5000' "${SCHEMA_PATH}")
KILL_PAIRS=$(jq -r '.properties.kill_switch_benchmark_pairs.default // 10' "${SCHEMA_PATH}")
AUDIT_DEFAULT=$(jq -r '.properties.audit_first_default_mode.default // 0' "${SCHEMA_PATH}")
echo "schema:    ${SCHEMA_PATH}"
echo "threshold: fixture_min_precision_and_recall = ${THRESHOLD}"
echo "kill_switch_max_ms       = ${KILL_MAX_MS}"
echo "kill_switch_benchmark_pairs = ${KILL_PAIRS}"
echo "audit_first_default_mode = ${AUDIT_DEFAULT}"

# ---- audit-first invariant: the schema MUST default every policy to audit ---
if [[ "${AUDIT_DEFAULT}" != "0" ]]; then
  echo "FAIL: audit_first_default_mode must be 0 (audit-only); got ${AUDIT_DEFAULT}" >&2
  exit 1
fi
echo "audit-first invariant: schema defaults every policy to audit-only (mode=0)"

# ---- the decision function (mirror of bpf/sensors/lsm.bpf.c::lsm_decide) ----
# Reads a fixture's .input and produces the decision the BPF engine would
# produce: {returned, decision, deny_source, own_denial_recorded,
# result_changed, event_kind}. The branch order is byte-for-byte the C
# engine's order: (1) preserve nonzero prior ret; (2) fail-open on invalid
# selector; (3) missing policy -> allow; (4) family mismatch / empty
# selector -> allow; (5) no prefix match -> allow; (6) audit mode ->
# audit_match (result unchanged); (7) deny mode -> kill-switch check then
# own-denial; (8) unknown mode -> fail-open.
read -r -d '' DECIDE_JQ <<'JQ' || true
def decide:
  .input as $in
  | ($in.prior_ret) as $pr
  | ($in.policy) as $pol
  | ($in.kill_switch.deny_disabled) as $kd
  | if $pr != 0 then
      { returned: $pr, decision: "preserve_prior", deny_source: "prior_lsm",
        own_denial_recorded: false, result_changed: false, event_kind: 15 }
    elif ($in.selector_valid | not) then
      { returned: 0, decision: "fail_open_unknown", deny_source: "none",
        own_denial_recorded: false, result_changed: false, event_kind: 15 }
    elif ($pol.present | not) then
      { returned: 0, decision: "allow", deny_source: "none",
        own_denial_recorded: false, result_changed: false, event_kind: 15 }
    elif ($pol.hook_family != $in.hook_family) or ($pol.selector == "") then
      { returned: 0, decision: "allow", deny_source: "none",
        own_denial_recorded: false, result_changed: false, event_kind: 15 }
    elif ($in.selector | startswith($pol.selector) | not) then
      { returned: 0, decision: "allow", deny_source: "none",
        own_denial_recorded: false, result_changed: false, event_kind: 15 }
    elif $pol.mode == "audit" then
      { returned: 0, decision: "audit_match", deny_source: "none",
        own_denial_recorded: false, result_changed: false, event_kind: 15 }
    elif $pol.mode == "deny" then
      ( if $kd then
          { returned: 0, decision: "deny_suppressed_killswitch", deny_source: "none",
            own_denial_recorded: false, result_changed: false, event_kind: 15 }
        else
          ( (if $pol.deny_errno >= 0 then -13 else $pol.deny_errno end) as $err
            | { returned: $err, decision: "deny", deny_source: "own_lsm",
                own_denial_recorded: true, result_changed: true, event_kind: 15 } )
        end )
    else
      { returned: 0, decision: "fail_open_unknown", deny_source: "none",
        own_denial_recorded: false, result_changed: false, event_kind: 15 }
    end;
decide
JQ

# ---- evaluate fixtures -----------------------------------------------------
TP=0; FP=0; FN=0; TN=0
TOTAL=0; MISMATCH=0
# Invariant violation counters.
V_AUDIT_CHANGED=0      # audit mode changed the syscall result
V_PRIOR_NOT_PRESERVED=0 # nonzero prior ret was not preserved verbatim
V_FALSE_OWN_DENIAL=0   # own-denial recorded without a real own deny
V_FAILOPEN_DENIED=0    # unknown/missing context produced a denial
OWN_WHEN_ALLOWED=0     # own-denial recorded but returned >= 0

for fixture in "${FIXTURES_DIR}"/*.json; do
  [[ -f "${fixture}" ]] || continue
  TOTAL=$((TOTAL + 1))
  fname="$(basename "${fixture}" .json)"

  ACTUAL=$(jq -c "${DECIDE_JQ}" "${fixture}")
  EXPECT=$(jq -c '.expect' "${fixture}")

  # Per-fixture exact match across every expect field.
  if [[ "${ACTUAL}" == "${EXPECT}" ]]; then
    MATCH="ok"
  else
    MATCH="MISMATCH"
    MISMATCH=$((MISMATCH + 1))
  fi

  # Own-denial classification (positive class = own_denial_recorded).
  EXP_OWN=$(jq -r '.expect.own_denial_recorded' "${fixture}")
  ACT_OWN=$(echo "${ACTUAL}" | jq -r '.own_denial_recorded')
  if [[ "${EXP_OWN}" == "true" && "${ACT_OWN}" == "true" ]]; then
    TP=$((TP + 1)); CLASS="TP"
  elif [[ "${EXP_OWN}" == "false" && "${ACT_OWN}" == "false" ]]; then
    TN=$((TN + 1)); CLASS="TN"
  elif [[ "${EXP_OWN}" == "false" && "${ACT_OWN}" == "true" ]]; then
    FP=$((FP + 1)); CLASS="FP"
  else
    FN=$((FN + 1)); CLASS="FN"
  fi

  printf '  %-4s %-40s -> %-26s returned=%s\n' \
    "${CLASS}" "${fname}" \
    "$(echo "${ACTUAL}" | jq -r '.decision')" \
    "$(echo "${ACTUAL}" | jq -r '.returned')"
  if [[ "${MATCH}" == "MISMATCH" ]]; then
    echo "       expected: ${EXPECT}"
    echo "       actual:   ${ACTUAL}"
  fi

  # ---- safety invariants (independent of the expect block) ----
  MODE=$(jq -r '.input.policy.mode' "${fixture}")
  PRIOR=$(jq -r '.input.prior_ret' "${fixture}")
  SEL_VALID=$(jq -r '.input.selector_valid' "${fixture}")
  PRESENT=$(jq -r '.input.policy.present' "${fixture}")
  ACT_RETURNED=$(echo "${ACTUAL}" | jq -r '.returned')
  ACT_DECISION=$(echo "${ACTUAL}" | jq -r '.decision')
  ACT_SRC=$(echo "${ACTUAL}" | jq -r '.deny_source')

  # (a) audit mode never changes the syscall result.
  if [[ "${MODE}" == "audit" && "${PRIOR}" == "0" && "${ACT_RETURNED}" != "0" ]]; then
    V_AUDIT_CHANGED=$((V_AUDIT_CHANGED + 1))
    echo "       INVARIANT VIOLATION: audit mode changed result to ${ACT_RETURNED}"
  fi
  # (b) nonzero prior ret is preserved verbatim.
  if [[ "${PRIOR}" != "0" && "${ACT_RETURNED}" != "${PRIOR}" ]]; then
    V_PRIOR_NOT_PRESERVED=$((V_PRIOR_NOT_PRESERVED + 1))
    echo "       INVARIANT VIOLATION: prior ret ${PRIOR} not preserved (got ${ACT_RETURNED})"
  fi
  if [[ "${PRIOR}" != "0" && "${ACT_SRC}" != "prior_lsm" ]]; then
    V_FALSE_OWN_DENIAL=$((V_FALSE_OWN_DENIAL + 1))
    echo "       INVARIANT VIOLATION: prior-LSM decision labeled ${ACT_SRC} (must be prior_lsm)"
  fi
  # (c) unknown/missing context fails open (never denies).
  if [[ "${SEL_VALID}" == "false" && "${ACT_RETURNED}" != "0" ]]; then
    V_FAILOPEN_DENIED=$((V_FAILOPEN_DENIED + 1))
    echo "       INVARIANT VIOLATION: invalid selector denied (returned ${ACT_RETURNED})"
  fi
  if [[ "${PRESENT}" == "false" && "${ACT_RETURNED}" != "0" ]]; then
    V_FAILOPEN_DENIED=$((V_FAILOPEN_DENIED + 1))
    echo "       INVARIANT VIOLATION: missing policy map denied (returned ${ACT_RETURNED})"
  fi
  # (d) own-denial is recorded ONLY when the engine returns an errno.
  if [[ "${ACT_OWN}" == "true" && "${ACT_RETURNED}" -ge 0 ]]; then
    OWN_WHEN_ALLOWED=$((OWN_WHEN_ALLOWED + 1))
    echo "       INVARIANT VIOLATION: own-denial recorded but returned ${ACT_RETURNED} (>=0)"
  fi
  if [[ "${ACT_SRC}" == "own_lsm" && "${ACT_DECISION}" != "deny" ]]; then
    V_FALSE_OWN_DENIAL=$((V_FALSE_OWN_DENIAL + 1))
    echo "       INVARIANT VIOLATION: deny_source own_lsm with decision ${ACT_DECISION}"
  fi
done

# ---- precision / recall over the own-denial class --------------------------
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
echo "=== enforcement audit-first decision evaluation ==="
echo "fixtures:   ${TOTAL}"
echo "TP=${TP}  FP=${FP}  FN=${FN}  TN=${TN}  (exact-mismatch=${MISMATCH})"
echo "precision:  ${PRECISION}  (own-denial class)"
echo "recall:     ${RECALL}  (own-denial class)"
echo "threshold:  ${THRESHOLD}"
echo ""
echo "safety invariants:"
echo "  audit-mode result changes:      ${V_AUDIT_CHANGED} (must be 0)"
echo "  prior-ret not preserved:        ${V_PRIOR_NOT_PRESERVED} (must be 0)"
echo "  false own-denial attributions:  ${V_FALSE_OWN_DENIAL} (must be 0)"
echo "  fail-open denials:              ${V_FAILOPEN_DENIED} (must be 0)"
echo "  own-denial without errno:       ${OWN_WHEN_ALLOWED} (must be 0)"

# ---- verdict ---------------------------------------------------------------
PASS_PR=$(awk "BEGIN { print (${PRECISION} >= ${THRESHOLD} && ${RECALL} >= ${THRESHOLD}) ? 1 : 0 }")
INVARIANT_OK=1
if [[ $((V_AUDIT_CHANGED + V_PRIOR_NOT_PRESERVED + V_FALSE_OWN_DENIAL + V_FAILOPEN_DENIED + OWN_WHEN_ALLOWED)) -ne 0 ]]; then
  INVARIANT_OK=0
fi
EXACT_OK=1
[[ "${MISMATCH}" -ne 0 ]] && EXACT_OK=0

echo ""
if [[ "${PASS_PR}" == "1" && "${INVARIANT_OK}" == "1" && "${EXACT_OK}" == "1" ]]; then
  echo "verdict:    PASS (precision ${PRECISION}, recall ${RECALL} >= ${THRESHOLD}; all invariants hold; all fixtures exact-match)"
else
  echo "verdict:    FAIL (precision ${PRECISION}, recall ${RECALL}, threshold ${THRESHOLD}, invariants_ok=${INVARIANT_OK}, exact_ok=${EXACT_OK})" >&2
  exit 1
fi

# ---- privileged half: BLOCKED on this host ---------------------------------
# The decision LOGIC above is fully validated by the synthetic corpus. The
# privileged half of the acceptance criteria -- real syscall-result change,
# real errno delivery to userspace, real prior-LSM composition, and the
# kill-switch p99 latency (bench/kill-switch.sh --workloads cpu,net --pairs
# ${KILL_PAIRS}, p99 <= ${KILL_MAX_MS} ms) -- requires loading the BPF LSM
# object, which this host forbids (unprivileged_bpf_disabled=2, CapEff=0).
echo ""
echo "privileged lane: BLOCKED"
echo "  reason:  host cannot load BPF programs (unprivileged_bpf_disabled=2, CapEff=0)"
echo "  deferred: real syscall-result change, errno delivery, prior-LSM composition,"
echo "            kill-switch p99 <= ${KILL_MAX_MS}ms over ${KILL_PAIRS} pairs (bench/kill-switch.sh)"
echo "  re-open on the declared self-hosted / rootful runner."
exit 0
