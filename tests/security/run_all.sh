#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Orchestrator: runs all adversarial security test suites and aggregates
# evidence into a single JSONL file with a summary.
#
# Usage: bash tests/security/run_all.sh
# Requires: bash, jq, openssl, curl, podman (or PSQL_CMD override)
#
# Environment overrides:
#   PSQL_CMD    — psql command (default: podman exec -i k1-postgres psql)
#   PG_USER     — PostgreSQL user (default: control_app)
#   PG_DB       — PostgreSQL database (default: kernel_v1)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
EVIDENCE_DIR="${REPO_ROOT}/.omo/evidence"
mkdir -p "${EVIDENCE_DIR}"

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
COMBINED_EVIDENCE="${EVIDENCE_DIR}/security-all-${TIMESTAMP}.jsonl"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  kernel-v1 Adversarial Security Integration Tests        ║"
echo "║  $(date -u +%Y-%m-%dT%H:%M:%SZ)                                    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Pre-flight: check infrastructure
echo "--- Pre-flight checks ---"
PG_OK=false
DEX_OK=false

if ${PSQL_CMD:-podman exec -i k1-postgres psql} -U "${PG_USER:-control_app}" -d "${PG_DB:-kernel_v1}" -t -A -c "SELECT 1;" 2>/dev/null | grep -q 1; then
  echo "  [OK] PostgreSQL reachable"
  PG_OK=true
else
  echo "  [FAIL] PostgreSQL NOT reachable"
fi

if curl -sf -o /dev/null "http://127.0.0.1:5556/dex/.well-known/openid-configuration" 2>/dev/null; then
  echo "  [OK] Dex OIDC reachable"
  DEX_OK=true
else
  echo "  [WARN] Dex OIDC NOT reachable — live OIDC tests will be DEFERRED"
fi

echo "  [INFO] SPIRE NOT running — SPIFFE tests DEFERRED"
echo ""

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
TOTAL_DEFERRED=0
SUITES_FAILED=0

run_suite() {
  local name="$1" script="$2"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  SUITE: ${name}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  local suite_evidence="${EVIDENCE_DIR}/security-${name}-${TIMESTAMP}.jsonl"

  # Each suite sources lib.sh which writes to EVIDENCE_FILE.
  # Override EVIDENCE_FILE for per-suite isolation.
  if EVIDENCE_FILE="${suite_evidence}" bash "${script}"; then
    echo "  → Suite ${name}: ALL PASS"
  else
    echo "  → Suite ${name}: FAILURES DETECTED"
    SUITES_FAILED=$((SUITES_FAILED + 1))
  fi

  # Append suite evidence to combined file
  if [ -f "${suite_evidence}" ]; then
    cat "${suite_evidence}" >> "${COMBINED_EVIDENCE}"
    # Count results (grep -c exits 1 on zero matches; capture cleanly)
    local p f s d
    p=$(grep -c '"result":"PASS"' "${suite_evidence}" 2>/dev/null) || p=0
    f=$(grep -c '"result":"FAIL"' "${suite_evidence}" 2>/dev/null) || f=0
    s=$(grep -c '"result":"SKIP"' "${suite_evidence}" 2>/dev/null) || s=0
    d=$(grep -c '"result":"DEFERRED"' "${suite_evidence}" 2>/dev/null) || d=0
    TOTAL_PASS=$((TOTAL_PASS + p))
    TOTAL_FAIL=$((TOTAL_FAIL + f))
    TOTAL_SKIP=$((TOTAL_SKIP + s))
    TOTAL_DEFERRED=$((TOTAL_DEFERRED + d))
  fi
  echo ""
}

# Run suites in order
run_suite "oidc"       "${SCRIPT_DIR}/oidc_tokens.sh"
run_suite "rbac"       "${SCRIPT_DIR}/rbac_matrix.sh"
run_suite "postgres"   "${SCRIPT_DIR}/postgres_security.sh"
run_suite "policy"     "${SCRIPT_DIR}/policy_protocol.sh"

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------
TOTAL=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP + TOTAL_DEFERRED))

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  FINAL SECURITY TEST SUMMARY                            ║"
echo "╠═══════════════════════════════════════════════════════════╣"
printf "║  Total:    %-44s ║\n" "${TOTAL}"
printf "║  Pass:     %-44s ║\n" "${TOTAL_PASS}"
printf "║  Fail:     %-44s ║\n" "${TOTAL_FAIL}"
printf "║  Skip:     %-44s ║\n" "${TOTAL_SKIP}"
printf "║  Deferred: %-44s ║\n" "${TOTAL_DEFERRED}"
printf "║  Suites failed: %-38s ║\n" "${SUITES_FAILED}"
echo "╠═══════════════════════════════════════════════════════════╣"
printf "║  Evidence: %-44s ║\n" "$(basename "${COMBINED_EVIDENCE}")"
echo "╚═══════════════════════════════════════════════════════════╝"

# Write summary as final evidence line
jq -cn \
  --argjson total "${TOTAL}" \
  --argjson pass "${TOTAL_PASS}" \
  --argjson fail "${TOTAL_FAIL}" \
  --argjson skip "${TOTAL_SKIP}" \
  --argjson deferred "${TOTAL_DEFERRED}" \
  --argjson suites_failed "${SUITES_FAILED}" \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{test_id:"SUMMARY", category:"all", name:"security suite summary", result:(if $fail > 0 then "FAIL" else "PASS" end), detail:"total=\($total) pass=\($pass) fail=\($fail) skip=\($skip) deferred=\($deferred) suites_failed=\($suites_failed)", timestamp:$ts}' \
  >> "${COMBINED_EVIDENCE}"

# Exit non-zero if any failures
if [ "${TOTAL_FAIL}" -gt 0 ]; then
  echo ""
  echo "SECURITY FAILURES DETECTED — review evidence: ${COMBINED_EVIDENCE}"
  exit 1
fi

echo ""
echo "All security tests passed (or deferred). Evidence: ${COMBINED_EVIDENCE}"
exit 0
