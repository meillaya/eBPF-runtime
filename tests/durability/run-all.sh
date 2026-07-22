#!/usr/bin/env bash
# tests/durability/run-all.sh — orchestrator for all durability test suites.
#
# Runs PostgreSQL, Kafka, ClickHouse, and Outbox durability tests
# against live infrastructure and prints a combined summary.
#
# Usage:
#   tests/durability/run-all.sh --schema bench/schemas/durability.v1.json
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SCHEMA_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --schema) SCHEMA_PATH="$2"; shift 2 ;;
    -h|--help) echo "usage: $0 --schema PATH"; exit 0 ;;
    *) echo "error: unknown argument '$1'" >&2; exit 1 ;;
  esac
done

if [[ -z "${SCHEMA_PATH}" ]]; then
  echo "error: --schema PATH required" >&2
  exit 1
fi
[[ "${SCHEMA_PATH}" != /* ]] && SCHEMA_PATH="${WORKSPACE_ROOT}/${SCHEMA_PATH}"

echo "============================================"
echo "  Durability Integration Test Suite"
echo "  schema: ${SCHEMA_PATH}"
echo "============================================"
echo ""

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
SUITES_PASS=0
SUITES_FAIL=0
SUITE_RESULTS=()

run_suite() {
  local name="$1" script="$2"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  SUITE: ${name}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""

  local output
  local exit_code=0
  output=$(bash "${script}" --schema "${SCHEMA_PATH}" 2>&1) || exit_code=$?
  echo "${output}"

  # Extract counts from the summary line.
  local p f s
  p=$(echo "${output}" | grep -oP 'passed: \K[0-9]+' | tail -1 || echo "0")
  f=$(echo "${output}" | grep -oP 'failed: \K[0-9]+' | tail -1 || echo "0")
  s=$(echo "${output}" | grep -oP 'skipped: \K[0-9]+' | tail -1 || echo "0")

  TOTAL_PASS=$((TOTAL_PASS + ${p:-0}))
  TOTAL_FAIL=$((TOTAL_FAIL + ${f:-0}))
  TOTAL_SKIP=$((TOTAL_SKIP + ${s:-0}))

  if [[ ${exit_code} -eq 0 ]]; then
    SUITES_PASS=$((SUITES_PASS + 1))
    SUITE_RESULTS+=("PASS: ${name} (${p} passed, ${f} failed, ${s} skipped)")
  else
    SUITES_FAIL=$((SUITES_FAIL + 1))
    SUITE_RESULTS+=("FAIL: ${name} (${p} passed, ${f} failed, ${s} skipped)")
  fi
}

# ---- run all suites ----------------------------------------------------------
run_suite "PostgreSQL" "${SCRIPT_DIR}/postgresql.sh"
run_suite "Kafka" "${SCRIPT_DIR}/kafka.sh"
run_suite "ClickHouse" "${SCRIPT_DIR}/clickhouse.sh"
run_suite "Outbox" "${SCRIPT_DIR}/outbox.sh"

# ---- combined summary --------------------------------------------------------
echo ""
echo "============================================"
echo "  COMBINED DURABILITY SUMMARY"
echo "============================================"
echo ""
for result in "${SUITE_RESULTS[@]}"; do
  echo "  ${result}"
done
echo ""
echo "  total passed:  ${TOTAL_PASS}"
echo "  total failed:  ${TOTAL_FAIL}"
echo "  total skipped: ${TOTAL_SKIP}"
echo "  suites passed: ${SUITES_PASS}/4"
echo ""

if [[ ${TOTAL_FAIL} -gt 0 ]] || [[ ${SUITES_FAIL} -gt 0 ]]; then
  echo "DURABILITY SUITE: FAIL"
  exit 1
fi

echo "DURABILITY SUITE: PASS"
exit 0
