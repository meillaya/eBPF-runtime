#!/usr/bin/env bash
# bench/comparators/auditd.sh — auditd comparator
#
# Runs the workload while auditd watches the bench scratch directory
# with -p wa (write + attribute change). This measures the overhead of
# the kernel audit subsystem on the same paths the workload touches.
#
# Requires root (auditctl needs CAP_AUDIT_CONTROL). If auditctl is not
# available or the user is not root, the comparator exits 2 (skip).
#
# Usage:
#   bench/comparators/auditd.sh --workload NAME --iterations N \
#     --warmup N --ops N [--out FILE]
#
# Output: JSONL with "comparator":"auditd" injected into each row.
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

WORKLOAD=""
ITERATIONS=""
WARMUP=""
OPS=""
OUT_FILE=""
WATCH_DIR="${BENCH_WATCH_DIR:-/tmp/bench-auditd}"

usage() {
  cat <<USAGE 1>&2
usage: bench/comparators/auditd.sh --workload NAME --iterations N --warmup N --ops N [--out FILE]

Environment:
  BENCH_WATCH_DIR  Directory auditd watches (default: /tmp/bench-auditd).
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --workload)   [ $# -ge 2 ] || { usage; exit 1; }; WORKLOAD="$2"; shift 2 ;;
    --iterations) [ $# -ge 2 ] || { usage; exit 1; }; ITERATIONS="$2"; shift 2 ;;
    --warmup)     [ $# -ge 2 ] || { usage; exit 1; }; WARMUP="$2"; shift 2 ;;
    --ops)        [ $# -ge 2 ] || { usage; exit 1; }; OPS="$2"; shift 2 ;;
    --out)        [ $# -ge 2 ] || { usage; exit 1; }; OUT_FILE="$2"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "bench/comparators/auditd.sh: unknown argument: $1" 1>&2; usage; exit 1 ;;
  esac
done

if [ -z "${WORKLOAD}" ]; then
  echo "bench/comparators/auditd.sh: --workload is required" 1>&2; exit 1
fi

WORKLOAD_SCRIPT="${WORKSPACE_ROOT}/bench/workloads/${WORKLOAD}.sh"
if [ ! -x "${WORKLOAD_SCRIPT}" ]; then
  echo "bench/comparators/auditd.sh: workload script not found or not executable: ${WORKLOAD_SCRIPT}" 1>&2
  exit 1
fi

if ! command -v auditctl >/dev/null 2>&1; then
  echo "bench/comparators/auditd.sh: SKIP — auditctl not installed" 1>&2
  exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "bench/comparators/auditd.sh: SKIP — auditctl requires root (CAP_AUDIT_CONTROL)" 1>&2
  exit 2
fi

# ---- audit watch lifecycle -------------------------------------------------
mkdir -p "${WATCH_DIR}"
auditctl -w "${WATCH_DIR}" -p wa -k bench_auditd

cleanup() {
  auditctl -d "${WATCH_DIR}" -p wa -k bench_auditd 2>/dev/null || true
}
trap cleanup EXIT

# ---- run workload ----------------------------------------------------------
"${WORKLOAD_SCRIPT}" \
  --iterations "${ITERATIONS}" \
  --warmup "${WARMUP}" \
  --ops "${OPS}" \
  | jq -c --arg c "auditd" '. + {comparator: $c}' \
  > "${OUT_FILE:-/dev/stdout}"
