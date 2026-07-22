#!/usr/bin/env bash
# bench/comparators/observe.sh — agent observe/audit mode comparator
#
# Runs the workload while the kernel-v1 agent is running in dev mode
# (audit-first default: every policy starts at mode=0/audit, the LSM
# hook NEVER changes the syscall result). The agent is started before
# the workload and stopped after.
#
# The agent binary is expected at target/debug/agent (cargo build).
# If the binary is missing the comparator exits 2 (skip) so the
# orchestrator can record a skip note without failing the suite.
#
# Usage:
#   bench/comparators/observe.sh --workload NAME --iterations N \
#     --warmup N --ops N [--out FILE]
#
# Output: JSONL with "comparator":"observe" injected into each row.
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
AGENT_BIN="${AGENT_BIN:-${WORKSPACE_ROOT}/target/debug/agent}"

usage() {
  cat <<USAGE 1>&2
usage: bench/comparators/observe.sh --workload NAME --iterations N --warmup N --ops N [--out FILE]

Environment:
  AGENT_BIN  Path to the agent binary (default: target/debug/agent).
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
    *) echo "bench/comparators/observe.sh: unknown argument: $1" 1>&2; usage; exit 1 ;;
  esac
done

if [ -z "${WORKLOAD}" ]; then
  echo "bench/comparators/observe.sh: --workload is required" 1>&2; exit 1
fi

WORKLOAD_SCRIPT="${WORKSPACE_ROOT}/bench/workloads/${WORKLOAD}.sh"
if [ ! -x "${WORKLOAD_SCRIPT}" ]; then
  echo "bench/comparators/observe.sh: workload script not found or not executable: ${WORKLOAD_SCRIPT}" 1>&2
  exit 1
fi

# ---- agent lifecycle -------------------------------------------------------
if [ ! -x "${AGENT_BIN}" ]; then
  echo "bench/comparators/observe.sh: SKIP — agent binary not found: ${AGENT_BIN}" 1>&2
  echo "bench/comparators/observe.sh: build with 'cargo build -p agent' first" 1>&2
  exit 2
fi

# Start the agent in dev mode (loopback, audit-first default). The agent
# ships every policy at mode=0 (audit); the LSM hook never changes the
# syscall result in this mode. This is the "observe" comparator.
"${AGENT_BIN}" --dev --log-level warn &
AGENT_PID=$!

cleanup() {
  if kill -0 "${AGENT_PID}" 2>/dev/null; then
    kill -TERM "${AGENT_PID}" 2>/dev/null || true
    wait "${AGENT_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Give the agent a moment to bind its loopback listener.
sleep 1

# ---- run workload ----------------------------------------------------------
"${WORKLOAD_SCRIPT}" \
  --iterations "${ITERATIONS}" \
  --warmup "${WARMUP}" \
  --ops "${OPS}" \
  | jq -c --arg c "observe" '. + {comparator: $c}' \
  > "${OUT_FILE:-/dev/stdout}"
