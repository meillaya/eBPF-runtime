#!/usr/bin/env bash
# bench/comparators/enforce.sh — agent enforce/deny mode comparator
#
# Runs the workload while the kernel-v1 agent is running in dev mode
# with a deny policy active. The deny policy is loaded via the agent's
# policy API; the LSM hook returns EACCES for matching selectors.
#
# NOTE: The current agent binary does not expose a --mode enforce CLI
# flag. Enforcement is controlled via the policy map (audit_first_
# default_mode=0 → deny via staged commit). This comparator starts the
# agent in dev mode and documents that a deny policy must be loaded
# through the control-plane API for a true enforce-mode measurement.
# Until the policy-loading API is wired into the bench harness, this
# comparator runs the agent in dev mode (same as observe) and tags the
# output as "enforce" so the analysis pipeline has a placeholder row.
# The orchestrator records this caveat in the run metadata.
#
# The agent binary is expected at target/debug/agent (cargo build).
# If the binary is missing the comparator exits 2 (skip).
#
# Usage:
#   bench/comparators/enforce.sh --workload NAME --iterations N \
#     --warmup N --ops N [--out FILE]
#
# Output: JSONL with "comparator":"enforce" injected into each row.
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
usage: bench/comparators/enforce.sh --workload NAME --iterations N --warmup N --ops N [--out FILE]

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
    *) echo "bench/comparators/enforce.sh: unknown argument: $1" 1>&2; usage; exit 1 ;;
  esac
done

if [ -z "${WORKLOAD}" ]; then
  echo "bench/comparators/enforce.sh: --workload is required" 1>&2; exit 1
fi

WORKLOAD_SCRIPT="${WORKSPACE_ROOT}/bench/workloads/${WORKLOAD}.sh"
if [ ! -x "${WORKLOAD_SCRIPT}" ]; then
  echo "bench/comparators/enforce.sh: workload script not found or not executable: ${WORKLOAD_SCRIPT}" 1>&2
  exit 1
fi

# ---- agent lifecycle -------------------------------------------------------
if [ ! -x "${AGENT_BIN}" ]; then
  echo "bench/comparators/enforce.sh: SKIP — agent binary not found: ${AGENT_BIN}" 1>&2
  echo "bench/comparators/enforce.sh: build with 'cargo build -p agent' first" 1>&2
  exit 2
fi

# Start the agent in dev mode. A deny policy would be loaded via the
# control-plane API; until that is wired in, this measures the agent
# process overhead with the policy map present (audit-first default).
"${AGENT_BIN}" --dev --log-level warn &
AGENT_PID=$!

cleanup() {
  if kill -0 "${AGENT_PID}" 2>/dev/null; then
    kill -TERM "${AGENT_PID}" 2>/dev/null || true
    wait "${AGENT_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

sleep 1

# ---- run workload ----------------------------------------------------------
"${WORKLOAD_SCRIPT}" \
  --iterations "${ITERATIONS}" \
  --warmup "${WARMUP}" \
  --ops "${OPS}" \
  | jq -c --arg c "enforce" '. + {comparator: $c}' \
  > "${OUT_FILE:-/dev/stdout}"
