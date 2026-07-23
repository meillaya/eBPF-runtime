#!/usr/bin/env bash
# bench/comparators/falco.sh — Falco comparator
#
# Runs the workload while Falco is active with its default ruleset.
# Falco uses eBPF/kernel-module probes to monitor syscalls and emits
# alerts when rules match. This measures the overhead of a production
# Falco deployment on the same host.
#
# If falco is not installed the comparator exits 2 (skip) with a note.
# Falco typically requires root and a kernel probe; the comparator
# checks for the binary and exits 2 if unavailable.
#
# Usage:
#   bench/comparators/falco.sh --workload NAME --iterations N \
#     --warmup N --ops N [--out FILE]
#
# Output: JSONL with "comparator":"falco" injected into each row.
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
FALCO_RULES="${FALCO_RULES:-/etc/falco/falco_rules.yaml}"

usage() {
  cat <<USAGE 1>&2
usage: bench/comparators/falco.sh --workload NAME --iterations N --warmup N --ops N [--out FILE]

Environment:
  FALCO_RULES  Path to Falco rules file (default: /etc/falco/falco_rules.yaml).
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
    *) echo "bench/comparators/falco.sh: unknown argument: $1" 1>&2; usage; exit 1 ;;
  esac
done

if [ -z "${WORKLOAD}" ]; then
  echo "bench/comparators/falco.sh: --workload is required" 1>&2; exit 1
fi

WORKLOAD_SCRIPT="${WORKSPACE_ROOT}/bench/workloads/${WORKLOAD}.sh"
if [ ! -x "${WORKLOAD_SCRIPT}" ]; then
  echo "bench/comparators/falco.sh: workload script not found or not executable: ${WORKLOAD_SCRIPT}" 1>&2
  exit 1
fi

if ! command -v falco >/dev/null 2>&1; then
  echo "bench/comparators/falco.sh: SKIP — falco not installed" 1>&2
  echo "bench/comparators/falco.sh: install from https://falco.org/docs/getting-started/" 1>&2
  exit 2
fi

if [ ! -f "${FALCO_RULES}" ]; then
  echo "bench/comparators/falco.sh: SKIP — falco rules not found: ${FALCO_RULES}" 1>&2
  exit 2
fi

# ---- falco lifecycle -------------------------------------------------------
# Start falco in the background with the default ruleset. Falco needs
# root and a kernel probe (eBPF or kernel module).
falco -r "${FALCO_RULES}" --unbuffered &
FALCO_PID=$!

cleanup() {
  if kill -0 "${FALCO_PID}" 2>/dev/null; then
    kill -TERM "${FALCO_PID}" 2>/dev/null || true
    wait "${FALCO_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Give falco time to load its probe and rules.
sleep 2

# ---- run workload ----------------------------------------------------------
"${WORKLOAD_SCRIPT}" \
  --iterations "${ITERATIONS}" \
  --warmup "${WARMUP}" \
  --ops "${OPS}" \
  | jq -c --arg c "falco" '. + {comparator: $c}' \
  > "${OUT_FILE:-/dev/stdout}"
