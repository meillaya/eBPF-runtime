#!/usr/bin/env bash
# bench/comparators/strace.sh — strace comparator
#
# Runs the workload under strace -f -e trace=all -o /dev/null. This
# measures the overhead of full syscall tracing (the traditional
# "how bad is strace" baseline). strace uses ptrace(2) which stops
# the tracee on every syscall entry/exit.
#
# If strace is not installed the comparator exits 2 (skip).
#
# Usage:
#   bench/comparators/strace.sh --workload NAME --iterations N \
#     --warmup N --ops N [--out FILE]
#
# Output: JSONL with "comparator":"strace" injected into each row.
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

usage() {
  cat <<USAGE 1>&2
usage: bench/comparators/strace.sh --workload NAME --iterations N --warmup N --ops N [--out FILE]
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
    *) echo "bench/comparators/strace.sh: unknown argument: $1" 1>&2; usage; exit 1 ;;
  esac
done

if [ -z "${WORKLOAD}" ]; then
  echo "bench/comparators/strace.sh: --workload is required" 1>&2; exit 1
fi

WORKLOAD_SCRIPT="${WORKSPACE_ROOT}/bench/workloads/${WORKLOAD}.sh"
if [ ! -x "${WORKLOAD_SCRIPT}" ]; then
  echo "bench/comparators/strace.sh: workload script not found or not executable: ${WORKLOAD_SCRIPT}" 1>&2
  exit 1
fi

if ! command -v strace >/dev/null 2>&1; then
  echo "bench/comparators/strace.sh: SKIP — strace not installed" 1>&2
  exit 2
fi

# Run the workload under strace. -f follows forks (python3 threads),
# -e trace=all traces every syscall class, -o /dev/null discards the
# trace output so we measure pure ptrace overhead.
strace -f -e trace=all -o /dev/null -- \
  "${WORKLOAD_SCRIPT}" \
    --iterations "${ITERATIONS}" \
    --warmup "${WARMUP}" \
    --ops "${OPS}" \
  | jq -c --arg c "strace" '. + {comparator: $c}' \
  > "${OUT_FILE:-/dev/stdout}"
