#!/usr/bin/env bash
# bench/comparators/no-agent.sh — baseline comparator (bare workload)
#
# Runs the workload with no wrapper, no agent, no tracing. This is the
# baseline every other comparator is measured against.
#
# Usage:
#   bench/comparators/no-agent.sh --workload NAME --iterations N \
#     --warmup N --ops N [--out FILE]
#
# Output: JSONL with "comparator":"no-agent" injected into each row.
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
usage: bench/comparators/no-agent.sh --workload NAME --iterations N --warmup N --ops N [--out FILE]
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
    *) echo "bench/comparators/no-agent.sh: unknown argument: $1" 1>&2; usage; exit 1 ;;
  esac
done

if [ -z "${WORKLOAD}" ]; then
  echo "bench/comparators/no-agent.sh: --workload is required" 1>&2; exit 1
fi

WORKLOAD_SCRIPT="${WORKSPACE_ROOT}/bench/workloads/${WORKLOAD}.sh"
if [ ! -x "${WORKLOAD_SCRIPT}" ]; then
  echo "bench/comparators/no-agent.sh: workload script not found or not executable: ${WORKLOAD_SCRIPT}" 1>&2
  exit 1
fi

# Run the bare workload and inject the comparator tag.
"${WORKLOAD_SCRIPT}" \
  --iterations "${ITERATIONS}" \
  --warmup "${WARMUP}" \
  --ops "${OPS}" \
  | jq -c --arg c "no-agent" '. + {comparator: $c}' \
  > "${OUT_FILE:-/dev/stdout}"
