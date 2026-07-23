#!/usr/bin/env bash
# bench/workloads/syscall.sh — deterministic syscall-heavy workload generator
#
# Tight loop of getpid / gettimeofday / open / close / stat syscalls via
# python3 os module. Each iteration performs ops_per_iteration syscall
# batches; per-batch latency is measured with time.perf_counter_ns().
# Deterministic: fixed syscall sequence, fixed temp file path.
#
# Usage:
#   bench/workloads/syscall.sh --iterations N --warmup N --ops N [--out FILE]
#
# Output: one JSONL row per measured iteration to stdout (or --out FILE).
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCHEMA_PATH="${WORKSPACE_ROOT}/bench/schemas/runs.v1.json"

ITERATIONS=""
WARMUP=""
OPS=""
OUT_FILE=""

usage() {
  cat <<USAGE 1>&2
usage: bench/workloads/syscall.sh --iterations N --warmup N --ops N [--out FILE]

Flags:
  --iterations N  Measured iterations (default: schema#sample_size).
  --warmup N      Warmup iterations, discarded (default: schema#warmup_iterations).
  --ops N         Operations per iteration (default: schema#ops_per_iteration).
  --out FILE      Write JSONL to FILE instead of stdout.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --iterations) [ $# -ge 2 ] || { usage; exit 1; }; ITERATIONS="$2"; shift 2 ;;
    --warmup)     [ $# -ge 2 ] || { usage; exit 1; }; WARMUP="$2"; shift 2 ;;
    --ops)        [ $# -ge 2 ] || { usage; exit 1; }; OPS="$2"; shift 2 ;;
    --out)        [ $# -ge 2 ] || { usage; exit 1; }; OUT_FILE="$2"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "bench/workloads/syscall.sh: unknown argument: $1" 1>&2; usage; exit 1 ;;
  esac
done

# ---- schema defaults -------------------------------------------------------
if [ ! -f "${SCHEMA_PATH}" ]; then
  echo "bench/workloads/syscall.sh: schema not found: ${SCHEMA_PATH}" 1>&2; exit 1
fi
if [ -z "${ITERATIONS}" ]; then
  ITERATIONS="$(jq -r '.properties.sample_size.default' "${SCHEMA_PATH}")"
fi
if [ -z "${WARMUP}" ]; then
  WARMUP="$(jq -r '.properties.warmup_iterations.default' "${SCHEMA_PATH}")"
fi
if [ -z "${OPS}" ]; then
  OPS="$(jq -r '.properties.ops_per_iteration.default' "${SCHEMA_PATH}")"
fi

# ---- run -------------------------------------------------------------------
exec python3 - "${ITERATIONS}" "${WARMUP}" "${OPS}" "${OUT_FILE}" <<'PYEOF'
import json, os, resource, sys, tempfile, time

iterations = int(sys.argv[1])
warmup = int(sys.argv[2])
ops = int(sys.argv[3])
out_file = sys.argv[4] if sys.argv[4] else None

# Scratch file for open/close/stat syscalls.
fd, path = tempfile.mkstemp(prefix="bench-syscall-", suffix=".tmp")
os.close(fd)

def syscall_batch():
    """One batch: getpid + gettimeofday + open + read + close + stat."""
    os.getpid()
    time.time()
    f = os.open(path, os.O_RDONLY)
    os.read(f, 64)
    os.close(f)
    os.stat(path)

def run_iteration(iteration_num):
    latencies = []
    for _ in range(ops):
        t0 = time.perf_counter_ns()
        syscall_batch()
        latencies.append(time.perf_counter_ns() - t0)
    latencies.sort()
    n = len(latencies)
    def pct(p):
        idx = min(int(n * p / 100.0), n - 1)
        return latencies[idx]
    total_ns = sum(latencies)
    throughput = ops / (total_ns / 1e9) if total_ns > 0 else 0
    ru = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "workload": "syscall",
        "iteration": iteration_num,
        "p50_ns": pct(50),
        "p95_ns": pct(95),
        "p99_ns": pct(99),
        "p999_ns": pct(99.9),
        "throughput_ops": round(throughput, 2),
        "cpu_pct": round((ru.ru_utime + ru.ru_stime) * 100.0 / max(time.monotonic(), 1e-9), 2),
        "rss_kb": ru.ru_maxrss,
    }

out = open(out_file, "w", encoding="utf-8") if out_file else sys.stdout
try:
    for i in range(warmup):
        run_iteration(-(i + 1))
    for i in range(1, iterations + 1):
        row = run_iteration(i)
        out.write(json.dumps(row, separators=(",", ":")) + "\n")
        out.flush()
finally:
    os.unlink(path)
    if out_file:
        out.close()
PYEOF
