#!/usr/bin/env bash
# bench/workloads/io.sh — deterministic file I/O workload generator
#
# Sequential write + random read via python3 on a tmpfs-backed file.
# Fixed seed for the random read offsets so the access pattern is
# reproducible across runs. Each iteration performs ops_per_iteration
# I/O operations (half sequential writes, half random reads).
#
# Usage:
#   bench/workloads/io.sh --iterations N --warmup N --ops N [--out FILE]
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
usage: bench/workloads/io.sh --iterations N --warmup N --ops N [--out FILE]

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
    *) echo "bench/workloads/io.sh: unknown argument: $1" 1>&2; usage; exit 1 ;;
  esac
done

# ---- schema defaults -------------------------------------------------------
if [ ! -f "${SCHEMA_PATH}" ]; then
  echo "bench/workloads/io.sh: schema not found: ${SCHEMA_PATH}" 1>&2; exit 1
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
import json, os, random, resource, sys, tempfile, time

iterations = int(sys.argv[1])
warmup = int(sys.argv[2])
ops = int(sys.argv[3])
out_file = sys.argv[4] if sys.argv[4] else None

BLOCK = 4096
FILE_BLOCKS = 256  # 1 MiB scratch file

# Deterministic PRNG for random read offsets.
rng = random.Random(0xDEAD_BEEF)

# Create scratch file in /tmp (prefer tmpfs).
fd, path = tempfile.mkstemp(prefix="bench-io-", suffix=".bin")
try:
    with os.fdopen(fd, "wb") as f:
        f.write(b"\xaa" * (BLOCK * FILE_BLOCKS))

    def run_iteration(iteration_num):
        latencies = []
        half = ops // 2
        # Sequential writes.
        with open(path, "r+b") as f:
            for i in range(half):
                t0 = time.perf_counter_ns()
                f.seek((i % FILE_BLOCKS) * BLOCK)
                f.write(b"\x5a" * BLOCK)
                latencies.append(time.perf_counter_ns() - t0)
            f.flush()
            os.fsync(f.fileno())
            # Random reads (fixed seed → reproducible offsets).
            offsets = [rng.randrange(FILE_BLOCKS) for _ in range(ops - half)]
            for off in offsets:
                t0 = time.perf_counter_ns()
                f.seek(off * BLOCK)
                f.read(BLOCK)
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
            "workload": "io",
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
        if out_file:
            out.close()
finally:
    os.unlink(path)
PYEOF
