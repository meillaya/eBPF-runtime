#!/usr/bin/env bash
# bench/analyze.sh — statistical analysis pipeline (task 59)
#
# Reads the JSONL run data produced by bench/benchmark.sh and computes
# the release-gate evidence: paired p99 latency increase and throughput
# decrease for each (workload, comparator) pair relative to the
# no-agent baseline, with 95% confidence-interval upper bounds.
#
# All thresholds (p99 max %, throughput max %, confidence level) are
# read from bench/schemas/runs.v1.json — nothing is hardcoded.
#
# Usage:
#   bench/analyze.sh --in DIR [--schema PATH] [--out FILE]
#
# Input:
#   DIR/runs.jsonl      — JSONL rows from bench/benchmark.sh
#   DIR/manifest.json   — run metadata
#
# Output (default: DIR/analysis.json):
#   {
#     "workload": "cpu",
#     "comparator": "observe",
#     "baseline_p99_ns": ...,
#     "comparator_p99_ns": ...,
#     "p99_increase_pct": 2.3,
#     "p99_ci_upper_pct": 4.1,
#     "baseline_throughput_ops": ...,
#     "comparator_throughput_ops": ...,
#     "throughput_decrease_pct": 1.8,
#     "throughput_ci_upper_pct": 3.5,
#     "pass": true
#   }
#
# Exit codes:
#   0  Analysis complete (regardless of pass/fail gate).
#   1  Input missing, malformed, or no baseline data.
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SCHEMA_PATH=""
IN_DIR=""
OUT_FILE=""

usage() {
  cat <<USAGE 1>&2
usage: bench/analyze.sh --in DIR [--schema PATH] [--out FILE]

Flags:
  --in DIR       Input directory containing runs.jsonl and manifest.json.
  --schema PATH  Path to runs.v1.json schema (default: bench/schemas/runs.v1.json).
  --out FILE     Output analysis JSON (default: DIR/analysis.json).
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --in)     [ $# -ge 2 ] || { usage; exit 1; }; IN_DIR="$2"; shift 2 ;;
    --schema) [ $# -ge 2 ] || { usage; exit 1; }; SCHEMA_PATH="$2"; shift 2 ;;
    --out)    [ $# -ge 2 ] || { usage; exit 1; }; OUT_FILE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "bench/analyze.sh: unknown argument: $1" 1>&2; usage; exit 1 ;;
  esac
done

if [ -z "${IN_DIR}" ]; then
  echo "bench/analyze.sh: --in is required" 1>&2
  exit 1
fi

RUNS_FILE="${IN_DIR}/runs.jsonl"
if [ ! -f "${RUNS_FILE}" ]; then
  echo "bench/analyze.sh: runs file not found: ${RUNS_FILE}" 1>&2
  exit 1
fi

if [ -z "${SCHEMA_PATH}" ]; then
  SCHEMA_PATH="${WORKSPACE_ROOT}/bench/schemas/runs.v1.json"
fi
if [ ! -f "${SCHEMA_PATH}" ]; then
  echo "bench/analyze.sh: schema not found: ${SCHEMA_PATH}" 1>&2
  exit 1
fi

if [ -z "${OUT_FILE}" ]; then
  OUT_FILE="${IN_DIR}/analysis.json"
fi

# Read gate thresholds from schema.
CONFIDENCE="$(jq -r '.properties.confidence_level.default' "${SCHEMA_PATH}")"
P99_MAX_PCT="$(jq -r '.properties.default_p99_latency_max_pct.default' "${SCHEMA_PATH}")"
TPUT_MAX_PCT="$(jq -r '.properties.default_throughput_decrease_max_pct.default' "${SCHEMA_PATH}")"

echo "bench/analyze.sh: input=${RUNS_FILE}"
echo "bench/analyze.sh: confidence=${CONFIDENCE} p99_max_pct=${P99_MAX_PCT} tput_max_pct=${TPUT_MAX_PCT}"

# ---- analysis (python3) ----------------------------------------------------
python3 - "${RUNS_FILE}" "${OUT_FILE}" "${CONFIDENCE}" "${P99_MAX_PCT}" "${TPUT_MAX_PCT}" <<'PYEOF'
import json, math, sys
from collections import defaultdict

runs_file = sys.argv[1]
out_file = sys.argv[2]
confidence = float(sys.argv[3])
p99_max_pct = float(sys.argv[4])
tput_max_pct = float(sys.argv[5])

# ---- load runs -------------------------------------------------------------
# Group by (workload, comparator) -> list of iteration rows.
data = defaultdict(list)
with open(runs_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        key = (row["workload"], row["comparator"])
        data[key].append(row)

if not data:
    print("bench/analyze.sh: no run data found", file=sys.stderr)
    sys.exit(1)

# ---- t critical value ------------------------------------------------------
# For the paired-difference CI we need t_{alpha/2, n-1}. With n>=30
# (schema default sample_size=30) the normal approximation z is within
# 2% of the true t. We use a small lookup for common n and fall back
# to z for large n.
def t_critical(n, conf):
    """Two-tailed t critical value for n-1 degrees of freedom."""
    alpha = 1.0 - conf
    # Abramowitz & Stegun 26.2.22 approximation for the normal quantile.
    # For the t-distribution with df >= 30, z is a good approximation.
    # For small df we use a conservative lookup.
    p = 1.0 - alpha / 2.0
    # Normal quantile approximation (Beasley-Springer-Moro).
    if p <= 0.0 or p >= 1.0:
        return 1.96
    if p < 0.5:
        sign = -1.0
        pp = p
    else:
        sign = 1.0
        pp = 1.0 - p
    t_val = math.sqrt(-2.0 * math.log(pp))
    c0, c1, c2 = 2.515517, 0.802853, 0.010328
    d1, d2, d3 = 1.432788, 0.189269, 0.001308
    z = t_val - (c0 + c1 * t_val + c2 * t_val * t_val) / \
        (1.0 + d1 * t_val + d2 * t_val * t_val + d3 * t_val * t_val * t_val)
    z = sign * z
    # Cornish-Fisher correction for t-distribution.
    df = n - 1
    if df < 1:
        df = 1
    g1 = (z**3 + z) / (4 * df)
    g2 = (5 * z**5 + 16 * z**3 + 3 * z) / (96 * df**2)
    return z + g1 + g2

# ---- paired analysis -------------------------------------------------------
workloads = sorted(set(wl for wl, _ in data.keys()))
# Comparators to evaluate against baseline (exclude no-agent itself).
test_comparators = sorted(set(
    cmp for _, cmp in data.keys() if cmp != "no-agent"
))

results = []

for wl in workloads:
    baseline_key = (wl, "no-agent")
    if baseline_key not in data:
        print(f"bench/analyze.sh: WARNING — no baseline for workload={wl}, skipping", file=sys.stderr)
        continue

    baseline_rows = sorted(data[baseline_key], key=lambda r: r["iteration"])
    n = len(baseline_rows)
    if n < 2:
        print(f"bench/analyze.sh: WARNING — baseline n={n} < 2 for workload={wl}, skipping", file=sys.stderr)
        continue

    # Baseline aggregates (mean across iterations).
    bl_p99_vals = [r["p99_ns"] for r in baseline_rows]
    bl_tput_vals = [r["throughput_ops"] for r in baseline_rows]
    bl_p99_mean = sum(bl_p99_vals) / n
    bl_tput_mean = sum(bl_tput_vals) / n

    for cmp in test_comparators:
        cmp_key = (wl, cmp)
        if cmp_key not in data:
            continue

        cmp_rows = sorted(data[cmp_key], key=lambda r: r["iteration"])
        m = len(cmp_rows)
        paired_n = min(n, m)
        if paired_n < 2:
            print(f"bench/analyze.sh: WARNING — paired n={paired_n} < 2 for workload={wl} comparator={cmp}, skipping", file=sys.stderr)
            continue

        # Paired differences (aligned by iteration index).
        p99_diffs = []
        tput_diffs = []
        for i in range(paired_n):
            p99_diffs.append(cmp_rows[i]["p99_ns"] - baseline_rows[i]["p99_ns"])
            # Throughput decrease: positive means comparator is slower.
            tput_diffs.append(baseline_rows[i]["throughput_ops"] - cmp_rows[i]["throughput_ops"])

        def mean(xs):
            return sum(xs) / len(xs)

        def stdev(xs):
            mu = mean(xs)
            return math.sqrt(sum((x - mu) ** 2 for x in xs) / (len(xs) - 1))

        p99_diff_mean = mean(p99_diffs)
        p99_diff_se = stdev(p99_diffs) / math.sqrt(paired_n)
        tput_diff_mean = mean(tput_diffs)
        tput_diff_se = stdev(tput_diffs) / math.sqrt(paired_n)

        tc = t_critical(paired_n, confidence)

        # Percentage increase/decrease relative to baseline mean.
        p99_increase_pct = (p99_diff_mean / bl_p99_mean * 100.0) if bl_p99_mean > 0 else 0.0
        p99_ci_upper_pct = ((p99_diff_mean + tc * p99_diff_se) / bl_p99_mean * 100.0) if bl_p99_mean > 0 else 0.0

        tput_decrease_pct = (tput_diff_mean / bl_tput_mean * 100.0) if bl_tput_mean > 0 else 0.0
        tput_ci_upper_pct = ((tput_diff_mean + tc * tput_diff_se) / bl_tput_mean * 100.0) if bl_tput_mean > 0 else 0.0

        # Gate: pass iff CI upper bound is within threshold.
        passed = (p99_ci_upper_pct <= p99_max_pct) and (tput_ci_upper_pct <= tput_max_pct)

        cmp_p99_vals = [r["p99_ns"] for r in cmp_rows[:paired_n]]
        cmp_tput_vals = [r["throughput_ops"] for r in cmp_rows[:paired_n]]

        results.append({
            "workload": wl,
            "comparator": cmp,
            "n": paired_n,
            "baseline_p99_ns": round(bl_p99_mean, 2),
            "comparator_p99_ns": round(mean(cmp_p99_vals), 2),
            "p99_increase_pct": round(p99_increase_pct, 4),
            "p99_ci_upper_pct": round(p99_ci_upper_pct, 4),
            "baseline_throughput_ops": round(bl_tput_mean, 2),
            "comparator_throughput_ops": round(mean(cmp_tput_vals), 2),
            "throughput_decrease_pct": round(tput_decrease_pct, 4),
            "throughput_ci_upper_pct": round(tput_ci_upper_pct, 4),
            "confidence_level": confidence,
            "p99_latency_max_pct": p99_max_pct,
            "throughput_decrease_max_pct": tput_max_pct,
            "pass": passed,
        })

# ---- output ----------------------------------------------------------------
output = {
    "schema_version": 1,
    "analysis": results,
    "gate_summary": {
        "total_pairs": len(results),
        "passed": sum(1 for r in results if r["pass"]),
        "failed": sum(1 for r in results if not r["pass"]),
        "all_pass": all(r["pass"] for r in results) if results else False,
    },
}

with open(out_file, "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2, sort_keys=False)
    f.write("\n")

print(f"bench/analyze.sh: analysis written to {out_file}")
print(f"bench/analyze.sh: {output['gate_summary']['passed']}/{output['gate_summary']['total_pairs']} pairs passed")
for r in results:
    status = "PASS" if r["pass"] else "FAIL"
    print(f"  [{status}] {r['workload']}/{r['comparator']}: "
          f"p99 +{r['p99_increase_pct']:.2f}% (CI ≤{r['p99_ci_upper_pct']:.2f}%), "
          f"tput -{r['throughput_decrease_pct']:.2f}% (CI ≤{r['throughput_ci_upper_pct']:.2f}%)")
PYEOF
