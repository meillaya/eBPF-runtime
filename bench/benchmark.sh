#!/usr/bin/env bash
# bench/benchmark.sh — comparative benchmark orchestrator (task 59)
#
# Runs every workload under every comparator, collecting JSONL run data
# for the statistical analysis pipeline (bench/analyze.sh). All numeric
# constants (sample size, warmup, ops per iteration, gate thresholds)
# are read from bench/schemas/runs.v1.json — nothing is hardcoded.
#
# Usage:
#   bench/benchmark.sh [OPTIONS]
#
# Options:
#   --dry-run          Validate the harness (schema, scripts, tools)
#                      without running any workloads.
#   --comparators L    Comma-separated subset of comparators to run
#                      (default: all from schema).
#   --workloads L      Comma-separated subset of workloads to run
#                      (default: all from schema).
#   --out DIR          Output directory (default: bench/bench-out/).
#   --schema PATH      Path to runs schema (default: bench/schemas/runs.v1.json).
#   -h, --help         Show this help.
#
# Output:
#   bench/bench-out/runs.jsonl          — all run rows (one per iteration)
#   bench/bench-out/manifest.json       — run metadata (schema, env, flags)
#   bench/bench-out/skipped.json        — comparators skipped with reason
#
# Exit codes:
#   0  All requested runs completed (skips are not failures).
#   1  Schema missing/malformed, workload/comparator script missing,
#      or a comparator failed (exit != 0 and != 2).
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

# ---- paths -----------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SCHEMA_PATH=""
DRY_RUN=false
COMPARATORS_OVERRIDE=""
WORKLOADS_OVERRIDE=""
OUT_DIR=""

usage() {
  cat <<USAGE 1>&2
usage: bench/benchmark.sh [OPTIONS]

Options:
  --dry-run          Validate the harness without running workloads.
  --comparators L    Comma-separated comparator subset (default: schema).
  --workloads L      Comma-separated workload subset (default: schema).
  --out DIR          Output directory (default: bench/bench-out/).
  --schema PATH      Path to runs.v1.json schema.
  -h, --help         Show this help.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)     DRY_RUN=true; shift ;;
    --comparators) [ $# -ge 2 ] || { usage; exit 1; }; COMPARATORS_OVERRIDE="$2"; shift 2 ;;
    --workloads)   [ $# -ge 2 ] || { usage; exit 1; }; WORKLOADS_OVERRIDE="$2"; shift 2 ;;
    --out)         [ $# -ge 2 ] || { usage; exit 1; }; OUT_DIR="$2"; shift 2 ;;
    --schema)      [ $# -ge 2 ] || { usage; exit 1; }; SCHEMA_PATH="$2"; shift 2 ;;
    -h|--help)     usage; exit 0 ;;
    *) echo "bench/benchmark.sh: unknown argument: $1" 1>&2; usage; exit 1 ;;
  esac
done

# ---- schema ----------------------------------------------------------------
if [ -z "${SCHEMA_PATH}" ]; then
  SCHEMA_PATH="${WORKSPACE_ROOT}/bench/schemas/runs.v1.json"
fi
if [ ! -f "${SCHEMA_PATH}" ]; then
  echo "bench/benchmark.sh: schema not found: ${SCHEMA_PATH}" 1>&2
  exit 1
fi
if ! jq -e . "${SCHEMA_PATH}" >/dev/null 2>&1; then
  echo "bench/benchmark.sh: schema is not valid JSON: ${SCHEMA_PATH}" 1>&2
  exit 1
fi

# Read constants from schema (the ONLY source of truth).
SAMPLE_SIZE="$(jq -r '.properties.sample_size.default' "${SCHEMA_PATH}")"
WARMUP="$(jq -r '.properties.warmup_iterations.default' "${SCHEMA_PATH}")"
OPS="$(jq -r '.properties.ops_per_iteration.default' "${SCHEMA_PATH}")"
CONFIDENCE="$(jq -r '.properties.confidence_level.default' "${SCHEMA_PATH}")"
P99_MAX_PCT="$(jq -r '.properties.default_p99_latency_max_pct.default' "${SCHEMA_PATH}")"
TPUT_MAX_PCT="$(jq -r '.properties.default_throughput_decrease_max_pct.default' "${SCHEMA_PATH}")"

# Validate schema constants are sane.
for val in "${SAMPLE_SIZE}" "${WARMUP}" "${OPS}"; do
  if ! printf '%s' "${val}" | grep -Eq '^[0-9]+$'; then
    echo "bench/benchmark.sh: schema constant must be a positive integer (got: ${val})" 1>&2
    exit 1
  fi
done

# ---- resolve workloads / comparators --------------------------------------
if [ -n "${WORKLOADS_OVERRIDE}" ]; then
  IFS=',' read -ra WORKLOADS <<< "${WORKLOADS_OVERRIDE}"
else
  mapfile -t WORKLOADS < <(jq -r '.properties.workloads.default[]' "${SCHEMA_PATH}")
fi

if [ -n "${COMPARATORS_OVERRIDE}" ]; then
  IFS=',' read -ra COMPARATORS <<< "${COMPARATORS_OVERRIDE}"
else
  mapfile -t COMPARATORS < <(jq -r '.properties.comparators.default[]' "${SCHEMA_PATH}")
fi

# ---- output dir ------------------------------------------------------------
if [ -z "${OUT_DIR}" ]; then
  OUT_DIR="${WORKSPACE_ROOT}/bench/bench-out"
fi
mkdir -p "${OUT_DIR}"

RUNS_FILE="${OUT_DIR}/runs.jsonl"
MANIFEST_FILE="${OUT_DIR}/manifest.json"
SKIPPED_FILE="${OUT_DIR}/skipped.json"

# ---- validation ------------------------------------------------------------
echo "bench/benchmark.sh: schema=${SCHEMA_PATH}"
echo "bench/benchmark.sh: sample_size=${SAMPLE_SIZE} warmup=${WARMUP} ops=${OPS}"
echo "bench/benchmark.sh: confidence=${CONFIDENCE} p99_max_pct=${P99_MAX_PCT} tput_max_pct=${TPUT_MAX_PCT}"
echo "bench/benchmark.sh: workloads=${WORKLOADS[*]}"
echo "bench/benchmark.sh: comparators=${COMPARATORS[*]}"

VALIDATION_OK=true

for wl in "${WORKLOADS[@]}"; do
  wl_script="${WORKSPACE_ROOT}/bench/workloads/${wl}.sh"
  if [ ! -x "${wl_script}" ]; then
    echo "bench/benchmark.sh: workload script missing or not executable: ${wl_script}" 1>&2
    VALIDATION_OK=false
  fi
done

for cmp in "${COMPARATORS[@]}"; do
  cmp_script="${WORKSPACE_ROOT}/bench/comparators/${cmp}.sh"
  if [ ! -x "${cmp_script}" ]; then
    echo "bench/benchmark.sh: comparator script missing or not executable: ${cmp_script}" 1>&2
    VALIDATION_OK=false
  fi
done

if [ "${VALIDATION_OK}" != "true" ]; then
  echo "bench/benchmark.sh: validation FAILED" 1>&2
  exit 1
fi

echo "bench/benchmark.sh: validation passed"

# ---- dry-run: stop here ----------------------------------------------------
if [ "${DRY_RUN}" = "true" ]; then
  echo "bench/benchmark.sh: --dry-run — harness validated, no workloads executed"
  # Write a minimal manifest so downstream tooling can detect a dry run.
  jq -n \
    --arg schema "${SCHEMA_PATH}" \
    --argjson sample_size "${SAMPLE_SIZE}" \
    --argjson warmup "${WARMUP}" \
    --argjson ops "${OPS}" \
    --argjson confidence "${CONFIDENCE}" \
    --argjson p99_max_pct "${P99_MAX_PCT}" \
    --argjson tput_max_pct "${TPUT_MAX_PCT}" \
    --arg dry_run "true" \
    '{
      schema: $schema,
      sample_size: $sample_size,
      warmup_iterations: $warmup,
      ops_per_iteration: $ops,
      confidence_level: $confidence,
      p99_latency_max_pct: $p99_max_pct,
      throughput_decrease_max_pct: $tput_max_pct,
      dry_run: ($dry_run == "true"),
      workloads: [],
      comparators: []
    }' > "${MANIFEST_FILE}"
  echo "bench/benchmark.sh: manifest written to ${MANIFEST_FILE}"
  exit 0
fi

# ---- run -------------------------------------------------------------------
: > "${RUNS_FILE}"
echo "[]" > "${SKIPPED_FILE}"

TOTAL_RUNS=$(( ${#WORKLOADS[@]} * ${#COMPARATORS[@]} ))
RUN_NUM=0

for wl in "${WORKLOADS[@]}"; do
  for cmp in "${COMPARATORS[@]}"; do
    RUN_NUM=$(( RUN_NUM + 1 ))
    cmp_script="${WORKSPACE_ROOT}/bench/comparators/${cmp}.sh"
    echo "bench/benchmark.sh: [${RUN_NUM}/${TOTAL_RUNS}] workload=${wl} comparator=${cmp}"

    set +e
    "${cmp_script}" \
      --workload "${wl}" \
      --iterations "${SAMPLE_SIZE}" \
      --warmup "${WARMUP}" \
      --ops "${OPS}" \
      >> "${RUNS_FILE}"
    EXIT_CODE=$?
    set -e

    if [ "${EXIT_CODE}" -eq 2 ]; then
      echo "bench/benchmark.sh: [${RUN_NUM}/${TOTAL_RUNS}] SKIPPED (exit 2)"
      # Record the skip.
      SKIPPED_FILE_TMP="${SKIPPED_FILE}.tmp"
      jq --arg wl "${wl}" --arg cmp "${cmp}" \
        '. + [{workload: $wl, comparator: $cmp, reason: "comparator unavailable (exit 2)"}]' \
        "${SKIPPED_FILE}" > "${SKIPPED_FILE_TMP}"
      mv "${SKIPPED_FILE_TMP}" "${SKIPPED_FILE}"
    elif [ "${EXIT_CODE}" -ne 0 ]; then
      echo "bench/benchmark.sh: [${RUN_NUM}/${TOTAL_RUNS}] FAILED (exit ${EXIT_CODE})" 1>&2
      exit 1
    fi
  done
done

# ---- manifest --------------------------------------------------------------
KERNEL_RELEASE="$(uname -r)"
BTFS_HASH="none"
if [ -f /sys/kernel/btf/vmlinux ]; then
  BTFS_HASH="$(sha256sum /sys/kernel/btf/vmlinux | cut -d' ' -f1)"
fi

jq -n \
  --arg schema "${SCHEMA_PATH}" \
  --argjson sample_size "${SAMPLE_SIZE}" \
  --argjson warmup "${WARMUP}" \
  --argjson ops "${OPS}" \
  --argjson confidence "${CONFIDENCE}" \
  --argjson p99_max_pct "${P99_MAX_PCT}" \
  --argjson tput_max_pct "${TPUT_MAX_PCT}" \
  --arg kernel "${KERNEL_RELEASE}" \
  --arg btf "${BTFS_HASH}" \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson workloads "$(printf '%s\n' "${WORKLOADS[@]}" | jq -R . | jq -s .)" \
  --argjson comparators "$(printf '%s\n' "${COMPARATORS[@]}" | jq -R . | jq -s .)" \
  '{
    schema: $schema,
    sample_size: $sample_size,
    warmup_iterations: $warmup,
    ops_per_iteration: $ops,
    confidence_level: $confidence,
    p99_latency_max_pct: $p99_max_pct,
    throughput_decrease_max_pct: $tput_max_pct,
    dry_run: false,
    kernel_release: $kernel,
    btf_sha256: $btf,
    started_at: $ts,
    workloads: $workloads,
    comparators: $comparators
  }' > "${MANIFEST_FILE}"

echo "bench/benchmark.sh: runs written to ${RUNS_FILE}"
echo "bench/benchmark.sh: manifest written to ${MANIFEST_FILE}"
echo "bench/benchmark.sh: skipped written to ${SKIPPED_FILE}"
echo "bench/benchmark.sh: done — run 'bench/analyze.sh --in ${OUT_DIR}' for statistical analysis"
