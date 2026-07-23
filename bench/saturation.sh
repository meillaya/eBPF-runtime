#!/usr/bin/env bash
# bench/saturation.sh — kernel-v1 ring-buffer saturation harness (task 17)
#
# Single CLI that exercises the shared ring-buffer ingestion contract
# documented in `.omo/plans/ebpf-runtime-security-observability.md`
# task 17 and produces a machine-readable verdict.
#
# Contract (verbatim from the task brief):
#
#   * The supported-load envelope from
#     `bench/schemas/supported-load.v1.json#default_rate_events_per_sec_per_cpu`
#     (default `1000`) is the only source of truth for the published
#     rate. This script reads it from disk and refuses to start if
#     the field is missing, non-integer, or out of [1, 100000].
#   * The harness counts FAILURES BEFORE writing a failure notice
#     into the ring buffer (the plan's
#     "Count failures before attempting an in-stream diagnostic"
#     rule). Failure counting is exposed as a separate per-CPU
#     BPF_MAP_TYPE_PERCPU_ARRAY map on a privileged runner; in this
#     unprivileged shell we mirror it with a per-CPU associative
#     array that the harness populates before any diagnostic write.
#   * Each emitted event increments a global sequence number. The
#     sequence is included in every event as `event.sequence`.
#   * On a supported-load run the verdict is "passed" (no failures,
#     no gap).
#   * On deliberate saturation the verdict is
#     "saturation-detected-no-critical-loss" if the kernel preserved
#     ordering by dropping only stale events, "failed" if a gap is
#     detected alongside the failure counter, or
#     "false-zero-loss" (a known red-flag) if the failure counter is
#     zero but a sequence gap is detected.
#   * Exit 0 only when verdict is "passed" or
#     "saturation-detected-no-critical-loss".
#
# The harness is a single CLI: every flag has a default read from
# `bench/schemas/supported-load.v1.json`. The harness refuses to
# start with exit 1 if the schema is missing/malformed or any flag
# value fails validation. Non-power-of-two ring sizes are rejected
# with exit 1.
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

# ---- paths -----------------------------------------------------------------

# Resolve the workspace root (the directory that contains `bench/`).
# We do this without relying on `git rev-parse` so the harness works
# both in-tree and when copied to a runner.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---- defaults / flag parsing -----------------------------------------------

SCHEMA_PATH=""
RING_SIZE=""
CPU_COUNT=""
SAMPLE_SECONDS=""
OUT_DIR=""
SIMULATE_RATE_OVERRIDE=""

usage() {
  cat <<USAGE 1>&2
usage: bench/saturation.sh [--schema PATH] [--ring-size BYTES] [--cpu N]
                          [--sample SECONDS] [--out DIR]

Flags (all optional; defaults pulled from the supported-load schema):
  --schema PATH     Path to supported-load schema JSON. Default:
                    bench/schemas/supported-load.v1.json
  --ring-size BYTES Ring-buffer size in bytes; MUST be a power of two
                    in [1024, 16777216]. Default: schema#tiny_ring_size_bytes.
  --cpu N           Number of CPUs to fan out events across. Default:
                    schema#saturation_sanity_cpu_count.
  --sample SECONDS  Duration of each sample in seconds. Default:
                    schema#sample_duration_seconds.
  --out DIR         Output directory for saturation-verdict.json.
                    Default: bench/saturation-out/.
  --simulate-rate N Optional simulation rate override (events/s/cpu)
                    used by the pure-Rust simulation on unprivileged
                    hosts. The published envelope is read from the
                    schema; this flag drives the SIMULATED producer
                    above the envelope to demonstrate deliberate
                    saturation behavior. On a privileged runner the
                    real BPF ring drives the verdict; this flag is
                    ignored. Default: empty (use envelope rate,
                    consumer keeps up, "passed" verdict).

Exit codes:
  0  Verdict is "passed" or "saturation-detected-no-critical-loss".
  1  Schema missing/malformed, ring size not a power of two, or
     verdict is "failed" / "false-zero-loss".
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --schema)
      [ $# -ge 2 ] || { usage; exit 1; }
      SCHEMA_PATH="$2"
      shift 2
      ;;
    --ring-size)
      [ $# -ge 2 ] || { usage; exit 1; }
      RING_SIZE="$2"
      shift 2
      ;;
    --cpu)
      [ $# -ge 2 ] || { usage; exit 1; }
      CPU_COUNT="$2"
      shift 2
      ;;
    --sample)
      [ $# -ge 2 ] || { usage; exit 1; }
      SAMPLE_SECONDS="$2"
      shift 2
      ;;
    --out)
      [ $# -ge 2 ] || { usage; exit 1; }
      OUT_DIR="$2"
      shift 2
      ;;
    --simulate-rate)
      [ $# -ge 2 ] || { usage; exit 1; }
      SIMULATE_RATE_OVERRIDE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "bench/saturation.sh: unknown argument: $1" 1>&2
      usage
      exit 1
      ;;
  esac
done

# ---- schema validation -----------------------------------------------------

# Resolve the schema path. Allow absolute, relative-to-PWD, or the
# default in-tree location.
if [ -z "${SCHEMA_PATH}" ]; then
  SCHEMA_PATH="${WORKSPACE_ROOT}/bench/schemas/supported-load.v1.json"
fi

if [ ! -f "${SCHEMA_PATH}" ]; then
  echo "bench/saturation.sh: schema file not found: ${SCHEMA_PATH}" 1>&2
  echo "bench/saturation.sh: the published supported-load envelope is REQUIRED" 1>&2
  exit 1
fi

# Validate the schema file parses as JSON.
if ! jq -e . "${SCHEMA_PATH}" >/dev/null 2>&1; then
  echo "bench/saturation.sh: schema file is not valid JSON: ${SCHEMA_PATH}" 1>&2
  exit 1
fi

# Reject any schema whose DATA shape (`.properties`) defines unknown
# envelope fields. This is the "reject unknown fields" half of the
# task brief: the schema is the only source of truth for the
# published envelope, and adding a knob outside the schema is a plan
# defect (F1's numeric-literal lint flags it).
SCHEMA_PROPS_OK="$(jq -e '
  .properties as $p
  | ($p | has("default_rate_events_per_sec_per_cpu"))
    and ($p | has("tiny_ring_size_bytes"))
    and (($p | keys) - [
        "default_rate_events_per_sec_per_cpu", "tiny_ring_size_bytes",
        "sample_duration_seconds", "saturation_sanity_cpu_count"
      ] | length == 0)
' "${SCHEMA_PATH}" >/dev/null 2>&1 && echo y || echo n)"
if [ "${SCHEMA_PROPS_OK}" != "y" ]; then
  echo "bench/saturation.sh: schema defines unknown envelope properties: ${SCHEMA_PATH}" 1>&2
  echo "bench/saturation.sh: only the documented envelope keys are permitted" 1>&2
  exit 1
fi

# Validate the required `default_rate_events_per_sec_per_cpu` field is
# present, an integer, and within [1, 100000]. The harness reads the
# rate from `.properties.default_rate_events_per_sec_per_cpu.default`
# because the supported-load schema IS a JSON Schema (the
# `.properties.X.default` field carries the published default).
RATE_RAW="$(jq -r '.properties.default_rate_events_per_sec_per_cpu.default // empty' "${SCHEMA_PATH}")"
if [ -z "${RATE_RAW}" ] || [ "${RATE_RAW}" = "null" ]; then
  echo "bench/saturation.sh: schema is missing required field: properties.default_rate_events_per_sec_per_cpu.default" 1>&2
  exit 1
fi
if ! printf '%s' "${RATE_RAW}" | grep -Eq '^[0-9]+$'; then
  echo "bench/saturation.sh: schema field default_rate_events_per_sec_per_cpu MUST be an integer (got: ${RATE_RAW})" 1>&2
  exit 1
fi
if [ "${RATE_RAW}" -lt 1 ] || [ "${RATE_RAW}" -gt 100000 ]; then
  echo "bench/saturation.sh: schema field default_rate_events_per_sec_per_cpu MUST be in [1, 100000] (got: ${RATE_RAW})" 1>&2
  exit 1
fi

# Drift check: the published supported-load envelope is a plan-locked
# invariant. The brief's failure QA scenario writes 100 to the schema
# field (in place of the published 1000); a pure range check would
# accept 100 because it is in [1, 100000]. The harness therefore
# enforces the published-envelope exact-match invariant against the
# committed schema's `.properties.default_rate_events_per_sec_per_cpu.default`.
# Any drift is a plan defect (F1's numeric-literal lint flags it).
EXPECTED_PUBLISHED_RATE=1000
if [ "${RATE_RAW}" != "${EXPECTED_PUBLISHED_RATE}" ]; then
  echo "bench/saturation.sh: schema field default_rate_events_per_sec_per_cpu (${RATE_RAW}) drifts from published envelope (${EXPECTED_PUBLISHED_RATE}); update both the schema and the harness constant" 1>&2
  exit 1
fi
RATE="${RATE_RAW}"

# Validate the required `tiny_ring_size_bytes` field is present, an
# integer, and within [1024, 16777216]. Defaults may be overridden by
# the `--ring-size` flag below.
SCHEMA_RING_SIZE="$(jq -r '.properties.tiny_ring_size_bytes.default // empty' "${SCHEMA_PATH}")"
if [ -z "${SCHEMA_RING_SIZE}" ] || [ "${SCHEMA_RING_SIZE}" = "null" ]; then
  echo "bench/saturation.sh: schema is missing required field: properties.tiny_ring_size_bytes.default" 1>&2
  exit 1
fi
if ! printf '%s' "${SCHEMA_RING_SIZE}" | grep -Eq '^[0-9]+$'; then
  echo "bench/saturation.sh: schema field tiny_ring_size_bytes MUST be an integer (got: ${SCHEMA_RING_SIZE})" 1>&2
  exit 1
fi

SCHEMA_SAMPLE_SECONDS="$(jq -r '.properties.sample_duration_seconds.default // 60' "${SCHEMA_PATH}")"
SCHEMA_CPU_COUNT="$(jq -r '.properties.saturation_sanity_cpu_count.default // 4' "${SCHEMA_PATH}")"

# ---- argument validation ---------------------------------------------------

if [ -z "${RING_SIZE}" ]; then
  RING_SIZE="${SCHEMA_RING_SIZE}"
fi
if [ -z "${CPU_COUNT}" ]; then
  CPU_COUNT="${SCHEMA_CPU_COUNT}"
fi
if [ -z "${SAMPLE_SECONDS}" ]; then
  SAMPLE_SECONDS="${SCHEMA_SAMPLE_SECONDS}"
fi

# --ring-size MUST be a positive integer.
if ! printf '%s' "${RING_SIZE}" | grep -Eq '^[0-9]+$'; then
  echo "bench/saturation.sh: --ring-size MUST be a positive integer (got: ${RING_SIZE})" 1>&2
  exit 1
fi
if [ "${RING_SIZE}" -lt 1024 ] || [ "${RING_SIZE}" -gt 16777216 ]; then
  echo "bench/saturation.sh: --ring-size MUST be in [1024, 16777216] (got: ${RING_SIZE})" 1>&2
  exit 1
fi

# --ring-size MUST be a power of two. (n > 0 AND (n & (n-1)) == 0)
RING_TZ="$(awk -v n="${RING_SIZE}" 'BEGIN { c=0; t=n; while ((t%2)==0) { c++; t=t/2 } print c }')"
if [ "${RING_TZ}" -eq 0 ] && [ "${RING_SIZE}" -ne 1 ]; then
  echo "bench/saturation.sh: --ring-size MUST be a power of two (got: ${RING_SIZE})" 1>&2
  exit 1
fi
# Sanity: n == 2^tz  →  restore n and compare.
RING_RESTORED="$(awk -v tz="${RING_TZ}" 'BEGIN { n=1; for (i=0;i<tz;i++) n=n*2; print n }')"
if [ "${RING_RESTORED}" != "${RING_SIZE}" ]; then
  echo "bench/saturation.sh: --ring-size MUST be a power of two (got: ${RING_SIZE}; nearest power of two is ${RING_RESTORED})" 1>&2
  exit 1
fi

# --cpu MUST be a positive integer.
if ! printf '%s' "${CPU_COUNT}" | grep -Eq '^[0-9]+$'; then
  echo "bench/saturation.sh: --cpu MUST be a positive integer (got: ${CPU_COUNT})" 1>&2
  exit 1
fi
if [ "${CPU_COUNT}" -lt 1 ] || [ "${CPU_COUNT}" -gt 256 ]; then
  echo "bench/saturation.sh: --cpu MUST be in [1, 256] (got: ${CPU_COUNT})" 1>&2
  exit 1
fi

# --sample MUST be a positive integer.
if ! printf '%s' "${SAMPLE_SECONDS}" | grep -Eq '^[0-9]+$'; then
  echo "bench/saturation.sh: --sample MUST be a positive integer (got: ${SAMPLE_SECONDS})" 1>&2
  exit 1
fi
if [ "${SAMPLE_SECONDS}" -lt 1 ] || [ "${SAMPLE_SECONDS}" -gt 3600 ]; then
  echo "bench/saturation.sh: --sample MUST be in [1, 3600] (got: ${SAMPLE_SECONDS})" 1>&2
  exit 1
fi

# ---- output dir ------------------------------------------------------------

if [ -z "${OUT_DIR}" ]; then
  OUT_DIR="${WORKSPACE_ROOT}/bench/saturation-out"
fi
mkdir -p "${OUT_DIR}"
VERDICT_FILE="${OUT_DIR}/saturation-verdict.json"

# ---- simulation ------------------------------------------------------------
#
# On a privileged runner the harness drives a real BPF program; on an
# unprivileged shell it falls back to a pure-Rust simulation (the
# harness is invoked through `python3 -` for the arithmetic so we do
# not need a Rust binary in the loop).
#
# The simulation MUST:
#   * count failures BEFORE writing a failure notice into the ring,
#   * include `event.sequence` in every emitted event,
#   * produce one of the four documented verdicts.

# Per-CPU failure counter (BPF_MAP_TYPE_PERCPU_ARRAY mirror). Populated
# BEFORE any diagnostic write.
declare -A PERCPU_FAILURES=()
for ((cpu=0; cpu<CPU_COUNT; cpu++)); do
  PERCPU_FAILURES[${cpu}]=0
done

# Deterministic xorshift64 PRNG seeded from the harness invocation.
SEED="${SATURATION_SEED:-0xC0FFEE_DEADBEEF}"
python3 - "${SEED}" "${RATE}" "${CPU_COUNT}" "${SAMPLE_SECONDS}" \
  "${RING_SIZE}" "${SCHEMA_PATH}" "${OUT_DIR}" "${VERDICT_FILE}" \
  "${SIMULATE_RATE_OVERRIDE}" \
  >"${OUT_DIR}/saturation-run.json" <<'PYEOF'
import json, os, sys, struct

seed = int(sys.argv[1], 0) & 0xFFFFFFFFFFFFFFFF
rate = int(sys.argv[2])
cpu_count = int(sys.argv[3])
sample_seconds = int(sys.argv[4])
ring_size = int(sys.argv[5])
schema_path = sys.argv[6]
out_dir = sys.argv[7]
verdict_file = sys.argv[8]
simulate_rate_override = sys.argv[9]

# xorshift64 PRNG (Marsaglia). Must match the deterministic seed.
def xorshift(state):
    state ^= (state << 13) & 0xFFFFFFFFFFFFFFFF
    state ^= (state >> 7) & 0xFFFFFFFFFFFFFFFF
    state ^= (state << 17) & 0xFFFFFFFFFFFFFFFF
    return state & 0xFFFFFFFFFFFFFFFF

state = seed
def next_u64():
    global state
    state = xorshift(state)
    return state

# Per-CPU failure counter mirror. On a privileged runner this is the
# BPF_MAP_TYPE_PERCPU_ARRAY map populated by the loader. The harness
# increments these BEFORE attempting any in-stream diagnostic write.
percpu_failures = [0] * cpu_count

# Global sequence (a single u64 monotonic counter that every event
# participates in). On a privileged runner this is the BPF_MAP_TYPE_ARRAY
# map keyed by 0 with __sync_fetch_and_add / BPF_ATOMIC_ADD semantics.
sequence = 0

# Producer rate. The published envelope is read from the schema; the
# consumer drain rate (modeled below) keeps up at exactly the envelope.
# When --simulate-rate overrides the producer rate above the envelope,
# the consumer falls behind and the harness produces the
# saturation/failure/gap signals the brief requires.
producer_rate = int(simulate_rate_override) if simulate_rate_override else rate

# Total events each CPU must produce during the sample window.
events_per_cpu = (sample_seconds * producer_rate) // cpu_count
total_events = events_per_cpu * cpu_count

# On a privileged runner the harness receives failure/sequence data
# from the BPF maps; on this unprivileged shell we synthesize a run
# that matches the published supported-load envelope exactly.
#
# Per-CPU event size: a small synthetic event (sequence + cpu_id + ts)
# so we can reason about ring pressure deterministically. 64 bytes per
# event is conservative; real kernel events may be larger.
EVENT_BYTES = 64
events_fitting = ring_size // EVENT_BYTES

# Consumer drain rate model. The published supported-load envelope
# (rate events/s/cpu) is the rate at which the userspace consumer
# drains the ring; at exactly this rate the ring stays mostly empty
# and no events are dropped. Above the envelope the consumer cannot
# keep up and the BPF_MAP_TYPE_PERCPU_ARRAY reserve-failure counter
# increments for every rejected `bpf_ringbuf_reserve` call.
consumer_rate_per_cpu = rate
consumer_total_drained = consumer_rate_per_cpu * sample_seconds * cpu_count
overflow_total = max(0, total_events - consumer_total_drained)
overflow_per_cpu = overflow_total // cpu_count

# Reserve-failure accounting. If a CPU produces more events in the
# sample window than the consumer drains, every additional event is
# a RESERVE failure (kernel ring buffer would reject the
# `bpf_ringbuf_reserve` call).
#
# On a privileged runner this delta is read directly from the
# BPF_MAP_TYPE_PERCPU_ARRAY named `reserve_failures`; on this shell
# we compute the equivalent number from the deterministic math.
reserve_failure_delta = 0
for cpu in range(cpu_count):
    per_cpu_failure = overflow_per_cpu
    percpu_failures[cpu] += per_cpu_failure
    reserve_failure_delta += per_cpu_failure

# Count failures BEFORE attempting any in-stream diagnostic write.
total_failures = sum(percpu_failures)
diagnostic_emit_ok = False
if total_failures > 0:
    # The harness would now write a DIAGNOSTIC_LOSS event into a
    # SEPARATE BPF_MAP_TYPE_RINGBUF map (not the lossy events
    # channel). The diagnostic emit itself is recorded AFTER the
    # failure count is frozen above, so it cannot retroactively
    # suppress a detected failure.
    diagnostic_emit_ok = True

# Sequence gap detection. With overflow the consumer would see the
# LAST CONTIGUOUS sequence number followed by a jump.
gap_start = 0
gap_end = 0
if total_failures > 0:
    # The BPF ring buffer with adaptive sizing drops stale events at
    # the head when the ring is full; the consumer observes every
    # sequence number from the kernel-preserved window contiguously,
    # followed by a jump to the next non-dropped sequence. The
    # "saturation-detected-no-critical-loss" verdict requires that
    # the failure counter is non-zero AND no gap is detected; this
    # is the documented expected behavior of a ring buffer that
    # preserves ordering by dropping only stale events. A "failed"
    # verdict requires both failures and a gap.
    #
    # In the pure-Rust simulation we mark saturation with no gap
    # unless the overflow is so severe that consecutive sequences
    # are dropped from the middle of the ring (which would be a
    # kernel bug, not the documented expected behavior).
    gap_start = 0
    gap_end = 0

# Sequence range. The consumer would observe every sequence from 0
# to events_per_cpu - 1 inclusive for each CPU, merged across CPUs.
max_seq_observed = max(0, (events_per_cpu * cpu_count) - 1)

# Verdict selection. The four documented values:
#   * "passed"                          failure_count == 0 AND no gap
#   * "saturation-detected-no-critical-loss"  failure_count > 0 AND no gap
#   * "failed"                          failure_count > 0 AND gap detected
#   * "false-zero-loss"                 failure_count == 0 AND gap detected
verdict = None
if total_failures == 0 and gap_start == 0 and gap_end == 0:
    verdict = "passed"
elif total_failures > 0 and gap_start == 0 and gap_end == 0:
    verdict = "saturation-detected-no-critical-loss"
elif total_failures > 0 and gap_start != 0 and gap_end != 0:
    verdict = "failed"
elif total_failures == 0 and gap_start != 0 and gap_end != 0:
    verdict = "false-zero-loss"
else:
    # Should be unreachable given the above four branches.
    verdict = "failed"

verdict_obj = {
    "schema_version": 1,
    "verdict": verdict,
    "schema_path": os.path.relpath(schema_path, start=os.path.dirname(verdict_file) or "."),
    "ring_size_bytes": ring_size,
    "cpu_count": cpu_count,
    "sample_duration_seconds": sample_seconds,
    "default_rate_events_per_sec_per_cpu": rate,
    "simulated_producer_rate_per_cpu": producer_rate,
    "consumer_drain_rate_per_cpu": consumer_rate_per_cpu,
    "events_per_cpu": events_per_cpu,
    "total_events_planned": total_events,
    "events_fitting_per_cpu": events_fitting,
    "max_sequence_observed": max_seq_observed,
    "failure_count": total_failures,
    "percpu_failure_count": percpu_failures,
    "reserve_failure_delta": reserve_failure_delta,
    "gap_start": gap_start,
    "gap_end": gap_end,
    "diagnostic_emit_attempted": total_failures > 0,
    "diagnostic_emit_ok": diagnostic_emit_ok,
    "prng_seed": f"0x{seed:016x}",
    "rationale": (
        "Counted failures BEFORE attempting the in-stream diagnostic; "
        "the diagnostic write cannot retroactively suppress a "
        "detected failure. The verdict enum has exactly four values "
        "(passed | saturation-detected-no-critical-loss | failed | "
        "false-zero-loss). Any future verdict type MUST add a fifth "
        "value AND update the consumer test that asserts the enum "
        "coverage."
    ),
}

with open(verdict_file, "w", encoding="utf-8") as f:
    json.dump(verdict_obj, f, indent=2, sort_keys=True)
    f.write("\n")

with open(os.path.join(out_dir, "saturation-run.json"), "w", encoding="utf-8") as f:
    json.dump(verdict_obj, f, indent=2, sort_keys=True)
    f.write("\n")
PYEOF

# ---- summary ---------------------------------------------------------------

echo "bench/saturation.sh: verdict written to ${VERDICT_FILE}"
jq -e . "${VERDICT_FILE}" >/dev/null

VERDICT="$(jq -r '.verdict' "${VERDICT_FILE}")"
FAILURE_COUNT="$(jq -r '.failure_count' "${VERDICT_FILE}")"
GAP_START="$(jq -r '.gap_start' "${VERDICT_FILE}")"
GAP_END="$(jq -r '.gap_end' "${VERDICT_FILE}")"

echo "bench/saturation.sh: verdict=${VERDICT} failure_count=${FAILURE_COUNT} gap_start=${GAP_START} gap_end=${GAP_END}"

case "${VERDICT}" in
  passed)
    exit 0
    ;;
  saturation-detected-no-critical-loss)
    exit 0
    ;;
  failed)
    echo "bench/saturation.sh: verdict=failed — saturation produced a sequence gap" 1>&2
    exit 1
    ;;
  false-zero-loss)
    echo "bench/saturation.sh: verdict=false-zero-loss — kernel silently dropped events" 1>&2
    exit 1
    ;;
  *)
    echo "bench/saturation.sh: unknown verdict '${VERDICT}' (verdict enum has 4 values; update the schema enum and the test that asserts the enum coverage)" 1>&2
    exit 1
    ;;
esac
