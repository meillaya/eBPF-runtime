#!/usr/bin/env bash
# Local recorder benchmark harness.
#
# Measures wall time, CPU time, RSS, event rate, bundle size, and query
# latency for `ebpf-fleet record` under a deterministic process/file
# workload. Runs as root because BPF loading needs CAP_BPF/CAP_PERFMON.
#
# Usage:
#   sudo scripts/bench/run.sh --duration 10 --workload mixed
#   sudo scripts/bench/run.sh --duration 20 --stacks events --workload file
#
# Output: target/bench/<UTC stamp>/{bench.json,record.err,query.txt,bundle/}
#
# This harness intentionally does not compare against bpftrace/perf yet; add a
# separate comparison row before publishing a "vs prior art" claim.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

duration=10
workload=mixed
stacks=off
binary="${EBPF_FLEET_BIN:-$root/target/release/ebpf-fleet}"
out_root="${EBPF_BENCH_OUT:-$root/target/bench}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="$out_root/$stamp"
mkdir -p "$run_dir"

while (($#)); do
  case "$1" in
    --duration) duration="${2:?}"; shift 2 ;;
    --workload) workload="${2:?}"; shift 2 ;;
    --stacks) stacks="${2:?}"; shift 2 ;;
    --binary) binary="${2:?}"; shift 2 ;;
    --help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "bench: unknown argument $1" >&2; exit 2 ;;
  esac
done

[[ "$(id -u)" == "0" ]] || { echo "bench: run as root (sudo)" >&2; exit 1; }
[[ -x "$binary" ]] || { echo "bench: missing binary $binary" >&2; exit 1; }
[[ "$duration" =~ ^[0-9]+$ ]] || { echo "bench: --duration must be seconds" >&2; exit 2; }
case "$stacks" in off|events|all) ;; *) echo "bench: invalid --stacks" >&2; exit 2 ;; esac
case "$workload" in process|file|mixed) ;; *) echo "bench: invalid --workload" >&2; exit 2 ;; esac

workload_pid=""
cleanup() {
  if [[ -n "$workload_pid" ]] && kill -0 "$workload_pid" 2>/dev/null; then
    kill "$workload_pid" 2>/dev/null || true
    wait "$workload_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

start_workload() {
  case "$workload" in
    process)
      ( while :; do /bin/true; done ) &
      ;;
    file)
      ( i=0; while :; do i=$((i + 1)); printf x >"/tmp/ebpf-bench-$i"; cat "/tmp/ebpf-bench-$i" >/dev/null; rm -f "/tmp/ebpf-bench-$i"; done ) &
      ;;
    mixed)
      ( i=0; while :; do i=$((i + 1)); /bin/true; printf x >"/tmp/ebpf-bench-$i"; rm -f "/tmp/ebpf-bench-$i"; done ) &
      ;;
  esac
  workload_pid=$!
}

start_ns="$(date +%s%N)"
start_workload
sleep 0.5
/usr/bin/time -v "$binary" record --for "$duration" --stacks "$stacks" \
  --out "$run_dir/bundle" >"$run_dir/record.out" 2>"$run_dir/record.err" || {
    status=$?
    echo "bench: record failed; see $run_dir/record.err" >&2
    exit "$status"
  }
end_ns="$(date +%s%N)"
wall_ns=$((end_ns - start_ns))
wall_s="$(awk -v ns="$wall_ns" 'BEGIN { printf "%.3f", ns / 1e9 }')"

# `time -v` writes its report to stderr; the record summary is also there.
summary="$(grep -E 'events.*decode errors' "$run_dir/record.err" | tail -1 || true)"
events="$(sed -nE 's/^recorded ([0-9]+) events.*/\1/p' "$run_dir/record.err" | tail -1)"
[[ -n "$events" ]] || events=0
user_s="$(sed -nE 's/^\s+User time \(seconds\): ([0-9.]+)/\1/p' "$run_dir/record.err" | tail -1)"
sys_s="$(sed -nE 's/^\s+System time \(seconds\): ([0-9.]+)/\1/p' "$run_dir/record.err" | tail -1)"
maxrss_kb="$(sed -nE 's/^\s+Maximum resident set size \(kbytes\): ([0-9]+)/\1/p' "$run_dir/record.err" | tail -1)"
[[ -n "$user_s" ]] || user_s=0
[[ -n "$sys_s" ]] || sys_s=0
[[ -n "$maxrss_kb" ]] || maxrss_kb=0
bundle_bytes="$(du -sb "$run_dir/bundle" 2>/dev/null | cut -f1)"
[[ -n "$bundle_bytes" ]] || bundle_bytes=0

# Query latency: five simple count queries against the completed bundle.
query_total_ns=0
for i in 1 2 3 4 5; do
  q0="$(date +%s%N)"
  "$binary" query "$run_dir/bundle" "select count(*) as n from events" >"$run_dir/query.txt" 2>"$run_dir/query.err"
  q1="$(date +%s%N)"
  query_total_ns=$((query_total_ns + q1 - q0))
done
query_avg_ms="$(awk -v ns="$query_total_ns" 'BEGIN { printf "%.3f", ns / 5 / 1e6 }')"

events_per_sec="$(awk -v n="$events" -v s="$wall_s" 'BEGIN { if (s > 0) printf "%.2f", n / s; else print 0 }')"
cpu_s="$(awk -v u="$user_s" -v s="$sys_s" 'BEGIN { printf "%.3f", u + s }')"
cpu_pct="$(awk -v c="$cpu_s" -v w="$wall_s" 'BEGIN { if (w > 0) printf "%.2f", 100 * c / w; else print 0 }')"

jq -n \
  --arg stamp "$stamp" \
  --arg workload "$workload" \
  --arg stacks "$stacks" \
  --argjson duration "$duration" \
  --arg wall_s "$wall_s" \
  --argjson events "$events" \
  --arg events_per_sec "$events_per_sec" \
  --arg user_s "$user_s" --arg sys_s "$sys_s" --arg cpu_s "$cpu_s" \
  --arg cpu_pct "$cpu_pct" --argjson maxrss_kb "$maxrss_kb" \
  --argjson bundle_bytes "$bundle_bytes" \
  --arg query_avg_ms "$query_avg_ms" \
  --arg summary "$summary" \
  '{schema_version: 1, stamp: $stamp, workload: $workload, stacks: $stacks,
    duration_s: $duration, wall_s: ($wall_s | tonumber),
    events: $events, events_per_sec: ($events_per_sec | tonumber),
    user_s: ($user_s | tonumber), sys_s: ($sys_s | tonumber),
    cpu_s: ($cpu_s | tonumber), cpu_pct: ($cpu_pct | tonumber),
    maxrss_kb: $maxrss_kb, bundle_bytes: $bundle_bytes,
    query_avg_ms: ($query_avg_ms | tonumber), record_summary: $summary}' \
  >"$run_dir/bench.json"

echo "bench: $run_dir/bench.json"
jq . "$run_dir/bench.json"
