#!/usr/bin/env bash
# Verify the development compose data path from inside the rootful VM.
# Run as root with the compose provider on PATH, for example:
#   sudo env PATH="/home/core/bin:$PATH" bash scripts/verify-compose.sh

set -euo pipefail

file="${COMPOSE_FILE:-compose.yaml}"
compose=(podman compose -f "$file")
api="${API_BASE:-http://127.0.0.1:8080}"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }

"${compose[@]}" ps
curl -fsS "$api/healthz" >/dev/null || fail "healthz"
pass "healthz"
curl -fsS "$api/readyz" >/dev/null || fail "readyz"
pass "readyz"

events=$(curl -fsS "$api/api/v1/events?limit=5")
grep -q '"event_id"' <<<"$events" || fail "no events returned"
pass "events returned"
agents=$(curl -fsS "$api/api/v1/agents")
grep -q '"spiffe_id"' <<<"$agents" || fail "no agents returned"
pass "agent registered"

"${compose[@]}" exec -T agent /usr/local/bin/ebpf-runtime check \
  | tee /tmp/ebpf-sensor-table.txt
awk 'NR > 1 { if ($3 < 1 || $4 != 0 || $5 != 0) bad = 1 } END { exit bad }' \
  /tmp/ebpf-sensor-table.txt || fail "sensor table has a blocked or failed sensor"
pass "sensors attached"

before=$("${compose[@]}" exec -T clickhouse clickhouse-client --query "SELECT count() FROM ebpf.events" | tr -d '[:space:]')
sleep 5
after=$("${compose[@]}" exec -T clickhouse clickhouse-client --query "SELECT count() FROM ebpf.events" | tr -d '[:space:]')
[[ "$before" =~ ^[0-9]+$ && "$after" =~ ^[0-9]+$ ]] || fail "ClickHouse count is not numeric"
(( after > before )) || fail "ClickHouse count did not rise ($before -> $after)"
pass "ClickHouse projection rises ($before -> $after)"

curl -fsS "$api/" | grep -qi "eBPF fleet" || fail "dashboard index did not load"
pass "dashboard index loads"

echo "compose data path verified"
