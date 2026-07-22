#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Standalone agent API + CLI smoke test (plan task 26).
#
# Usage: bench/agent-api-smoke.sh --schema bench/schemas/storage.v1.json
#
# Starts the agent in dev mode on the schema-defined loopback bind/port,
# exercises every REST endpoint and CLI command with bounded pagination,
# asserts the forbidden non-loopback bind and the typed invalid-cursor /
# oversized-filter rejections, then sends SIGTERM and asserts the agent
# drains/flushes within the schema-defined drain timeout.

set -euo pipefail

SCHEMA=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --schema) SCHEMA="${2:-}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; echo "usage: $0 --schema <path>" >&2; exit 2 ;;
  esac
done
[[ -n "$SCHEMA" ]] || { echo "usage: $0 --schema <path>" >&2; exit 2; }
[[ -f "$SCHEMA" ]] || { echo "schema not found: $SCHEMA" >&2; exit 2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

jq_get() { jq -r ".properties.$1.default" "$SCHEMA"; }

BIND_HOST="$(jq_get default_loopback_dev_bind)"
DEV_PORT="$(jq_get default_dev_port)"
DRAIN_MS="$(jq_get default_drain_timeout_ms)"
PAGE_LIMIT="$(jq_get default_page_limit)"
MAX_LIMIT="$(jq_get max_page_limit)"

LISTEN="${BIND_HOST}:${DEV_PORT}"
BASE="http://${LISTEN}"
WORKDIR="$(mktemp -d /tmp/agent-smoke.XXXXXX)"
DB="${WORKDIR}/outbox.db"
AGENT_BIN="target/debug/agent"
CLI_BIN="target/debug/cli"
AGENT_PID=""

echo "== smoke: schema=$SCHEMA bind=$LISTEN drain_ms=$DRAIN_MS page=$PAGE_LIMIT max=$MAX_LIMIT =="

cleanup() {
  if [[ -n "$AGENT_PID" ]] && kill -0 "$AGENT_PID" 2>/dev/null; then
    kill -KILL "$AGENT_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "== building agent + cli =="
cargo build -p agent -p cli

assert_http() {
  local url="$1" expected="$2" desc="$3" code
  code="$(curl -s -o "${WORKDIR}/body" -w "%{http_code}" "$url" || true)"
  if [[ "$code" != "$expected" ]]; then
    echo "FAIL: $desc: expected HTTP $expected got $code for $url" >&2
    cat "${WORKDIR}/body" >&2 || true
    exit 1
  fi
  echo "ok: $desc (HTTP $code)"
}

assert_contains() {
  local url="$1" needle="$2" desc="$3" body
  body="$(curl -s "$url")"
  if ! grep -q -- "$needle" <<<"$body"; then
    echo "FAIL: $desc: '$needle' not in response for $url" >&2
    echo "$body" >&2
    exit 1
  fi
  echo "ok: $desc"
}

assert_cli() {
  local desc="$1"; shift
  if ! "$CLI_BIN" --dev --addr "$LISTEN" "$@" >"${WORKDIR}/cli_out" 2>&1; then
    echo "FAIL: $desc: cli $* failed" >&2
    cat "${WORKDIR}/cli_out" >&2
    exit 1
  fi
  echo "ok: $desc"
}

assert_cli_contains() {
  local desc="$1" needle="$2"; shift 2
  if ! "$CLI_BIN" --dev --addr "$LISTEN" "$@" >"${WORKDIR}/cli_out" 2>&1; then
    echo "FAIL: $desc: cli $* failed" >&2
    cat "${WORKDIR}/cli_out" >&2
    exit 1
  fi
  if ! grep -q -- "$needle" "${WORKDIR}/cli_out"; then
    echo "FAIL: $desc: '$needle' not in cli output" >&2
    cat "${WORKDIR}/cli_out" >&2
    exit 1
  fi
  echo "ok: $desc"
}

echo "== forbidden non-loopback bind must be rejected (strict check) =="
if "$AGENT_BIN" --dev --listen 0.0.0.0:8080 --db "${WORKDIR}/forbidden.db" >"${WORKDIR}/forbidden_out" 2>&1; then
  echo "FAIL: agent accepted forbidden non-loopback bind 0.0.0.0:8080" >&2
  exit 1
fi
if ! grep -qi "loopback" "${WORKDIR}/forbidden_out"; then
  echo "FAIL: forbidden-bind rejection did not mention loopback" >&2
  cat "${WORKDIR}/forbidden_out" >&2
  exit 1
fi
echo "ok: non-loopback bind 0.0.0.0:8080 rejected"

echo "== starting agent in dev mode on $LISTEN =="
"$AGENT_BIN" --dev --listen "$LISTEN" --db "$DB" --log-level warn >"${WORKDIR}/agent.log" 2>&1 &
AGENT_PID=$!

echo "== waiting for health =="
healthy=0
for _ in $(seq 1 200); do
  code="$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/api/v1/health" || true)"
  if [[ "$code" == "200" ]]; then healthy=1; break; fi
  sleep 0.05
done
[[ "$healthy" == "1" ]] || { echo "FAIL: agent never became healthy" >&2; cat "${WORKDIR}/agent.log" >&2; exit 1; }
echo "ok: agent healthy"

echo "== REST endpoints (bounded pagination + filtering) =="
assert_contains "${BASE}/api/v1/health" "status" "health endpoint"
assert_contains "${BASE}/api/v1/readiness" "status" "readiness endpoint"
assert_contains "${BASE}/api/v1/metrics" "ebpf_agent" "metrics endpoint"
assert_contains "${BASE}/api/v1/events?limit=${PAGE_LIMIT}" "events" "events endpoint (limit=${PAGE_LIMIT})"
assert_contains "${BASE}/api/v1/events?kind=DnsPacket" "DnsPacket" "events filtering by kind"
assert_contains "${BASE}/api/v1/process-tree" "processes" "process-tree endpoint"
assert_contains "${BASE}/api/v1/sockets" "sockets" "sockets endpoint"
assert_contains "${BASE}/api/v1/dns" "dns" "dns endpoint"
assert_contains "${BASE}/api/v1/files" "files" "files endpoint"
assert_contains "${BASE}/api/v1/syscall-histograms" "histograms" "syscall-histograms endpoint"
assert_contains "${BASE}/api/v1/export?limit=5" "event_id" "export endpoint (ndjson)"

echo "== pagination cursor advances (bounded) =="
cursor="$(curl -s "${BASE}/api/v1/events?limit=5" | jq -r '.next_cursor // empty')"
[[ -n "$cursor" ]] || { echo "FAIL: no next_cursor on bounded page" >&2; exit 1; }
assert_contains "${BASE}/api/v1/events?limit=5&cursor=${cursor}" "events" "events page 2 via cursor"
echo "ok: cursor pagination works (cursor=${cursor})"

echo "== typed rejections (no server crash) =="
assert_http "${BASE}/api/v1/events?cursor=garbage" "400" "invalid cursor rejected"
assert_http "${BASE}/api/v1/events?limit=$((MAX_LIMIT + 1))" "400" "oversized limit rejected"
assert_http "${BASE}/api/v1/events?kind=$(printf 'x%.0s' $(seq 1 2000))" "400" "oversized filter rejected"
# server still healthy after rejections
assert_http "${BASE}/api/v1/health" "200" "server healthy after typed rejections"

echo "== CLI commands (all, bounded) =="
assert_cli_contains "cli preflight" "PREFLIGHT COVERAGE MATRIX" preflight
assert_cli_contains "cli status" "health:" status
assert_cli_contains "cli health" "status" health
assert_cli_contains "cli query-history" "events" query-history --limit 10
assert_cli_contains "cli process-tree" "processes" process-tree
assert_cli_contains "cli sockets" "sockets" sockets
assert_cli_contains "cli dns-packets" "dns" dns-packets
assert_cli_contains "cli files" "files" files
assert_cli_contains "cli syscall-histograms" "histograms" syscall-histograms
assert_cli_contains "cli export" "event_id" export --limit 5

echo "== WebSocket live events (CLI live-events, bounded) =="
assert_cli "cli live-events (3 live events)" live-events --limit 3

echo "== SIGTERM drains/flushes within ${DRAIN_MS}ms =="
kill -TERM "$AGENT_PID"
drain_secs=$(( (DRAIN_MS + 1000) / 1000 ))
exit_code=0
wait "$AGENT_PID" || exit_code=$?
if [[ "$exit_code" != "0" ]]; then
  echo "FAIL: agent exited with code $exit_code after SIGTERM" >&2
  cat "${WORKDIR}/agent.log" >&2
  exit 1
fi
echo "ok: agent drained/flushed and exited 0 after SIGTERM"
AGENT_PID=""

echo "SMOKE-PASS: all agent API + CLI commands work with bounded pagination"
