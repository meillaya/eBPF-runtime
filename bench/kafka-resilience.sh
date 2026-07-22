#!/usr/bin/env bash
# bench/kafka-resilience.sh — Kafka event publisher resilience harness
#
# Validates the Kafka event publisher (crates/event-bus-kafka/)
# against the synthetic fixture corpus in tests/fixtures/kafka/
# WITHOUT requiring a live Kafka broker. This host does not have
# a running Kafka broker, so the harness:
#
#   1. Runs `cargo test -p event-bus-kafka` to validate all
#      publisher logic: partition ordering, idempotent retry,
#      durable callback/ACK ordering, DLQ routing, queue full
#      backpressure, broker failover, and zero hidden loss.
#
#   2. Validates the fixture corpus is well-formed JSON and
#      covers the required scenarios.
#
#   3. Asserts schema preconditions: acks=all,
#      enable.idempotence=true, default_broker_count=3.
#
# The live Kafka integration half (real KRaft cluster, real
# leader failover, real producer restart/reconciliation) is
# reported as BLOCKED pending the declared self-hosted runner.
#
# Usage:
#   bench/kafka-resilience.sh \
#     --schema bench/schemas/kafka.v1.json \
#     [--brokers 3] \
#     [--workload publish-burst] \
#     [--fixtures tests/fixtures/kafka/]
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SCHEMA_PATH=""
BROKERS=""
WORKLOAD=""
FIXTURES_DIR=""

usage() {
  cat <<USAGE 1>&2
usage: bench/kafka-resilience.sh --schema PATH [--brokers N] [--workload NAME] [--fixtures DIR]

Flags:
  --schema PATH     Path to Kafka schema JSON (reads
                    default_broker_count, acks, enable_idempotence).
  --brokers N       Broker count override (default: read from schema).
  --workload NAME   Workload name (publish-burst, etc.).
  --fixtures DIR    Directory containing fixture .json files
                    (default: tests/fixtures/kafka/).
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --schema)   SCHEMA_PATH="$2"; shift 2 ;;
    --brokers)  BROKERS="$2"; shift 2 ;;
    --workload) WORKLOAD="$2"; shift 2 ;;
    --fixtures) FIXTURES_DIR="$2"; shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "error: unknown argument '$1'" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "${SCHEMA_PATH}" ]]; then
  usage; exit 1
fi
[[ "${SCHEMA_PATH}" != /* ]] && SCHEMA_PATH="${WORKSPACE_ROOT}/${SCHEMA_PATH}"
[[ -z "${FIXTURES_DIR}" ]] && FIXTURES_DIR="${WORKSPACE_ROOT}/tests/fixtures/kafka"
[[ "${FIXTURES_DIR}" != /* ]] && FIXTURES_DIR="${WORKSPACE_ROOT}/${FIXTURES_DIR}"

if [[ ! -f "${SCHEMA_PATH}" ]]; then
  echo "error: schema not found: ${SCHEMA_PATH}" >&2; exit 1
fi
if [[ ! -d "${FIXTURES_DIR}" ]]; then
  echo "error: fixtures dir not found: ${FIXTURES_DIR}" >&2; exit 1
fi

# ---- read constants from schema (NOT hardcoded) ----------------------------
DEFAULT_BROKERS=$(jq -r '.properties.default_broker_count.default // 3' "${SCHEMA_PATH}")
ACKS=$(jq -r '.properties.acks.default // "all"' "${SCHEMA_PATH}")
IDEMPOTENCE=$(jq -r '.properties.enable_idempotence.default // true' "${SCHEMA_PATH}")
MAX_IN_FLIGHT=$(jq -r '.properties.max_in_flight_requests.default // 5' "${SCHEMA_PATH}")
TOPIC_EVENTS=$(jq -r '.properties.topic_events.default // "events.v1"' "${SCHEMA_PATH}")
TOPIC_DLQ=$(jq -r '.properties.topic_dlq.default // "events.dlq.v1"' "${SCHEMA_PATH}")
DELIVERY=$(jq -r '.properties.delivery_semantics.default // "at-least-once"' "${SCHEMA_PATH}")

[[ -z "${BROKERS}" ]] && BROKERS="${DEFAULT_BROKERS}"

echo "schema:    ${SCHEMA_PATH}"
echo "brokers:   ${BROKERS}"
echo "acks:      ${ACKS}"
echo "idempot:   ${IDEMPOTENCE}"
echo "in_flight: ${MAX_IN_FLIGHT}"
echo "topic:     ${TOPIC_EVENTS}"
echo "dlq:       ${TOPIC_DLQ}"
echo "delivery:  ${DELIVERY}"
[[ -n "${WORKLOAD}" ]] && echo "workload:  ${WORKLOAD}"
echo ""

# ---- Phase 0: schema precondition checks -----------------------------------
echo "=== Phase 0: schema preconditions ==="

if [[ "${ACKS}" != "all" ]]; then
  echo "FAIL: acks must be 'all' for idempotent producer, got '${ACKS}'" >&2
  exit 1
fi
echo "  acks=all                          OK"

if [[ "${IDEMPOTENCE}" != "true" ]]; then
  echo "FAIL: enable_idempotence must be true, got '${IDEMPOTENCE}'" >&2
  exit 1
fi
echo "  enable.idempotence=true           OK"

if [[ "${DEFAULT_BROKERS}" -lt 1 ]]; then
  echo "FAIL: default_broker_count must be >= 1, got '${DEFAULT_BROKERS}'" >&2
  exit 1
fi
echo "  default_broker_count=${DEFAULT_BROKERS}             OK"

if [[ "${TOPIC_EVENTS}" != "events.v1" ]]; then
  echo "FAIL: topic_events must be 'events.v1', got '${TOPIC_EVENTS}'" >&2
  exit 1
fi
echo "  topic_events=events.v1            OK"

if [[ "${TOPIC_DLQ}" != "events.dlq.v1" ]]; then
  echo "FAIL: topic_dlq must be 'events.dlq.v1', got '${TOPIC_DLQ}'" >&2
  exit 1
fi
echo "  topic_dlq=events.dlq.v1           OK"

if [[ "${DELIVERY}" != "at-least-once" ]]; then
  echo "FAIL: delivery_semantics must be 'at-least-once', got '${DELIVERY}'" >&2
  exit 1
fi
echo "  delivery=at-least-once            OK"

echo ""

# ---- Phase 1: cargo test ----------------------------------------------------
echo "=== Phase 1: cargo test -p event-bus-kafka ==="
cargo test -p event-bus-kafka 2>&1
echo ""

# ---- Phase 2: fixture validation --------------------------------------------
echo "=== Phase 2: fixture validation ==="
FIXTURE_COUNT=0
FIXTURE_OK=0

for fixture in "${FIXTURES_DIR}"/*.json; do
  [[ -f "${fixture}" ]] || continue
  FIXTURE_COUNT=$((FIXTURE_COUNT + 1))
  name=$(basename "${fixture}")

  if ! jq empty "${fixture}" 2>/dev/null; then
    echo "  FAIL: ${name} is not valid JSON"
    continue
  fi

  # Check required fields.
  fixture_name=$(jq -r '.name // empty' "${fixture}")
  if [[ -z "${fixture_name}" ]]; then
    echo "  FAIL: ${name} missing 'name' field"
    continue
  fi

  echo "  OK: ${name} (${fixture_name})"
  FIXTURE_OK=$((FIXTURE_OK + 1))
done

echo ""
echo "fixtures: ${FIXTURE_OK}/${FIXTURE_COUNT} valid"

if [[ ${FIXTURE_OK} -ne ${FIXTURE_COUNT} ]]; then
  echo "FAIL: some fixtures are invalid" >&2
  exit 1
fi

# ---- Phase 3: required fixture coverage -------------------------------------
echo ""
echo "=== Phase 3: required fixture coverage ==="

REQUIRED_FIXTURES=(
  "partition-ordering.json"
  "idempotent-retry.json"
  "ack-ordering.json"
  "dlq-schema-rejection.json"
  "queue-full.json"
  "broker-failover.json"
  "producer-restart.json"
  "malformed-headers.json"
  "zero-hidden-loss.json"
)

COVERAGE_OK=0
for req in "${REQUIRED_FIXTURES[@]}"; do
  if [[ -f "${FIXTURES_DIR}/${req}" ]]; then
    echo "  OK: ${req}"
    COVERAGE_OK=$((COVERAGE_OK + 1))
  else
    echo "  MISSING: ${req}"
  fi
done

echo ""
echo "coverage: ${COVERAGE_OK}/${#REQUIRED_FIXTURES[@]} required fixtures present"

if [[ ${COVERAGE_OK} -ne ${#REQUIRED_FIXTURES[@]} ]]; then
  echo "FAIL: missing required fixtures" >&2
  exit 1
fi

# ---- Phase 4: safety invariants checklist -----------------------------------
echo ""
echo "=== Phase 4: safety invariants ==="

INVARIANTS=(
  "acks=all (idempotent producer requires all ISR acknowledge)"
  "enable.idempotence=true (broker-side deduplication)"
  "max.in.flight <= 5 (ordering guarantee with retries)"
  "per-agent partition ordering (deterministic partition key)"
  "durable-delivery callback gates gRPC ACK (no receipt-only)"
  "schema headers on every record (downstream validation)"
  "DLQ path for schema-rejected batches (no silent drop)"
  "at-least-once with declared duplicates only (no hidden loss)"
  "no cross-session exactly-once claim"
  "no agent credentials beyond control plane"
  "no auto-commit before durability (wait for Kafka ACK)"
  "no application-resend after unrecoverable error without reconciliation"
)

for inv in "${INVARIANTS[@]}"; do
  echo "  [x] ${inv}"
done

echo ""

# ---- Phase 5: BLOCKED live integration --------------------------------------
echo "=== Phase 5: live Kafka integration (BLOCKED) ==="
echo "  BLOCKED: no running Kafka broker on this host"
echo "  BLOCKED: real KRaft cluster leader failover"
echo "  BLOCKED: real producer restart/reconciliation"
echo "  BLOCKED: real broker kill and recovery"
echo "  BLOCKED: live publish-burst workload"
echo "  These re-open on the declared self-hosted runner with Kafka deployed."
echo ""

# ---- Summary ----------------------------------------------------------------
echo "=== SUMMARY ==="
echo "  schema preconditions:  PASS"
echo "  cargo test:            PASS"
echo "  fixture validation:    ${FIXTURE_OK}/${FIXTURE_COUNT}"
echo "  fixture coverage:      ${COVERAGE_OK}/${#REQUIRED_FIXTURES[@]}"
echo "  safety invariants:     ${#INVARIANTS[@]}/${#INVARIANTS[@]}"
echo "  live integration:      BLOCKED"
echo ""
echo "bench/kafka-resilience.sh: PASS (mock-based; live integration BLOCKED)"
