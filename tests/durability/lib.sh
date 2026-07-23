#!/usr/bin/env bash
# tests/durability/lib.sh — shared helpers for durability integration tests.
#
# Provides: psql_exec, kafka_exec, ch_query, pass/fail counters,
# cleanup trap, and schema constant loading.
#
# Infrastructure access:
#   PostgreSQL: podman exec k1-postgres psql
#   Kafka:      podman exec k1-kafka kafka-*
#   ClickHouse: curl http://127.0.0.1:8123
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

# ---- counters ----------------------------------------------------------------
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TEST_NAMES=()

# ---- infrastructure endpoints ------------------------------------------------
PG_CONTAINER="${PG_CONTAINER:-k1-postgres}"
PG_USER="${PG_USER:-control_app}"
PG_DB="${PG_DB:-kernel_v1}"
KAFKA_CONTAINER="${KAFKA_CONTAINER:-k1-kafka}"
KAFKA_BOOTSTRAP="${KAFKA_BOOTSTRAP:-localhost:9092}"
CH_URL="${CH_URL:-http://127.0.0.1:8123}"

# ---- schema constants (loaded by load_schema) --------------------------------
SCHEMA_PATH=""
MESSAGE_COUNT=1000
PRODUCE_TIMEOUT_MS=30000
CONSUME_TIMEOUT_MS=30000
PG_MAX_CONNECTIONS=100
PG_POOL_RESERVE=3
PG_STATEMENT_TIMEOUT_MS=5000
CH_EVENTS_TTL_DAYS=30
CH_DLQ_TTL_DAYS=90
CH_DEDUP_MERGE_WAIT_S=10
KAFKA_TOPIC_PARTITIONS=3
KAFKA_REPLICATION_FACTOR=1
KAFKA_ACKS="all"
KAFKA_CONSUMER_GROUP_COUNT=2
OUTBOX_RETRY_COUNT=3
DELIVERY_SEMANTICS="at-least-once"
TEST_PREFIX="durability_test_"

# ---- load_schema: read constants from bench/schemas/durability.v1.json -------
load_schema() {
  SCHEMA_PATH="${1:-}"
  if [[ -z "${SCHEMA_PATH}" ]]; then
    echo "error: --schema PATH required" >&2
    exit 1
  fi
  [[ "${SCHEMA_PATH}" != /* ]] && SCHEMA_PATH="$(pwd)/${SCHEMA_PATH}"
  if [[ ! -f "${SCHEMA_PATH}" ]]; then
    echo "error: schema not found: ${SCHEMA_PATH}" >&2
    exit 1
  fi

  MESSAGE_COUNT=$(jq -r '.properties.message_count.default // 1000' "${SCHEMA_PATH}")
  PRODUCE_TIMEOUT_MS=$(jq -r '.properties.produce_timeout_ms.default // 30000' "${SCHEMA_PATH}")
  CONSUME_TIMEOUT_MS=$(jq -r '.properties.consume_timeout_ms.default // 30000' "${SCHEMA_PATH}")
  PG_MAX_CONNECTIONS=$(jq -r '.properties.pg_max_connections.default // 100' "${SCHEMA_PATH}")
  PG_POOL_RESERVE=$(jq -r '.properties.pg_pool_exhaustion_reserve.default // 3' "${SCHEMA_PATH}")
  PG_STATEMENT_TIMEOUT_MS=$(jq -r '.properties.pg_statement_timeout_ms.default // 5000' "${SCHEMA_PATH}")
  CH_EVENTS_TTL_DAYS=$(jq -r '.properties.ch_events_ttl_days.default // 30' "${SCHEMA_PATH}")
  CH_DLQ_TTL_DAYS=$(jq -r '.properties.ch_dlq_ttl_days.default // 90' "${SCHEMA_PATH}")
  CH_DEDUP_MERGE_WAIT_S=$(jq -r '.properties.ch_dedup_merge_wait_s.default // 10' "${SCHEMA_PATH}")
  KAFKA_TOPIC_PARTITIONS=$(jq -r '.properties.kafka_topic_partitions.default // 3' "${SCHEMA_PATH}")
  KAFKA_REPLICATION_FACTOR=$(jq -r '.properties.kafka_replication_factor.default // 1' "${SCHEMA_PATH}")
  KAFKA_ACKS=$(jq -r '.properties.kafka_acks.default // "all"' "${SCHEMA_PATH}")
  KAFKA_CONSUMER_GROUP_COUNT=$(jq -r '.properties.kafka_consumer_group_count.default // 2' "${SCHEMA_PATH}")
  OUTBOX_RETRY_COUNT=$(jq -r '.properties.outbox_retry_count.default // 3' "${SCHEMA_PATH}")
  DELIVERY_SEMANTICS=$(jq -r '.properties.delivery_semantics.default // "at-least-once"' "${SCHEMA_PATH}")
  TEST_PREFIX=$(jq -r '.properties.test_prefix.default // "durability_test_"' "${SCHEMA_PATH}")
}

# ---- psql_exec: run SQL against PostgreSQL via podman exec -------------------
# Usage: psql_exec "SELECT 1"
# Returns: query output on stdout, exit code from psql.
psql_exec() {
  podman exec "${PG_CONTAINER}" psql \
    -U "${PG_USER}" -d "${PG_DB}" \
    -v ON_ERROR_STOP=1 \
    -t -A \
    -c "$1" 2>&1
}

# psql_exec_allow_fail: like psql_exec but does not set -e on failure.
psql_exec_allow_fail() {
  podman exec "${PG_CONTAINER}" psql \
    -U "${PG_USER}" -d "${PG_DB}" \
    -t -A \
    -c "$1" 2>&1 || true
}

# ---- kafka_exec: run Kafka CLI tools via podman exec -------------------------
# Usage: kafka_exec kafka-topics --list
kafka_exec() {
  podman exec "${KAFKA_CONTAINER}" "$@" 2>&1
}

# ---- ch_query: run a ClickHouse query via HTTP -------------------------------
# Usage: ch_query "SELECT 1"
ch_query() {
  curl -sf "${CH_URL}/" --data-binary "$1" 2>&1
}

# ch_query_allow_fail: like ch_query but returns empty on failure.
ch_query_allow_fail() {
  curl -s "${CH_URL}/" --data-binary "$1" 2>&1 || true
}

# ---- test result helpers -----------------------------------------------------
pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  TEST_NAMES+=("PASS: $1")
  echo "  PASS: $1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  TEST_NAMES+=("FAIL: $1")
  echo "  FAIL: $1" >&2
}

skip() {
  SKIP_COUNT=$((SKIP_COUNT + 1))
  TEST_NAMES+=("SKIP: $1")
  echo "  SKIP: $1"
}

# assert_eq: assert two values are equal.
assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    pass "${desc}"
  else
    fail "${desc} (expected='${expected}', actual='${actual}')"
  fi
}

# assert_ge: assert actual >= expected (numeric).
assert_ge() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "${actual}" -ge "${expected}" ]] 2>/dev/null; then
    pass "${desc}"
  else
    fail "${desc} (expected >= ${expected}, actual='${actual}')"
  fi
}

# assert_contains: assert haystack contains needle.
assert_contains() {
  local desc="$1" haystack="$2" needle="$3"
  if echo "${haystack}" | grep -qF "${needle}"; then
    pass "${desc}"
  else
    fail "${desc} (expected to contain '${needle}')"
  fi
}

# assert_not_contains: assert haystack does NOT contain needle.
assert_not_contains() {
  local desc="$1" haystack="$2" needle="$3"
  if echo "${haystack}" | grep -qF "${needle}"; then
    fail "${desc} (should NOT contain '${needle}')"
  else
    pass "${desc}"
  fi
}

# ---- cleanup tracking --------------------------------------------------------
CLEANUP_PG_TABLES=()
CLEANUP_KAFKA_TOPICS=()
CLEANUP_CH_TABLES=()
CLEANUP_KAFKA_GROUPS=()

register_pg_cleanup() { CLEANUP_PG_TABLES+=("$1"); }
register_kafka_cleanup() { CLEANUP_KAFKA_TOPICS+=("$1"); }
register_ch_cleanup() { CLEANUP_CH_TABLES+=("$1"); }
register_kafka_group_cleanup() { CLEANUP_KAFKA_GROUPS+=("$1"); }

run_cleanup() {
  echo ""
  echo "=== Cleanup ==="

  for tbl in "${CLEANUP_PG_TABLES[@]+"${CLEANUP_PG_TABLES[@]}"}"; do
    echo "  dropping PG table: ${tbl}"
    psql_exec_allow_fail "DROP TABLE IF EXISTS ${tbl} CASCADE" >/dev/null 2>&1 || true
  done

  for topic in "${CLEANUP_KAFKA_TOPICS[@]+"${CLEANUP_KAFKA_TOPICS[@]}"}"; do
    echo "  deleting Kafka topic: ${topic}"
    kafka_exec kafka-topics --bootstrap-server "${KAFKA_BOOTSTRAP}" --delete --topic "${topic}" >/dev/null 2>&1 || true
  done

  for tbl in "${CLEANUP_CH_TABLES[@]+"${CLEANUP_CH_TABLES[@]}"}"; do
    echo "  dropping CH table: ${tbl}"
    ch_query_allow_fail "DROP TABLE IF EXISTS ${tbl}" >/dev/null 2>&1 || true
  done

  for grp in "${CLEANUP_KAFKA_GROUPS[@]+"${CLEANUP_KAFKA_GROUPS[@]}"}"; do
    echo "  deleting Kafka consumer group: ${grp}"
    kafka_exec kafka-consumer-groups --bootstrap-server "${KAFKA_BOOTSTRAP}" --delete --group "${grp}" >/dev/null 2>&1 || true
  done

  echo "  cleanup complete"
}

trap run_cleanup EXIT

# ---- summary -----------------------------------------------------------------
print_summary() {
  local suite_name="${1:-durability}"
  echo ""
  echo "=== ${suite_name} SUMMARY ==="
  echo "  passed: ${PASS_COUNT}"
  echo "  failed: ${FAIL_COUNT}"
  echo "  skipped: ${SKIP_COUNT}"
  echo ""
  if [[ ${FAIL_COUNT} -gt 0 ]]; then
    echo "  FAILED TESTS:"
    for t in "${TEST_NAMES[@]}"; do
      [[ "${t}" == FAIL:* ]] && echo "    ${t}"
    done
    echo ""
    echo "${suite_name}: FAIL"
    return 1
  fi
  echo "${suite_name}: PASS"
  return 0
}
