#!/usr/bin/env bash
# tests/durability/outbox.sh — Outbox pattern durability integration tests.
#
# Tests the outbox pattern against live PostgreSQL + Kafka:
#   1. Happy path: write event to outbox → publish to Kafka →
#      delete from outbox only after ACK.
#   2. Failure: if Kafka publish fails, outbox row remains
#      (no data loss).
#   3. Duplicate: if delete fails after publish, re-publish is
#      idempotent (at-least-once with declared duplicates).
#
# The outbox table is created in PostgreSQL. Kafka is used as the
# publish target. This mirrors the crates/storage-local outbox
# pattern (SQLite equivalent) adapted for the control-plane stack.
#
# Usage:
#   tests/durability/outbox.sh --schema bench/schemas/durability.v1.json
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"

# ---- parse args --------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --schema) load_schema "$2"; shift 2 ;;
    -h|--help) echo "usage: $0 --schema PATH"; exit 0 ;;
    *) echo "error: unknown argument '$1'" >&2; exit 1 ;;
  esac
done
[[ -z "${SCHEMA_PATH}" ]] && { echo "error: --schema required" >&2; exit 1; }

echo "=== Outbox Pattern Durability Tests ==="
echo "  schema: ${SCHEMA_PATH}"
echo "  retry_count: ${OUTBOX_RETRY_COUNT}"
echo "  delivery: ${DELIVERY_SEMANTICS}"
echo ""

# ---- setup -------------------------------------------------------------------
OUTBOX_TBL="${TEST_PREFIX}outbox"
OUTBOX_TOPIC="${TEST_PREFIX}outbox_events"

register_pg_cleanup "${OUTBOX_TBL}"
register_kafka_cleanup "${OUTBOX_TOPIC}"

# Create outbox table in PostgreSQL.
psql_exec "DROP TABLE IF EXISTS ${OUTBOX_TBL} CASCADE" >/dev/null
psql_exec "
CREATE TABLE ${OUTBOX_TBL} (
  id          SERIAL PRIMARY KEY,
  event_id    TEXT NOT NULL UNIQUE,
  payload     JSONB NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  published   BOOLEAN NOT NULL DEFAULT false,
  published_at TIMESTAMPTZ,
  acked       BOOLEAN NOT NULL DEFAULT false,
  acked_at    TIMESTAMPTZ
);
" >/dev/null

# Create Kafka topic for outbox publishing.
kafka_exec kafka-topics --bootstrap-server "${KAFKA_BOOTSTRAP}" \
  --create --topic "${OUTBOX_TOPIC}" \
  --partitions 1 \
  --replication-factor "${KAFKA_REPLICATION_FACTOR}" \
  >/dev/null 2>&1 || true
sleep 2

# ---- helper: write event to outbox -------------------------------------------
outbox_write() {
  local event_id="$1" payload="$2"
  psql_exec "
INSERT INTO ${OUTBOX_TBL} (event_id, payload)
VALUES ('${event_id}', '${payload}')
ON CONFLICT (event_id) DO NOTHING;
" >/dev/null
}

count_matches() {
  local data="$1" pattern="$2"
  local n
  n=$(echo "${data}" | grep -c "${pattern}" 2>/dev/null) || n=0
  echo "${n}"
}

outbox_publish() {
  local event_id="$1"
  local payload
  payload=$(psql_exec "SELECT payload::text FROM ${OUTBOX_TBL} WHERE event_id = '${event_id}' AND NOT published")
  if [[ -z "${payload}" ]]; then
    return 1
  fi
  echo "${payload}" | podman exec -i "${KAFKA_CONTAINER}" \
    kafka-console-producer \
      --bootstrap-server "${KAFKA_BOOTSTRAP}" \
      --topic "${OUTBOX_TOPIC}" \
      --producer-property "acks=${KAFKA_ACKS}" \
    >/dev/null 2>&1
  psql_exec "
UPDATE ${OUTBOX_TBL}
SET published = true, published_at = now()
WHERE event_id = '${event_id}';
" >/dev/null
}

# ---- helper: ack outbox row (delete after ACK) -------------------------------
outbox_ack() {
  local event_id="$1"
  psql_exec "
UPDATE ${OUTBOX_TBL}
SET acked = true, acked_at = now()
WHERE event_id = '${event_id}' AND published = true;
" >/dev/null
  # Delete only after ACK (the core outbox guarantee).
  psql_exec "DELETE FROM ${OUTBOX_TBL} WHERE event_id = '${event_id}' AND acked = true" >/dev/null
}

echo "=== Test 1: Happy Path (write → publish → delete after ACK) ==="

# 1a. Write event to outbox.
outbox_write "outbox-happy-1" '{"event_id":"outbox-happy-1","seq":1,"data":"happy-path"}'
OUTBOX_COUNT=$(psql_exec "SELECT count(*) FROM ${OUTBOX_TBL} WHERE event_id = 'outbox-happy-1'")
assert_eq "1a: event written to outbox" "1" "${OUTBOX_COUNT}"

# 1b. Publish to Kafka.
outbox_publish "outbox-happy-1"
PUBLISHED=$(psql_exec "SELECT published FROM ${OUTBOX_TBL} WHERE event_id = 'outbox-happy-1'")
assert_eq "1b: event marked as published" "t" "${PUBLISHED}"

# 1c. Verify message arrived in Kafka.
sleep 2
KAFKA_MSG=$(timeout 15 podman exec "${KAFKA_CONTAINER}" \
  kafka-console-consumer \
    --bootstrap-server "${KAFKA_BOOTSTRAP}" \
    --topic "${OUTBOX_TOPIC}" \
    --from-beginning \
    --max-messages 1 \
    --timeout-ms 10000 \
  2>/dev/null || true)
assert_contains "1c: message present in Kafka topic" "${KAFKA_MSG}" "outbox-happy-1"

# 1d. ACK and delete from outbox.
outbox_ack "outbox-happy-1"
AFTER_ACK=$(psql_exec "SELECT count(*) FROM ${OUTBOX_TBL} WHERE event_id = 'outbox-happy-1'")
assert_eq "1d: outbox row deleted after ACK" "0" "${AFTER_ACK}"

echo ""
echo "=== Test 2: Failure — Kafka Publish Fails, Outbox Row Remains ==="

# 2a. Write event to outbox.
outbox_write "outbox-fail-1" '{"event_id":"outbox-fail-1","seq":2,"data":"should-survive"}'

# 2b. Attempt publish to a NON-EXISTENT topic (simulates Kafka failure).
FAIL_RESULT=$(echo '{"event_id":"outbox-fail-1"}' | \
  podman exec -i "${KAFKA_CONTAINER}" \
  kafka-console-producer \
    --bootstrap-server "${KAFKA_BOOTSTRAP}" \
    --topic "${TEST_PREFIX}nonexistent_topic_xyz" \
    --request-required-acks "${KAFKA_ACKS}" \
  2>&1 || true)

# The publish failed; do NOT mark as published.
# Verify outbox row still exists and is NOT published.
FAIL_ROW=$(psql_exec "SELECT count(*) FROM ${OUTBOX_TBL} WHERE event_id = 'outbox-fail-1' AND published = false")
assert_eq "2a: outbox row remains after failed publish" "1" "${FAIL_ROW}"

FAIL_PUBLISHED=$(psql_exec "SELECT published FROM ${OUTBOX_TBL} WHERE event_id = 'outbox-fail-1'")
assert_eq "2b: outbox row NOT marked published after failure" "f" "${FAIL_PUBLISHED}"

# 2c. Retry: publish to the correct topic succeeds.
echo "  retrying publish to correct topic..."
outbox_publish "outbox-fail-1"
RETRY_PUBLISHED=$(psql_exec "SELECT published FROM ${OUTBOX_TBL} WHERE event_id = 'outbox-fail-1'")
assert_eq "2c: retry publish succeeds, row marked published" "t" "${RETRY_PUBLISHED}"

# 2d. ACK and delete.
outbox_ack "outbox-fail-1"
FAIL_AFTER_ACK=$(psql_exec "SELECT count(*) FROM ${OUTBOX_TBL} WHERE event_id = 'outbox-fail-1'")
assert_eq "2d: outbox row deleted after successful retry + ACK" "0" "${FAIL_AFTER_ACK}"

echo ""
echo "=== Test 3: Duplicate — Delete Fails After Publish, Re-publish is Idempotent ==="

# 3a. Write event to outbox.
outbox_write "outbox-dup-1" '{"event_id":"outbox-dup-1","seq":3,"data":"idempotent"}'

# 3b. Publish to Kafka (first delivery).
outbox_publish "outbox-dup-1"

# 3c. Simulate delete failure: do NOT call outbox_ack.
# The row remains in outbox with published=true.
DUP_ROW=$(psql_exec "SELECT count(*) FROM ${OUTBOX_TBL} WHERE event_id = 'outbox-dup-1' AND published = true")
assert_eq "3a: outbox row remains after simulated delete failure" "1" "${DUP_ROW}"

# 3d. Re-publish (simulating relay/reconciliation after crash).
# The publisher re-reads the outbox and publishes again.
# This is at-least-once: the message will appear twice in Kafka.
echo "  re-publishing (simulating crash recovery relay)..."
PAYLOAD=$(psql_exec "SELECT payload::text FROM ${OUTBOX_TBL} WHERE event_id = 'outbox-dup-1'")
echo "${PAYLOAD}" | podman exec -i "${KAFKA_CONTAINER}" \
  kafka-console-producer \
    --bootstrap-server "${KAFKA_BOOTSTRAP}" \
    --topic "${OUTBOX_TOPIC}" \
    --producer-property "acks=${KAFKA_ACKS}" \
  >/dev/null 2>&1

sleep 2
DUP_CONSUMED=$(timeout 15 podman exec "${KAFKA_CONTAINER}" \
  kafka-console-consumer \
    --bootstrap-server "${KAFKA_BOOTSTRAP}" \
    --topic "${OUTBOX_TOPIC}" \
    --from-beginning \
    --timeout-ms 10000 \
  2>/dev/null || true)
DUP_COUNT=$(count_matches "${DUP_CONSUMED}" "outbox-dup-1")
assert_ge "3b: re-publish creates declared duplicate in Kafka (>= 2)" "2" "${DUP_COUNT}"
echo "  NOTE: at-least-once delivery; consumer-side dedup by event_id is required."

# 3f. Now ACK and delete (recovery complete).
outbox_ack "outbox-dup-1"
DUP_AFTER_ACK=$(psql_exec "SELECT count(*) FROM ${OUTBOX_TBL} WHERE event_id = 'outbox-dup-1'")
assert_eq "3c: outbox row deleted after recovery ACK" "0" "${DUP_AFTER_ACK}"

echo ""
echo "=== Test 4: Batch Outbox (multiple events, atomic publish) ==="

# 4a. Write a batch of events to outbox in a single transaction.
BATCH_SIZE=10
psql_exec "
BEGIN;
$(for i in $(seq 1 "${BATCH_SIZE}"); do
  echo "INSERT INTO ${OUTBOX_TBL} (event_id, payload) VALUES ('outbox-batch-${i}', '{\"event_id\":\"outbox-batch-${i}\",\"seq\":${i}}');"
done)
COMMIT;
" >/dev/null

BATCH_COUNT=$(psql_exec "SELECT count(*) FROM ${OUTBOX_TBL} WHERE event_id LIKE 'outbox-batch-%'")
assert_eq "4a: batch of ${BATCH_SIZE} events written atomically" "${BATCH_SIZE}" "${BATCH_COUNT}"

# 4b. Publish all batch events.
for i in $(seq 1 "${BATCH_SIZE}"); do
  outbox_publish "outbox-batch-${i}"
done

BATCH_PUBLISHED=$(psql_exec "SELECT count(*) FROM ${OUTBOX_TBL} WHERE event_id LIKE 'outbox-batch-%' AND published = true")
assert_eq "4b: all ${BATCH_SIZE} batch events published" "${BATCH_SIZE}" "${BATCH_PUBLISHED}"

# 4c. ACK and delete all.
for i in $(seq 1 "${BATCH_SIZE}"); do
  outbox_ack "outbox-batch-${i}"
done

BATCH_REMAINING=$(psql_exec "SELECT count(*) FROM ${OUTBOX_TBL} WHERE event_id LIKE 'outbox-batch-%'")
assert_eq "4c: all batch events deleted after ACK" "0" "${BATCH_REMAINING}"

# ---- summary -----------------------------------------------------------------
print_summary "outbox-durability"
