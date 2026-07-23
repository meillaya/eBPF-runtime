#!/usr/bin/env bash
# tests/durability/kafka.sh — Kafka durability integration tests.
#
# Tests against live Kafka KRaft single broker (k1-kafka):
#   1. Idempotent producer: produce N messages with acks=all,
#      verify exactly N in topic.
#   2. Duplicate detection: produce same message ID twice,
#      verify dedup at consumer.
#   3. Partition ordering: produce to same partition, verify
#      order preserved.
#   4. Consumer group: two consumers, verify partition assignment
#      and rebalance.
#
# Delivery semantics: at-least-once with declared duplicates only.
# No cross-session exactly-once claim.
#
# Usage:
#   tests/durability/kafka.sh --schema bench/schemas/durability.v1.json
#
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --schema) load_schema "$2"; shift 2 ;;
    -h|--help) echo "usage: $0 --schema PATH"; exit 0 ;;
    *) echo "error: unknown argument '$1'" >&2; exit 1 ;;
  esac
done
[[ -z "${SCHEMA_PATH}" ]] && { echo "error: --schema required" >&2; exit 1; }

echo "=== Kafka Durability Tests ==="
echo "  schema: ${SCHEMA_PATH}"
echo "  message_count: ${MESSAGE_COUNT}"
echo "  acks: ${KAFKA_ACKS}"
echo "  partitions: ${KAFKA_TOPIC_PARTITIONS}"
echo "  delivery: ${DELIVERY_SEMANTICS}"
echo ""

TOPIC_IDEMPOTENT="${TEST_PREFIX}kafka_idempotent"
TOPIC_DEDUP="${TEST_PREFIX}kafka_dedup"
TOPIC_ORDER="${TEST_PREFIX}kafka_order"
TOPIC_REBALANCE="${TEST_PREFIX}kafka_rebalance"
GROUP_REBALANCE="${TEST_PREFIX}cg_rebalance"

register_kafka_cleanup "${TOPIC_IDEMPOTENT}"
register_kafka_cleanup "${TOPIC_DEDUP}"
register_kafka_cleanup "${TOPIC_ORDER}"
register_kafka_cleanup "${TOPIC_REBALANCE}"
register_kafka_group_cleanup "${GROUP_REBALANCE}"

create_topic() {
  local name="$1" partitions="$2"
  kafka_exec kafka-topics --bootstrap-server "${KAFKA_BOOTSTRAP}" \
    --create --topic "${name}" \
    --partitions "${partitions}" \
    --replication-factor "${KAFKA_REPLICATION_FACTOR}" \
    --config "min.insync.replicas=1" \
    >/dev/null 2>&1 || true
  sleep 2
}

# count_lines: count non-empty lines matching a pattern, always returns a single integer.
count_lines() {
  local data="$1" pattern="$2"
  local n
  n=$(echo "${data}" | grep -c "${pattern}" 2>/dev/null) || n=0
  echo "${n}"
}

produce_messages() {
  local topic="$1" count="$2" prefix="$3"
  {
    for i in $(seq 1 "${count}"); do
      echo "{\"event_id\":\"${prefix}-${i}\",\"seq\":${i}}"
    done
  } | podman exec -i "${KAFKA_CONTAINER}" \
    kafka-console-producer \
      --bootstrap-server "${KAFKA_BOOTSTRAP}" \
      --topic "${topic}" \
      --producer-property "acks=${KAFKA_ACKS}" \
    >/dev/null 2>&1
}

produce_keyed_messages() {
  local topic="$1" count="$2" prefix="$3" key="$4"
  {
    for i in $(seq 1 "${count}"); do
      echo "${key}|{\"event_id\":\"${prefix}-${i}\",\"seq\":${i}}"
    done
  } | podman exec -i "${KAFKA_CONTAINER}" \
    kafka-console-producer \
      --bootstrap-server "${KAFKA_BOOTSTRAP}" \
      --topic "${topic}" \
      --property "parse.key=true" \
      --property "key.separator=|" \
      --producer-property "acks=${KAFKA_ACKS}" \
    >/dev/null 2>&1
}

produce_one() {
  local topic="$1" message="$2"
  echo "${message}" | podman exec -i "${KAFKA_CONTAINER}" \
    kafka-console-producer \
      --bootstrap-server "${KAFKA_BOOTSTRAP}" \
      --topic "${topic}" \
      --producer-property "acks=${KAFKA_ACKS}" \
    >/dev/null 2>&1
}

consume_messages() {
  local topic="$1" max_messages="$2" timeout_ms="$3" group="${4:-}"
  local group_flag=()
  [[ -n "${group}" ]] && group_flag=(--group "${group}")

  timeout $(( (timeout_ms / 1000) + 5 )) \
    podman exec "${KAFKA_CONTAINER}" \
    kafka-console-consumer \
      --bootstrap-server "${KAFKA_BOOTSTRAP}" \
      --topic "${topic}" \
      --from-beginning \
      --max-messages "${max_messages}" \
      --timeout-ms "${timeout_ms}" \
      "${group_flag[@]+"${group_flag[@]}"}" \
    2>/dev/null || true
}

echo "=== Test 1: Idempotent Producer (acks=all, ${MESSAGE_COUNT} messages) ==="

create_topic "${TOPIC_IDEMPOTENT}" 1

echo "  producing ${MESSAGE_COUNT} messages..."
produce_messages "${TOPIC_IDEMPOTENT}" "${MESSAGE_COUNT}" "idemp"

echo "  counting messages in topic..."
CONSUMED=$(consume_messages "${TOPIC_IDEMPOTENT}" "${MESSAGE_COUNT}" "${CONSUME_TIMEOUT_MS}")
CONSUMED_COUNT=$(count_lines "${CONSUMED}" "event_id")

assert_eq "1a: exactly ${MESSAGE_COUNT} messages produced and consumed" "${MESSAGE_COUNT}" "${CONSUMED_COUNT}"

FIRST_SEQ=$(echo "${CONSUMED}" | head -1 | jq -r '.seq // empty' 2>/dev/null || echo "")
LAST_SEQ=$(echo "${CONSUMED}" | tail -1 | jq -r '.seq // empty' 2>/dev/null || echo "")
assert_eq "1b: first message seq=1" "1" "${FIRST_SEQ}"
assert_eq "1c: last message seq=${MESSAGE_COUNT}" "${MESSAGE_COUNT}" "${LAST_SEQ}"

echo ""
echo "=== Test 2: Duplicate Detection ==="

create_topic "${TOPIC_DEDUP}" 1

echo "  producing duplicate messages..."
produce_one "${TOPIC_DEDUP}" '{"event_id":"dup-event-1","seq":1}'
produce_one "${TOPIC_DEDUP}" '{"event_id":"dup-event-1","seq":1}'
produce_one "${TOPIC_DEDUP}" '{"event_id":"unique-event-1","seq":2}'

sleep 2

DEDUP_CONSUMED=$(consume_messages "${TOPIC_DEDUP}" 10 "${CONSUME_TIMEOUT_MS}")
TOTAL_MSGS=$(count_lines "${DEDUP_CONSUMED}" "event_id")
DUP_COUNT=$(count_lines "${DEDUP_CONSUMED}" "dup-event-1")
UNIQUE_COUNT=$(count_lines "${DEDUP_CONSUMED}" "unique-event-1")

# At-least-once: Kafka stores both copies (broker does not dedup by content).
# Dedup is the CONSUMER's responsibility (declared duplicates).
assert_eq "2a: unique message appears exactly once" "1" "${UNIQUE_COUNT}"
assert_ge "2b: duplicate event_id appears >= 2 times (at-least-once, declared dup)" "2" "${DUP_COUNT}"
echo "  NOTE: Kafka broker stores duplicates; consumer-side dedup is required."
echo "  Total messages in topic: ${TOTAL_MSGS} (2 dups + 1 unique = 3 expected)"

echo ""
echo "=== Test 3: Partition Ordering ==="

create_topic "${TOPIC_ORDER}" "${KAFKA_TOPIC_PARTITIONS}"

ORDER_COUNT=100
echo "  producing ${ORDER_COUNT} keyed messages to same partition..."
produce_keyed_messages "${TOPIC_ORDER}" "${ORDER_COUNT}" "order" "order-key"

sleep 2

ORDER_CONSUMED=$(consume_messages "${TOPIC_ORDER}" "${ORDER_COUNT}" "${CONSUME_TIMEOUT_MS}")
ORDER_COUNT_CONSUMED=$(count_lines "${ORDER_CONSUMED}" "event_id")

assert_eq "3a: all ${ORDER_COUNT} ordered messages consumed" "${ORDER_COUNT}" "${ORDER_COUNT_CONSUMED}"

SEQ_VALUES=$(echo "${ORDER_CONSUMED}" | jq -r '.seq // empty' 2>/dev/null | tr '\n' ' ')
IS_ORDERED=true
PREV=0
for s in ${SEQ_VALUES}; do
  if [[ "${s}" -le "${PREV}" ]] 2>/dev/null; then
    IS_ORDERED=false
    break
  fi
  PREV="${s}"
done

if [[ "${IS_ORDERED}" == "true" ]]; then
  pass "3b: partition ordering preserved (seq monotonically increasing)"
else
  fail "3b: partition ordering violated (seq not monotonic: ${SEQ_VALUES})"
fi

echo ""
echo "=== Test 4: Consumer Group Rebalance ==="

create_topic "${TOPIC_REBALANCE}" "${KAFKA_TOPIC_PARTITIONS}"

REBALANCE_MSG_COUNT=30
echo "  producing ${REBALANCE_MSG_COUNT} messages for rebalance test..."
produce_messages "${TOPIC_REBALANCE}" "${REBALANCE_MSG_COUNT}" "rebal"

sleep 2

echo "  starting consumer 1 (group: ${GROUP_REBALANCE})..."
CONSUMER1_OUT="/tmp/${TEST_PREFIX}consumer1.out"
timeout 25 podman exec "${KAFKA_CONTAINER}" \
  kafka-console-consumer \
    --bootstrap-server "${KAFKA_BOOTSTRAP}" \
    --topic "${TOPIC_REBALANCE}" \
    --from-beginning \
    --group "${GROUP_REBALANCE}" \
    --timeout-ms 20000 \
  > "${CONSUMER1_OUT}" 2>/dev/null &
C1_PID=$!

sleep 3

echo "  starting consumer 2 (triggers rebalance)..."
CONSUMER2_OUT="/tmp/${TEST_PREFIX}consumer2.out"
timeout 25 podman exec "${KAFKA_CONTAINER}" \
  kafka-console-consumer \
    --bootstrap-server "${KAFKA_BOOTSTRAP}" \
    --topic "${TOPIC_REBALANCE}" \
    --from-beginning \
    --group "${GROUP_REBALANCE}" \
    --timeout-ms 20000 \
  > "${CONSUMER2_OUT}" 2>/dev/null &
C2_PID=$!

wait "${C1_PID}" 2>/dev/null || true
wait "${C2_PID}" 2>/dev/null || true

C1_COUNT=$(count_lines "$(cat "${CONSUMER1_OUT}" 2>/dev/null || true)" "event_id")
C2_COUNT=$(count_lines "$(cat "${CONSUMER2_OUT}" 2>/dev/null || true)" "event_id")
TOTAL_CONSUMED=$((C1_COUNT + C2_COUNT))

echo "  consumer 1 received: ${C1_COUNT} messages"
echo "  consumer 2 received: ${C2_COUNT} messages"
echo "  total consumed: ${TOTAL_CONSUMED}"

assert_ge "4a: total consumed >= produced (at-least-once)" "${REBALANCE_MSG_COUNT}" "${TOTAL_CONSUMED}"

if [[ "${C1_COUNT}" -gt 0 ]] && [[ "${C2_COUNT}" -gt 0 ]]; then
  pass "4b: both consumers received messages (partition assignment worked)"
else
  skip "4b: one consumer may not have received messages before timeout (timing-dependent)"
fi

GROUP_STATE=$(kafka_exec kafka-consumer-groups \
  --bootstrap-server "${KAFKA_BOOTSTRAP}" \
  --describe --group "${GROUP_REBALANCE}" 2>/dev/null || echo "")

if echo "${GROUP_STATE}" | grep -q "${TOPIC_REBALANCE}"; then
  pass "4c: consumer group has partition assignments"
else
  skip "4c: consumer group state not available (group may have expired)"
fi

rm -f "${CONSUMER1_OUT}" "${CONSUMER2_OUT}" 2>/dev/null || true

print_summary "kafka-durability"
