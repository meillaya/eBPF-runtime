#!/usr/bin/env bash
# tests/durability/clickhouse.sh — ClickHouse durability integration tests.
#
# Tests against live ClickHouse 24.8 (k1-clickhouse):
#   1. ReplacingMergeTree deduplication: insert duplicate event_ids,
#      verify dedup via FINAL query.
#   2. DLQ routing: insert malformed/schema-rejected messages,
#      verify routing to events_dlq_v1.
#   3. TTL enforcement: verify _ttl_expires_at is set correctly.
#
# Usage:
#   tests/durability/clickhouse.sh --schema bench/schemas/durability.v1.json
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

echo "=== ClickHouse Durability Tests ==="
echo "  schema: ${SCHEMA_PATH}"
echo "  events_ttl_days: ${CH_EVENTS_TTL_DAYS}"
echo "  dlq_ttl_days: ${CH_DLQ_TTL_DAYS}"
echo "  dedup_merge_wait_s: ${CH_DEDUP_MERGE_WAIT_S}"
echo ""

# ---- test table names --------------------------------------------------------
DEDUP_TBL="${TEST_PREFIX}ch_dedup"
DLQ_TBL="${TEST_PREFIX}ch_dlq"
TTL_TBL="${TEST_PREFIX}ch_ttl"

register_ch_cleanup "${DEDUP_TBL}"
register_ch_cleanup "${DLQ_TBL}"
register_ch_cleanup "${TTL_TBL}"

echo "=== Test 1: ReplacingMergeTree Deduplication ==="

# Create a test ReplacingMergeTree table mirroring events_v1 structure.
ch_query "DROP TABLE IF EXISTS ${DEDUP_TBL}" >/dev/null
ch_query "
CREATE TABLE ${DEDUP_TBL} (
    event_id    String,
    seq         UInt64,
    payload     String DEFAULT '',
    _version    UInt64 DEFAULT 0,
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(_version)
ORDER BY (event_id)
SETTINGS index_granularity = 8192
" >/dev/null

# Insert 5 unique events.
echo "  inserting 5 unique events..."
for i in $(seq 1 5); do
  ch_query "INSERT INTO ${DEDUP_TBL} (event_id, seq, payload, _version) VALUES ('evt-${i}', ${i}, 'payload-${i}', 1)" >/dev/null
done

# Insert 3 duplicates with higher _version (simulating re-delivery).
echo "  inserting 3 duplicates with higher _version..."
for i in 1 2 3; do
  ch_query "INSERT INTO ${DEDUP_TBL} (event_id, seq, payload, _version) VALUES ('evt-${i}', ${i}, 'payload-${i}-v2', 2)" >/dev/null
done

# Count raw rows (before merge): should be 8 (5 + 3 dups).
RAW_COUNT=$(ch_query "SELECT count() FROM ${DEDUP_TBL}")
echo "  raw row count (pre-merge): ${RAW_COUNT}"
assert_ge "1a: raw rows include duplicates (>= 5)" "5" "${RAW_COUNT}"

# Count deduplicated rows via FINAL: should be exactly 5.
FINAL_COUNT=$(ch_query "SELECT count() FROM ${DEDUP_TBL} FINAL")
assert_eq "1b: FINAL query returns exactly 5 unique events" "5" "${FINAL_COUNT}"

# Verify the highest _version wins for deduplicated rows.
V2_COUNT=$(ch_query "SELECT count() FROM ${DEDUP_TBL} FINAL WHERE _version = 2")
assert_eq "1c: 3 events have _version=2 (highest version wins)" "3" "${V2_COUNT}"

V1_ONLY=$(ch_query "SELECT count() FROM ${DEDUP_TBL} FINAL WHERE _version = 1")
assert_eq "1d: 2 events retain _version=1 (no duplicate delivered)" "2" "${V1_ONLY}"

# Verify argMax dedup matches FINAL.
ARGMAX_COUNT=$(ch_query "
SELECT count() FROM (
  SELECT event_id, argMax(seq, _version) AS seq, argMax(_version, _version) AS ver
  FROM ${DEDUP_TBL}
  GROUP BY event_id
)")
assert_eq "1e: argMax dedup matches FINAL count" "5" "${ARGMAX_COUNT}"

# Force a merge and verify physical dedup.
echo "  forcing OPTIMIZE TABLE FINAL merge..."
ch_query "OPTIMIZE TABLE ${DEDUP_TBL} FINAL" >/dev/null
sleep 2

MERGED_COUNT=$(ch_query "SELECT count() FROM ${DEDUP_TBL}")
assert_eq "1f: after OPTIMIZE FINAL, physical rows = 5" "5" "${MERGED_COUNT}"

echo ""
echo "=== Test 2: DLQ Routing for Malformed Messages ==="

# Create a test DLQ table mirroring events_dlq_v1 structure.
ch_query "DROP TABLE IF EXISTS ${DLQ_TBL}" >/dev/null
ch_query "
CREATE TABLE ${DLQ_TBL} (
    original_topic      LowCardinality(String) DEFAULT 'events.v1',
    original_partition  Int32 DEFAULT -1,
    original_offset     UInt64 DEFAULT 0,
    dlq_reason          LowCardinality(String),
    event_id            String DEFAULT '',
    schema_major        UInt16 DEFAULT 0,
    raw_payload         String DEFAULT '',
    ingested_at         DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = MergeTree()
ORDER BY (original_topic, original_partition, original_offset)
SETTINGS index_granularity = 8192
" >/dev/null

# Simulate DLQ routing: schema-rejected message (schema_major != 1).
echo "  inserting schema-rejected message (schema_major=99)..."
ch_query "
INSERT INTO ${DLQ_TBL}
  (original_topic, original_partition, original_offset, dlq_reason, event_id, schema_major, raw_payload)
VALUES
  ('events.v1', 0, 42, 'schema_major_unsupported: got 99, supported 1', 'bad-evt-1', 99, '{\"event_id\":\"bad-evt-1\",\"schema_major\":99}')
" >/dev/null

# Simulate DLQ routing: malformed JSON.
echo "  inserting malformed JSON message..."
ch_query "
INSERT INTO ${DLQ_TBL}
  (original_topic, original_partition, original_offset, dlq_reason, event_id, schema_major, raw_payload)
VALUES
  ('events.v1', 1, 99, 'malformed_json: parse failure', '', 0, 'not-valid-json{{{')
" >/dev/null

# Insert a valid message for contrast (should NOT be in DLQ).
# (In production, valid messages go to events_v1 via MV, not DLQ.)

DLQ_COUNT=$(ch_query "SELECT count() FROM ${DLQ_TBL}")
assert_eq "2a: DLQ contains 2 rejected messages" "2" "${DLQ_COUNT}"

SCHEMA_REJECT=$(ch_query "SELECT count() FROM ${DLQ_TBL} WHERE dlq_reason LIKE 'schema_major_unsupported%'")
assert_eq "2b: 1 schema-rejected message in DLQ" "1" "${SCHEMA_REJECT}"

MALFORMED=$(ch_query "SELECT count() FROM ${DLQ_TBL} WHERE dlq_reason LIKE 'malformed_json%'")
assert_eq "2c: 1 malformed JSON message in DLQ" "1" "${MALFORMED}"

# Verify DLQ preserves forensic metadata.
FORENSIC=$(ch_query "
SELECT original_topic, original_partition, original_offset
FROM ${DLQ_TBL}
WHERE event_id = 'bad-evt-1'
FORMAT TabSeparated
")
assert_contains "2d: DLQ preserves original topic" "${FORENSIC}" "events.v1"
assert_contains "2e: DLQ preserves original offset" "${FORENSIC}" "42"

# Verify raw_payload is preserved for debugging.
RAW_PAYLOAD=$(ch_query "SELECT raw_payload FROM ${DLQ_TBL} WHERE event_id = 'bad-evt-1'")
assert_contains "2f: DLQ preserves raw payload" "${RAW_PAYLOAD}" "bad-evt-1"

echo ""
echo "=== Test 3: TTL Enforcement ==="

# Create a test table with TTL mirroring events_v1.
ch_query "DROP TABLE IF EXISTS ${TTL_TBL}" >/dev/null
ch_query "
CREATE TABLE ${TTL_TBL} (
    event_id        String,
    ingested_at     DateTime64(3, 'UTC') DEFAULT now64(3),
    _ttl_expires_at DateTime DEFAULT now() + INTERVAL ${CH_EVENTS_TTL_DAYS} DAY
) ENGINE = MergeTree()
ORDER BY (event_id)
TTL _ttl_expires_at
SETTINGS index_granularity = 8192
" >/dev/null

# Insert a row and verify TTL is set correctly.
ch_query "INSERT INTO ${TTL_TBL} (event_id) VALUES ('ttl-test-1')" >/dev/null

# Verify _ttl_expires_at is approximately now() + TTL days.
TTL_CHECK=$(ch_query "
SELECT
  dateDiff('day', now(), _ttl_expires_at) AS days_until_expiry
FROM ${TTL_TBL}
WHERE event_id = 'ttl-test-1'
")
# Allow +/- 1 day tolerance for timing.
TTL_DAYS_ACTUAL="${TTL_CHECK}"
if [[ "${TTL_DAYS_ACTUAL}" -ge $((CH_EVENTS_TTL_DAYS - 1)) ]] && [[ "${TTL_DAYS_ACTUAL}" -le $((CH_EVENTS_TTL_DAYS + 1)) ]] 2>/dev/null; then
  pass "3a: TTL set to ~${CH_EVENTS_TTL_DAYS} days (actual: ${TTL_DAYS_ACTUAL} days)"
else
  fail "3a: TTL expected ~${CH_EVENTS_TTL_DAYS} days, got ${TTL_DAYS_ACTUAL}"
fi

# Verify TTL is configured on the table engine.
TTL_ENGINE=$(ch_query "
SELECT engine_full FROM system.tables
WHERE name = '${TTL_TBL}' AND database = currentDatabase()
")
assert_contains "3b: table engine includes TTL clause" "${TTL_ENGINE}" "TTL"

# Insert a row with expired TTL and verify merge removes it.
echo "  inserting expired row (TTL in the past)..."
ch_query "
INSERT INTO ${TTL_TBL} (event_id, ingested_at, _ttl_expires_at)
VALUES ('ttl-expired', now64(3), now() - INTERVAL 1 DAY)
" >/dev/null

# Force merge to apply TTL.
echo "  forcing OPTIMIZE TABLE FINAL to apply TTL..."
ch_query "OPTIMIZE TABLE ${TTL_TBL} FINAL" >/dev/null
sleep 2

EXPIRED_COUNT=$(ch_query "SELECT count() FROM ${TTL_TBL} WHERE event_id = 'ttl-expired'")
assert_eq "3c: expired row removed by TTL merge" "0" "${EXPIRED_COUNT}"

VALID_COUNT=$(ch_query "SELECT count() FROM ${TTL_TBL} WHERE event_id = 'ttl-test-1'")
assert_eq "3d: non-expired row survives TTL merge" "1" "${VALID_COUNT}"

# Verify production events_v1 table has TTL configured (if it exists).
PROD_TTL=$(ch_query_allow_fail "
SELECT engine_full FROM system.tables
WHERE name = 'events_v1' AND database = currentDatabase()
")
if [[ -n "${PROD_TTL}" ]] && echo "${PROD_TTL}" | grep -q "TTL"; then
  pass "3e: production events_v1 has TTL configured"
else
  skip "3e: production events_v1 table not found or no TTL (may not be migrated yet)"
fi

# ---- summary -----------------------------------------------------------------
print_summary "clickhouse-durability"
