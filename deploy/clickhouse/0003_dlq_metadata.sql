-- SPDX-License-Identifier: Apache-2.0 OR MIT
-- Migration 0003: DLQ / malformed message metadata table.
--
-- Repeatability: CREATE TABLE IF NOT EXISTS / CREATE MATERIALIZED VIEW
-- IF NOT EXISTS. No destructive operations.
--
-- Purpose: capture messages that cannot be ingested into events_v1.
-- Two routing paths:
--   1. Malformed JSON: kafka_skip_broken_messages is 0, so parse
--      failures stop the consumer. For resilience, a separate
--      kafka_skip_broken_messages = 100 consumer can feed this table.
--   2. Schema-rejected: messages with unsupported schema_major
--      (detected by the MV's WHERE clause) route here.
--
-- The DLQ table preserves topic/partition/offset for forensic
-- replay and the raw payload for debugging. Payload is bounded
-- to 64 KiB.
--
-- Mirrors the event-bus-kafka DlqRouter metadata headers:
--   dlq_reason, dlq_original_topic, dlq_original_partition.

CREATE TABLE IF NOT EXISTS events_dlq_v1
(
    -- Kafka transport metadata (where the bad message came from)
    original_topic      LowCardinality(String)  DEFAULT 'events.v1',
    original_partition  Int32                   DEFAULT -1,
    original_offset     UInt64                  DEFAULT 0,
    kafka_timestamp     DateTime64(3, 'UTC')    DEFAULT now64(3),

    -- DLQ routing metadata (mirrors DlqRouter headers)
    dlq_reason          LowCardinality(String),
    dlq_routed_at       DateTime64(3, 'UTC')    DEFAULT now64(3),

    -- Partial parse results (best-effort extraction)
    event_id            String                  DEFAULT '',
    batch_id            String                  DEFAULT '',
    schema_major        UInt16                  DEFAULT 0,
    schema_minor        UInt16                  DEFAULT 0,
    event_kind          LowCardinality(String)  DEFAULT '',

    -- Raw payload (bounded to 64 KiB for debugging)
    raw_payload         String                  DEFAULT '',
    raw_key             String                  DEFAULT '',

    -- Ingestion metadata
    ingested_at         DateTime64(3, 'UTC')    DEFAULT now64(3),

    -- TTL: DLQ entries expire after 90 days (longer than events
    -- for forensic analysis). Configurable via {dlq_ttl_days}.
    _ttl_expires_at     DateTime                DEFAULT now() + INTERVAL {dlq_ttl_days:UInt16} DAY
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ingested_at)
ORDER BY (original_topic, original_partition, original_offset)
TTL _ttl_expires_at
SETTINGS index_granularity = 8192;

-- Index on dlq_reason for filtering by rejection category.
ALTER TABLE events_dlq_v1
    ADD INDEX IF NOT EXISTS idx_dlq_reason (dlq_reason)
    TYPE bloom_filter GRANULARITY 4;

-- Materialized view: routes schema-rejected messages to DLQ.
-- Fires on events_v1_kafka inserts where schema_major != 1
-- (the supported major version from protocol::SCHEMA_MAJOR).
-- Valid messages (schema_major = 1) go to events_v1 via events_v1_mv.
CREATE MATERIALIZED VIEW IF NOT EXISTS events_dlq_schema_rejected_mv
TO events_dlq_v1
AS
SELECT
    _topic              AS original_topic,
    _partition          AS original_partition,
    _offset             AS original_offset,
    _timestamp          AS kafka_timestamp,

    concat('schema_major_unsupported: got ', toString(schema_major), ', supported 1')
                        AS dlq_reason,
    now64(3)            AS dlq_routed_at,

    event_id,
    batch_id,
    schema_major,
    schema_minor,
    toLowCardinality(event_kind) AS event_kind,

    substring(payload, 1, 65536) AS raw_payload,
    _key                AS raw_key,

    now64(3)            AS ingested_at,
    now() + INTERVAL {dlq_ttl_days:UInt16} DAY AS _ttl_expires_at
FROM events_v1_kafka
WHERE schema_major != 1;
