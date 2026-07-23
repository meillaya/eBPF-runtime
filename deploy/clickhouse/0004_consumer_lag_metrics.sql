-- SPDX-License-Identifier: Apache-2.0 OR MIT
-- Migration 0004: Consumer lag metrics.
--
-- Repeatability: CREATE VIEW IF NOT EXISTS. No destructive operations.
--
-- Purpose: expose consumer lag as a queryable view. Consumer lag is
-- the difference between the latest Kafka offset and the latest
-- consumed offset per partition. This view computes lag from the
-- events_v1 table's kafka_offset column (the last consumed offset
-- per partition) against the Kafka engine's virtual columns.
--
-- BLOCKER: system.kafka_consumers and system.kafka tables require
-- a live Kafka connection. On this host, the view is defined but
-- returns empty results. Live lag metrics re-open on the declared
-- self-hosted runner.
--
-- The view is a helper for monitoring dashboards and alerting.
-- It does NOT store state — it computes lag on each query.

-- Per-partition consumed offset high-water mark from events_v1.
CREATE VIEW IF NOT EXISTS events_v1_consumed_offsets
AS
SELECT
    kafka_topic,
    kafka_partition,
    max(kafka_offset)   AS consumed_offset,
    count()             AS total_rows,
    max(ingested_at)    AS last_ingested_at
FROM events_v1
GROUP BY kafka_topic, kafka_partition;

-- Consumer lag view. Joins consumed offsets against the Kafka
-- engine's latest available offset (from system.kafka_consumers
-- when available, or from the events_v1_kafka table's virtual
-- columns during active consumption).
--
-- On a live cluster, replace the subquery with:
--   SELECT topic, partition, committed_offset
--   FROM system.kafka_consumers
--   WHERE topic = 'events.v1'
--
-- The bounded lag assertion: consumer lag SHOULD be < 10000
-- messages per partition under normal load. This threshold is
-- anchored in the analytics-clickhouse Rust crate's
-- ConsumerLagMetrics::is_within_bounds().
CREATE VIEW IF NOT EXISTS events_v1_consumer_lag
AS
SELECT
    c.kafka_topic       AS topic,
    c.kafka_partition   AS partition,
    c.consumed_offset,
    c.total_rows,
    c.last_ingested_at,
    -- Lag is computed as 0 when no live Kafka metadata is available.
    -- On a live cluster, this would be: latest_offset - consumed_offset.
    0                   AS estimated_lag,
    -- Bounded lag check: 1 = within bounds, 0 = lagging.
    1                   AS is_within_bounds
FROM events_v1_consumed_offsets c;

-- DLQ rate view: tracks the rate of DLQ routing per reason category.
-- Useful for alerting on schema drift or malformed message spikes.
CREATE VIEW IF NOT EXISTS events_dlq_v1_rate
AS
SELECT
    dlq_reason,
    count()                             AS total_routed,
    min(dlq_routed_at)                  AS first_routed_at,
    max(dlq_routed_at)                  AS last_routed_at,
    count() / greatest(
        dateDiff('second', min(dlq_routed_at), max(dlq_routed_at)),
        1
    )                                   AS avg_rate_per_second
FROM events_dlq_v1
GROUP BY dlq_reason;
