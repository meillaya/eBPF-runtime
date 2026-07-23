-- SPDX-License-Identifier: Apache-2.0 OR MIT
-- Migration 0002: Kafka engine consumer + materialized view.
--
-- Repeatability: CREATE TABLE IF NOT EXISTS / CREATE MATERIALIZED VIEW
-- IF NOT EXISTS. No destructive operations.
--
-- Architecture:
--   events_v1_kafka (Kafka engine) → events_v1_mv (MV) → events_v1 (RMT)
--
-- The Kafka engine table acts as a consumer group reader. The MV
-- transforms raw Kafka messages into typed rows and inserts into
-- events_v1. Malformed messages are routed to events_dlq_v1 via
-- a separate MV (see 0003_dlq_metadata.sql).
--
-- Consumer group: {kafka_consumer_group:String} macro allows
-- per-environment consumer group naming. Default: 'clickhouse-events-v1'.
--
-- BLOCKER: No live Kafka broker on this host. This SQL defines the
-- schema; live ingestion re-opens on the declared self-hosted runner.

-- Raw Kafka consumer table. Reads from events.v1 topic.
-- kafka_format = 'JSONEachRow' matches the publisher's serialization.
-- kafka_num_consumers = 1 for single-node; scale with partition count
-- on a cluster (one consumer per partition is the upper bound).
CREATE TABLE IF NOT EXISTS events_v1_kafka
(
    -- Kafka message fields (JSONEachRow deserialization)
    event_id            String,
    batch_id            String                  DEFAULT '',
    seq                 UInt64                  DEFAULT 0,
    schema_major        UInt16                  DEFAULT 1,
    schema_minor        UInt16                  DEFAULT 0,
    event_kind          String,
    sensor              String                  DEFAULT '',
    agent_generation    String                  DEFAULT '',
    node_name           String                  DEFAULT '',
    cluster             String                  DEFAULT '',
    ts_monotonic_ns     UInt64                  DEFAULT 0,
    boot_id_hex         String                  DEFAULT '',
    pid_tgid            UInt64                  DEFAULT 0,
    cgroup_id           UInt64                  DEFAULT 0,
    uid                 UInt32                  DEFAULT 0,
    gid                 UInt32                  DEFAULT 0,
    payload             String                  DEFAULT '',

    -- Kafka virtual columns (exposed by the Kafka engine)
    _topic              String,
    _partition          Int32,
    _offset             UInt64,
    _timestamp          DateTime64(3, 'UTC'),
    _key                String
)
ENGINE = Kafka()
SETTINGS
    kafka_broker_list = '{kafka_broker_list:String}',
    kafka_topic_list = 'events.v1',
    kafka_group_name = '{kafka_consumer_group:String}',
    kafka_format = 'JSONEachRow',
    kafka_num_consumers = 1,
    kafka_max_block_size = 65536,
    kafka_skip_broken_messages = 0,
    kafka_commit_every_batch = 1;

-- Materialized view: transforms Kafka messages into events_v1 rows.
-- The MV fires on every INSERT into events_v1_kafka (i.e., every
-- Kafka poll). Malformed messages that fail JSONEachRow parsing
-- are handled by the DLQ MV (0003).
--
-- Payload is bounded to 65536 bytes (64 KiB) via substring() to
-- prevent unbounded storage from oversized messages.
CREATE MATERIALIZED VIEW IF NOT EXISTS events_v1_mv
TO events_v1
AS
SELECT
    _topic              AS kafka_topic,
    _partition          AS kafka_partition,
    _offset             AS kafka_offset,
    _timestamp          AS kafka_timestamp,

    event_id,
    batch_id,
    seq,
    schema_major,
    schema_minor,

    toLowCardinality(event_kind)      AS event_kind,
    toLowCardinality(sensor)          AS sensor,
    toLowCardinality(agent_generation) AS agent_generation,
    toLowCardinality(node_name)       AS node_name,
    toLowCardinality(cluster)         AS cluster,

    ts_monotonic_ns,
    toFixedString(boot_id_hex, 32)    AS boot_id_hex,
    pid_tgid,
    cgroup_id,
    uid,
    gid,

    substring(payload, 1, 65536)      AS payload,

    now64(3)                          AS ingested_at,
    _offset                           AS _version,
    now() + INTERVAL {events_ttl_days:UInt16} DAY AS _ttl_expires_at
FROM events_v1_kafka;
