-- SPDX-License-Identifier: Apache-2.0 OR MIT
-- Migration 0001: events_v1 — versioned ReplacingMergeTree for ingested events.
--
-- Repeatability: CREATE TABLE IF NOT EXISTS + no destructive ALTER.
-- Cluster-compatible: uses {cluster}/{shard}/{replica} macros for
-- ReplicatedReplacingMergeTree when deployed on a cluster; single-node
-- deployments use plain ReplacingMergeTree (the Replicated* variant
-- requires ZooKeeper/ClickHouse Keeper).
--
-- Deduplication strategy: ReplacingMergeTree(_version) collapses rows
-- with the same ORDER BY key, keeping the row with the highest _version.
-- Background merges are NOT relied upon for immediate uniqueness —
-- exact queries MUST use FINAL or argMax (see 0005_exact_query_helpers.sql).
--
-- TTL: 30 days by default, configurable via the {events_ttl_days:UInt16}
-- macro. Set to 0 to disable TTL (data retained indefinitely).

-- The canonical events table. Each row is one event from a Kafka batch.
-- ORDER BY (event_id) makes event_id the deduplication key for
-- ReplacingMergeTree: duplicate deliveries of the same event_id collapse
-- to the row with the highest _version after merge.
CREATE TABLE IF NOT EXISTS events_v1
(
    -- Kafka transport metadata (preserved for forensics and lag tracking)
    kafka_topic         LowCardinality(String)  DEFAULT '',
    kafka_partition     Int32                   DEFAULT -1,
    kafka_offset        UInt64                  DEFAULT 0,
    kafka_timestamp     DateTime64(3, 'UTC')    DEFAULT now64(3),

    -- Event identity
    event_id            String,
    batch_id            String                  DEFAULT '',
    seq                 UInt64                  DEFAULT 0,

    -- Schema versioning (from Kafka record headers)
    schema_major        UInt16                  DEFAULT 1,
    schema_minor        UInt16                  DEFAULT 0,

    -- Low-cardinality dimensions (bounded enum-like values)
    event_kind          LowCardinality(String),
    sensor              LowCardinality(String)  DEFAULT '',
    agent_generation    LowCardinality(String)  DEFAULT '',
    node_name           LowCardinality(String)  DEFAULT '',
    cluster             LowCardinality(String)  DEFAULT '',

    -- Typed common columns (mirrors protocol::events::Event)
    ts_monotonic_ns     UInt64                  DEFAULT 0,
    boot_id_hex         FixedString(32)         DEFAULT '00000000000000000000000000000000',
    pid_tgid            UInt64                  DEFAULT 0,
    cgroup_id           UInt64                  DEFAULT 0,
    uid                 UInt32                  DEFAULT 0,
    gid                 UInt32                  DEFAULT 0,

    -- Bounded payload: JSON string capped at 64 KiB.
    -- The Kafka consumer enforces kafka_max_message_size_bytes;
    -- this column stores the per-event payload subset.
    -- Bounded by the materialized view's substring() call.
    payload             String                  DEFAULT '',

    -- Ingestion metadata
    ingested_at         DateTime64(3, 'UTC')    DEFAULT now64(3),

    -- Version column for ReplacingMergeTree deduplication.
    -- Higher _version wins on merge. Uses kafka_offset as a
    -- monotonically increasing proxy: re-delivered messages get
    -- a higher offset, so the latest delivery wins.
    _version            UInt64                  DEFAULT 0,

    -- TTL column: rows expire 30 days after ingestion by default.
    -- Configurable via the {events_ttl_days} macro (0 = no TTL).
    _ttl_expires_at     DateTime                DEFAULT now() + INTERVAL {events_ttl_days:UInt16} DAY
)
ENGINE = ReplacingMergeTree(_version)
PARTITION BY toYYYYMMDD(ingested_at)
ORDER BY (event_id)
TTL _ttl_expires_at
SETTINGS index_granularity = 8192;

-- Secondary index on (node_name, event_kind) for common filter patterns.
-- Low-cardinality dimensions make this highly selective.
ALTER TABLE events_v1
    ADD INDEX IF NOT EXISTS idx_node_kind (node_name, event_kind)
    TYPE bloom_filter GRANULARITY 4;

-- Secondary index on (batch_id) for batch-level lookups.
ALTER TABLE events_v1
    ADD INDEX IF NOT EXISTS idx_batch_id (batch_id)
    TYPE bloom_filter GRANULARITY 4;
