-- SPDX-License-Identifier: Apache-2.0 OR MIT
-- Migration 0005: Exact-query helpers using FINAL / argMax.
--
-- Repeatability: CREATE VIEW IF NOT EXISTS. No destructive operations.
--
-- CRITICAL INVARIANT: ReplacingMergeTree does NOT guarantee
-- immediate deduplication. Background merges collapse duplicates
-- asynchronously. Queries that need exactly-one-row-per-event_id
-- MUST use one of:
--   1. SELECT ... FROM events_v1 FINAL — forces merge-on-read
--   2. SELECT argMax(col, _version) ... GROUP BY event_id — manual dedup
--
-- These views encode the exact-query patterns. Consumers MUST NOT
-- query events_v1 directly for uniqueness-sensitive results.

-- Exact query via FINAL: returns one row per event_id with the
-- highest _version. FINAL forces a merge-on-read, which is
-- correct but slower than argMax for large scans.
-- Use for: point lookups, small result sets, dashboards.
CREATE VIEW IF NOT EXISTS events_v1_exact_final
AS
SELECT *
FROM events_v1 FINAL;

-- Exact query via argMax: returns one row per event_id using
-- aggregate deduplication. Faster than FINAL for large scans
-- because it avoids the merge-on-read overhead.
-- Use for: analytics, aggregations, large result sets.
--
-- argMax(col, _version) returns the value of `col` from the row
-- with the maximum `_version` within each GROUP BY group.
CREATE VIEW IF NOT EXISTS events_v1_exact_argmax
AS
SELECT
    event_id,
    argMax(batch_id, _version)          AS batch_id,
    argMax(seq, _version)               AS seq,
    argMax(schema_major, _version)      AS schema_major,
    argMax(schema_minor, _version)      AS schema_minor,
    argMax(event_kind, _version)        AS event_kind,
    argMax(sensor, _version)            AS sensor,
    argMax(agent_generation, _version)  AS agent_generation,
    argMax(node_name, _version)         AS node_name,
    argMax(cluster, _version)           AS cluster,
    argMax(ts_monotonic_ns, _version)   AS ts_monotonic_ns,
    argMax(boot_id_hex, _version)       AS boot_id_hex,
    argMax(pid_tgid, _version)          AS pid_tgid,
    argMax(cgroup_id, _version)         AS cgroup_id,
    argMax(uid, _version)               AS uid,
    argMax(gid, _version)               AS gid,
    argMax(payload, _version)           AS payload,
    argMax(kafka_topic, _version)       AS kafka_topic,
    argMax(kafka_partition, _version)   AS kafka_partition,
    argMax(kafka_offset, _version)      AS kafka_offset,
    argMax(kafka_timestamp, _version)   AS kafka_timestamp,
    argMax(ingested_at, _version)       AS ingested_at,
    max(_version)                       AS _version
FROM events_v1
GROUP BY event_id;

-- Duplicate detector: shows event_ids that have more than one
-- physical row (i.e., duplicates not yet merged). Useful for
-- verifying that the deduplication strategy works: before a
-- merge, duplicates are visible; after exact query (FINAL/argMax),
-- only one logical row remains.
CREATE VIEW IF NOT EXISTS events_v1_duplicates
AS
SELECT
    event_id,
    count()             AS physical_rows,
    min(_version)       AS min_version,
    max(_version)       AS max_version,
    groupArray(kafka_offset) AS kafka_offsets
FROM events_v1
GROUP BY event_id
HAVING count() > 1;
