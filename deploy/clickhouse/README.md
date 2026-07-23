# ClickHouse Event Ingestion — deploy/clickhouse/

Kafka → ClickHouse event ingestion pipeline with explicit deduplication
and DLQ routing. Part of the eBPF runtime security & observability
platform's analytics layer.

## Architecture

```
events.v1 (Kafka)
    │
    ▼
events_v1_kafka (Kafka engine table, consumer group)
    │
    ├──► events_v1_mv ──► events_v1 (ReplacingMergeTree)
    │                         │
    │                         ├──► events_v1_exact_final (FINAL view)
    │                         ├──► events_v1_exact_argmax (argMax view)
    │                         └──► events_v1_duplicates (dup detector)
    │
    └──► events_dlq_schema_rejected_mv ──► events_dlq_v1 (DLQ metadata)
```

## Migrations

All migrations are **repeatable** (idempotent):

| File | Purpose | Repeatability |
|------|---------|---------------|
| `0001_events_v1.sql` | Core events table (ReplacingMergeTree) | `CREATE TABLE IF NOT EXISTS` |
| `0002_kafka_consumer.sql` | Kafka engine + materialized view | `CREATE TABLE/MV IF NOT EXISTS` |
| `0003_dlq_metadata.sql` | DLQ metadata table + schema-reject MV | `CREATE TABLE/MV IF NOT EXISTS` |
| `0004_consumer_lag_metrics.sql` | Consumer lag + DLQ rate views | `CREATE VIEW IF NOT EXISTS` |
| `0005_exact_query_helpers.sql` | FINAL/argMax exact-query views | `CREATE VIEW IF NOT EXISTS` |

### Running migrations

```bash
# Single-node (default TTL: 30d events, 90d DLQ)
for f in deploy/clickhouse/0*.sql; do
  clickhouse-client \
    --param events_ttl_days=30 \
    --param dlq_ttl_days=90 \
    --param kafka_broker_list=localhost:9092 \
    --param kafka_consumer_group=clickhouse-events-v1 \
    --multiquery < "$f"
done

# Custom TTL (e.g., 7d for staging)
clickhouse-client --param events_ttl_days=7 ...
```

### Migration repeatability test

Migrations can be run multiple times without error. The Rust crate
`analytics-clickhouse` validates this via `migration::validate_repeatable()`,
which parses each SQL file and asserts:
- All DDL uses `IF NOT EXISTS` / `IF EXISTS` guards
- No `DROP TABLE` / `TRUNCATE` / destructive `ALTER`
- No `INSERT` / `DELETE` / `UPDATE` (migrations are schema-only)

## Cluster-Compatible Replication

The schema supports both single-node and cluster deployments:

- **Single-node**: uses plain `ReplacingMergeTree` (no ZooKeeper needed)
- **Cluster**: switch to `ReplicatedReplacingMergeTree` with macros:
  ```sql
  ENGINE = ReplicatedReplacingMergeTree(
      '/clickhouse/tables/{shard}/events_v1',
      '{replica}',
      _version
  )
  ```
  Macros (`{cluster}`, `{shard}`, `{replica}`) are defined in `config.xml`.

The `config.xml` includes commented-out `remote_servers` and `zookeeper`
sections for cluster deployment. **No live cluster is operated** — this
is configuration-only.

## TTL Configuration

| Table | Default TTL | Macro | Disable |
|-------|-------------|-------|---------|
| `events_v1` | 30 days | `{events_ttl_days:UInt16}` | Set to 0 |
| `events_dlq_v1` | 90 days | `{dlq_ttl_days:UInt16}` | Set to 0 |

TTL is enforced by ClickHouse's background merge process. Rows are
physically deleted after the TTL expires and a merge runs. The
`_ttl_expires_at` column is computed at insert time.

## Deduplication Strategy

**Critical**: ReplacingMergeTree does NOT guarantee immediate
deduplication. Background merges collapse duplicates asynchronously.

For exact queries (one row per `event_id`):

1. **FINAL** (merge-on-read): `SELECT * FROM events_v1 FINAL`
   - Correct but slower for large scans
   - Use for point lookups, dashboards

2. **argMax** (aggregate dedup): `SELECT argMax(col, _version) ... GROUP BY event_id`
   - Faster for large scans
   - Use for analytics, aggregations

The `events_v1_duplicates` view shows physical duplicates before merge.
The `events_v1_exact_final` and `events_v1_exact_argmax` views provide
deduplicated results.

## DLQ Routing

Messages are routed to `events_dlq_v1` when:

1. **Schema major mismatch**: `schema_major != 1` (the supported version)
2. **Malformed JSON**: parse failures (handled by `kafka_skip_broken_messages`)

DLQ records preserve:
- Original topic/partition/offset (for forensic replay)
- Rejection reason (mirrors `event-bus-kafka` DlqRouter headers)
- Raw payload (bounded to 64 KiB)

## Consumer Lag Metrics

The `events_v1_consumer_lag` view computes per-partition lag.
The bounded lag threshold (10,000 messages/partition) is anchored
in the Rust crate's `ConsumerLagMetrics::is_within_bounds()`.

**BLOCKER**: Live lag metrics require a running Kafka broker.
On this host, the view returns `estimated_lag = 0`.

## Security

- ClickHouse is **control-plane only**: agents never connect directly
- No agent credentials are stored in ClickHouse
- The Kafka consumer group runs in the control plane alongside the
  `event-bus-kafka` publisher
