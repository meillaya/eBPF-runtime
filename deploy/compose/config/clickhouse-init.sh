#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# ClickHouse init script for kernel-v1 local development.
#
# Applies the parameterized migrations from deploy/clickhouse/ in order.
# The SQL files use {param:Type} macros that require --param flags,
# so this shell wrapper is necessary (raw .sql files in the init dir
# cannot pass parameters).
#
# Consumed by: deploy/compose/dev-infra.yml (clickhouse service)
# Mounted at:  /docker-entrypoint-initdb.d/00-init.sh
#
# SECURITY: DEV-ONLY. Kafka broker address points to the compose
# network service name. TTL values are dev defaults.

set -euo pipefail

MIGRATIONS_DIR="/docker-entrypoint-initdb.d/migrations"

# Dev parameters matching deploy/clickhouse/README.md defaults.
PARAMS=(
    --param events_ttl_days=30
    --param dlq_ttl_days=90
    --param kafka_broker_list=kafka:9092
    --param kafka_consumer_group=clickhouse-events-v1
)

echo "[clickhouse-init] applying migrations from ${MIGRATIONS_DIR}"

for f in "${MIGRATIONS_DIR}"/0*.sql; do
    if [ ! -f "$f" ]; then
        echo "[clickhouse-init] no migration files found in ${MIGRATIONS_DIR}"
        exit 1
    fi
    echo "[clickhouse-init] applying $(basename "$f")"
    clickhouse-client --multiquery "${PARAMS[@]}" < "$f"
done

echo "[clickhouse-init] all migrations applied successfully"
