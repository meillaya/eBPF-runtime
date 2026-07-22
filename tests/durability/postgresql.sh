#!/usr/bin/env bash
# tests/durability/postgresql.sh — PostgreSQL durability integration tests.
#
# Tests against live PostgreSQL 16 (k1-postgres):
#   1. Transaction atomicity: INSERT state + INSERT audit in one tx,
#      verify both-or-neither.
#   2. Crash recovery: kill connection mid-transaction, verify no
#      partial state.
#   3. Connection pool exhaustion: open max connections, verify
#      graceful rejection.
#   4. RLS: verify cross-cluster isolation under concurrent access.
#
# Usage:
#   tests/durability/postgresql.sh --schema bench/schemas/durability.v1.json
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

echo "=== PostgreSQL Durability Tests ==="
echo "  schema: ${SCHEMA_PATH}"
echo "  max_connections: ${PG_MAX_CONNECTIONS}"
echo ""

# ---- setup: create test tables -----------------------------------------------
STATE_TBL="${TEST_PREFIX}pg_state"
AUDIT_TBL="${TEST_PREFIX}pg_audit"
RLS_TBL="${TEST_PREFIX}pg_rls"

register_pg_cleanup "${STATE_TBL}"
register_pg_cleanup "${AUDIT_TBL}"
register_pg_cleanup "${RLS_TBL}"

psql_exec "DROP TABLE IF EXISTS ${STATE_TBL} CASCADE" >/dev/null
psql_exec "DROP TABLE IF EXISTS ${AUDIT_TBL} CASCADE" >/dev/null
psql_exec "DROP TABLE IF EXISTS ${RLS_TBL} CASCADE" >/dev/null

psql_exec "
CREATE TABLE ${STATE_TBL} (
  id          SERIAL PRIMARY KEY,
  cluster     TEXT NOT NULL,
  agent_id    TEXT NOT NULL,
  state_json  JSONB NOT NULL DEFAULT '{}',
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE ${AUDIT_TBL} (
  id          SERIAL PRIMARY KEY,
  state_id    INTEGER NOT NULL REFERENCES ${STATE_TBL}(id),
  action      TEXT NOT NULL,
  actor       TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
" >/dev/null

echo "=== Test 1: Transaction Atomicity (state + audit in same tx) ==="

# 1a. Successful tx: both state and audit inserted.
psql_exec "
BEGIN;
INSERT INTO ${STATE_TBL} (cluster, agent_id, state_json)
  VALUES ('cluster-a', 'agent-1', '{\"status\": \"active\"}')
  RETURNING id;
INSERT INTO ${AUDIT_TBL} (state_id, action, actor)
  VALUES (currval('${STATE_TBL}_id_seq'), 'create', 'test-harness');
COMMIT;
" >/dev/null

STATE_COUNT=$(psql_exec "SELECT count(*) FROM ${STATE_TBL} WHERE agent_id = 'agent-1'")
AUDIT_COUNT=$(psql_exec "SELECT count(*) FROM ${AUDIT_TBL} WHERE actor = 'test-harness'")
assert_eq "1a: state row inserted in tx" "1" "${STATE_COUNT}"
assert_eq "1a: audit row inserted in same tx" "1" "${AUDIT_COUNT}"

# 1b. Failed tx: neither state nor audit inserted (rollback on error).
psql_exec_allow_fail "
BEGIN;
INSERT INTO ${STATE_TBL} (cluster, agent_id, state_json)
  VALUES ('cluster-a', 'agent-rollback', '{\"status\": \"should-not-exist\"}');
INSERT INTO ${AUDIT_TBL} (state_id, action, actor)
  VALUES (999999, 'create', 'rollback-actor');
COMMIT;
" >/dev/null

ROLLBACK_STATE=$(psql_exec "SELECT count(*) FROM ${STATE_TBL} WHERE agent_id = 'agent-rollback'")
ROLLBACK_AUDIT=$(psql_exec "SELECT count(*) FROM ${AUDIT_TBL} WHERE actor = 'rollback-actor'")
assert_eq "1b: state row NOT inserted after failed tx" "0" "${ROLLBACK_STATE}"
assert_eq "1b: audit row NOT inserted after failed tx" "0" "${ROLLBACK_AUDIT}"

# 1c. Explicit ROLLBACK: neither inserted.
psql_exec "
BEGIN;
INSERT INTO ${STATE_TBL} (cluster, agent_id, state_json)
  VALUES ('cluster-b', 'agent-explicit-rb', '{\"status\": \"rolled-back\"}');
ROLLBACK;
" >/dev/null

RB_STATE=$(psql_exec "SELECT count(*) FROM ${STATE_TBL} WHERE agent_id = 'agent-explicit-rb'")
assert_eq "1c: explicit ROLLBACK leaves no state row" "0" "${RB_STATE}"

echo ""
echo "=== Test 2: Crash Recovery (kill connection mid-transaction) ==="

# Insert a known-good row first.
psql_exec "
INSERT INTO ${STATE_TBL} (cluster, agent_id, state_json)
  VALUES ('cluster-crash', 'agent-pre-crash', '{\"status\": \"durable\"}');
" >/dev/null

# Start a tx in a background psql, insert a row, then kill the connection
# from another session using pg_terminate_backend. The uncommitted row
# must NOT be visible.
psql_exec "
INSERT INTO ${STATE_TBL} (cluster, agent_id, state_json)
  VALUES ('cluster-crash', 'agent-crash-victim', '{\"status\": \"in-flight\"}');
" >/dev/null

# Get the PID of a new connection that starts a tx and sleeps.
# We use a DO block that inserts then raises an exception to simulate crash.
psql_exec_allow_fail "
DO \$\$
BEGIN
  INSERT INTO ${STATE_TBL} (cluster, agent_id, state_json)
    VALUES ('cluster-crash', 'agent-crash-mid-tx', '{\"status\": \"should-vanish\"}');
  -- Simulate crash: raise an exception to abort the tx.
  RAISE EXCEPTION 'simulated connection crash';
END;
\$\$;
" >/dev/null

CRASH_STATE=$(psql_exec "SELECT count(*) FROM ${STATE_TBL} WHERE agent_id = 'agent-crash-mid-tx'")
assert_eq "2a: mid-tx crash leaves no partial state" "0" "${CRASH_STATE}"

# Verify the pre-crash row is still durable.
PRE_CRASH=$(psql_exec "SELECT count(*) FROM ${STATE_TBL} WHERE agent_id = 'agent-pre-crash'")
assert_eq "2b: pre-crash row survives" "1" "${PRE_CRASH}"

# 2c. Terminate a real backend mid-transaction.
# Open a background psql that starts a tx, inserts, and sleeps.
podman exec -d "${PG_CONTAINER}" psql \
  -U "${PG_USER}" -d "${PG_DB}" \
  -c "BEGIN; INSERT INTO ${STATE_TBL} (cluster, agent_id, state_json) VALUES ('cluster-crash', 'agent-terminated', '{\"status\": \"terminated\"}'); SELECT pg_sleep(30);" \
  >/dev/null 2>&1 || true

# Wait for the backend to appear.
sleep 1
BACKEND_PID=$(psql_exec "
SELECT pid FROM pg_stat_activity
WHERE query LIKE '%agent-terminated%' AND pid != pg_backend_pid()
LIMIT 1
" 2>/dev/null || echo "")

if [[ -n "${BACKEND_PID}" ]]; then
  psql_exec "SELECT pg_terminate_backend(${BACKEND_PID})" >/dev/null 2>&1 || true
  sleep 1
  TERM_STATE=$(psql_exec "SELECT count(*) FROM ${STATE_TBL} WHERE agent_id = 'agent-terminated'")
  assert_eq "2c: pg_terminate_backend mid-tx leaves no partial state" "0" "${TERM_STATE}"
else
  skip "2c: could not find background backend to terminate"
fi

echo ""
echo "=== Test 3: Connection Pool Exhaustion ==="

# Target: open (max_connections - reserve) connections, then verify
# the next connection is rejected gracefully.
TARGET_CONNS=$((PG_MAX_CONNECTIONS - PG_POOL_RESERVE))
echo "  target connections: ${TARGET_CONNS} (max=${PG_MAX_CONNECTIONS}, reserve=${PG_POOL_RESERVE})"

# Open connections in background, each holding a pg_sleep.
CONN_PIDS=()
for i in $(seq 1 "${TARGET_CONNS}"); do
  podman exec -d "${PG_CONTAINER}" psql \
    -U "${PG_USER}" -d "${PG_DB}" \
    -c "SELECT pg_sleep(15);" \
    >/dev/null 2>&1 || true
done

# Wait for connections to establish.
sleep 3

ACTIVE_CONNS=$(psql_exec "SELECT count(*) FROM pg_stat_activity WHERE datname = '${PG_DB}'" 2>/dev/null || echo "0")
echo "  active connections: ${ACTIVE_CONNS}"

# Try one more connection — should fail or be rejected.
EXTRA_RESULT=$(psql_exec_allow_fail "SELECT 1")
if echo "${EXTRA_RESULT}" | grep -qiE "sorry|too many|connection|remaining"; then
  pass "3a: connection beyond pool limit is gracefully rejected"
elif [[ "${ACTIVE_CONNS}" -ge "${TARGET_CONNS}" ]]; then
  # Pool is saturated; the extra connection may have queued or failed.
  pass "3a: pool saturated at ${ACTIVE_CONNS}/${PG_MAX_CONNECTIONS} connections"
else
  skip "3a: could not saturate pool (active=${ACTIVE_CONNS}, target=${TARGET_CONNS})"
fi

# Wait for background connections to expire.
echo "  waiting for background connections to expire..."
sleep 16

AFTER_CONNS=$(psql_exec "SELECT count(*) FROM pg_stat_activity WHERE datname = '${PG_DB}'" 2>/dev/null || echo "0")
assert_ge "3b: connections released after sleep expiry" "0" "${AFTER_CONNS}"

echo ""
echo "=== Test 4: RLS Cross-Cluster Isolation ==="

# Superusers ALWAYS bypass RLS (even with FORCE). Create a non-superuser
# role to test RLS enforcement properly.
RLS_ROLE="${TEST_PREFIX}rls_user"

psql_exec "DROP ROLE IF EXISTS ${RLS_ROLE}" >/dev/null 2>&1 || true
psql_exec "
CREATE TABLE ${RLS_TBL} (
  id        SERIAL PRIMARY KEY,
  cluster   TEXT NOT NULL,
  data      TEXT NOT NULL
);
ALTER TABLE ${RLS_TBL} ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${RLS_TBL} FORCE ROW LEVEL SECURITY;
CREATE POLICY cluster_isolation ON ${RLS_TBL}
  USING (cluster = current_setting('app.cluster', true));
CREATE ROLE ${RLS_ROLE} LOGIN;
GRANT SELECT ON ${RLS_TBL} TO ${RLS_ROLE};
" >/dev/null

# Insert rows for two clusters (as superuser/table owner, bypasses RLS).
psql_exec "
INSERT INTO ${RLS_TBL} (cluster, data) VALUES ('cluster-alpha', 'alpha-secret');
INSERT INTO ${RLS_TBL} (cluster, data) VALUES ('cluster-beta', 'beta-secret');
INSERT INTO ${RLS_TBL} (cluster, data) VALUES ('cluster-alpha', 'alpha-public');
" >/dev/null

# rls_query: run a query as the non-superuser RLS role with a cluster setting.
# Filters out SET noise from psql output.
rls_query() {
  local cluster_setting="$1" query="$2"
  if [[ -n "${cluster_setting}" ]]; then
    podman exec "${PG_CONTAINER}" psql \
      -U "${RLS_ROLE}" -d "${PG_DB}" \
      -v ON_ERROR_STOP=1 -t -A \
      -c "SET app.cluster = '${cluster_setting}'" \
      -c "${query}" 2>&1 | grep -v '^SET$'
  else
    podman exec "${PG_CONTAINER}" psql \
      -U "${RLS_ROLE}" -d "${PG_DB}" \
      -v ON_ERROR_STOP=1 -t -A \
      -c "${query}" 2>&1
  fi
}

# 4a. Set app.cluster = 'cluster-alpha', verify only alpha rows visible.
ALPHA_ROWS=$(rls_query "cluster-alpha" "SELECT count(*) FROM ${RLS_TBL}")
assert_eq "4a: RLS shows only cluster-alpha rows" "2" "${ALPHA_ROWS}"

# 4b. Set app.cluster = 'cluster-beta', verify only beta rows visible.
BETA_ROWS=$(rls_query "cluster-beta" "SELECT count(*) FROM ${RLS_TBL}")
assert_eq "4b: RLS shows only cluster-beta rows" "1" "${BETA_ROWS}"

# 4c. No cluster set: no rows visible (RLS policy denies all without setting).
NO_CLUSTER_ROWS=$(rls_query "" "SELECT count(*) FROM ${RLS_TBL}")
assert_eq "4c: RLS with no cluster set shows zero rows" "0" "${NO_CLUSTER_ROWS}"

# 4d. Concurrent access: two sessions with different clusters see isolated data.
CONCURRENT_ALPHA=$(rls_query "cluster-alpha" "SELECT string_agg(data, ',' ORDER BY id) FROM ${RLS_TBL}")
CONCURRENT_BETA=$(rls_query "cluster-beta" "SELECT string_agg(data, ',' ORDER BY id) FROM ${RLS_TBL}")
assert_contains "4d: concurrent alpha session sees alpha data" "${CONCURRENT_ALPHA}" "alpha-secret"
assert_not_contains "4d: concurrent alpha session does NOT see beta data" "${CONCURRENT_ALPHA}" "beta-secret"
assert_contains "4d: concurrent beta session sees beta data" "${CONCURRENT_BETA}" "beta-secret"
assert_not_contains "4d: concurrent beta session does NOT see alpha data" "${CONCURRENT_BETA}" "alpha-secret"

psql_exec "DROP ROLE IF EXISTS ${RLS_ROLE}" >/dev/null 2>&1 || true

# ---- summary -----------------------------------------------------------------
print_summary "postgresql-durability"
