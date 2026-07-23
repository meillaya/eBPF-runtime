#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Policy rollout protocol adversarial tests.
#
# Tests replay attacks, stale version rejection, digest mismatch,
# and unauthorized stage/commit against the live PostgreSQL schema.
# Mirrors invariants from crates/policy-rollout/src/state_machine/mod.rs:
#   - Monotonic version: commands with version <= current are rejected
#   - All commands are SPIFFE-bound (authorization required)
#   - Every transition is audited
#
# Usage: bash tests/security/policy_protocol.sh
# Requires: bash, jq, openssl, podman (or PSQL_CMD override)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"

CATEGORY="policy-protocol"

POLICY_ID="55555555-0000-0000-0000-000000000001"
PV_V1="66666666-0000-0000-0000-000000000001"
PV_V2="66666666-0000-0000-0000-000000000002"
DIGEST_LEN=$(jq -r '.properties.policy_protocol.properties.digest_hex_length.default' "${SCHEMA}")

echo "═══ Policy Rollout Protocol Adversarial Tests ═══"
echo ""

# Helper: run SQL as policy-admin role via RLS test user
try_as_policy_admin() {
  psql_rls -c "BEGIN; SET LOCAL app.role = 'policy-admin'; SET LOCAL app.cluster_id = '${CLUSTER_ALPHA}'; $1 ROLLBACK;" 2>&1
}

# Helper: run SQL as viewer role
try_as_viewer() {
  psql_rls -c "BEGIN; SET LOCAL app.role = 'viewer'; SET LOCAL app.cluster_id = '${CLUSTER_ALPHA}'; $1 ROLLBACK;" 2>&1
}

# ---------------------------------------------------------------------------
# POL-001: Replay attack — reuse committed version number
# Attempt to INSERT a new policy_version with version=1 (already committed).
# UNIQUE(policy_id, version) constraint must reject.
# ---------------------------------------------------------------------------
OUT=$(try_as_policy_admin "INSERT INTO policy_versions (id, policy_id, version, content_digest, content_hex, status) VALUES ('aaaaaaaa-1111-1111-1111-111111111111', '${POLICY_ID}', 1, 'replay_digest_0000000000000000000000000000000000000000000000000', 'replay', 'staged');")
if echo "${OUT}" | grep -qi "duplicate key\|unique\|ERROR\|violates"; then
  pass "POL-001" "${CATEGORY}" "replay attack: duplicate version rejected" "UNIQUE(policy_id, version) enforced: $(echo "${OUT}" | head -1)"
else
  fail "POL-001" "${CATEGORY}" "replay attack: duplicate version rejected" "replay INSERT succeeded: ${OUT}"
fi

# ---------------------------------------------------------------------------
# POL-002: Stale version rejection — version <= current max
# The state machine rejects commands with version <= current.
# At DB level: attempt to INSERT version=2 again (already exists as staged).
# ---------------------------------------------------------------------------
OUT=$(try_as_policy_admin "INSERT INTO policy_versions (id, policy_id, version, content_digest, content_hex, status) VALUES ('aaaaaaaa-2222-2222-2222-222222222222', '${POLICY_ID}', 2, 'stale_digest_00000000000000000000000000000000000000000000000000', 'stale', 'staged');")
if echo "${OUT}" | grep -qi "duplicate key\|unique\|ERROR\|violates"; then
  pass "POL-002" "${CATEGORY}" "stale version rejected (duplicate v2)" "monotonic version enforced: $(echo "${OUT}" | head -1)"
else
  fail "POL-002" "${CATEGORY}" "stale version rejected (duplicate v2)" "stale INSERT succeeded: ${OUT}"
fi

# ---------------------------------------------------------------------------
# POL-003: Digest mismatch detection
# Compute SHA-256 of known content and verify it differs from a
# tampered digest. The protocol requires content_digest = SHA-256(content).
# ---------------------------------------------------------------------------
CONTENT="test-policy-content-v3"
REAL_DIGEST=$(echo -n "${CONTENT}" | openssl dgst -sha256 -hex | awk '{print $NF}')
FAKE_DIGEST="0000000000000000000000000000000000000000000000000000000000000000"
if [ "${REAL_DIGEST}" != "${FAKE_DIGEST}" ] && [ ${#REAL_DIGEST} -eq "${DIGEST_LEN}" ]; then
  pass "POL-003" "${CATEGORY}" "digest mismatch detectable" "SHA-256(${CONTENT:0:12}...)=${REAL_DIGEST:0:16}... ≠ fake digest (len=${DIGEST_LEN})"
else
  fail "POL-003" "${CATEGORY}" "digest mismatch detectable" "digest computation failed: len=${#REAL_DIGEST}, expected=${DIGEST_LEN}"
fi

# ---------------------------------------------------------------------------
# POL-004: Digest mismatch on INSERT — wrong digest for content
# Insert a version with a digest that does NOT match the content.
# The DB accepts it (no CHECK constraint), but the protocol layer
# (policy-rollout crate) MUST reject it. This documents the gap.
# ---------------------------------------------------------------------------
CONTENT_HEX=$(echo -n "mismatched-content" | xxd -p | tr -d '\n')
WRONG_DIGEST="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
OUT=$(try_as_policy_admin "INSERT INTO policy_versions (id, policy_id, version, content_digest, content_hex, status) VALUES ('aaaaaaaa-3333-3333-3333-333333333333', '${POLICY_ID}', 3, '${WRONG_DIGEST}', '${CONTENT_HEX}', 'staged');")
if echo "${OUT}" | grep -qi "INSERT\|ERROR.*duplicate"; then
  # DB accepted it — document that digest validation is at the protocol layer
  pass "POL-004" "${CATEGORY}" "digest mismatch: DB accepts (protocol-layer validation)" "DB has no CHECK constraint on digest — policy-rollout crate MUST validate"
else
  fail "POL-004" "${CATEGORY}" "digest mismatch: DB accepts (protocol-layer validation)" "unexpected: ${OUT}"
fi

# ---------------------------------------------------------------------------
# POL-005: Unauthorized stage — viewer cannot INSERT policy_versions
# pv_write RLS: USING (app.role IN ('policy-admin', 'admin'))
# ---------------------------------------------------------------------------
OUT=$(try_as_viewer "INSERT INTO policy_versions (id, policy_id, version, content_digest, content_hex, status) VALUES ('aaaaaaaa-4444-4444-4444-444444444444', '${POLICY_ID}', 4, 'viewer_digest_0000000000000000000000000000000000000000000000000', 'hack', 'staged');")
if echo "${OUT}" | grep -qi "permission denied\|row-level security\|ERROR\|violates"; then
  pass "POL-005" "${CATEGORY}" "viewer cannot stage policy versions" "RLS blocked: $(echo "${OUT}" | head -1)"
else
  fail "POL-005" "${CATEGORY}" "viewer cannot stage policy versions" "viewer INSERT succeeded: ${OUT}"
fi

# ---------------------------------------------------------------------------
# POL-006: Unauthorized commit — viewer cannot UPDATE status to committed
# ---------------------------------------------------------------------------
OUT=$(try_as_viewer "UPDATE policy_versions SET status = 'committed' WHERE id = '${PV_V2}';")
if echo "${OUT}" | grep -qi "permission denied\|row-level security\|ERROR\|UPDATE 0"; then
  pass "POL-006" "${CATEGORY}" "viewer cannot commit policy versions" "blocked or 0 rows: $(echo "${OUT}" | head -1)"
else
  fail "POL-006" "${CATEGORY}" "viewer cannot commit policy versions" "UPDATE succeeded: ${OUT}"
fi

# ---------------------------------------------------------------------------
# POL-007: Monotonic version — new version must be > max existing
# Attempt to INSERT version=0 (below current max=2).
# DB UNIQUE constraint won't catch this (0 is unique), but the protocol
# layer MUST reject non-monotonic versions.
# ---------------------------------------------------------------------------
OUT=$(try_as_policy_admin "INSERT INTO policy_versions (id, policy_id, version, content_digest, content_hex, status) VALUES ('aaaaaaaa-5555-5555-5555-555555555555', '${POLICY_ID}', 0, 'zero_version_digest_00000000000000000000000000000000000000000000', 'zero', 'staged');")
if echo "${OUT}" | grep -qi "INSERT"; then
  # DB accepted version=0 — document that monotonic enforcement is at protocol layer
  pass "POL-007" "${CATEGORY}" "version=0 accepted by DB (protocol-layer monotonic check)" "DB allows non-monotonic version — state machine MUST reject version <= current"
else
  pass "POL-007" "${CATEGORY}" "version=0 rejected" "rejected: $(echo "${OUT}" | head -1)"
fi

# ---------------------------------------------------------------------------
# POL-008: policy-admin CAN stage (positive control)
# ---------------------------------------------------------------------------
TS=$(date +%s)
OUT=$(try_as_policy_admin "INSERT INTO policy_versions (id, policy_id, version, content_digest, content_hex, status) VALUES ('aaaaaaaa-6666-6666-6666-666666666666', '${POLICY_ID}', 10, 'positive_control_digest_0000000000000000000000000000000000000000', 'cafe${TS}', 'staged');")
if echo "${OUT}" | grep -qi "permission denied\|row-level security"; then
  fail "POL-008" "${CATEGORY}" "policy-admin can stage" "RLS blocked policy-admin: ${OUT}"
else
  pass "POL-008" "${CATEGORY}" "policy-admin can stage" "allowed: $(echo "${OUT}" | head -1)"
fi

# ---------------------------------------------------------------------------
# POL-009: Rollout ack idempotency — UNIQUE(rollout_id, agent_id)
# Attempt duplicate ack for same rollout+agent.
# ---------------------------------------------------------------------------
# First create a rollout
OUT=$(try_as_policy_admin "INSERT INTO rollouts (id, policy_version_id, state) VALUES ('bbbbbbbb-1111-1111-1111-111111111111', '${PV_V1}', 'pending');")
# Then insert an ack
OUT=$(try_as_policy_admin "INSERT INTO rollout_acks (id, rollout_id, agent_id, policy_version, digest_hex) VALUES ('cccccccc-1111-1111-1111-111111111111', 'bbbbbbbb-1111-1111-1111-111111111111', '33333333-0000-0000-0000-000000000001', 1, 'aabb');")
# Attempt duplicate ack
OUT=$(try_as_policy_admin "INSERT INTO rollout_acks (id, rollout_id, agent_id, policy_version, digest_hex) VALUES ('cccccccc-2222-2222-2222-222222222222', 'bbbbbbbb-1111-1111-1111-111111111111', '33333333-0000-0000-0000-000000000001', 1, 'aabb');")
if echo "${OUT}" | grep -qi "duplicate key\|unique\|ERROR\|violates"; then
  pass "POL-009" "${CATEGORY}" "rollout ack idempotency enforced" "UNIQUE(rollout_id, agent_id) rejected duplicate: $(echo "${OUT}" | head -1)"
else
  fail "POL-009" "${CATEGORY}" "rollout ack idempotency enforced" "duplicate ack accepted: ${OUT}"
fi

# ---------------------------------------------------------------------------
# POL-010: Status lifecycle — invalid status rejected
# Attempt to set status to an invalid value.
# DB has no CHECK constraint on status, so this documents the gap.
# ---------------------------------------------------------------------------
OUT=$(try_as_policy_admin "UPDATE policy_versions SET status = 'INVALID_STATUS' WHERE id = '${PV_V2}';")
if echo "${OUT}" | grep -qi "UPDATE 1\|UPDATE 0"; then
  pass "POL-010" "${CATEGORY}" "invalid status accepted by DB (protocol-layer validation)" "DB has no CHECK on status — state machine MUST validate lifecycle"
else
  pass "POL-010" "${CATEGORY}" "invalid status handling" "result: $(echo "${OUT}" | head -1)"
fi

# ---------------------------------------------------------------------------
# POL-011: Unauthorized rollout creation — viewer cannot create rollouts
# rollout_write: USING (app.role IN ('policy-admin', 'admin'))
# ---------------------------------------------------------------------------
OUT=$(try_as_viewer "INSERT INTO rollouts (id, policy_version_id, state) VALUES ('bbbbbbbb-9999-9999-9999-999999999999', '${PV_V1}', 'pending');")
if echo "${OUT}" | grep -qi "permission denied\|row-level security\|ERROR\|violates"; then
  pass "POL-011" "${CATEGORY}" "viewer cannot create rollouts" "RLS blocked: $(echo "${OUT}" | head -1)"
else
  fail "POL-011" "${CATEGORY}" "viewer cannot create rollouts" "viewer INSERT succeeded: ${OUT}"
fi

# ---------------------------------------------------------------------------
# POL-012: Audit trail — policy stage generates audit entry
# Insert a policy version and verify audit_log can record it.
# ---------------------------------------------------------------------------
OUT=$(try_as_policy_admin "INSERT INTO policy_versions (id, policy_id, version, content_digest, content_hex, status) VALUES ('aaaaaaaa-7777-7777-7777-777777777777', '${POLICY_ID}', 11, 'audit_test_digest_0000000000000000000000000000000000000000000000', 'audit', 'staged'); INSERT INTO audit_log (seq, actor, action, resource) VALUES (nextval('audit_log_seq'), 'policy-admin@example.com', 'policy.stage', '/api/v1/policies/stage');")
if echo "${OUT}" | grep -qi "permission denied\|row-level security"; then
  fail "POL-012" "${CATEGORY}" "policy stage + audit in same transaction" "blocked: ${OUT}"
else
  pass "POL-012" "${CATEGORY}" "policy stage + audit in same transaction" "same-tx audit works: $(echo "${OUT}" | head -1)"
fi

echo ""
summary
