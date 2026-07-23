-- Drop all RLS policies.
DROP POLICY IF EXISTS cluster_isolation ON clusters;
DROP POLICY IF EXISTS node_isolation ON nodes;
DROP POLICY IF EXISTS agent_isolation ON agents;
DROP POLICY IF EXISTS cursor_isolation ON event_cursors;
DROP POLICY IF EXISTS policy_read ON policies;
DROP POLICY IF EXISTS policy_write ON policies;
DROP POLICY IF EXISTS pv_read ON policy_versions;
DROP POLICY IF EXISTS pv_write ON policy_versions;
DROP POLICY IF EXISTS target_isolation ON rollout_targets;
DROP POLICY IF EXISTS rollout_read ON rollouts;
DROP POLICY IF EXISTS rollout_write ON rollouts;
DROP POLICY IF EXISTS ack_insert ON rollout_acks;
DROP POLICY IF EXISTS ack_read ON rollout_acks;
DROP POLICY IF EXISTS oidc_admin ON oidc_role_bindings;
DROP POLICY IF EXISTS oidc_session_access ON oidc_sessions;
DROP POLICY IF EXISTS oidc_revocation_admin ON oidc_revocations;
DROP POLICY IF EXISTS audit_insert ON audit_log;
DROP POLICY IF EXISTS audit_read ON audit_log;

-- Disable RLS.
ALTER TABLE clusters DISABLE ROW LEVEL SECURITY;
ALTER TABLE nodes DISABLE ROW LEVEL SECURITY;
ALTER TABLE agents DISABLE ROW LEVEL SECURITY;
ALTER TABLE event_cursors DISABLE ROW LEVEL SECURITY;
ALTER TABLE policies DISABLE ROW LEVEL SECURITY;
ALTER TABLE policy_versions DISABLE ROW LEVEL SECURITY;
ALTER TABLE rollout_targets DISABLE ROW LEVEL SECURITY;
ALTER TABLE rollouts DISABLE ROW LEVEL SECURITY;
ALTER TABLE rollout_acks DISABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_role_bindings DISABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_sessions DISABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_revocations DISABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log DISABLE ROW LEVEL SECURITY;
