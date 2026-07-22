-- RLS defense-in-depth: row-level security policies.
-- RLS is NOT the primary authorization mechanism (service RBAC is).
-- It provides defense-in-depth: even if service logic is bypassed,
-- the database prevents cross-cluster mutations and audit tampering.

-- Enable RLS on all state tables.
ALTER TABLE clusters ENABLE ROW LEVEL SECURITY;
ALTER TABLE nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE rollout_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE rollouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE rollout_acks ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_role_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

-- Cluster-scoped RLS: the app role sets `app.cluster_id` via
-- `SET LOCAL app.cluster_id = '<uuid>'` at transaction start.
-- Policies restrict access to rows matching the session's cluster.

-- Clusters: can only see own cluster.
CREATE POLICY cluster_isolation ON clusters
    USING (id::text = current_setting('app.cluster_id', true))
    WITH CHECK (id::text = current_setting('app.cluster_id', true));

-- Nodes: scoped to cluster.
CREATE POLICY node_isolation ON nodes
    USING (cluster_id::text = current_setting('app.cluster_id', true))
    WITH CHECK (cluster_id::text = current_setting('app.cluster_id', true));

-- Agents: scoped to cluster.
CREATE POLICY agent_isolation ON agents
    USING (cluster_id::text = current_setting('app.cluster_id', true))
    WITH CHECK (cluster_id::text = current_setting('app.cluster_id', true));

-- Event cursors: scoped via agent's cluster.
CREATE POLICY cursor_isolation ON event_cursors
    USING (agent_id IN (
        SELECT id FROM agents
        WHERE cluster_id::text = current_setting('app.cluster_id', true)
    ))
    WITH CHECK (agent_id IN (
        SELECT id FROM agents
        WHERE cluster_id::text = current_setting('app.cluster_id', true)
    ));

-- Policies: global (not cluster-scoped), but only policy-admin+ can write.
-- RLS allows read for all app roles; write restricted by service RBAC.
CREATE POLICY policy_read ON policies
    FOR SELECT USING (true);
CREATE POLICY policy_write ON policies
    FOR ALL USING (current_setting('app.role', true) IN ('policy-admin', 'admin'))
    WITH CHECK (current_setting('app.role', true) IN ('policy-admin', 'admin'));

-- Policy versions: same as policies.
CREATE POLICY pv_read ON policy_versions
    FOR SELECT USING (true);
CREATE POLICY pv_write ON policy_versions
    FOR ALL USING (current_setting('app.role', true) IN ('policy-admin', 'admin'))
    WITH CHECK (current_setting('app.role', true) IN ('policy-admin', 'admin'));

-- Rollout targets: cluster-scoped.
CREATE POLICY target_isolation ON rollout_targets
    USING (cluster_id::text = current_setting('app.cluster_id', true))
    WITH CHECK (cluster_id::text = current_setting('app.cluster_id', true));

-- Rollouts: readable by all, writable by policy-admin+.
CREATE POLICY rollout_read ON rollouts
    FOR SELECT USING (true);
CREATE POLICY rollout_write ON rollouts
    FOR ALL USING (current_setting('app.role', true) IN ('policy-admin', 'admin'))
    WITH CHECK (current_setting('app.role', true) IN ('policy-admin', 'admin'));

-- Rollout acks: agents can insert their own ack; cluster-scoped read.
CREATE POLICY ack_insert ON rollout_acks
    FOR INSERT WITH CHECK (agent_id IN (
        SELECT id FROM agents
        WHERE cluster_id::text = current_setting('app.cluster_id', true)
    ));
CREATE POLICY ack_read ON rollout_acks
    FOR SELECT USING (agent_id IN (
        SELECT id FROM agents
        WHERE cluster_id::text = current_setting('app.cluster_id', true)
    ));

-- OIDC tables: admin-only access.
CREATE POLICY oidc_admin ON oidc_role_bindings
    USING (current_setting('app.role', true) = 'admin')
    WITH CHECK (current_setting('app.role', true) = 'admin');
CREATE POLICY oidc_session_access ON oidc_sessions
    USING (current_setting('app.role', true) IN ('policy-admin', 'admin')
           OR sub = current_setting('app.sub', true))
    WITH CHECK (current_setting('app.role', true) IN ('policy-admin', 'admin'));
CREATE POLICY oidc_revocation_admin ON oidc_revocations
    USING (current_setting('app.role', true) = 'admin')
    WITH CHECK (current_setting('app.role', true) = 'admin');

-- Audit log: INSERT only for audit_writer role; SELECT for admin.
-- NO UPDATE, NO DELETE policies exist (RLS default-deny).
CREATE POLICY audit_insert ON audit_log
    FOR INSERT WITH CHECK (true);
CREATE POLICY audit_read ON audit_log
    FOR SELECT USING (current_setting('app.role', true) IN ('policy-admin', 'admin'));
-- Explicitly NO UPDATE or DELETE policy: RLS denies them by default.
