-- Least-privilege roles: app role, audit role, migration role.
-- The application NEVER connects as superuser.

-- App role: read/write fleet state, insert audit, listen/notify.
-- Cannot UPDATE/DELETE audit_log. Cannot bypass RLS.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'control_app') THEN
        CREATE ROLE control_app LOGIN PASSWORD 'control_app_dev_only';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'control_audit') THEN
        CREATE ROLE control_audit LOGIN PASSWORD 'control_audit_dev_only';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'control_migrate') THEN
        CREATE ROLE control_migrate LOGIN PASSWORD 'control_migrate_dev_only';
    END IF;
END
$$;

-- control_app: DML on state tables, INSERT-only on audit_log.
GRANT USAGE ON SCHEMA public TO control_app;
GRANT SELECT, INSERT, UPDATE ON clusters, nodes, agents TO control_app;
GRANT SELECT, INSERT, UPDATE ON event_cursors TO control_app;
GRANT SELECT, INSERT, UPDATE ON policies, policy_versions TO control_app;
GRANT SELECT, INSERT, UPDATE ON rollout_targets, rollouts, rollout_acks TO control_app;
GRANT SELECT, INSERT, UPDATE ON oidc_role_bindings, oidc_sessions, oidc_revocations TO control_app;
GRANT SELECT, INSERT ON audit_log TO control_app;
GRANT USAGE ON SEQUENCE audit_log_seq TO control_app;
-- Explicitly NO UPDATE/DELETE on audit_log for control_app.

-- control_audit: read-only on all tables + insert audit.
GRANT USAGE ON SCHEMA public TO control_audit;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO control_audit;
GRANT INSERT ON audit_log TO control_audit;
GRANT USAGE ON SEQUENCE audit_log_seq TO control_audit;

-- control_migrate: full DDL for migrations only.
GRANT ALL PRIVILEGES ON SCHEMA public TO control_migrate;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO control_migrate;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO control_migrate;

-- Ensure control_app does NOT have BYPASSRLS.
ALTER ROLE control_app NOBYPASSRLS;
ALTER ROLE control_audit NOBYPASSRLS;
-- control_migrate needs BYPASSRLS for migration operations.
ALTER ROLE control_migrate BYPASSRLS;
