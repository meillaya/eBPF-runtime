-- Append-only audit log. NO UPDATE, NO DELETE permitted.
-- Same-transaction writes: audit entries are inserted in the same
-- transaction as the state change they record.

CREATE TABLE audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Monotonic sequence for global ordering.
    seq         BIGINT NOT NULL,
    -- Actor: OIDC subject performing the action.
    actor       TEXT NOT NULL,
    -- Action: the operation performed (e.g. "policy.stage", "agent.register").
    action      TEXT NOT NULL,
    -- Resource: the target resource identifier.
    resource    TEXT NOT NULL,
    -- Cluster scope (NULL for global operations).
    cluster_id  UUID REFERENCES clusters(id) ON DELETE SET NULL,
    -- Optional detail payload (JSON).
    detail_json TEXT NOT NULL DEFAULT '{}',
    -- Whether the operation succeeded.
    success     BOOLEAN NOT NULL DEFAULT true,
    -- Error message if the operation failed.
    error_msg   TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (seq)
);

-- Sequence for monotonic audit ordering.
CREATE SEQUENCE audit_log_seq START 1;

-- Index for actor-scoped and time-scoped queries.
CREATE INDEX idx_audit_log_actor ON audit_log(actor, created_at DESC);
CREATE INDEX idx_audit_log_created ON audit_log(created_at DESC);
CREATE INDEX idx_audit_log_cluster ON audit_log(cluster_id, created_at DESC);

-- Revoke UPDATE and DELETE on audit_log from all non-superuser roles.
-- The audit_writer role can only INSERT.
-- This is enforced at the role level (migration 0006) AND by RLS (migration 0005).
