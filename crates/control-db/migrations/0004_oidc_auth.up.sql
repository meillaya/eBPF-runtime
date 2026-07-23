-- OIDC auth: role bindings, sessions, revocations.
-- Mirrors the auth crate's RBAC model (viewer/analyst/policy-admin/admin).

CREATE TABLE oidc_role_bindings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Binding type: 'group' or 'sub'.
    binding_type TEXT NOT NULL CHECK (binding_type IN ('group', 'sub')),
    -- The group name or subject (user ID).
    principal   TEXT NOT NULL,
    -- Role: viewer/analyst/policy-admin/admin.
    role        TEXT NOT NULL CHECK (role IN ('viewer', 'analyst', 'policy-admin', 'admin')),
    version     BIGINT NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (binding_type, principal, role)
);

CREATE TABLE oidc_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      TEXT NOT NULL UNIQUE,
    -- OIDC subject (user identity).
    sub             TEXT NOT NULL,
    -- Resolved role for this session.
    role            TEXT NOT NULL CHECK (role IN ('viewer', 'analyst', 'policy-admin', 'admin')),
    -- Groups at session creation (JSON array for change detection).
    groups_json     TEXT NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked         BOOLEAN NOT NULL DEFAULT false,
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX idx_oidc_sessions_sub ON oidc_sessions(sub);

CREATE TABLE oidc_revocations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The revoked session_id or sub (for bulk revocation).
    target_type TEXT NOT NULL CHECK (target_type IN ('session', 'sub')),
    target      TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    revoked_by  TEXT NOT NULL DEFAULT '',
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_oidc_revocations_target ON oidc_revocations(target_type, target);
