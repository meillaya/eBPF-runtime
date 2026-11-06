ALTER TABLE policies
    ADD COLUMN IF NOT EXISTS cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE;
ALTER TABLE policy_versions
    ADD COLUMN IF NOT EXISTS author TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_policy_versions_created ON policy_versions(created_at DESC);

CREATE TABLE IF NOT EXISTS policy_acks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_version BIGINT NOT NULL,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    digest TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (policy_version, agent_id)
);
