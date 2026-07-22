-- Policy rollout: policies, versions, targets, rollouts, acks.
-- Optimistic concurrency via version columns; rollout state machine
-- mirrors the protocol crate's PolicyActivation lifecycle.

CREATE TABLE policies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    version     BIGINT NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE policy_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id       UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    -- Monotonically increasing version per policy.
    version         BIGINT NOT NULL,
    -- SHA-256 digest of the policy content (hex-encoded).
    content_digest  TEXT NOT NULL,
    -- The serialized policy content (JSON or protobuf bytes hex).
    content_hex     TEXT NOT NULL DEFAULT '',
    -- Status mirrors PolicyStatus: staged/ready/committed/applied/rejected/stale.
    status          TEXT NOT NULL DEFAULT 'staged',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (policy_id, version)
);

CREATE TABLE rollout_targets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_version_id UUID NOT NULL REFERENCES policy_versions(id) ON DELETE CASCADE,
    -- Empty target_agent_ids means all agents in the cluster.
    cluster_id      UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    agent_id        UUID REFERENCES agents(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (policy_version_id, cluster_id, agent_id)
);

CREATE TABLE rollouts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_version_id UUID NOT NULL REFERENCES policy_versions(id) ON DELETE CASCADE,
    -- Rollout state: pending/in_progress/completed/failed/cancelled.
    state           TEXT NOT NULL DEFAULT 'pending',
    -- Threshold percent (1..=100) for commit.
    threshold_percent INTEGER NOT NULL DEFAULT 100,
    -- Aggregate counts (updated atomically with acks).
    committed_count INTEGER NOT NULL DEFAULT 0,
    ack_count       INTEGER NOT NULL DEFAULT 0,
    rejected_count  INTEGER NOT NULL DEFAULT 0,
    version         BIGINT NOT NULL DEFAULT 1,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    UNIQUE (policy_version_id)
);

CREATE TABLE rollout_acks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rollout_id      UUID NOT NULL REFERENCES rollouts(id) ON DELETE CASCADE,
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    -- The policy version the agent acknowledges.
    policy_version  BIGINT NOT NULL,
    -- Digest the agent computed locally.
    digest_hex      TEXT NOT NULL DEFAULT '',
    -- Whether the ack was accepted or rejected.
    accepted        BOOLEAN NOT NULL DEFAULT true,
    rejected_reason TEXT NOT NULL DEFAULT '',
    acked_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Idempotent: one ack per agent per rollout.
    UNIQUE (rollout_id, agent_id)
);

CREATE INDEX idx_rollout_acks_rollout ON rollout_acks(rollout_id);
CREATE INDEX idx_policy_versions_policy ON policy_versions(policy_id, version DESC);
