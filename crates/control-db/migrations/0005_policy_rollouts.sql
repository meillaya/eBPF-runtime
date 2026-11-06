-- Thresholded policy rollouts.
--
-- A rollout is created for one committed policy version. The expected agent
-- denominator is snapshotted at creation time so an agent that disappears
-- during the rollout does not silently shrink the threshold. The unique
-- partial index permits at most one pending rollout per cluster.

CREATE TABLE IF NOT EXISTS policy_rollouts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version BIGINT NOT NULL,
    previous_version BIGINT,
    requested_by TEXT NOT NULL,
    min_ratio DOUBLE PRECISION NOT NULL CHECK (min_ratio > 0 AND min_ratio <= 1),
    timeout_secs INTEGER NOT NULL CHECK (timeout_secs BETWEEN 1 AND 86400),
    force BOOLEAN NOT NULL DEFAULT false,
    status TEXT NOT NULL DEFAULT 'pending',
    expected_agents INTEGER NOT NULL DEFAULT 0,
    applied_agents INTEGER NOT NULL DEFAULT 0,
    rejected_agents INTEGER NOT NULL DEFAULT 0,
    reason TEXT NOT NULL DEFAULT '',
    detail JSONB NOT NULL DEFAULT '{}',
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deadline_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_policy_rollouts_cluster
    ON policy_rollouts(cluster_id, started_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS uq_policy_rollouts_pending
    ON policy_rollouts(cluster_id)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_policy_acks_rollout
    ON policy_acks(policy_version, status, updated_at);
