-- Event ingress cursors: per-agent sequence tracking for idempotent ingestion.
-- Each agent has a monotonically advancing cursor; duplicate events are
-- detected by (agent_id, sequence) uniqueness.

CREATE TABLE event_cursors (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    -- Monotonic sequence number per agent.
    sequence    BIGINT NOT NULL,
    -- Idempotency key from the batch (UUID v4 or monotonic u64 string).
    idempotency_key TEXT NOT NULL,
    -- Batch metadata.
    batch_size  INTEGER NOT NULL DEFAULT 0,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Idempotent: same agent + sequence is a duplicate.
    UNIQUE (agent_id, sequence),
    -- Idempotent: same idempotency key is a duplicate.
    UNIQUE (agent_id, idempotency_key)
);

CREATE INDEX idx_event_cursors_agent ON event_cursors(agent_id, sequence DESC);
