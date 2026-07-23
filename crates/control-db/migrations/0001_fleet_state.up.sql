-- Fleet state: clusters, nodes, agents with SPIFFE identity references.
-- Optimistic concurrency via version columns; short transactions only.

CREATE TABLE clusters (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    -- SPIFFE trust domain for this cluster (e.g. "kernel-v1.test").
    trust_domain TEXT NOT NULL,
    version     BIGINT NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE nodes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id  UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    hostname    TEXT NOT NULL DEFAULT '',
    kernel_release TEXT NOT NULL DEFAULT '',
    version     BIGINT NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (cluster_id, name)
);

CREATE TABLE agents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id         UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    cluster_id      UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    -- SPIFFE ID: spiffe://<trust_domain>/agent/<cluster>/<node>
    spiffe_id       TEXT NOT NULL UNIQUE,
    agent_generation TEXT NOT NULL,
    boot_id_hex     TEXT NOT NULL DEFAULT '',
    protocol_major  INTEGER NOT NULL DEFAULT 1,
    -- Health snapshot (denormalized for fast reads).
    health_epoch_s  BIGINT NOT NULL DEFAULT 0,
    events_emitted  BIGINT NOT NULL DEFAULT 0,
    events_dropped  BIGINT NOT NULL DEFAULT 0,
    version         BIGINT NOT NULL DEFAULT 1,
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for fast cluster-scoped agent lookups.
CREATE INDEX idx_agents_cluster ON agents(cluster_id);
CREATE INDEX idx_agents_node ON agents(node_id);
