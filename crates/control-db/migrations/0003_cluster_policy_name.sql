ALTER TABLE policies DROP CONSTRAINT IF EXISTS policies_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS uq_policies_cluster_name ON policies(cluster_id, name);
