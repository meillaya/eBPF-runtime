ALTER TABLE event_batches
    ADD COLUMN IF NOT EXISTS relayed_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_batches_pending_projection
    ON event_batches(received_at)
    WHERE relayed_at IS NULL;
