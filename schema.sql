
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS log_events (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    event       TEXT NOT NULL,
    labels      JSONB DEFAULT '{}'::jsonb,
    kv          JSONB NOT NULL,
    latency_us  DOUBLE PRECISION,
    raw         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp     ON log_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_event         ON log_events (event);
CREATE INDEX IF NOT EXISTS idx_events_event_time    ON log_events (event, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_instance_time ON log_events ((labels->>'instance'), timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_labels        ON log_events USING gin (labels);
CREATE INDEX IF NOT EXISTS idx_events_kv            ON log_events USING gin (kv);
CREATE INDEX IF NOT EXISTS idx_events_raw_trgm      ON log_events USING gin (raw gin_trgm_ops);
