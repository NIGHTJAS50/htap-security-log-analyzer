CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE IF NOT EXISTS security_events (
 id BIGSERIAL PRIMARY KEY,
 source TEXT NOT NULL,
 level TEXT NOT NULL,
 message TEXT NOT NULL,
 occurred_at TIMESTAMPTZ NOT NULL,
 metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
 embedding VECTOR(384) NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS security_events_time_idx ON security_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS security_events_embedding_idx ON security_events USING hnsw (embedding vector_cosine_ops);
