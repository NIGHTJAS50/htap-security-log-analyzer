from datetime import datetime, timezone
import json
import os
from typing import Any

import clickhouse_connect
import psycopg
import redis
from fastapi import FastAPI
from pydantic import BaseModel, Field
from sentence_transformers import SentenceTransformer

app = FastAPI(title="HTAP Security Log Analyzer", version="0.1.0")
model = SentenceTransformer("all-MiniLM-L6-v2")

PG_DSN = os.getenv("PG_DSN", "postgresql://security:security@localhost:5432/security_logs")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CH_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
cache = redis.from_url(REDIS_URL, decode_responses=True)

class LogEvent(BaseModel):
    source: str
    level: str = "INFO"
    message: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)

class SearchResult(BaseModel):
    id: int
    source: str
    level: str
    message: str
    occurred_at: datetime
    similarity: float


def vector_literal(values: list[float]) -> str:
    return "[" + ",".join(str(value) for value in values) + "]"

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

@app.post("/logs")
def ingest(event: LogEvent) -> dict[str, Any]:
    embedding = model.encode(event.message, normalize_embeddings=True).tolist()
    with psycopg.connect(PG_DSN) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO security_events (source, level, message, occurred_at, metadata, embedding)
                   VALUES (%s, %s, %s, %s, %s, %s::vector) RETURNING id""",
                (event.source, event.level, event.message, event.occurred_at, json.dumps(event.metadata), vector_literal(embedding)),
            )
            event_id = cursor.fetchone()[0]
    try:
        client = clickhouse_connect.get_client(host=CH_HOST)
        client.insert("security_analytics.events", [[event.source, event.level, event.occurred_at, event.message, event_id]], column_names=["source", "level", "occurred_at", "message", "event_id"])
    except Exception:
        pass
    return {"id": event_id, "status": "stored"}

@app.get("/search", response_model=list[SearchResult])
def search(q: str, limit: int = 10) -> list[SearchResult]:
    cache_key = f"search:{q}:{limit}"
    cached = cache.get(cache_key)
    if cached:
        return json.loads(cached)
    embedding = model.encode(q, normalize_embeddings=True).tolist()
    with psycopg.connect(PG_DSN) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT id, source, level, message, occurred_at,
                          1 - (embedding <=> %s::vector) AS similarity
                   FROM security_events ORDER BY embedding <=> %s::vector LIMIT %s""",
                (vector_literal(embedding), vector_literal(embedding), min(limit, 100)),
            )
            results = [SearchResult(id=row[0], source=row[1], level=row[2], message=row[3], occurred_at=row[4], similarity=float(row[5])) for row in cursor.fetchall()]
    payload = [result.model_dump(mode="json") for result in results]
    cache.setex(cache_key, 60, json.dumps(payload))
    return results
