import asyncio
import json
import os
import time
import uuid
from typing import AsyncIterator

import pytest
import pytest_asyncio
import redis.asyncio as redis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from api.routes import get_cache, router
from cache.redis_client import RedisCache
from db.models import Alert, Base
from services.processing_service import ProcessingService
from workers.alert_worker import AlertWorker

pytestmark = pytest.mark.asyncio


def _require_isolated_url(test_env_var: str, prod_env_var: str) -> str:
    value = os.getenv(test_env_var, "").strip()
    if not value:
        pytest.skip(f"{test_env_var} is not set; skipping integration test.")

    prod_value = os.getenv(prod_env_var, "").strip()
    if prod_value and value == prod_value:
        raise RuntimeError(
            f"{test_env_var} must not match {prod_env_var}. "
            "Use a dedicated test service/database."
        )
    return value


@pytest_asyncio.fixture
async def db_engine() -> AsyncIterator[AsyncEngine]:
    """
    Setup:
      - Connect to dedicated TEST_DATABASE_URL
      - Recreate schema
    Teardown:
      - Drop schema and dispose engine
    """
    test_database_url = _require_isolated_url("TEST_DATABASE_URL", "DATABASE_URL")
    if "postgresql" not in test_database_url:
        raise RuntimeError("TEST_DATABASE_URL must point to PostgreSQL for this integration test.")

    engine = create_async_engine(test_database_url, future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    try:
        yield engine
    finally:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()


@pytest.fixture
def db_sessionmaker(db_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=db_engine,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )


@pytest_asyncio.fixture
async def redis_client() -> AsyncIterator[redis.Redis]:
    """
    Setup:
      - Connect to dedicated TEST_REDIS_URL
      - Flush DB before tests
    Teardown:
      - Flush DB and close client
    """
    test_redis_url = _require_isolated_url("TEST_REDIS_URL", "REDIS_URL")
    client = redis.from_url(test_redis_url, decode_responses=True)
    try:
        await client.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis unavailable at TEST_REDIS_URL: {exc}")

    await client.flushdb()
    try:
        yield client
    finally:
        await client.flushdb()
        await client.aclose()


@pytest_asyncio.fixture
async def integration_env(redis_client: redis.Redis) -> AsyncIterator[RedisCache]:
    """
    Setup:
      - Use per-test Redis keys/channels to avoid collisions
    Teardown:
      - Restore env vars and cleanup keys used in this test
    """
    suffix = uuid.uuid4().hex
    queue_key = f"alerts:queue:test:{suffix}"
    dlq_key = f"alerts:dlq:test:{suffix}"
    channel = f"alerts:stream:test:{suffix}"

    env_keys = {
        "ALERT_QUEUE_KEY": queue_key,
        "ALERT_DLQ_KEY": dlq_key,
        "ALERT_PUBSUB_CHANNEL": channel,
        "ALERT_MAX_RETRIES": "3",
        "ALERT_RETRY_BASE_SECONDS": "0.01",
    }
    previous = {key: os.getenv(key) for key in env_keys}
    for key, value in env_keys.items():
        os.environ[key] = value

    cache = RedisCache(redis_client)
    await redis_client.delete(queue_key, dlq_key)
    try:
        yield cache
    finally:
        await redis_client.delete(queue_key, dlq_key)
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@pytest_asyncio.fixture
async def test_app(integration_env: RedisCache) -> AsyncIterator[FastAPI]:
    app = FastAPI()
    app.include_router(router, prefix="/api/v3")

    async def _override_get_cache() -> RedisCache:
        return integration_env

    app.dependency_overrides[get_cache] = _override_get_cache
    try:
        yield app
    finally:
        app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def http_client(test_app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture(autouse=True)
async def clear_alert_rows(db_sessionmaker: async_sessionmaker[AsyncSession]) -> AsyncIterator[None]:
    async with db_sessionmaker() as session:
        await session.execute(delete(Alert))
        await session.commit()
    yield
    async with db_sessionmaker() as session:
        await session.execute(delete(Alert))
        await session.commit()


async def _next_pubsub_payload(pubsub: redis.client.PubSub, timeout_seconds: float = 3.0) -> dict:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.2)
        if message and message.get("type") == "message":
            data = message.get("data")
            if isinstance(data, bytes):
                data = data.decode("utf-8")
            if isinstance(data, str):
                parsed = json.loads(data)
                if isinstance(parsed, dict):
                    return parsed
        await asyncio.sleep(0.01)
    raise AssertionError("Timed out waiting for alert pub/sub message.")


async def test_post_alert_to_queue_then_worker_persists_caches_and_publishes(
    http_client: AsyncClient,
    integration_env: RedisCache,
    redis_client: redis.Redis,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    # Subscribe before processing so we can assert publish event.
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(integration_env.cfg.alert_channel)

    try:
        # 1) Send POST /alerts request.
        response = await http_client.post(
            "/api/v3/alerts",
            json={
                "severity": "HIGH",
                "type": "THREAT",
                "confidence": 0.97,
                "zone": "zone:test",
                "payload": {"source": "pytest"},
            },
        )
        assert response.status_code == 200
        response_data = response.json()
        alert_id = response_data["alert_id"]
        assert response_data["status"] == "queued"

        # 2) Assert message is added to Redis queue.
        queue_size = await redis_client.llen(integration_env.cfg.queue_key)
        assert queue_size == 1

        queued_raw = await redis_client.lindex(integration_env.cfg.queue_key, 0)
        assert isinstance(queued_raw, str)
        queued_payload = json.loads(queued_raw)
        assert queued_payload["schema_version"] == "1.0"
        assert queued_payload["alert_id"] == alert_id
        assert queued_payload["retry_count"] == 0
        assert queued_payload["data"]["status"] == "queued"

        # 3) Run worker (simulated by consuming one queue message and processing it).
        popped_payload = await integration_env.pop_alert_queue(timeout=1)
        assert popped_payload is not None
        worker = AlertWorker(redis_cache=integration_env)
        worker.sessionmaker = db_sessionmaker
        await worker._process_one(popped_payload)

        # 4a) Verify alert row exists in PostgreSQL.
        async with db_sessionmaker() as session:
            result = await session.execute(select(Alert).where(Alert.alert_id == alert_id))
            stored_alert = result.scalar_one_or_none()
            assert stored_alert is not None
            assert stored_alert.alert_id == alert_id
            assert stored_alert.status == "processed"
            assert stored_alert.payload.get("alert_id") == alert_id

        # 4b) Verify cached in Redis.
        cached_alert = await integration_env.get_cached_alert(alert_id)
        assert cached_alert is not None
        assert cached_alert["alert_id"] == alert_id
        assert cached_alert["status"] == "processed"

        # 4c) Verify published via pub/sub.
        published_payload = await _next_pubsub_payload(pubsub)
        assert published_payload["alert_id"] == alert_id
        assert published_payload["status"] == "processed"
        assert published_payload["zone"] == "zone:test"
    finally:
        await pubsub.unsubscribe(integration_env.cfg.alert_channel)
        await pubsub.aclose()


async def test_worker_retries_and_pushes_to_dlq_after_max_retries(
    integration_env: RedisCache,
    redis_client: redis.Redis,
    db_sessionmaker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alert_id = f"ALT-FAIL-{uuid.uuid4().hex[:10].upper()}"
    queued_payload = {
        "alert_id": alert_id,
        "severity": "HIGH",
        "type": "THREAT",
        "confidence": 0.9,
        "zone": "zone:dlq",
        "status": "queued",
        "retry_count": 0,
        "payload": {"source": "pytest-dlq"},
    }

    async def _always_fail(self, payload: dict) -> None:  # noqa: ANN001
        raise RuntimeError("forced failure for dlq integration test")

    monkeypatch.setattr(ProcessingService, "process", _always_fail)

    worker = AlertWorker(redis_cache=integration_env)
    worker.sessionmaker = db_sessionmaker
    worker.max_retries = 3
    worker.base_backoff_seconds = 0.001

    await worker._process_one(dict(queued_payload))

    # Ensure alert was never persisted.
    async with db_sessionmaker() as session:
        result = await session.execute(select(Alert).where(Alert.alert_id == alert_id))
        assert result.scalar_one_or_none() is None

    # Ensure message was pushed to DLQ with required metadata.
    dlq_size = await redis_client.llen(integration_env.cfg.dlq_key)
    assert dlq_size == 1

    dlq_raw = await redis_client.lindex(integration_env.cfg.dlq_key, 0)
    assert isinstance(dlq_raw, str)
    dlq_payload = json.loads(dlq_raw)

    assert dlq_payload["alert_id"] == alert_id
    assert dlq_payload["original_payload"]["alert_id"] == alert_id
    assert dlq_payload["error_message"] == "forced failure for dlq integration test"
    assert dlq_payload["retry_count"] == 3
    assert isinstance(dlq_payload["timestamp"], str)
