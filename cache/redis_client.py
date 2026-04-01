import asyncio
import json
import os
from functools import lru_cache
from typing import Any, Dict, Optional

from dotenv import load_dotenv
import redis.asyncio as redis

load_dotenv()


class RedisSettings:
    def __init__(self) -> None:
        self.url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.cache_ttl_seconds = int(os.getenv("REDIS_CACHE_TTL", "60"))
        self.queue_key = os.getenv("ALERT_QUEUE_KEY", "alerts:queue")
        self.dlq_key = os.getenv("ALERT_DLQ_KEY", "alerts:dlq")
        self.metrics_key = os.getenv("ALERT_METRICS_KEY", "alerts:metrics")
        self.alert_channel = os.getenv("ALERT_PUBSUB_CHANNEL", "alerts:stream")
        self.active_threats_key = os.getenv("ACTIVE_THREATS_KEY", "threats:active")
        self.track_state_key = os.getenv("TRACK_STATE_KEY", "tracks:state")


@lru_cache
def get_redis() -> redis.Redis:
    cfg = RedisSettings()
    return redis.from_url(cfg.url, decode_responses=True)


async def ping_with_retry(client: redis.Redis, attempts: int = 3, delay: float = 0.5) -> bool:
    for _ in range(attempts):
        try:
            await client.ping()
            return True
        except Exception:
            await asyncio.sleep(delay)
    return False


class RedisCache:
    """Small convenience wrapper for caching and queues."""

    def __init__(self, client: Optional[redis.Redis] = None) -> None:
        self.client = client or get_redis()
        self.cfg = RedisSettings()

    @staticmethod
    def _to_json(payload: Dict[str, Any]) -> str:
        return json.dumps(payload, separators=(",", ":"))

    @staticmethod
    def _from_json(raw: Any) -> Optional[Dict[str, Any]]:
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        if not isinstance(raw, str):
            return None
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

    async def cache_alert(self, alert_id: str, payload: Dict[str, Any]) -> None:
        await self.client.setex(
            f"alert:{alert_id}",
            self.cfg.cache_ttl_seconds,
            self._to_json(payload),
        )

    async def get_cached_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        data = await self.client.get(f"alert:{alert_id}")
        return self._from_json(data)

    async def cache_recent_alerts(self, alerts: list[Dict[str, Any]]) -> None:
        if not alerts:
            return
        key = "alerts:recent"
        pipe = self.client.pipeline()
        pipe.delete(key)
        for alert in alerts:
            pipe.rpush(key, self._to_json(alert))
        pipe.expire(key, self.cfg.cache_ttl_seconds)
        await pipe.execute()

    async def get_recent_alerts(self, limit: int = 50) -> list[Dict[str, Any]]:
        key = "alerts:recent"
        items = await self.client.lrange(key, -limit, -1)
        return [parsed for item in items if (parsed := self._from_json(item)) is not None]

    async def cache_track_state(self, track_id: str, payload: Dict[str, Any]) -> None:
        await self.client.hset(self.cfg.track_state_key, track_id, self._to_json(payload))

    async def get_track_state(self, track_id: str) -> Optional[Dict[str, Any]]:
        value = await self.client.hget(self.cfg.track_state_key, track_id)
        return self._from_json(value)

    async def push_alert_queue(self, payload: Dict[str, Any] | str) -> None:
        message = payload
        if not isinstance(payload, str):
            message = self._to_json(payload)
        await self.client.lpush(self.cfg.queue_key, message)

    async def push_alert_dlq(self, payload: Dict[str, Any] | str) -> None:
        message = payload
        if not isinstance(payload, str):
            message = self._to_json(payload)
        await self.client.lpush(self.cfg.dlq_key, message)

    async def pop_alert_dlq(self) -> Optional[Dict[str, Any]]:
        payload = await self.client.rpop(self.cfg.dlq_key)
        if payload is None:
            return None
        return self._from_json(payload)

    async def pop_alert_queue(self, timeout: int = 5) -> Optional[Dict[str, Any]]:
        item = await self.client.brpop(self.cfg.queue_key, timeout=timeout)
        if not item:
            return None
        _, payload = item
        return self._from_json(payload)

    async def publish_alert(self, payload: Dict[str, Any]) -> None:
        await self.client.publish(self.cfg.alert_channel, self._to_json(payload))

    async def subscribe_alerts(self):
        pubsub = self.client.pubsub()
        await pubsub.subscribe(self.cfg.alert_channel)
        return pubsub

    async def incr_metric(self, name: str, amount: int = 1) -> int:
        return int(await self.client.hincrby(self.cfg.metrics_key, name, amount))

    async def get_metrics(self) -> Dict[str, int]:
        raw = await self.client.hgetall(self.cfg.metrics_key)
        out: Dict[str, int] = {}
        for key, value in raw.items():
            try:
                out[str(key)] = int(value)
            except (TypeError, ValueError):
                out[str(key)] = 0
        return out

    async def queue_length(self) -> int:
        return int(await self.client.llen(self.cfg.queue_key))

    async def dlq_length(self) -> int:
        return int(await self.client.llen(self.cfg.dlq_key))
