from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.schemas import AlertIn
from cache.redis_client import RedisCache
from db.models import Alert
from services.alert_queue_producer import AlertQueueProducer


class AlertService:
    def __init__(self, db: AsyncSession, cache: Optional[RedisCache] = None) -> None:
        self.db = db
        self.cache = cache or RedisCache()

    async def create_alert(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        API-side ingest is queue-only. DB insert happens in the worker.
        """
        producer = AlertQueueProducer(self.cache)
        queued_alert = await producer.enqueue_alert(AlertIn(**data))
        return producer.as_dict(queued_alert)

    async def recent_alerts(self, limit: int = 50) -> List[Alert]:
        cached = await self.cache.get_recent_alerts(limit)
        if cached:
            return cached  # type: ignore[return-value]

        result = await self.db.execute(select(Alert).order_by(Alert.created_at.desc()).limit(limit))
        alerts = list(result.scalars())
        await self.cache.cache_recent_alerts([a.payload for a in alerts])
        return alerts
