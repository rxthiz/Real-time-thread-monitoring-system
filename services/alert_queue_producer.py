import json
import uuid
from typing import Any, Dict, Optional

from fastapi.encoders import jsonable_encoder

from api.schemas import AlertIn, QueuedAlert
from cache.redis_client import RedisCache
from services.message_broker import AlertMessageBroker


class AlertQueueProducer:
    """Builds and enqueues validated alert envelopes for asynchronous processing."""

    def __init__(self, cache: Optional[RedisCache] = None) -> None:
        self.cache = cache or RedisCache()
        self.broker = AlertMessageBroker()

    @staticmethod
    def generate_alert_id() -> str:
        return f"ALT-{uuid.uuid4().hex[:20].upper()}"

    async def enqueue_alert(self, body: AlertIn) -> QueuedAlert:
        alert_id = self.generate_alert_id()

        # Validation layer before queueing:
        # 1) FastAPI validates request body as AlertIn.
        # 2) We validate final outbound envelope as QueuedAlert.
        queued_alert = QueuedAlert.from_alert_in(alert_id=alert_id, body=body)

        # Serialize to JSON to keep queue payload stable across workers/languages.
        serialized = json.dumps(jsonable_encoder(queued_alert), separators=(",", ":"))
        await self.broker.publish_queue(serialized)
        return queued_alert

    @staticmethod
    def as_dict(alert: QueuedAlert) -> Dict[str, Any]:
        if hasattr(alert, "model_dump"):
            return alert.model_dump()  # type: ignore[attr-defined]
        return alert.dict()
