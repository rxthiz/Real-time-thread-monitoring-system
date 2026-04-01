import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from cache.redis_client import RedisCache
from db.models import Alert

logger = logging.getLogger(__name__)


class ProcessingService:
    """Encapsulates idempotent alert processing + persistence + publish."""

    def __init__(self, db: AsyncSession, cache: Optional[RedisCache] = None) -> None:
        self.db = db
        self.cache = cache or RedisCache()

    async def process(self, payload: Dict[str, Any]) -> None:
        """Persist the alert and publish to pub/sub."""
        started = time.perf_counter()
        queue_alert_id = str(payload.get("alert_id", "")).strip()
        if not queue_alert_id:
            logger.warning(
                "alert_missing_id_skip",
                extra={"payload_keys": list(payload.keys())[:20]},
            )
            return

        # Fast path duplicate check to avoid unnecessary INSERT attempts.
        existing_result = await self.db.execute(
            select(Alert.id).where(Alert.alert_id == queue_alert_id).limit(1)
        )
        existing_id = existing_result.scalar_one_or_none()
        if existing_id is not None:
            logger.info(
                "alert_duplicate_precheck_skip alert_id=%s existing_row_id=%s",
                queue_alert_id,
                existing_id,
                extra={
                    "alert_id": queue_alert_id,
                    "existing_row_id": existing_id,
                },
            )
            return

        processed_payload = dict(payload)
        processed_payload["alert_id"] = queue_alert_id
        processed_payload["status"] = "processed"
        processed_payload["processed_at"] = datetime.now(timezone.utc).isoformat()
        alert = Alert(
            alert_id=queue_alert_id,
            severity=str(processed_payload.get("severity", "LOW")),
            type=str(processed_payload.get("type", "THREAT")),
            confidence=float(processed_payload.get("confidence", 0.0)),
            track_id=processed_payload.get("track_id"),
            zone=str(processed_payload.get("zone", "unknown")),
            status="processed",
            payload=processed_payload,
        )
        self.db.add(alert)
        try:
            await self.db.commit()
        except IntegrityError:
            # Race-safe idempotency: another worker inserted same alert_id first.
            await self.db.rollback()
            logger.info(
                "alert_duplicate_integrity_skip alert_id=%s",
                queue_alert_id,
                extra={"alert_id": queue_alert_id},
            )
            return

        await self.db.refresh(alert)

        # Worker is responsible for cache refresh and websocket fan-out.
        await self.cache.cache_alert(queue_alert_id, processed_payload)
        await self.cache.publish_alert(processed_payload)

        elapsed_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "alert_processed alert_id=%s db_row_id=%s zone=%s severity=%s confidence=%s ms=%s",
            queue_alert_id,
            alert.id,
            alert.zone,
            alert.severity,
            alert.confidence,
            round(elapsed_ms, 2),
            extra={
                "alert_id": queue_alert_id,
                "db_row_id": alert.id,
                "zone": alert.zone,
                "severity": alert.severity,
                "confidence": alert.confidence,
                "ms": round(elapsed_ms, 2),
            },
        )
