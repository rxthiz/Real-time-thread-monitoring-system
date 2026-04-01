import asyncio
from copy import deepcopy
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# Allow direct script execution: `python workers/alert_worker.py`
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.schemas import DeadLetterAlert
from cache.redis_client import RedisCache, get_redis
from db.session import get_sessionmaker
from services.message_broker import AlertMessageBroker
from services.processing_service import ProcessingService

# Structured logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("alert_worker")


class AlertWorker:
    def __init__(self, redis_cache: Optional[RedisCache] = None) -> None:
        self.cache = redis_cache or RedisCache()
        self.stop_event = asyncio.Event()
        self.queue_key = os.getenv("ALERT_QUEUE_KEY", "alerts:queue")
        self.dlq_key = os.getenv("ALERT_DLQ_KEY", "alerts:dlq")
        self.max_retries = int(os.getenv("ALERT_MAX_RETRIES", "3"))
        self.base_backoff_seconds = float(os.getenv("ALERT_RETRY_BASE_SECONDS", "0.5"))
        self.sessionmaker = get_sessionmaker()
        self.broker = AlertMessageBroker()

    async def handle_shutdown(self) -> None:
        logger.info("shutdown_signal_received")
        self.stop_event.set()

    @staticmethod
    def _retry_count(payload: Dict[str, Any]) -> int:
        try:
            return max(0, int(payload.get("retry_count", 0)))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _extract_alert_id(payload: Dict[str, Any]) -> str:
        raw = str(payload.get("alert_id", "")).strip()
        if raw:
            return raw
        data = payload.get("data")
        if isinstance(data, dict):
            nested = str(data.get("alert_id", "")).strip()
            if nested:
                return nested
        return "unknown"

    @staticmethod
    def _normalize_envelope(raw_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Backward compatibility:
        - New versioned envelope: {schema_version, alert_id, data, ...}
        - Legacy flat payload: {...alert fields...}
        """
        schema_version = str(raw_payload.get("schema_version", "")).strip()
        if schema_version:
            envelope = dict(raw_payload)
            envelope["retry_count"] = AlertWorker._retry_count(raw_payload)
            envelope["alert_id"] = AlertWorker._extract_alert_id(raw_payload)
            if not isinstance(envelope.get("data"), dict):
                envelope["data"] = {}
            return envelope

        # Legacy flat payload fallback (treated as schema v1.0 data body).
        legacy = dict(raw_payload)
        alert_id = AlertWorker._extract_alert_id(legacy)
        retry_count = AlertWorker._retry_count(legacy)
        legacy.pop("retry_count", None)
        return {
            "schema_version": "1.0",
            "alert_id": alert_id,
            "retry_count": retry_count,
            "data": legacy,
        }

    async def process_v1(self, service: ProcessingService, envelope: Dict[str, Any]) -> None:
        body = dict(envelope.get("data", {}))
        body["alert_id"] = envelope.get("alert_id")
        body["retry_count"] = envelope.get("retry_count", 0)
        await service.process(body)

    async def process_v2(self, service: ProcessingService, envelope: Dict[str, Any]) -> None:
        # Placeholder for future v2 transformations/validations.
        body = dict(envelope.get("data", {}))
        body["alert_id"] = envelope.get("alert_id")
        body["retry_count"] = envelope.get("retry_count", 0)
        await service.process(body)

    async def _route_by_version(self, service: ProcessingService, envelope: Dict[str, Any]) -> None:
        version = str(envelope.get("schema_version", "1.0")).strip() or "1.0"
        if version == "1.0":
            await self.process_v1(service, envelope)
            return
        if version == "2.0":
            await self.process_v2(service, envelope)
            return
        await self.cache.incr_metric("alerts_unsupported_schema_total", 1)
        raise ValueError(f"unsupported_schema_version:{version}")

    async def _push_to_dlq(
        self,
        *,
        payload: Dict[str, Any],
        error_message: str,
        retry_count: int,
    ) -> None:
        alert_id = self._extract_alert_id(payload)
        dlq_payload = DeadLetterAlert(
            alert_id=alert_id,
            original_payload=payload,
            error_message=error_message or "processing_failed",
            retry_count=retry_count,
            timestamp=datetime.now(timezone.utc),
        )
        if hasattr(dlq_payload, "model_dump"):
            encoded_payload = dlq_payload.model_dump(mode="json")  # type: ignore[attr-defined]
        else:
            encoded_payload = dlq_payload.dict()
        await self.broker.publish_dlq(json.dumps(encoded_payload, separators=(",", ":")))
        await self.cache.incr_metric("alerts_dlq_total", 1)
        logger.error(
            "alert_sent_to_dlq alert_id=%s retry_count=%s dlq=%s error=%s",
            alert_id,
            retry_count,
            self.dlq_key,
            error_message,
        )

    async def _process_one(self, payload: Dict[str, Any]) -> None:
        # Keep a stable copy for DLQ metadata while retry_count mutates on retries.
        envelope = self._normalize_envelope(payload)
        original_payload = deepcopy(envelope)
        while not self.stop_event.is_set():
            retry_count = self._retry_count(envelope)
            envelope["retry_count"] = retry_count
            try:
                async with self.sessionmaker() as db:
                    service = ProcessingService(db, self.cache)
                    await self._route_by_version(service, envelope)
                await self.cache.incr_metric("alerts_processed_total", 1)
                return
            except Exception as exc:  # noqa: BLE001
                if retry_count >= self.max_retries:
                    await self._push_to_dlq(
                        payload=original_payload,
                        error_message=str(exc),
                        retry_count=retry_count,
                    )
                    return

                next_retry = retry_count + 1
                envelope["retry_count"] = next_retry
                backoff_seconds = self.base_backoff_seconds * (2 ** (next_retry - 1))
                await self.cache.incr_metric("alerts_retry_total", 1)
                logger.warning(
                    "alert_retry_scheduled alert_id=%s retry_count=%s max_retries=%s backoff_seconds=%.2f error=%s",
                    self._extract_alert_id(envelope),
                    next_retry,
                    self.max_retries,
                    backoff_seconds,
                    str(exc),
                )
                await asyncio.sleep(backoff_seconds)

    async def run(self) -> None:
        logger.info(
            "alert_worker_started queue=%s dlq=%s max_retries=%s",
            self.queue_key,
            self.dlq_key,
            self.max_retries,
        )
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.handle_shutdown()))
            except NotImplementedError:
                # Windows event loops may not support add_signal_handler.
                def _fallback_handler(*_args: Any) -> None:
                    loop.call_soon_threadsafe(lambda: asyncio.create_task(self.handle_shutdown()))

                signal.signal(sig, _fallback_handler)

        # Warm ping with retry for redis-backed cache metrics/pubsub.
        redis_client = get_redis()
        from cache.redis_client import ping_with_retry

        if not await ping_with_retry(redis_client):
            logger.warning("redis_unreachable_startup")

        while not self.stop_event.is_set():
            try:
                raw = await self.broker.consume_queue(timeout=2)
                if raw is None:
                    continue
                payload = raw
                if isinstance(raw, (bytes, str)):
                    try:
                        payload = json.loads(raw)
                    except json.JSONDecodeError:
                        await self.cache.incr_metric("alerts_invalid_json_total", 1)
                        logger.warning("invalid_json_payload", extra={"raw": str(raw)[:200]})
                        continue
                if not isinstance(payload, dict):
                    await self.cache.incr_metric("alerts_invalid_payload_total", 1)
                    logger.warning("invalid_payload_type_skip type=%s", type(payload).__name__)
                    continue
                await self._process_one(payload)
            except asyncio.CancelledError:
                break
            except Exception as exc:  # noqa: BLE001
                await self.cache.incr_metric("alerts_worker_loop_error_total", 1)
                logger.error("worker_loop_error", extra={"error": str(exc)})
                await asyncio.sleep(0.5)

        logger.info("alert_worker_stopped")
        await self.broker.close()


async def main() -> None:
    worker = AlertWorker()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
