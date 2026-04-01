from typing import Any, Dict
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.schemas import AlertIn
from cache.redis_client import RedisCache
from db.session import get_db
from services.alert_queue_producer import AlertQueueProducer
from services.message_broker import AlertMessageBroker
from services.alert_service import AlertService
from services.track_service import TrackService

router = APIRouter()


async def get_cache() -> RedisCache:
    return RedisCache()


def get_queue_producer(cache: RedisCache = Depends(get_cache)) -> AlertQueueProducer:
    return AlertQueueProducer(cache)


@router.post("/alerts")
async def enqueue_alert(
    body: AlertIn,
    producer: AlertQueueProducer = Depends(get_queue_producer),
):
    """
    Event-driven flow:
    1) API validates + enqueues alert JSON only.
    2) Worker consumes queue and performs DB insert.
    3) Worker updates Redis cache and publishes to websocket channel.
    """
    queued_alert = await producer.enqueue_alert(body)
    return {
        "alert_id": queued_alert.alert_id,
        "status": "queued",
        "schema_version": queued_alert.schema_version,
    }


@router.get("/alerts/recent")
async def recent_alerts(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    cache: RedisCache = Depends(get_cache),
):
    alert_service = AlertService(db, cache)
    alerts = await alert_service.recent_alerts(limit)
    return {"alerts": alerts}


@router.get("/ops/metrics")
async def ops_metrics(cache: RedisCache = Depends(get_cache)):
    """
    Operational queue/worker metrics sourced from Redis counters.
    """
    broker = AlertMessageBroker()
    queue_depth = await broker.queue_length()
    dlq_depth = await broker.dlq_length()
    counters = await cache.get_metrics()
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "broker_backend": broker.cfg.backend,
        "queue_depth": queue_depth,
        "dlq_depth": dlq_depth,
        "counters": counters,
        "alerts": {
            "dlq_non_zero": bool(dlq_depth and dlq_depth > 0),
            "worker_loop_errors": counters.get("alerts_worker_loop_error_total", 0),
            "unsupported_schema": counters.get("alerts_unsupported_schema_total", 0),
        },
    }
    await broker.close()
    return payload


@router.get("/ops/health")
async def ops_health(
    db: AsyncSession = Depends(get_db),
    cache: RedisCache = Depends(get_cache),
):
    db_ok = False
    redis_ok = False
    db_error = ""
    redis_error = ""
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception as exc:  # noqa: BLE001
        db_error = str(exc)
    try:
        await cache.client.ping()
        redis_ok = True
    except Exception as exc:  # noqa: BLE001
        redis_error = str(exc)

    status = "ok" if db_ok and redis_ok else "degraded"
    return {
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dependencies": {
            "postgres": {"ok": db_ok, "error": db_error},
            "redis": {"ok": redis_ok, "error": redis_error},
        },
        "broker_backend": AlertMessageBroker().cfg.backend,
    }


@router.get("/tracks/{track_id}")
async def get_track(
    track_id: str,
    db: AsyncSession = Depends(get_db),
    cache: RedisCache = Depends(get_cache),
):
    track_service = TrackService(db, cache)
    track = await track_service.get_track(track_id)
    if not track:
        raise HTTPException(status_code=404, detail="Track not found")
    return track


@router.post("/incident")
async def create_incident(
    payload: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
):
    from db.models import Incident

    incident = Incident(
        incident_id=payload.get("incident_id"),
        escalation_level=payload.get("escalation_level", 1),
        acknowledged=payload.get("acknowledged", False),
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    return {"incident_id": incident.incident_id, "acknowledged": incident.acknowledged}
