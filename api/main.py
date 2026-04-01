import asyncio
import base64
import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import cv2
import numpy as np
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect, status
import redis.asyncio as redis
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from api.map_services import fetch_nearby_services
from api.routes import router as v3_router
from cache.redis_client import RedisCache, get_redis, ping_with_retry
from api.realtime_engine import RealtimeThreatEngine
from src.reports.timeline_pdf import build_incident_timeline_pdf
from src.utils.config import load_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

engine: Optional[RealtimeThreatEngine] = None
auth_sessions: dict[str, dict[str, Any]] = {}

SESSION_COOKIE_NAME = "rtm_session"
SESSION_MAX_AGE_SECONDS = int(os.getenv("THREAT_SESSION_MAX_AGE_SECONDS", "43200"))
SESSION_SECURE_COOKIE = os.getenv("THREAT_SECURE_COOKIE", "0") == "1"

ADMIN_USERNAME = os.getenv("THREAT_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("THREAT_ADMIN_PASSWORD", "admin123")
USER_USERNAME = os.getenv("THREAT_USER_USERNAME", "user")
USER_PASSWORD = os.getenv("THREAT_USER_PASSWORD", "user123")

ROLE_CREDENTIALS: dict[str, tuple[str, str]] = {
    "admin": (ADMIN_USERNAME, ADMIN_PASSWORD),
    "operator": (USER_USERNAME, USER_PASSWORD),
    "user": (USER_USERNAME, USER_PASSWORD),
}


def _security_log(type_: str, message: str, **extra: Any) -> None:
    payload: Dict[str, Any] = {
        "event": "SECURITY",
        "type": type_,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    payload.update({key: value for key, value in extra.items() if value is not None})
    logger.warning(json.dumps(payload, default=str))


class LoginRequest(BaseModel):
    role: str
    username: str
    password: str


class AlertDispositionRequest(BaseModel):
    disposition: str
    note: str = ""


class ZonePolicyUpdateRequest(BaseModel):
    hour_of_day: int
    adaptive_threshold: Optional[float] = None
    snooze_minutes: Optional[int] = None


class ReIDDetectionPayload(BaseModel):
    label: str
    confidence: float
    bbox_xyxy: Optional[list[float]] = None
    bbox: Optional[list[float]] = None


class ReIDObserveRequest(BaseModel):
    source: str
    frame_id: Optional[int] = None
    timestamp: Optional[str] = None
    frame_base64: Optional[str] = None
    zone_key: Optional[str] = None
    camera_id: Optional[str] = None
    detections: list[ReIDDetectionPayload]


class IncidentEventRequest(BaseModel):
    event_type: str
    note: str = ""
    source: str = ""
    unit_id: str = ""
    officer_id: str = ""
    eta_minutes: Optional[int] = None


class ShiftWindowInput(BaseModel):
    name: str
    start: str
    end: str


class ShiftWindowsUpdateRequest(BaseModel):
    windows: list[ShiftWindowInput]


class EscalationStepInput(BaseModel):
    name: str
    delay_seconds: int
    channels: list[str]
    recipients: list[str] = []


class EscalationChainUpdateRequest(BaseModel):
    steps: list[EscalationStepInput]


class EscalationStartRequest(BaseModel):
    source: str = ""
    note: str = ""
    reason: str = "SOS_TRIGGERED"


class EscalationAcknowledgeRequest(BaseModel):
    note: str = ""
    resolution: str = "ACKNOWLEDGED"


class ServiceCreateRequest(BaseModel):
    name: str
    type: str
    lat: float
    lng: float
    phone: str
    email: str = ""
    is_active: bool = True
    priority: int = 1


class SOSDispatchRequest(BaseModel):
    incident_id: str
    services: list[str]
    reason: str = ""


class SOSManualRequest(BaseModel):
    incident_id: str
    services: list[str]
    reason: str = ""


class SOSTestSmsRequest(BaseModel):
    to: str
    message: str = ""


class FalsePositiveFeedbackRequest(BaseModel):
    alert_id: str
    label: str


def get_engine() -> RealtimeThreatEngine:
    if engine is None:
        raise HTTPException(status_code=503, detail="Threat engine not initialized")
    return engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine
    cfg_path = os.getenv("THREAT_CONFIG", "src/config/settings.yaml")
    cfg = load_settings(cfg_path)
    engine = RealtimeThreatEngine(cfg)
    engine.start()
    try:
        yield
    finally:
        if engine is not None:
            engine.stop()


app = FastAPI(title="Realtime Threat Monitoring API", version="2.0.0", lifespan=lifespan)
app.include_router(v3_router, prefix="/api/v3")

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "web"
REACT_DASHBOARD_DIR = STATIC_DIR / "react-zone-dashboard"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173,http://localhost:3000",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def create_session(username: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    auth_sessions[token] = {"username": username, "role": role, "issued_at": time.time()}
    return token


def get_session(token: Optional[str]) -> Optional[dict[str, Any]]:
    if not token:
        return None
    payload = auth_sessions.get(token)
    if payload is None:
        return None
    issued_at = float(payload.get("issued_at", 0))
    if time.time() - issued_at > SESSION_MAX_AGE_SECONDS:
        auth_sessions.pop(token, None)
        return None
    return payload


def invalidate_session(token: Optional[str]) -> None:
    if not token:
        return
    auth_sessions.pop(token, None)


def require_session(request: Request) -> dict[str, Any]:
    payload = get_session(request.cookies.get(SESSION_COOKIE_NAME))
    if payload is None:
        _security_log("UNAUTHORIZED", "Missing or expired session", path=str(request.url.path))
        raise HTTPException(status_code=401, detail="Authentication required")
    return payload


def require_admin(session: dict[str, Any] = Depends(require_session)) -> dict[str, Any]:
    if session.get("role") != "admin":
        _security_log(
            "FORBIDDEN",
            "Admin access required",
            username=session.get("username"),
            role=session.get("role"),
        )
        raise HTTPException(status_code=403, detail="Admin access required")
    return session


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        max_age=SESSION_MAX_AGE_SECONDS,
        samesite="lax",
        secure=SESSION_SECURE_COOKIE,
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(key=SESSION_COOKIE_NAME)


def is_logged_in(request: Request) -> bool:
    return get_session(request.cookies.get(SESSION_COOKIE_NAME)) is not None


def websocket_session(websocket: WebSocket) -> Optional[dict[str, Any]]:
    payload = get_session(websocket.cookies.get(SESSION_COOKIE_NAME))
    if payload is None:
        _security_log("WS_UNAUTHORIZED", "Rejected websocket connection", path=str(websocket.url.path))
    return payload


@app.on_event("startup")
async def _warm_connections() -> None:
    # warm DB engine
    _ = load_settings(os.getenv("THREAT_CONFIG", "src/config/settings.yaml"))
    # warm Redis
    client: redis.Redis = get_redis()
    await ping_with_retry(client)


def normalize_disposition(value: str) -> str:
    token = str(value).strip().lower().replace(" ", "_")
    mapping = {
        "acknowledged": "ACKNOWLEDGED",
        "acknowledge": "ACKNOWLEDGED",
        "escalated": "ESCALATED",
        "escalate": "ESCALATED",
        "dismissed": "DISMISSED",
        "dismiss": "DISMISSED",
    }
    normalized = mapping.get(token)
    if normalized is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid disposition. Allowed: acknowledged, escalated, dismissed",
        )
    return normalized


def parse_hhmm(value: str) -> int:
    text = str(value).strip()
    parts = text.split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid time '{value}'. Expected HH:MM")
    hh = int(parts[0])
    mm = int(parts[1])
    if hh < 0 or hh > 23:
        raise ValueError(f"Invalid hour in '{value}'")
    if mm < 0 or mm > 59:
        raise ValueError(f"Invalid minute in '{value}'")
    return (hh * 60) + mm


@app.get("/login")
async def login_page(request: Request):
    if not STATIC_DIR.exists():
        raise HTTPException(status_code=404, detail="Dashboard files not found")
    if is_logged_in(request):
        return RedirectResponse(url="/")
    return FileResponse(str(STATIC_DIR / "login.html"))


@app.post("/api/auth/login")
async def login(body: LoginRequest):
    role = body.role.strip().lower()
    username = body.username.strip()
    password = body.password

    expected = ROLE_CREDENTIALS.get(role)
    if expected is None:
        _security_log("INVALID_ROLE", "Rejected login for invalid role", role=role, username=username)
        raise HTTPException(status_code=400, detail="Invalid role")
    expected_username, expected_password = expected
    if username != expected_username or password != expected_password:
        _security_log("LOGIN_FAILED", "Invalid username or password", role=role, username=username)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    normalized_role = "operator" if role == "user" else role
    token = create_session(username=username, role=normalized_role)
    response = JSONResponse({"message": "Login successful", "role": normalized_role, "username": username})
    set_session_cookie(response, token)
    return response


@app.post("/api/auth/logout")
async def logout(request: Request):
    invalidate_session(request.cookies.get(SESSION_COOKIE_NAME))
    response = JSONResponse({"message": "Logged out"})
    clear_session_cookie(response)
    return response


@app.get("/api/auth/me")
async def auth_me(session: dict[str, Any] = Depends(require_session)):
    return {"username": session["username"], "role": session["role"]}


@app.get("/api/status")
async def get_status(_: dict[str, Any] = Depends(require_session)):
    return get_engine().status()


@app.post("/api/camera/open")
async def open_camera(index: int = 0, _: dict[str, Any] = Depends(require_admin)):
    service = get_engine()
    try:
        status = service.switch_to_camera(index=index)
        return {"message": "Live camera opened", "status": status}
    except Exception as exc:
        logger.warning("Unable to open live camera index=%s: %s", index, exc)
        try:
            status = service.switch_to_default_source()
        except Exception as fallback_exc:
            raise HTTPException(
                status_code=500,
                detail=f"Unable to open live camera ({exc}) and fallback to default video ({fallback_exc})",
            ) from fallback_exc
        return {
            "message": "Live camera unavailable; switched to default video",
            "status": status,
            "fallback": True,
            "error": str(exc),
        }


@app.post("/api/camera/close")
async def close_camera(_: dict[str, Any] = Depends(require_admin)):
    service = get_engine()
    try:
        status = service.switch_to_default_source()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unable to switch to default video: {exc}") from exc
    return {"message": "Switched to default video", "status": status}


@app.get("/api/map/nearby")
async def map_nearby(lat: float, lon: float, radius_km: int = 5, _: dict[str, Any] = Depends(require_session)):
    try:
        return await fetch_nearby_services(lat=lat, lon=lon, radius_km=radius_km)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/services")
async def get_services(_: dict[str, Any] = Depends(require_session)):
    return get_engine().list_services()


@app.post("/api/services")
async def create_service(
    body: ServiceCreateRequest,
    session: dict[str, Any] = Depends(require_admin),
):
    operator_id = str(session.get("username", "")).strip() or "unknown"
    try:
        payload = body.model_dump() if hasattr(body, "model_dump") else body.dict()
        service = get_engine().create_service(payload, operator_id=operator_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Service created", "service": service}


@app.post("/api/sos/dispatch")
async def dispatch_sos(
    body: SOSDispatchRequest,
    session: dict[str, Any] = Depends(require_session),
):
    operator_id = str(session.get("username", "")).strip() or "unknown"
    try:
        payload = get_engine().trigger_sos(
            incident_id=str(body.incident_id).strip(),
            services=body.services,
            trigger_type="manual",
            reason=str(body.reason).strip() or "Manual dispatch",
            operator_id=operator_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "SOS dispatched", **payload}


@app.post("/api/sos/manual")
async def manual_sos(
    body: SOSManualRequest,
    session: dict[str, Any] = Depends(require_session),
):
    operator_id = str(session.get("username", "")).strip() or "unknown"
    try:
        payload = get_engine().manual_trigger_sos(
            incident_id=str(body.incident_id).strip(),
            services=body.services,
            reason=str(body.reason).strip() or "Manual trigger",
            operator_id=operator_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Manual SOS triggered", **payload}


@app.post("/api/sos/test-sms")
async def test_sos_sms(
    body: SOSTestSmsRequest,
    session: dict[str, Any] = Depends(require_admin),
):
    phone = str(body.to or "").strip()
    if not phone:
        raise HTTPException(status_code=400, detail="Field 'to' is required")

    operator_id = str(session.get("username", "")).strip() or "unknown"
    message = str(body.message or "").strip()
    if not message:
        message = (
            f"[Threat Monitor Test] Admin={operator_id} "
            f"Time={datetime.now(timezone.utc).isoformat()}"
        )

    sender = get_engine().sms_sender
    result = sender.send_sms(phone, message)
    return {
        "message": "Test SMS attempted",
        "provider": sender.provider,
        "simulation_mode": sender.simulation,
        "result": result,
    }


@app.get("/")
async def dashboard(request: Request):
    if not STATIC_DIR.exists():
        raise HTTPException(status_code=404, detail="Dashboard files not found")
    if not is_logged_in(request):
        return RedirectResponse(url="/login")
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/zone-map-dashboard")
async def react_zone_dashboard(request: Request):
    if not STATIC_DIR.exists():
        raise HTTPException(status_code=404, detail="Dashboard files not found")
    if not is_logged_in(request):
        return RedirectResponse(url="/login")
    react_index = REACT_DASHBOARD_DIR / "index.html"
    if not react_index.exists():
        raise HTTPException(
            status_code=404,
            detail="React zone dashboard build not found. Build frontend/ to web/react-zone-dashboard first.",
        )
    return FileResponse(str(react_index))


@app.get("/api/detections/history")
async def get_history(limit: int = 100, _: dict[str, Any] = Depends(require_session)):
    return get_engine().detection_history(limit)


@app.delete("/api/detections/history")
async def clear_history(_: dict[str, Any] = Depends(require_admin)):
    get_engine().clear_detections()
    return {"message": "Detection history cleared"}


@app.get("/api/alerts/history")
async def get_alert_history(limit: int = 100, _: dict[str, Any] = Depends(require_session)):
    return get_engine().alert_history(limit)


@app.get("/api/alerts/{alert_id}/explanation")
async def get_alert_explanation(alert_id: str, _: dict[str, Any] = Depends(require_session)):
    try:
        return get_engine().alert_explanation(alert_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.delete("/api/alerts/history")
async def clear_alert_history(_: dict[str, Any] = Depends(require_admin)):
    get_engine().clear_alerts()
    return {"message": "Alert history cleared"}


@app.post("/api/alerts/{alert_id}/disposition")
async def add_alert_disposition(
    alert_id: str,
    body: AlertDispositionRequest,
    session: dict[str, Any] = Depends(require_session),
):
    disposition = normalize_disposition(body.disposition)
    operator_id = str(session.get("username", "")).strip() or "unknown"
    try:
        result = get_engine().add_alert_disposition(
            alert_id=alert_id,
            disposition=disposition,
            operator_id=operator_id,
            note=body.note,
        )
    except KeyError as exc:
        reason = str(exc.args[0]) if exc.args else str(exc)
        raise HTTPException(status_code=404, detail=reason) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Disposition recorded", **result}


@app.get("/api/alerts/{alert_id}/audit")
async def get_alert_audit(alert_id: str, limit: int = 200, _: dict[str, Any] = Depends(require_session)):
    try:
        payload = get_engine().alert_audit(alert_id=alert_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return payload


@app.post("/api/feedback")
async def submit_false_positive_feedback(
    body: FalsePositiveFeedbackRequest,
    session: dict[str, Any] = Depends(require_session),
):
    operator_id = str(session.get("username", "")).strip() or "unknown"
    try:
        payload = get_engine().submit_false_positive_feedback(
            alert_id=body.alert_id,
            label=body.label,
            operator_id=operator_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "False-positive feedback recorded", **payload}


@app.get("/api/model/status")
async def get_false_positive_model_status(_: dict[str, Any] = Depends(require_session)):
    return get_engine().false_positive_model_status()


@app.get("/api/alerts/{alert_id}/evidence")
async def get_alert_evidence(
    alert_id: str,
    download: bool = False,
    thumbnail: bool = False,
    _: dict[str, Any] = Depends(require_session),
):
    service = get_engine()
    if download and thumbnail:
        raise HTTPException(status_code=400, detail="download and thumbnail cannot both be true")
    if download:
        try:
            clip_path = service.alert_evidence_file(alert_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return FileResponse(str(clip_path), media_type="video/mp4", filename=clip_path.name)
    if thumbnail:
        try:
            thumbnail_path = service.alert_evidence_thumbnail_file(alert_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return FileResponse(str(thumbnail_path), media_type="image/jpeg", filename=thumbnail_path.name)

    try:
        return service.alert_evidence(alert_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/audit/entries")
async def get_audit_entries(
    alert_id: Optional[str] = None,
    limit: int = 200,
    _: dict[str, Any] = Depends(require_admin),
):
    return get_engine().audit_entries(alert_id=alert_id, limit=limit)


@app.get("/api/audit/verify")
async def verify_audit_chain(
    alert_id: Optional[str] = None,
    limit: int = 5000,
    _: dict[str, Any] = Depends(require_admin),
):
    return get_engine().audit_chain(alert_id=alert_id, limit=limit)


@app.get("/api/zones/policies")
async def list_zone_policies(limit: int = 200, _: dict[str, Any] = Depends(require_admin)):
    return get_engine().list_zone_policies(limit=limit)


@app.get("/api/zones/live-status")
async def get_zone_live_status(limit: int = 200, _: dict[str, Any] = Depends(require_session)):
    return get_engine().zone_live_status(limit=limit)


@app.get("/api/zones/layout")
async def get_zone_layout(limit: int = 200, _: dict[str, Any] = Depends(require_session)):
    return get_engine().zone_layout(limit=limit)


@app.get("/api/zones/{zone_key}/policy")
async def get_zone_policy(
    zone_key: str,
    hour_of_day: Optional[int] = None,
    _: dict[str, Any] = Depends(require_admin),
):
    try:
        return get_engine().get_zone_policy(zone_key=zone_key, hour_of_day=hour_of_day)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/zones/{zone_key}/policy")
async def set_zone_policy(
    zone_key: str,
    body: ZonePolicyUpdateRequest,
    session: dict[str, Any] = Depends(require_admin),
):
    operator_id = str(session.get("username", "")).strip() or "unknown"
    try:
        policy = get_engine().set_zone_policy(
            zone_key=zone_key,
            hour_of_day=body.hour_of_day,
            operator_id=operator_id,
            adaptive_threshold=body.adaptive_threshold,
            snooze_minutes=body.snooze_minutes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Zone policy updated", "policy": policy}


@app.get("/api/analytics/shift-windows")
async def get_shift_windows(_: dict[str, Any] = Depends(require_session)):
    return get_engine().shift_windows()


@app.post("/api/analytics/shift-windows")
async def set_shift_windows(
    body: ShiftWindowsUpdateRequest,
    session: dict[str, Any] = Depends(require_admin),
):
    operator_id = str(session.get("username", "")).strip() or "unknown"
    windows = []
    for item in body.windows:
        try:
            start_minute = parse_hhmm(item.start)
            end_minute = parse_hhmm(item.end)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        windows.append(
            {
                "name": item.name.strip(),
                "start_minute": start_minute,
                "end_minute": end_minute,
            }
        )
    try:
        payload = get_engine().set_shift_windows(windows=windows, operator_id=operator_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Shift windows updated", **payload}


@app.get("/api/analytics/overview")
async def get_analytics_overview(
    days: int = 30,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    zone_key: Optional[str] = None,
    hour_start: Optional[int] = None,
    hour_end: Optional[int] = None,
    _: dict[str, Any] = Depends(require_session),
):
    if hour_start is not None and (hour_start < 0 or hour_start > 23):
        raise HTTPException(status_code=400, detail="hour_start must be between 0 and 23")
    if hour_end is not None and (hour_end < 0 or hour_end > 23):
        raise HTTPException(status_code=400, detail="hour_end must be between 0 and 23")
    return get_engine().analytics_overview(
        days=days,
        from_ts=from_ts,
        to_ts=to_ts,
        zone_key=zone_key,
        hour_start=hour_start,
        hour_end=hour_end,
    )


@app.get("/api/analytics/heatmap")
async def get_analytics_heatmap(
    days: int = 30,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    zone_key: Optional[str] = None,
    _: dict[str, Any] = Depends(require_session),
):
    return get_engine().analytics_heatmap(
        days=days,
        from_ts=from_ts,
        to_ts=to_ts,
        zone_key=zone_key,
    )


@app.get("/api/escalation/chain")
async def get_escalation_chain(_: dict[str, Any] = Depends(require_session)):
    return get_engine().escalation_chain()


@app.post("/api/escalation/chain")
async def set_escalation_chain(
    body: EscalationChainUpdateRequest,
    session: dict[str, Any] = Depends(require_admin),
):
    operator_id = str(session.get("username", "")).strip() or "unknown"
    steps = []
    for item in body.steps:
        channels = [str(ch).strip().lower() for ch in item.channels if str(ch).strip()]
        recipients = [str(value).strip() for value in item.recipients if str(value).strip()]
        steps.append(
            {
                "name": item.name.strip(),
                "delay_seconds": int(item.delay_seconds),
                "channels": channels,
                "recipients": recipients,
            }
        )
    try:
        payload = get_engine().set_escalation_chain(steps=steps, operator_id=operator_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Escalation chain updated", **payload}


@app.get("/api/incidents/{incident_id}/escalation/status")
async def get_incident_escalation_status(
    incident_id: str,
    _: dict[str, Any] = Depends(require_session),
):
    try:
        return get_engine().incident_escalation_status(incident_id=incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/incidents/{incident_id}/escalation/start")
async def start_incident_escalation(
    incident_id: str,
    body: EscalationStartRequest,
    session: dict[str, Any] = Depends(require_session),
):
    operator_id = str(session.get("username", "")).strip() or "unknown"
    try:
        payload = get_engine().start_incident_escalation(
            incident_id=incident_id,
            operator_id=operator_id,
            source=body.source.strip(),
            note=body.note.strip(),
            reason=body.reason.strip() or "SOS_TRIGGERED",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Escalation started", **payload}


@app.post("/api/incidents/{incident_id}/escalation/ack")
async def acknowledge_incident_escalation(
    incident_id: str,
    body: EscalationAcknowledgeRequest,
    session: dict[str, Any] = Depends(require_session),
):
    operator_id = str(session.get("username", "")).strip() or "unknown"
    try:
        payload = get_engine().acknowledge_incident_escalation(
            incident_id=incident_id,
            operator_id=operator_id,
            note=body.note.strip(),
            resolution=body.resolution.strip() or "ACKNOWLEDGED",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Escalation acknowledged", **payload}


@app.get("/api/incidents/{incident_id}/response")
async def get_incident_response(
    incident_id: str,
    _: dict[str, Any] = Depends(require_session),
):
    try:
        return get_engine().incident_response_snapshot(incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/incidents/{incident_id}/ack")
async def acknowledge_incident_response(
    incident_id: str,
    body: EscalationAcknowledgeRequest,
    session: dict[str, Any] = Depends(require_session),
):
    operator_id = str(session.get("username", "")).strip() or "unknown"
    try:
        payload = get_engine().acknowledge_incident_response(
            incident_id=incident_id,
            operator_id=operator_id,
            note=body.note.strip(),
            resolution=body.resolution.strip() or "ACKNOWLEDGED",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Incident acknowledged", **payload}


@app.get("/api/reid/tracks")
async def get_reid_tracks(
    limit: int = 100,
    within_seconds: int = 900,
    _: dict[str, Any] = Depends(require_session),
):
    return get_engine().reid_recent_tracks(limit=limit, within_seconds=within_seconds)


@app.get("/api/reid/tracks/{threat_id}/path")
async def get_reid_track_path(threat_id: str, _: dict[str, Any] = Depends(require_session)):
    payload = get_engine().reid_track_path(threat_id)
    if payload is None:
        raise HTTPException(status_code=404, detail=f"Unknown threat_id '{threat_id}'")
    return payload


@app.get("/api/reid/tracks/{threat_id}")
async def get_reid_track(threat_id: str, _: dict[str, Any] = Depends(require_session)):
    payload = get_engine().reid_track(threat_id)
    if payload is None:
        raise HTTPException(status_code=404, detail=f"Unknown threat_id '{threat_id}'")
    return payload


@app.get("/api/predictive/tracks")
async def get_predictive_tracks(
    limit: int = 100,
    within_seconds: int = 900,
    _: dict[str, Any] = Depends(require_session),
):
    return get_engine().predictive_tracks(limit=limit, within_seconds=within_seconds, high_risk_only=False)


@app.get("/api/predictive/high-risk")
async def get_predictive_high_risk(
    limit: int = 100,
    within_seconds: int = 900,
    _: dict[str, Any] = Depends(require_session),
):
    return get_engine().predictive_tracks(limit=limit, within_seconds=within_seconds, high_risk_only=True)


@app.get("/api/tracks/high-risk")
async def get_behavior_high_risk_tracks(
    limit: int = 100,
    threshold: Optional[float] = None,
    _: dict[str, Any] = Depends(require_session),
):
    try:
        return get_engine().high_risk_track_profiles(limit=limit, threshold=threshold)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/tracks/{track_id}/profile")
async def get_track_profile(track_id: str, _: dict[str, Any] = Depends(require_session)):
    try:
        return get_engine().track_profile(track_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/reid/observe")
async def observe_reid(body: ReIDObserveRequest, _: dict[str, Any] = Depends(require_session)):
    frame = None
    if body.frame_base64:
        try:
            encoded = str(body.frame_base64)
            if "," in encoded:
                encoded = encoded.split(",", 1)[1]
            raw = base64.b64decode(encoded, validate=True)
            arr = np.frombuffer(raw, dtype=np.uint8)
            frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if frame is None:
                raise ValueError("Decoded frame is empty")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid frame_base64: {exc}") from exc

    detections: list[Dict[str, Any]] = []
    for det in body.detections:
        payload: Dict[str, Any] = {
            "label": str(det.label),
            "confidence": float(det.confidence),
        }
        if det.bbox_xyxy is not None:
            if len(det.bbox_xyxy) != 4:
                raise HTTPException(status_code=400, detail="bbox_xyxy must have 4 numbers")
            payload["bbox_xyxy"] = [float(v) for v in det.bbox_xyxy]
        elif det.bbox is not None:
            if len(det.bbox) != 4:
                raise HTTPException(status_code=400, detail="bbox must have 4 numbers [x,y,w,h]")
            payload["bbox"] = [float(v) for v in det.bbox]
        else:
            raise HTTPException(status_code=400, detail="Each detection must provide bbox_xyxy or bbox")
        detections.append(payload)

    return get_engine().correlate_external_detections(
        source=body.source,
        detections=detections,
        frame=frame,
        frame_id=body.frame_id,
        timestamp=body.timestamp,
        zone_key=body.zone_key,
        camera_id=body.camera_id,
    )


@app.get("/api/incidents/{incident_id}/timeline")
async def get_incident_timeline(
    incident_id: str,
    limit: int = 3000,
    _: dict[str, Any] = Depends(require_session),
):
    try:
        return get_engine().incident_timeline(incident_id=incident_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/incidents/{incident_id}/events")
async def add_incident_event(
    incident_id: str,
    body: IncidentEventRequest,
    session: dict[str, Any] = Depends(require_session),
):
    operator_id = str(session.get("username", "")).strip() or "unknown"
    details: Dict[str, Any] = {
        "note": body.note.strip(),
        "source": body.source.strip(),
        "unit_id": body.unit_id.strip(),
        "officer_id": body.officer_id.strip(),
    }
    if body.eta_minutes is not None:
        details["eta_minutes"] = int(body.eta_minutes)
    clean_details = {k: v for k, v in details.items() if not (isinstance(v, str) and v == "")}
    try:
        entry = get_engine().add_incident_event(
            incident_id=incident_id,
            event_type=body.event_type,
            operator_id=operator_id,
            details=clean_details,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Incident event recorded", "entry": entry}


@app.get("/api/incidents/{incident_id}/report.pdf")
async def get_incident_report_pdf(
    incident_id: str,
    limit: int = 3000,
    _: dict[str, Any] = Depends(require_session),
):
    try:
        timeline = get_engine().incident_timeline(incident_id=incident_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    pdf_bytes = build_incident_timeline_pdf(timeline)
    safe_name = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in incident_id)
    if not safe_name:
        safe_name = "incident"
    headers = {"Content-Disposition": f'attachment; filename="incident_{safe_name}.pdf"'}
    return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)


@app.websocket("/ws/stream")
async def stream_frames(websocket: WebSocket):
    if websocket_session(websocket) is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    await websocket.accept()
    service = get_engine()
    try:
        while True:
            payload = service.get_frame_payload()
            if payload is not None:
                await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(1 / 30)
    except WebSocketDisconnect:
        logger.info("Stream client disconnected")
    except Exception as exc:
        logger.warning("Stream websocket error: %s", exc)


@app.websocket("/ws/detections")
async def stream_detections(websocket: WebSocket):
    if websocket_session(websocket) is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    await websocket.accept()
    service = get_engine()
    last_seq = -1
    try:
        while True:
            packets = service.detection_packets_since(last_seq=last_seq, limit=100)
            for payload in packets:
                last_seq = max(last_seq, int(payload.get("seq", -1)))
                await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        logger.info("Detection client disconnected")
    except Exception as exc:
        logger.warning("Detection websocket error: %s", exc)


@app.websocket("/ws/alerts")
async def stream_alerts(websocket: WebSocket):
    """Redis-backed alert broadcast channel."""
    await websocket.accept()
    try:
        cache = RedisCache(get_redis())
        pubsub = await cache.subscribe_alerts()
        async for message in pubsub.listen():
            if message and message.get("type") == "message":
                await websocket.send_text(str(message.get("data")))
    except WebSocketDisconnect:
        logger.info("Alert websocket disconnected")
    except Exception as exc:
        logger.error("Alert websocket error: %s", exc)
