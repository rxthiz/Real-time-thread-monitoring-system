from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple


def _parse_iso(ts: str) -> datetime:
    token = str(ts or "").strip()
    if not token:
        return datetime.now(timezone.utc)
    if token.endswith("Z"):
        token = token[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(token)
    except ValueError:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def traffic_multiplier(*, incident_ts: str = "", profile: str = "city") -> float:
    hour = _parse_iso(incident_ts).hour
    token = str(profile or "city").strip().lower()
    if token not in {"city", "urban", "metro"}:
        return 1.0
    if 7 <= hour <= 10:
        return 1.35
    if 17 <= hour <= 21:
        return 1.45
    if 22 <= hour or hour <= 5:
        return 0.9
    return 1.1


def base_speed_kmph(service_type: str, routing_cfg: Dict[str, Any]) -> float:
    raw = routing_cfg.get("base_speed_kmph", {}) if isinstance(routing_cfg.get("base_speed_kmph", {}), dict) else {}
    defaults = {"police": 50.0, "hospital": 42.0, "fire": 45.0}
    token = str(service_type or "").strip().lower()
    speed = float(raw.get(token, defaults.get(token, 40.0)))
    return max(10.0, speed)


def estimate_eta_minutes(
    *,
    distance_km: float,
    service_type: str,
    incident_ts: str = "",
    routing_cfg: Dict[str, Any] | None = None,
) -> Tuple[float, float, float]:
    cfg = routing_cfg or {}
    profile = str(cfg.get("traffic_profile", "city")).strip().lower() or "city"
    road_factor = max(0.7, min(2.0, float(cfg.get("road_network_factor", 1.12))))
    t_mult = traffic_multiplier(incident_ts=incident_ts, profile=profile)
    speed = base_speed_kmph(service_type, cfg)
    effective_speed = max(5.0, speed / max(0.1, t_mult * road_factor))
    eta = max(1.0, (max(0.0, float(distance_km)) / effective_speed) * 60.0)
    return round(eta, 2), round(effective_speed, 2), round(t_mult, 3)


def routing_priority_score(*, priority: int, eta_minutes: float, distance_km: float) -> float:
    p = max(1, int(priority or 1))
    eta = max(0.1, float(eta_minutes or 0.1))
    distance = max(0.0, float(distance_km or 0.0))
    score = (p * 0.5) + (1.0 / (1.0 + eta)) + (1.0 / (1.0 + distance))
    return round(score, 4)


def build_route_summary(selected_services: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not selected_services:
        return {
            "count": 0,
            "avg_eta_minutes": 0.0,
            "min_eta_minutes": 0.0,
            "max_eta_minutes": 0.0,
        }
    etas = [float(item.get("eta_minutes", 0.0) or 0.0) for item in selected_services]
    etas = [value for value in etas if value > 0.0] or [0.0]
    return {
        "count": len(selected_services),
        "avg_eta_minutes": round(sum(etas) / len(etas), 2),
        "min_eta_minutes": round(min(etas), 2),
        "max_eta_minutes": round(max(etas), 2),
    }
