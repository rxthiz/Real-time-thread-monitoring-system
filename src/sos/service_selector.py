from typing import Dict, List, Tuple

from src.sos.geo_utils import haversine_km
from src.sos.routing import estimate_eta_minutes, routing_priority_score


def _limit_by_type(service_type: str) -> int:
    token = service_type.lower()
    if token == "police":
        return 2
    if token == "hospital":
        return 3
    if token == "fire":
        return 1
    return 1


def select_services(
    services: List[Dict],
    *,
    incident_lat: float,
    incident_lng: float,
    radius_km: float = 10.0,
    incident_ts: str = "",
    routing_cfg: Dict[str, float] | None = None,
) -> List[Dict]:
    """Filter to active services within radius and choose nearest by type/priority."""
    chosen: List[Dict] = []
    per_type: Dict[str, List[Tuple[float, Dict]]] = {}
    for svc in services:
        if not bool(svc.get("is_active", True)):
            continue
        svc_type = str(svc.get("type", "")).lower()
        distance = haversine_km(incident_lat, incident_lng, float(svc.get("lat")), float(svc.get("lng")))
        if distance > radius_km:
            continue
        record = dict(svc)
        record["distance_km"] = round(distance, 3)
        eta_minutes, effective_speed_kmph, traffic_mult = estimate_eta_minutes(
            distance_km=distance,
            service_type=svc_type,
            incident_ts=incident_ts,
            routing_cfg=routing_cfg or {},
        )
        record["eta_minutes"] = eta_minutes
        record["effective_speed_kmph"] = effective_speed_kmph
        record["traffic_multiplier"] = traffic_mult
        record["routing_score"] = routing_priority_score(
            priority=int(record.get("priority", 1) or 1),
            eta_minutes=eta_minutes,
            distance_km=distance,
        )
        per_type.setdefault(svc_type, []).append((distance, record))

    for svc_type, items in per_type.items():
        items.sort(
            key=lambda pair: (
                float(pair[1].get("eta_minutes", 0.0)),
                -int(pair[1].get("priority", 1)),
                pair[0],
            )
        )
        limit = _limit_by_type(svc_type)
        chosen.extend([item[1] for item in items[:limit]])

    chosen.sort(key=lambda item: (float(item.get("eta_minutes", 0.0)), str(item.get("type"))))
    return chosen
