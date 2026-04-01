import uuid
from typing import Any, Dict, Optional, Tuple

from src.sos.geo_utils import validate_lat_lon


class IncidentManager:
    def __init__(self, audit_store, *, zone_locations: Optional[Dict[str, Dict[str, float]]] = None):
        self.audit_store = audit_store
        self.zone_locations = zone_locations or {}

    def get_or_create_incident(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        alert_id = str(alert.get("alert_id", "")).strip()
        zone_key = str(alert.get("zone_key", "")).strip() or "zone:default"
        existing = self.audit_store.incident_by_alert(alert_id) if alert_id else None
        if existing is not None:
            return existing
        payload = {
            "incident_id": f"INC-{uuid.uuid4().hex[:12].upper()}",
            "alert_id": alert_id or None,
            "zone_key": zone_key,
            "status": "active",
            "severity": alert.get("severity"),
            "confidence": alert.get("confidence") or (alert.get("event") or {}).get("score"),
        }
        location, _ = self.resolve_incident_location(payload)
        if location is not None:
            payload["lat"], payload["lng"] = location
        return self.audit_store.create_incident(payload)

    def resolve_incident_location(self, incident: Dict[str, Any]) -> Tuple[Optional[Tuple[float, float]], Optional[str]]:
        if incident.get("lat") is not None and incident.get("lng") is not None:
            try:
                lat, lng = validate_lat_lon(float(incident["lat"]), float(incident["lng"]))
                return (lat, lng), None
            except Exception as exc:
                return None, str(exc)

        zone_key = str(incident.get("zone_key") or "").strip()
        zone_loc = self.zone_locations.get(zone_key) or self.zone_locations.get(zone_key.lower())
        if zone_loc and "lat" in zone_loc and "lng" in zone_loc:
            try:
                lat, lng = validate_lat_lon(float(zone_loc["lat"]), float(zone_loc["lng"]))
                return (lat, lng), None
            except Exception as exc:
                return None, str(exc)
        return None, f"Missing zone location for {zone_key or 'unknown zone'}"


__all__ = ["IncidentManager"]
