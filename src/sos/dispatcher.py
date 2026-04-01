from typing import Any, Callable, Dict, List, Optional

from src.sos.routing import build_route_summary
from src.sos.service_selector import select_services
from src.sos.sms_sender import SmsSender


class SOSDispatcher:
    def __init__(
        self,
        *,
        audit_store,
        sms_sender: SmsSender,
        packet_emitter: Callable[[Dict[str, Any]], None],
        radius_km: float = 10.0,
        fallback_endpoints: Optional[Dict[str, str]] = None,
        service_stale_after_seconds: float = 900.0,
        dispatch_timeout_seconds: float = 20.0,
        pending_retry_seconds: float = 10.0,
        routing_cfg: Optional[Dict[str, Any]] = None,
    ):
        self.audit_store = audit_store
        self.sms_sender = sms_sender
        self.packet_emitter = packet_emitter
        self.radius_km = float(radius_km)
        self.fallback_endpoints = fallback_endpoints or {}
        self.service_stale_after_seconds = float(service_stale_after_seconds)
        self.dispatch_timeout_seconds = float(dispatch_timeout_seconds)
        self.pending_retry_seconds = float(pending_retry_seconds)
        self.routing_cfg = routing_cfg or {}
        self._pending_alerts: List[Dict[str, Any]] = []

    def start(self) -> None:
        self._pending_alerts.clear()

    def stop(self) -> None:
        self._pending_alerts.clear()

    def dispatch(
        self,
        *,
        sos_id: str,
        incident: Dict[str, Any],
        services: List[str],
        reason: str,
        live_link: str,
        control_phone: str,
    ) -> Dict[str, Any]:
        catalog = self.audit_store.list_services(active_only=True)
        filtered = [svc for svc in catalog if str(svc.get("type", "")).lower() in {s.lower() for s in services}]
        if incident.get("lat") is None or incident.get("lng") is None:
            return {"status": "failed", "error": "Incident location missing", "selected_services": []}
        selected = select_services(
            filtered,
            incident_lat=incident["lat"],
            incident_lng=incident["lng"],
            radius_km=self.radius_km,
            incident_ts=str(incident.get("created_at") or ""),
            routing_cfg=self.routing_cfg,
        )
        message = self._build_message(incident=incident, reason=reason, live_link=live_link, control_phone=control_phone)
        deliveries: List[Dict[str, Any]] = []
        for svc in selected:
            result = self.sms_sender.send_sms(svc.get("phone"), message)
            result["service_id"] = svc.get("id")
            deliveries.append(result)
        route_summary = build_route_summary(selected)

        packet = {
            "type": "sos",
            "sos_id": sos_id,
            "incident_id": incident.get("incident_id"),
            "services": [svc.get("type") for svc in selected],
            "route_summary": route_summary,
            "status": "sent" if deliveries else "failed",
            "simulation_mode": self.sms_sender.simulation,
        }
        self.packet_emitter("sos", packet)
        return {
            "status": packet["status"],
            "selected_services": selected,
            "deliveries": deliveries,
            "route_summary": route_summary,
            "warning": None if selected else "No services within radius",
        }

    @staticmethod
    def _build_message(*, incident: Dict[str, Any], reason: str, live_link: str, control_phone: str) -> str:
        severity = incident.get("severity") or "UNKNOWN"
        zone = incident.get("zone_key") or "zone"
        ts = incident.get("created_at")
        incident_id = incident.get("incident_id")
        top = incident.get("top_weapon") or "Threat"
        live = live_link or "/"
        control = control_phone or "N/A"
        return (
            "🚨 EMERGENCY ALERT\n"
            f"Type: {top}\n"
            f"Severity: {severity}\n"
            f"Location: {zone}\n"
            f"Time: {ts}\n"
            f"Incident: {incident_id}\n"
            f"Reason: {reason}\n"
            f"Live: {live}\n"
            f"Control: {control}"
        )


__all__ = ["SOSDispatcher"]
