from typing import Dict


def normalize_requested_services(body: Dict) -> Dict:
    services = [str(s).strip().lower() for s in body.get("services", []) if str(s).strip()]
    if not services:
        raise ValueError("At least one service type is required")
    payload = {
        "incident_id": str(body.get("incident_id") or "").strip(),
        "zone_key": str(body.get("zone_key") or "").strip(),
        "services": services,
        "reason": str(body.get("reason") or "Manual SOS").strip(),
    }
    return payload


__all__ = ["normalize_requested_services"]
