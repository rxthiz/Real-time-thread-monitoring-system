from typing import Dict, Optional


class AutoSOSTrigger:
    def __init__(self, *, min_confidence: float = 0.85, required_severity: str = "CRITICAL", cooldown_seconds: float = 60.0):
        self.min_confidence = float(min_confidence)
        self.required_severity = str(required_severity or "CRITICAL").upper()
        self.cooldown_seconds = float(cooldown_seconds)

    def should_trigger(
        self,
        alert_payload: Dict,
        *,
        now_ts: float,
        min_confidence_override: Optional[float] = None,
    ) -> bool:
        severity = str(alert_payload.get("severity") or "").upper()
        if severity != self.required_severity:
            return False
        confidence = float(alert_payload.get("event", {}).get("score", 0.0) or alert_payload.get("confidence", 0.0))
        threshold = float(min_confidence_override) if min_confidence_override is not None else self.min_confidence
        return confidence >= threshold


__all__ = ["AutoSOSTrigger"]
