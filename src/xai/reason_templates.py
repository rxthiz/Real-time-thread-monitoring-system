from typing import Optional


def confidence_band(value: float) -> str:
    score = float(value)
    if score >= 0.9:
        return "very high"
    if score >= 0.75:
        return "high"
    if score >= 0.5:
        return "moderate"
    return "low"


def _humanize(token: str) -> str:
    return str(token or "").strip().replace("_", " ").replace("-", " ")


def weapon_reason(label: str, confidence: float) -> str:
    safe_label = _humanize(label) or "weapon"
    band = confidence_band(confidence)
    if safe_label.lower() == "gun":
        return f"Gun detected with {band} confidence"
    if safe_label.lower() == "knife":
        return f"Knife detected with {band} confidence"
    return f"{safe_label.title()} detected with {band} confidence"


def action_reason(label: str, confidence: float) -> Optional[str]:
    safe_label = _humanize(label).lower()
    if not safe_label or safe_label == "unknown":
        return None
    if any(token in safe_label for token in ("aggressive", "fight", "attack", "threat", "brandish")):
        return "Aggressive behavior detected"
    if any(token in safe_label for token in ("running", "sprint", "chase")):
        return "Rapid motion detected"
    if any(token in safe_label for token in ("fall", "collapse")):
        return "Fall or collapse behavior detected"
    return f"{safe_label.title()} behavior detected with {confidence_band(confidence)} confidence"


def persistence_reason(count: int) -> Optional[str]:
    repeat_count = max(0, int(count))
    if repeat_count >= 4:
        return "Persistent threat observed across recent frames"
    if repeat_count >= 2:
        return "Repeated threat detections observed"
    return None


def combine_reasons(*parts: Optional[str]) -> str:
    clean = [str(part).strip() for part in parts if str(part or "").strip()]
    if not clean:
        return "Threat conditions met"
    if len(clean) == 1:
        return clean[0]
    rest = [item[:1].lower() + item[1:] if item else item for item in clean[1:]]
    if len(clean) == 2:
        return f"{clean[0]} and {rest[0]}"
    return ", ".join([clean[0], *rest[:-1]]) + f", and {rest[-1]}"


def summarize_alert(reason: str, severity: str, zone_key: str = "") -> str:
    safe_reason = str(reason or "Threat conditions met").strip()
    safe_severity = str(severity or "LOW").strip().upper() or "LOW"
    safe_zone = str(zone_key or "").strip()
    if safe_zone:
        return f"{safe_severity.title()} risk alert triggered in {safe_zone} due to {safe_reason.lower()}."
    return f"{safe_severity.title()} risk alert triggered due to {safe_reason.lower()}."
