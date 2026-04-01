from typing import Any, Callable, Dict


class EscalationManager:
    def __init__(
        self,
        *,
        start_callback: Callable[..., Dict[str, Any]],
        acknowledge_callback: Callable[..., Dict[str, Any]],
        status_callback: Callable[..., Dict[str, Any]],
    ):
        self._start_callback = start_callback
        self._acknowledge_callback = acknowledge_callback
        self._status_callback = status_callback

    def start_escalation(self, *, incident_id: str, operator_id: str, source: str, note: str, reason: str) -> Dict[str, Any]:
        return self._start_callback(
            incident_id=incident_id,
            operator_id=operator_id,
            source=source,
            note=note,
            reason=reason,
        )

    def acknowledge(self, *, incident_id: str, operator_id: str, note: str, resolution: str = "ACKNOWLEDGED") -> Dict[str, Any]:
        return self._acknowledge_callback(
            incident_id=incident_id,
            operator_id=operator_id,
            note=note,
            resolution=resolution,
        )

    def status(self, incident_id: str) -> Dict[str, Any]:
        return self._status_callback(incident_id)
