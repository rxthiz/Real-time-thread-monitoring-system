from datetime import datetime, timezone
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field, condecimal, conint, constr


class AlertIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    severity: constr(strip_whitespace=True, min_length=1) = "LOW"
    type: constr(strip_whitespace=True, min_length=1) = "THREAT"
    confidence: condecimal(ge=0, le=1) = 0
    track_id: Optional[str] = None
    zone: constr(strip_whitespace=True, min_length=1) = "zone:default"
    status: constr(strip_whitespace=True, min_length=1) = "queued"
    payload: Dict[str, Any] = Field(default_factory=dict)


class QueuedAlert(BaseModel):
    """
    Versioned queue envelope.

    Canonical format:
    {
      "schema_version": "1.0",
      "alert_id": "...",
      "data": {...}
    }
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    schema_version: constr(strip_whitespace=True, min_length=1) = "1.0"
    alert_id: constr(strip_whitespace=True, min_length=1)
    retry_count: conint(ge=0) = 0
    data: Dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_alert_in(cls, alert_id: str, body: AlertIn) -> "QueuedAlert":
        if hasattr(body, "model_dump"):
            body_data = body.model_dump()  # type: ignore[attr-defined]
        else:
            body_data = body.dict()

        # Payload body for schema v1.0
        body_data["status"] = "queued"
        body_data["ingested_at"] = datetime.now(timezone.utc).isoformat()

        return cls(
            schema_version="1.0",
            alert_id=alert_id,
            retry_count=0,
            data=body_data,
        )


class DeadLetterAlert(BaseModel):
    """DLQ payload for exhausted retries."""

    model_config = ConfigDict(str_strip_whitespace=True)

    alert_id: constr(strip_whitespace=True, min_length=1)
    original_payload: Dict[str, Any]
    error_message: constr(strip_whitespace=True, min_length=1)
    retry_count: conint(ge=0)
    timestamp: datetime
