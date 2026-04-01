from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .session import Base


def utcnow() -> datetime:
    return datetime.utcnow()


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class Alert(TimestampMixin, Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    track_id: Mapped[Optional[int]] = mapped_column(ForeignKey("tracks.id"), nullable=True)
    zone: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="new", nullable=False)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    track: Mapped["Track"] = relationship(back_populates="alerts")
    incident_links: Mapped[list["Incident"]] = relationship(
        secondary="incident_alerts", back_populates="alerts"
    )


class Track(TimestampMixin, Base):
    __tablename__ = "tracks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    track_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    behavior_profile: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    alerts: Mapped[list[Alert]] = relationship(back_populates="track")


class Incident(TimestampMixin, Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    escalation_level: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    alerts: Mapped[list[Alert]] = relationship(
        secondary="incident_alerts", back_populates="incident_links"
    )


class AuditLog(TimestampMixin, Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    meta: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)


class IncidentAlert(Base):
    """Join table between incidents and alerts."""

    __tablename__ = "incident_alerts"

    incident_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("incidents.id"), primary_key=True
    )
    alert_id: Mapped[int] = mapped_column(Integer, ForeignKey("alerts.id"), primary_key=True)
