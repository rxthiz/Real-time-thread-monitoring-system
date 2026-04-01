import base64
import json
import logging
import os
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event, Lock, Thread
from time import monotonic, sleep
from typing import Any, Deque, Dict, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request

import cv2
import numpy as np

from src.alerts.notifier import AlertNotifier
from src.alerts.audit_store import AlertAuditStore
from src.correlation.reid_correlator import ReIDCorrelator
from src.evidence.clip_recorder import ClipRecorder
from src.filters.false_positive_filter import FalsePositiveFilter
from src.fusion.rule_engine import RuleBasedFusion
from src.models.action_recognizer import ActionRecognizer
from src.models.weapon_detector import WeaponDetector
from src.predictive.behavior_analyzer import BehaviorAnalyzer
from src.predictive.profile_memory import TrackProfileStore
from src.sos.auto_trigger import AutoSOSTrigger
from src.sos.dispatcher import SOSDispatcher
from src.sos.escalation_manager import EscalationManager
from src.sos.incident_manager import IncidentManager
from src.sos.manual_trigger import normalize_requested_services
from src.sos.sms_sender import SmsSender
from src.utils.types import ActionPrediction, SeverityEvent, WeaponDetection

logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parent.parent


class RealtimeThreatEngine:
    ALLOWED_DISPOSITIONS = {"ACKNOWLEDGED", "ESCALATED", "DISMISSED"}
    ALLOWED_INCIDENT_EVENT_TYPES = {
        "SOS_TRIGGERED",
        "POLICE_DISPATCHED",
        "OFFICER_DISPATCHED",
        "OFFICER_ARRIVED",
        "SCENE_CLEARED",
        "MANUAL_NOTE",
    }
    ALLOWED_ESCALATION_CHANNELS = {"webhook", "sms", "push"}
    WEEKDAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    LIVE_ZONE_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        edge_cfg = cfg.get("edge", {}) if isinstance(cfg.get("edge", {}), dict) else {}
        self.edge_enabled = bool(edge_cfg.get("enabled", False))
        self.edge_max_fps = max(0.0, float(edge_cfg.get("max_fps", 0.0)))
        self.edge_input_scale = float(edge_cfg.get("input_scale", 1.0))
        self.edge_input_scale = max(0.25, min(1.0, self.edge_input_scale))
        self.edge_prefer_cpu = bool(edge_cfg.get("prefer_cpu", True))
        if self.edge_enabled and self.edge_prefer_cpu:
            weapon_cfg = cfg.get("weapon", {}) if isinstance(cfg.get("weapon", {}), dict) else {}
            weapon_cfg["device"] = "cpu"
            cfg["weapon"] = weapon_cfg
        self.detector = WeaponDetector(cfg)
        self.fusion = RuleBasedFusion(cfg)
        self.notifier = AlertNotifier(cfg)
        audit_db_path = os.getenv("THREAT_AUDIT_DB_PATH", "data/alert_audit.db")
        self.audit_store = AlertAuditStore(db_path=audit_db_path)
        self.reid_correlator = ReIDCorrelator(cfg)
        self.predictive_analyzer = BehaviorAnalyzer(cfg)
        self.track_profile_store = TrackProfileStore(db_path=audit_db_path, cfg=cfg)
        self.false_positive_filter = FalsePositiveFilter(cfg, db_path=audit_db_path)

        evidence_cfg = cfg.get("evidence", {})
        self.evidence_enabled = bool(evidence_cfg.get("enabled", True))
        self.evidence_pre_event_seconds = max(0.0, float(evidence_cfg.get("pre_event_seconds", 10.0)))
        self.evidence_post_event_seconds = max(0.0, float(evidence_cfg.get("post_event_seconds", 10.0)))
        self.evidence_dir = str(evidence_cfg.get("output_dir", "data/evidence")).strip() or "data/evidence"
        self.evidence_watermark_timestamp = bool(evidence_cfg.get("watermark_timestamp", True))
        self._capture_fps = 0.0
        self.clip_recorder: Optional[ClipRecorder] = None
        if self.evidence_enabled:
            self.clip_recorder = self._create_clip_recorder()

        xai_cfg = cfg.get("xai", {})
        self.xai_enabled = bool(xai_cfg.get("enabled", True))
        self.xai_persistence_window_seconds = max(5, int(xai_cfg.get("persistence_window_seconds", 20)))
        self.xai_persistent_detection_threshold = max(2, int(xai_cfg.get("persistent_detection_threshold", 3)))

        adaptive_cfg = cfg.get("adaptive_alerting", {})
        weapon_cfg = cfg.get("weapon", {})
        self.adaptive_enabled = bool(adaptive_cfg.get("enabled", True))
        self.zone_base_threshold = float(
            adaptive_cfg.get("base_confidence_threshold", weapon_cfg.get("confidence_threshold", 0.12))
        )
        self.zone_min_threshold = float(
            adaptive_cfg.get("min_confidence_threshold", self.zone_base_threshold)
        )
        self.zone_max_threshold = float(adaptive_cfg.get("max_confidence_threshold", 0.95))
        if self.zone_min_threshold > self.zone_max_threshold:
            self.zone_min_threshold, self.zone_max_threshold = self.zone_max_threshold, self.zone_min_threshold
        self.zone_tune_step = float(adaptive_cfg.get("threshold_step", 0.05))
        self.dismiss_trigger_count = int(adaptive_cfg.get("dismiss_trigger_count", 10))
        self.zone_snooze_minutes = int(adaptive_cfg.get("snooze_minutes", 30))
        self.policy_cache_ttl_seconds = max(1.0, float(adaptive_cfg.get("policy_cache_ttl_seconds", 10.0)))
        self.live_status_window_seconds = max(60, int(os.getenv("THREAT_LIVE_STATUS_WINDOW_SECONDS", "900")))
        self.critical_alert_count_threshold = max(
            2,
            int(os.getenv("THREAT_CRITICAL_ALERT_COUNT_THRESHOLD", "3")),
        )
        self._zone_policy_cache: Dict[tuple[str, int], Dict[str, Any]] = {}
        self._zone_policy_cache_expiry: Dict[tuple[str, int], float] = {}

        action_cfg = cfg.get("action", {})
        self.action_enabled = bool(action_cfg.get("enabled", True))
        self.action_infer_every = int(action_cfg.get("infer_every_n_processed_frames", 12))
        self.action_frame_interval = int(action_cfg.get("frame_interval", 2))
        self.action_recognizer: Optional[ActionRecognizer] = None
        if self.action_enabled:
            try:
                self.action_recognizer = ActionRecognizer(cfg)
            except Exception as exc:
                logger.warning("Action recognizer unavailable, disabling action inference: %s", exc)
                self.action_enabled = False

        pipeline_cfg = cfg.get("pipeline", {})
        self.process_every = max(1, int(pipeline_cfg.get("process_every_n_frames", 2)))
        self.min_alert_gap = float(pipeline_cfg.get("min_alert_gap_seconds", 2.0))

        clip_len = int(action_cfg.get("clip_len", 16))
        self.clip_buffer: Deque[np.ndarray] = deque(maxlen=clip_len)

        self.max_history = 1000
        self._alerts: Deque[Dict[str, Any]] = deque(maxlen=self.max_history)
        self._detections: Deque[Dict[str, Any]] = deque(maxlen=self.max_history)
        self._ws_packets: Deque[Dict[str, Any]] = deque(maxlen=self.max_history * 4)
        self._latest_detection: Optional[Dict[str, Any]] = None

        self._capture = None
        self._default_source = self._resolve_source()
        self._capture_source = self._default_source
        self._source_name = self._source_label(self._capture_source)
        self._loop_video = bool(int(os.getenv("THREAT_LOOP_VIDEO", "1")))

        self._running = False
        self._thread: Optional[Thread] = None
        self._stop_event = Event()
        self._lock = Lock()

        self._latest_frame: Optional[np.ndarray] = None
        self._latest_annotated: Optional[np.ndarray] = None
        self._frame_id = 0
        self._detection_seq = 0
        self._last_alert_at = 0.0
        self._resolution = {"width": 0, "height": 0}

        self._live_fps = 0.0
        self._last_frame_tick = 0.0

        escalation_cfg = cfg.get("escalation", {})
        delivery_cfg = escalation_cfg.get("delivery", {})
        self.escalation_enabled = bool(escalation_cfg.get("enabled", True))
        self.escalation_auto_start_on_sos = bool(escalation_cfg.get("auto_start_on_sos", True))
        self.escalation_poll_interval_seconds = max(
            0.5, float(escalation_cfg.get("poll_interval_seconds", 1.0))
        )
        self.escalation_delivery_timeout_seconds = max(
            0.5,
            float(delivery_cfg.get("timeout_seconds", 4.0)),
        )
        self.escalation_delivery_endpoints = {
            "webhook": str(
                delivery_cfg.get("webhook_url")
                or os.getenv("THREAT_ESCALATION_WEBHOOK_URL", "")
            ).strip(),
            "sms": str(
                delivery_cfg.get("sms_webhook_url")
                or os.getenv("THREAT_ESCALATION_SMS_WEBHOOK_URL", "")
            ).strip(),
            "push": str(
                delivery_cfg.get("push_webhook_url")
                or os.getenv("THREAT_ESCALATION_PUSH_WEBHOOK_URL", "")
            ).strip(),
        }
        self._escalation_lock = Lock()
        self._active_escalations: Dict[str, Dict[str, Any]] = {}
        self._escalation_stop_event = Event()
        self._escalation_thread: Optional[Thread] = None

        sos_cfg = cfg.get("sos", {})
        sms_cfg = sos_cfg.get("sms", {})
        self.sos_zone_locations = sos_cfg.get("zone_locations", {}) if isinstance(sos_cfg.get("zone_locations", {}), dict) else {}
        self.sos_live_link = str(
            sos_cfg.get("live_link")
            or os.getenv("THREAT_SOS_LIVE_LINK", "http://localhost:8000/zone-map-dashboard")
        ).strip()
        self.sos_control_phone = str(
            sos_cfg.get("control_phone")
            or os.getenv("THREAT_SOS_CONTROL_PHONE", "+910000000000")
        ).strip()
        self.sos_simulation_mode = bool(int(os.getenv("THREAT_SMS_SIMULATION_MODE", "1")))
        if "simulation_mode" in sms_cfg:
            self.sos_simulation_mode = bool(sms_cfg.get("simulation_mode"))
        self.sos_dispatch_radius_km = float(sos_cfg.get("radius_km", 10.0))
        self.sos_retry_limit = max(1, int(sos_cfg.get("retry_limit", 3)))
        self.sos_zone_auto_thresholds = sos_cfg.get("zone_auto_thresholds", {}) if isinstance(sos_cfg.get("zone_auto_thresholds", {}), dict) else {}
        self.sos_service_stale_after_seconds = max(60, int(sos_cfg.get("service_stale_after_seconds", 900)))
        self.sos_global_alert_limit_per_minute = max(1, int(sos_cfg.get("global_alert_limit_per_minute", 120)))
        self.sos_global_pause_seconds = max(1, int(sos_cfg.get("global_pause_seconds", 30)))
        self.sos_zone_alert_limit_per_minute = max(1, int(sos_cfg.get("zone_alert_limit_per_minute", 10)))
        self.sos_duplicate_window_seconds = max(1, int(sos_cfg.get("duplicate_window_seconds", 60)))
        raw_routing_cfg = sos_cfg.get("routing", {}) if isinstance(sos_cfg.get("routing", {}), dict) else {}
        self.sos_routing_cfg = {
            "traffic_profile": str(raw_routing_cfg.get("traffic_profile", "city")).strip().lower() or "city",
            "road_network_factor": float(raw_routing_cfg.get("road_network_factor", 1.12)),
            "base_speed_kmph": raw_routing_cfg.get("base_speed_kmph", {})
            if isinstance(raw_routing_cfg.get("base_speed_kmph", {}), dict)
            else {},
        }
        self.sms_sender = SmsSender(
            simulation_mode=self.sos_simulation_mode,
            provider=str(
                sms_cfg.get("provider")
                or os.getenv("THREAT_SMS_PROVIDER", "webhook")
            ).strip().lower(),
            webhook_url=str(
                sms_cfg.get("webhook_url")
                or os.getenv("THREAT_SMS_WEBHOOK_URL", self.escalation_delivery_endpoints.get("sms", ""))
            ).strip(),
            timeout_seconds=float(sms_cfg.get("timeout_seconds", 5.0)),
            max_retries=int(sms_cfg.get("max_retries", 3)),
            retry_delay_seconds=float(sms_cfg.get("retry_delay_seconds", 2.0)),
            twilio_account_sid=str(
                sms_cfg.get("twilio_account_sid")
                or os.getenv("THREAT_TWILIO_ACCOUNT_SID", "")
            ).strip(),
            twilio_auth_token=str(
                sms_cfg.get("twilio_auth_token")
                or os.getenv("THREAT_TWILIO_AUTH_TOKEN", "")
            ).strip(),
            twilio_from_number=str(
                sms_cfg.get("twilio_from_number")
                or os.getenv("THREAT_TWILIO_FROM_NUMBER", "")
            ).strip(),
            twilio_messaging_service_sid=str(
                sms_cfg.get("twilio_messaging_service_sid")
                or os.getenv("THREAT_TWILIO_MESSAGING_SERVICE_SID", "")
            ).strip(),
        )
        self.incident_manager = IncidentManager(self.audit_store, zone_locations=self.sos_zone_locations)
        self.sos_dispatcher = SOSDispatcher(
            audit_store=self.audit_store,
            sms_sender=self.sms_sender,
            packet_emitter=self._emit_system_event,
            radius_km=self.sos_dispatch_radius_km,
            fallback_endpoints={
                "email": str(sos_cfg.get("email_webhook_url") or os.getenv("THREAT_EMAIL_WEBHOOK_URL", "")).strip(),
                "push": str(sos_cfg.get("push_webhook_url") or self.escalation_delivery_endpoints.get("push", "")).strip(),
                "webhook": str(sos_cfg.get("webhook_url") or self.escalation_delivery_endpoints.get("webhook", "")).strip(),
            },
            service_stale_after_seconds=self.sos_service_stale_after_seconds,
            dispatch_timeout_seconds=float(sos_cfg.get("dispatch_timeout_seconds", 20.0)),
            pending_retry_seconds=float(sos_cfg.get("pending_retry_seconds", 10.0)),
            routing_cfg=self.sos_routing_cfg,
        )
        self.sos_auto_trigger = AutoSOSTrigger(
            min_confidence=float(sos_cfg.get("auto_min_confidence", 0.85)),
            required_severity=str(sos_cfg.get("auto_required_severity", "CRITICAL")),
            cooldown_seconds=int(sos_cfg.get("zone_cooldown_seconds", 60)),
        )
        self.sos_escalation_manager = EscalationManager(
            start_callback=self.start_incident_escalation,
            acknowledge_callback=self.acknowledge_incident_escalation,
            status_callback=self.incident_escalation_status,
        )
        self._recent_alert_key_ticks: Dict[str, float] = {}
        self._zone_alert_ticks: Dict[str, Deque[float]] = {}
        self._global_alert_ticks: Deque[float] = deque()
        self._global_alert_pause_until_tick = 0.0
        behavior_memory_cfg = cfg.get("behavior_memory", {}) if isinstance(cfg.get("behavior_memory", {}), dict) else {}
        self.behavior_alert_escalation_threshold = float(
            behavior_memory_cfg.get("alert_escalation_threshold", 0.82)
        )

    @staticmethod
    def _iso_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _resolve_source() -> int | str:
        mode = os.getenv("THREAT_SOURCE", "auto").strip().lower()
        raw_video_path = os.getenv("THREAT_VIDEO_PATH", "data/sample.mp4")
        if mode == "camera":
            return int(os.getenv("THREAT_CAMERA_INDEX", "0"))

        if mode == "video":
            return RealtimeThreatEngine._normalize_video_source(raw_video_path)

        # Auto mode: prefer sample video for reproducible local demos, then fallback to webcam.
        fallback_video = RealtimeThreatEngine._find_existing_video_source(raw_video_path)
        if fallback_video is not None:
            return fallback_video
        return int(os.getenv("THREAT_CAMERA_INDEX", "0"))

    @staticmethod
    def _is_stream_source(value: str) -> bool:
        return "://" in value

    @staticmethod
    def _video_candidates(video_path: str) -> list[Path]:
        path = Path(video_path).expanduser()
        if path.is_absolute():
            return [path]
        return [Path.cwd() / path, PROJECT_ROOT / path]

    @staticmethod
    def _find_existing_video_source(video_path: str) -> Optional[str]:
        if RealtimeThreatEngine._is_stream_source(video_path):
            return video_path

        seen: set[str] = set()
        for candidate in RealtimeThreatEngine._video_candidates(video_path):
            resolved = candidate.resolve()
            key = str(resolved)
            if key in seen:
                continue
            seen.add(key)
            if resolved.exists():
                return key
        return None

    @staticmethod
    def _normalize_video_source(video_path: str) -> str:
        if RealtimeThreatEngine._is_stream_source(video_path):
            return video_path

        existing = RealtimeThreatEngine._find_existing_video_source(video_path)
        if existing is not None:
            return existing

        path = Path(video_path).expanduser()
        if path.is_absolute():
            return str(path)
        return str((PROJECT_ROOT / path).resolve())

    def _create_clip_recorder(self) -> ClipRecorder:
        return ClipRecorder(
            evidence_dir=self.evidence_dir,
            pre_event_seconds=self.evidence_pre_event_seconds,
            post_event_seconds=self.evidence_post_event_seconds,
            default_fps=20.0,
            watermark_timestamp=self.evidence_watermark_timestamp,
            on_complete=self._on_evidence_clip_complete,
        )

    def _run_process_loop_guarded(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._process_loop()
                break
            except Exception as exc:
                self._log_error("PROCESS_LOOP_FAILURE", str(exc))
                sleep(0.1)

    def _run_escalation_loop_guarded(self) -> None:
        while not self._escalation_stop_event.is_set():
            try:
                self._escalation_loop()
                break
            except Exception as exc:
                self._log_error("ESCALATION_LOOP_FAILURE", str(exc))
                sleep(0.1)

    def start(self) -> None:
        if self._running:
            return

        if self.evidence_enabled and (self.clip_recorder is None or not self.clip_recorder.is_running()):
            self.clip_recorder = self._create_clip_recorder()

        self._capture = cv2.VideoCapture(self._capture_source)
        if not self._capture.isOpened():
            raise RuntimeError(f"Unable to open capture source: {self._capture_source}")

        self._capture_fps = float(self._capture.get(cv2.CAP_PROP_FPS) or 0.0)
        self._resolution = {
            "width": int(self._capture.get(cv2.CAP_PROP_FRAME_WIDTH) or 0),
            "height": int(self._capture.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0),
        }
        if self.clip_recorder is not None:
            self.clip_recorder.update_stream(
                fps=self._capture_fps,
                width=self._resolution["width"],
                height=self._resolution["height"],
            )

        self._running = True
        self._stop_event.clear()
        self._escalation_stop_event.clear()
        self._thread = Thread(target=self._run_process_loop_guarded, daemon=True, name="threat-engine-worker")
        self._thread.start()
        self.sos_dispatcher.start()
        if self.escalation_enabled:
            self._escalation_thread = Thread(
                target=self._run_escalation_loop_guarded,
                daemon=True,
                name="escalation-worker",
            )
            self._escalation_thread.start()
        logger.info("Realtime threat engine started with source=%s", self._capture_source)

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        self._escalation_stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        if self._escalation_thread is not None:
            self._escalation_thread.join(timeout=2.0)
            self._escalation_thread = None

        if self._capture is not None:
            self._capture.release()
            self._capture = None
        if self.clip_recorder is not None:
            self.clip_recorder.stop()
        self.sos_dispatcher.stop()
        logger.info("Realtime threat engine stopped")

    def is_running(self) -> bool:
        return self._running

    def status(self) -> Dict[str, Any]:
        with self._escalation_lock:
            active_escalations = len(self._active_escalations)
        try:
            active_services = len(self.audit_store.list_services(active_only=True))
        except Exception:
            active_services = 0
        return {
            "camera_active": self.is_running(),
            "source": self._source_name,
            "fps": round(self._live_fps, 2),
            "resolution": self._resolution,
            "action_enabled": self.action_enabled,
            "adaptive_alerting": {
                "enabled": self.adaptive_enabled,
                "base_threshold": round(self.zone_base_threshold, 4),
            },
            "escalation": {
                "enabled": self.escalation_enabled,
                "active_incidents": active_escalations,
            },
            "sos": {
                "simulation_mode": self.sos_simulation_mode,
                "provider": self.sms_sender.provider,
                "dispatch_radius_km": self.sos_dispatch_radius_km,
                "routing_profile": self.sos_routing_cfg.get("traffic_profile"),
                "retry_limit": self.sos_retry_limit,
                "active_services": active_services,
                "pending_queue": len(self.sos_dispatcher._pending_alerts),
            },
            "reid": self.reid_correlator.stats(),
            "predictive": {
                "enabled": self.predictive_analyzer.enabled,
                "high_risk_threshold": round(float(self.predictive_analyzer.high_risk_threshold), 4),
                "pre_alert_threshold": round(float(self.predictive_analyzer.pre_alert_threshold), 4),
            },
            "evidence": {
                "enabled": self.evidence_enabled,
                "pre_event_seconds": round(self.evidence_pre_event_seconds, 3),
                "post_event_seconds": round(self.evidence_post_event_seconds, 3),
                "output_dir": self.evidence_dir,
            },
            "edge": {
                "enabled": self.edge_enabled,
                "max_fps": self.edge_max_fps,
                "input_scale": self.edge_input_scale,
                "prefer_cpu": self.edge_prefer_cpu,
            },
            "xai": {
                "enabled": self.xai_enabled,
                "persistence_window_seconds": self.xai_persistence_window_seconds,
                "persistent_detection_threshold": self.xai_persistent_detection_threshold,
            },
            "timestamp": self._iso_now(),
        }

    @staticmethod
    def _source_label(source: int | str) -> str:
        if isinstance(source, int):
            return f"camera:{source}"
        return str(source)

    @staticmethod
    def _zone_key(source_name: str) -> str:
        source = str(source_name or "").strip().lower()
        if source.startswith("camera:"):
            return source
        return "zone:default"

    @staticmethod
    def _current_local_hour() -> int:
        return int(datetime.now(timezone.utc).hour)

    def _invalidate_zone_policy_cache(self, zone_key: str, hour_of_day: int) -> None:
        cache_key = (str(zone_key), int(hour_of_day))
        self._zone_policy_cache.pop(cache_key, None)
        self._zone_policy_cache_expiry.pop(cache_key, None)

    def _zone_policy(self, zone_key: str, hour_of_day: int, force_refresh: bool = False) -> Dict[str, Any]:
        safe_zone = str(zone_key).strip() or "zone:default"
        safe_hour = int(hour_of_day)
        if safe_hour < 0 or safe_hour > 23:
            raise ValueError("hour_of_day must be between 0 and 23")
        cache_key = (safe_zone, safe_hour)
        now_tick = monotonic()
        if (
            self.adaptive_enabled
            and not force_refresh
            and cache_key in self._zone_policy_cache
            and now_tick < self._zone_policy_cache_expiry.get(cache_key, 0.0)
        ):
            return dict(self._zone_policy_cache[cache_key])

        if not self.adaptive_enabled:
            policy = {
                "zone_key": safe_zone,
                "hour_of_day": safe_hour,
                "base_threshold": round(self.zone_base_threshold, 4),
                "adaptive_threshold": round(self.zone_base_threshold, 4),
                "effective_threshold": round(self.zone_base_threshold, 4),
                "dismiss_count": 0,
                "acknowledged_count": 0,
                "escalated_count": 0,
                "snooze_until": None,
                "is_snoozed": False,
                "updated_at": self._iso_now(),
            }
        else:
            policy = self.audit_store.get_zone_policy(
                zone_key=safe_zone,
                hour_of_day=safe_hour,
                base_threshold=self.zone_base_threshold,
                min_threshold=self.zone_min_threshold,
                max_threshold=self.zone_max_threshold,
            )
        self._zone_policy_cache[cache_key] = dict(policy)
        self._zone_policy_cache_expiry[cache_key] = now_tick + self.policy_cache_ttl_seconds
        return policy

    @staticmethod
    def _suppression_reason(weapon_confidence: float, zone_policy: Dict[str, Any]) -> Optional[str]:
        if bool(zone_policy.get("is_snoozed")):
            return f"snoozed until {zone_policy.get('snooze_until')}"
        threshold = float(zone_policy.get("effective_threshold", 0.0))
        if float(weapon_confidence) < threshold:
            return f"confidence {weapon_confidence:.3f} below threshold {threshold:.3f}"
        return None

    def _log_structured(self, *, level: str, event: str, type_: str, message: str, **extra: Any) -> None:
        payload: Dict[str, Any] = {
            "event": event,
            "type": type_,
            "message": message,
            "timestamp": self._iso_now(),
        }
        payload.update({key: value for key, value in extra.items() if value is not None})
        text = json.dumps(payload, default=str)
        logger_method = getattr(logger, level, logger.error)
        logger_method(text)

    def _log_error(self, type_: str, message: str, **extra: Any) -> None:
        self._log_structured(level="error", event="ERROR", type_=type_, message=message, **extra)

    def _log_warning(self, type_: str, message: str, **extra: Any) -> None:
        self._log_structured(level="warning", event="WARN", type_=type_, message=message, **extra)

    def _allow_alert_flow(self, *, zone_key: str, severity: str) -> tuple[bool, Optional[str]]:
        now_tick = monotonic()
        safe_zone = str(zone_key).strip() or "zone:default"
        safe_severity = str(severity or "LOW").strip().upper()
        if now_tick < self._global_alert_pause_until_tick and safe_severity != "CRITICAL":
            return False, "global_flood_pause"

        cutoff = now_tick - 60.0
        alert_key = f"{safe_zone}:{safe_severity}"
        last_tick = float(self._recent_alert_key_ticks.get(alert_key, 0.0))
        if now_tick - last_tick < self.sos_duplicate_window_seconds:
            return False, "duplicate_alert"
        self._recent_alert_key_ticks = {
            key: tick for key, tick in self._recent_alert_key_ticks.items() if now_tick - float(tick) < self.sos_duplicate_window_seconds
        }

        zone_ticks = self._zone_alert_ticks.setdefault(safe_zone, deque())
        while zone_ticks and zone_ticks[0] < cutoff:
            zone_ticks.popleft()
        if len(zone_ticks) >= self.sos_zone_alert_limit_per_minute:
            return False, "zone_rate_limit"

        while self._global_alert_ticks and self._global_alert_ticks[0] < cutoff:
            self._global_alert_ticks.popleft()
        if len(self._global_alert_ticks) >= self.sos_global_alert_limit_per_minute and safe_severity != "CRITICAL":
            self._global_alert_pause_until_tick = now_tick + self.sos_global_pause_seconds
            return False, "global_flood_limit"

        zone_ticks.append(now_tick)
        self._global_alert_ticks.append(now_tick)
        self._recent_alert_key_ticks[alert_key] = now_tick
        return True, None

    def _switch_source(self, target_source: int | str) -> Dict[str, Any]:
        if self._running and self._capture_source == target_source:
            return self.status()

        previous_source = self._capture_source
        previous_name = self._source_name
        was_running = self._running

        if was_running:
            self.stop()

        self._capture_source = target_source
        self._source_name = self._source_label(target_source)
        with self._lock:
            self._latest_frame = None
            self._latest_annotated = None
            self._live_fps = 0.0

        try:
            self.start()
        except Exception:
            self._capture_source = previous_source
            self._source_name = previous_name
            if was_running:
                try:
                    self.start()
                except Exception as restore_exc:
                    logger.error("Failed to restore previous capture source: %s", restore_exc)
            raise

        return self.status()

    def switch_to_camera(self, index: int = 0) -> Dict[str, Any]:
        return self._switch_source(int(index))

    def switch_to_default_source(self) -> Dict[str, Any]:
        return self._switch_source(self._default_source)

    def get_frame_payload(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            frame = self._latest_annotated.copy() if self._latest_annotated is not None else None
            frame_id = self._frame_id
            fps = self._live_fps
        if frame is None:
            return None

        ok, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 75])
        if not ok:
            return None

        b64 = base64.b64encode(buf).decode("utf-8")
        height, width = frame.shape[:2]
        return {
            "frame": b64,
            "frame_id": frame_id,
            "fps": round(fps, 2),
            "width": int(width),
            "height": int(height),
            "timestamp": self._iso_now(),
        }

    def get_latest_detection(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return dict(self._latest_detection) if self._latest_detection is not None else None

    def detection_packets_since(self, last_seq: int = -1, limit: int = 100) -> list[Dict[str, Any]]:
        safe_last_seq = int(last_seq)
        count = max(1, min(int(limit), self.max_history * 4))
        with self._lock:
            packets = [dict(item) for item in self._ws_packets if int(item.get("seq", -1)) > safe_last_seq]
        return packets[:count]

    def _publish_ws_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(packet)
        with self._lock:
            self._detection_seq += 1
            payload["seq"] = int(payload.get("seq", self._detection_seq))
            self._latest_detection = payload
            self._ws_packets.append(dict(payload))
        return payload

    def _emit_system_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        event = {
            "type": str(event_type).strip().upper(),
            "timestamp": self._iso_now(),
            **dict(payload or {}),
        }
        return self._publish_ws_packet(event)

    def detection_history(self, limit: int = 100) -> Dict[str, Any]:
        count = max(1, min(limit, self.max_history))
        with self._lock:
            items = list(self._detections)[-count:]
            total = len(self._detections)
        return {"detections": items, "total": total}

    def alert_history(self, limit: int = 100) -> Dict[str, Any]:
        count = max(1, min(limit, self.max_history))
        with self._lock:
            items = list(self._alerts)[-count:]
            total = len(self._alerts)
        alert_ids = [item.get("alert_id") for item in items if item.get("alert_id")]
        latest_dispositions = self.audit_store.latest_dispositions(alert_ids)
        persisted_records = self.notifier.get_alert_records([str(alert_id) for alert_id in alert_ids if alert_id])
        enriched_items = []
        for item in items:
            payload = dict(item)
            alert_id = payload.get("alert_id")
            incident = self.audit_store.incident_by_alert(str(alert_id)) if alert_id else None
            if alert_id in latest_dispositions:
                payload["latest_disposition"] = latest_dispositions[alert_id]
            persisted = persisted_records.get(str(alert_id)) if alert_id else None
            if isinstance(persisted, dict):
                for field in [
                    "explanation",
                    "evidence_status",
                    "evidence_clip_path",
                    "clip_duration",
                    "frame_count",
                    "evidence_error",
                    "evidence_created_at",
                    "evidence_thumbnail_path",
                    "evidence_sha256",
                    "evidence_clip_name",
                    "evidence_logical_filename",
                    "evidence_clip",
                    "fp_filter",
                    "false_positive_feedback",
                ]:
                    if field in persisted:
                        payload[field] = persisted.get(field)
            if incident is not None:
                payload["incident_id"] = incident.get("incident_id")
            payload["evidence_clip"] = self._build_evidence_clip_payload(payload, str(alert_id or "").strip())
            enriched_items.append(payload)
        return {"alerts": enriched_items, "total": total}

    def _alert_payload(self, alert_id: str) -> Optional[Dict[str, Any]]:
        safe_alert_id = str(alert_id).strip()
        if not safe_alert_id:
            return None
        with self._lock:
            for item in reversed(self._alerts):
                if str(item.get("alert_id", "")).strip() == safe_alert_id:
                    return dict(item)
        persisted = self.notifier.get_alert_record(safe_alert_id)
        return dict(persisted) if isinstance(persisted, dict) else None

    def alert_explanation(self, alert_id: str) -> Dict[str, Any]:
        payload = self._alert_payload(alert_id)
        if payload is None:
            raise ValueError(f"Unknown alert_id '{alert_id}'")
        explanation = payload.get("explanation")
        if not isinstance(explanation, dict) or not explanation:
            event = payload.get("event") if isinstance(payload.get("event"), dict) else {}
            explanation = event.get("explanation") if isinstance(event.get("explanation"), dict) else {}
        if not explanation:
            raise ValueError(f"No explanation available for alert_id '{alert_id}'")
        return {
            "alert_id": str(payload.get("alert_id", "")).strip() or str(alert_id).strip(),
            "timestamp": payload.get("timestamp"),
            "zone_key": payload.get("zone_key"),
            "severity": payload.get("severity") or (payload.get("event", {}) or {}).get("level"),
            "explanation": explanation,
        }

    def clear_detections(self) -> None:
        with self._lock:
            self._detections.clear()
            self._ws_packets.clear()
            self._latest_detection = None

    def clear_alerts(self) -> None:
        with self._lock:
            self._alerts.clear()

    def list_services(self) -> Dict[str, Any]:
        services = self.audit_store.list_services(active_only=False)
        return {
            "services": services,
            "total": len(services),
            "simulation_mode": self.sos_simulation_mode,
        }

    def create_service(self, payload: Dict[str, Any], *, operator_id: str) -> Dict[str, Any]:
        service = self.audit_store.create_service(payload)
        self.audit_store.append_entry(
            alert_id=f"SERVICE-{service['id']}",
            action="SERVICE_CREATED",
            operator_id=operator_id,
            details=service,
            event_timestamp=self._iso_now(),
        )
        return service

    def get_or_create_incident(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        incident = self.incident_manager.get_or_create_incident(alert)
        alert_id = str(alert.get("alert_id", "")).strip()
        if alert_id:
            with self._lock:
                for item in self._alerts:
                    if str(item.get("alert_id", "")).strip() == alert_id:
                        item["incident_id"] = incident["incident_id"]
                        break
        try:
            self.audit_store.append_incident_event(
                incident_id=incident["incident_id"],
                action="INCIDENT_LINKED",
                operator_id="system",
                details={
                    "incident_id": incident["incident_id"],
                    "alert_id": incident.get("alert_id"),
                    "zone_key": incident.get("zone_key"),
                    "severity": incident.get("severity"),
                    "confidence": incident.get("confidence"),
                },
                event_timestamp=incident.get("created_at") or self._iso_now(),
            )
        except Exception:
            pass
        return incident

    def _validated_incident_for_dispatch(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(incident or {})
        location_error = None
        location = None
        if payload.get("lat") is not None and payload.get("lng") is not None:
            location = self.incident_manager.resolve_incident_location(payload)[0]
        else:
            location, location_error = self.incident_manager.resolve_incident_location(payload)
        if location is None:
            if location_error and "Missing zone location" in location_error:
                self._log_structured(
                    level="critical",
                    event="ERROR",
                    type_="ZONE_LOCATION_MISSING",
                    message=location_error,
                    incident_id=payload.get("incident_id"),
                    zone_key=payload.get("zone_key"),
                )
            else:
                self._log_error(
                    "INVALID_LOCATION",
                    location_error or "Invalid incident location",
                    incident_id=payload.get("incident_id"),
                    zone_key=payload.get("zone_key"),
                )
            raise ValueError(location_error or "Invalid incident location")
        payload["lat"], payload["lng"] = location
        try:
            self.audit_store.update_incident(
                str(payload.get("incident_id", "")).strip(),
                {"lat": payload["lat"], "lng": payload["lng"]},
            )
        except Exception:
            self._log_warning(
                "INCIDENT_LOCATION_CACHE",
                "Unable to persist resolved incident location",
                incident_id=payload.get("incident_id"),
            )
        return payload

    def incident_response_snapshot(self, incident_id: str) -> Dict[str, Any]:
        incident = self.audit_store.incident_state(incident_id)
        if incident is None:
            raise ValueError(f"Unknown incident_id '{incident_id}'")
        sos_event = self.audit_store.latest_sos_event(incident_id)
        dispatches = self.audit_store.incident_dispatches(incident_id, limit=400)
        escalation = self.incident_escalation_status(incident_id)
        return {
            "incident": incident,
            "sos_event": sos_event,
            "dispatches": dispatches,
            "escalation": escalation,
            "simulation_mode": self.sos_simulation_mode,
        }

    def trigger_sos(
        self,
        *,
        incident_id: str,
        services: list[str],
        trigger_type: str,
        reason: str,
        operator_id: str,
    ) -> Dict[str, Any]:
        try:
            incident = self.audit_store.incident_state(incident_id)
            if incident is None:
                raise ValueError(f"Unknown incident_id '{incident_id}'")
            incident = self._validated_incident_for_dispatch(incident)
            requested_services = normalize_requested_services(services)
            duplicate = self.audit_store.find_active_sos_event(incident_id)
            if duplicate is not None:
                return {
                    "incident_id": incident_id,
                    "duplicate": True,
                    "sos_event": duplicate,
                    "dispatch": {
                        "status": duplicate.get("status"),
                        "selected_services": self.audit_store.incident_dispatches(incident_id, limit=400),
                        "simulation_mode": self.sos_simulation_mode,
                    },
                    "escalation": self.incident_escalation_status(incident_id),
                }

            sos_event = self.audit_store.create_sos_event(
                incident_id=incident_id,
                trigger_type=trigger_type,
                reason=reason,
                services=requested_services,
                status="dispatching",
            )
            self.audit_store.update_incident(incident_id, {"last_sos_at": sos_event.get("created_at"), "status": "active"})
            self.add_incident_event(
                incident_id=incident_id,
                event_type="SOS_TRIGGERED",
                operator_id=operator_id,
                details={
                    "source": trigger_type,
                    "note": reason,
                    "services": requested_services,
                    "sos_id": sos_event.get("sos_id"),
                },
                event_timestamp=sos_event.get("created_at"),
            )
            self.audit_store.append_incident_event(
                incident_id=incident_id,
                action="SOS_EVENT_CREATED",
                operator_id=operator_id,
                details={
                    "incident_id": incident_id,
                    "sos_id": sos_event.get("sos_id"),
                    "trigger_type": trigger_type,
                    "reason": reason,
                    "services": requested_services,
                },
                event_timestamp=sos_event.get("created_at"),
            )
            self.audit_store.update_sos_event(
                str(sos_event["sos_id"]),
                {"dispatch_started_at": self._iso_now(), "status": "dispatching"},
            )
            dispatch = self.sos_dispatcher.dispatch(
                sos_id=str(sos_event["sos_id"]),
                incident=incident,
                services=requested_services,
                reason=reason,
                live_link=self.sos_live_link,
                control_phone=self.sos_control_phone,
            )
            final_status = "active" if dispatch.get("selected_services") or dispatch.get("status") == "queued" else "failed"
            sos_event = self.audit_store.update_sos_event(
                str(sos_event["sos_id"]),
                {
                    "status": final_status,
                    "dispatch_completed_at": self._iso_now(),
                    "escalation_status": "started" if self.escalation_enabled else "disabled",
                },
            )
            self.audit_store.append_incident_event(
                incident_id=incident_id,
                action="SOS_DISPATCHED",
                operator_id=operator_id,
                details={
                    "incident_id": incident_id,
                    "sos_id": sos_event.get("sos_id"),
                    "services": requested_services,
                    "phones": [item.get("phone") for item in dispatch.get("selected_services", [])],
                    "status": dispatch.get("status"),
                    "simulation_mode": self.sos_simulation_mode,
                    "warning": dispatch.get("warning"),
                },
                event_timestamp=self._iso_now(),
            )
            self._emit_system_event(
                "SOS_TRIGGERED",
                {
                    "incident_id": incident_id,
                    "sos_id": sos_event.get("sos_id"),
                    "services": requested_services,
                    "trigger_type": trigger_type,
                    "reason": reason,
                    "simulation_mode": self.sos_simulation_mode,
                    "delivery_status": dispatch.get("status"),
                },
            )
            return {
                "incident_id": incident_id,
                "duplicate": False,
                "sos_event": sos_event,
                "dispatch": dispatch,
                "escalation": self.incident_escalation_status(incident_id),
            }
        except Exception as exc:
            self._log_error(
                "SOS_TRIGGER_FAILURE",
                str(exc),
                incident_id=incident_id,
                trigger_type=trigger_type,
                reason=reason,
            )
            raise

    def handle_alert_for_sos(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        now_ts = monotonic()
        zone_key = str(alert.get("zone_key") or alert.get("source") or "zone:default").strip() or "zone:default"
        zone_threshold = float(self.sos_zone_auto_thresholds.get(zone_key, self.sos_auto_trigger.min_confidence))
        if not self.sos_auto_trigger.should_trigger(alert, now_ts=now_ts, min_confidence_override=zone_threshold):
            return None
        location, location_error = self.incident_manager.resolve_incident_location(alert)
        if location is None:
            log_level = "critical" if location_error and "Missing zone location" in location_error else "error"
            self._log_structured(
                level=log_level,
                event="ERROR",
                type_="INVALID_LOCATION" if log_level != "critical" else "ZONE_LOCATION_MISSING",
                message=location_error or "Invalid alert location",
                zone_key=alert.get("zone_key"),
                alert_id=alert.get("alert_id"),
            )
            return None
        safe_alert = dict(alert)
        safe_alert["lat"], safe_alert["lng"] = location
        incident = self.get_or_create_incident(safe_alert)
        services = ["police", "hospital", "fire"]
        return self.trigger_sos(
            incident_id=str(incident["incident_id"]),
            services=services,
            trigger_type="auto",
            reason="Automatic critical threat trigger",
            operator_id="system",
        )

    def manual_trigger_sos(
        self,
        *,
        incident_id: str,
        services: list[str],
        reason: str,
        operator_id: str,
    ) -> Dict[str, Any]:
        return self.trigger_sos(
            incident_id=incident_id,
            services=services,
            trigger_type="manual",
            reason=reason,
            operator_id=operator_id,
        )

    def acknowledge_incident_response(
        self,
        *,
        incident_id: str,
        operator_id: str,
        note: str = "",
        resolution: str = "ACKNOWLEDGED",
    ) -> Dict[str, Any]:
        self.audit_store.update_incident(
            incident_id,
            {
                "acknowledged": True,
                "acknowledged_at": self._iso_now(),
                "acknowledged_by": operator_id,
                "status": "acknowledged",
            },
        )
        latest_sos = self.audit_store.latest_sos_event(incident_id)
        if latest_sos is not None:
            self.audit_store.update_sos_event(
                latest_sos["sos_id"],
                {"status": "acknowledged", "acknowledged_at": self._iso_now(), "escalation_status": "stopped"},
            )
        escalation = self.sos_escalation_manager.acknowledge(
            incident_id=incident_id,
            operator_id=operator_id,
            note=note,
            resolution=resolution,
        )
        self._emit_system_event(
            "ESCALATION_UPDATE",
            {
                "incident_id": incident_id,
                "status": "acknowledged",
                "resolution": resolution,
            },
        )
        return self.incident_response_snapshot(incident_id) | {"escalation": escalation}

    @staticmethod
    def _resolve_local_path(path_value: str) -> Path:
        path = Path(str(path_value).strip()).expanduser()
        if path.is_absolute():
            return path
        return (PROJECT_ROOT / path).resolve()

    def _find_alert_payload(self, alert_id: str) -> Optional[Dict[str, Any]]:
        safe_alert_id = str(alert_id).strip()
        if not safe_alert_id:
            return None
        with self._lock:
            for item in reversed(self._alerts):
                if str(item.get("alert_id", "")).strip() == safe_alert_id:
                    return item
        return None

    def _update_alert_state(self, alert_id: str, updates: Dict[str, Any]) -> None:
        safe_alert_id = str(alert_id).strip()
        if not safe_alert_id:
            return
        with self._lock:
            for item in self._alerts:
                if str(item.get("alert_id", "")).strip() == safe_alert_id:
                    item.update(dict(updates))
                    break

    def _update_alert_evidence_state(self, alert_id: str, updates: Dict[str, Any]) -> None:
        self._update_alert_state(alert_id, updates)

    @staticmethod
    def _build_evidence_clip_payload(payload: Optional[Dict[str, Any]], alert_id: str = "") -> Dict[str, Any]:
        source = dict(payload) if isinstance(payload, dict) else {}
        nested = source.get("evidence_clip") if isinstance(source.get("evidence_clip"), dict) else {}
        path = nested.get("path") or source.get("evidence_clip_path") or source.get("clip_path")
        duration = nested.get("duration")
        if duration is None:
            duration = source.get("clip_duration") if source.get("clip_duration") is not None else source.get("duration")
        frames = nested.get("frames")
        if frames is None:
            frames = source.get("frame_count")
        status = nested.get("status") or source.get("evidence_status") or source.get("status")
        created_at = nested.get("created_at") or source.get("evidence_created_at") or source.get("created_at")
        thumbnail_path = nested.get("thumbnail_path") or source.get("evidence_thumbnail_path") or source.get("thumbnail_path")
        sha256 = nested.get("sha256") or source.get("evidence_sha256") or source.get("sha256")
        clip_name = nested.get("clip_name") or source.get("evidence_clip_name") or source.get("clip_name")
        logical_filename = (
            nested.get("logical_filename")
            or source.get("evidence_logical_filename")
            or source.get("logical_filename")
        )
        error = nested.get("error") or source.get("evidence_error") or source.get("error")

        if not status:
            status = "ready" if path else "not_requested"

        safe_alert_id = str(alert_id).strip()
        download_url = nested.get("download_url")
        thumbnail_url = nested.get("thumbnail_url")
        if not download_url and path and safe_alert_id:
            download_url = f"/api/alerts/{safe_alert_id}/evidence?download=1"
        if not thumbnail_url and thumbnail_path and safe_alert_id:
            thumbnail_url = f"/api/alerts/{safe_alert_id}/evidence?thumbnail=1"

        return {
            "path": path,
            "duration": duration,
            "frames": frames,
            "status": status,
            "created_at": created_at,
            "thumbnail_path": thumbnail_path,
            "thumbnail_url": thumbnail_url,
            "sha256": sha256,
            "clip_name": clip_name,
            "logical_filename": logical_filename,
            "download_url": download_url,
            "error": error,
        }

    def _evidence_updates_from_payload(self, alert_id: str, payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        evidence_clip = self._build_evidence_clip_payload(payload, alert_id)
        return {
            "evidence_status": evidence_clip.get("status"),
            "evidence_clip_path": evidence_clip.get("path"),
            "clip_duration": evidence_clip.get("duration"),
            "frame_count": evidence_clip.get("frames"),
            "evidence_error": evidence_clip.get("error"),
            "evidence_created_at": evidence_clip.get("created_at"),
            "evidence_thumbnail_path": evidence_clip.get("thumbnail_path"),
            "evidence_sha256": evidence_clip.get("sha256"),
            "evidence_clip_name": evidence_clip.get("clip_name"),
            "evidence_logical_filename": evidence_clip.get("logical_filename"),
            "evidence_clip": evidence_clip,
        }

    def _should_capture_evidence(self, severity_level: str) -> bool:
        return self.evidence_enabled and self.clip_recorder is not None and str(severity_level).upper() in {"HIGH", "CRITICAL"}

    def _on_evidence_clip_complete(self, alert_id: str, payload: Dict[str, Any]) -> None:
        evidence_updates = self._evidence_updates_from_payload(alert_id, payload)
        self._update_alert_evidence_state(alert_id, evidence_updates)
        try:
            self.notifier.update_alert_evidence(alert_id=alert_id, evidence_payload=evidence_updates)
        except Exception as exc:
            logger.error("Failed to persist evidence metadata alert_id=%s: %s", alert_id, exc)

        audit_action = "EVIDENCE_CAPTURED" if payload.get("status") == "ready" else "EVIDENCE_CAPTURE_FAILED"
        try:
            self.audit_store.append_entry(
                alert_id=alert_id,
                action=audit_action,
                operator_id="system",
                details=evidence_updates,
                event_timestamp=self._iso_now(),
            )
        except Exception as exc:
            logger.error("Failed to append evidence audit entry alert_id=%s: %s", alert_id, exc)

    def alert_evidence(self, alert_id: str) -> Dict[str, Any]:
        safe_alert_id = str(alert_id).strip()
        if not safe_alert_id:
            raise ValueError("alert_id is required")

        alert_payload = self._find_alert_payload(safe_alert_id)
        persisted = self.notifier.get_alert_record(safe_alert_id)
        recorder_status = self.clip_recorder.evidence_status(safe_alert_id) if self.clip_recorder is not None else None
        merged: Dict[str, Any] = {}
        for source in [persisted, alert_payload, recorder_status]:
            if isinstance(source, dict):
                merged.update(source)

        if not merged and not self.audit_store.alert_exists(safe_alert_id):
            raise ValueError(f"Unknown alert_id '{safe_alert_id}'")

        evidence_clip = self._build_evidence_clip_payload(merged, safe_alert_id)
        clip_path = evidence_clip.get("path")
        if clip_path and not evidence_clip.get("created_at"):
            try:
                clip_stat = self._resolve_local_path(str(clip_path)).stat()
                evidence_clip["created_at"] = datetime.fromtimestamp(clip_stat.st_mtime, timezone.utc).isoformat()
            except (FileNotFoundError, OSError, ValueError):
                pass

        return {
            "alert_id": safe_alert_id,
            "clip_path": clip_path,
            "download_url": evidence_clip.get("download_url"),
            "duration": evidence_clip.get("duration"),
            "frame_count": evidence_clip.get("frames"),
            "status": evidence_clip.get("status"),
            "created_at": evidence_clip.get("created_at"),
            "thumbnail_path": evidence_clip.get("thumbnail_path"),
            "thumbnail_url": evidence_clip.get("thumbnail_url"),
            "sha256": evidence_clip.get("sha256"),
            "logical_filename": evidence_clip.get("logical_filename"),
            "clip_name": evidence_clip.get("clip_name"),
            "error": evidence_clip.get("error"),
            "evidence_clip": evidence_clip,
        }

    def alert_evidence_file(self, alert_id: str) -> Path:
        payload = self.alert_evidence(alert_id)
        clip_path = payload.get("clip_path")
        if not clip_path:
            raise FileNotFoundError(f"No evidence clip available for alert_id '{alert_id}'")
        resolved = self._resolve_local_path(str(clip_path))
        if not resolved.exists():
            raise FileNotFoundError(f"Evidence clip not found at '{resolved}'")
        return resolved

    def alert_evidence_thumbnail_file(self, alert_id: str) -> Path:
        payload = self.alert_evidence(alert_id)
        evidence_clip = payload.get("evidence_clip") if isinstance(payload.get("evidence_clip"), dict) else {}
        thumbnail_path = evidence_clip.get("thumbnail_path") or payload.get("thumbnail_path")
        if not thumbnail_path:
            raise FileNotFoundError(f"No evidence thumbnail available for alert_id '{alert_id}'")
        resolved = self._resolve_local_path(str(thumbnail_path))
        if not resolved.exists():
            raise FileNotFoundError(f"Evidence thumbnail not found at '{resolved}'")
        return resolved

    def add_alert_disposition(
        self,
        *,
        alert_id: str,
        disposition: str,
        operator_id: str,
        note: str = "",
    ) -> Dict[str, Any]:
        safe_alert_id = str(alert_id).strip()
        if not safe_alert_id:
            raise ValueError("alert_id is required")

        normalized = str(disposition).strip().upper()
        if normalized not in self.ALLOWED_DISPOSITIONS:
            raise ValueError(f"Unsupported disposition '{disposition}'")

        if not self.audit_store.alert_exists(safe_alert_id):
            raise KeyError(f"Unknown alert_id '{safe_alert_id}'")

        details = {"note": str(note or "").strip()}
        entry = self.audit_store.append_entry(
            alert_id=safe_alert_id,
            action=normalized,
            operator_id=operator_id,
            details=details,
            event_timestamp=self._iso_now(),
        )
        if self.adaptive_enabled:
            learning = self.audit_store.apply_disposition_learning(
                alert_id=safe_alert_id,
                action=normalized,
                base_threshold=self.zone_base_threshold,
                min_threshold=self.zone_min_threshold,
                max_threshold=self.zone_max_threshold,
                tune_step=self.zone_tune_step,
                dismiss_trigger_count=self.dismiss_trigger_count,
                snooze_minutes=self.zone_snooze_minutes,
            )
        else:
            learning = {"updated": False, "reason": "Adaptive alerting disabled"}
        policy = learning.get("policy")
        if isinstance(policy, dict):
            self._invalidate_zone_policy_cache(
                zone_key=str(policy.get("zone_key", "zone:default")),
                hour_of_day=int(policy.get("hour_of_day", 0)),
            )
        if bool(learning.get("auto_tuned")):
            try:
                self.audit_store.append_entry(
                    alert_id=safe_alert_id,
                    action="POLICY_AUTO_TUNED",
                    operator_id="system",
                    details={
                        "zone_key": learning.get("zone_key"),
                        "hour_of_day": learning.get("hour_of_day"),
                        "policy": learning.get("policy"),
                        "trigger_action": normalized,
                    },
                    event_timestamp=self._iso_now(),
                )
            except Exception as exc:
                logger.error("Failed to append POLICY_AUTO_TUNED audit entry alert_id=%s: %s", safe_alert_id, exc)
        return {"entry": entry, "learning": learning}

    def false_positive_model_status(self) -> Dict[str, Any]:
        return self.false_positive_filter.status()

    def submit_false_positive_feedback(
        self,
        *,
        alert_id: str,
        label: str,
        operator_id: str,
    ) -> Dict[str, Any]:
        safe_alert_id = str(alert_id or "").strip()
        if not safe_alert_id:
            raise ValueError("alert_id is required")
        normalized_label = str(label or "").strip().lower()
        if normalized_label not in {"true", "false"}:
            raise ValueError("label must be 'true' or 'false'")

        payload = self._alert_payload(safe_alert_id)
        if not isinstance(payload, dict):
            raise ValueError(f"Unknown alert_id '{safe_alert_id}'")
        filter_payload = payload.get("fp_filter") if isinstance(payload.get("fp_filter"), dict) else None
        if not isinstance(filter_payload, dict):
            raise ValueError("Alert does not have false-positive filter context")

        label_value = 1 if normalized_label == "true" else 0
        result = self.false_positive_filter.record_feedback(
            alert_id=safe_alert_id,
            label=label_value,
            operator_id=operator_id,
            filter_payload=filter_payload,
        )
        feedback = result.get("feedback", {}) if isinstance(result.get("feedback"), dict) else {}

        updated_filter_payload = {
            **dict(filter_payload),
            "feedback": feedback,
        }
        updates: Dict[str, Any] = {
            "fp_filter": updated_filter_payload,
            "false_positive_feedback": feedback,
        }
        if label_value == 1 and not payload.get("incident_id"):
            try:
                incident = self.get_or_create_incident(payload)
                updates["incident_id"] = incident.get("incident_id")
            except Exception as exc:
                logger.error("Failed to create incident for confirmed alert_id=%s: %s", safe_alert_id, exc)

        self._update_alert_state(safe_alert_id, updates)
        try:
            self.notifier.update_alert_record(safe_alert_id, updates)
        except Exception as exc:
            logger.error("Failed to persist false-positive feedback alert_id=%s: %s", safe_alert_id, exc)

        try:
            self.audit_store.append_entry(
                alert_id=safe_alert_id,
                action="FP_FEEDBACK",
                operator_id=operator_id,
                details={
                    "label": normalized_label,
                    "feedback": feedback,
                    "fp_filter": {
                        "decision": updated_filter_payload.get("decision"),
                        "threat_probability": updated_filter_payload.get("threat_probability"),
                        "final_score": updated_filter_payload.get("final_score"),
                    },
                },
                event_timestamp=self._iso_now(),
            )
        except Exception as exc:
            logger.error("Failed to append FP_FEEDBACK audit entry alert_id=%s: %s", safe_alert_id, exc)

        refreshed = self._alert_payload(safe_alert_id)
        return {
            "feedback": feedback,
            "model_status": result.get("model_status"),
            "alert": refreshed,
        }

    def alert_audit(self, alert_id: str, limit: int = 200) -> Dict[str, Any]:
        safe_alert_id = str(alert_id).strip()
        if not safe_alert_id:
            raise ValueError("alert_id is required")
        return self.audit_store.fetch_entries(alert_id=safe_alert_id, limit=limit)

    def audit_chain(self, alert_id: Optional[str] = None, limit: int = 5000) -> Dict[str, Any]:
        return self.audit_store.verify_chain(alert_id=alert_id, limit=limit)

    def audit_entries(self, alert_id: Optional[str] = None, limit: int = 200) -> Dict[str, Any]:
        safe_alert_id = str(alert_id).strip() if alert_id is not None else None
        if safe_alert_id == "":
            safe_alert_id = None
        return self.audit_store.fetch_entries(alert_id=safe_alert_id, limit=limit)

    def get_zone_policy(self, zone_key: str, hour_of_day: Optional[int] = None) -> Dict[str, Any]:
        safe_hour = int(hour_of_day) if hour_of_day is not None else self._current_local_hour()
        return self._zone_policy(zone_key=zone_key, hour_of_day=safe_hour, force_refresh=True)

    def list_zone_policies(self, limit: int = 200) -> Dict[str, Any]:
        return self.audit_store.list_zone_policies(limit=limit)

    def set_zone_policy(
        self,
        *,
        zone_key: str,
        hour_of_day: int,
        operator_id: str,
        adaptive_threshold: Optional[float] = None,
        snooze_minutes: Optional[int] = None,
    ) -> Dict[str, Any]:
        policy = self.audit_store.set_zone_policy(
            zone_key=zone_key,
            hour_of_day=hour_of_day,
            base_threshold=self.zone_base_threshold,
            min_threshold=self.zone_min_threshold,
            max_threshold=self.zone_max_threshold,
            adaptive_threshold=adaptive_threshold,
            snooze_minutes=snooze_minutes,
        )
        self._invalidate_zone_policy_cache(
            zone_key=str(policy.get("zone_key", zone_key)),
            hour_of_day=int(policy.get("hour_of_day", hour_of_day)),
        )
        try:
            self.audit_store.append_entry(
                alert_id=f"POLICY-{policy['zone_key']}-{policy['hour_of_day']}",
                action="POLICY_TUNED",
                operator_id=operator_id,
                details={
                    "zone_key": policy["zone_key"],
                    "hour_of_day": policy["hour_of_day"],
                    "adaptive_threshold": policy["adaptive_threshold"],
                    "snooze_until": policy["snooze_until"],
                },
                event_timestamp=self._iso_now(),
            )
        except Exception as exc:
            logger.error(
                "Failed to append POLICY_TUNED audit entry zone=%s hour=%s: %s",
                policy.get("zone_key"),
                policy.get("hour_of_day"),
                exc,
            )
        return policy

    @classmethod
    def _severity_rank(cls, value: Optional[str]) -> int:
        token = str(value or "LOW").strip().upper()
        return int(cls.LIVE_ZONE_SEVERITY_RANK.get(token, 0))

    @classmethod
    def _severity_from_rank(cls, value: int) -> str:
        safe_rank = max(0, min(int(value), max(cls.LIVE_ZONE_SEVERITY_RANK.values())))
        for label, rank in cls.LIVE_ZONE_SEVERITY_RANK.items():
            if rank == safe_rank:
                return label
        return "LOW"

    def zone_live_status(self, limit: int = 200) -> list[Dict[str, Any]]:
        count = max(1, min(int(limit), 2000))
        current_hour = self._current_local_hour()
        window_start = datetime.now(timezone.utc) - timedelta(seconds=self.live_status_window_seconds)
        min_dt = datetime.min.replace(tzinfo=timezone.utc)

        with self._lock:
            alerts = [dict(item) for item in self._alerts]
            detections = [dict(item) for item in self._detections]
            current_source = str(self._source_name or "")

        known_zone_keys = {self._zone_key(current_source)}
        for item in self.audit_store.list_zone_policies(limit=2000).get("policies", []):
            zone_key = str(item.get("zone_key", "")).strip() or "zone:default"
            known_zone_keys.add(zone_key)

        zone_state: Dict[str, Dict[str, Any]] = {}

        def ensure_zone(zone_key: str) -> Dict[str, Any]:
            safe_zone = str(zone_key).strip() or "zone:default"
            return zone_state.setdefault(
                safe_zone,
                {
                    "zone_key": safe_zone,
                    "severity": "LOW",
                    "alert_count": 0,
                    "last_event_ts": None,
                    "current_threshold": None,
                    "is_snoozed": False,
                    "_severity_rank": 0,
                    "_last_event_dt": None,
                    "_max_score": 0.0,
                },
            )

        def update_last_event(zone: Dict[str, Any], timestamp: Optional[str]) -> None:
            if not timestamp:
                return
            dt = self._parse_iso_utc(timestamp)
            previous = zone.get("_last_event_dt")
            if previous is None or dt > previous:
                zone["_last_event_dt"] = dt
                zone["last_event_ts"] = dt.isoformat()

        def update_severity(zone: Dict[str, Any], level: Optional[str], score: Optional[float]) -> None:
            rank = self._severity_rank(level)
            numeric_score = float(score or 0.0)
            if rank > int(zone.get("_severity_rank", 0)) or (
                rank == int(zone.get("_severity_rank", 0))
                and numeric_score > float(zone.get("_max_score", 0.0))
            ):
                zone["_severity_rank"] = rank
                zone["_max_score"] = numeric_score
                zone["severity"] = self._severity_from_rank(rank)

        for packet in detections:
            packet_dt = self._parse_iso_utc(packet.get("timestamp"))
            if packet_dt < window_start:
                continue
            zone_key = self._zone_key(str(packet.get("source") or ""))
            known_zone_keys.add(zone_key)
            zone = ensure_zone(zone_key)
            update_last_event(zone, packet.get("timestamp"))
            severity = packet.get("severity") if isinstance(packet.get("severity"), dict) else {}
            update_severity(zone, severity.get("level"), severity.get("score"))

        for alert in alerts:
            alert_dt = self._parse_iso_utc(alert.get("timestamp"))
            if alert_dt < window_start:
                continue
            zone_key = str(alert.get("zone_key") or self._zone_key(str(alert.get("source") or ""))).strip() or "zone:default"
            known_zone_keys.add(zone_key)
            zone = ensure_zone(zone_key)
            zone["alert_count"] = int(zone.get("alert_count", 0)) + 1
            update_last_event(zone, alert.get("timestamp"))
            event = alert.get("event") if isinstance(alert.get("event"), dict) else {}
            update_severity(zone, event.get("level"), event.get("score"))

        for zone_key in known_zone_keys:
            zone = ensure_zone(zone_key)
            policy = self._zone_policy(zone_key=zone_key, hour_of_day=current_hour, force_refresh=True)
            zone["current_threshold"] = round(
                float(
                    policy.get("effective_threshold", policy.get("adaptive_threshold", self.zone_base_threshold))
                ),
                4,
            )
            zone["is_snoozed"] = bool(policy.get("is_snoozed"))
            update_last_event(zone, policy.get("updated_at"))

        high_rank = self.LIVE_ZONE_SEVERITY_RANK["HIGH"]
        critical_rank = self.LIVE_ZONE_SEVERITY_RANK["CRITICAL"]
        for zone in zone_state.values():
            if int(zone.get("alert_count", 0)) >= self.critical_alert_count_threshold and int(
                zone.get("_severity_rank", 0)
            ) >= high_rank:
                zone["_severity_rank"] = critical_rank
                zone["severity"] = "CRITICAL"

        items = sorted(
            zone_state.values(),
            key=lambda item: (
                int(item.get("_severity_rank", 0)),
                int(item.get("alert_count", 0)),
                item.get("_last_event_dt") or min_dt,
            ),
            reverse=True,
        )

        return [
            {
                "zone_key": item["zone_key"],
                "severity": item["severity"],
                "alert_count": int(item["alert_count"]),
                "last_event_ts": item["last_event_ts"],
                "current_threshold": item["current_threshold"],
                "is_snoozed": bool(item["is_snoozed"]),
            }
            for item in items[:count]
        ]

    @staticmethod
    def _auto_zone_layout(zone_keys: list[str]) -> list[Dict[str, Any]]:
        keys = sorted({str(zone_key).strip() for zone_key in zone_keys if str(zone_key).strip()})
        if not keys:
            keys = ["zone:default"]

        if len(keys) <= 2:
            columns = 2
        elif len(keys) <= 4:
            columns = 2
        elif len(keys) <= 9:
            columns = 3
        else:
            columns = int(np.ceil(np.sqrt(len(keys))))
        rows = int(np.ceil(len(keys) / columns))
        gap = 2.4
        width = (100.0 - (gap * (columns + 1))) / columns
        height = (100.0 - (gap * (rows + 1))) / rows

        layout = []
        for index, zone_key in enumerate(keys):
            column = index % columns
            row = index // columns
            x = gap + column * (width + gap)
            y = gap + row * (height + gap)
            layout.append(
                {
                    "zone_key": zone_key,
                    "coordinates": [
                        round(x, 3),
                        round(y, 3),
                        round(x + width, 3),
                        round(y + height, 3),
                    ],
                }
            )
        return layout

    def zone_layout(self, limit: int = 200) -> list[Dict[str, Any]]:
        live_items = self.zone_live_status(limit=max(1, min(int(limit), 2000)))
        zone_keys = [str(item.get("zone_key", "")).strip() for item in live_items if str(item.get("zone_key", "")).strip()]
        return self._auto_zone_layout(zone_keys)

    def escalation_chain(self) -> Dict[str, Any]:
        payload = self.audit_store.list_escalation_chain()
        steps = []
        for index, item in enumerate(payload.get("steps", []), start=1):
            channels = [
                str(ch).strip().lower()
                for ch in item.get("channels", [])
                if str(ch).strip().lower() in self.ALLOWED_ESCALATION_CHANNELS
            ]
            recipients = [str(value).strip() for value in item.get("recipients", []) if str(value).strip()]
            steps.append(
                {
                    "step_index": index - 1,
                    "name": str(item.get("name", f"Step-{index}")).strip() or f"Step-{index}",
                    "delay_seconds": max(0, int(item.get("delay_seconds", 0))),
                    "channels": channels,
                    "recipients": recipients,
                    "display_order": int(item.get("display_order", index)),
                    "updated_at": item.get("updated_at"),
                }
            )
        steps.sort(key=lambda step: (int(step["display_order"]), int(step["delay_seconds"])))
        for idx, step in enumerate(steps):
            step["step_index"] = idx
        return {"steps": steps, "total": len(steps)}

    def set_escalation_chain(self, steps: list[Dict[str, Any]], operator_id: str) -> Dict[str, Any]:
        normalized: list[Dict[str, Any]] = []
        for item in steps:
            channels = [str(ch).strip().lower() for ch in item.get("channels", []) if str(ch).strip()]
            recipients = [str(value).strip() for value in item.get("recipients", []) if str(value).strip()]
            normalized.append(
                {
                    "name": str(item.get("name", "")).strip(),
                    "delay_seconds": int(item.get("delay_seconds", 0)),
                    "channels": channels,
                    "recipients": recipients,
                }
            )
        saved = self.audit_store.replace_escalation_chain(normalized)
        details = {"steps": saved.get("steps", [])}
        try:
            self.audit_store.append_entry(
                alert_id="POLICY-ESCALATION-CHAIN",
                action="ESCALATION_CHAIN_UPDATED",
                operator_id=operator_id,
                details=details,
                event_timestamp=self._iso_now(),
            )
        except Exception as exc:
            logger.error("Failed to append ESCALATION_CHAIN_UPDATED audit entry: %s", exc)
        return self.escalation_chain()

    @staticmethod
    def _safe_incident_id(incident_id: str) -> str:
        safe = str(incident_id).strip()
        if not safe:
            raise ValueError("incident_id is required")
        return safe

    def _delivery_attempt(
        self,
        *,
        incident_id: str,
        step: Dict[str, Any],
        channel: str,
        source: str,
    ) -> Dict[str, Any]:
        safe_channel = str(channel).strip().lower()
        if safe_channel not in self.ALLOWED_ESCALATION_CHANNELS:
            return {
                "channel": safe_channel,
                "delivery_status": "FAILED",
                "delivery_confirmed": False,
                "error": f"Unsupported channel '{safe_channel}'",
                "target": "",
                "http_status": None,
            }

        endpoint = str(self.escalation_delivery_endpoints.get(safe_channel, "")).strip()
        if not endpoint:
            return {
                "channel": safe_channel,
                "delivery_status": "UNCONFIGURED",
                "delivery_confirmed": False,
                "error": f"No endpoint configured for channel '{safe_channel}'",
                "target": "",
                "http_status": None,
            }

        payload = {
            "incident_id": incident_id,
            "timestamp": self._iso_now(),
            "step_name": step.get("name"),
            "step_index": step.get("step_index"),
            "delay_seconds": step.get("delay_seconds"),
            "channel": safe_channel,
            "recipients": step.get("recipients", []),
            "source": source,
            "message": f"Escalation {step.get('name')} triggered for incident {incident_id}",
        }
        body = json.dumps(payload).encode("utf-8")
        req = urllib_request.Request(
            endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib_request.urlopen(req, timeout=self.escalation_delivery_timeout_seconds) as response:
                status_code = int(response.getcode() or 0)
                raw = response.read()
            text = raw.decode("utf-8", errors="ignore").strip() if raw else ""
            confirmed = 200 <= status_code < 300
            if text:
                try:
                    parsed = json.loads(text)
                except Exception:
                    parsed = None
                if isinstance(parsed, dict):
                    if "confirmed" in parsed:
                        confirmed = bool(parsed.get("confirmed"))
                    elif "delivered" in parsed:
                        confirmed = bool(parsed.get("delivered"))
                    elif "acknowledged" in parsed:
                        confirmed = bool(parsed.get("acknowledged"))
                    elif "ok" in parsed:
                        confirmed = bool(parsed.get("ok"))
            status = "CONFIRMED" if confirmed else "FAILED"
            return {
                "channel": safe_channel,
                "delivery_status": status,
                "delivery_confirmed": bool(confirmed),
                "error": "" if confirmed else f"Channel '{safe_channel}' returned non-confirmed response",
                "target": endpoint,
                "http_status": status_code,
                "response": text[:300],
            }
        except urllib_error.HTTPError as exc:
            return {
                "channel": safe_channel,
                "delivery_status": "FAILED",
                "delivery_confirmed": False,
                "error": f"HTTPError: {exc}",
                "target": endpoint,
                "http_status": int(exc.code),
            }
        except Exception as exc:
            return {
                "channel": safe_channel,
                "delivery_status": "FAILED",
                "delivery_confirmed": False,
                "error": str(exc),
                "target": endpoint,
                "http_status": None,
            }

    def _trigger_escalation_step(self, incident_id: str, state: Dict[str, Any], step_index: int) -> None:
        steps = state.get("steps", [])
        if step_index < 0 or step_index >= len(steps):
            return
        step = steps[step_index]
        source = str(state.get("source", "")).strip()
        now_iso = self._iso_now()
        self.audit_store.append_incident_event(
            incident_id=incident_id,
            action="ESCALATION_STEP_TRIGGERED",
            operator_id="system",
            details={
                "incident_id": incident_id,
                "step_index": step_index,
                "step_name": step.get("name"),
                "delay_seconds": step.get("delay_seconds"),
                "target": str(step.get("name", "")).strip().lower().replace(" ", "_"),
                "channels": step.get("channels", []),
                "recipients": step.get("recipients", []),
                "source": source,
            },
            event_timestamp=now_iso,
        )
        self._emit_system_event(
            "ESCALATION_UPDATE",
            {
                "incident_id": incident_id,
                "level": step_index + 1,
                "target": str(step.get("name", "")).strip().lower().replace(" ", "_"),
                "status": "sent",
            },
        )
        for channel in step.get("channels", []):
            result: Dict[str, Any] = {}
            for attempt in range(1, self.sos_retry_limit + 1):
                result = self._delivery_attempt(
                    incident_id=incident_id,
                    step=step,
                    channel=str(channel),
                    source=source,
                )
                result["attempt"] = attempt
                if bool(result.get("delivery_confirmed")) or str(result.get("delivery_status")) in {"CONFIRMED", "UNCONFIGURED"}:
                    break
            details = {
                "incident_id": incident_id,
                "step_index": step_index,
                "step_name": step.get("name"),
                "delay_seconds": step.get("delay_seconds"),
                "channel": result.get("channel"),
                "delivery_status": result.get("delivery_status"),
                "delivery_confirmed": bool(result.get("delivery_confirmed")),
                "attempt": int(result.get("attempt", 1)),
                "target": result.get("target"),
                "http_status": result.get("http_status"),
                "error": result.get("error"),
                "response": result.get("response"),
                "recipients": step.get("recipients", []),
                "source": source,
            }
            self.audit_store.append_incident_event(
                incident_id=incident_id,
                action="ESCALATION_DELIVERY",
                operator_id="system",
                details=details,
                event_timestamp=self._iso_now(),
            )
        with self._escalation_lock:
            current = self._active_escalations.get(incident_id)
            if current is not None:
                current["triggered_steps"] = set(current.get("triggered_steps", set()))
                current["triggered_steps"].add(step_index)

    def _is_incident_response_event(self, event_type: str) -> bool:
        return str(event_type).strip().upper() in {
            "POLICE_DISPATCHED",
            "OFFICER_DISPATCHED",
            "OFFICER_ARRIVED",
            "SCENE_CLEARED",
        }

    def _resolve_escalation(
        self,
        *,
        incident_id: str,
        operator_id: str,
        resolution: str,
        note: str = "",
    ) -> None:
        safe_incident = self._safe_incident_id(incident_id)
        safe_resolution = str(resolution).strip().upper() or "RESOLVED"
        details = {"incident_id": safe_incident, "resolution": safe_resolution, "note": str(note or "").strip()}
        details = {k: v for k, v in details.items() if not (isinstance(v, str) and v == "")}
        self.audit_store.append_incident_event(
            incident_id=safe_incident,
            action="ESCALATION_RESOLVED",
            operator_id=operator_id,
            details=details,
            event_timestamp=self._iso_now(),
        )
        with self._escalation_lock:
            self._active_escalations.pop(safe_incident, None)

    def start_incident_escalation(
        self,
        *,
        incident_id: str,
        operator_id: str,
        source: str = "",
        note: str = "",
        reason: str = "SOS_TRIGGERED",
        event_timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self.escalation_enabled:
            raise ValueError("Escalation is disabled")
        safe_incident = self._safe_incident_id(incident_id)
        status = self.incident_escalation_status(safe_incident)
        if bool(status.get("active")):
            return status

        chain = self.escalation_chain()
        steps = chain.get("steps", [])
        if not steps:
            raise ValueError("Escalation chain is not configured")

        start_iso = event_timestamp or self._iso_now()
        start_dt = self._parse_iso_utc(start_iso)
        state = {
            "incident_id": safe_incident,
            "started_at": start_iso,
            "started_at_dt": start_dt,
            "started_by": operator_id,
            "source": str(source or "").strip(),
            "note": str(note or "").strip(),
            "reason": str(reason or "SOS_TRIGGERED").strip().upper(),
            "steps": [dict(step) for step in steps],
            "triggered_steps": set(),
        }
        with self._escalation_lock:
            self._active_escalations[safe_incident] = state

        details = {
            "incident_id": safe_incident,
            "source": state["source"],
            "note": state["note"],
            "reason": state["reason"],
            "steps": [
                {
                    "step_index": step.get("step_index"),
                    "name": step.get("name"),
                    "delay_seconds": step.get("delay_seconds"),
                    "channels": step.get("channels", []),
                    "recipients": step.get("recipients", []),
                }
                for step in steps
            ],
        }
        details = {k: v for k, v in details.items() if not (isinstance(v, str) and v == "")}
        self.audit_store.append_incident_event(
            incident_id=safe_incident,
            action="ESCALATION_STARTED",
            operator_id=operator_id,
            details=details,
            event_timestamp=start_iso,
        )
        latest_sos = self.audit_store.latest_sos_event(safe_incident)
        if latest_sos is not None:
            self.audit_store.update_sos_event(latest_sos["sos_id"], {"escalation_status": "started"})
        self._emit_system_event(
            "ESCALATION_UPDATE",
            {
                "incident_id": safe_incident,
                "level": 0,
                "status": "started",
            },
        )
        return self.incident_escalation_status(safe_incident)

    def acknowledge_incident_escalation(
        self,
        *,
        incident_id: str,
        operator_id: str,
        note: str = "",
        resolution: str = "ACKNOWLEDGED",
    ) -> Dict[str, Any]:
        safe_incident = self._safe_incident_id(incident_id)
        safe_resolution = str(resolution or "ACKNOWLEDGED").strip().upper()
        details = {
            "incident_id": safe_incident,
            "note": str(note or "").strip(),
            "resolution": safe_resolution,
        }
        details = {k: v for k, v in details.items() if not (isinstance(v, str) and v == "")}
        self.audit_store.append_incident_event(
            incident_id=safe_incident,
            action="ESCALATION_ACKNOWLEDGED",
            operator_id=operator_id,
            details=details,
            event_timestamp=self._iso_now(),
        )
        latest_sos = self.audit_store.latest_sos_event(safe_incident)
        if latest_sos is not None:
            self.audit_store.update_sos_event(
                latest_sos["sos_id"],
                {"status": "acknowledged", "acknowledged_at": self._iso_now(), "escalation_status": "acknowledged"},
            )
        with self._escalation_lock:
            self._active_escalations.pop(safe_incident, None)
        self._emit_system_event(
            "ESCALATION_UPDATE",
            {
                "incident_id": safe_incident,
                "status": "acknowledged",
                "resolution": safe_resolution,
            },
        )
        return self.incident_escalation_status(safe_incident)

    def incident_escalation_status(self, incident_id: str, limit: int = 1200) -> Dict[str, Any]:
        safe_incident = self._safe_incident_id(incident_id)
        entries = self.audit_store.incident_events(safe_incident, limit=limit).get("entries", [])
        configured_steps = self.escalation_chain().get("steps", [])
        started_event: Optional[Dict[str, Any]] = None
        active = False
        acknowledged = False
        resolved = False
        exhausted = False
        acknowledged_by = None
        acknowledged_at = None
        resolution = None

        steps_source = [dict(step) for step in configured_steps]
        step_runtime: Dict[int, Dict[str, Any]] = {}
        for step in steps_source:
            idx = int(step.get("step_index", len(step_runtime)))
            step_runtime[idx] = {
                "step_index": idx,
                "name": step.get("name"),
                "delay_seconds": int(step.get("delay_seconds", 0)),
                "channels": list(step.get("channels", [])),
                "recipients": list(step.get("recipients", [])),
                "triggered_at": None,
                "deliveries": [],
            }

        for entry in entries:
            action = str(entry.get("action", "")).upper()
            details = entry.get("details", {}) if isinstance(entry.get("details"), dict) else {}
            if action == "ESCALATION_STARTED":
                started_event = entry
                active = True
                chain_snapshot = details.get("steps")
                if isinstance(chain_snapshot, list) and chain_snapshot:
                    step_runtime.clear()
                    for idx, raw in enumerate(chain_snapshot):
                        if not isinstance(raw, dict):
                            continue
                        step_idx = int(raw.get("step_index", idx))
                        step_runtime[step_idx] = {
                            "step_index": step_idx,
                            "name": raw.get("name"),
                            "delay_seconds": int(raw.get("delay_seconds", 0)),
                            "channels": list(raw.get("channels", [])),
                            "recipients": list(raw.get("recipients", [])),
                            "triggered_at": None,
                            "deliveries": [],
                        }
            elif action == "ESCALATION_STEP_TRIGGERED":
                idx = int(details.get("step_index", -1))
                if idx not in step_runtime:
                    step_runtime[idx] = {
                        "step_index": idx,
                        "name": details.get("step_name"),
                        "delay_seconds": int(details.get("delay_seconds", 0)),
                        "channels": list(details.get("channels", [])),
                        "recipients": list(details.get("recipients", [])),
                        "triggered_at": None,
                        "deliveries": [],
                    }
                step_runtime[idx]["triggered_at"] = entry.get("event_timestamp")
            elif action == "ESCALATION_DELIVERY":
                idx = int(details.get("step_index", -1))
                if idx not in step_runtime:
                    step_runtime[idx] = {
                        "step_index": idx,
                        "name": details.get("step_name"),
                        "delay_seconds": int(details.get("delay_seconds", 0)),
                        "channels": [],
                        "recipients": [],
                        "triggered_at": None,
                        "deliveries": [],
                    }
                step_runtime[idx]["deliveries"].append(
                    {
                        "channel": details.get("channel"),
                        "delivery_status": details.get("delivery_status"),
                        "delivery_confirmed": bool(details.get("delivery_confirmed")),
                        "target": details.get("target"),
                        "http_status": details.get("http_status"),
                        "error": details.get("error"),
                        "timestamp": entry.get("event_timestamp"),
                    }
                )
            elif action == "ESCALATION_ACKNOWLEDGED":
                acknowledged = True
                active = False
                resolved = True
                acknowledged_by = entry.get("operator_id")
                acknowledged_at = entry.get("event_timestamp")
                resolution = details.get("resolution") or "ACKNOWLEDGED"
            elif action == "ESCALATION_RESOLVED":
                resolved = True
                active = False
                resolution = details.get("resolution") or "RESOLVED"
            elif action == "ESCALATION_CHAIN_EXHAUSTED":
                exhausted = True
                active = False
                resolution = "CHAIN_EXHAUSTED"
            elif action == "SCENE_CLEARED":
                resolved = True
                active = False
                resolution = resolution or "SCENE_CLEARED"

        steps = sorted(step_runtime.values(), key=lambda item: int(item.get("step_index", 0)))
        with self._escalation_lock:
            runtime = self._active_escalations.get(safe_incident)
        if runtime is not None and not resolved and not acknowledged:
            active = True
            started_event = started_event or {
                "event_timestamp": runtime.get("started_at"),
                "operator_id": runtime.get("started_by"),
                "details": {"source": runtime.get("source"), "reason": runtime.get("reason")},
            }
            for idx in runtime.get("triggered_steps", set()):
                for step in steps:
                    if int(step.get("step_index", -1)) == int(idx) and not step.get("triggered_at"):
                        step["triggered_at"] = self._iso_now()
                        break

        return {
            "incident_id": safe_incident,
            "active": bool(active),
            "acknowledged": bool(acknowledged),
            "resolved": bool(resolved),
            "exhausted": bool(exhausted),
            "started_at": started_event.get("event_timestamp") if isinstance(started_event, dict) else None,
            "started_by": started_event.get("operator_id") if isinstance(started_event, dict) else None,
            "source": (started_event.get("details", {}) or {}).get("source") if isinstance(started_event, dict) else None,
            "reason": (started_event.get("details", {}) or {}).get("reason") if isinstance(started_event, dict) else None,
            "acknowledged_by": acknowledged_by,
            "acknowledged_at": acknowledged_at,
            "resolution": resolution,
            "steps": steps,
            "generated_at": self._iso_now(),
        }

    def _escalation_loop(self) -> None:
        while not self._escalation_stop_event.is_set():
            with self._escalation_lock:
                incident_ids = list(self._active_escalations.keys())
            now_dt = datetime.now(timezone.utc)
            for incident_id in incident_ids:
                with self._escalation_lock:
                    state = self._active_escalations.get(incident_id)
                if state is None:
                    continue
                started_at_dt = state.get("started_at_dt")
                if not isinstance(started_at_dt, datetime):
                    started_at_dt = self._parse_iso_utc(state.get("started_at"))
                elapsed = max(0.0, (now_dt - started_at_dt).total_seconds())
                steps = state.get("steps", [])
                triggered_steps = set(state.get("triggered_steps", set()))
                for idx, step in enumerate(steps):
                    delay_seconds = max(0, int(step.get("delay_seconds", 0)))
                    if idx in triggered_steps:
                        continue
                    if elapsed >= delay_seconds:
                        try:
                            self._trigger_escalation_step(incident_id, state, idx)
                        except Exception as exc:
                            logger.error(
                                "Escalation step trigger failed incident=%s step=%s: %s",
                                incident_id,
                                idx,
                                exc,
                            )
                with self._escalation_lock:
                    current = self._active_escalations.get(incident_id)
                    if current is None:
                        continue
                    current_steps = current.get("steps", [])
                    current_triggered = set(current.get("triggered_steps", set()))
                    if current_steps and len(current_triggered) >= len(current_steps):
                        self._active_escalations.pop(incident_id, None)
                        try:
                            self.audit_store.append_incident_event(
                                incident_id=incident_id,
                                action="ESCALATION_CHAIN_EXHAUSTED",
                                operator_id="system",
                                details={"incident_id": incident_id, "note": "All escalation steps were triggered"},
                                event_timestamp=self._iso_now(),
                            )
                            latest_sos = self.audit_store.latest_sos_event(incident_id)
                            if latest_sos is not None:
                                self.audit_store.update_sos_event(
                                    latest_sos["sos_id"],
                                    {"status": "active", "escalation_status": "chain_exhausted"},
                                )
                            self._emit_system_event(
                                "ESCALATION_UPDATE",
                                {
                                    "incident_id": incident_id,
                                    "status": "chain_exhausted",
                                },
                            )
                        except Exception as exc:
                            logger.error("Failed to append ESCALATION_CHAIN_EXHAUSTED for incident=%s: %s", incident_id, exc)
            self._escalation_stop_event.wait(self.escalation_poll_interval_seconds)

    @staticmethod
    def _bbox_xyxy_from_payload(payload: Dict[str, Any]) -> list[float]:
        raw_xyxy = payload.get("bbox_xyxy")
        if isinstance(raw_xyxy, list) and len(raw_xyxy) == 4:
            values = [float(v) for v in raw_xyxy]
            return values

        raw_bbox = payload.get("bbox")
        if isinstance(raw_bbox, list) and len(raw_bbox) == 4:
            x, y, w, h = [float(v) for v in raw_bbox]
            return [x, y, x + max(0.0, w), y + max(0.0, h)]
        raise ValueError("Detection payload requires bbox_xyxy or bbox")

    def _attach_reid(
        self,
        *,
        payload: Dict[str, Any],
        frame: Optional[np.ndarray],
        source: str,
        zone_key: Optional[str],
        camera_id: Optional[str],
        frame_id: Optional[int],
        timestamp: str,
    ) -> Dict[str, Any]:
        enriched = dict(payload)
        if not self.reid_correlator.enabled:
            return enriched
        label = str(enriched.get("label", "unknown"))
        if not self.reid_correlator.supports_label(label):
            return enriched
        try:
            bbox_xyxy = self._bbox_xyxy_from_payload(enriched)
            reid = self.reid_correlator.observe(
                source=source,
                frame_id=frame_id,
                timestamp=timestamp,
                bbox_xyxy=bbox_xyxy,
                label=label,
                confidence=float(enriched.get("confidence", 0.0)),
                frame=frame,
                zone_key=zone_key,
                camera_id=camera_id,
            )
            predictive = self._analyze_predictive_track(
                track_id=str(reid.get("track_id") or reid.get("threat_id") or ""),
                source=source,
                timestamp=timestamp,
            )
            if isinstance(predictive, dict):
                reid["predictive"] = predictive
                enriched["predictive"] = predictive
            profile = self.track_profile_store.update_track_profile(
                track_id=str(reid.get("track_id") or reid.get("threat_id") or ""),
                zone_key=str(reid.get("zone_key") or zone_key or "zone:unknown"),
                risk_score=float((predictive or {}).get("risk_score", 0.0)),
                timestamp=timestamp,
                behavior_flags=list((predictive or {}).get("behavior_flags", [])) if isinstance(predictive, dict) else [],
            )
            compact_profile = self.track_profile_store.compact_profile(profile)
            if isinstance(compact_profile, dict):
                reid["track_profile"] = compact_profile
                enriched["track_profile"] = compact_profile
            enriched["reid"] = reid
        except Exception as exc:
            logger.warning("ReID correlate failed source=%s frame_id=%s: %s", source, frame_id, exc)
        return enriched

    @staticmethod
    def _packet_reid_summary(det_payloads: list[Dict[str, Any]]) -> Dict[str, Any]:
        threat_ids = []
        cross_camera_matches = 0
        path_points = 0
        for payload in det_payloads:
            reid = payload.get("reid")
            if not isinstance(reid, dict):
                continue
            threat_id = reid.get("track_id") or reid.get("threat_id")
            if threat_id:
                threat_ids.append(str(threat_id))
            if bool(reid.get("cross_camera")):
                cross_camera_matches += 1
            if isinstance(reid.get("path_point"), dict):
                path_points += 1
        unique_ids = sorted(set(threat_ids))
        return {
            "tracks_touched": unique_ids,
            "cross_camera_matches": cross_camera_matches,
            "path_points": path_points,
        }

    @staticmethod
    def _packet_predictive_summary(det_payloads: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
        items: list[Dict[str, Any]] = []
        seen: set[str] = set()
        for payload in det_payloads:
            predictive = payload.get("predictive")
            if not isinstance(predictive, dict):
                reid = payload.get("reid") if isinstance(payload.get("reid"), dict) else {}
                predictive = reid.get("predictive") if isinstance(reid.get("predictive"), dict) else None
            if not isinstance(predictive, dict):
                continue
            track_id = str(
                predictive.get("track_id")
                or predictive.get("threat_id")
                or (payload.get("reid", {}) or {}).get("track_id")
                or (payload.get("reid", {}) or {}).get("threat_id")
                or ""
            ).strip()
            if not track_id or track_id in seen:
                continue
            seen.add(track_id)
            items.append(
                {
                    "track_id": track_id,
                    "risk_score": predictive.get("risk_score"),
                    "risk_level": predictive.get("risk_level"),
                    "current_zone": predictive.get("current_zone") or predictive.get("zone_key"),
                    "behavior_flags": list(predictive.get("behavior_flags", [])),
                    "reason": predictive.get("reason"),
                    "track_profile": dict(payload.get("track_profile", {}))
                    if isinstance(payload.get("track_profile"), dict)
                    else None,
                    "predictive": dict(predictive),
                }
            )
        return items

    def _augment_track_with_predictive(
        self,
        track: Optional[Dict[str, Any]],
        *,
        force: bool = False,
        include_full_profile: bool = False,
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(track, dict):
            return None
        enriched = dict(track)
        if not self.predictive_analyzer.enabled:
            profile = self._track_profile_payload(
                str(enriched.get("track_id") or enriched.get("threat_id") or ""),
                include_full=include_full_profile,
            )
            if isinstance(profile, dict):
                enriched["track_profile"] = profile
            return enriched
        zone_key = str(enriched.get("zone_key") or "zone:unknown").strip() or "zone:unknown"
        zone_policy = None
        try:
            zone_policy = self._zone_policy(zone_key=zone_key, hour_of_day=self._current_local_hour())
        except Exception:
            zone_policy = None
        predictive = self.predictive_analyzer.analyze_track(enriched, zone_policy=zone_policy, force=force)
        if predictive:
            enriched["predictive"] = predictive
        profile = self._track_profile_payload(
            str(enriched.get("track_id") or enriched.get("threat_id") or ""),
            include_full=include_full_profile,
        )
        if isinstance(profile, dict):
            enriched["track_profile"] = profile
        return enriched

    def _track_profile_payload(self, track_id: str, *, include_full: bool = False) -> Optional[Dict[str, Any]]:
        profile = self.track_profile_store.get_track_profile(track_id)
        if not isinstance(profile, dict):
            return None
        if include_full:
            return profile
        return self.track_profile_store.compact_profile(profile)

    @staticmethod
    def _severity_rank(level: str) -> int:
        mapping = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        return mapping.get(str(level or "").upper(), 0)

    @staticmethod
    def _severity_from_rank(rank: int) -> str:
        levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        safe_rank = max(0, min(int(rank), len(levels) - 1))
        return levels[safe_rank]

    def _apply_behavior_profile_to_event(
        self,
        *,
        event: SeverityEvent,
        behavior_profile: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(behavior_profile, dict):
            return None
        behavior_risk = max(0.0, min(1.0, float(behavior_profile.get("behavior_risk_score", 0.0))))
        flags = list(behavior_profile.get("behavior_flags", []))
        context = {
            "track_id": behavior_profile.get("track_id"),
            "current_risk": round(max(0.0, min(1.0, float(event.score))), 4),
            "behavior_risk": round(behavior_risk, 4),
            "avg_risk": round(max(0.0, min(1.0, float(behavior_profile.get("avg_risk_score", 0.0)))), 4),
            "max_risk": round(max(0.0, min(1.0, float(behavior_profile.get("max_risk_score", 0.0)))), 4),
            "flags": flags,
            "visits": int(behavior_profile.get("visit_count", 0) or 0),
            "zones": list(behavior_profile.get("zones", [])),
        }
        if behavior_risk >= max(0.0, min(1.0, self.behavior_alert_escalation_threshold)):
            previous_level = str(event.level or "LOW").upper()
            next_level = self._severity_from_rank(self._severity_rank(previous_level) + 1)
            if next_level != previous_level:
                event.level = next_level
                event.score = max(float(event.score), behavior_risk)
                reason_suffix = "Historical behavior risk elevated alert severity"
                event.reason = f"{event.reason}. {reason_suffix}" if event.reason else reason_suffix
                context["severity_escalated"] = True
                context["previous_level"] = previous_level
                context["new_level"] = next_level
        return context

    def _evaluate_false_positive_filter(
        self,
        *,
        top_weapon: WeaponDetection,
        event: SeverityEvent,
        zone_key: str,
        hour_of_day: int,
        timestamp: str,
        frame_shape: Optional[tuple[int, int]],
        track_id: str = "",
        track: Optional[Dict[str, Any]] = None,
        behavior_profile: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        behavior_risk = 0.0
        if isinstance(behavior_profile, dict):
            behavior_risk = float(behavior_profile.get("behavior_risk_score", 0.0))
        return self.false_positive_filter.evaluate(
            object_type=top_weapon.label,
            confidence=float(top_weapon.confidence),
            severity=str(event.level or "LOW"),
            severity_score=float(event.score),
            bbox_xyxy=list(top_weapon.bbox_xyxy),
            frame_shape=frame_shape,
            zone_key=zone_key,
            hour_of_day=hour_of_day,
            timestamp=timestamp,
            track_id=track_id,
            track=track,
            behavior_risk=behavior_risk,
        )

    def _emit_predictive_pre_alert(
        self,
        *,
        track: Dict[str, Any],
        predictive: Dict[str, Any],
        source: str,
        timestamp: str,
    ) -> Optional[Dict[str, Any]]:
        track_id = str(track.get("track_id") or track.get("threat_id") or "").strip()
        if not track_id or not predictive:
            return None

        alert_id = f"PAL-{uuid.uuid4().hex[:20].upper()}"
        event_level = str(predictive.get("risk_level") or "HIGH").upper()
        risk_score = float(predictive.get("risk_score", 0.0))
        reason = str(predictive.get("reason") or "Predictive threat behavior detected").strip()
        explanation = predictive.get("explanation") if isinstance(predictive.get("explanation"), dict) else {}
        behavior_profile = track.get("track_profile") if isinstance(track.get("track_profile"), dict) else None
        event = SeverityEvent(
            timestamp_sec=float(self._frame_id),
            weapon="predictive",
            action="behavior",
            score=risk_score,
            level=event_level,
            reason=reason,
            explanation=explanation,
        )
        evidence_updates = self._evidence_updates_from_payload(alert_id, {"status": "not_requested"})
        zone_key = str(track.get("zone_key") or predictive.get("zone_key") or self._zone_key(source)).strip() or "zone:default"
        severity_payload = self._severity_to_payload(event)
        alert_payload = {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "source": source,
            "zone_key": zone_key,
            "threat_id": track_id,
            "severity": event_level,
            "event": severity_payload,
            "explanation": explanation,
            "top_weapon": "Predictive Risk",
            "alert_type": "PREDICTIVE_ALERT",
            "predictive": dict(predictive),
            "behavior_context": behavior_profile,
            **evidence_updates,
        }
        persisted_alert = self.notifier.emit(event, payload=alert_payload)
        with self._lock:
            self._alerts.append(dict(persisted_alert))

        audit_details = {
            "source": source,
            "zone_key": zone_key,
            "threat_id": track_id,
            "risk_score": round(risk_score, 4),
            "behavior_flags": list(predictive.get("behavior_flags", [])),
            "behavior_context": behavior_profile,
            "predictive": dict(predictive),
            "event": severity_payload,
        }
        try:
            self.audit_store.append_entry(
                alert_id=alert_id,
                action="PREDICTIVE_ALERT_RAISED",
                operator_id="system",
                details=audit_details,
                event_timestamp=timestamp,
            )
        except Exception as exc:
            logger.error("Failed to append predictive alert audit entry alert_id=%s: %s", alert_id, exc)

        packet = {
            "type": "predictive",
            "timestamp": timestamp,
            "source": source,
            "zone_key": zone_key,
            "alert_id": alert_id,
            "track_id": track_id,
            "risk_score": round(risk_score, 4),
            "risk_level": event_level,
            "reason": reason,
            "behavior_flags": list(predictive.get("behavior_flags", [])),
            "behavior_context": behavior_profile,
            "severity": severity_payload,
            "explanation": explanation,
            "predictive": dict(predictive),
            "alert_type": "PREDICTIVE_ALERT",
        }
        return self._publish_ws_packet(packet)

    def _analyze_predictive_track(
        self,
        *,
        track_id: str,
        source: str,
        timestamp: str,
    ) -> Optional[Dict[str, Any]]:
        safe_track_id = str(track_id or "").strip()
        if not safe_track_id or not self.predictive_analyzer.enabled:
            return None
        track = self.reid_correlator.track(safe_track_id)
        enriched_track = self._augment_track_with_predictive(track, force=False)
        if not isinstance(enriched_track, dict):
            return None
        predictive = enriched_track.get("predictive")
        if not isinstance(predictive, dict):
            return None
        if self.predictive_analyzer.should_emit_pre_alert(safe_track_id, predictive):
            self._emit_predictive_pre_alert(
                track=enriched_track,
                predictive=predictive,
                source=source,
                timestamp=timestamp,
            )
        return predictive

    def _recent_matching_detection_count(
        self,
        *,
        zone_key: str,
        label: str,
        timestamp: str,
    ) -> int:
        safe_zone = str(zone_key or "").strip()
        safe_label = str(label or "").strip().lower()
        if not safe_zone or not safe_label:
            return 1

        now_dt = self._parse_iso_utc(timestamp)
        horizon_seconds = float(self.xai_persistence_window_seconds)
        count = 1
        with self._lock:
            packets = list(self._detections)
        for packet in reversed(packets):
            packet_ts = packet.get("timestamp")
            dt = (now_dt - self._parse_iso_utc(packet_ts)).total_seconds()
            if dt < 0:
                continue
            if dt > horizon_seconds:
                break
            packet_zone = str(packet.get("zone_key") or self._zone_key(str(packet.get("source", ""))))
            if packet_zone != safe_zone:
                continue
            for det in packet.get("detections", []) if isinstance(packet.get("detections"), list) else []:
                if str(det.get("label", "")).strip().lower() == safe_label:
                    count += 1
        return count

    def reid_recent_tracks(self, limit: int = 100, within_seconds: int = 900) -> list[Dict[str, Any]]:
        tracks = self.reid_correlator.recent_tracks(limit=limit, within_seconds=within_seconds)
        return [
            item
            for item in (
                self._augment_track_with_predictive(track, force=False, include_full_profile=False)
                for track in tracks
            )
            if item
        ]

    def reid_track(self, threat_id: str) -> Optional[Dict[str, Any]]:
        return self._augment_track_with_predictive(
            self.reid_correlator.track(threat_id),
            force=False,
            include_full_profile=True,
        )

    def reid_track_path(self, threat_id: str) -> Optional[Dict[str, Any]]:
        return self.reid_correlator.track_path(threat_id)

    def predictive_tracks(self, limit: int = 100, within_seconds: int = 900, high_risk_only: bool = False) -> list[Dict[str, Any]]:
        tracks = self.reid_correlator.recent_tracks(limit=limit, within_seconds=within_seconds)
        items: list[Dict[str, Any]] = []
        for track in tracks:
            enriched = self._augment_track_with_predictive(track, force=False, include_full_profile=False)
            predictive = enriched.get("predictive") if isinstance(enriched, dict) else None
            if not isinstance(predictive, dict):
                continue
            if high_risk_only and not bool(predictive.get("high_risk")):
                continue
            payload = dict(predictive)
            if isinstance(enriched.get("track_profile"), dict):
                payload["track_profile"] = dict(enriched.get("track_profile"))
                payload["behavior_risk_score"] = enriched["track_profile"].get("behavior_risk_score")
            items.append(payload)
        items.sort(
            key=lambda item: (
                float(item.get("behavior_risk_score", item.get("risk_score", 0.0))),
                self._parse_iso_utc(item.get("last_seen")),
            ),
            reverse=True,
        )
        return items[: max(1, min(int(limit), 2000))]

    def track_profile(self, track_id: str) -> Dict[str, Any]:
        profile = self.track_profile_store.get_track_profile(track_id)
        if not isinstance(profile, dict):
            raise ValueError(f"Unknown track_id '{track_id}'")
        current_track = self.reid_track(track_id)
        if isinstance(current_track, dict):
            current_track_payload = dict(current_track)
            current_track_payload["track_profile"] = self.track_profile_store.compact_profile(profile)
            profile["current_track"] = current_track_payload
            profile["current_predictive"] = current_track.get("predictive")
        return profile

    def high_risk_track_profiles(self, limit: int = 100, threshold: Optional[float] = None) -> list[Dict[str, Any]]:
        items = self.track_profile_store.get_high_risk_profiles(limit=limit, threshold=threshold)
        for item in items:
            track_id = str(item.get("track_id") or "").strip()
            if not track_id:
                continue
            current_track = self._augment_track_with_predictive(
                self.reid_correlator.track(track_id),
                force=False,
                include_full_profile=False,
            )
            if isinstance(current_track, dict):
                item["current_track"] = current_track
                item["current_predictive"] = current_track.get("predictive")
        return items

    def correlate_external_detections(
        self,
        *,
        source: str,
        detections: list[Dict[str, Any]],
        frame: Optional[np.ndarray] = None,
        frame_id: Optional[int] = None,
        timestamp: Optional[str] = None,
        zone_key: Optional[str] = None,
        camera_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        safe_source = str(source or "camera:unknown")
        ts = timestamp or self._iso_now()
        safe_camera = str(camera_id or safe_source)
        safe_zone = str(zone_key or self._zone_key(safe_source))
        items: list[Dict[str, Any]] = []
        for det in detections:
            payload = {
                "label": str(det.get("label", "unknown")),
                "confidence": float(det.get("confidence", 0.0)),
            }
            if "bbox_xyxy" in det and isinstance(det["bbox_xyxy"], list) and len(det["bbox_xyxy"]) == 4:
                payload["bbox_xyxy"] = [float(v) for v in det["bbox_xyxy"]]
            elif "bbox" in det and isinstance(det["bbox"], list) and len(det["bbox"]) == 4:
                payload["bbox"] = [float(v) for v in det["bbox"]]
                payload["bbox_xyxy"] = self._bbox_xyxy_from_payload(payload)
            else:
                continue
            payload["bbox_center"] = self._bbox_center_from_xyxy(
                payload["bbox_xyxy"],
                frame_shape=frame.shape[:2] if frame is not None and frame.size > 0 else None,
            )
            enriched = self._attach_reid(
                payload=payload,
                frame=frame,
                source=safe_source,
                zone_key=safe_zone,
                camera_id=safe_camera,
                frame_id=frame_id,
                timestamp=ts,
            )
            items.append(enriched)

        packet = {
            "type": "detection",
            "source": safe_source,
            "camera_id": safe_camera,
            "zone_key": safe_zone,
            "timestamp": ts,
            "frame_id": frame_id,
            "detections": items,
            "correlation": self._packet_reid_summary(items),
            "predictive": self._packet_predictive_summary(items),
        }
        if items:
            packet = self._publish_ws_packet(packet)
            with self._lock:
                self._detections.append(packet)
        return packet

    @staticmethod
    def _parse_iso_utc(value: Optional[str]) -> datetime:
        if not value:
            return datetime.now(timezone.utc)
        text = str(value).strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return datetime.now(timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    @staticmethod
    def _minute_to_hhmm(value: int) -> str:
        total = int(value) % 1440
        hh = total // 60
        mm = total % 60
        return f"{hh:02d}:{mm:02d}"

    @staticmethod
    def _hour_in_window(hour: int, start_hour: Optional[int], end_hour: Optional[int]) -> bool:
        if start_hour is None or end_hour is None:
            return True
        safe_hour = int(hour) % 24
        s = int(start_hour) % 24
        e = int(end_hour) % 24
        if s == e:
            return True
        if s < e:
            return s <= safe_hour < e
        return safe_hour >= s or safe_hour < e

    @staticmethod
    def _latency_percentile(values: list[float], percentile: float) -> float:
        if not values:
            return 0.0
        p = max(0.0, min(float(percentile), 1.0))
        ordered = sorted(values)
        idx = int(round((len(ordered) - 1) * p))
        return float(ordered[idx])

    def shift_windows(self) -> Dict[str, Any]:
        payload = self.audit_store.list_shift_windows()
        items = payload.get("windows", [])
        windows = []
        for item in items:
            windows.append(
                {
                    "name": item["name"],
                    "start_minute": int(item["start_minute"]),
                    "end_minute": int(item["end_minute"]),
                    "start": self._minute_to_hhmm(int(item["start_minute"])),
                    "end": self._minute_to_hhmm(int(item["end_minute"])),
                    "display_order": int(item["display_order"]),
                    "updated_at": item["updated_at"],
                }
            )
        return {"windows": windows, "total": len(windows)}

    def set_shift_windows(self, windows: list[Dict[str, Any]], operator_id: str) -> Dict[str, Any]:
        saved = self.audit_store.replace_shift_windows(windows)
        details = {"windows": saved.get("windows", [])}
        try:
            self.audit_store.append_entry(
                alert_id="POLICY-SHIFT-WINDOWS",
                action="SHIFT_WINDOWS_UPDATED",
                operator_id=operator_id,
                details=details,
                event_timestamp=self._iso_now(),
            )
        except Exception as exc:
            logger.error("Failed to append SHIFT_WINDOWS_UPDATED audit entry: %s", exc)
        return self.shift_windows()

    @staticmethod
    def _shift_for_minute(minute_of_day: int, windows: list[Dict[str, Any]]) -> str:
        for window in windows:
            start = int(window.get("start_minute", 0)) % 1440
            end = int(window.get("end_minute", 0)) % 1440
            name = str(window.get("name", "Unassigned"))
            if start < end and start <= minute_of_day < end:
                return name
            if start > end and (minute_of_day >= start or minute_of_day < end):
                return name
        return "Unassigned"

    def _analytics_time_range(
        self,
        *,
        days: int = 30,
        from_ts: Optional[str] = None,
        to_ts: Optional[str] = None,
    ) -> tuple[datetime, datetime]:
        now_utc = datetime.now(timezone.utc)
        end_dt = self._parse_iso_utc(to_ts) if to_ts else now_utc
        if from_ts:
            start_dt = self._parse_iso_utc(from_ts)
        else:
            safe_days = max(1, min(int(days), 365))
            start_dt = end_dt - timedelta(days=safe_days)
        if start_dt > end_dt:
            start_dt, end_dt = end_dt, start_dt
        return start_dt, end_dt

    def analytics_overview(
        self,
        *,
        days: int = 30,
        from_ts: Optional[str] = None,
        to_ts: Optional[str] = None,
        zone_key: Optional[str] = None,
        hour_start: Optional[int] = None,
        hour_end: Optional[int] = None,
        limit: int = 120000,
    ) -> Dict[str, Any]:
        start_dt, end_dt = self._analytics_time_range(days=days, from_ts=from_ts, to_ts=to_ts)
        local_tz = datetime.now().astimezone().tzinfo or timezone.utc
        shifts = self.shift_windows().get("windows", [])

        alerts = self.audit_store.fetch_entries_by_actions(
            actions=["ALERT_RAISED"],
            from_ts=start_dt.isoformat(),
            to_ts=end_dt.isoformat(),
            limit=limit,
        )["entries"]

        shift_counts: Dict[str, int] = {str(shift["name"]): 0 for shift in shifts}
        zone_counts: Dict[str, int] = {}
        selected_alerts: Dict[str, Dict[str, Any]] = {}

        for entry in alerts:
            details = entry.get("details", {}) if isinstance(entry.get("details"), dict) else {}
            source_zone = str(details.get("zone_key") or details.get("source") or "zone:unknown")
            if zone_key and source_zone != str(zone_key):
                continue
            event_dt_utc = self._parse_iso_utc(entry.get("event_timestamp"))
            local_dt = event_dt_utc.astimezone(local_tz)
            if not self._hour_in_window(local_dt.hour, hour_start, hour_end):
                continue
            minute_of_day = (local_dt.hour * 60) + local_dt.minute
            shift_name = self._shift_for_minute(minute_of_day, shifts)
            shift_counts[shift_name] = int(shift_counts.get(shift_name, 0)) + 1
            zone_counts[source_zone] = int(zone_counts.get(source_zone, 0)) + 1
            selected_alerts[str(entry.get("alert_id", ""))] = {
                "raised_at": event_dt_utc,
                "zone_key": source_zone,
                "threat_id": str(details.get("threat_id", "")).strip() or None,
            }

        total_incidents = sum(shift_counts.values())
        incidents_by_shift = []
        for shift in shifts:
            name = str(shift["name"])
            count = int(shift_counts.get(name, 0))
            incidents_by_shift.append(
                {
                    "name": name,
                    "start": shift["start"],
                    "end": shift["end"],
                    "count": count,
                    "percent": round((count / total_incidents) * 100, 2) if total_incidents > 0 else 0.0,
                }
            )
        if "Unassigned" in shift_counts and shift_counts["Unassigned"] > 0:
            count = int(shift_counts["Unassigned"])
            incidents_by_shift.append(
                {
                    "name": "Unassigned",
                    "start": "-",
                    "end": "-",
                    "count": count,
                    "percent": round((count / total_incidents) * 100, 2) if total_incidents > 0 else 0.0,
                }
            )

        operator_metrics: Dict[str, Dict[str, Any]] = {}
        if selected_alerts:
            operator_actions = self.audit_store.fetch_entries_for_alert_ids(
                alert_ids=list(selected_alerts.keys()),
                actions=["ACKNOWLEDGED", "ESCALATED", "DISMISSED"],
                limit=limit,
            )["entries"]
            earliest_action: Dict[str, Dict[str, Any]] = {}
            for action in operator_actions:
                alert_id = str(action.get("alert_id", "")).strip()
                if not alert_id or alert_id not in selected_alerts:
                    continue
                ts = self._parse_iso_utc(action.get("event_timestamp"))
                prior = earliest_action.get(alert_id)
                if prior is None or ts < prior["timestamp"]:
                    earliest_action[alert_id] = {"timestamp": ts, "action": action}

            for alert_id, payload in earliest_action.items():
                raised_at = selected_alerts[alert_id]["raised_at"]
                latency = (payload["timestamp"] - raised_at).total_seconds()
                if latency < 0:
                    continue
                action = payload["action"]
                operator_id = str(action.get("operator_id", "unknown")).strip() or "unknown"
                metric = operator_metrics.setdefault(
                    operator_id,
                    {"latencies": [], "handled": 0, "acknowledged": 0, "escalated": 0, "dismissed": 0},
                )
                metric["latencies"].append(float(latency))
                metric["handled"] += 1
                kind = str(action.get("action", "")).upper()
                if kind == "ACKNOWLEDGED":
                    metric["acknowledged"] += 1
                elif kind == "ESCALATED":
                    metric["escalated"] += 1
                elif kind == "DISMISSED":
                    metric["dismissed"] += 1

        operator_response = []
        for operator_id, metric in operator_metrics.items():
            latencies = metric["latencies"]
            if not latencies:
                continue
            operator_response.append(
                {
                    "operator_id": operator_id,
                    "handled": int(metric["handled"]),
                    "avg_response_seconds": round(sum(latencies) / len(latencies), 2),
                    "p50_response_seconds": round(self._latency_percentile(latencies, 0.5), 2),
                    "min_response_seconds": round(min(latencies), 2),
                    "max_response_seconds": round(max(latencies), 2),
                    "acknowledged": int(metric["acknowledged"]),
                    "escalated": int(metric["escalated"]),
                    "dismissed": int(metric["dismissed"]),
                }
            )
        operator_response.sort(key=lambda item: (item["avg_response_seconds"], -item["handled"]))

        zone_risk = [{"zone_key": zone, "count": count} for zone, count in zone_counts.items()]
        zone_risk.sort(key=lambda item: item["count"], reverse=True)

        return {
            "generated_at": self._iso_now(),
            "window": {"from": start_dt.isoformat(), "to": end_dt.isoformat()},
            "filters": {
                "zone_key": zone_key,
                "hour_start": hour_start,
                "hour_end": hour_end,
            },
            "shift_windows": shifts,
            "summary": {
                "total_incidents": total_incidents,
                "alerts_considered": len(selected_alerts),
                "operators_with_actions": len(operator_response),
                "zones_in_scope": len(zone_risk),
            },
            "incidents_by_shift": incidents_by_shift,
            "operator_response": operator_response,
            "zone_risk": zone_risk,
        }

    def analytics_heatmap(
        self,
        *,
        days: int = 30,
        from_ts: Optional[str] = None,
        to_ts: Optional[str] = None,
        zone_key: Optional[str] = None,
        limit: int = 120000,
    ) -> Dict[str, Any]:
        start_dt, end_dt = self._analytics_time_range(days=days, from_ts=from_ts, to_ts=to_ts)
        local_tz = datetime.now().astimezone().tzinfo or timezone.utc
        alerts = self.audit_store.fetch_entries_by_actions(
            actions=["ALERT_RAISED"],
            from_ts=start_dt.isoformat(),
            to_ts=end_dt.isoformat(),
            limit=limit,
        )["entries"]

        matrices: Dict[str, list[list[int]]] = {}
        totals: Dict[str, int] = {}
        for entry in alerts:
            details = entry.get("details", {}) if isinstance(entry.get("details"), dict) else {}
            zone = str(details.get("zone_key") or details.get("source") or "zone:unknown")
            if zone_key and zone != str(zone_key):
                continue
            dt_local = self._parse_iso_utc(entry.get("event_timestamp")).astimezone(local_tz)
            dow = int(dt_local.weekday())  # Mon=0
            hour = int(dt_local.hour)
            matrix = matrices.setdefault(zone, [[0 for _ in range(24)] for _ in range(7)])
            matrix[dow][hour] += 1
            totals[zone] = int(totals.get(zone, 0)) + 1

        zones_payload = []
        for zone, matrix in matrices.items():
            max_count = max(max(row) for row in matrix) if matrix else 0
            peak_day = 0
            peak_hour = 0
            peak_value = -1
            for day in range(7):
                for hour in range(24):
                    val = matrix[day][hour]
                    if val > peak_value:
                        peak_value = val
                        peak_day = day
                        peak_hour = hour
            zones_payload.append(
                {
                    "zone_key": zone,
                    "total": int(totals.get(zone, 0)),
                    "matrix": matrix,
                    "max_count": int(max_count),
                    "peak": {
                        "day": self.WEEKDAY_LABELS[peak_day],
                        "hour": peak_hour,
                        "count": int(peak_value if peak_value >= 0 else 0),
                    },
                }
            )
        zones_payload.sort(key=lambda item: item["total"], reverse=True)

        return {
            "generated_at": self._iso_now(),
            "window": {"from": start_dt.isoformat(), "to": end_dt.isoformat()},
            "days_of_week": list(self.WEEKDAY_LABELS),
            "hours": list(range(24)),
            "zones": zones_payload,
            "total_zones": len(zones_payload),
        }

    @staticmethod
    def _timeline_sort_key(event: Dict[str, Any]) -> tuple[datetime, int]:
        ts = RealtimeThreatEngine._parse_iso_utc(event.get("timestamp"))
        order = int(event.get("_order", 0))
        return (ts, order)

    @staticmethod
    def _stringify_details(details: Dict[str, Any]) -> str:
        parts = []
        for key in (
            "weapon",
            "score",
            "level",
            "reason",
            "unit_id",
            "officer_id",
            "eta_minutes",
            "step_name",
            "step_index",
            "delay_seconds",
            "channel",
            "delivery_status",
            "delivery_confirmed",
            "target",
            "resolution",
            "note",
        ):
            value = details.get(key)
            if value is None or value == "":
                continue
            parts.append(f"{key}={value}")
        if not parts:
            if details:
                parts.append(", ".join(f"{k}={v}" for k, v in details.items()))
            else:
                parts.append("-")
        return "; ".join(parts)

    def _resolved_incident_context(self, incident_id: str) -> Dict[str, Any]:
        safe_incident_id = str(incident_id).strip()
        if not safe_incident_id:
            raise ValueError("incident_id is required")

        primary_alert_id: Optional[str] = None
        threat_id: Optional[str] = None
        token_upper = safe_incident_id.upper()
        if token_upper.startswith("THR-"):
            threat_id = safe_incident_id
        elif token_upper.startswith("ALT-"):
            primary_alert_id = safe_incident_id
        else:
            # Flexible mode: treat as threat id first, fallback to alert id.
            if safe_incident_id.lower().startswith("thr-"):
                threat_id = safe_incident_id
            else:
                primary_alert_id = safe_incident_id

        if primary_alert_id and not threat_id:
            context = self.audit_store.get_alert_context(primary_alert_id)
            if context is not None:
                details = context.get("details", {})
                candidate = str(details.get("threat_id", "")).strip()
                if candidate:
                    threat_id = candidate

        related_alert_ids: list[str] = []
        if threat_id:
            related_alert_ids.extend(self.audit_store.alert_ids_by_threat(threat_id))
        if primary_alert_id:
            if primary_alert_id not in related_alert_ids:
                related_alert_ids.append(primary_alert_id)
        if not primary_alert_id and related_alert_ids:
            primary_alert_id = related_alert_ids[0]

        with self._lock:
            mem_alerts = list(self._alerts)
        for alert in mem_alerts:
            alert_id = str(alert.get("alert_id", "")).strip()
            if not alert_id:
                continue
            if threat_id and str(alert.get("threat_id", "")).strip() == threat_id:
                if alert_id not in related_alert_ids:
                    related_alert_ids.append(alert_id)
            if primary_alert_id and alert_id == primary_alert_id and not threat_id:
                mem_threat = str(alert.get("threat_id", "")).strip()
                if mem_threat:
                    threat_id = mem_threat

        return {
            "incident_id": safe_incident_id,
            "primary_alert_id": primary_alert_id,
            "threat_id": threat_id,
            "related_alert_ids": related_alert_ids,
        }

    def add_incident_event(
        self,
        *,
        incident_id: str,
        event_type: str,
        operator_id: str,
        details: Dict[str, Any],
        event_timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        safe_incident_id = str(incident_id).strip()
        if not safe_incident_id:
            raise ValueError("incident_id is required")
        safe_type = str(event_type).strip().upper()
        if safe_type not in self.ALLOWED_INCIDENT_EVENT_TYPES:
            raise ValueError(
                f"Unsupported event_type '{event_type}'. Allowed: {', '.join(sorted(self.ALLOWED_INCIDENT_EVENT_TYPES))}"
            )
        payload = dict(details)
        payload["incident_id"] = safe_incident_id
        entry = self.audit_store.append_incident_event(
            incident_id=safe_incident_id,
            action=safe_type,
            operator_id=operator_id,
            details=payload,
            event_timestamp=event_timestamp or self._iso_now(),
        )
        if safe_type == "SOS_TRIGGERED" and self.escalation_enabled and self.escalation_auto_start_on_sos:
            try:
                self.start_incident_escalation(
                    incident_id=safe_incident_id,
                    operator_id=operator_id,
                    source=str(payload.get("source", "")).strip(),
                    note=str(payload.get("note", "")).strip(),
                    reason="SOS_TRIGGERED",
                    event_timestamp=entry.get("event_timestamp"),
                )
            except Exception as exc:
                logger.error("Failed to auto-start escalation incident=%s: %s", safe_incident_id, exc)
        elif self._is_incident_response_event(safe_type):
            with self._escalation_lock:
                active = safe_incident_id in self._active_escalations
            if active:
                try:
                    self._resolve_escalation(
                        incident_id=safe_incident_id,
                        operator_id=operator_id,
                        resolution=safe_type,
                        note=f"Auto-resolved due to incident event {safe_type}",
                    )
                except Exception as exc:
                    logger.error(
                        "Failed to auto-resolve escalation incident=%s event=%s: %s",
                        safe_incident_id,
                        safe_type,
                        exc,
                    )
        return entry

    def incident_timeline(self, incident_id: str, limit: int = 3000) -> Dict[str, Any]:
        count = max(1, min(int(limit), 20000))
        context = self._resolved_incident_context(incident_id)
        related_alert_ids = list(context["related_alert_ids"])
        threat_id = context["threat_id"]
        primary_alert_id = context["primary_alert_id"]

        alert_entries = self.audit_store.fetch_entries_for_alert_ids(
            alert_ids=related_alert_ids,
            limit=count,
        )["entries"]
        incident_entries = self.audit_store.incident_events(context["incident_id"], limit=count)["entries"]

        with self._lock:
            detection_packets = list(self._detections)

        events: list[Dict[str, Any]] = []
        detection_count = 0
        alert_count = 0
        operator_action_count = 0
        dispatch_count = 0
        escalation_count = 0
        match_source: Optional[str] = None
        match_frame_id: Optional[int] = None
        if not threat_id and primary_alert_id:
            alert_ctx = self.audit_store.get_alert_context(primary_alert_id) or {}
            details = alert_ctx.get("details", {}) if isinstance(alert_ctx, dict) else {}
            match_source = str(details.get("source", "")).strip() or None
            try:
                match_frame_id = int(details.get("frame_id")) if details.get("frame_id") is not None else None
            except (TypeError, ValueError):
                match_frame_id = None

        for packet in detection_packets:
            packet_ts = packet.get("timestamp")
            source = packet.get("source")
            frame_id = packet.get("frame_id")
            detections = packet.get("detections", [])
            if not isinstance(detections, list):
                continue
            for det in detections:
                if not isinstance(det, dict):
                    continue
                reid = det.get("reid", {})
                det_threat_id = str(reid.get("threat_id", "")).strip() if isinstance(reid, dict) else ""
                if threat_id:
                    if det_threat_id != threat_id:
                        continue
                elif primary_alert_id:
                    # If no threat id exists, detections are weakly linked only when alert frame/source matches.
                    if match_source is None or match_frame_id is None:
                        continue
                    if str(source) != match_source or int(frame_id or -1) != match_frame_id:
                        continue
                event = {
                    "timestamp": packet_ts,
                    "category": "DETECTION",
                    "source": source,
                    "operator_id": "system",
                    "title": f"Detection {det.get('label', 'weapon')} confidence={float(det.get('confidence', 0.0)):.3f}",
                    "details": f"frame_id={frame_id}; threat_id={det_threat_id or '-'}",
                    "threat_id": det_threat_id or None,
                    "alert_id": None,
                    "_order": 10,
                }
                events.append(event)
                detection_count += 1

        for entry in alert_entries:
            action = str(entry.get("action", "")).upper()
            details = entry.get("details", {}) if isinstance(entry.get("details"), dict) else {}
            event_ts = entry.get("event_timestamp")
            source = details.get("source") or "-"
            event = {
                "timestamp": event_ts,
                "source": source,
                "operator_id": entry.get("operator_id") or "system",
                "alert_id": entry.get("alert_id"),
                "threat_id": details.get("threat_id"),
                "_order": 20,
            }

            if action == "ALERT_RAISED":
                event.update(
                    {
                        "category": "ALERT",
                        "title": f"Alert raised ({details.get('event', {}).get('level', '-')})",
                        "details": self._stringify_details(details.get("event", {})),
                    }
                )
                alert_count += 1
            elif action in {"ACKNOWLEDGED", "ESCALATED", "DISMISSED"}:
                event.update(
                    {
                        "category": "OPERATOR_ACTION",
                        "title": action.title().replace("_", " "),
                        "details": self._stringify_details(details),
                    }
                )
                operator_action_count += 1
            elif action in {"POLICY_AUTO_TUNED", "POLICY_TUNED"}:
                event.update(
                    {
                        "category": "SYSTEM_POLICY",
                        "title": action.title().replace("_", " "),
                        "details": self._stringify_details(details),
                    }
                )
            else:
                event.update(
                    {
                        "category": "AUDIT_EVENT",
                        "title": action.title().replace("_", " "),
                        "details": self._stringify_details(details),
                    }
                )
            events.append(event)

        for entry in incident_entries:
            action = str(entry.get("action", "")).upper()
            details = entry.get("details", {}) if isinstance(entry.get("details"), dict) else {}
            category = "INCIDENT_EVENT"
            if action in {"SOS_TRIGGERED", "POLICE_DISPATCHED", "OFFICER_DISPATCHED", "OFFICER_ARRIVED", "SCENE_CLEARED"}:
                category = "DISPATCH"
                dispatch_count += 1
            elif action.startswith("ESCALATION_"):
                category = "ESCALATION"
                escalation_count += 1
            event = {
                "timestamp": entry.get("event_timestamp"),
                "category": category,
                "source": details.get("source") or details.get("zone_key") or "-",
                "operator_id": entry.get("operator_id") or "unknown",
                "title": action.title().replace("_", " "),
                "details": self._stringify_details(details),
                "alert_id": None,
                "threat_id": threat_id,
                "_order": 30,
            }
            events.append(event)

        events.sort(key=self._timeline_sort_key)
        if len(events) > count:
            events = events[-count:]

        for event in events:
            event.pop("_order", None)

        return {
            "incident_id": context["incident_id"],
            "primary_alert_id": primary_alert_id,
            "threat_id": threat_id,
            "related_alert_ids": related_alert_ids,
            "generated_at": self._iso_now(),
            "summary": {
                "total_events": len(events),
                "detections": detection_count,
                "alerts": alert_count,
                "operator_actions": operator_action_count,
                "dispatch_events": dispatch_count,
                "escalation_events": escalation_count,
            },
            "events": events,
        }

    def _process_loop(self) -> None:
        processed_frames = 0
        last_action_pred: Optional[ActionPrediction] = None
        self._last_frame_tick = monotonic()

        while not self._stop_event.is_set():
            if self._capture is None:
                sleep(0.05)
                continue

            ok, frame = self._capture.read()
            if not ok:
                if isinstance(self._capture_source, str) and self._loop_video:
                    self._capture.set(cv2.CAP_PROP_POS_FRAMES, 0)
                    continue
                sleep(0.05)
                continue

            tick = monotonic()
            dt = tick - self._last_frame_tick
            if self.edge_enabled and self.edge_max_fps > 0 and dt > 0 and (1.0 / dt) > self.edge_max_fps:
                sleep(max(0.0, (1.0 / self.edge_max_fps) - dt))
                tick = monotonic()
                dt = tick - self._last_frame_tick
            self._last_frame_tick = tick
            if dt > 0:
                inst_fps = 1.0 / dt
                if self._live_fps <= 0:
                    self._live_fps = inst_fps
                else:
                    self._live_fps = (0.9 * self._live_fps) + (0.1 * inst_fps)

            with self._lock:
                self._frame_id += 1
                frame_id = self._frame_id
                self._latest_frame = frame
            frame_timestamp = self._iso_now()

            if self.clip_recorder is not None and self._capture_fps <= 0 and frame_id % 30 == 0:
                self.clip_recorder.update_stream(
                    fps=self._live_fps,
                    width=frame.shape[1],
                    height=frame.shape[0],
                )

            if frame_id % self.action_frame_interval == 0:
                self.clip_buffer.append(frame.copy())

            detections: list[WeaponDetection] = []
            action_payload = None
            severity_payload = None
            det_payloads: list[Dict[str, Any]] = []
            pending_evidence_capture: Optional[Dict[str, Any]] = None

            if frame_id % self.process_every == 0:
                processed_frames += 1
                inference_frame = frame
                if self.edge_enabled and self.edge_input_scale < 1.0:
                    scaled = cv2.resize(
                        frame,
                        dsize=None,
                        fx=self.edge_input_scale,
                        fy=self.edge_input_scale,
                        interpolation=cv2.INTER_LINEAR,
                    )
                    inference_frame = scaled
                detections = self.detector.infer(inference_frame)
                if (
                    self.edge_enabled
                    and self.edge_input_scale < 1.0
                    and inference_frame is not frame
                    and inference_frame.shape[:2] != frame.shape[:2]
                ):
                    scale_x = frame.shape[1] / max(1, inference_frame.shape[1])
                    scale_y = frame.shape[0] / max(1, inference_frame.shape[0])
                    for det in detections:
                        det.bbox_xyxy = [
                            float(det.bbox_xyxy[0]) * scale_x,
                            float(det.bbox_xyxy[1]) * scale_y,
                            float(det.bbox_xyxy[2]) * scale_x,
                            float(det.bbox_xyxy[3]) * scale_y,
                        ]
                packet_timestamp = frame_timestamp

                if (
                    self.action_enabled
                    and self.action_recognizer is not None
                    and detections
                    and len(self.clip_buffer) == self.clip_buffer.maxlen
                    and processed_frames % max(1, self.action_infer_every) == 0
                ):
                    try:
                        last_action_pred = self.action_recognizer.infer(list(self.clip_buffer))
                    except Exception as exc:
                        logger.warning("Action inference failed, skipping clip: %s", exc)

                if last_action_pred is not None:
                    action_payload = {
                        "label": last_action_pred.label,
                        "confidence": round(last_action_pred.confidence, 4),
                    }

                if detections:
                    zone_key = self._zone_key(self._source_name)
                    emitted_alert_id = None
                    explanation_payload = None
                    for det in detections:
                        base_payload = self._weapon_to_payload(det, frame_shape=frame.shape[:2])
                        enriched = self._attach_reid(
                            payload=base_payload,
                            frame=frame,
                            source=self._source_name,
                            zone_key=zone_key,
                            camera_id=self._source_name,
                            frame_id=frame_id,
                            timestamp=packet_timestamp,
                        )
                        det_payloads.append(enriched)

                    top_index = max(range(len(detections)), key=lambda idx: detections[idx].confidence)
                    top_weapon = detections[top_index]
                    top_reid = det_payloads[top_index].get("reid") if top_index < len(det_payloads) else None
                    top_track_id = (
                        str(top_reid.get("track_id") or top_reid.get("threat_id") or "").strip()
                        if isinstance(top_reid, dict)
                        else ""
                    )
                    top_track = self.reid_correlator.track(top_track_id) if top_track_id else None
                    top_behavior_profile = (
                        det_payloads[top_index].get("track_profile")
                        if top_index < len(det_payloads) and isinstance(det_payloads[top_index].get("track_profile"), dict)
                        else None
                    )
                    event = self.fusion.fuse(float(frame_id), top_weapon, last_action_pred)
                    behavior_context = self._apply_behavior_profile_to_event(
                        event=event,
                        behavior_profile=top_behavior_profile,
                    )
                    hour_of_day = self._current_local_hour()
                    zone_policy = self._zone_policy(zone_key=zone_key, hour_of_day=hour_of_day)
                    repeated_count = self._recent_matching_detection_count(
                        zone_key=zone_key,
                        label=top_weapon.label,
                        timestamp=packet_timestamp,
                    )
                    xai_rules = []
                    if repeated_count >= self.xai_persistent_detection_threshold:
                        xai_rules.append("persistent_threat")
                    explanation_payload = self.fusion.explain(
                        weapon=top_weapon,
                        action=last_action_pred,
                        event=event,
                        repeated_count=repeated_count,
                        ml_filter_score=event.score,
                        zone_key=zone_key,
                        rules_triggered=xai_rules,
                    )
                    if isinstance(behavior_context, dict):
                        explanation_payload = {
                            **dict(explanation_payload or {}),
                            "behavior_context": behavior_context,
                        }
                    fp_filter_result = self._evaluate_false_positive_filter(
                        top_weapon=top_weapon,
                        event=event,
                        zone_key=zone_key,
                        hour_of_day=hour_of_day,
                        timestamp=packet_timestamp,
                        frame_shape=frame.shape[:2],
                        track_id=top_track_id,
                        track=top_track,
                        behavior_profile=top_behavior_profile,
                    )
                    fp_filter_decision = str(fp_filter_result.get("decision") or "accepted").strip().lower()
                    if isinstance(fp_filter_result, dict):
                        explanation_payload = {
                            **dict(explanation_payload or {}),
                            "false_positive_filter": {
                                "decision": fp_filter_result.get("decision"),
                                "threat_probability": fp_filter_result.get("threat_probability"),
                                "final_score": fp_filter_result.get("final_score"),
                                "reason": fp_filter_result.get("reason"),
                                "feature_importance": fp_filter_result.get("feature_importance"),
                            },
                        }
                    event.explanation = explanation_payload
                    severity_payload = self._severity_to_payload(event)
                    suppression_reason = None
                    if event.level not in {"HIGH", "MEDIUM", "CRITICAL"}:
                        suppression_reason = "severity_below_alert_threshold"
                    else:
                        suppression_reason = self._suppression_reason(top_weapon.confidence, zone_policy)
                    if suppression_reason is None and fp_filter_decision == "rejected":
                        suppression_reason = "false_positive_rejected"
                    if suppression_reason is None and not self._should_emit_alert(event):
                        suppression_reason = "min_alert_gap"
                    if suppression_reason is None:
                        allowed, rejection_reason = self._allow_alert_flow(zone_key=zone_key, severity=event.level)
                        if not allowed:
                            suppression_reason = rejection_reason
                            if rejection_reason in {"zone_rate_limit", "global_flood_limit"}:
                                self._log_warning(
                                    rejection_reason.upper(),
                                    f"Alert dropped for zone={zone_key} severity={event.level}",
                                    zone_key=zone_key,
                                    severity=event.level,
                                )
                            else:
                                self._log_structured(
                                    level="info",
                                    event="INFO",
                                    type_=rejection_reason.upper(),
                                    message=f"Alert ignored for zone={zone_key} severity={event.level}",
                                    zone_key=zone_key,
                                    severity=event.level,
                                )
                    if suppression_reason is None:
                        alert_id = f"ALT-{uuid.uuid4().hex[:20].upper()}"
                        emitted_alert_id = alert_id
                        evidence_status = "processing" if self._should_capture_evidence(event.level) else "not_requested"
                        evidence_updates = self._evidence_updates_from_payload(
                            alert_id,
                            {"status": evidence_status},
                        )
                        fp_filter_payload = {
                            **dict(fp_filter_result or {}),
                            "alert_id": alert_id,
                        }
                        alert_payload = {
                            "alert_id": alert_id,
                            "timestamp": packet_timestamp,
                            "source": self._source_name,
                            "threat_id": top_reid.get("threat_id") if isinstance(top_reid, dict) else None,
                            "zone_key": zone_key,
                            "hour_of_day": hour_of_day,
                            "effective_threshold": zone_policy.get("effective_threshold"),
                            "frame_id": frame_id,
                            "severity": severity_payload.get("level") if isinstance(severity_payload, dict) else event.level,
                            "confidence": round(float(top_weapon.confidence), 4),
                            "event": severity_payload,
                            "explanation": explanation_payload,
                            "top_weapon": top_weapon.label,
                            "behavior_context": behavior_context,
                            "fp_filter": fp_filter_payload,
                            "threat_probability": fp_filter_payload.get("threat_probability"),
                            "alert_type": (
                                "OPERATOR_REVIEW_ALERT"
                                if fp_filter_payload.get("decision") == "uncertain"
                                else "THREAT_ALERT"
                            ),
                            **evidence_updates,
                        }
                        persisted_alert = self.notifier.emit(event, payload=alert_payload)
                        with self._lock:
                            self._alerts.append(dict(persisted_alert))
                        if evidence_status == "processing":
                            pending_evidence_capture = {
                                "alert_id": alert_id,
                                "timestamp": packet_timestamp,
                                "zone_key": zone_key,
                                "severity": event.level,
                                "source": self._source_name,
                            }
                        try:
                            self.audit_store.append_entry(
                                alert_id=alert_id,
                                action="ALERT_RAISED",
                                operator_id="system",
                                details={
                                    "source": self._source_name,
                                    "zone_key": zone_key,
                                    "hour_of_day": hour_of_day,
                                    "effective_threshold": zone_policy.get("effective_threshold"),
                                    "frame_id": frame_id,
                                    "event": severity_payload,
                                    "explanation": explanation_payload,
                                    "top_weapon": top_weapon.label,
                                    "threat_id": top_reid.get("threat_id") if isinstance(top_reid, dict) else None,
                                    "reid": top_reid if isinstance(top_reid, dict) else None,
                                    "behavior_context": behavior_context,
                                    "fp_filter": fp_filter_payload,
                                    "evidence_status": evidence_status,
                                    "evidence_clip": evidence_updates.get("evidence_clip"),
                                },
                                event_timestamp=packet_timestamp,
                            )
                        except Exception as exc:
                            logger.error("Failed to append alert audit entry alert_id=%s: %s", alert_id, exc)
                        try:
                            persisted_alert["confidence"] = round(float(top_weapon.confidence), 4)
                            if fp_filter_payload.get("decision") == "accepted":
                                self.handle_alert_for_sos(dict(persisted_alert))
                        except Exception as exc:
                            logger.error("Failed to evaluate SOS auto-trigger alert_id=%s: %s", alert_id, exc)
                        self._log_structured(
                            level="info",
                            event="FP_FILTER",
                            type_="FILTER_DECISION",
                            message=f"False-positive filter decision={fp_filter_payload.get('decision')}",
                            alert_id=alert_id,
                            probability=fp_filter_payload.get("threat_probability"),
                            decision=fp_filter_payload.get("decision"),
                        )
                    else:
                        logger.info(
                            "Alert suppressed source=%s zone=%s hour=%s conf=%.3f reason=%s",
                            self._source_name,
                            zone_key,
                            hour_of_day,
                            float(top_weapon.confidence),
                            suppression_reason,
                        )
                        if suppression_reason == "false_positive_rejected":
                            self._log_structured(
                                level="info",
                                event="FP_FILTER",
                                type_="FILTER_REJECTED",
                                message="False-positive filter rejected alert candidate",
                                alert_id=f"candidate:{frame_id}:{zone_key}",
                                probability=fp_filter_result.get("threat_probability"),
                                decision=fp_filter_result.get("decision"),
                            )

                if det_payloads:
                    packet = {
                        "type": "detection",
                        "timestamp": packet_timestamp,
                        "source": self._source_name,
                        "zone_key": zone_key,
                        "alert_id": emitted_alert_id,
                        "frame_id": frame_id,
                        "detections": det_payloads,
                        "action": action_payload,
                        "severity": severity_payload,
                        "explanation": explanation_payload,
                        "fp_filter": fp_filter_result if isinstance(fp_filter_result, dict) else None,
                        "correlation": self._packet_reid_summary(det_payloads),
                        "predictive": self._packet_predictive_summary(det_payloads),
                    }
                    packet = self._publish_ws_packet(packet)
                    with self._lock:
                        self._detections.append(packet)

            annotated = self._draw(frame, detections, action_payload, severity_payload)
            with self._lock:
                self._latest_annotated = annotated
            if pending_evidence_capture is not None and self.clip_recorder is not None:
                started = self.clip_recorder.begin_capture(**pending_evidence_capture)
                if not started:
                    failure_updates = self._evidence_updates_from_payload(
                        pending_evidence_capture["alert_id"],
                        {
                            "status": "not_available",
                            "error": "Evidence not available",
                            "evidence": "NOT_AVAILABLE",
                        },
                    )
                    self._update_alert_evidence_state(pending_evidence_capture["alert_id"], failure_updates)
                    try:
                        self.notifier.update_alert_evidence(
                            alert_id=pending_evidence_capture["alert_id"],
                            evidence_payload=failure_updates,
                        )
                    except Exception as exc:
                        logger.error(
                            "Failed to persist evidence start failure alert_id=%s: %s",
                            pending_evidence_capture["alert_id"],
                            exc,
                        )
            if self.clip_recorder is not None:
                self.clip_recorder.append_frame(
                    frame=annotated,
                    timestamp=frame_timestamp,
                    frame_id=frame_id,
                )

    def _should_emit_alert(self, event: SeverityEvent) -> bool:
        if event.level not in {"HIGH", "MEDIUM", "CRITICAL"}:
            return False
        now = monotonic()
        if now - self._last_alert_at < self.min_alert_gap:
            return False
        self._last_alert_at = now
        return True

    @staticmethod
    def _bbox_center_from_xyxy(
        bbox_xyxy: list[float],
        *,
        frame_shape: Optional[tuple[int, int]] = None,
    ) -> Dict[str, float]:
        x1, y1, x2, y2 = [float(v) for v in bbox_xyxy[:4]]
        cx = (x1 + x2) / 2.0
        cy = (y1 + y2) / 2.0

        if frame_shape is not None and int(frame_shape[0]) > 0 and int(frame_shape[1]) > 0:
            frame_h, frame_w = int(frame_shape[0]), int(frame_shape[1])
            nx = cx / float(frame_w)
            ny = cy / float(frame_h)
        elif max(abs(x1), abs(y1), abs(x2), abs(y2)) <= 1.0:
            nx = cx
            ny = cy
        else:
            nx = 0.5
            ny = 0.5

        return {
            "x": round(max(0.0, min(1.0, nx)), 4),
            "y": round(max(0.0, min(1.0, ny)), 4),
        }

    @classmethod
    def _weapon_to_payload(
        cls,
        det: WeaponDetection,
        *,
        frame_shape: Optional[tuple[int, int]] = None,
    ) -> Dict[str, Any]:
        x1, y1, x2, y2 = [int(round(v)) for v in det.bbox_xyxy]
        w = max(1, x2 - x1)
        h = max(1, y2 - y1)
        return {
            "label": det.label,
            "confidence": round(det.confidence, 4),
            "bbox": [x1, y1, w, h],
            "bbox_xyxy": [x1, y1, x2, y2],
            "bbox_center": cls._bbox_center_from_xyxy([x1, y1, x2, y2], frame_shape=frame_shape),
        }

    @staticmethod
    def _severity_to_payload(event: SeverityEvent) -> Dict[str, Any]:
        return {
            "weapon": event.weapon,
            "action": event.action,
            "score": round(event.score, 4),
            "level": event.level,
            "reason": event.reason,
            "timestamp_sec": round(event.timestamp_sec, 3),
            "explanation": dict(event.explanation) if isinstance(event.explanation, dict) else {},
        }

    @staticmethod
    def _draw(
        frame: np.ndarray,
        detections: list[WeaponDetection],
        action_payload: Optional[Dict[str, Any]],
        severity_payload: Optional[Dict[str, Any]],
    ) -> np.ndarray:
        canvas = frame.copy()

        for det in detections:
            x1, y1, x2, y2 = [int(round(v)) for v in det.bbox_xyxy]
            cv2.rectangle(canvas, (x1, y1), (x2, y2), (0, 0, 255), 2)
            cv2.putText(
                canvas,
                f"{det.label}:{det.confidence:.2f}",
                (x1, max(20, y1 - 8)),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.6,
                (0, 0, 255),
                2,
            )

        line_y = 24
        if action_payload is not None:
            cv2.putText(
                canvas,
                f"ACTION {action_payload['label']}:{action_payload['confidence']:.2f}",
                (10, line_y),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.6,
                (0, 255, 255),
                2,
            )
            line_y += 26

        if severity_payload is not None:
            cv2.putText(
                canvas,
                f"SEVERITY {severity_payload['level']}:{severity_payload['score']:.2f}",
                (10, line_y),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.7,
                (0, 255, 0),
                2,
            )

        return canvas
