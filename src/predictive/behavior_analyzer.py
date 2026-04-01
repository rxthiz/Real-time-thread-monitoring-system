import re
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from time import monotonic
from typing import Any, Deque, Dict, List, Optional

from src.predictive.pattern_detector import (
    circular_stats,
    current_zone_duration_seconds,
    pacing_stats,
    parse_iso,
    speed_stats,
    zone_transition_stats,
)
from src.predictive.anomaly_detector import AnomalyDetector
from src.predictive.risk_model import PredictiveRiskModel


class BehaviorAnalyzer:
    def __init__(self, cfg: Dict[str, Any]) -> None:
        predictive_cfg = cfg.get("predictive", {})
        reid_cfg = cfg.get("reid", {})
        self.enabled = bool(predictive_cfg.get("enabled", True))
        self.analysis_window_seconds = max(30.0, float(predictive_cfg.get("analysis_window_seconds", 180.0)))
        self.update_interval_seconds = max(0.05, float(predictive_cfg.get("update_interval_seconds", 0.35)))
        self.track_retention_seconds = max(
            self.analysis_window_seconds,
            float(predictive_cfg.get("track_retention_seconds", reid_cfg.get("track_retention_seconds", 120.0))),
        )
        self.smoothing_window = max(1, int(predictive_cfg.get("smoothing_window", 6)))
        self.loitering_seconds = max(10.0, float(predictive_cfg.get("loitering_seconds", 90.0)))
        self.transition_window_seconds = max(15.0, float(predictive_cfg.get("transition_window_seconds", 120.0)))
        self.transition_count_threshold = max(1, int(predictive_cfg.get("transition_count_threshold", 4)))
        self.pacing_switch_threshold = max(2, int(predictive_cfg.get("pacing_switch_threshold", 3)))
        self.circular_close_ratio = max(0.05, float(predictive_cfg.get("circular_close_ratio", 0.35)))
        self.min_circular_distance = max(0.05, float(predictive_cfg.get("min_circular_distance", 0.85)))
        self.speed_threshold = max(0.05, float(predictive_cfg.get("speed_threshold", 0.55)))
        self.acceleration_threshold = max(0.05, float(predictive_cfg.get("acceleration_threshold", 0.65)))
        self.medium_risk_threshold = float(predictive_cfg.get("medium_risk_threshold", 0.45))
        self.high_risk_threshold = float(predictive_cfg.get("high_risk_threshold", 0.70))
        self.pre_alert_threshold = float(predictive_cfg.get("pre_alert_threshold", 0.85))
        self.pre_alert_clear_threshold = float(predictive_cfg.get("pre_alert_clear_threshold", 0.58))
        raw_restricted_zones = predictive_cfg.get("restricted_zones", [])
        self.restricted_zones = {
            str(zone_key).strip()
            for zone_key in raw_restricted_zones
            if str(zone_key).strip()
        }
        raw_zone_weights = predictive_cfg.get("zone_weights", {}) if isinstance(predictive_cfg.get("zone_weights", {}), dict) else {}
        self.zone_weights = {
            str(zone_key).strip(): max(0.0, min(1.0, float(weight)))
            for zone_key, weight in raw_zone_weights.items()
            if str(zone_key).strip()
        }
        raw_target_labels = predictive_cfg.get("target_labels", reid_cfg.get("target_labels", []))
        self.target_labels = tuple(
            self._normalize_label(label)
            for label in raw_target_labels
            if self._normalize_label(label)
        )
        self.risk_model = PredictiveRiskModel(cfg)
        self.anomaly_detector = AnomalyDetector(cfg)

        self._lock = Lock()
        self._state: Dict[str, Dict[str, Any]] = {}
        self._last_prune_tick = monotonic()

    @staticmethod
    def _normalize_label(value: Any) -> str:
        token = re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower())
        return token.strip("_")

    def _supports_track(self, track: Dict[str, Any]) -> bool:
        if not self.target_labels:
            return True
        labels = track.get("labels") if isinstance(track.get("labels"), dict) else {}
        normalized = [self._normalize_label(name) for name in labels]
        for label in normalized:
            if not label:
                continue
            for target in self.target_labels:
                if label == target or label.startswith(f"{target}_") or label.endswith(f"_{target}") or f"_{target}_" in label:
                    return True
        return False

    @staticmethod
    def _human_duration(seconds: float) -> str:
        value = max(0.0, float(seconds or 0.0))
        if value >= 60.0:
            return f"{value / 60.0:.1f} min"
        return f"{value:.0f} s"

    def _zone_sensitivity(self, zone_key: str, zone_policy: Optional[Dict[str, Any]]) -> float:
        score = max(0.0, min(1.0, float(self.zone_weights.get(str(zone_key).strip(), 0.0))))
        if str(zone_key).strip() in self.restricted_zones:
            score = max(score, 1.0)
        if isinstance(zone_policy, dict):
            threshold = zone_policy.get("effective_threshold")
            if threshold is None:
                threshold = zone_policy.get("adaptive_threshold")
            if threshold is not None:
                score = max(score, max(0.0, min(1.0, 1.0 - float(threshold))))
        return round(score, 4)

    def _reason_text(
        self,
        *,
        zone_key: str,
        loitering_duration: float,
        transition_count: int,
        pacing_score_value: float,
        circular_score_value: float,
        speed_score_value: float,
        zone_weight: float,
        flags: List[str],
    ) -> str:
        reasons: List[str] = []
        if "loitering" in flags:
            if zone_weight >= 0.8:
                reasons.append(f"Loitering in restricted zone for {self._human_duration(loitering_duration)}")
            else:
                reasons.append(f"Loitering for {self._human_duration(loitering_duration)}")
        if "repeated_zone_transitions" in flags:
            reasons.append(f"Repeated zone transitions ({transition_count})")
        if "pacing" in flags:
            reasons.append("Pacing / back-and-forth movement")
        if "circular_movement" in flags:
            reasons.append("Circular movement pattern")
        if "sudden_speed" in flags:
            reasons.append("Sudden speed increase")
        if "anomalous_pattern" in flags:
            reasons.append("Anomalous movement signature")
        if "restricted_zone" in flags and not any("restricted zone" in reason.lower() for reason in reasons):
            reasons.append(f"Sensitive zone activity in {zone_key}")
        return " + ".join(reasons[:3]) if reasons else "Behavior pattern within normal range"

    def _summary_text(self, *, risk_score: float, risk_level: str, flags: List[str], zone_key: str) -> str:
        if not flags:
            return f"Track activity in {zone_key} remains low risk."
        label = str(risk_level or "LOW").title()
        joined = ", ".join(flag.replace("_", " ") for flag in flags[:3])
        return f"{label} predictive risk due to {joined} in {zone_key}."

    def _prune_locked(self) -> None:
        now_tick = monotonic()
        if now_tick - self._last_prune_tick < 10.0:
            return
        self._last_prune_tick = now_tick
        now_dt = datetime.now(timezone.utc)
        drop_ids: List[str] = []
        for track_id, state in self._state.items():
            last_seen = parse_iso(state.get("last_seen"))
            age = (now_dt - last_seen).total_seconds()
            if age > self.track_retention_seconds:
                drop_ids.append(track_id)
        for track_id in drop_ids:
            self._state.pop(track_id, None)

    def analyze_track(
        self,
        track: Dict[str, Any],
        *,
        zone_policy: Optional[Dict[str, Any]] = None,
        force: bool = False,
    ) -> Dict[str, Any]:
        if not self.enabled:
            return {}

        safe_track = dict(track or {})
        track_id = str(safe_track.get("track_id") or safe_track.get("threat_id") or "").strip()
        if not track_id:
            return {}
        if not self._supports_track(safe_track):
            return {}

        now_tick = monotonic()
        with self._lock:
            self._prune_locked()
            state = self._state.setdefault(
                track_id,
                {
                    "scores": deque(maxlen=self.smoothing_window),
                    "last_analysis_tick": 0.0,
                    "analysis": None,
                    "pre_alert_active": False,
                    "last_seen": safe_track.get("last_seen"),
                },
            )
            if (
                not force
                and state.get("analysis") is not None
                and (now_tick - float(state.get("last_analysis_tick", 0.0))) < self.update_interval_seconds
            ):
                return dict(state["analysis"])

        path = list(safe_track.get("path", [])) if isinstance(safe_track.get("path"), list) else []
        current_zone = str(safe_track.get("zone_key") or (path[-1].get("zone_key") if path else "zone:unknown")).strip() or "zone:unknown"
        last_seen = str(safe_track.get("last_seen") or safe_track.get("last_seen_at") or "").strip() or datetime.now(timezone.utc).isoformat()
        created_at = str(safe_track.get("created_at") or "").strip() or (path[0].get("ts") if path else last_seen)
        loitering_duration = current_zone_duration_seconds(path, default_start_ts=created_at)
        if loitering_duration <= 0.0 and created_at:
            loitering_duration = max(0.0, (parse_iso(last_seen) - parse_iso(created_at)).total_seconds()) if len(set(point.get("zone_key") for point in path if point.get("zone_key"))) <= 1 else 0.0
        loitering_score = min(1.0, loitering_duration / max(self.loitering_seconds, 1.0))

        transition_stats = zone_transition_stats(
            path,
            within_seconds=self.transition_window_seconds,
            transition_threshold=self.transition_count_threshold,
        )
        pacing = pacing_stats(
            path,
            within_seconds=self.analysis_window_seconds,
            switch_threshold=self.pacing_switch_threshold,
        )
        circular = circular_stats(
            path,
            within_seconds=self.analysis_window_seconds,
            min_distance=self.min_circular_distance,
            close_ratio=self.circular_close_ratio,
        )
        speed = speed_stats(
            path,
            within_seconds=self.analysis_window_seconds,
            speed_threshold=self.speed_threshold,
            acceleration_threshold=self.acceleration_threshold,
        )
        movement_score = max(float(pacing.get("score", 0.0)), float(circular.get("score", 0.0)))
        zone_weight = self._zone_sensitivity(current_zone, zone_policy)
        anomaly_result = self.anomaly_detector.score(
            {
                "loitering": loitering_score,
                "movement": movement_score,
                "transitions": float(transition_stats.get("score", 0.0)),
                "speed": float(speed.get("score", 0.0)),
                "zone_sensitivity": zone_weight,
            }
        )
        anomaly_score = float(anomaly_result.get("anomaly_score", 0.0))

        score_payload = self.risk_model.score(
            loitering_score=loitering_score,
            movement_score=movement_score,
            transition_score=float(transition_stats.get("score", 0.0)),
            speed_score=float(speed.get("score", 0.0)),
            zone_weight=zone_weight,
            anomaly_score=anomaly_score,
            factor_values={
                "loitering": self._human_duration(loitering_duration),
                "movement": f"pacing={float(pacing.get('score', 0.0)):.2f}, circular={float(circular.get('score', 0.0)):.2f}",
                "transitions": int(transition_stats.get("transition_count", 0)),
                "speed": f"max={float(speed.get('max_speed', 0.0)):.2f}/s",
                "zone_sensitivity": current_zone,
                "anomaly": f"score={anomaly_score:.3f}",
            },
        )

        with self._lock:
            state = self._state.setdefault(
                track_id,
                {
                    "scores": deque(maxlen=self.smoothing_window),
                    "last_analysis_tick": 0.0,
                    "analysis": None,
                    "pre_alert_active": False,
                    "last_seen": last_seen,
                },
            )
            scores: Deque[float] = state["scores"]
            scores.append(float(score_payload["risk_score_raw"]))
            smoothed_score = round(sum(scores) / len(scores), 4)
            risk_level = self.risk_model.risk_level(smoothed_score)
            high_risk = smoothed_score >= self.high_risk_threshold
            pre_alert = smoothed_score >= self.pre_alert_threshold

            flags: List[str] = []
            if loitering_score >= 0.55:
                flags.append("loitering")
            if float(transition_stats.get("score", 0.0)) >= 0.50:
                flags.append("repeated_zone_transitions")
            if float(pacing.get("score", 0.0)) >= 0.45:
                flags.append("pacing")
            if float(circular.get("score", 0.0)) >= 0.45:
                flags.append("circular_movement")
            if float(speed.get("score", 0.0)) >= 0.50:
                flags.append("sudden_speed")
            if bool(anomaly_result.get("is_anomaly")) or anomaly_score >= 0.75:
                flags.append("anomalous_pattern")
            if zone_weight >= 0.75:
                flags.append("restricted_zone")

            reason = self._reason_text(
                zone_key=current_zone,
                loitering_duration=loitering_duration,
                transition_count=int(transition_stats.get("transition_count", 0)),
                pacing_score_value=float(pacing.get("score", 0.0)),
                circular_score_value=float(circular.get("score", 0.0)),
                speed_score_value=float(speed.get("score", 0.0)),
                zone_weight=zone_weight,
                flags=flags,
            )
            summary = self._summary_text(
                risk_score=smoothed_score,
                risk_level=risk_level,
                flags=flags,
                zone_key=current_zone,
            )

            explanation = {
                "reason": reason,
                "summary": summary,
                "factors": list(score_payload.get("factors", [])),
                "model_breakdown": dict(score_payload.get("model_breakdown", {})),
                "feature_importance": list(score_payload.get("feature_importance", [])),
                "final_score": smoothed_score,
                "severity": risk_level,
                "anomaly_detection": dict(anomaly_result),
            }

            analysis = {
                "track_id": track_id,
                "threat_id": track_id,
                "timestamp": last_seen,
                "last_seen": last_seen,
                "current_zone": current_zone,
                "zone_key": current_zone,
                "camera_id": safe_track.get("camera_id"),
                "duration": round(loitering_duration, 3),
                "risk_score": smoothed_score,
                "risk_score_raw": float(score_payload["risk_score_raw"]),
                "risk_level": risk_level,
                "high_risk": high_risk,
                "pre_alert": pre_alert,
                "behavior_flags": flags,
                "reason": reason,
                "summary": summary,
                "factors": explanation["factors"],
                "model_breakdown": explanation["model_breakdown"],
                "feature_importance": explanation["feature_importance"],
                "anomaly": dict(anomaly_result),
                "explanation": explanation,
                "metrics": {
                    "loitering_duration_seconds": round(loitering_duration, 3),
                    "transition_count": int(transition_stats.get("transition_count", 0)),
                    "pacing_score": float(pacing.get("score", 0.0)),
                    "circular_score": float(circular.get("score", 0.0)),
                    "speed_score": float(speed.get("score", 0.0)),
                    "max_speed": float(speed.get("max_speed", 0.0)),
                    "max_acceleration": float(speed.get("max_acceleration", 0.0)),
                    "zone_weight": zone_weight,
                    "anomaly_score": anomaly_score,
                    "anomaly_backend": anomaly_result.get("backend"),
                    "anomaly_ready": bool(anomaly_result.get("ready")),
                },
            }
            state["analysis"] = analysis
            state["last_analysis_tick"] = now_tick
            state["last_seen"] = last_seen
            return dict(analysis)

    def should_emit_pre_alert(self, track_id: str, analysis: Dict[str, Any]) -> bool:
        safe_track_id = str(track_id or "").strip()
        if not safe_track_id or not analysis:
            return False
        with self._lock:
            state = self._state.setdefault(
                safe_track_id,
                {
                    "scores": deque(maxlen=self.smoothing_window),
                    "last_analysis_tick": 0.0,
                    "analysis": dict(analysis),
                    "pre_alert_active": False,
                    "last_seen": analysis.get("last_seen"),
                },
            )
            risk_score = float(analysis.get("risk_score", 0.0))
            if risk_score < self.pre_alert_clear_threshold:
                state["pre_alert_active"] = False
                return False
            if not bool(analysis.get("pre_alert")):
                return False
            if bool(state.get("pre_alert_active")):
                return False
            state["pre_alert_active"] = True
            return True

    def recent_tracks(self, *, limit: int = 100, within_seconds: int = 900, high_risk_only: bool = False) -> List[Dict[str, Any]]:
        count = max(1, min(int(limit), 2000))
        horizon = max(10, min(int(within_seconds), 24 * 3600))
        now_dt = datetime.now(timezone.utc)
        with self._lock:
            self._prune_locked()
            items: List[Dict[str, Any]] = []
            for state in self._state.values():
                analysis = state.get("analysis")
                if not isinstance(analysis, dict):
                    continue
                age = (now_dt - parse_iso(analysis.get("last_seen"))).total_seconds()
                if age > horizon:
                    continue
                if high_risk_only and not bool(analysis.get("high_risk")):
                    continue
                items.append(dict(analysis))
        items.sort(key=lambda item: parse_iso(item.get("last_seen")), reverse=True)
        return items[:count]
