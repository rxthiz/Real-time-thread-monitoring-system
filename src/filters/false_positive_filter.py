import json
import logging
import sqlite3
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Optional

import numpy as np

logger = logging.getLogger(__name__)


class FalsePositiveFilter:
    FEATURE_NAMES = [
        "bias",
        "confidence",
        "severity_score",
        "bbox_area",
        "motion_intensity",
        "duration_norm",
        "smoothed_score",
        "behavior_risk",
        "persistence_ratio",
        "object_gun",
        "object_knife",
        "object_stick",
        "object_other",
        "zone_high_risk",
        "zone_public",
        "zone_low_risk",
        "time_night",
        "time_day",
        "time_evening",
    ]

    DEFAULT_WEIGHTS = {
        "bias": -1.20,
        "confidence": 1.80,
        "severity_score": 1.35,
        "bbox_area": 0.70,
        "motion_intensity": 0.60,
        "duration_norm": 0.90,
        "smoothed_score": 1.10,
        "behavior_risk": 0.95,
        "persistence_ratio": 1.05,
        "object_gun": 0.50,
        "object_knife": 0.25,
        "object_stick": -0.05,
        "object_other": -0.20,
        "zone_high_risk": 0.30,
        "zone_public": 0.00,
        "zone_low_risk": -0.20,
        "time_night": 0.15,
        "time_day": -0.05,
        "time_evening": 0.05,
    }

    def __init__(self, cfg: Dict[str, Any], *, db_path: str | Path) -> None:
        fp_cfg = cfg.get("false_positive_filter", {}) if isinstance(cfg.get("false_positive_filter", {}), dict) else {}
        predictive_cfg = cfg.get("predictive", {}) if isinstance(cfg.get("predictive", {}), dict) else {}

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.enabled = bool(fp_cfg.get("enabled", True))
        self.smoothing_window = max(2, int(fp_cfg.get("smoothing_window", 5)))
        self.min_frames = max(1, int(fp_cfg.get("min_frames", 5)))
        self.temporal_reset_seconds = max(1.0, float(fp_cfg.get("temporal_reset_seconds", 8.0)))
        self.final_score_rule_weight = max(0.0, min(1.0, float(fp_cfg.get("rule_score_weight", 0.6))))
        self.final_score_ml_weight = max(0.0, min(1.0, float(fp_cfg.get("ml_probability_weight", 0.4))))
        if (self.final_score_rule_weight + self.final_score_ml_weight) <= 0:
            self.final_score_rule_weight = 0.6
            self.final_score_ml_weight = 0.4
        else:
            total = self.final_score_rule_weight + self.final_score_ml_weight
            self.final_score_rule_weight /= total
            self.final_score_ml_weight /= total
        self.fail_safe_confidence = max(0.0, min(1.0, float(fp_cfg.get("fail_safe_confidence", 0.9))))
        self.fail_safe_severity = str(fp_cfg.get("fail_safe_severity", "CRITICAL")).strip().upper() or "CRITICAL"
        self.min_feedback_samples = max(4, int(fp_cfg.get("min_feedback_samples", 8)))
        self.learning_rate = max(0.0001, float(fp_cfg.get("learning_rate", 0.25)))
        self.training_epochs = max(40, int(fp_cfg.get("training_epochs", 180)))
        self.l2_penalty = max(0.0, float(fp_cfg.get("l2_penalty", 0.01)))
        self.hard_negative_weight = max(1.0, float(fp_cfg.get("hard_negative_weight", 1.8)))
        self.hard_negative_threshold = max(0.0, min(1.0, float(fp_cfg.get("hard_negative_threshold", 0.7))))
        self.classifier_name = "custom_logistic_regression"

        zone_thresholds = fp_cfg.get("zone_thresholds", {}) if isinstance(fp_cfg.get("zone_thresholds", {}), dict) else {}
        self.zone_thresholds = {
            "high_risk": self._normalize_threshold_pair(zone_thresholds.get("high_risk"), accept=0.6, uncertain=0.4),
            "public": self._normalize_threshold_pair(zone_thresholds.get("public"), accept=0.7, uncertain=0.4),
            "low_risk": self._normalize_threshold_pair(zone_thresholds.get("low_risk"), accept=0.8, uncertain=0.55),
        }
        self.zone_type_overrides = {
            str(zone_key).strip(): str(zone_type).strip().lower()
            for zone_key, zone_type in (fp_cfg.get("zone_types", {}) if isinstance(fp_cfg.get("zone_types", {}), dict) else {}).items()
            if str(zone_key).strip() and str(zone_type).strip()
        }
        self.high_risk_zones = {
            str(zone).strip()
            for zone in fp_cfg.get("high_risk_zones", [])
            if str(zone).strip()
        }
        self.low_risk_zones = {
            str(zone).strip()
            for zone in fp_cfg.get("low_risk_zones", [])
            if str(zone).strip()
        }
        self.restricted_zones = {
            str(zone).strip()
            for zone in predictive_cfg.get("restricted_zones", [])
            if str(zone).strip()
        }

        self._lock = Lock()
        self._temporal_state: Dict[str, Dict[str, Any]] = {}
        self._model_state: Dict[str, Any] = {}
        self._init_schema()
        self._load_model_state()

    @staticmethod
    def _iso_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _parse_iso(value: Optional[str]) -> datetime:
        if not value:
            return datetime.now(timezone.utc)
        text = str(value).strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return datetime.now(timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    @staticmethod
    def _clamp01(value: Any) -> float:
        try:
            score = float(value)
        except (TypeError, ValueError):
            score = 0.0
        return max(0.0, min(1.0, score))

    @staticmethod
    def _normalize_threshold_pair(value: Any, *, accept: float, uncertain: float) -> Dict[str, float]:
        if not isinstance(value, dict):
            return {"accept": accept, "uncertain": uncertain}
        accept_value = max(0.0, min(1.0, float(value.get("accept", accept))))
        uncertain_value = max(0.0, min(accept_value, float(value.get("uncertain", uncertain))))
        return {"accept": accept_value, "uncertain": uncertain_value}

    @staticmethod
    def _sigmoid(values: np.ndarray) -> np.ndarray:
        clipped = np.clip(values, -20.0, 20.0)
        return 1.0 / (1.0 + np.exp(-clipped))

    @staticmethod
    def _safe_object_type(label: Any) -> str:
        token = str(label or "other").strip().lower()
        if token in {"gun", "knife", "stick"}:
            return token
        return "other"

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS fp_feedback (
                  alert_id TEXT PRIMARY KEY,
                  operator_id TEXT NOT NULL,
                  label INTEGER NOT NULL CHECK(label IN (0, 1)),
                  features_json TEXT NOT NULL,
                  decision TEXT NOT NULL,
                  probability REAL NOT NULL,
                  final_score REAL NOT NULL,
                  hard_negative INTEGER NOT NULL DEFAULT 0,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS fp_model_state (
                  id INTEGER PRIMARY KEY CHECK(id = 1),
                  classifier_name TEXT NOT NULL,
                  weights_json TEXT NOT NULL,
                  feature_names_json TEXT NOT NULL,
                  metrics_json TEXT NOT NULL,
                  trained INTEGER NOT NULL DEFAULT 0,
                  sample_count INTEGER NOT NULL DEFAULT 0,
                  positive_count INTEGER NOT NULL DEFAULT 0,
                  negative_count INTEGER NOT NULL DEFAULT 0,
                  hard_negative_count INTEGER NOT NULL DEFAULT 0,
                  training_revision INTEGER NOT NULL DEFAULT 0,
                  last_trained_at TEXT,
                  updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def _default_model_state(self) -> Dict[str, Any]:
        weights = {name: float(self.DEFAULT_WEIGHTS.get(name, 0.0)) for name in self.FEATURE_NAMES}
        return {
            "classifier_name": self.classifier_name,
            "weights": weights,
            "feature_names": list(self.FEATURE_NAMES),
            "metrics": {},
            "trained": False,
            "sample_count": 0,
            "positive_count": 0,
            "negative_count": 0,
            "hard_negative_count": 0,
            "training_revision": 0,
            "last_trained_at": None,
            "updated_at": self._iso_now(),
        }

    def _load_model_state(self) -> None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM fp_model_state WHERE id = 1").fetchone()
            if row is None:
                state = self._default_model_state()
                conn.execute(
                    """
                    INSERT INTO fp_model_state (
                      id, classifier_name, weights_json, feature_names_json, metrics_json, trained,
                      sample_count, positive_count, negative_count, hard_negative_count,
                      training_revision, last_trained_at, updated_at
                    ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        state["classifier_name"],
                        json.dumps(state["weights"]),
                        json.dumps(state["feature_names"]),
                        json.dumps(state["metrics"]),
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        None,
                        state["updated_at"],
                    ),
                )
                conn.commit()
                self._model_state = state
                return
        weights = json.loads(row["weights_json"]) if row else {}
        self._model_state = {
            "classifier_name": row["classifier_name"],
            "weights": {
                name: float(weights.get(name, self.DEFAULT_WEIGHTS.get(name, 0.0)))
                for name in self.FEATURE_NAMES
            },
            "feature_names": json.loads(row["feature_names_json"]),
            "metrics": json.loads(row["metrics_json"]),
            "trained": bool(row["trained"]),
            "sample_count": int(row["sample_count"]),
            "positive_count": int(row["positive_count"]),
            "negative_count": int(row["negative_count"]),
            "hard_negative_count": int(row["hard_negative_count"]),
            "training_revision": int(row["training_revision"]),
            "last_trained_at": row["last_trained_at"],
            "updated_at": row["updated_at"],
        }

    def _save_model_state_locked(self, state: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE fp_model_state
                SET
                  classifier_name = ?,
                  weights_json = ?,
                  feature_names_json = ?,
                  metrics_json = ?,
                  trained = ?,
                  sample_count = ?,
                  positive_count = ?,
                  negative_count = ?,
                  hard_negative_count = ?,
                  training_revision = ?,
                  last_trained_at = ?,
                  updated_at = ?
                WHERE id = 1
                """,
                (
                    state["classifier_name"],
                    json.dumps(state["weights"]),
                    json.dumps(state["feature_names"]),
                    json.dumps(state["metrics"]),
                    1 if state["trained"] else 0,
                    int(state["sample_count"]),
                    int(state["positive_count"]),
                    int(state["negative_count"]),
                    int(state["hard_negative_count"]),
                    int(state["training_revision"]),
                    state["last_trained_at"],
                    state["updated_at"],
                ),
            )
            conn.commit()
        self._model_state = dict(state)

    def _zone_type(self, zone_key: str) -> str:
        safe_zone = str(zone_key or "zone:default").strip() or "zone:default"
        override = self.zone_type_overrides.get(safe_zone)
        if override in {"high_risk", "low_risk", "public"}:
            return override
        if safe_zone in self.restricted_zones or safe_zone in self.high_risk_zones:
            return "high_risk"
        if safe_zone in self.low_risk_zones:
            return "low_risk"
        return "public"

    @staticmethod
    def _time_bucket(hour_of_day: int) -> str:
        hour = max(0, min(23, int(hour_of_day)))
        if hour < 6 or hour >= 20:
            return "night"
        if hour < 17:
            return "day"
        return "evening"

    def _temporal_key(self, *, track_id: str, zone_key: str, object_type: str) -> str:
        safe_track = str(track_id or "").strip()
        if safe_track:
            return f"track:{safe_track}"
        return f"zone:{zone_key}:{object_type}"

    def _update_temporal_state(self, *, key: str, score: float, timestamp: str) -> Dict[str, Any]:
        now_dt = self._parse_iso(timestamp)
        state = self._temporal_state.get(key)
        if state is None:
            state = {"scores": deque(maxlen=self.smoothing_window), "frames": 0, "last_seen": timestamp}
            self._temporal_state[key] = state
        else:
            last_seen_dt = self._parse_iso(state.get("last_seen"))
            if (now_dt - last_seen_dt).total_seconds() > self.temporal_reset_seconds:
                state = {"scores": deque(maxlen=self.smoothing_window), "frames": 0, "last_seen": timestamp}
                self._temporal_state[key] = state

        scores = state["scores"]
        scores.append(self._clamp01(score))
        state["frames"] = int(state.get("frames", 0)) + 1
        state["last_seen"] = timestamp
        smoothed_score = sum(scores) / max(1, len(scores))
        frames = int(state["frames"])
        persistence_ratio = min(1.0, frames / max(1, self.min_frames))
        return {
            "frames": frames,
            "smoothed_score": round(self._clamp01(smoothed_score), 4),
            "persistence_ratio": round(self._clamp01(persistence_ratio), 4),
        }

    @staticmethod
    def _motion_intensity(track: Optional[Dict[str, Any]]) -> float:
        if not isinstance(track, dict):
            return 0.0
        path = track.get("path") if isinstance(track.get("path"), list) else []
        if len(path) < 2:
            return 0.0
        steps: list[float] = []
        for left, right in zip(path[-5:-1], path[-4:]):
            try:
                dx = float(right.get("x", 0.0)) - float(left.get("x", 0.0))
                dy = float(right.get("y", 0.0)) - float(left.get("y", 0.0))
            except (TypeError, ValueError):
                continue
            steps.append(float(np.sqrt((dx * dx) + (dy * dy))))
        if not steps:
            return 0.0
        return round(max(0.0, min(1.0, float(np.mean(steps) * 3.5))), 4)

    @staticmethod
    def _bbox_area_ratio(bbox_xyxy: list[float], *, frame_shape: Optional[tuple[int, int]] = None) -> float:
        if not isinstance(bbox_xyxy, list) or len(bbox_xyxy) != 4:
            return 0.0
        try:
            x1, y1, x2, y2 = [float(value) for value in bbox_xyxy]
        except (TypeError, ValueError):
            return 0.0
        width = max(0.0, x2 - x1)
        height = max(0.0, y2 - y1)
        if frame_shape is not None and int(frame_shape[0]) > 0 and int(frame_shape[1]) > 0:
            area = width * height
            frame_area = max(1.0, float(frame_shape[0]) * float(frame_shape[1]))
            return round(max(0.0, min(1.0, area / frame_area)), 4)
        largest = max(abs(x1), abs(y1), abs(x2), abs(y2))
        if largest <= 1.0:
            return round(max(0.0, min(1.0, width * height)), 4)
        return 0.0

    def _build_feature_payload(
        self,
        *,
        confidence: float,
        severity_score: float,
        object_type: str,
        bbox_area: float,
        motion_intensity: float,
        duration_frames: int,
        smoothed_score: float,
        persistence_ratio: float,
        zone_type: str,
        hour_of_day: int,
        behavior_risk: float,
    ) -> Dict[str, Any]:
        return {
            "confidence": round(self._clamp01(confidence), 4),
            "severity_score": round(self._clamp01(severity_score), 4),
            "object": self._safe_object_type(object_type),
            "bbox_area": round(self._clamp01(bbox_area), 4),
            "motion_intensity": round(self._clamp01(motion_intensity), 4),
            "duration": max(1, int(duration_frames)),
            "smoothed_score": round(self._clamp01(smoothed_score), 4),
            "persistence_ratio": round(self._clamp01(persistence_ratio), 4),
            "zone": zone_type,
            "time": self._time_bucket(hour_of_day),
            "behavior_risk": round(self._clamp01(behavior_risk), 4),
        }

    def _vectorize_features(self, features: Dict[str, Any]) -> np.ndarray:
        vector = np.zeros(len(self.FEATURE_NAMES), dtype=np.float64)
        mapping = {name: index for index, name in enumerate(self.FEATURE_NAMES)}
        vector[mapping["bias"]] = 1.0
        vector[mapping["confidence"]] = self._clamp01(features.get("confidence"))
        vector[mapping["severity_score"]] = self._clamp01(features.get("severity_score"))
        vector[mapping["bbox_area"]] = self._clamp01(features.get("bbox_area"))
        vector[mapping["motion_intensity"]] = self._clamp01(features.get("motion_intensity"))
        vector[mapping["duration_norm"]] = min(1.0, max(0.0, int(features.get("duration", 0)) / max(1, self.min_frames * 2)))
        vector[mapping["smoothed_score"]] = self._clamp01(features.get("smoothed_score"))
        vector[mapping["behavior_risk"]] = self._clamp01(features.get("behavior_risk"))
        vector[mapping["persistence_ratio"]] = self._clamp01(features.get("persistence_ratio"))

        object_type = self._safe_object_type(features.get("object"))
        vector[mapping[f"object_{object_type}"]] = 1.0

        zone_type = str(features.get("zone", "public")).strip().lower()
        if zone_type not in {"high_risk", "public", "low_risk"}:
            zone_type = "public"
        vector[mapping[f"zone_{zone_type}"]] = 1.0

        time_bucket = str(features.get("time", "day")).strip().lower()
        if time_bucket not in {"night", "day", "evening"}:
            time_bucket = "day"
        vector[mapping[f"time_{time_bucket}"]] = 1.0
        return vector

    def _predict_from_vector_locked(self, vector: np.ndarray) -> float:
        weights = np.array(
            [float(self._model_state["weights"].get(name, 0.0)) for name in self.FEATURE_NAMES],
            dtype=np.float64,
        )
        logit = float(np.dot(vector, weights))
        return round(float(self._sigmoid(np.array([logit], dtype=np.float64))[0]), 4)

    def _feature_importance(self, vector: np.ndarray) -> list[Dict[str, Any]]:
        weights = np.array(
            [float(self._model_state["weights"].get(name, 0.0)) for name in self.FEATURE_NAMES],
            dtype=np.float64,
        )
        contributions = vector * weights
        raw_items: list[tuple[str, float]] = []
        for name, contribution in zip(self.FEATURE_NAMES, contributions):
            if name == "bias":
                continue
            if abs(float(contribution)) < 1e-6:
                continue
            raw_items.append((name, float(contribution)))
        if not raw_items:
            return []
        total = sum(abs(value) for _, value in raw_items) or 1.0
        raw_items.sort(key=lambda item: abs(item[1]), reverse=True)
        items = []
        for name, contribution in raw_items[:6]:
            items.append(
                {
                    "feature": name,
                    "importance": round(abs(contribution) / total, 4),
                    "contribution": round(contribution, 4),
                    "direction": "positive" if contribution >= 0 else "negative",
                }
            )
        return items

    def evaluate(
        self,
        *,
        object_type: str,
        confidence: float,
        severity: str,
        severity_score: float,
        bbox_xyxy: list[float],
        frame_shape: Optional[tuple[int, int]],
        zone_key: str,
        hour_of_day: int,
        timestamp: str,
        track_id: str = "",
        track: Optional[Dict[str, Any]] = None,
        behavior_risk: float = 0.0,
    ) -> Dict[str, Any]:
        safe_object = self._safe_object_type(object_type)
        safe_zone = str(zone_key or "zone:default").strip() or "zone:default"
        severity_level = str(severity or "LOW").strip().upper() or "LOW"
        model_confidence = self._clamp01(severity_score)
        detection_confidence = self._clamp01(confidence)

        if not self.enabled:
            zone_type = self._zone_type(safe_zone)
            thresholds = dict(self.zone_thresholds.get(zone_type, self.zone_thresholds["public"]))
            features = self._build_feature_payload(
                confidence=detection_confidence,
                severity_score=model_confidence,
                object_type=safe_object,
                bbox_area=self._bbox_area_ratio(bbox_xyxy, frame_shape=frame_shape),
                motion_intensity=self._motion_intensity(track),
                duration_frames=1,
                smoothed_score=model_confidence,
                persistence_ratio=1.0,
                zone_type=zone_type,
                hour_of_day=hour_of_day,
                behavior_risk=behavior_risk,
            )
            return {
                "enabled": False,
                "classifier": self.classifier_name,
                "trained": bool(self._model_state.get("trained")),
                "decision": "accepted",
                "operator_review_required": False,
                "bypassed": True,
                "reason": "False-positive filter disabled",
                "threat_probability": round(model_confidence, 4),
                "final_score": round(model_confidence, 4),
                "model_confidence": round(model_confidence, 4),
                "thresholds": thresholds,
                "features": features,
                "feature_importance": [],
            }

        with self._lock:
            zone_type = self._zone_type(safe_zone)
            thresholds = dict(self.zone_thresholds.get(zone_type, self.zone_thresholds["public"]))
            temporal = self._update_temporal_state(
                key=self._temporal_key(track_id=track_id, zone_key=safe_zone, object_type=safe_object),
                score=model_confidence,
                timestamp=timestamp,
            )
            features = self._build_feature_payload(
                confidence=detection_confidence,
                severity_score=model_confidence,
                object_type=safe_object,
                bbox_area=self._bbox_area_ratio(bbox_xyxy, frame_shape=frame_shape),
                motion_intensity=self._motion_intensity(track),
                duration_frames=int(temporal["frames"]),
                smoothed_score=float(temporal["smoothed_score"]),
                persistence_ratio=float(temporal["persistence_ratio"]),
                zone_type=zone_type,
                hour_of_day=hour_of_day,
                behavior_risk=behavior_risk,
            )
            vector = self._vectorize_features(features)
            threat_probability = self._predict_from_vector_locked(vector)
            final_score = round(
                (self.final_score_rule_weight * model_confidence) + (self.final_score_ml_weight * threat_probability),
                4,
            )
            persistence_met = int(features["duration"]) >= self.min_frames
            feature_importance = self._feature_importance(vector)

        bypassed = severity_level == self.fail_safe_severity and detection_confidence >= self.fail_safe_confidence
        decision = "rejected"
        reason = "Rejected by ML false-positive filter"
        if bypassed:
            decision = "accepted"
            reason = "Critical fail-safe bypass"
        elif not persistence_met and final_score >= thresholds["uncertain"]:
            decision = "uncertain"
            reason = f"Temporal persistence below {self.min_frames} frames"
        elif final_score >= thresholds["accept"]:
            decision = "accepted"
            reason = "Threat probability passed acceptance threshold"
        elif final_score >= thresholds["uncertain"]:
            decision = "uncertain"
            reason = "Threat probability requires operator confirmation"

        top_features = []
        for item in feature_importance[:3]:
            feature_name = str(item["feature"]).replace("_", " ")
            direction = "supports" if item["direction"] == "positive" else "reduces"
            top_features.append(f"{feature_name} {direction} threat")
        if top_features:
            reason = f"{reason}. " + ", ".join(top_features)

        return {
            "enabled": self.enabled,
            "classifier": self.classifier_name,
            "trained": bool(self._model_state.get("trained")),
            "decision": decision,
            "operator_review_required": decision == "uncertain",
            "bypassed": bypassed,
            "reason": reason,
            "threat_probability": round(threat_probability, 4),
            "final_score": round(final_score, 4),
            "model_confidence": round(model_confidence, 4),
            "thresholds": thresholds,
            "features": features,
            "feature_importance": feature_importance,
        }

    def _load_feedback_rows_locked(self) -> list[sqlite3.Row]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT alert_id, operator_id, label, features_json, decision, probability, final_score, hard_negative, created_at, updated_at
                FROM fp_feedback
                ORDER BY updated_at ASC, alert_id ASC
                """
            ).fetchall()
        return list(rows)

    def _compute_metrics(self, y_true: np.ndarray, probabilities: np.ndarray) -> Dict[str, float]:
        if y_true.size <= 0:
            return {}
        y_pred = (probabilities >= 0.5).astype(np.int64)
        tp = int(np.sum((y_pred == 1) & (y_true == 1)))
        tn = int(np.sum((y_pred == 0) & (y_true == 0)))
        fp = int(np.sum((y_pred == 1) & (y_true == 0)))
        fn = int(np.sum((y_pred == 0) & (y_true == 1)))
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        fpr = fp / max(1, fp + tn)
        tpr = recall
        accuracy = (tp + tn) / max(1, tp + tn + fp + fn)
        return {
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "false_positive_rate": round(float(fpr), 4),
            "true_positive_rate": round(float(tpr), 4),
            "accuracy": round(float(accuracy), 4),
        }

    def _retrain_model_locked(self) -> None:
        rows = self._load_feedback_rows_locked()
        if len(rows) < self.min_feedback_samples:
            state = dict(self._model_state)
            state["sample_count"] = len(rows)
            state["positive_count"] = sum(1 for row in rows if int(row["label"]) == 1)
            state["negative_count"] = sum(1 for row in rows if int(row["label"]) == 0)
            state["hard_negative_count"] = sum(1 for row in rows if int(row["hard_negative"]) == 1)
            state["updated_at"] = self._iso_now()
            self._save_model_state_locked(state)
            return

        vectors: list[np.ndarray] = []
        labels: list[int] = []
        sample_weights: list[float] = []
        positives = 0
        negatives = 0
        hard_negatives = 0

        for row in rows:
            try:
                features = json.loads(row["features_json"])
            except Exception:
                continue
            vector = self._vectorize_features(features)
            label = 1 if int(row["label"]) == 1 else 0
            vectors.append(vector)
            labels.append(label)
            if label == 1:
                positives += 1
            else:
                negatives += 1
            hard_negative = 1 if int(row["hard_negative"]) == 1 else 0
            if hard_negative:
                hard_negatives += 1
            sample_weights.append(self.hard_negative_weight if hard_negative else 1.0)

        if not vectors:
            return

        x = np.vstack(vectors)
        y = np.array(labels, dtype=np.float64)
        weights = np.array(
            [float(self._model_state["weights"].get(name, self.DEFAULT_WEIGHTS.get(name, 0.0))) for name in self.FEATURE_NAMES],
            dtype=np.float64,
        )
        class_weights = np.ones_like(y)
        if positives > 0:
            class_weights[y == 1] = len(y) / max(1.0, 2.0 * positives)
        if negatives > 0:
            class_weights[y == 0] = len(y) / max(1.0, 2.0 * negatives)
        total_sample_weights = np.array(sample_weights, dtype=np.float64) * class_weights
        norm = max(1.0, float(np.sum(total_sample_weights)))

        for _ in range(self.training_epochs):
            logits = x @ weights
            probs = self._sigmoid(logits)
            errors = (probs - y) * total_sample_weights
            gradient = (x.T @ errors) / norm
            gradient[1:] += self.l2_penalty * weights[1:]
            weights -= self.learning_rate * gradient

        probabilities = self._sigmoid(x @ weights)
        metrics = self._compute_metrics(y.astype(np.int64), probabilities)
        state = {
            "classifier_name": self.classifier_name,
            "weights": {name: round(float(value), 6) for name, value in zip(self.FEATURE_NAMES, weights)},
            "feature_names": list(self.FEATURE_NAMES),
            "metrics": metrics,
            "trained": True,
            "sample_count": int(len(y)),
            "positive_count": int(positives),
            "negative_count": int(negatives),
            "hard_negative_count": int(hard_negatives),
            "training_revision": int(self._model_state.get("training_revision", 0)) + 1,
            "last_trained_at": self._iso_now(),
            "updated_at": self._iso_now(),
        }
        self._save_model_state_locked(state)

    def record_feedback(
        self,
        *,
        alert_id: str,
        label: int,
        operator_id: str,
        filter_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        safe_alert_id = str(alert_id or "").strip()
        if not safe_alert_id:
            raise ValueError("alert_id is required")
        safe_label = 1 if int(label) == 1 else 0
        features = filter_payload.get("features") if isinstance(filter_payload.get("features"), dict) else None
        if not isinstance(features, dict):
            raise ValueError("Alert does not include false-positive filter features")
        created_at = self._iso_now()
        decision = str(filter_payload.get("decision") or "accepted").strip().lower() or "accepted"
        probability = self._clamp01(filter_payload.get("threat_probability"))
        final_score = self._clamp01(filter_payload.get("final_score"))
        hard_negative = 1 if safe_label == 0 and max(probability, final_score) >= self.hard_negative_threshold else 0

        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO fp_feedback (
                      alert_id, operator_id, label, features_json, decision, probability, final_score,
                      hard_negative, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(alert_id) DO UPDATE SET
                      operator_id = excluded.operator_id,
                      label = excluded.label,
                      features_json = excluded.features_json,
                      decision = excluded.decision,
                      probability = excluded.probability,
                      final_score = excluded.final_score,
                      hard_negative = excluded.hard_negative,
                      updated_at = excluded.updated_at
                    """,
                    (
                        safe_alert_id,
                        str(operator_id or "unknown").strip() or "unknown",
                        safe_label,
                        json.dumps(features),
                        decision,
                        round(probability, 4),
                        round(final_score, 4),
                        hard_negative,
                        created_at,
                        created_at,
                    ),
                )
                conn.commit()
            self._retrain_model_locked()
            state = dict(self._model_state)

        feedback = {
            "alert_id": safe_alert_id,
            "label": "true" if safe_label == 1 else "false",
            "label_value": safe_label,
            "operator_id": str(operator_id or "unknown").strip() or "unknown",
            "hard_negative": bool(hard_negative),
            "created_at": created_at,
            "probability": round(probability, 4),
            "final_score": round(final_score, 4),
        }
        logger.info(
            json.dumps(
                {
                    "event": "FP_FEEDBACK",
                    "alert_id": safe_alert_id,
                    "label": feedback["label"],
                    "hard_negative": bool(hard_negative),
                    "timestamp": created_at,
                }
            )
        )
        return {
            "feedback": feedback,
            "model_status": {
                "classifier": state["classifier_name"],
                "trained": bool(state["trained"]),
                "sample_count": int(state["sample_count"]),
                "positive_count": int(state["positive_count"]),
                "negative_count": int(state["negative_count"]),
                "hard_negative_count": int(state["hard_negative_count"]),
                "training_revision": int(state["training_revision"]),
                "last_trained_at": state.get("last_trained_at"),
                "metrics": dict(state.get("metrics", {})),
            },
        }

    def status(self) -> Dict[str, Any]:
        with self._lock:
            state = dict(self._model_state)
        return {
            "enabled": self.enabled,
            "classifier": state.get("classifier_name", self.classifier_name),
            "trained": bool(state.get("trained")),
            "sample_count": int(state.get("sample_count", 0)),
            "positive_count": int(state.get("positive_count", 0)),
            "negative_count": int(state.get("negative_count", 0)),
            "hard_negative_count": int(state.get("hard_negative_count", 0)),
            "training_revision": int(state.get("training_revision", 0)),
            "last_trained_at": state.get("last_trained_at"),
            "metrics": dict(state.get("metrics", {})),
            "thresholds": dict(self.zone_thresholds),
            "min_frames": self.min_frames,
            "smoothing_window": self.smoothing_window,
            "fail_safe": {
                "severity": self.fail_safe_severity,
                "confidence": self.fail_safe_confidence,
            },
        }
