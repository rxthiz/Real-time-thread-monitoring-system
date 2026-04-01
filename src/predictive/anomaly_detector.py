from __future__ import annotations

import bisect
import importlib.util
from collections import deque
from typing import Any, Deque, Dict, Iterable, Optional

import numpy as np


class AnomalyDetector:
    """
    Lightweight anomaly scorer for behavioral features.

    Preferred backend:
    - IsolationForest (if sklearn is installed)

    Fallback backend:
    - Statistical z-score detector
    """

    FEATURE_ORDER = (
        "loitering",
        "movement",
        "transitions",
        "speed",
        "zone_sensitivity",
    )

    def __init__(self, cfg: Dict[str, Any]) -> None:
        predictive_cfg = cfg.get("predictive", {}) if isinstance(cfg.get("predictive", {}), dict) else {}
        anomaly_cfg = (
            predictive_cfg.get("anomaly_detection", {})
            if isinstance(predictive_cfg.get("anomaly_detection", {}), dict)
            else {}
        )
        self.enabled = bool(anomaly_cfg.get("enabled", True))
        self.backend = str(anomaly_cfg.get("backend", "isolation_forest")).strip().lower()
        self.min_samples = max(16, int(anomaly_cfg.get("min_samples", 64)))
        self.max_samples = max(self.min_samples, int(anomaly_cfg.get("max_samples", 400)))
        self.fit_interval = max(5, int(anomaly_cfg.get("fit_interval", 30)))
        self.contamination = max(0.001, min(0.49, float(anomaly_cfg.get("contamination", 0.08))))
        self.random_state = int(anomaly_cfg.get("random_state", 42))
        self.anomaly_threshold = max(0.0, min(1.0, float(anomaly_cfg.get("anomaly_threshold", 0.72))))

        self._vectors: Deque[np.ndarray] = deque(maxlen=self.max_samples)
        self._raw_scores: Deque[float] = deque(maxlen=self.max_samples)
        self._updates = 0
        self._model: Optional[Any] = None
        self._sklearn_available = importlib.util.find_spec("sklearn") is not None

    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    def _vector(self, features: Dict[str, Any]) -> np.ndarray:
        values = [self._clamp(float(features.get(name, 0.0))) for name in self.FEATURE_ORDER]
        return np.asarray(values, dtype=np.float32)

    def _ensure_model(self) -> bool:
        if self.backend != "isolation_forest" or not self._sklearn_available:
            return False
        if len(self._vectors) < self.min_samples:
            return False
        if self._model is not None and (self._updates % self.fit_interval) != 0:
            return True
        try:
            from sklearn.ensemble import IsolationForest  # type: ignore

            model = IsolationForest(
                n_estimators=120,
                contamination=self.contamination,
                random_state=self.random_state,
            )
            model.fit(np.asarray(self._vectors, dtype=np.float32))
            self._model = model
            return True
        except Exception:
            self._model = None
            return False

    @staticmethod
    def _rank_to_anomaly(sorted_values: Iterable[float], value: float) -> float:
        values = list(sorted_values)
        if not values:
            return 0.0
        index = bisect.bisect_right(values, float(value))
        rank = index / max(1, len(values))
        return max(0.0, min(1.0, 1.0 - rank))

    def _score_statistical(self, vector: np.ndarray) -> Dict[str, Any]:
        if len(self._vectors) < self.min_samples:
            return {
                "backend": "statistical",
                "ready": False,
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "reason": "warming_up",
            }
        data = np.asarray(self._vectors, dtype=np.float32)
        mean = np.mean(data, axis=0)
        std = np.std(data, axis=0)
        safe_std = np.where(std < 1e-6, 1e-6, std)
        z = np.abs((vector - mean) / safe_std)
        max_z = float(np.max(z))
        score = max(0.0, min(1.0, (max_z - 1.5) / 3.0))
        return {
            "backend": "statistical",
            "ready": True,
            "anomaly_score": round(score, 4),
            "is_anomaly": bool(score >= self.anomaly_threshold),
            "reason": "z_score",
        }

    def score(self, features: Dict[str, Any]) -> Dict[str, Any]:
        if not self.enabled:
            return {
                "backend": "disabled",
                "ready": False,
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "reason": "disabled",
            }

        vector = self._vector(features)
        self._vectors.append(vector)
        self._updates += 1

        if self._ensure_model() and self._model is not None:
            try:
                raw = float(self._model.score_samples(vector.reshape(1, -1))[0])
                self._raw_scores.append(raw)
                anomaly_score = self._rank_to_anomaly(sorted(self._raw_scores), raw)
                is_anomaly = bool(self._model.predict(vector.reshape(1, -1))[0] == -1)
                return {
                    "backend": "isolation_forest",
                    "ready": True,
                    "anomaly_score": round(anomaly_score, 4),
                    "is_anomaly": is_anomaly or anomaly_score >= self.anomaly_threshold,
                    "reason": "iforest",
                }
            except Exception:
                # Fall through to statistical fallback if model scoring fails.
                pass

        return self._score_statistical(vector)
