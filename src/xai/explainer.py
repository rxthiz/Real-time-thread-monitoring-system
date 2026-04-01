from __future__ import annotations

from typing import Any, Dict, Optional

from src.xai.feature_importance import build_feature_importance
from src.xai.reason_templates import (
    action_reason,
    combine_reasons,
    persistence_reason,
    summarize_alert,
    weapon_reason,
)


class AlertExplainer:
    def __init__(self, cfg: Dict[str, Any]):
        xai_cfg = cfg.get("xai", {})
        self.enabled = bool(xai_cfg.get("enabled", True))
        self.persistent_detection_threshold = max(2, int(xai_cfg.get("persistent_detection_threshold", 3)))
        self.max_feature_count = max(3, int(xai_cfg.get("max_feature_count", 5)))

    @staticmethod
    def _as_float(*values: Any, fallback: float = 0.0) -> float:
        for value in values:
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
        return float(fallback)

    def generate_explanation(
        self,
        detection: Dict[str, Any],
        rule_output: Dict[str, Any],
        ml_output: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ml = ml_output or {}
        severity = str(rule_output.get("severity", rule_output.get("level", "LOW"))).strip().upper() or "LOW"
        final_score = round(self._as_float(rule_output.get("score"), ml.get("ml_filter_score"), fallback=0.0), 4)
        zone_key = str(ml.get("zone_key", detection.get("zone_key", ""))).strip()
        if not self.enabled:
            return {
                "reason": str(rule_output.get("reason", "Threat conditions met")).strip() or "Threat conditions met",
                "summary": summarize_alert(str(rule_output.get("reason", "Threat conditions met")), severity, zone_key=zone_key),
                "factors": [],
                "model_breakdown": {},
                "feature_importance": [],
                "final_score": final_score,
                "severity": severity,
                "rule_reason": str(rule_output.get("reason", "")).strip(),
            }

        weapon_payload = detection.get("weapon") if isinstance(detection.get("weapon"), dict) else {}
        action_payload = detection.get("action") if isinstance(detection.get("action"), dict) else {}
        weapon_label = str(weapon_payload.get("label", detection.get("label", "weapon"))).strip().lower() or "weapon"
        weapon_conf = self._as_float(weapon_payload.get("confidence"), detection.get("confidence"), fallback=0.0)
        action_label = str(action_payload.get("label", rule_output.get("action", "unknown"))).strip().lower() or "unknown"
        action_conf = self._as_float(action_payload.get("confidence"), fallback=0.0)
        repeated_count = max(1, int(self._as_float(ml.get("repeated_count"), fallback=1)))

        weapon_component = max(0.0, self._as_float(rule_output.get("weapon_component"), fallback=weapon_conf * 0.55))
        action_component = max(
            0.0,
            self._as_float(
                rule_output.get("action_component"),
                fallback=(action_conf * 0.25 if action_label != "unknown" else 0.0),
            ),
        )
        persistence_component = 0.0
        if repeated_count >= self.persistent_detection_threshold:
            persistence_component = min(0.24, 0.06 * repeated_count)
        confidence_component = min(0.32, max(0.05, weapon_conf * 0.3))

        factors = [
            {
                "name": "object_type",
                "value": weapon_label,
                "impact": round(max(weapon_component, 0.2), 4),
            },
            {
                "name": "confidence",
                "value": round(weapon_conf, 4),
                "impact": round(confidence_component, 4),
            },
        ]
        if action_label != "unknown" and action_conf > 0.0:
            factors.append(
                {
                    "name": "motion",
                    "value": action_label,
                    "impact": round(max(action_component, 0.08), 4),
                }
            )
        if persistence_component > 0.0:
            factors.append(
                {
                    "name": "persistence",
                    "value": repeated_count,
                    "impact": round(persistence_component, 4),
                }
            )

        reason = combine_reasons(
            weapon_reason(weapon_label, weapon_conf),
            action_reason(action_label, action_conf),
            persistence_reason(repeated_count),
        )
        model_breakdown = {
            "weapon_model_confidence": round(weapon_conf, 4),
            "action_model_confidence": round(action_conf, 4),
            "ml_filter_score": round(self._as_float(ml.get("ml_filter_score"), final_score, fallback=final_score), 4),
        }

        return {
            "reason": reason,
            "summary": summarize_alert(reason, severity, zone_key=zone_key),
            "factors": factors,
            "model_breakdown": model_breakdown,
            "feature_importance": build_feature_importance(factors, max_items=self.max_feature_count),
            "final_score": final_score,
            "severity": severity,
            "rule_reason": str(rule_output.get("reason", "")).strip(),
        }
