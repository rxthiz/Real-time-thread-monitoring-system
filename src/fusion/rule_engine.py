from typing import Any, Dict, Optional

from src.utils.types import ActionPrediction, SeverityEvent, WeaponDetection
from src.xai.explainer import AlertExplainer


class RuleBasedFusion:
    def __init__(self, cfg: Dict):
        fusion_cfg = cfg["fusion"]
        self.weapon_weights = fusion_cfg["weapon_weights"]
        self.action_weights = fusion_cfg["action_weights"]
        self.high_thr = float(fusion_cfg["high_severity_threshold"])
        self.med_thr = float(fusion_cfg["medium_severity_threshold"])
        weapon_only_cfg = fusion_cfg.get("weapon_only_rules", {})
        self.weapon_only_enabled = bool(weapon_only_cfg.get("enabled", True))
        self.weapon_only_medium_conf_thresholds = {
            str(k).lower(): float(v)
            for k, v in weapon_only_cfg.get(
                "medium_conf_thresholds", {"gun": 0.25, "knife": 0.30, "stick": 0.25}
            ).items()
        }
        self.weapon_only_high_conf_thresholds = {
            str(k).lower(): float(v)
            for k, v in weapon_only_cfg.get(
                "high_conf_thresholds", {"gun": 0.70, "knife": 0.80, "stick": 0.90}
            ).items()
        }
        self.explainer = AlertExplainer(cfg)

    def explain(
        self,
        weapon: WeaponDetection,
        action: Optional[ActionPrediction],
        event: SeverityEvent,
        *,
        repeated_count: int = 1,
        ml_filter_score: Optional[float] = None,
        zone_key: str = "",
        rules_triggered: Optional[list[str]] = None,
    ) -> Dict[str, Any]:
        action_label = action.label if action else "unknown"
        action_confidence = float(action.confidence) if action else 0.0
        weapon_weight = float(self.weapon_weights.get(weapon.label, 0.1))
        action_weight = float(self.action_weights.get(action.label, 0.2)) if action else 0.0

        return self.explainer.generate_explanation(
            detection={
                "weapon": {
                    "label": weapon.label,
                    "confidence": float(weapon.confidence),
                },
                "action": {
                    "label": action_label,
                    "confidence": action_confidence,
                }
                if action is not None
                else None,
                "zone_key": zone_key,
            },
            rule_output={
                "reason": event.reason,
                "severity": event.level,
                "score": float(event.score),
                "weapon_component": 0.65 * weapon_weight * float(weapon.confidence),
                "action_component": 0.35 * action_weight * action_confidence,
                "weapon_weight": weapon_weight,
                "action_weight": action_weight,
                "rules_triggered": list(rules_triggered or []),
            },
            ml_output={
                "ml_filter_score": float(event.score if ml_filter_score is None else ml_filter_score),
                "repeated_count": max(1, int(repeated_count)),
                "zone_key": zone_key,
            },
        )

    def _build_event(
        self,
        *,
        timestamp_sec: float,
        weapon: WeaponDetection,
        action: Optional[ActionPrediction],
        score: float,
        level: str,
        reason: str,
        rules_triggered: Optional[list[str]] = None,
    ) -> SeverityEvent:
        action_label = action.label if action else "unknown"
        event = SeverityEvent(
            timestamp_sec=timestamp_sec,
            weapon=weapon.label,
            action=action_label,
            score=score,
            level=level,
            reason=reason,
        )
        event.explanation = self.explain(
            weapon=weapon,
            action=action,
            event=event,
            rules_triggered=rules_triggered,
        )
        return event

    def fuse(
        self,
        timestamp_sec: float,
        weapon: WeaponDetection,
        action: Optional[ActionPrediction],
    ) -> SeverityEvent:
        w = float(self.weapon_weights.get(weapon.label, 0.1)) * weapon.confidence
        a_weight = float(self.action_weights.get(action.label, 0.2)) if action else 0.2
        a_conf = float(action.confidence) if action else 0.0
        a = a_weight * a_conf

        score = min(1.0, 0.65 * w + 0.35 * a)
        act = action.label if action else "unknown"

        if self.weapon_only_enabled and action is None:
            high_thr = float(
                self.weapon_only_high_conf_thresholds.get(weapon.label, 1.1)
            )
            med_thr = float(
                self.weapon_only_medium_conf_thresholds.get(weapon.label, 1.1)
            )
            if weapon.confidence >= high_thr:
                level = "HIGH"
                score = max(score, self.high_thr)
                reason = (
                    f"weapon-only rule: {weapon.label} confidence "
                    f"{weapon.confidence:.2f} >= {high_thr:.2f}"
                )
                return self._build_event(
                    timestamp_sec=timestamp_sec,
                    score=score,
                    level=level,
                    reason=reason,
                    weapon=weapon,
                    action=action,
                    rules_triggered=["weapon_only_high"],
                )
            if weapon.confidence >= med_thr:
                level = "MEDIUM"
                score = max(score, self.med_thr)
                reason = (
                    f"weapon-only rule: {weapon.label} confidence "
                    f"{weapon.confidence:.2f} >= {med_thr:.2f}"
                )
                return self._build_event(
                    timestamp_sec=timestamp_sec,
                    score=score,
                    level=level,
                    reason=reason,
                    weapon=weapon,
                    action=action,
                    rules_triggered=["weapon_only_medium"],
                )

        if score >= self.high_thr:
            level = "HIGH"
        elif score >= self.med_thr:
            level = "MEDIUM"
        else:
            level = "LOW"

        reason = f"weapon={weapon.label}({weapon.confidence:.2f}), action={act}({a_conf:.2f})"

        return self._build_event(
            timestamp_sec=timestamp_sec,
            score=score,
            level=level,
            reason=reason,
            weapon=weapon,
            action=action,
            rules_triggered=["fusion_score"],
        )
