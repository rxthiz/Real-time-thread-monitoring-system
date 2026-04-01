from typing import Any, Dict, List


class PredictiveRiskModel:
    def __init__(self, cfg: Dict[str, Any]) -> None:
        predictive_cfg = cfg.get("predictive", {})
        weights_cfg = predictive_cfg.get("weights", {}) if isinstance(predictive_cfg.get("weights", {}), dict) else {}
        self.weights = {
            "loitering": max(0.0, float(weights_cfg.get("loitering", 0.30))),
            "movement": max(0.0, float(weights_cfg.get("movement", 0.25))),
            "transitions": max(0.0, float(weights_cfg.get("transitions", 0.20))),
            "speed": max(0.0, float(weights_cfg.get("speed", 0.10))),
            "zone_sensitivity": max(0.0, float(weights_cfg.get("zone_sensitivity", 0.15))),
            "anomaly": max(0.0, float(weights_cfg.get("anomaly", 0.20))),
        }
        self.medium_risk_threshold = float(predictive_cfg.get("medium_risk_threshold", 0.45))
        self.high_risk_threshold = float(predictive_cfg.get("high_risk_threshold", 0.70))
        self.pre_alert_threshold = float(predictive_cfg.get("pre_alert_threshold", 0.85))

    def risk_level(self, risk_score: float) -> str:
        score = max(0.0, min(1.0, float(risk_score or 0.0)))
        if score >= self.pre_alert_threshold:
            return "CRITICAL"
        if score >= self.high_risk_threshold:
            return "HIGH"
        if score >= self.medium_risk_threshold:
            return "MEDIUM"
        return "LOW"

    def score(
        self,
        *,
        loitering_score: float,
        movement_score: float,
        transition_score: float,
        speed_score: float,
        zone_weight: float,
        anomaly_score: float = 0.0,
        factor_values: Dict[str, Any],
    ) -> Dict[str, Any]:
        components = {
            "loitering": max(0.0, min(1.0, float(loitering_score or 0.0))),
            "movement": max(0.0, min(1.0, float(movement_score or 0.0))),
            "transitions": max(0.0, min(1.0, float(transition_score or 0.0))),
            "speed": max(0.0, min(1.0, float(speed_score or 0.0))),
            "zone_sensitivity": max(0.0, min(1.0, float(zone_weight or 0.0))),
            "anomaly": max(0.0, min(1.0, float(anomaly_score or 0.0))),
        }

        total_weight = sum(self.weights.values()) or 1.0
        weighted_total = sum(self.weights[name] * components[name] for name in self.weights)
        risk_score = max(0.0, min(1.0, weighted_total / total_weight))
        level = self.risk_level(risk_score)

        total_contribution = weighted_total or 1.0
        factors: List[Dict[str, Any]] = []
        feature_importance: List[Dict[str, Any]] = []
        for name in ["loitering", "movement", "transitions", "speed", "zone_sensitivity", "anomaly"]:
            contribution = self.weights[name] * components[name]
            impact = max(0.0, min(1.0, contribution / total_contribution)) if weighted_total > 0 else 0.0
            factors.append(
                {
                    "name": name,
                    "value": factor_values.get(name),
                    "impact": round(impact, 4),
                }
            )
            feature_importance.append(
                {
                    "feature": name,
                    "importance": round(impact, 4),
                }
            )

        return {
            "risk_score_raw": round(risk_score, 4),
            "risk_level": level,
            "model_breakdown": {
                "loitering_score": round(components["loitering"], 4),
                "movement_score": round(components["movement"], 4),
                "transition_score": round(components["transitions"], 4),
                "speed_score": round(components["speed"], 4),
                "zone_sensitivity": round(components["zone_sensitivity"], 4),
                "anomaly_score": round(components["anomaly"], 4),
            },
            "factors": factors,
            "feature_importance": feature_importance,
        }
