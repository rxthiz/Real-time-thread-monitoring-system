from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class WeaponDetection:
    label: str
    confidence: float
    bbox_xyxy: List[float]


@dataclass
class ActionPrediction:
    label: str
    confidence: float


@dataclass
class SeverityEvent:
    timestamp_sec: float
    weapon: str
    action: str
    score: float
    level: str
    reason: str
    explanation: Dict[str, Any] = field(default_factory=dict)
