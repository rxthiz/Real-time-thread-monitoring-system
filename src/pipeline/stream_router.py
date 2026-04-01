from collections import defaultdict
from typing import Dict, List

from src.utils.types import ActionPrediction, WeaponDetection


class StreamRouter:
    """
    Separates detections into logical streams for downstream fusion.
    """

    def split_weapon_streams(self, detections: List[WeaponDetection]) -> Dict[str, List[WeaponDetection]]:
        streams: Dict[str, List[WeaponDetection]] = defaultdict(list)
        for det in detections:
            streams[det.label].append(det)
        return dict(streams)

    def split_action_stream(self, action: ActionPrediction | None) -> Dict[str, ActionPrediction]:
        if action is None:
            return {}
        return {action.label: action}
