from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, Iterable, Optional


class PathManager:
    def __init__(self, *, max_points: int = 160, merge_distance: float = 0.015) -> None:
        self.max_points = max(8, int(max_points))
        self.merge_distance = max(0.0, float(merge_distance))

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
        return dt

    @staticmethod
    def _clamp_unit(value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    def build_point(
        self,
        *,
        zone_key: str,
        camera_id: str,
        timestamp: str,
        bbox_xyxy: list[float],
        frame_shape: Optional[tuple[int, int]] = None,
        frame_id: Optional[int] = None,
    ) -> Dict[str, object]:
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
            "x": round(self._clamp_unit(nx), 4),
            "y": round(self._clamp_unit(ny), 4),
            "zone_key": str(zone_key),
            "camera_id": str(camera_id),
            "ts": str(timestamp),
            "frame_id": int(frame_id) if frame_id is not None else None,
        }

    def append_point(self, path: Deque[Dict[str, object]], point: Dict[str, object]) -> None:
        if path and self._should_merge(path[-1], point):
            path[-1] = point
            return
        path.append(point)

    def new_path(self, points: Optional[Iterable[Dict[str, object]]] = None) -> Deque[Dict[str, object]]:
        return deque(points or [], maxlen=self.max_points)

    def to_payload(self, path: Iterable[Dict[str, object]], limit: Optional[int] = None) -> list[Dict[str, object]]:
        items = list(path)
        if limit is not None and limit > 0:
            items = items[-int(limit) :]
        return [dict(item) for item in items]

    @staticmethod
    def unique_values(path: Iterable[Dict[str, object]], field: str) -> list[str]:
        ordered: list[str] = []
        seen: set[str] = set()
        for point in path:
            value = str(point.get(field, "")).strip()
            if not value or value in seen:
                continue
            seen.add(value)
            ordered.append(value)
        return ordered

    def _should_merge(self, left: Dict[str, object], right: Dict[str, object]) -> bool:
        if str(left.get("zone_key")) != str(right.get("zone_key")):
            return False
        if str(left.get("camera_id")) != str(right.get("camera_id")):
            return False
        dx = float(left.get("x", 0.0)) - float(right.get("x", 0.0))
        dy = float(left.get("y", 0.0)) - float(right.get("y", 0.0))
        if (dx * dx + dy * dy) ** 0.5 > self.merge_distance:
            return False
        left_ts = self._parse_iso(str(left.get("ts", "")))
        right_ts = self._parse_iso(str(right.get("ts", "")))
        return abs((right_ts - left_ts).total_seconds()) <= 1.0
