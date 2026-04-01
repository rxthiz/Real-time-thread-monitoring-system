from collections import deque
from typing import Any, Deque, Dict, List, Optional

import numpy as np


class FrameBufferManager:
    def __init__(self, *, pre_event_seconds: float = 10.0, default_fps: float = 20.0) -> None:
        self.pre_event_seconds = max(0.0, float(pre_event_seconds))
        self._fps = self._safe_fps(default_fps)
        self._frames: Deque[Dict[str, Any]] = deque(maxlen=self._buffer_size(self._fps))

    @staticmethod
    def _safe_fps(value: float) -> float:
        fps = float(value or 0.0)
        if fps <= 1.0:
            return 20.0
        return min(fps, 120.0)

    def _buffer_size(self, fps: float) -> int:
        return max(1, int(round(self._safe_fps(fps) * self.pre_event_seconds)))

    @property
    def fps(self) -> float:
        return self._fps

    def update_fps(self, fps: float) -> float:
        safe_fps = self._safe_fps(fps)
        if abs(safe_fps - self._fps) > 0.01:
            self._fps = safe_fps
            self._frames = deque(self._frames, maxlen=self._buffer_size(self._fps))
        return self._fps

    def append(
        self,
        *,
        frame: np.ndarray,
        timestamp: str,
        frame_id: int,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        entry = {
            "frame": frame.copy(),
            "timestamp": str(timestamp),
            "frame_id": int(frame_id),
            "metadata": dict(metadata) if isinstance(metadata, dict) else {},
        }
        self._frames.append(entry)
        return entry

    def snapshot(self) -> List[Dict[str, Any]]:
        return list(self._frames)
