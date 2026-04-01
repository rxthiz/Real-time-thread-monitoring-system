import logging
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Lock, Thread
from typing import Any, Callable, Dict, Optional

import numpy as np

from src.evidence.buffer_manager import FrameBufferManager
from src.evidence.video_writer import EvidenceVideoWriter

logger = logging.getLogger(__name__)


class ClipRecorder:
    def __init__(
        self,
        *,
        evidence_dir: str | Path,
        pre_event_seconds: float = 10.0,
        post_event_seconds: float = 10.0,
        default_fps: float = 20.0,
        video_codec: str = "mp4v",
        watermark_timestamp: bool = True,
        on_complete: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ) -> None:
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        self.pre_event_seconds = max(0.0, float(pre_event_seconds))
        self.post_event_seconds = max(0.0, float(post_event_seconds))
        self.default_fps = self._safe_fps(default_fps)
        self.video_codec = str(video_codec or "mp4v")[:4].ljust(4, "v")
        self.watermark_timestamp = bool(watermark_timestamp)
        self.on_complete = on_complete

        self._lock = Lock()
        self._stop_event = Event()
        self._jobs: Queue[Dict[str, Any]] = Queue()
        self._writer_thread = Thread(target=self._writer_loop, daemon=True, name="clip-recorder-writer")

        self._fps = self.default_fps
        self._resolution = (0, 0)
        self._buffer_manager = FrameBufferManager(
            pre_event_seconds=self.pre_event_seconds,
            default_fps=self.default_fps,
        )
        self._video_writer = EvidenceVideoWriter(
            evidence_dir=self.evidence_dir,
            video_codec=self.video_codec,
            watermark_timestamp=self.watermark_timestamp,
            generate_thumbnail=True,
        )
        self._active_recordings: Dict[str, Dict[str, Any]] = {}
        self._evidence_index: Dict[str, Dict[str, Any]] = {}

        self._writer_thread.start()

    def is_running(self) -> bool:
        return self._writer_thread.is_alive() and not self._stop_event.is_set()

    @staticmethod
    def _safe_fps(value: float) -> float:
        fps = float(value or 0.0)
        if fps <= 1.0:
            return 20.0
        return min(fps, 120.0)

    def update_stream(self, *, fps: float, width: int, height: int) -> None:
        safe_fps = self._safe_fps(fps)
        safe_width = max(0, int(width or 0))
        safe_height = max(0, int(height or 0))
        with self._lock:
            if abs(safe_fps - self._fps) > 0.01:
                self._fps = safe_fps
                self._buffer_manager.update_fps(self._fps)
            if safe_width > 0 and safe_height > 0:
                self._resolution = (safe_width, safe_height)

    def append_frame(self, *, frame: np.ndarray, timestamp: str, frame_id: int) -> None:
        if frame is None:
            return
        height, width = frame.shape[:2]
        completed_jobs: list[Dict[str, Any]] = []
        with self._lock:
            if width > 0 and height > 0 and self._resolution == (0, 0):
                self._resolution = (int(width), int(height))

            frame_entry = self._buffer_manager.append(
                frame=frame,
                timestamp=str(timestamp),
                frame_id=int(frame_id),
            )

            for alert_id, state in list(self._active_recordings.items()):
                state["frames"].append(frame_entry)
                state["remaining_frames"] = max(0, int(state["remaining_frames"]) - 1)
                if int(state["remaining_frames"]) == 0:
                    completed_jobs.append(self._active_recordings.pop(alert_id))

        for job in completed_jobs:
            self._jobs.put(job)

    def begin_capture(
        self,
        *,
        alert_id: str,
        timestamp: str,
        zone_key: str,
        severity: str,
        source: str,
    ) -> bool:
        safe_alert_id = str(alert_id).strip()
        if not safe_alert_id:
            return False

        with self._lock:
            existing = self._evidence_index.get(safe_alert_id)
            if existing and existing.get("status") in {"processing", "ready"}:
                return False
            if safe_alert_id in self._active_recordings:
                return False

            fps = self._fps
            width, height = self._resolution
            pre_frames = self._buffer_manager.snapshot()
            post_frame_count = max(1, int(round(fps * self.post_event_seconds)))
            state = {
                "alert_id": safe_alert_id,
                "timestamp": str(timestamp),
                "zone_key": str(zone_key),
                "severity": str(severity).upper(),
                "source": str(source),
                "fps": fps,
                "resolution": (width, height),
                "frames": pre_frames,
                "remaining_frames": post_frame_count,
            }
            self._active_recordings[safe_alert_id] = state
            self._evidence_index[safe_alert_id] = {
                "alert_id": safe_alert_id,
                "status": "processing",
                "clip_path": None,
                "duration": None,
                "frame_count": len(pre_frames),
                "download_url": None,
                "created_at": None,
                "thumbnail_path": None,
                "sha256": None,
                "clip_name": None,
                "logical_filename": None,
                "timestamp": str(timestamp),
                "zone_key": str(zone_key),
                "severity": str(severity).upper(),
                "source": str(source),
                "error": None,
            }
        return True

    def evidence_status(self, alert_id: str) -> Optional[Dict[str, Any]]:
        safe_alert_id = str(alert_id).strip()
        if not safe_alert_id:
            return None
        with self._lock:
            payload = self._evidence_index.get(safe_alert_id)
            if payload is None:
                return None
            return dict(payload)

    def stop(self, timeout: float = 5.0) -> None:
        pending_jobs: list[Dict[str, Any]] = []
        with self._lock:
            for alert_id in list(self._active_recordings.keys()):
                pending_jobs.append(self._active_recordings.pop(alert_id))

        for job in pending_jobs:
            self._jobs.put(job)

        self._stop_event.set()
        self._jobs.put({"_sentinel": True})
        self._writer_thread.join(timeout=max(0.5, float(timeout)))

    def _writer_loop(self) -> None:
        while True:
            try:
                job = self._jobs.get(timeout=0.2)
            except Empty:
                if self._stop_event.is_set():
                    break
                continue

            try:
                if job.get("_sentinel"):
                    if self._stop_event.is_set():
                        break
                    continue
                metadata = self._write_clip(job)
            except Exception as exc:
                logger.exception("Evidence clip write failed alert_id=%s", job.get("alert_id"))
                metadata = {
                    "status": "failed",
                    "clip_path": None,
                    "duration": None,
                    "frame_count": int(len(job.get("frames", []))),
                    "download_url": None,
                    "created_at": None,
                    "thumbnail_path": None,
                    "sha256": None,
                    "clip_name": None,
                    "logical_filename": None,
                    "error": str(exc),
                }
            finally:
                self._jobs.task_done()

            alert_id = str(job.get("alert_id", "")).strip()
            if not alert_id:
                continue
            payload = {
                "alert_id": alert_id,
                "timestamp": str(job.get("timestamp", "")),
                "zone_key": str(job.get("zone_key", "")),
                "severity": str(job.get("severity", "")),
                "source": str(job.get("source", "")),
                **metadata,
            }
            with self._lock:
                self._evidence_index[alert_id] = payload
            if self.on_complete is not None:
                try:
                    self.on_complete(alert_id, dict(payload))
                except Exception:
                    logger.exception("Evidence completion callback failed alert_id=%s", alert_id)

    def _write_clip(self, job: Dict[str, Any]) -> Dict[str, Any]:
        return self._video_writer.write_clip(job)
