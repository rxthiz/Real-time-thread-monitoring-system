import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import cv2


class EvidenceVideoWriter:
    def __init__(
        self,
        *,
        evidence_dir: str | Path,
        video_codec: str = "mp4v",
        watermark_timestamp: bool = True,
        generate_thumbnail: bool = True,
    ) -> None:
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.video_codec = str(video_codec or "mp4v")[:4].ljust(4, "v")
        self.watermark_timestamp = bool(watermark_timestamp)
        self.generate_thumbnail = bool(generate_thumbnail)

    @staticmethod
    def _safe_token(value: Any, fallback: str = "unknown") -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
        safe = safe.strip("-._")
        return safe or fallback

    @staticmethod
    def _safe_timestamp_token(value: Optional[str]) -> str:
        if not value:
            return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        text = str(value).strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return EvidenceVideoWriter._safe_token(text, fallback="timestamp")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

    @staticmethod
    def _safe_fps(value: float) -> float:
        fps = float(value or 0.0)
        if fps <= 1.0:
            return 20.0
        return min(fps, 120.0)

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    def _watermark_frame(self, frame, *, timestamp: str, zone_key: str, severity: str):
        canvas = frame.copy()
        header = f"Zone {zone_key or 'zone:default'} | Severity {severity or 'HIGH'}"
        cv2.putText(
            canvas,
            header,
            (12, 28),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.6,
            (255, 255, 255),
            2,
        )
        if self.watermark_timestamp and timestamp:
            cv2.putText(
                canvas,
                timestamp,
                (12, max(24, canvas.shape[0] - 18)),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.55,
                (255, 255, 255),
                2,
            )
        return canvas

    def write_clip(self, job: Dict[str, Any]) -> Dict[str, Any]:
        frames = list(job.get("frames", []))
        if not frames:
            raise RuntimeError("No frames available for evidence clip")

        fps = self._safe_fps(job.get("fps", 20.0))
        width, height = job.get("resolution", (0, 0))
        width = int(width or 0)
        height = int(height or 0)
        if width <= 0 or height <= 0:
            first_frame = frames[0].get("frame")
            if first_frame is None:
                raise RuntimeError("Evidence clip has no valid frame data")
            height, width = first_frame.shape[:2]

        timestamp_token = self._safe_timestamp_token(job.get("timestamp"))
        zone_token = self._safe_token(job.get("zone_key"), fallback="zone-default")
        severity_token = self._safe_token(str(job.get("severity", "HIGH")).lower(), fallback="high")
        alert_token = self._safe_token(job.get("alert_id"), fallback="alert")
        logical_filename = f"{timestamp_token}*{zone_token}*{severity_token}_{alert_token}.mp4"
        filename = logical_filename.replace("*", "_")
        clip_path = self.evidence_dir / filename
        thumbnail_path = clip_path.with_suffix(".jpg")

        fourcc = cv2.VideoWriter_fourcc(*self.video_codec)
        writer = cv2.VideoWriter(str(clip_path), fourcc, fps, (width, height))
        if not writer.isOpened():
            raise RuntimeError(f"Unable to open evidence writer at '{clip_path}'")

        written_frames = 0
        thumbnail_saved = False
        try:
            for entry in frames:
                frame = entry.get("frame")
                if frame is None:
                    continue
                canvas = self._watermark_frame(
                    frame,
                    timestamp=str(entry.get("timestamp") or ""),
                    zone_key=str(job.get("zone_key") or ""),
                    severity=str(job.get("severity") or ""),
                )
                if canvas.shape[1] != width or canvas.shape[0] != height:
                    canvas = cv2.resize(canvas, (width, height), interpolation=cv2.INTER_LINEAR)
                writer.write(canvas)
                if self.generate_thumbnail and not thumbnail_saved:
                    thumbnail_saved = bool(cv2.imwrite(str(thumbnail_path), canvas))
                written_frames += 1
        finally:
            writer.release()

        if written_frames == 0:
            try:
                os.remove(clip_path)
            except OSError:
                pass
            try:
                thumbnail_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise RuntimeError("Evidence clip writer produced zero frames")

        created_at = datetime.now(timezone.utc).isoformat()
        return {
            "status": "ready",
            "clip_path": str(clip_path.as_posix()),
            "clip_name": filename,
            "logical_filename": logical_filename,
            "thumbnail_path": str(thumbnail_path.as_posix()) if thumbnail_saved else None,
            "duration": round(written_frames / fps, 3),
            "frame_count": int(written_frames),
            "created_at": created_at,
            "sha256": self._sha256_file(clip_path),
            "download_url": None,
            "error": None,
        }
