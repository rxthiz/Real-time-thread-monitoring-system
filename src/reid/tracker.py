import logging
import re
import uuid
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from time import monotonic
from typing import Any, Deque, Dict, Optional

import numpy as np

from src.reid.embedding_model import ReIDEmbeddingModel
from src.reid.path_manager import PathManager

logger = logging.getLogger(__name__)


class ReIDCorrelator:
    def __init__(self, cfg: Dict[str, Any]):
        reid_cfg = cfg.get("reid", {})
        self.enabled = bool(reid_cfg.get("enabled", True))
        self.similarity_threshold = float(reid_cfg.get("similarity_threshold", 0.7))
        self.temporal_window_seconds = float(reid_cfg.get("temporal_window_seconds", 60))
        self.max_tracks = int(reid_cfg.get("max_tracks", 2000))
        self.track_retention_seconds = float(
            reid_cfg.get("track_retention_seconds", max(60.0, self.temporal_window_seconds))
        )
        self.max_events_per_track = int(reid_cfg.get("max_events_per_track", 120))
        self.max_embeddings_per_track = int(reid_cfg.get("max_embeddings_per_track", 12))
        self.max_path_points = int(reid_cfg.get("max_path_points", 160))
        self.prune_interval_seconds = float(reid_cfg.get("prune_interval_seconds", 8.0))
        self.same_zone_bonus = float(reid_cfg.get("same_zone_bonus", 0.04))
        self.same_camera_bonus = float(reid_cfg.get("same_camera_bonus", 0.025))
        self.adjacent_zone_bonus = float(reid_cfg.get("adjacent_zone_bonus", 0.015))
        self.track_path_preview_points = int(reid_cfg.get("track_path_preview_points", 24))
        raw_target_labels = reid_cfg.get("target_labels", [])
        self.target_labels = tuple(
            self._normalize_label(label)
            for label in raw_target_labels
            if self._normalize_label(label)
        )
        adjacency = reid_cfg.get("zone_adjacency", {}) if isinstance(reid_cfg.get("zone_adjacency", {}), dict) else {}
        self.zone_adjacency = {
            str(zone): {str(item) for item in values if str(item).strip()}
            for zone, values in adjacency.items()
            if isinstance(values, list)
        }

        self.embedding_model = ReIDEmbeddingModel(cfg)
        self.path_manager = PathManager(max_points=self.max_path_points)

        self._tracks: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()
        self._last_prune_tick = monotonic()

    @staticmethod
    def _iso_now() -> str:
        return datetime.now(timezone.utc).isoformat()

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
    def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
        if a.size == 0 or b.size == 0:
            return 0.0
        denom = (np.linalg.norm(a) * np.linalg.norm(b)) + 1e-12
        if denom <= 0.0:
            return 0.0
        return float(np.dot(a, b) / denom)

    @staticmethod
    def _normalize_label(value: Any) -> str:
        token = re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower())
        return token.strip("_")

    def supports_label(self, label: Any) -> bool:
        token = self._normalize_label(label)
        if not token:
            return False
        if not self.target_labels:
            return True
        for target in self.target_labels:
            if token == target or token.startswith(f"{target}_") or token.endswith(f"_{target}"):
                return True
            if f"_{target}_" in token:
                return True
        return False

    def _new_track_id(self) -> str:
        return f"THR-{uuid.uuid4().hex[:16].upper()}"

    def _zone_bonus(self, zone_key: str, camera_id: str, track: Dict[str, Any]) -> float:
        bonus = 0.0
        if str(track.get("last_zone_key", "")) == str(zone_key):
            bonus += self.same_zone_bonus
        elif zone_key in self.zone_adjacency.get(str(track.get("last_zone_key", "")), set()):
            bonus += self.adjacent_zone_bonus

        if str(track.get("last_camera_id", "")) == str(camera_id):
            bonus += self.same_camera_bonus
        return bonus

    def _track_similarity(self, embedding: np.ndarray, track: Dict[str, Any]) -> float:
        embeddings = list(track.get("embeddings", []))
        if not embeddings:
            return 0.0
        sims = [self._cosine_similarity(embedding, vector) for vector in embeddings]
        if not sims:
            return 0.0
        top = sorted(sims, reverse=True)[: min(3, len(sims))]
        mean_sim = float(sum(top) / len(top))
        avg_embedding = track.get("avg_embedding")
        if isinstance(avg_embedding, np.ndarray):
            mean_sim = max(mean_sim, self._cosine_similarity(embedding, avg_embedding))
        return mean_sim

    def _prune_locked(self) -> None:
        now_tick = monotonic()
        if now_tick - self._last_prune_tick < self.prune_interval_seconds:
            return
        self._last_prune_tick = now_tick
        now_utc = datetime.now(timezone.utc)

        drop_ids = []
        for track_id, track in self._tracks.items():
            age = (now_utc - self._parse_iso(track.get("last_seen_at"))).total_seconds()
            if age > self.track_retention_seconds:
                drop_ids.append(track_id)
        for track_id in drop_ids:
            self._tracks.pop(track_id, None)

        if len(self._tracks) > self.max_tracks:
            ordered = sorted(
                self._tracks.items(),
                key=lambda item: self._parse_iso(item[1].get("last_seen_at")),
                reverse=True,
            )
            keep_ids = {track_id for track_id, _ in ordered[: self.max_tracks]}
            self._tracks = {track_id: track for track_id, track in self._tracks.items() if track_id in keep_ids}

    def observe(
        self,
        *,
        source: str,
        frame_id: Optional[int],
        timestamp: Optional[str],
        bbox_xyxy: list[float],
        label: str,
        confidence: float,
        frame: Optional[np.ndarray] = None,
        zone_key: Optional[str] = None,
        camera_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self.enabled:
            return {}

        ts_text = timestamp or self._iso_now()
        ts_dt = self._parse_iso(ts_text)
        safe_camera = str(camera_id or source or "camera:unknown")
        safe_zone = str(zone_key or safe_camera or "zone:unknown")
        frame_shape = frame.shape[:2] if frame is not None and frame.size > 0 else None
        cache_key = f"{safe_camera}:{frame_id}:{','.join(str(int(round(v))) for v in bbox_xyxy[:4])}"
        embedding = self.embedding_model.extract(frame=frame, bbox_xyxy=bbox_xyxy, cache_key=cache_key)
        path_point = self.path_manager.build_point(
            zone_key=safe_zone,
            camera_id=safe_camera,
            timestamp=ts_text,
            bbox_xyxy=bbox_xyxy,
            frame_shape=frame_shape,
            frame_id=frame_id,
        )

        with self._lock:
            self._prune_locked()

            best_track_id: Optional[str] = None
            best_raw_similarity = -1.0
            best_score = -1.0
            best_track: Optional[Dict[str, Any]] = None

            for track_id, track in self._tracks.items():
                last_seen = self._parse_iso(track.get("last_seen_at"))
                dt = abs((ts_dt - last_seen).total_seconds())
                if dt > self.temporal_window_seconds:
                    continue
                raw_similarity = self._track_similarity(embedding, track)
                score = raw_similarity + self._zone_bonus(safe_zone, safe_camera, track)
                if score > best_score:
                    best_score = score
                    best_raw_similarity = raw_similarity
                    best_track_id = track_id
                    best_track = track

            if best_track is None or best_score < self.similarity_threshold:
                track_id = self._new_track_id()
                track = {
                    "track_id": track_id,
                    "threat_id": track_id,
                    "created_at": ts_text,
                    "last_seen_at": ts_text,
                    "last_seen": ts_text,
                    "last_zone_key": safe_zone,
                    "last_camera_id": safe_camera,
                    "event_count": 0,
                    "match_count": 0,
                    "confidence": round(float(confidence), 4),
                    "labels": {},
                    "embeddings": deque(maxlen=self.max_embeddings_per_track),
                    "avg_embedding": None,
                    "zones": deque(maxlen=self.max_path_points),
                    "cameras": deque(maxlen=self.max_path_points),
                    "path": self.path_manager.new_path(),
                    "events": deque(maxlen=self.max_events_per_track),
                }
                self._tracks[track_id] = track
                is_new_track = True
                matched_zone = None
                matched_camera = None
                matched_timestamp = None
            else:
                track_id = best_track_id or self._new_track_id()
                track = best_track
                is_new_track = False
                matched_zone = track.get("last_zone_key")
                matched_camera = track.get("last_camera_id")
                matched_timestamp = track.get("last_seen_at")

            embeddings: Deque[np.ndarray] = track["embeddings"]
            embeddings.append(embedding)
            track["avg_embedding"] = np.mean(np.stack(list(embeddings)), axis=0).astype(np.float32)
            track["event_count"] = int(track.get("event_count", 0)) + 1
            if not is_new_track:
                track["match_count"] = int(track.get("match_count", 0)) + 1
            labels: Dict[str, int] = dict(track.get("labels", {}))
            labels[str(label)] = int(labels.get(str(label), 0)) + 1
            track["labels"] = labels
            track["last_seen_at"] = ts_text
            track["last_seen"] = ts_text
            track["last_zone_key"] = safe_zone
            track["last_camera_id"] = safe_camera
            track["confidence"] = round(best_raw_similarity if not is_new_track else float(confidence), 4)

            zones: Deque[str] = track["zones"]
            if not zones or zones[-1] != safe_zone:
                zones.append(safe_zone)
            cameras: Deque[str] = track["cameras"]
            if not cameras or cameras[-1] != safe_camera:
                cameras.append(safe_camera)

            self.path_manager.append_point(track["path"], path_point)
            track["events"].append(
                {
                    "timestamp": ts_text,
                    "zone_key": safe_zone,
                    "camera_id": safe_camera,
                    "frame_id": int(frame_id) if frame_id is not None else None,
                    "label": str(label),
                    "confidence": round(float(confidence), 4),
                    "similarity": None if is_new_track else round(best_raw_similarity, 4),
                }
            )

        cross_camera = bool(not is_new_track and matched_camera is not None and str(matched_camera) != safe_camera)
        return {
            "track_id": track_id,
            "threat_id": track_id,
            "is_new_track": is_new_track,
            "similarity": None if is_new_track else round(best_raw_similarity, 4),
            "confidence": track["confidence"],
            "matched_zone_key": matched_zone,
            "matched_camera_id": matched_camera,
            "matched_timestamp": matched_timestamp,
            "zone_key": safe_zone,
            "camera_id": safe_camera,
            "cross_camera": cross_camera,
            "path_point": path_point,
        }

    def track(self, threat_id: str) -> Optional[Dict[str, Any]]:
        safe_id = str(threat_id).strip()
        if not safe_id:
            return None
        with self._lock:
            track = self._tracks.get(safe_id)
            if track is None:
                return None
            return self._track_payload(track, include_full_path=True)

    def track_path(self, threat_id: str) -> Optional[Dict[str, Any]]:
        safe_id = str(threat_id).strip()
        if not safe_id:
            return None
        with self._lock:
            track = self._tracks.get(safe_id)
            if track is None:
                return None
            return {
                "track_id": safe_id,
                "threat_id": safe_id,
                "last_seen": track.get("last_seen_at"),
                "path": self.path_manager.to_payload(track.get("path", [])),
            }

    def recent_tracks(self, *, limit: int = 100, within_seconds: int = 900) -> list[Dict[str, Any]]:
        count = max(1, min(int(limit), 2000))
        horizon = max(10, min(int(within_seconds), 24 * 3600))
        now_utc = datetime.now(timezone.utc)
        with self._lock:
            self._prune_locked()
            tracks = []
            for track in self._tracks.values():
                age = (now_utc - self._parse_iso(track.get("last_seen_at"))).total_seconds()
                if age > horizon:
                    continue
                tracks.append(self._track_payload(track, include_full_path=False))
            tracks.sort(key=lambda item: self._parse_iso(item.get("last_seen")), reverse=True)
            return tracks[:count]

    def _track_payload(self, track: Dict[str, Any], *, include_full_path: bool) -> Dict[str, Any]:
        path_limit = None if include_full_path else self.track_path_preview_points
        path = self.path_manager.to_payload(track.get("path", []), limit=path_limit)
        return {
            "track_id": track.get("track_id"),
            "threat_id": track.get("threat_id"),
            "created_at": track.get("created_at"),
            "last_seen": track.get("last_seen_at"),
            "last_seen_at": track.get("last_seen_at"),
            "camera_id": track.get("last_camera_id"),
            "zone_key": track.get("last_zone_key"),
            "zones": list(track.get("zones", [])),
            "cameras": list(track.get("cameras", [])),
            "path": path,
            "confidence": round(float(track.get("confidence", 0.0)), 4),
            "event_count": int(track.get("event_count", 0)),
            "match_count": int(track.get("match_count", 0)),
            "labels": dict(track.get("labels", {})),
        }

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            self._prune_locked()
            active_tracks = len(self._tracks)
        return {
            "enabled": self.enabled,
            "active_tracks": active_tracks,
            "similarity_threshold": self.similarity_threshold,
            "temporal_window_seconds": self.temporal_window_seconds,
            "embedding_backend": self.embedding_model.backend,
            "embedding_dim": self.embedding_model.embedding_dim,
            "target_labels": list(self.target_labels),
        }
