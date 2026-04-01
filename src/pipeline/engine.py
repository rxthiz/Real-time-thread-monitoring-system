from collections import deque
from queue import Empty, Full, Queue
from threading import Event, Thread
from time import monotonic
from typing import Deque, Dict, List

import cv2
import numpy as np

from src.alerts.notifier import AlertNotifier
from src.fusion.rule_engine import RuleBasedFusion
from src.models.action_recognizer import ActionRecognizer
from src.models.weapon_detector import WeaponDetector
from src.pipeline.stream_router import StreamRouter


class ThreatEngine:
    def __init__(self, cfg: Dict):
        self.cfg = cfg
        self.detector = WeaponDetector(cfg)
        self.action_enabled = bool(cfg["action"].get("enabled", True))
        self.action_async = bool(cfg["action"].get("async_inference", True))
        self.action_infer_every = int(cfg["action"].get("infer_every_n_processed_frames", 12))
        self.action_recognizer = ActionRecognizer(cfg) if self.action_enabled else None
        self.fusion = RuleBasedFusion(cfg)
        self.notifier = AlertNotifier(cfg)
        self.router = StreamRouter()

        self.process_every = int(cfg["pipeline"].get("process_every_n_frames", 2))
        self.min_alert_gap = float(cfg["pipeline"].get("min_alert_gap_seconds", 2.0))
        self.progress_every = int(cfg["pipeline"].get("progress_every_n_frames", 60))
        self.show_progress = bool(cfg["pipeline"].get("show_progress", True))
        self.live_view = bool(cfg["pipeline"].get("live_view", True))
        self.window_name = str(cfg["pipeline"].get("window_name", "Threat Monitor"))
        self.action_frame_interval = int(cfg["action"].get("frame_interval", 2))

        clip_len = int(cfg["action"]["clip_len"])
        self.clip_buffer: Deque[np.ndarray] = deque(maxlen=clip_len)
        self.last_alert_at = 0.0

    def run_video(self, video_path: str) -> None:
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            raise RuntimeError(f"Unable to open video: {video_path}")
        self._run_capture(cap, source_name=video_path, use_wallclock_ts=False)

    def run_camera(self, camera_index: int = 0) -> None:
        cap = cv2.VideoCapture(camera_index)
        if not cap.isOpened():
            raise RuntimeError(f"Unable to open camera index: {camera_index}")
        self._run_capture(cap, source_name=f"camera:{camera_index}", use_wallclock_ts=True)

    def _run_capture(
        self, cap: cv2.VideoCapture, source_name: str, use_wallclock_ts: bool
    ) -> None:
        action_jobs: Queue = Queue(maxsize=1)
        action_results: Queue = Queue(maxsize=1)
        action_stop = Event()
        action_worker = self._start_action_worker(action_jobs, action_results, action_stop)

        fps = cap.get(cv2.CAP_PROP_FPS) or 30.0
        frame_idx = 0
        processed_frames = 0
        alert_count = 0
        start = monotonic()
        last_frame_tick = start
        live_fps = 0.0
        last_weapon_dets = []
        last_action_pred = None
        last_det_frame_idx = -10**9

        if self.show_progress:
            print(
                f"[INFO] Started video processing: {source_name} | fps={fps:.2f} | process_every={self.process_every}"
            )

        while True:
            ok, frame = cap.read()
            if not ok:
                break

            frame_idx += 1
            processed_frames += 1
            now_tick = monotonic()
            dt = now_tick - last_frame_tick
            last_frame_tick = now_tick
            if dt > 0:
                inst_fps = 1.0 / dt
                # Smooth live FPS for stable on-screen display.
                if live_fps <= 0.0:
                    live_fps = inst_fps
                else:
                    live_fps = (0.9 * live_fps) + (0.1 * inst_fps)
            if frame_idx % self.action_frame_interval == 0:
                self.clip_buffer.append(frame)
            weapon_dets = []
            ts = self._get_timestamp_sec(cap, frame_idx, fps, start, use_wallclock_ts)
            while True:
                try:
                    last_action_pred = action_results.get_nowait()
                except Empty:
                    break

            if self.show_progress and frame_idx % self.progress_every == 0:
                elapsed = monotonic() - start
                print(
                    f"[PROGRESS] frame={frame_idx} ts={ts:.2f}s elapsed={elapsed:.2f}s stream_fps={live_fps:.2f}"
                )

            if frame_idx % self.process_every == 0:
                weapon_dets = self.detector.infer(frame)
                if weapon_dets:
                    last_weapon_dets = weapon_dets
                    last_det_frame_idx = frame_idx

                if (
                    self.action_enabled
                    and weapon_dets
                    and len(self.clip_buffer) == self.clip_buffer.maxlen
                    and frame_idx % max(1, self.action_infer_every) == 0
                ):
                    if self.action_async:
                        clip = [f.copy() for f in self.clip_buffer]
                        self._push_action_job(action_jobs, clip)
                    else:
                        pred = self.action_recognizer.infer(list(self.clip_buffer))
                        if pred is not None:
                            last_action_pred = pred

                if weapon_dets:
                    weapon_streams = self.router.split_weapon_streams(weapon_dets)
                    _ = self.router.split_action_stream(last_action_pred)

                    now = monotonic()
                    if now - self.last_alert_at >= self.min_alert_gap:
                        for _, stream_dets in weapon_streams.items():
                            top_weapon = max(stream_dets, key=lambda d: d.confidence)
                            event = self.fusion.fuse(ts, top_weapon, last_action_pred)
                            if event.level in {"HIGH", "MEDIUM"}:
                                self.notifier.emit(event)
                                alert_count += 1
                                self.last_alert_at = now
                                break

            if self.live_view:
                disp = frame.copy()
                draw_weapon_dets = weapon_dets
                if (
                    not draw_weapon_dets
                    and frame_idx - last_det_frame_idx <= self.process_every
                ):
                    draw_weapon_dets = last_weapon_dets

                for det in draw_weapon_dets:
                    x1, y1, x2, y2 = [int(v) for v in det.bbox_xyxy]
                    cv2.rectangle(disp, (x1, y1), (x2, y2), (0, 0, 255), 2)
                    cv2.putText(
                        disp,
                        f"{det.label}:{det.confidence:.2f}",
                        (x1, max(20, y1 - 8)),
                        cv2.FONT_HERSHEY_SIMPLEX,
                        0.6,
                        (0, 0, 255),
                        2,
                    )
                if last_action_pred is not None:
                    cv2.putText(
                        disp,
                        f"action:{last_action_pred.label}:{last_action_pred.confidence:.2f}",
                        (10, 28),
                        cv2.FONT_HERSHEY_SIMPLEX,
                        0.7,
                        (0, 255, 255),
                        2,
                    )
                cv2.putText(
                    disp,
                    f"frame:{frame_idx} ts:{ts:.2f}s",
                    (10, 56),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.7,
                    (0, 255, 0),
                    2,
                )
                cv2.putText(
                    disp,
                    f"LIVE FPS: {live_fps:.2f}",
                    (10, 84),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.7,
                    (255, 255, 0),
                    2,
                )
                cv2.imshow(self.window_name, disp)
                key = cv2.waitKey(1) & 0xFF
                if key == ord("q"):
                    if self.show_progress:
                        print("[INFO] Stopped by user (pressed 'q').")
                    break

        cap.release()
        if action_worker is not None:
            action_stop.set()
            self._push_action_job(action_jobs, None)
            action_worker.join(timeout=1.5)
        if self.live_view:
            cv2.destroyAllWindows()
        if self.show_progress:
            total_elapsed = monotonic() - start
            avg_proc_fps = processed_frames / total_elapsed if total_elapsed > 0 else 0.0
            print(
                f"[INFO] Completed video processing: frames={processed_frames} alerts={alert_count} elapsed={total_elapsed:.2f}s avg_proc_fps={avg_proc_fps:.2f}"
            )

    @staticmethod
    def _get_timestamp_sec(
        cap: cv2.VideoCapture,
        frame_idx: int,
        fps: float,
        start_monotonic: float,
        use_wallclock_ts: bool,
    ) -> float:
        if use_wallclock_ts:
            return monotonic() - start_monotonic

        pos_msec = cap.get(cv2.CAP_PROP_POS_MSEC)
        if pos_msec and pos_msec > 0:
            return pos_msec / 1000.0

        if fps > 0:
            return frame_idx / fps
        return monotonic() - start_monotonic

    def _start_action_worker(
        self, action_jobs: Queue, action_results: Queue, action_stop: Event
    ) -> Thread | None:
        if not self.action_enabled or not self.action_async:
            return None

        def _worker() -> None:
            while not action_stop.is_set():
                try:
                    job = action_jobs.get(timeout=0.1)
                except Empty:
                    continue
                if job is None:
                    break
                try:
                    pred = self.action_recognizer.infer(job)
                    if pred is not None:
                        if action_results.full():
                            try:
                                action_results.get_nowait()
                            except Empty:
                                pass
                        action_results.put_nowait(pred)
                finally:
                    action_jobs.task_done()

        worker = Thread(target=_worker, daemon=True, name="action-infer-worker")
        worker.start()
        return worker

    @staticmethod
    def _push_action_job(action_jobs: Queue, clip_or_none) -> None:
        if action_jobs.full():
            try:
                action_jobs.get_nowait()
            except Empty:
                pass
        try:
            action_jobs.put_nowait(clip_or_none)
        except Full:
            pass
