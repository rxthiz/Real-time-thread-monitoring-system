from typing import Dict, List, Optional

import numpy as np
import torch
import cv2
import os
import tempfile

from src.utils.types import ActionPrediction


class ActionRecognizer:
    """
    Video Swin inference wrapper through MMAction2.

    Expected config:
      action.swin_config
      action.swin_checkpoint
    """

    def __init__(self, cfg: Dict):
        self.top_k = int(cfg["action"].get("top_k", 1))
        self.clip_fps = float(cfg["action"].get("inference_clip_fps", 15.0))
        self.model = None
        self.label_map: Optional[List[str]] = None

        swin_cfg = cfg["action"]["swin_config"]
        swin_ckpt = cfg["action"]["swin_checkpoint"]

        try:
            from mmaction.apis import init_recognizer
        except ImportError as exc:
            raise ImportError(
                "MMAction2 is required for Video Swin action recognition. "
                "Install with: pip install mmaction2 mmengine mmcv-lite"
            ) from exc

        device = "cuda:0" if torch.cuda.is_available() else "cpu"
        self.model = init_recognizer(swin_cfg, swin_ckpt, device=device)

        # Optional labels from dataset metadata if available.
        if hasattr(self.model, "dataset_meta") and self.model.dataset_meta:
            classes = self.model.dataset_meta.get("classes")
            if classes:
                self.label_map = list(classes)

    def infer(self, clip_frames: List[np.ndarray]) -> Optional[ActionPrediction]:
        if self.model is None or not clip_frames:
            return None

        from mmaction.apis import inference_recognizer

        clip_path = self._write_temp_clip(clip_frames, self.clip_fps)
        try:
            pred = inference_recognizer(self.model, clip_path)
        finally:
            if clip_path and os.path.exists(clip_path):
                os.remove(clip_path)

        score_obj = None
        if hasattr(pred, "pred_scores") and pred.pred_scores is not None:
            score_obj = pred.pred_scores
        elif hasattr(pred, "pred_score") and pred.pred_score is not None:
            score_obj = pred.pred_score
        else:
            return None

        if hasattr(score_obj, "numel") and score_obj.numel() == 0:
            return None

        if hasattr(score_obj, "detach"):
            scores = score_obj.detach().cpu().numpy()
        else:
            scores = np.asarray(score_obj)
        if scores.size == 0:
            return None
        top_idx = int(np.argmax(scores))
        top_score = float(scores[top_idx])

        if self.label_map and top_idx < len(self.label_map):
            label = str(self.label_map[top_idx]).lower()
        else:
            label = f"class_{top_idx}"

        return ActionPrediction(label=label, confidence=top_score)

    @staticmethod
    def _write_temp_clip(clip_frames: List[np.ndarray], fps: float) -> str:
        h, w = clip_frames[0].shape[:2]
        fd, path = tempfile.mkstemp(suffix=".mp4")
        os.close(fd)
        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        writer = cv2.VideoWriter(path, fourcc, max(fps, 1.0), (w, h))
        try:
            for frame in clip_frames:
                if frame.shape[:2] != (h, w):
                    frame = cv2.resize(frame, (w, h))
                writer.write(frame)
        finally:
            writer.release()
        return path
