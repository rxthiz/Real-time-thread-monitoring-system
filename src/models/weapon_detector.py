import logging
from typing import Dict, List

import torch
from ultralytics import YOLO

from src.utils.types import WeaponDetection

logger = logging.getLogger(__name__)


class WeaponDetector:
    def __init__(self, cfg: Dict):
        weapon_cfg = cfg["weapon"]
        self.model_family = str(weapon_cfg.get("model_family", "yolo_world")).lower()
        self.allowed_classes = set(weapon_cfg["allowed_classes"])
        self.conf_thr = float(weapon_cfg["confidence_threshold"])
        self.class_thresholds = {
            str(k).lower(): float(v)
            for k, v in weapon_cfg.get("class_thresholds", {}).items()
        }
        if self.class_thresholds:
            self.predict_conf = min(self.conf_thr, min(self.class_thresholds.values()))
        else:
            self.predict_conf = self.conf_thr
        self.imgsz = int(weapon_cfg.get("imgsz", 1280))
        self.iou = float(weapon_cfg.get("iou_threshold", 0.5))
        self.max_det = int(weapon_cfg.get("max_detections", 100))
        self.augment = bool(weapon_cfg.get("augment_inference", True))
        requested_device = weapon_cfg.get("device", None)
        self.device = self._resolve_device(requested_device)

        raw_aliases = weapon_cfg.get("class_aliases", {})
        self.class_aliases = {
            str(alias).lower(): str(target).lower()
            for alias, target in raw_aliases.items()
        }
        self.model = YOLO(weapon_cfg["yolo_weights"])

        # YOLO-World supports open-vocabulary prompts, useful for weapon categories
        # that are not present in standard COCO class sets.
        self.using_world = False
        prompts = weapon_cfg.get("class_prompts", [])
        if self.model_family == "yolo_world":
            try:
                from ultralytics import YOLOWorld

                self.model = YOLOWorld(weapon_cfg["yolo_weights"])
                if prompts:
                    self.model.set_classes([str(p) for p in prompts])
                self.using_world = True
            except Exception:
                self.using_world = False

        logger.info("WeaponDetector initialized with device=%s", self.device)

    @staticmethod
    def _resolve_device(requested_device):
        if requested_device is None:
            # Prefer CUDA by default when available.
            return 0 if torch.cuda.is_available() else "cpu"

        if isinstance(requested_device, str):
            normalized = requested_device.strip().lower()
            if normalized in {"cuda", "cuda:0", "gpu", "0"}:
                if torch.cuda.is_available():
                    return 0
                logger.warning(
                    "Requested GPU device, but CUDA is unavailable. Falling back to CPU."
                )
                return "cpu"
            return requested_device

        if isinstance(requested_device, int):
            if requested_device >= 0 and not torch.cuda.is_available():
                logger.warning(
                    "Requested GPU index %s, but CUDA is unavailable. Falling back to CPU.",
                    requested_device,
                )
                return "cpu"
            return requested_device

        return requested_device

    def infer(self, frame) -> List[WeaponDetection]:
        results = self.model.predict(
            source=frame,
            verbose=False,
            imgsz=self.imgsz,
            conf=self.predict_conf,
            iou=self.iou,
            max_det=self.max_det,
            augment=self.augment,
            device=self.device,
        )
        if not results:
            return []

        out: List[WeaponDetection] = []
        r = results[0]
        names = r.names

        for box in r.boxes:
            cls_id = int(box.cls.item())
            raw_label = str(names[cls_id]).lower()
            label = self.class_aliases.get(raw_label, raw_label)
            conf = float(box.conf.item())
            min_conf = float(self.class_thresholds.get(label, self.conf_thr))
            if label not in self.allowed_classes or conf < min_conf:
                continue
            xyxy = [float(v) for v in box.xyxy[0].tolist()]
            out.append(WeaponDetection(label=label, confidence=conf, bbox_xyxy=xyxy))

        return out
