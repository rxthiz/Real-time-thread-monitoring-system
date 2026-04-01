import importlib.util
import logging
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, Optional

import cv2
import numpy as np
import torch
import torch.nn as nn
from torchvision import transforms
from torchvision.models import resnet18, resnet50

logger = logging.getLogger(__name__)


class ReIDEmbeddingModel:
    def __init__(self, cfg: Dict[str, Any]):
        reid_cfg = cfg.get("reid", {})
        self.enabled = bool(reid_cfg.get("enabled", True))
        self.backend_preference = str(reid_cfg.get("backend", "auto")).strip().lower()
        self.model_name = str(reid_cfg.get("model_name", "osnet_x1_0")).strip() or "osnet_x1_0"
        self.weights_path = str(reid_cfg.get("weights_path", "")).strip()
        self.embedding_cache_size = max(32, int(reid_cfg.get("embedding_cache_size", 512)))
        self.min_crop_side = max(8, int(reid_cfg.get("min_crop_side", 18)))
        self.input_width = max(32, int(reid_cfg.get("input_width", 128)))
        self.input_height = max(64, int(reid_cfg.get("input_height", 256)))
        self.handcrafted_bins = max(4, int(reid_cfg.get("handcrafted_bins", 16)))
        self.device_name = str(
            reid_cfg.get("device", "cuda" if torch.cuda.is_available() else "cpu")
        ).strip().lower()
        self.device = torch.device("cuda" if self.device_name == "cuda" and torch.cuda.is_available() else "cpu")
        self._handcrafted_dim = self.handcrafted_bins * 4 + 2 + 8
        self._deep_dim = 0
        self._embedding_dim = self._handcrafted_dim

        self._cache: OrderedDict[str, np.ndarray] = OrderedDict()
        self._backend = "handcrafted"
        self._model: Optional[nn.Module] = None
        self._transform = transforms.Compose(
            [
                transforms.ToPILImage(),
                transforms.Resize((self.input_height, self.input_width)),
                transforms.ToTensor(),
                transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
            ]
        )
        self._load_backend()

    @property
    def backend(self) -> str:
        return self._backend

    @property
    def embedding_dim(self) -> int:
        return int(self._embedding_dim)

    @staticmethod
    def _normalize(vector: np.ndarray) -> np.ndarray:
        if vector.size == 0:
            return vector.astype(np.float32)
        array = vector.astype(np.float32, copy=False)
        norm = float(np.linalg.norm(array))
        if norm <= 0.0:
            return array
        return array / norm

    def _load_backend(self) -> None:
        if not self.enabled:
            self._backend = "disabled"
            return

        if self.backend_preference in {"auto", "torchreid"} and importlib.util.find_spec("torchreid"):
            if self._try_load_torchreid():
                return

        if self.backend_preference in {"auto", "torchvision", "resnet"}:
            if self._try_load_torchvision():
                return

        self._backend = "handcrafted"
        logger.warning(
            "ReID embedding model is using handcrafted fallback. Install torchreid with OSNet weights or configure reid.weights_path for stronger embeddings."
        )
        self._embedding_dim = self._handcrafted_dim

    def _try_load_torchreid(self) -> bool:
        try:
            from torchreid.utils import FeatureExtractor  # type: ignore
        except Exception as exc:
            logger.warning("torchreid import failed: %s", exc)
            return False

        kwargs: Dict[str, Any] = {
            "model_name": self.model_name,
            "device": str(self.device),
        }
        if self.weights_path:
            kwargs["model_path"] = self.weights_path
        try:
            self._model = FeatureExtractor(**kwargs)
        except Exception as exc:
            logger.warning("torchreid OSNet loader failed: %s", exc)
            return False
        self._backend = f"torchreid:{self.model_name}"
        self._deep_dim = self._infer_deep_dim()
        self._embedding_dim = self._handcrafted_dim + self._deep_dim
        logger.info("Loaded torchreid backend %s on %s", self.model_name, self.device)
        return True

    def _try_load_torchvision(self) -> bool:
        try:
            if "18" in self.model_name:
                model = resnet18(weights=None)
                model_label = "resnet18"
            else:
                model = resnet50(weights=None)
                model_label = "resnet50"
            model.fc = nn.Identity()

            resolved = self._resolve_weights_path(self.weights_path)
            if resolved is not None:
                checkpoint = torch.load(resolved, map_location="cpu")
                state_dict = checkpoint.get("state_dict", checkpoint) if isinstance(checkpoint, dict) else checkpoint
                clean_state = {}
                for key, value in state_dict.items():
                    clean_key = str(key)
                    if clean_key.startswith("module."):
                        clean_key = clean_key[7:]
                    clean_state[clean_key] = value
                model.load_state_dict(clean_state, strict=False)
                self._backend = f"torchvision:{model_label}:local"
            else:
                self._backend = f"torchvision:{model_label}:random"
            model.eval()
            model.to(self.device)
            self._model = model
            self._deep_dim = self._infer_deep_dim()
            self._embedding_dim = self._handcrafted_dim + self._deep_dim
            logger.info("Loaded torchvision ReID backbone backend=%s", self._backend)
            return True
        except Exception as exc:
            logger.warning("torchvision ReID loader failed: %s", exc)
            self._model = None
            return False

    @staticmethod
    def _resolve_weights_path(value: str) -> Optional[Path]:
        text = str(value or "").strip()
        if not text:
            return None
        path = Path(text).expanduser()
        if path.is_absolute() and path.exists():
            return path
        local = Path.cwd() / path
        if local.exists():
            return local
        return None

    def extract(
        self,
        *,
        frame: Optional[np.ndarray],
        bbox_xyxy: list[float],
        cache_key: Optional[str] = None,
    ) -> np.ndarray:
        crop = self._extract_crop(frame, bbox_xyxy)
        return self.extract_from_crop(crop, cache_key=cache_key)

    def extract_from_crop(self, crop: Optional[np.ndarray], cache_key: Optional[str] = None) -> np.ndarray:
        if cache_key:
            cached = self._cache_get(cache_key)
            if cached is not None:
                return cached

        embedding = self._handcrafted_embedding(crop)
        deep = self._deep_embedding(crop)
        if deep is not None and deep.size > 0:
            embedding = self._normalize(np.concatenate([deep, embedding], dtype=np.float32))

        if cache_key:
            self._cache_set(cache_key, embedding)
        return embedding

    def _infer_deep_dim(self) -> int:
        dummy = np.zeros((self.input_height, self.input_width, 3), dtype=np.uint8)
        vector = self._deep_embedding(dummy)
        return int(vector.size) if vector is not None else 0

    def _deep_embedding(self, crop: Optional[np.ndarray]) -> Optional[np.ndarray]:
        if crop is None or crop.size == 0 or self._model is None:
            return None

        if hasattr(self._model, "__class__") and self._backend.startswith("torchreid:"):
            try:
                # torchreid FeatureExtractor expects RGB images.
                rgb = cv2.cvtColor(crop, cv2.COLOR_BGR2RGB)
                feature = self._model([rgb])
                if torch.is_tensor(feature):
                    vector = feature.detach().cpu().numpy().reshape(-1).astype(np.float32)
                else:
                    vector = np.asarray(feature).reshape(-1).astype(np.float32)
                return self._normalize(vector)
            except Exception as exc:
                logger.debug("torchreid feature extraction failed: %s", exc)
                return None

        try:
            rgb = cv2.cvtColor(crop, cv2.COLOR_BGR2RGB)
            tensor = self._transform(rgb).unsqueeze(0).to(self.device)
            with torch.no_grad():
                feature = self._model(tensor)
            vector = feature.detach().cpu().numpy().reshape(-1).astype(np.float32)
            return self._normalize(vector)
        except Exception as exc:
            logger.debug("torchvision feature extraction failed: %s", exc)
            return None

    def _handcrafted_embedding(self, crop: Optional[np.ndarray]) -> np.ndarray:
        if crop is None or crop.size == 0:
            return np.zeros(self._handcrafted_dim, dtype=np.float32)

        resized = cv2.resize(crop, (self.input_width, self.input_height), interpolation=cv2.INTER_LINEAR)
        hsv = cv2.cvtColor(resized, cv2.COLOR_BGR2HSV)
        lab = cv2.cvtColor(resized, cv2.COLOR_BGR2LAB)
        gray = cv2.cvtColor(resized, cv2.COLOR_BGR2GRAY)

        bins = self.handcrafted_bins
        h_hist = cv2.calcHist([hsv], [0], None, [bins], [0, 180]).flatten()
        s_hist = cv2.calcHist([hsv], [1], None, [bins], [0, 256]).flatten()
        v_hist = cv2.calcHist([hsv], [2], None, [bins], [0, 256]).flatten()
        l_hist = cv2.calcHist([lab], [0], None, [bins], [0, 256]).flatten()
        edge = cv2.Canny(gray, 60, 180)
        edge_hist = cv2.calcHist([edge], [0], None, [2], [0, 256]).flatten()

        moments = np.array(
            [
                float(np.mean(gray)),
                float(np.std(gray)),
                float(np.mean(resized[:, :, 0])),
                float(np.mean(resized[:, :, 1])),
                float(np.mean(resized[:, :, 2])),
                float(np.std(resized[:, :, 0])),
                float(np.std(resized[:, :, 1])),
                float(np.std(resized[:, :, 2])),
            ],
            dtype=np.float32,
        )

        feature = np.concatenate([h_hist, s_hist, v_hist, l_hist, edge_hist, moments]).astype(np.float32)
        return self._normalize(feature)

    def _extract_crop(self, frame: Optional[np.ndarray], bbox_xyxy: list[float]) -> Optional[np.ndarray]:
        if frame is None or frame.size == 0 or len(bbox_xyxy) != 4:
            return None
        frame_h, frame_w = frame.shape[:2]
        if frame_h <= 0 or frame_w <= 0:
            return None

        x1, y1, x2, y2 = [int(round(float(v))) for v in bbox_xyxy]
        x1 = max(0, min(frame_w - 1, x1))
        y1 = max(0, min(frame_h - 1, y1))
        x2 = max(0, min(frame_w, x2))
        y2 = max(0, min(frame_h, y2))
        if x2 <= x1 or y2 <= y1:
            return None
        if (x2 - x1) < self.min_crop_side or (y2 - y1) < self.min_crop_side:
            return None
        return frame[y1:y2, x1:x2]

    def _cache_get(self, key: str) -> Optional[np.ndarray]:
        value = self._cache.get(key)
        if value is None:
            return None
        self._cache.move_to_end(key)
        return value.copy()

    def _cache_set(self, key: str, value: np.ndarray) -> None:
        self._cache[key] = value.copy()
        self._cache.move_to_end(key)
        while len(self._cache) > self.embedding_cache_size:
            self._cache.popitem(last=False)
