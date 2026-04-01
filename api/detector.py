import cv2

# Plug in your CLIP/YOLO model here
class ObjectDetector:
    def __init__(self):
        # TODO: load your actual model from src/
        pass

    def detect(self, frame) -> list:
        # Returns list of dicts: {label, confidence, bbox: [x,y,w,h]}
        # Replace this stub with your real model inference
        return []

    def draw(self, frame, detections: list):
        for d in detections:
            x, y, w, h = d["bbox"]
            label = f'{d["label"]} {d["confidence"]:.2f}'
            cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)
            cv2.putText(frame, label, (x, y-10),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
        return frame