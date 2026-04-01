import cv2
import threading

class CameraStream:
    def __init__(self, index=0):
        self.index = index
        self.fps = 30
        self._cap = None
        self._frame = None
        self._lock = threading.Lock()
        self._running = False
        self._thread = None

    def start(self):
        self._cap = cv2.VideoCapture(self.index)
        self._running = True
        self._thread = threading.Thread(target=self._update, daemon=True)
        self._thread.start()

    def _update(self):
        while self._running:
            ret, frame = self._cap.read()
            if ret:
                with self._lock:
                    self._frame = frame

    def read_frame(self):
        with self._lock:
            return self._frame.copy() if self._frame is not None else None

    def is_running(self):
        return self._running

    def resolution(self):
        if self._cap:
            return {"width": int(self._cap.get(3)), "height": int(self._cap.get(4))}
        return {"width": 0, "height": 0}

    def stop(self):
        self._running = False
        if self._cap:
            self._cap.release()