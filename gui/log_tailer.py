"""LogTailer — 로그 파일 테일 워커 (QThread)"""
import os
from PyQt5.QtCore import QThread, pyqtSignal

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(PROJECT_ROOT, "logs", "training_progress.log")
POLL_MS  = 800


class LogTailer(QThread):
    new_lines = pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = True
        self._offset = 0

    def run(self):
        while self._running:
            if os.path.exists(LOG_PATH):
                try:
                    size = os.path.getsize(LOG_PATH)
                    if size > self._offset:
                        with open(LOG_PATH, encoding="utf-8", errors="replace") as f:
                            f.seek(self._offset)
                            lines = f.readlines()
                        self._offset = size
                        clean = [l.rstrip() for l in lines if l.strip()]
                        if clean:
                            self.new_lines.emit(clean)
                    elif size < self._offset:
                        # 파일 재생성 (로그 로테이션)
                        self._offset = 0
                except OSError:
                    pass
            self.msleep(POLL_MS)

    def reset(self):
        self._offset = 0

    def stop(self):
        self._running = False
