"""DataMonitor — JSON 파일 폴링 워커 (QThread)"""
import json
import os
from PyQt5.QtCore import QThread, pyqtSignal

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DASHBOARD_PATH = os.path.join(PROJECT_ROOT, "logs", "dashboard.json")
METRICS_PATH   = os.path.join(PROJECT_ROOT, "data", "metrics", "latest.json")
ALERTS_PATH    = os.path.join(PROJECT_ROOT, "data", "alerts", "summary.json")

POLL_MS = 1500


def _safe_load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


class DataMonitor(QThread):
    dashboard_updated = pyqtSignal(dict)
    metrics_updated   = pyqtSignal(dict)
    alerts_updated    = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = True
        self._mtimes: dict[str, float] = {}

    def run(self):
        while self._running:
            self._check(DASHBOARD_PATH, "dashboard", self.dashboard_updated)
            self._check(METRICS_PATH,   "metrics",   self.metrics_updated)
            self._check(ALERTS_PATH,    "alerts",    self.alerts_updated)
            self.msleep(POLL_MS)

    def _check(self, path: str, key: str, signal):
        if not os.path.exists(path):
            return
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return
        if self._mtimes.get(key) != mtime:
            self._mtimes[key] = mtime
            data = _safe_load(path)
            if data:
                signal.emit(data)

    def stop(self):
        self._running = False
