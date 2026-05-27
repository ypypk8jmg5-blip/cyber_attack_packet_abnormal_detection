"""
Agent-23: AlertDeduplicator
Role: Suppress duplicate alerts for the same (src_ip, attack_type) within a 60s window.
Stateful: dedup dict with timestamps; Thread-safe.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional, Tuple

DEDUP_WINDOW_SECS = 60


class AlertDeduplicator:
    agent_id = "agent-23-alert-deduplicator"

    def __init__(self, window_secs: int = DEDUP_WINDOW_SECS):
        self._window = window_secs
        self._lock = threading.Lock()
        # key → (last_alert_time, count)
        self._seen: Dict[Tuple[str, str], tuple] = {}
        self._suppressed_count = 0

    def process(self, alert: Dict[str, Any]) -> bool:
        """Return True if alert should be forwarded; False if suppressed."""
        src_ip = alert.get("src_ip", "unknown")
        attack_type = alert.get("attack_type", "unknown")
        key = (src_ip, attack_type)
        now = time.time()

        with self._lock:
            if key in self._seen:
                last_time, count = self._seen[key]
                if now - last_time < self._window:
                    self._seen[key] = (last_time, count + 1)
                    self._suppressed_count += 1
                    return False  # suppress
            self._seen[key] = (now, 1)
            self._cleanup(now)
            return True

    def _cleanup(self, now: float) -> None:
        expired = [k for k, (t, _) in self._seen.items() if now - t >= self._window]
        for k in expired:
            del self._seen[k]

    def stats(self) -> dict:
        with self._lock:
            return {
                "active_keys":      len(self._seen),
                "suppressed_total": self._suppressed_count,
                "window_secs":      self._window,
            }
