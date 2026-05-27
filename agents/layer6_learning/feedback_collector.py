"""
Agent-25: FeedbackCollector
Role: Collect operator feedback (TP/FP/FN) and auto-generate FP feedback
      for normal_ftp / normal_stream mislabeled alerts.
Triggers OnlineModelUpdater after BATCH_SIZE events.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

FEEDBACK_PATH = "data/feedback/feedback_log.jsonl"
BATCH_SIZE = 50    # trigger updater after this many feedback events
AUTO_FP_NORMAL_TYPES = {"normal_ftp", "normal_stream", "normal_web", "normal_dns", "normal_email"}


class FeedbackCollector:
    agent_id = "agent-25-feedback-collector"

    def __init__(self, feedback_path: str = FEEDBACK_PATH,
                 on_batch_ready: Optional[Callable[[List[dict]], None]] = None):
        self._path = feedback_path
        self._lock = threading.Lock()
        self._buffer: List[Dict[str, Any]] = []
        self._on_batch_ready = on_batch_ready
        os.makedirs(os.path.dirname(feedback_path), exist_ok=True)

    def record(self, alert: Dict[str, Any], feedback_type: str,
               corrected_attack_type: Optional[str] = None,
               operator_id: str = "operator") -> None:
        """Manually record operator feedback."""
        entry = {
            "alert_id":             alert.get("alert_id", ""),
            "feedback_type":        feedback_type,   # true_positive | false_positive | false_negative
            "operator_id":          operator_id,
            "timestamp":            datetime.utcnow().isoformat(),
            "corrected_attack_type": corrected_attack_type,
            "packet_features":      alert.get("key_features", {}),
            "predicted_attack_type": alert.get("attack_type"),
            "confidence":           alert.get("confidence"),
        }
        self._add(entry)

    def auto_feedback(self, alert: Dict[str, Any], true_attack_type: Optional[str]) -> None:
        """Auto-generate feedback when ground truth is known (e.g., from stream labels)."""
        predicted = alert.get("attack_type", "unknown")
        is_true_normal = true_attack_type in AUTO_FP_NORMAL_TYPES if true_attack_type else False

        if is_true_normal and alert.get("severity") in {"CRITICAL", "HIGH"}:
            # System flagged a normal packet as high-severity → false positive
            self.record(alert, "false_positive",
                        corrected_attack_type=true_attack_type, operator_id="system_auto")

    def _add(self, entry: Dict[str, Any]) -> None:
        with self._lock:
            self._buffer.append(entry)
            self._write(entry)
            if len(self._buffer) >= BATCH_SIZE:
                batch = list(self._buffer)
                self._buffer.clear()
                if self._on_batch_ready:
                    threading.Thread(target=self._on_batch_ready, args=(batch,), daemon=True).start()

    def _write(self, entry: Dict[str, Any]) -> None:
        try:
            with open(self._path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    def load_all(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self._path):
            return []
        try:
            with open(self._path) as f:
                return [json.loads(line) for line in f if line.strip()]
        except Exception:
            return []
