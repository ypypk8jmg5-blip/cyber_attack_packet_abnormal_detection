"""
Agent-16: ThresholdManager
Role: Per-attack-type detection threshold table; auto-adjust via FPR/FNR feedback.
Stateful: threshold table persisted to JSON.
"""
from __future__ import annotations

import json
import os
import threading
from typing import Dict, Optional

from agents.base_agent import ATTACK_TYPES, BaseAgent, FinalDecision

THRESHOLD_PATH = "data/models/thresholds.json"
DEFAULT_THRESHOLD = 0.60
THRESHOLD_MIN = 0.30
THRESHOLD_MAX = 0.80
FPR_ADJUST_UP = 0.02
FNR_ADJUST_DOWN = 0.02


class ThresholdManager(BaseAgent):
    agent_id = "agent-16-threshold-manager"

    def __init__(self, threshold_path: str = THRESHOLD_PATH):
        super().__init__()
        self._lock = threading.Lock()
        self._path = threshold_path
        self._thresholds: Dict[str, float] = {t: DEFAULT_THRESHOLD for t in ATTACK_TYPES}
        self._thresholds["global"] = DEFAULT_THRESHOLD
        self._load()

    def process(self, decision: FinalDecision) -> FinalDecision:
        attack = decision.attack_type_final
        threshold = self._get_threshold(attack)
        decision.is_anomaly_final = decision.calibrated_confidence >= threshold
        return decision

    def _get_threshold(self, attack_type: Optional[str]) -> float:
        with self._lock:
            if attack_type and attack_type in self._thresholds:
                return self._thresholds[attack_type]
            return self._thresholds["global"]

    def adjust(self, attack_type: str, fpr_exceeded: bool = False, fnr_exceeded: bool = False) -> None:
        with self._lock:
            key = attack_type if attack_type in self._thresholds else "global"
            t = self._thresholds[key]
            if fpr_exceeded:
                t = min(THRESHOLD_MAX, t + FPR_ADJUST_UP)
            if fnr_exceeded:
                t = max(THRESHOLD_MIN, t - FNR_ADJUST_DOWN)
            self._thresholds[key] = t
        self._save()

    def get_all(self) -> Dict[str, float]:
        with self._lock:
            return dict(self._thresholds)

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            with open(self._path, "w") as f:
                json.dump(self._thresholds, f, indent=2)
        except Exception:
            pass

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path) as f:
                data = json.load(f)
            for k, v in data.items():
                self._thresholds[k] = float(v)
        except Exception:
            pass
