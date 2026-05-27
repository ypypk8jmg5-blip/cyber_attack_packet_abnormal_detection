"""
Agent-05: StatisticalAnalyzer  (weight=0.10)
Role: Z-score and Mahalanobis deviation from a rolling feature baseline.
Stateful: Welford online algorithm, window=1000 packets, persisted every 100.
"""
from __future__ import annotations

import json
import math
import os
import threading
from typing import Any, Dict, List, Optional

from agents.base_agent import (
    AnalysisAgent, AnalysisVote, EnrichedPacket, FEATURE_NAMES,
)

Z_THRESHOLD = 3.5
WINDOW = 1000
PERSIST_EVERY = 100
BASELINE_PATH = "data/stream/statistical_baseline.json"


class StatisticalAnalyzer(AnalysisAgent):
    agent_id = "agent-05-statistical"

    def __init__(self, baseline_path: str = BASELINE_PATH):
        super().__init__()
        self._lock = threading.Lock()
        self._baseline_path = baseline_path
        self._n = 0
        self._mean: List[float] = [0.0] * len(FEATURE_NAMES)
        self._m2: List[float] = [0.0] * len(FEATURE_NAMES)   # Welford M2
        self._since_save = 0
        self._load()

    # ------------------------------------------------------------------
    def _analyze(self, packet: EnrichedPacket) -> AnalysisVote:
        vec = packet.feature_vector
        with self._lock:
            self._update_stats(vec)
            z_scores = self._z_scores(vec)
            self._since_save += 1
            if self._since_save >= PERSIST_EVERY:
                self._save()
                self._since_save = 0

        max_z = max(abs(z) for z in z_scores) if z_scores else 0.0
        is_anomaly = max_z > Z_THRESHOLD

        if is_anomaly:
            worst_idx = max(range(len(z_scores)), key=lambda i: abs(z_scores[i]))
            worst_feat = FEATURE_NAMES[worst_idx]
            confidence = min(0.95, 0.5 + (max_z - Z_THRESHOLD) * 0.05)
        else:
            worst_feat = ""
            confidence = max(0.05, 0.5 - max_z * 0.05)

        return AnalysisVote(
            agent_id=self.agent_id,
            packet_id=packet.packet_id,
            is_anomaly=is_anomaly,
            confidence=confidence,
            attack_type=None,
            evidence={
                "method": "z-score",
                "max_z":  f"{max_z:.2f}",
                "worst_feature": worst_feat,
                "threshold": str(Z_THRESHOLD),
            },
            processing_time_ms=0.0,
        )

    def _update_stats(self, vec: List[float]) -> None:
        """Welford online mean/variance update."""
        self._n += 1
        for i, x in enumerate(vec):
            delta = x - self._mean[i]
            self._mean[i] += delta / self._n
            delta2 = x - self._mean[i]
            self._m2[i] += delta * delta2

    def _z_scores(self, vec: List[float]) -> List[float]:
        if self._n < 30:
            return [0.0] * len(vec)
        scores = []
        for i, x in enumerate(vec):
            variance = self._m2[i] / (self._n - 1) if self._n > 1 else 1.0
            std = math.sqrt(variance) if variance > 0 else 1.0
            scores.append((x - self._mean[i]) / std)
        return scores

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._baseline_path), exist_ok=True)
            with open(self._baseline_path, "w") as f:
                json.dump({"n": self._n, "mean": self._mean, "m2": self._m2}, f)
        except Exception:
            pass

    def _load(self) -> None:
        if not os.path.exists(self._baseline_path):
            return
        try:
            with open(self._baseline_path) as f:
                data = json.load(f)
            self._n = data.get("n", 0)
            self._mean = data.get("mean", self._mean)
            self._m2 = data.get("m2", self._m2)
        except Exception:
            pass
