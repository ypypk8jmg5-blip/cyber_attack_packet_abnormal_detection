"""
Agent-27: DriftDetector
Role: Monitor feature distribution drift (PSI + KS test) and signal
      the orchestrator when concept drift requires retraining.
Stateful: reference distribution loaded from training data.
Checks every 1000 packets; persists reference to JSON.
"""
from __future__ import annotations

import json
import logging
import math
import os
import threading
from typing import Any, Dict, List, Optional

from agents.base_agent import FEATURE_NAMES

REFERENCE_PATH = "data/models/reference_distribution.json"
DRIFT_LOG_PATH = "logs/drift_alerts.log"
BUCKET_COUNT = 10
PSI_MILD = 0.10
PSI_MODERATE = 0.20
PSI_SEVERE = 0.30
CHECK_INTERVAL = 1000  # packets

logging.basicConfig(
    filename=DRIFT_LOG_PATH, level=logging.WARNING,
    format="%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S",
)
_log = logging.getLogger("drift")


class DriftDetector:
    agent_id = "agent-27-drift-detector"

    def __init__(self, reference_path: str = REFERENCE_PATH):
        self._lock = threading.Lock()
        self._ref_path = reference_path
        self._reference: Optional[Dict[str, List[float]]] = None  # feature → bucket counts
        self._buffer: List[List[float]] = []
        self._packet_count = 0
        self._on_severe: Optional[Any] = None   # callback to PipelineOrchestrator
        self._load_reference()

    def set_severe_callback(self, cb) -> None:
        self._on_severe = cb

    def record(self, feature_vector: List[float]) -> None:
        with self._lock:
            self._buffer.append(feature_vector)
            self._packet_count += 1
            if self._packet_count % CHECK_INTERVAL == 0:
                self._check_drift()

    def build_reference(self, feature_vectors: List[List[float]]) -> None:
        """Build reference distribution from training data."""
        ref: Dict[str, List[float]] = {}
        for i, fname in enumerate(FEATURE_NAMES):
            vals = [v[i] for v in feature_vectors]
            ref[fname] = self._histogram(vals, BUCKET_COUNT)
        with self._lock:
            self._reference = ref
        self._save_reference(ref)

    # ------------------------------------------------------------------

    def _check_drift(self) -> None:
        if not self._reference or len(self._buffer) < 100:
            return

        recent = list(self._buffer[-CHECK_INTERVAL:])
        results = {}
        for i, fname in enumerate(FEATURE_NAMES):
            vals = [v[i] for v in recent]
            current_hist = self._histogram(vals, BUCKET_COUNT)
            ref_hist = self._reference.get(fname)
            if ref_hist:
                psi = self._psi(ref_hist, current_hist)
                results[fname] = psi

        overall_psi = sum(results.values()) / len(results) if results else 0.0
        level = self._severity(overall_psi)

        if overall_psi >= PSI_MILD:
            _log.warning("[%s] PSI=%.3f features=%s", level, overall_psi,
                         {k: f"{v:.3f}" for k, v in sorted(results.items(), key=lambda x: -x[1])[:3]})

        if level == "SEVERE" and self._on_severe:
            self._on_severe(overall_psi, results)

    @staticmethod
    def _histogram(values: List[float], n_buckets: int) -> List[float]:
        if not values:
            return [1.0 / n_buckets] * n_buckets
        lo, hi = min(values), max(values)
        if lo == hi:
            buckets = [0.0] * n_buckets
            buckets[0] = 1.0
            return buckets
        width = (hi - lo) / n_buckets
        counts = [0] * n_buckets
        for v in values:
            idx = min(int((v - lo) / width), n_buckets - 1)
            counts[idx] += 1
        total = len(values)
        # Add small smoothing to avoid log(0)
        return [(c + 0.5) / (total + 0.5 * n_buckets) for c in counts]

    @staticmethod
    def _psi(expected: List[float], actual: List[float]) -> float:
        psi = 0.0
        for e, a in zip(expected, actual):
            if e > 0 and a > 0:
                psi += (a - e) * math.log(a / e)
        return psi

    @staticmethod
    def _severity(psi: float) -> str:
        if psi >= PSI_SEVERE:
            return "SEVERE"
        if psi >= PSI_MODERATE:
            return "MODERATE"
        if psi >= PSI_MILD:
            return "MILD"
        return "NONE"

    def _save_reference(self, ref: Dict[str, List[float]]) -> None:
        try:
            os.makedirs(os.path.dirname(self._ref_path), exist_ok=True)
            with open(self._ref_path, "w") as f:
                json.dump(ref, f)
        except Exception:
            pass

    def _load_reference(self) -> None:
        if not os.path.exists(self._ref_path):
            return
        try:
            with open(self._ref_path) as f:
                self._reference = json.load(f)
        except Exception:
            pass
