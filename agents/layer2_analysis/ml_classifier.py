"""
Agent-06: MLClassifierAgent  (weight=0.35)  ★ Primary detector
Role: Run the existing RandomForest best_model.pkl for binary classification.
Stateful: hot-reloads model when file modification time changes.
"""
from __future__ import annotations

import os
from typing import Any, Optional

import joblib
import numpy as np

from agents.base_agent import (
    AnalysisAgent, AnalysisVote, EnrichedPacket, FEATURE_NAMES,
)

DEFAULT_MODEL_PATH = "data/models/best_model.pkl"
DEFAULT_THRESHOLD = 0.5


class MLClassifierAgent(AnalysisAgent):
    agent_id = "agent-06-ml-classifier"

    def __init__(self, model_path: str = DEFAULT_MODEL_PATH, threshold: float = DEFAULT_THRESHOLD):
        super().__init__()
        self._model_path = model_path
        self._threshold = threshold
        self._model_bundle: Optional[dict] = None
        self._mtime: float = 0.0
        self._try_load()

    # ------------------------------------------------------------------
    def _analyze(self, packet: EnrichedPacket) -> AnalysisVote:
        self._hot_reload()

        if self._model_bundle is None:
            return AnalysisVote.neutral(self.agent_id, packet.packet_id)

        clf = self._model_bundle["model"]
        scaler = self._model_bundle["scaler"]
        features = self._model_bundle.get("features", FEATURE_NAMES)

        vec = self._build_vector(packet, features)
        scaled = scaler.transform([vec])
        proba = clf.predict_proba(scaled)[0]

        # proba[1] = probability of anomaly class (label=1)
        anomaly_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
        is_anomaly = anomaly_prob >= self._threshold

        # Feature importance evidence
        importances = clf.feature_importances_
        top_idx = int(np.argmax(importances))
        top_feat = features[top_idx] if top_idx < len(features) else "unknown"

        return AnalysisVote(
            agent_id=self.agent_id,
            packet_id=packet.packet_id,
            is_anomaly=is_anomaly,
            confidence=anomaly_prob,
            attack_type=None,
            evidence={
                "method":         "RandomForest predict_proba",
                "anomaly_prob":   f"{anomaly_prob:.4f}",
                "threshold":      str(self._threshold),
                "top_feature":    top_feat,
            },
            processing_time_ms=0.0,
        )

    def _build_vector(self, packet: EnrichedPacket, features: list) -> list:
        fmap = dict(zip(packet.feature_names, packet.feature_vector))
        return [fmap.get(f, 0.0) for f in features]

    def _hot_reload(self) -> None:
        if not os.path.exists(self._model_path):
            return
        mtime = os.path.getmtime(self._model_path)
        if mtime != self._mtime:
            self._try_load()

    def _try_load(self) -> None:
        if not os.path.exists(self._model_path):
            return
        try:
            bundle = joblib.load(self._model_path)
            if isinstance(bundle, dict) and "model" in bundle:
                self._model_bundle = bundle
            else:
                # Legacy format: bare classifier
                self._model_bundle = {"model": bundle, "scaler": _IdentityScaler(), "features": FEATURE_NAMES}
            self._mtime = os.path.getmtime(self._model_path)
        except Exception:
            pass

    def update_threshold(self, threshold: float) -> None:
        self._threshold = max(0.0, min(1.0, threshold))


class _IdentityScaler:
    """Fallback scaler when model bundle has no scaler."""
    def transform(self, X):
        return X
