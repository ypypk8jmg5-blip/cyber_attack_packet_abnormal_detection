"""
Agent-15: ConfidenceScorer
Role: Platt-scaling calibration of the raw aggregate score.
Stateful: calibration parameters updated by FeedbackCollector.
Falls back to identity mapping until 100 feedback examples are collected.
"""
from __future__ import annotations

import json
import math
import os

from agents.base_agent import AggregatedDecision, BaseAgent, FinalDecision, EnrichedPacket

CALIB_PATH = "data/models/calibration_params.json"


class ConfidenceScorer(BaseAgent):
    agent_id = "agent-15-confidence-scorer"

    def __init__(self, calib_path: str = CALIB_PATH):
        super().__init__()
        self._calib_path = calib_path
        self._a = 1.0  # Platt scaling: sigmoid(a*x + b)
        self._b = 0.0
        self._calibrated = False
        self._load()

    def process(self, decision: AggregatedDecision,
                enriched: "EnrichedPacket | None" = None) -> FinalDecision:
        raw = decision.aggregate_score
        cal = self._calibrate(raw)

        band = "high" if cal > 0.80 else ("medium" if cal > 0.60 else "low")
        # ThresholdManager is the single source of truth for the final decision.
        is_anomaly = False

        return FinalDecision(
            packet_id=decision.packet_id,
            is_anomaly_final=is_anomaly,
            calibrated_confidence=cal,
            attack_type_final=decision.plurality_attack_type,
            aggregate_score=raw,
            vote_summary=decision.vote_summary,
            confidence_band=band,
            enriched_packet=enriched,
        )

    def _calibrate(self, x: float) -> float:
        if not self._calibrated:
            return x
        try:
            return 1.0 / (1.0 + math.exp(-(self._a * x + self._b)))
        except Exception:
            return x

    def update_params(self, a: float, b: float) -> None:
        self._a = a
        self._b = b
        self._calibrated = True
        self._save()

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._calib_path), exist_ok=True)
            with open(self._calib_path, "w") as f:
                json.dump({"a": self._a, "b": self._b, "calibrated": self._calibrated}, f)
        except Exception:
            pass

    def _load(self) -> None:
        if not os.path.exists(self._calib_path):
            return
        try:
            with open(self._calib_path) as f:
                d = json.load(f)
            self._a = d.get("a", 1.0)
            self._b = d.get("b", 0.0)
            self._calibrated = d.get("calibrated", False)
        except Exception:
            pass
