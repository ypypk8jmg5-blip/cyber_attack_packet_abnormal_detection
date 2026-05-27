"""
Agent-02: Normalizer
Role: Validate and clip raw feature values to canonical ranges; impute missing fields with 0.
Stateless, CPU-light, < 1ms per packet.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List

from agents.base_agent import BaseAgent, FEATURE_BOUNDS, FEATURE_NAMES, NormalizedPacket, RawBatch


class Normalizer(BaseAgent):
    agent_id = "agent-02-normalizer"

    def process(self, batch: RawBatch) -> List[NormalizedPacket]:
        results = []
        for i, raw in enumerate(batch.raw_packets):
            pkt_id = raw.get("packet_id") or f"PKT-{batch.batch_id}-{i:04d}"
            features, flags = self._normalize(raw)
            results.append(NormalizedPacket(
                packet_id=pkt_id,
                features=features,
                normalization_flags=flags,
            ))
        return results

    def _normalize(self, raw: Dict[str, Any]):
        features: Dict[str, float] = {}
        clipped: List[str] = []
        imputed: List[str] = []

        for name in FEATURE_NAMES:
            lo, hi = FEATURE_BOUNDS[name]
            val = raw.get(name)

            if val is None or val != val:   # None or NaN
                features[name] = float(lo)
                imputed.append(name)
                continue

            try:
                fval = float(val)
            except (TypeError, ValueError):
                features[name] = float(lo)
                imputed.append(name)
                continue

            if fval < lo:
                features[name] = float(lo)
                clipped.append(name)
            elif fval > hi:
                features[name] = float(hi)
                clipped.append(name)
            else:
                features[name] = fval

        flags = {
            "clipped_fields": clipped,
            "imputed_fields": imputed,
            "invalid_dropped": False,
        }
        return features, flags
