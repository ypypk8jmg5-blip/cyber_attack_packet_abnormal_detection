"""
Agent-03: FeatureExtractor
Role: Build the 12-dim feature vector and compute derived features.
Stateless, numpy-vectorized, < 1ms per packet.
"""
from __future__ import annotations

import math
from typing import Any, Dict, List

from agents.base_agent import BaseAgent, FEATURE_NAMES, FeatureEnvelope, NormalizedPacket


class FeatureExtractor(BaseAgent):
    agent_id = "agent-03-feature-extractor"

    def process(self, packets: List[NormalizedPacket]) -> List[FeatureEnvelope]:
        return [self._extract(p) for p in packets]

    def _extract(self, pkt: NormalizedPacket) -> FeatureEnvelope:
        f = pkt.features
        vec = [f[name] for name in FEATURE_NAMES]

        pps = max(f["packets_per_sec"], 1e-6)
        bps = f["bytes_per_sec"]
        conn = max(f["connection_count"], 1)
        failed = f["failed_attempts"]

        derived = {
            "bytes_per_packet": bps / pps,
            "failure_rate":     failed / conn,
            "connection_intensity": pps / conn,
        }

        protocol_map = {0: "TCP", 1: "UDP", 2: "ICMP"}
        metadata = {
            "protocol_name": protocol_map.get(int(f["protocol"]), "UNKNOWN"),
            "dst_port":      int(f["dst_port"]),
        }

        return FeatureEnvelope(
            packet_id=pkt.packet_id,
            feature_vector=vec,
            feature_names=list(FEATURE_NAMES),
            derived_features=derived,
            metadata=metadata,
        )
