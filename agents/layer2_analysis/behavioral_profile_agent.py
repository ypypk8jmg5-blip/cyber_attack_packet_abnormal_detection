"""
Agent-09: BehavioralProfileAgent  (weight=0.15)
Role: Maintain per-src_ip EWMA profiles; flag deviations from established baselines.
Stateful: ip_profiles dict, persisted every 5 min, expired after 24h inactivity.
"""
from __future__ import annotations

import json
import math
import os
import threading
import time
from typing import Any, Dict, Optional

from agents.base_agent import (
    AnalysisAgent, AnalysisVote, EnrichedPacket, FEATURE_NAMES,
)

ALPHA = 0.1           # EWMA decay — slow adaptation
DEVIATION_THRESH = 4.0
MIN_PACKETS = 10      # profile needs this many before it's trusted
EXPIRY_SECS = 86400   # 24h
PERSIST_PATH = "data/stream/ip_profiles.json"
PERSIST_INTERVAL = 300  # 5 min

_MONITORED = ["packets_per_sec", "bytes_per_sec", "connection_count", "failed_attempts"]
_IDX = {f: i for i, f in enumerate(FEATURE_NAMES)}


class _IPProfile:
    __slots__ = ("ewma", "ewm2", "n", "last_seen")

    def __init__(self):
        self.ewma: Dict[str, float] = {k: 0.0 for k in _MONITORED}
        self.ewm2: Dict[str, float] = {k: 0.001 for k in _MONITORED}  # variance
        self.n = 0
        self.last_seen = time.time()

    def update(self, fmap: Dict[str, float]) -> float:
        self.n += 1
        self.last_seen = time.time()
        max_dev = 0.0
        for feat in _MONITORED:
            x = fmap.get(feat, 0.0)
            old_mean = self.ewma[feat]
            self.ewma[feat] = ALPHA * x + (1 - ALPHA) * old_mean
            diff = x - old_mean
            self.ewm2[feat] = ALPHA * diff * diff + (1 - ALPHA) * self.ewm2[feat]
            if self.n >= MIN_PACKETS and self.ewm2[feat] > 0:
                std = math.sqrt(self.ewm2[feat])
                dev = abs(x - old_mean) / std
                max_dev = max(max_dev, dev)
        return max_dev


class BehavioralProfileAgent(AnalysisAgent):
    agent_id = "agent-09-behavioral-profile"

    def __init__(self, persist_path: str = PERSIST_PATH):
        super().__init__()
        self._lock = threading.Lock()
        self._profiles: Dict[str, _IPProfile] = {}
        self._persist_path = persist_path
        self._last_persist = time.time()
        self._load()

    def _analyze(self, packet: EnrichedPacket) -> AnalysisVote:
        src_ip = packet.metadata.get("src_ip", "unknown")
        fmap = dict(zip(packet.feature_names, packet.feature_vector))

        with self._lock:
            if src_ip not in self._profiles:
                self._profiles[src_ip] = _IPProfile()
            profile = self._profiles[src_ip]
            max_dev = profile.update(fmap)
            if time.time() - self._last_persist > PERSIST_INTERVAL:
                self._save()
                self._last_persist = time.time()
                self._expire()

        if profile.n < MIN_PACKETS:
            return AnalysisVote.neutral(self.agent_id, packet.packet_id)

        is_anomaly = max_dev > DEVIATION_THRESH
        confidence = min(0.90, 0.5 + (max_dev - DEVIATION_THRESH) * 0.05) if is_anomaly else max(0.05, 0.5 - max_dev * 0.05)

        return AnalysisVote(
            agent_id=self.agent_id,
            packet_id=packet.packet_id,
            is_anomaly=is_anomaly,
            confidence=confidence,
            attack_type=None,
            evidence={
                "method":    "EWMA behavioral profile",
                "src_ip":    src_ip,
                "max_deviation": f"{max_dev:.2f}",
                "threshold": str(DEVIATION_THRESH),
                "profile_n": str(profile.n),
            },
            processing_time_ms=0.0,
        )

    def _expire(self) -> None:
        now = time.time()
        expired = [ip for ip, p in self._profiles.items() if now - p.last_seen > EXPIRY_SECS]
        for ip in expired:
            del self._profiles[ip]

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._persist_path), exist_ok=True)
            data = {
                ip: {"ewma": p.ewma, "ewm2": p.ewm2, "n": p.n, "last_seen": p.last_seen}
                for ip, p in self._profiles.items()
            }
            with open(self._persist_path, "w") as f:
                json.dump(data, f)
        except Exception:
            pass

    def _load(self) -> None:
        if not os.path.exists(self._persist_path):
            return
        try:
            with open(self._persist_path) as f:
                data = json.load(f)
            for ip, d in data.items():
                p = _IPProfile()
                p.ewma = d["ewma"]
                p.ewm2 = d["ewm2"]
                p.n = d["n"]
                p.last_seen = d["last_seen"]
                self._profiles[ip] = p
        except Exception:
            pass
