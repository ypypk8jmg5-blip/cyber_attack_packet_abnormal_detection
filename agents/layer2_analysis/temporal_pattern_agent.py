"""
Agent-10: TemporalPatternAgent  (weight=0.05)
Role: Detect burst patterns (CUSUM) and periodic beaconing (FFT) in packet arrival times.
Stateful: 60-second rolling time-series at 1s resolution.
"""
from __future__ import annotations

import collections
import math
import threading
import time
from typing import Deque, List

from agents.base_agent import (
    AnalysisAgent, AnalysisVote, EnrichedPacket,
)

WINDOW_SECS = 60
BURST_RATIO_THRESH = 10.0   # max_1s / mean_10s > this → burst
CUSUM_THRESH = 5.0
# Known C2 beacon periods (seconds); detect if FFT dominant frequency matches
BEACON_PERIODS = {30, 60, 300}


class TemporalPatternAgent(AnalysisAgent):
    agent_id = "agent-10-temporal-pattern"

    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()
        # deque of (timestamp_sec, count) bins — 1-second resolution
        self._bins: Deque[List] = collections.deque(maxlen=WINDOW_SECS)
        self._current_bin_time = int(time.time())
        self._current_bin_count = 0
        self._cusum = 0.0
        self._cusum_mean = 0.0

    def _analyze(self, packet: EnrichedPacket) -> AnalysisVote:
        now = int(time.time())
        with self._lock:
            self._tick(now)
            counts = [b[1] for b in self._bins]

        if len(counts) < 10:
            return AnalysisVote.neutral(self.agent_id, packet.packet_id)

        burst_score, burst_flag = self._detect_burst(counts)
        beacon_flag = self._detect_beacon(counts)

        is_anomaly = burst_flag or beacon_flag
        if is_anomaly:
            confidence = min(0.85, 0.55 + burst_score * 0.03)
            attack_type = "ddos" if burst_flag else "botnet_c2"
            reason = "burst" if burst_flag else "beaconing"
        else:
            confidence = max(0.10, 0.4 - burst_score * 0.02)
            attack_type = None
            reason = "normal_temporal"

        return AnalysisVote(
            agent_id=self.agent_id,
            packet_id=packet.packet_id,
            is_anomaly=is_anomaly,
            confidence=confidence,
            attack_type=attack_type,
            evidence={
                "method":      "CUSUM+FFT temporal analysis",
                "burst_score": f"{burst_score:.2f}",
                "reason":      reason,
                "window_secs": str(WINDOW_SECS),
            },
            processing_time_ms=0.0,
        )

    def _tick(self, now: int) -> None:
        if now > self._current_bin_time:
            # Fill gaps with zero bins
            for t in range(self._current_bin_time, now):
                self._bins.append([t, self._current_bin_count if t == self._current_bin_time else 0])
            self._current_bin_time = now
            self._current_bin_count = 1
        else:
            self._current_bin_count += 1

    def _detect_burst(self, counts: List[int]):
        if not counts:
            return 0.0, False
        max_1s = max(counts[-10:]) if len(counts) >= 10 else max(counts)
        mean_10s = sum(counts[-10:]) / min(10, len(counts))
        ratio = max_1s / max(mean_10s, 0.01)

        # CUSUM
        mean_all = sum(counts) / len(counts) if counts else 1.0
        for c in counts[-10:]:
            self._cusum = max(0, self._cusum + c - mean_all - 0.5)

        burst_score = max(ratio, self._cusum / max(mean_all, 1.0))
        return burst_score, ratio > BURST_RATIO_THRESH or self._cusum > CUSUM_THRESH

    def _detect_beacon(self, counts: List[int]) -> bool:
        if len(counts) < WINDOW_SECS:
            return False
        # Simple FFT-based period detection
        try:
            n = len(counts)
            fft = [0.0] * n
            for k in range(1, n // 2):
                re = sum(counts[t] * math.cos(2 * math.pi * k * t / n) for t in range(n))
                im = sum(counts[t] * math.sin(2 * math.pi * k * t / n) for t in range(n))
                fft[k] = math.sqrt(re * re + im * im)
            dominant_k = max(range(1, n // 2), key=lambda k: fft[k])
            dominant_period = n / dominant_k if dominant_k else 0
            return int(dominant_period) in BEACON_PERIODS
        except Exception:
            return False
