"""
Agent-28: PerformanceMonitor
Role: Track throughput, E2E latency (P50/P95/P99), per-agent latency,
      alert rate, and FPR in a rolling window.  Extends logs/dashboard.json.
Stateful: rolling deque of timing samples.  Low-overhead daemon thread.
"""
from __future__ import annotations

import collections
import json
import os
import statistics
import threading
import time
from agents._timeutil import utcnow
from typing import Any, Deque, Dict, List, Optional

DASHBOARD_PATH = "logs/dashboard.json"
PERF_ALERT_LOG = "logs/performance_alerts.log"
ROLLING_WINDOW = 1000     # samples kept per metric
SLA_LATENCY_P95_MS = 100  # alert if P95 > this


class PerformanceMonitor:
    agent_id = "agent-28-performance-monitor"

    def __init__(self):
        self._lock = threading.Lock()
        self._e2e_latencies: Deque[float] = collections.deque(maxlen=ROLLING_WINDOW)
        self._agent_latencies: Dict[str, Deque[float]] = collections.defaultdict(
            lambda: collections.deque(maxlen=ROLLING_WINDOW)
        )
        self._alert_count = 0
        self._fp_count = 0
        self._tp_count = 0
        self._packet_count = 0
        self._start_time = time.time()
        self._last_flush = time.time()

    def record_e2e(self, latency_ms: float) -> None:
        with self._lock:
            self._e2e_latencies.append(latency_ms)
            self._packet_count += 1

    def record_agent(self, agent_id: str, latency_ms: float) -> None:
        with self._lock:
            self._agent_latencies[agent_id].append(latency_ms)

    def record_alert(self) -> None:
        with self._lock:
            self._alert_count += 1

    def record_feedback(self, feedback_type: str) -> None:
        with self._lock:
            if feedback_type == "true_positive":
                self._tp_count += 1
            elif feedback_type == "false_positive":
                self._fp_count += 1

    def flush(self) -> None:
        """Write current metrics to dashboard.json."""
        with self._lock:
            stats = self._compute()
        self._write_dashboard(stats)
        self._check_sla(stats)
        self._last_flush = time.time()

    def _compute(self) -> Dict[str, Any]:
        elapsed = time.time() - self._start_time
        throughput = self._packet_count / max(elapsed, 1.0)

        lats = list(self._e2e_latencies)
        p50 = p95 = p99 = 0.0
        if lats:
            lats_sorted = sorted(lats)
            p50 = lats_sorted[int(0.50 * len(lats_sorted))]
            p95 = lats_sorted[int(0.95 * len(lats_sorted))]
            p99 = lats_sorted[min(int(0.99 * len(lats_sorted)), len(lats_sorted)-1)]

        total_fb = self._tp_count + self._fp_count
        fpr = self._fp_count / max(total_fb, 1)

        agent_health = {}
        for aid, lats in self._agent_latencies.items():
            lats_list = list(lats)
            if lats_list:
                agent_health[aid] = {
                    "status": "healthy",
                    "avg_latency_ms": round(statistics.mean(lats_list), 2),
                }

        return {
            "generated_at":            utcnow().isoformat(),
            "throughput_pps":          round(throughput, 2),
            "packets_processed":       self._packet_count,
            "e2e_latency_p50_ms":     round(p50, 2),
            "e2e_latency_p95_ms":     round(p95, 2),
            "e2e_latency_p99_ms":     round(p99, 2),
            "alert_count":             self._alert_count,
            "false_positive_rate":     round(fpr, 4),
            "agent_health":            agent_health,
        }

    def _write_dashboard(self, stats: Dict[str, Any]) -> None:
        try:
            os.makedirs(os.path.dirname(DASHBOARD_PATH), exist_ok=True)
            data = {}
            if os.path.exists(DASHBOARD_PATH):
                with open(DASHBOARD_PATH) as f:
                    data = json.load(f)
            data["performance"] = stats
            with open(DASHBOARD_PATH, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def _check_sla(self, stats: Dict[str, Any]) -> None:
        p95 = stats.get("e2e_latency_p95_ms", 0.0)
        if p95 > SLA_LATENCY_P95_MS:
            msg = f"[PERF ALERT] P95 latency={p95:.1f}ms exceeds SLA={SLA_LATENCY_P95_MS}ms"
            try:
                with open(PERF_ALERT_LOG, "a") as f:
                    f.write(f"{utcnow().isoformat()} {msg}\n")
            except Exception:
                pass
