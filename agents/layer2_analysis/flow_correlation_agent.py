"""
Agent-12: FlowCorrelationAgent  (weight=0.00, issues flow-level votes)
Role: Aggregate per-(src_ip, dst_port_group) flow stats; detect attacks
      only visible at the flow level (port scan, aggregate DDoS, beaconing).
Stateful: flow table with 5-min expiry.
"""
from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional, Set, Tuple

from agents.base_agent import (
    AnalysisAgent, AnalysisVote, EnrichedPacket,
)

FLOW_EXPIRY_SECS = 300   # 5 min
SCAN_PORT_THRESH = 30    # unique dst_ports within a flow → port scan
BEACON_VARIANCE_THRESH = 2.0  # low inter-arrival variance → beaconing
AGGREGATE_PPS_THRESH = 2000   # aggregate pps across a dst_ip → DDoS


class _FlowRecord:
    __slots__ = ("total_packets", "unique_dst_ports", "arrivals", "last_seen",
                 "total_bytes", "failed_sum")

    def __init__(self):
        self.total_packets = 0
        self.unique_dst_ports: Set[int] = set()
        self.arrivals: List[float] = []
        self.last_seen = time.time()
        self.total_bytes = 0.0
        self.failed_sum = 0.0


class FlowCorrelationAgent(AnalysisAgent):
    agent_id = "agent-12-flow-correlation"

    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()
        self._flows: Dict[Tuple, _FlowRecord] = {}
        self._last_expire = time.time()

    def _analyze(self, packet: EnrichedPacket) -> AnalysisVote:
        src_ip = packet.metadata.get("src_ip", "unknown")
        fmap = dict(zip(packet.feature_names, packet.feature_vector))
        dst_port = int(fmap.get("dst_port", 0))
        key = (src_ip, dst_port // 100)  # port group (bucket of 100)

        with self._lock:
            if time.time() - self._last_expire > 60:
                self._expire()
                self._last_expire = time.time()

            if key not in self._flows:
                self._flows[key] = _FlowRecord()
            rec = self._flows[key]
            now = time.time()
            rec.total_packets += 1
            rec.unique_dst_ports.add(dst_port)
            rec.arrivals.append(now)
            if len(rec.arrivals) > 200:
                rec.arrivals = rec.arrivals[-200:]
            rec.last_seen = now
            rec.total_bytes += fmap.get("bytes_per_sec", 0)
            rec.failed_sum += fmap.get("failed_attempts", 0)

            # Evaluate flow
            attack, indicator = self._evaluate(rec, fmap)

        is_anomaly = attack is not None
        confidence = 0.80 if is_anomaly else 0.10

        return AnalysisVote(
            agent_id=self.agent_id,
            packet_id=packet.packet_id,
            is_anomaly=is_anomaly,
            confidence=confidence,
            attack_type=attack,
            evidence={
                "method":     "flow_correlation",
                "indicator":  indicator or "no_flow_anomaly",
                "flow_key":   f"{src_ip}:{dst_port//100}xx",
                "flow_pkts":  str(rec.total_packets),
            },
            processing_time_ms=0.0,
        )

    def _evaluate(self, rec: _FlowRecord, fmap: dict) -> Tuple[Optional[str], Optional[str]]:
        # Port scan: single source hits many ports quickly
        if len(rec.unique_dst_ports) > SCAN_PORT_THRESH:
            return "portscan", f"unique_dst_ports={len(rec.unique_dst_ports)}"

        # Beaconing: regular inter-arrival time (low variance)
        if len(rec.arrivals) >= 20:
            iats = [rec.arrivals[i+1] - rec.arrivals[i] for i in range(len(rec.arrivals)-1)]
            mean_iat = sum(iats) / len(iats)
            if mean_iat > 0:
                variance = sum((x - mean_iat)**2 for x in iats) / len(iats)
                cv = variance**0.5 / mean_iat
                if cv < 0.2 and mean_iat < 60:
                    return "botnet_c2", f"beacon_cv={cv:.3f} period={mean_iat:.1f}s"

        # Aggregate DDoS: massive pps on this flow
        if fmap.get("packets_per_sec", 0) > AGGREGATE_PPS_THRESH:
            return "ddos", f"agg_pps={fmap['packets_per_sec']:.0f}"

        return None, None

    def _expire(self) -> None:
        now = time.time()
        expired = [k for k, r in self._flows.items() if now - r.last_seen > FLOW_EXPIRY_SECS]
        for k in expired:
            del self._flows[k]
