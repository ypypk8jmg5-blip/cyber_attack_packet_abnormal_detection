"""
Agent-11: ProtocolSpecificAgent  (weight=0.00, corrects attack_type)
Role: Protocol-aware anomaly rules for TCP/UDP/ICMP.
Stateless, < 1ms.  Provides attack_type refinement rather than a primary vote.
"""
from __future__ import annotations

from typing import Optional, Tuple

from agents.base_agent import (
    AnalysisAgent, AnalysisVote, EnrichedPacket, SUSPICIOUS_PORTS,
)


def _classify(fmap: dict) -> Tuple[bool, Optional[str], str]:
    proto = int(fmap.get("protocol", -1))
    dst = int(fmap.get("dst_port", 0))
    syn = fmap.get("syn_flag_ratio", 0.0)
    failed = fmap.get("failed_attempts", 0)
    pps = fmap.get("packets_per_sec", 0.0)
    duration = fmap.get("duration", 0.0)
    size = fmap.get("packet_size", 0.0)
    outbound = fmap.get("outbound_ratio", 0.0)

    # TCP (protocol=0)
    if proto == 0:
        if syn > 0.85:
            return True, "synflood", "TCP SYN ratio > 0.85"
        if dst in {22, 3389, 21} and failed > 30:
            return True, "bruteforce", f"TCP dst_port={dst} failed_attempts={int(failed)}"
        if dst in {445, 139} and pps > 50:
            return True, "ransomware", "TCP SMB port high traffic"
        if dst in SUSPICIOUS_PORTS:
            return True, "botnet_c2", f"TCP suspicious port {dst}"

    # UDP (protocol=1)
    elif proto == 1:
        if dst == 53 and size > 400:
            return True, "dns_tunneling", "UDP DNS large packet"
        if pps > 5000 and size < 100:
            return True, "ddos", "UDP flood small packets high pps"

    # ICMP (protocol=2)
    elif proto == 2:
        if pps > 100 and duration < 0.05:
            return True, "arp_spoofing", "ICMP high pps short duration"

    # Cross-protocol
    if dst in SUSPICIOUS_PORTS:
        return True, "botnet_c2", f"Suspicious port {dst}"
    if outbound > 0.85 and fmap.get("bytes_per_sec", 0) > 5_000_000:
        return True, "exfiltration", "High outbound ratio + bytes_per_sec"

    return False, None, "no_protocol_violation"


class ProtocolSpecificAgent(AnalysisAgent):
    agent_id = "agent-11-protocol-specific"

    def _analyze(self, packet: EnrichedPacket) -> AnalysisVote:
        fmap = dict(zip(packet.feature_names, packet.feature_vector))
        is_anomaly, attack_type, indicator = _classify(fmap)
        confidence = 0.88 if is_anomaly else 0.05

        return AnalysisVote(
            agent_id=self.agent_id,
            packet_id=packet.packet_id,
            is_anomaly=is_anomaly,
            confidence=confidence,
            attack_type=attack_type,
            evidence={
                "method":    "protocol_rules",
                "indicator": indicator,
                "protocol":  str(int(fmap.get("protocol", -1))),
            },
            processing_time_ms=0.0,
        )
