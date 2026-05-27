"""
Agent-08: RuleSignatureAgent  (weight=0.25)
Role: Hard-coded deterministic signature rules for all 11 known attack types.
Stateless, < 1ms.  Matched confidence = 0.95; no match = 0.05.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from agents.base_agent import (
    AnalysisAgent, AnalysisVote, EnrichedPacket, FEATURE_NAMES,
)

# Each rule: (attack_type, callable(feature_dict) -> bool, indicator_description)
_RULES: List[Tuple[str, Any, str]] = [
    (
        "synflood",
        lambda f: f["syn_flag_ratio"] > 0.85 and f["packets_per_sec"] > 1000,
        "syn_flag_ratio>0.85 AND packets_per_sec>1000",
    ),
    (
        "ddos",
        lambda f: f["packets_per_sec"] > 500 and f["connection_count"] > 300,
        "packets_per_sec>500 AND connection_count>300",
    ),
    (
        "http_flood",
        lambda f: int(f["dst_port"]) in {80, 443, 8080, 8443} and f["packets_per_sec"] > 200,
        "dst_port in HTTP ports AND packets_per_sec>200",
    ),
    (
        "ransomware",
        lambda f: int(f["dst_port"]) in {445, 139, 3389} and f["unique_dst_ports"] > 50,
        "dst_port in SMB/RDP ports AND unique_dst_ports>50",
    ),
    (
        "portscan",
        lambda f: f["unique_dst_ports"] > 100 and f["duration"] < 0.1,
        "unique_dst_ports>100 AND duration<0.1s",
    ),
    (
        "arp_spoofing",
        lambda f: int(f["protocol"]) == 2 and f["packets_per_sec"] > 100 and f["duration"] < 0.05,
        "protocol=ICMP AND packets_per_sec>100 AND duration<0.05",
    ),
    (
        "dns_tunneling",
        lambda f: int(f["dst_port"]) == 53 and f["packet_size"] > 400,
        "dst_port=53(DNS) AND packet_size>400",
    ),
    (
        "bruteforce",
        lambda f: f["failed_attempts"] > 50 and f["unique_dst_ports"] <= 3 and f["duration"] < 1.0,
        "failed_attempts>50 AND unique_dst_ports<=3 AND duration<1s",
    ),
    (
        "exfiltration",
        lambda f: f["outbound_ratio"] > 0.85 and f["bytes_per_sec"] > 5_000_000,
        "outbound_ratio>0.85 AND bytes_per_sec>5MB",
    ),
    (
        "botnet_c2",
        lambda f: int(f["dst_port"]) in {4444, 6667, 1080, 8443, 9001},
        "dst_port in known C2 ports [4444,6667,1080,8443,9001]",
    ),
    (
        "slowloris",
        lambda f: f["duration"] > 60 and f["packets_per_sec"] < 0.5 and f["connection_count"] > 200,
        "duration>60s AND packets_per_sec<0.5 AND connection_count>200",
    ),
]


class RuleSignatureAgent(AnalysisAgent):
    agent_id = "agent-08-rule-signature"

    def _analyze(self, packet: EnrichedPacket) -> AnalysisVote:
        fmap = dict(zip(packet.feature_names, packet.feature_vector))
        matched_attack: Optional[str] = None
        matched_indicator: str = ""

        for attack_type, rule_fn, indicator in _RULES:
            try:
                if rule_fn(fmap):
                    matched_attack = attack_type
                    matched_indicator = indicator
                    break   # first matching rule wins
            except Exception:
                continue

        is_anomaly = matched_attack is not None
        confidence = 0.95 if is_anomaly else 0.05

        return AnalysisVote(
            agent_id=self.agent_id,
            packet_id=packet.packet_id,
            is_anomaly=is_anomaly,
            confidence=confidence,
            attack_type=matched_attack,
            evidence={
                "method":    "signature_rule",
                "rule":      matched_attack or "no_match",
                "indicator": matched_indicator,
            },
            processing_time_ms=0.0,
        )
