"""
Agent-21: SeverityClassifier
Role: Map (attack_type, confidence) → CRITICAL/HIGH/MEDIUM/LOW severity.
      Demotes by one level when confidence is 0.50–0.60 (low_confidence_detection flag).
Stateless, < 1ms.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from agents.base_agent import BaseAgent, FinalDecision

SEVERITY_MAP = {
    "CRITICAL": {"ddos", "synflood", "ransomware", "http_flood"},
    "HIGH":     {"portscan", "arp_spoofing", "dns_tunneling"},
    "MEDIUM":   {"bruteforce", "exfiltration", "botnet_c2"},
    "LOW":      {"slowloris"},
}

_TYPE_TO_BASE = {attack: sev for sev, attacks in SEVERITY_MAP.items() for attack in attacks}

DEMOTION_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
LOW_CONF_LOWER = 0.50
LOW_CONF_UPPER = 0.60


@dataclass
class SeverityResult:
    packet_id: str
    severity: str
    attack_type: Optional[str]
    confidence: float
    low_confidence_detection: bool
    severity_rationale: str
    final_decision: FinalDecision


class SeverityClassifier(BaseAgent):
    agent_id = "agent-21-severity-classifier"

    def process(self, decision: FinalDecision) -> SeverityResult:
        attack = decision.attack_type_final
        conf = decision.calibrated_confidence

        base_sev = _TYPE_TO_BASE.get(attack or "", "LOW")
        low_conf = LOW_CONF_LOWER <= conf < LOW_CONF_UPPER

        # Confidence-based demotion: low confidence → one tier down
        if low_conf:
            idx = DEMOTION_ORDER.index(base_sev)
            final_sev = DEMOTION_ORDER[min(idx + 1, len(DEMOTION_ORDER) - 1)]
        else:
            final_sev = base_sev

        rationale = f"{attack or 'unknown'} + confidence={conf:.3f}"
        if low_conf:
            rationale += " (demoted: low confidence)"

        return SeverityResult(
            packet_id=decision.packet_id,
            severity=final_sev,
            attack_type=attack,
            confidence=conf,
            low_confidence_detection=low_conf,
            severity_rationale=rationale,
            final_decision=decision,
        )
