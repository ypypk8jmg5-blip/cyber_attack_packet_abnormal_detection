"""
Agent-13: EvidenceAggregator
Role: Weighted ensemble of 8 AnalysisVotes → single AggregatedDecision.
Handles partial results (timeouts).  Rule veto: Agent-08 confidence>0.92 → floor=0.75.
"""
from __future__ import annotations

from collections import Counter
from typing import Dict, List, Optional

from agents.base_agent import (
    AggregatedDecision, AnalysisVote, BaseAgent,
)

# Weights per agent_id — must sum to 1.0 for the active agents
AGENT_WEIGHTS: Dict[str, float] = {
    "agent-06-ml-classifier":       0.35,
    "agent-08-rule-signature":       0.25,
    "agent-07-deep-learning":        0.20,
    "agent-09-behavioral-profile":   0.15,
    "agent-05-statistical":          0.10,
    "agent-10-temporal-pattern":     0.05,
    "agent-11-protocol-specific":    0.00,
    "agent-12-flow-correlation":     0.00,
}

RULE_VETO_AGENT = "agent-08-rule-signature"
RULE_VETO_CONF = 0.92
RULE_VETO_FLOOR = 0.75


class EvidenceAggregator(BaseAgent):
    agent_id = "agent-13-evidence-aggregator"

    def process(self, votes: List[AnalysisVote]) -> AggregatedDecision:
        if not votes:
            raise ValueError("EvidenceAggregator received empty vote list")

        packet_id = votes[0].packet_id
        vote_summary: Dict[str, dict] = {}
        weighted_sum = 0.0
        weight_total = 0.0
        attack_votes: Counter = Counter()
        timeout_agents: List[str] = []

        for vote in votes:
            aid = vote.agent_id
            w = AGENT_WEIGHTS.get(aid, 0.0)
            vote_summary[aid] = {
                "is_anomaly": vote.is_anomaly,
                "confidence": vote.confidence,
                "weight":     w,
                "attack_type": vote.attack_type,
            }

            if w > 0:
                # Treat confidence as anomaly evidence only when the agent votes
                # anomaly. A normal vote should suppress evidence, not invert a
                # low anomaly probability into a high anomaly score.
                if vote.evidence.get("method") == "neutral_fallback":
                    continue
                direction = vote.confidence if vote.is_anomaly else 0.0
                weighted_sum += w * direction
                weight_total += w

            if vote.is_anomaly and vote.attack_type:
                attack_votes[vote.attack_type] += 1

        # Normalise
        aggregate_score = (weighted_sum / weight_total) if weight_total > 0 else 0.5

        # Rule veto: if rule agent fires with high confidence → floor
        rule_vote = next((v for v in votes if v.agent_id == RULE_VETO_AGENT), None)
        if rule_vote and rule_vote.is_anomaly and rule_vote.confidence >= RULE_VETO_CONF:
            aggregate_score = max(aggregate_score, RULE_VETO_FLOOR)

        vote_count_anomaly = sum(1 for v in votes if v.is_anomaly)
        vote_count_normal = len(votes) - vote_count_anomaly
        plurality_attack = attack_votes.most_common(1)[0][0] if attack_votes else None

        return AggregatedDecision(
            packet_id=packet_id,
            aggregate_score=aggregate_score,
            vote_summary=vote_summary,
            vote_count_anomaly=vote_count_anomaly,
            vote_count_normal=vote_count_normal,
            plurality_attack_type=plurality_attack,
            attack_type_votes=dict(attack_votes),
            timeout_agents=timeout_agents,
        )
