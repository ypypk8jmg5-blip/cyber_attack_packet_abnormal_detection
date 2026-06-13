"""
Agent-14: ConflictResolver
Role: Apply priority-ordered conflict resolution rules to the aggregated evidence.
Stateless, < 1ms.
"""
from __future__ import annotations

import json
import os
from agents._timeutil import utcnow
from typing import Optional

from agents.base_agent import AggregatedDecision, BaseAgent

CONFLICT_LOG_PATH = "data/stream/conflict_log.json"

ML_AGENT = "agent-06-ml-classifier"
RULE_AGENT = "agent-08-rule-signature"
BEHAV_AGENT = "agent-09-behavioral-profile"
DL_AGENT = "agent-07-deep-learning"

RULE_OVERRIDE_CONF = 0.90
ML_LOW_CONF = 0.60
CONSENSUS_BOOST = 0.05
STAT_ONLY_CAP = 0.35
DL_STRONG_NORMAL = 0.20


class ConflictResolver(BaseAgent):
    agent_id = "agent-14-conflict-resolver"

    def __init__(self, conflict_log: str = CONFLICT_LOG_PATH):
        super().__init__()
        self._conflict_log = conflict_log

    def process(self, decision: AggregatedDecision) -> AggregatedDecision:
        summary = decision.vote_summary
        score = decision.aggregate_score

        rule = summary.get(RULE_AGENT, {})
        ml = summary.get(ML_AGENT, {})
        behav = summary.get(BEHAV_AGENT, {})
        dl = summary.get(DL_AGENT, {})

        rule_fires = rule.get("is_anomaly", False) and rule.get("confidence", 0) >= RULE_OVERRIDE_CONF
        ml_fires = ml.get("is_anomaly", False) and ml.get("confidence", 0) >= 0.70
        behav_fires = behav.get("is_anomaly", False) and behav.get("confidence", 0) >= 0.70
        dl_strong_normal = (not dl.get("is_anomaly", False)) and dl.get("confidence", 1.0) <= DL_STRONG_NORMAL

        # Rule 1: signature veto overrides ML disagreement
        if rule_fires and ml.get("confidence", 0) < ML_LOW_CONF:
            score = max(score, 0.70)

        # Rule 2: RF + Behavioral consensus → boost
        if ml_fires and behav_fires:
            score = min(1.0, score + CONSENSUS_BOOST)

        # Rule 3: statistical-only flag → cap confidence
        stat_only = (
            summary.get("agent-05-statistical", {}).get("is_anomaly", False)
            and not any(
                summary.get(a, {}).get("is_anomaly", False)
                for a in [RULE_AGENT, ML_AGENT, BEHAV_AGENT, DL_AGENT,
                          "agent-10-temporal-pattern", "agent-11-protocol-specific",
                          "agent-12-flow-correlation"]
            )
        )
        if stat_only:
            score = min(score, STAT_ONLY_CAP)

        # Rule 4: DL strong normal vs rule-based anomaly → log conflict
        if dl_strong_normal and rule_fires:
            self._log_conflict(decision, "DL_vs_rule")

        decision.aggregate_score = score
        return decision

    def _log_conflict(self, decision: AggregatedDecision, conflict_type: str) -> None:
        try:
            os.makedirs(os.path.dirname(self._conflict_log), exist_ok=True)
            entry = {
                "timestamp": utcnow().isoformat(),
                "packet_id": decision.packet_id,
                "conflict_type": conflict_type,
                "score": decision.aggregate_score,
            }
            logs = []
            if os.path.exists(self._conflict_log):
                with open(self._conflict_log) as f:
                    logs = json.load(f)
            logs.append(entry)
            with open(self._conflict_log, "w") as f:
                json.dump(logs[-1000:], f)  # keep last 1000 conflicts
        except Exception:
            pass
