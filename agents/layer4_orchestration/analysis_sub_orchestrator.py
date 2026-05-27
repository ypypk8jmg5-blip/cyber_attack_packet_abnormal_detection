"""
Agent-18: AnalysisSubOrchestrator
Role: Fan-out one EnrichedPacket to all 8 analysis agents concurrently,
      collect AnalysisVotes within a 100ms budget, substitute neutral votes for timeouts.
Uses concurrent.futures.ThreadPoolExecutor (analysis agents are mostly CPU-bound
but light enough for threads at single-packet scale; ProcessPool is managed by
Agent-19 LoadBalancer for batch workloads).
"""
from __future__ import annotations

import concurrent.futures
from typing import List

from agents.base_agent import AnalysisVote, EnrichedPacket
from agents.layer2_analysis.statistical_analyzer import StatisticalAnalyzer
from agents.layer2_analysis.ml_classifier import MLClassifierAgent
from agents.layer2_analysis.deep_learning_agent import DeepLearningAgent
from agents.layer2_analysis.rule_signature_agent import RuleSignatureAgent
from agents.layer2_analysis.behavioral_profile_agent import BehavioralProfileAgent
from agents.layer2_analysis.temporal_pattern_agent import TemporalPatternAgent
from agents.layer2_analysis.protocol_specific_agent import ProtocolSpecificAgent
from agents.layer2_analysis.flow_correlation_agent import FlowCorrelationAgent

TIMEOUT_MS = 100.0


class AnalysisSubOrchestrator:
    agent_id = "agent-18-analysis-sub-orchestrator"

    def __init__(self):
        self._agents = [
            StatisticalAnalyzer(),
            MLClassifierAgent(),
            DeepLearningAgent(),
            RuleSignatureAgent(),
            BehavioralProfileAgent(),
            TemporalPatternAgent(),
            ProtocolSpecificAgent(),
            FlowCorrelationAgent(),
        ]
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=len(self._agents),
            thread_name_prefix="analysis",
        )

    def analyze(self, packet: EnrichedPacket) -> List[AnalysisVote]:
        """Fan-out to all 8 agents, return votes within TIMEOUT_MS."""
        futures = {
            self._executor.submit(agent.analyze, packet): agent.agent_id
            for agent in self._agents
        }
        votes: List[AnalysisVote] = []
        timeout_sec = TIMEOUT_MS / 1000.0

        done, not_done = concurrent.futures.wait(
            futures, timeout=timeout_sec,
            return_when=concurrent.futures.ALL_COMPLETED,
        )

        for future in done:
            agent_id = futures[future]
            try:
                votes.append(future.result())
            except Exception:
                votes.append(AnalysisVote.neutral(agent_id, packet.packet_id))

        for future in not_done:
            agent_id = futures[future]
            future.cancel()
            votes.append(AnalysisVote.neutral(agent_id, packet.packet_id))

        return votes

    def analyze_batch(self, packets: List[EnrichedPacket]) -> List[List[AnalysisVote]]:
        return [self.analyze(p) for p in packets]

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False)
