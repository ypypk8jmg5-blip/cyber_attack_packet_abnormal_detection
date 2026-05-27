"""
BaseAgent ABC and shared data schemas for all 32 agents.
All analysis agents implement analyze() and return an AnalysisVote.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Shared data schemas (dataclasses used as typed dicts across layers)
# ---------------------------------------------------------------------------

@dataclass
class RawBatch:
    """Output of Agent-01 PacketReceiver."""
    batch_id: str
    raw_packets: List[Dict[str, Any]]
    source_file: str
    packet_count: int
    receive_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class NormalizedPacket:
    """Output of Agent-02 Normalizer."""
    packet_id: str
    features: Dict[str, float]
    normalization_flags: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FeatureEnvelope:
    """Output of Agent-03 FeatureExtractor.
    feature_vector order matches FEATURE_NAMES.
    """
    packet_id: str
    feature_vector: List[float]
    feature_names: List[str]
    derived_features: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EnrichedPacket:
    """Output of Agent-04 Enricher — fan-out source for Layer 2."""
    packet_id: str
    feature_vector: List[float]
    feature_names: List[str]
    derived_features: Dict[str, float]
    metadata: Dict[str, Any]
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisVote:
    """Standard output schema for all 8 Layer-2 analysis agents."""
    agent_id: str
    packet_id: str
    is_anomaly: bool
    confidence: float          # [0.0, 1.0]
    attack_type: Optional[str]
    evidence: Dict[str, str]
    processing_time_ms: float
    analysis_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @classmethod
    def neutral(cls, agent_id: str, packet_id: str) -> "AnalysisVote":
        """Neutral (abstain) vote used as fallback on timeout or error."""
        return cls(
            agent_id=agent_id,
            packet_id=packet_id,
            is_anomaly=False,
            confidence=0.5,
            attack_type=None,
            evidence={"method": "neutral_fallback"},
            processing_time_ms=0.0,
        )


@dataclass
class AggregatedDecision:
    """Output of Agent-13 EvidenceAggregator → input to Decision Layer."""
    packet_id: str
    aggregate_score: float
    vote_summary: Dict[str, Any]
    vote_count_anomaly: int
    vote_count_normal: int
    plurality_attack_type: Optional[str]
    attack_type_votes: Dict[str, int]
    timeout_agents: List[str] = field(default_factory=list)


@dataclass
class FinalDecision:
    """Output of Agent-16 ThresholdManager — triggers Output Layer if is_anomaly_final."""
    packet_id: str
    is_anomaly_final: bool
    calibrated_confidence: float
    attack_type_final: Optional[str]
    aggregate_score: float
    vote_summary: Dict[str, Any]
    confidence_band: str        # low | medium | high
    enriched_packet: Optional[EnrichedPacket] = None


# ---------------------------------------------------------------------------
# Feature constants (shared across all agents)
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    "duration", "protocol", "src_port", "dst_port",
    "packet_size", "packets_per_sec", "bytes_per_sec",
    "unique_dst_ports", "connection_count", "failed_attempts",
    "outbound_ratio", "syn_flag_ratio",
]

FEATURE_BOUNDS = {
    "duration":          (0.0,    3600.0),
    "protocol":          (0,      2),
    "src_port":          (0,      65535),
    "dst_port":          (0,      65535),
    "packet_size":       (0.0,    65535.0),
    "packets_per_sec":   (0.0,    100000.0),
    "bytes_per_sec":     (0.0,    1e9),
    "unique_dst_ports":  (0,      65535),
    "connection_count":  (0,      100000),
    "failed_attempts":   (0,      10000),
    "outbound_ratio":    (0.0,    1.0),
    "syn_flag_ratio":    (0.0,    1.0),
}

SUSPICIOUS_PORTS = {4444, 6667, 1080, 8443, 9001}

PORT_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 993: "IMAPS", 1935: "RTMP",
    3389: "RDP", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
}

ATTACK_TYPES = [
    "ddos", "synflood", "http_flood", "ransomware", "portscan",
    "arp_spoofing", "dns_tunneling", "bruteforce", "exfiltration",
    "botnet_c2", "slowloris",
]


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class BaseAgent(ABC):
    """Abstract base for all agents.

    Concrete agents implement process() with their specific input/output types.
    Analysis agents (Layer 2) additionally implement analyze() which wraps
    process() and returns an AnalysisVote with timing.
    """

    agent_id: str = "base"

    def __init__(self) -> None:
        self._start_time: float = 0.0

    def _start_timer(self) -> None:
        self._start_time = time.perf_counter()

    def _elapsed_ms(self) -> float:
        return (time.perf_counter() - self._start_time) * 1000.0

    @abstractmethod
    def process(self, input_data: Any) -> Any:
        """Main processing logic — each agent defines its own signature."""


class AnalysisAgent(BaseAgent, ABC):
    """Base for all 8 Layer-2 analysis agents.

    Subclasses implement _analyze() and return an AnalysisVote.
    This wrapper handles timing and neutral-vote fallback.
    """

    agent_id: str = "analysis-base"

    def process(self, packet: EnrichedPacket) -> AnalysisVote:
        return self.analyze(packet)

    def analyze(self, packet: EnrichedPacket) -> AnalysisVote:
        self._start_timer()
        try:
            vote = self._analyze(packet)
            vote.processing_time_ms = self._elapsed_ms()
            return vote
        except Exception:
            return AnalysisVote.neutral(self.agent_id, packet.packet_id)

    @abstractmethod
    def _analyze(self, packet: EnrichedPacket) -> AnalysisVote:
        """Implement anomaly analysis logic here."""
