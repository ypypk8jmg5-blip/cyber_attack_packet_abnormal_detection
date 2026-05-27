"""
Agent-04: Enricher
Role: Attach contextual metadata — service name, time-of-day, IP class,
      suspicious-port flag.  Fan-out starting point for Layer 2.
Stateless, static lookup tables, < 1ms per packet.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from agents.base_agent import (
    BaseAgent, EnrichedPacket, FeatureEnvelope,
    PORT_SERVICE_MAP, SUSPICIOUS_PORTS,
)

# Private CIDR prefix sets for internal IP detection
_INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                      "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                      "172.30.", "172.31.", "192.168.", "127.")


def _ip_class(ip: str) -> str:
    if not ip:
        return "unknown"
    for prefix in _INTERNAL_PREFIXES:
        if ip.startswith(prefix):
            return "internal"
    return "external"


def _time_of_day() -> str:
    h = datetime.now().hour
    weekday = datetime.now().weekday()
    if weekday >= 5:
        return "weekend"
    if 9 <= h < 18:
        return "business_hours"
    return "off_hours"


class Enricher(BaseAgent):
    agent_id = "agent-04-enricher"

    def process(self, envelopes: List[FeatureEnvelope]) -> List[EnrichedPacket]:
        tod = _time_of_day()
        return [self._enrich(env, tod) for env in envelopes]

    def _enrich(self, env: FeatureEnvelope, tod: str) -> EnrichedPacket:
        dst_port = env.metadata.get("dst_port", 0)
        src_ip = env.metadata.get("src_ip", "")

        service = PORT_SERVICE_MAP.get(dst_port, "UNKNOWN")
        is_well_known = dst_port in PORT_SERVICE_MAP
        is_suspicious = dst_port in SUSPICIOUS_PORTS

        context: Dict[str, Any] = {
            "service_name":       service,
            "is_well_known_port": is_well_known,
            "is_suspicious_port": is_suspicious,
            "time_of_day":        tod,
            "src_ip_class":       _ip_class(src_ip),
        }

        return EnrichedPacket(
            packet_id=env.packet_id,
            feature_vector=env.feature_vector,
            feature_names=env.feature_names,
            derived_features=env.derived_features,
            metadata=env.metadata,
            context=context,
        )
