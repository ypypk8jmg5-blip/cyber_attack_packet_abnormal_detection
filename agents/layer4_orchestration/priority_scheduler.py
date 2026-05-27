"""
Agent-20: PriorityScheduler
Role: Score enriched packets by risk context; expose a priority queue for
      the AnalysisSubOrchestrator to pull from in risk order.
Stateless scoring, heapq-based queue, < 0.5ms per packet.
"""
from __future__ import annotations

import heapq
import threading
from dataclasses import dataclass, field
from typing import List, Optional

from agents.base_agent import EnrichedPacket

# Priority bonus values (higher = processed sooner)
_PRIORITY_SUSPICIOUS_PORT = 10
_PRIORITY_UNKNOWN_SERVICE = 8
_PRIORITY_EXTERNAL_IP = 5
_PRIORITY_ICMP = 3


def _score(packet: EnrichedPacket) -> int:
    ctx = packet.context
    score = 0
    if ctx.get("is_suspicious_port"):
        score += _PRIORITY_SUSPICIOUS_PORT
    if ctx.get("service_name") == "UNKNOWN":
        score += _PRIORITY_UNKNOWN_SERVICE
    if ctx.get("src_ip_class") == "external":
        score += _PRIORITY_EXTERNAL_IP
    proto = packet.metadata.get("protocol_name", "")
    if proto == "ICMP":
        score += _PRIORITY_ICMP
    return score


@dataclass(order=True)
class _PriorityEntry:
    priority: int            # negative score for max-heap via heapq (min-heap)
    seq: int                 # tie-breaker: insertion order
    packet: EnrichedPacket = field(compare=False)


class PriorityScheduler:
    agent_id = "agent-20-priority-scheduler"

    def __init__(self):
        self._heap: List[_PriorityEntry] = []
        self._lock = threading.Lock()
        self._seq = 0

    def push(self, packet: EnrichedPacket) -> int:
        """Add packet to priority queue. Returns computed priority score."""
        priority = _score(packet)
        with self._lock:
            entry = _PriorityEntry(priority=-priority, seq=self._seq, packet=packet)
            heapq.heappush(self._heap, entry)
            self._seq += 1
        return priority

    def push_batch(self, packets: List[EnrichedPacket]) -> None:
        for p in packets:
            self.push(p)

    def pop(self) -> Optional[EnrichedPacket]:
        with self._lock:
            if self._heap:
                return heapq.heappop(self._heap).packet
        return None

    def pop_batch(self, n: int) -> List[EnrichedPacket]:
        results = []
        for _ in range(n):
            p = self.pop()
            if p is None:
                break
            results.append(p)
        return results

    def size(self) -> int:
        with self._lock:
            return len(self._heap)
