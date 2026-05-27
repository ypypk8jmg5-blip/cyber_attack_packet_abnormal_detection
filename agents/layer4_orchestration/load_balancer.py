"""
Agent-19: LoadBalancer
Role: Distribute incoming packet batches across multiple AnalysisSubOrchestrator workers.
Tracks per-worker queue depth; emits backpressure signal when overloaded.
Uses ThreadPoolExecutor (one thread per worker slot).
"""
from __future__ import annotations

import os
import queue
import threading
from typing import Callable, List, Optional

from agents.base_agent import EnrichedPacket

MAX_QUEUE_DEPTH = 1000
DEFAULT_WORKERS = max(1, (os.cpu_count() or 2) - 1)


class LoadBalancer:
    agent_id = "agent-19-load-balancer"

    def __init__(self, n_workers: int = DEFAULT_WORKERS):
        self._n_workers = n_workers
        self._queues: List[queue.Queue] = [queue.Queue() for _ in range(n_workers)]
        self._depths = [0] * n_workers
        self._lock = threading.Lock()
        self._backpressure = threading.Event()
        self._result_cb: Optional[Callable] = None

    @property
    def backpressure_active(self) -> bool:
        return self._backpressure.is_set()

    def total_queue_depth(self) -> int:
        return sum(q.qsize() for q in self._queues)

    def submit(self, packet: EnrichedPacket) -> int:
        """Route packet to the least-loaded worker. Returns worker index."""
        with self._lock:
            # Least-loaded worker selection
            worker_idx = min(range(self._n_workers), key=lambda i: self._queues[i].qsize())
            self._queues[worker_idx].put(packet)

            depth = self.total_queue_depth()
            if depth > MAX_QUEUE_DEPTH:
                self._backpressure.set()
            else:
                self._backpressure.clear()

        return worker_idx

    def submit_batch(self, packets: List[EnrichedPacket]) -> None:
        for p in packets:
            self.submit(p)

    def get_worker_queue(self, worker_idx: int) -> queue.Queue:
        return self._queues[worker_idx]

    def get_stats(self) -> dict:
        return {
            "n_workers":        self._n_workers,
            "queue_depths":     [q.qsize() for q in self._queues],
            "total_depth":      self.total_queue_depth(),
            "backpressure":     self._backpressure.is_set(),
        }
