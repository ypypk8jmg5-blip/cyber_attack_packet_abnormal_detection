"""
Agent-01: PacketReceiver
Role: Watch data/stream/ for new incoming_*.csv files and hand batches to the pipeline.
Stateless — processed_files set prevents double-processing.
"""
from __future__ import annotations

import glob
import os
import time
from datetime import datetime
from typing import Any, List, Optional, Set

import pandas as pd

from agents.base_agent import BaseAgent, RawBatch


class PacketReceiver(BaseAgent):
    agent_id = "agent-01-packet-receiver"

    def __init__(
        self,
        stream_dir: str = "data/stream",
        poll_interval: float = 1.0,
        process_existing: bool = False,
    ):
        super().__init__()
        self.stream_dir = stream_dir
        self.poll_interval = poll_interval
        self._processed: Set[str] = set()
        if not process_existing:
            pattern = os.path.join(self.stream_dir, "incoming_*.csv")
            self._processed.update(glob.glob(pattern))

    def process(self, input_data: Any = None) -> Optional[RawBatch]:
        """Scan for the oldest unprocessed incoming_*.csv and return a RawBatch.
        Returns None if no new file is available.
        """
        pattern = os.path.join(self.stream_dir, "incoming_*.csv")
        candidates = sorted(glob.glob(pattern))
        for path in candidates:
            if path not in self._processed:
                batch = self._load(path)
                if batch is not None:
                    self._processed.add(path)
                    return batch
        return None

    def _load(self, path: str) -> Optional[RawBatch]:
        try:
            df = pd.read_csv(path)
            ts = datetime.utcnow().isoformat()
            basename = os.path.basename(path)
            # batch_id derived from filename timestamp portion
            batch_id = "BATCH-" + basename.replace("incoming_", "").replace(".csv", "")
            return RawBatch(
                batch_id=batch_id,
                raw_packets=df.to_dict(orient="records"),
                source_file=path,
                packet_count=len(df),
                receive_timestamp=ts,
            )
        except Exception:
            return None

    def poll(self, max_batches: int = 0) -> List[RawBatch]:
        """Blocking poll loop.  max_batches=0 means infinite."""
        batches: List[RawBatch] = []
        seen = 0
        while True:
            batch = self.process()
            if batch:
                batches.append(batch)
                seen += 1
                if max_batches and seen >= max_batches:
                    break
            else:
                if max_batches and seen >= max_batches:
                    break
                time.sleep(self.poll_interval)
        return batches
