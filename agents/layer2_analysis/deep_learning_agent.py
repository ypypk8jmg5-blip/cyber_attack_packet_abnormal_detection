"""
Agent-07: DeepLearningAgent  (weight=0.20)
Role: LSTM Autoencoder reconstruction-error anomaly detection.
Stateful: per-IP sequence buffer (deque of last 20 packets).
Graceful degradation: returns neutral vote if PyTorch not installed.
"""
from __future__ import annotations

import collections
import os
from typing import Any, Deque, Dict, Optional

from agents.base_agent import (
    AnalysisAgent, AnalysisVote, EnrichedPacket, FEATURE_NAMES,
)

SEQ_LEN = 20
MODEL_PATH     = "data/models/lstm_autoencoder.pt"
THRESHOLD_PATH = "data/models/lstm_threshold.json"
WARMUP_MIN = 200   # packets before the model is trusted
DEFAULT_THRESHOLD = 0.05  # 미학습 시 기본 임계값 (사실상 비활성화 수준)


class DeepLearningAgent(AnalysisAgent):
    agent_id = "agent-07-deep-learning"

    def __init__(self, model_path: str = MODEL_PATH):
        super().__init__()
        self._model_path = model_path
        self._model = None
        self._threshold: float = self._load_threshold()
        self._is_trained: bool = False   # 실제 학습된 모델인지 여부
        self._n_seen = 0
        self._ip_buffers: Dict[str, Deque] = {}
        self._pytorch_available = self._load_model()

    def _load_threshold(self) -> float:
        """학습된 임계값 파일이 있으면 로드, 없으면 기본값 사용."""
        if os.path.exists(THRESHOLD_PATH):
            try:
                import json
                with open(THRESHOLD_PATH) as f:
                    data = json.load(f)
                t = float(data.get('threshold', DEFAULT_THRESHOLD))
                print(f"[{self.agent_id}] 임계값 로드: {t:.6f} (P{data.get('percentile',95)} 보정값)")
                return t
            except Exception:
                pass
        return DEFAULT_THRESHOLD

    # ------------------------------------------------------------------
    def _analyze(self, packet: EnrichedPacket) -> AnalysisVote:
        self._n_seen += 1
        src_ip = packet.metadata.get("src_ip", "unknown")

        # Maintain per-IP sequence buffer
        if src_ip not in self._ip_buffers:
            self._ip_buffers[src_ip] = collections.deque(maxlen=SEQ_LEN)
        self._ip_buffers[src_ip].append(packet.feature_vector)

        # Warm-up or model unavailable → neutral
        if not self._is_ready():
            return AnalysisVote.neutral(self.agent_id, packet.packet_id)
        if self._n_seen < WARMUP_MIN:
            return AnalysisVote.neutral(self.agent_id, packet.packet_id)

        buf = self._ip_buffers[src_ip]
        if len(buf) < SEQ_LEN:
            return AnalysisVote.neutral(self.agent_id, packet.packet_id)

        mse = self._reconstruction_error(list(buf))
        is_anomaly = mse > self._threshold
        confidence = min(0.95, mse / (self._threshold * 2)) if is_anomaly else max(0.05, 1.0 - mse / self._threshold)

        return AnalysisVote(
            agent_id=self.agent_id,
            packet_id=packet.packet_id,
            is_anomaly=is_anomaly,
            confidence=confidence,
            attack_type=None,
            evidence={
                "method":     "LSTM Autoencoder reconstruction",
                "mse":        f"{mse:.6f}",
                "threshold":  f"{self._threshold:.6f}",
                "seq_len":    str(SEQ_LEN),
            },
            processing_time_ms=0.0,
        )

    def _reconstruction_error(self, seq: list) -> float:
        try:
            import torch
            import torch.nn.functional as F
            x = torch.tensor(seq, dtype=torch.float32).unsqueeze(0)  # (1, SEQ_LEN, features)
            with torch.no_grad():
                recon = self._model(x)
            mse = float(F.mse_loss(recon, x).item())
            return mse
        except Exception:
            return 0.0

    def _load_model(self) -> bool:
        try:
            import torch
            if not os.path.exists(self._model_path):
                # 학습 파일 없음 → 랜덤 가중치 모델 (WARMUP 후에도 신뢰 불가)
                self._model = _build_default_autoencoder(len(FEATURE_NAMES))
                self._is_trained = False
                print(f"[{self.agent_id}] 경고: 학습된 모델 없음 — neutral vote 반환 (train_lstm.py 실행 필요)")
                return True
            self._model = torch.load(self._model_path, map_location="cpu", weights_only=False)
            self._model.eval()
            self._is_trained = True
            print(f"[{self.agent_id}] 학습된 모델 로드 완료: {self._model_path}")
            return True
        except ImportError:
            return False
        except Exception:
            return False

    def _is_ready(self) -> bool:
        """실제 추론 가능한 상태인지 확인."""
        return self._pytorch_available and self._model is not None and self._is_trained


try:
    import torch
    import torch.nn as nn

    class LSTMAutoencoder(nn.Module):
        """
        LSTM Autoencoder — 비지도 이상탐지 모델.
        모듈 최상위에 정의하여 pickle 직렬화 가능.
        학습: 정상 패킷 시퀀스만으로 복원 학습
        탐지: 재구성 오차(MSE) > threshold → 이상
        """
        def __init__(self, n_features: int = 12, hidden: int = 32):
            super().__init__()
            self.n_features = n_features
            self.hidden = hidden
            self.encoder = nn.LSTM(n_features, hidden, batch_first=True)
            self.decoder = nn.LSTM(hidden, n_features, batch_first=True)

        def forward(self, x):
            _, (h, _) = self.encoder(x)
            h_rep = h.permute(1, 0, 2).expand(-1, x.size(1), -1)
            out, _ = self.decoder(h_rep)
            return out

    _TORCH_AVAILABLE = True
except ImportError:
    _TORCH_AVAILABLE = False
    LSTMAutoencoder = None  # type: ignore


def _build_default_autoencoder(n_features: int, hidden: int = 32):
    """미학습 상태의 기본 모델 생성 (학습 전 placeholder)."""
    if not _TORCH_AVAILABLE:
        return None
    model = LSTMAutoencoder(n_features, hidden)
    model.eval()
    return model
