"""
Agent-00: AdaptivePacketGenerator  (Layer 0 — 신규)

역할: 이전 학습 사이클의 평가 결과(Agent-29/31 출력)를 읽어
      탐지 취약 공격 유형을 더 많이·더 다양하게 생성하는 AI 기반 패킷 생성기.

기존 generate_packets.py와의 차이:
  - 기존: 고정 numpy.random 분포 (매 사이클 동일한 패턴)
  - 신규: 이전 사이클 Recall 피드백 → 취약 유형 비율 동적 조정
           + 경계 샘플(boundary samples) 생성으로 탐지기 강화

3가지 AI 전략:
  1. Adaptive Weighting  — 취약 유형 샘플 비율 자동 상향
  2. Boundary Sampling   — 탐지 경계선 근방 어려운 샘플 생성
  3. Noise Injection     — 정상 트래픽에 미묘한 공격 시그니처 삽입 (FP 강화)
"""
from __future__ import annotations

import glob
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

# ── 기본 공격 유형별 분포 파라미터 (기존 generate_packets.py 기반) ────────────
BASE_ATTACK_PARAMS: Dict[str, Dict] = {
    "synflood":     {"syn_flag_ratio": (0.85, 0.99), "packets_per_sec": (1000, 10000), "connection_count": (500, 5000)},
    "ddos":         {"syn_flag_ratio": (0.50, 0.90), "packets_per_sec": (500,  5000),  "connection_count": (300, 2000)},
    "portscan":     {"unique_dst_ports": (100, 1024), "failed_attempts": (40, 200),    "connection_count": (50, 500)},
    "bruteforce":   {"failed_attempts":  (50, 500),   "packets_per_sec": (2, 20),      "dst_port_choices": [22, 3389, 21, 23]},
    "exfiltration": {"bytes_per_sec":    (5e6, 1e8),  "outbound_ratio":  (0.85, 0.99), "duration": (60, 600)},
    "dns_tunneling":{"packet_size":      (400, 1400), "protocol_fixed":  1,            "dst_port_fixed": 53},
    "http_flood":   {"packets_per_sec":  (200, 2000), "bytes_per_sec":   (5e5, 1e7),   "connection_count": (100, 1000)},
    "slowloris":    {"duration":         (60, 900),   "packets_per_sec": (0.01, 0.5),  "connection_count": (200, 2000)},
    "botnet_c2":    {"duration":         (0.1, 2),    "packets_per_sec": (0.1, 5),     "dst_port_choices": [4444, 6667, 1080, 8443, 9001]},
    "ransomware":   {"bytes_per_sec":    (1e6, 2e7),  "unique_dst_ports": (50, 300),   "failed_attempts": (10, 100)},
    "arp_spoofing": {"protocol_fixed":   2,           "packets_per_sec": (100, 1000),  "duration": (0.001, 0.05)},
}

NORMAL_TYPES = ["normal_web", "normal_dns", "normal_ftp", "normal_stream", "normal_email"]
ATTACK_TYPES = list(BASE_ATTACK_PARAMS.keys())
TARGET_RECALL = 0.90
METRICS_DIR = "data/metrics"


class AdaptivePacketGenerator:
    """
    AI 기반 적응형 패킷 생성기.
    이전 사이클 평가 피드백을 반영하여 샘플 분포를 동적으로 조정.
    """
    agent_id = "agent-00-adaptive-packet-generator"

    def __init__(self):
        self._prev_recall: Dict[str, float] = {}
        self._prev_fp_patterns: List[Dict] = []
        self._attack_weights: Dict[str, float] = {a: 1.0 for a in ATTACK_TYPES}
        self._cycle_history: List[Dict] = []

    # ── 공개 인터페이스 ────────────────────────────────────────────────────────

    def generate(
        self,
        total_size: int = 8000,
        normal_ratio: float = 0.65,
        cycle: int = 1,
        output_dir: str = "data/packets",
        mode: str = "train",
    ) -> str:
        """
        AI 적응형 패킷 생성 후 CSV 저장. 파일 경로 반환.
        """
        # 1. 이전 사이클 평가 결과 로드
        self._load_feedback(cycle)

        # 2. 적응형 가중치 계산
        self._compute_adaptive_weights()

        n_normal = int(total_size * normal_ratio)
        n_attack_total = total_size - n_normal

        # 3. 정상 트래픽 생성
        normal_df = self._generate_normal(n_normal, cycle)

        # 4. 공격 트래픽 생성 (적응형 비율 적용)
        attack_df = self._generate_attacks(n_attack_total, cycle)

        # 5. 경계 샘플 추가 (전체의 5%)
        boundary_df = self._generate_boundary_samples(int(total_size * 0.05), cycle)

        # 6. 병합·셔플
        df = pd.concat([normal_df, attack_df, boundary_df], ignore_index=True)
        df = df.sample(frac=1, random_state=None).reset_index(drop=True)

        # 7. 저장
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{output_dir}/train_cycle{cycle}_{ts}.csv" if mode == "train" else f"{output_dir}/test_{ts}.csv"
        df.to_csv(filename, index=False)

        self._print_summary(df, filename, cycle)
        return filename

    # ── Step 1: 피드백 로드 ────────────────────────────────────────────────────

    def _load_feedback(self, cycle: int) -> None:
        """Agent-31(AttackCoverage) + Agent-30(FalsePositive) 최신 출력 로드."""
        # 공격 유형별 Recall (Agent-31)
        coverage_files = sorted(glob.glob(f"{METRICS_DIR}/coverage_*.json"))
        if coverage_files:
            try:
                with open(coverage_files[-1]) as f:
                    cov = json.load(f)
                self._prev_recall = cov.get("per_attack_recall", {})
            except Exception:
                pass

        # FP 패턴 (Agent-30)
        fp_files = sorted(glob.glob(f"{METRICS_DIR}/fp_analysis_*.json"))
        if fp_files:
            try:
                with open(fp_files[-1]) as f:
                    fp = json.load(f)
                self._prev_fp_patterns = fp.get("top_patterns", [])
            except Exception:
                pass

        if self._prev_recall:
            low = [a for a, r in self._prev_recall.items() if r < TARGET_RECALL]
            print(f"[Agent-00] 피드백 로드 — 탐지 취약 유형 {len(low)}개: {low}")
        else:
            print(f"[Agent-00] 피드백 없음 — 균등 분포로 생성 (사이클 {cycle})")

    # ── Step 2: 적응형 가중치 ─────────────────────────────────────────────────

    def _compute_adaptive_weights(self) -> None:
        """
        Recall이 낮은 공격 유형의 가중치를 높임.
        가중치 = 1 + (TARGET_RECALL - recall) * BOOST_FACTOR
        Recall 정보 없으면 1.0 유지.
        """
        BOOST_FACTOR = 3.0
        total = 0.0
        for attack in ATTACK_TYPES:
            recall = self._prev_recall.get(attack)
            if recall is not None and recall < TARGET_RECALL:
                gap = TARGET_RECALL - recall
                self._attack_weights[attack] = 1.0 + gap * BOOST_FACTOR
            else:
                self._attack_weights[attack] = 1.0
            total += self._attack_weights[attack]

        # 정규화 (합 = n_attacks)
        n = len(ATTACK_TYPES)
        for a in ATTACK_TYPES:
            self._attack_weights[a] = self._attack_weights[a] / total * n

    # ── Step 3: 정상 트래픽 생성 ──────────────────────────────────────────────

    def _generate_normal(self, n: int, cycle: int) -> pd.DataFrame:
        """
        5종 정상 트래픽 생성.
        사이클이 올라갈수록 시간대·계절성 변동(noise)을 추가해
        탐지기가 다양한 정상 패턴을 학습하도록 함.
        """
        generators = [
            self._gen_normal_web,
            self._gen_normal_dns,
            self._gen_normal_ftp,
            self._gen_normal_stream,
            self._gen_normal_email,
        ]
        n_per = n // len(generators)
        # 사이클 기반 분포 확장 계수 (최대 1.5배)
        spread = min(1.0 + cycle * 0.05, 1.5)
        dfs = [g(n_per, spread) for g in generators]
        return pd.concat(dfs, ignore_index=True)

    def _gen_normal_web(self, n: int, spread: float) -> pd.DataFrame:
        return pd.DataFrame({
            "duration":        np.random.uniform(0.5,    30 * spread,    n),
            "protocol":        np.zeros(n, dtype=int),
            "src_port":        np.random.randint(1024, 65535, n),
            "dst_port":        np.random.choice([80, 443, 8080], n),
            "packet_size":     np.random.uniform(200,    1500,           n),
            "packets_per_sec": np.random.uniform(1,      30 * spread,    n),
            "bytes_per_sec":   np.random.uniform(5000,   100000 * spread,n),
            "unique_dst_ports":np.random.randint(1, 4,   n),
            "connection_count":np.random.randint(1, 15,  n),
            "failed_attempts": np.random.randint(0, 2,   n),
            "outbound_ratio":  np.random.uniform(0.3,    0.6,            n),
            "syn_flag_ratio":  np.random.uniform(0.05,   0.2,            n),
            "label":           np.zeros(n, dtype=int),
            "attack_type":     ["normal_web"] * n,
        })

    def _gen_normal_dns(self, n: int, spread: float) -> pd.DataFrame:
        return pd.DataFrame({
            "duration":        np.random.uniform(0.001, 0.5,   n),
            "protocol":        np.ones(n, dtype=int),
            "src_port":        np.random.randint(1024, 65535,  n),
            "dst_port":        np.full(n, 53),
            "packet_size":     np.random.uniform(40,   200,    n),
            "packets_per_sec": np.random.uniform(1,    10,     n),
            "bytes_per_sec":   np.random.uniform(100,  5000,   n),
            "unique_dst_ports":np.ones(n, dtype=int),
            "connection_count":np.random.randint(1, 5, n),
            "failed_attempts": np.zeros(n, dtype=int),
            "outbound_ratio":  np.random.uniform(0.4,  0.6,    n),
            "syn_flag_ratio":  np.zeros(n),
            "label":           np.zeros(n, dtype=int),
            "attack_type":     ["normal_dns"] * n,
        })

    def _gen_normal_ftp(self, n: int, spread: float) -> pd.DataFrame:
        return pd.DataFrame({
            "duration":        np.random.uniform(10,     300 * spread,   n),
            "protocol":        np.zeros(n, dtype=int),
            "src_port":        np.random.randint(1024, 65535,            n),
            "dst_port":        np.random.choice([21, 22, 445, 2049],     n),
            "packet_size":     np.random.uniform(1000,   1500,           n),
            "packets_per_sec": np.random.uniform(10,     100,            n),
            "bytes_per_sec":   np.random.uniform(50000,  800_000,        n),
            "unique_dst_ports":np.ones(n, dtype=int),
            "connection_count":np.random.randint(1, 5,  n),
            "failed_attempts": np.random.randint(0, 2,  n),
            "outbound_ratio":  np.random.uniform(0.3,    0.65,           n),
            "syn_flag_ratio":  np.random.uniform(0.05,   0.15,           n),
            "label":           np.zeros(n, dtype=int),
            "attack_type":     ["normal_ftp"] * n,
        })

    def _gen_normal_stream(self, n: int, spread: float) -> pd.DataFrame:
        return pd.DataFrame({
            "duration":        np.random.uniform(60,    3600,            n),
            "protocol":        np.zeros(n, dtype=int),
            "src_port":        np.random.randint(1024, 65535,            n),
            "dst_port":        np.random.choice([443, 1935, 8080],       n),
            "packet_size":     np.random.uniform(800,   1500,            n),
            "packets_per_sec": np.random.uniform(5,     45,              n),
            "bytes_per_sec":   np.random.uniform(100000,2_000_000,       n),
            "unique_dst_ports":np.random.randint(1, 3,  n),
            "connection_count":np.random.randint(1, 8,  n),
            "failed_attempts": np.zeros(n, dtype=int),
            "outbound_ratio":  np.random.uniform(0.05,  0.3,             n),
            "syn_flag_ratio":  np.random.uniform(0.1,   0.25,            n),
            "label":           np.zeros(n, dtype=int),
            "attack_type":     ["normal_stream"] * n,
        })

    def _gen_normal_email(self, n: int, spread: float) -> pd.DataFrame:
        return pd.DataFrame({
            "duration":        np.random.uniform(1,     30,              n),
            "protocol":        np.zeros(n, dtype=int),
            "src_port":        np.random.randint(1024, 65535,            n),
            "dst_port":        np.random.choice([25, 110, 143, 465, 993],n),
            "packet_size":     np.random.uniform(100,   1000,            n),
            "packets_per_sec": np.random.uniform(1,     20,              n),
            "bytes_per_sec":   np.random.uniform(1000,  50000,           n),
            "unique_dst_ports":np.random.randint(1, 3,  n),
            "connection_count":np.random.randint(1, 5,  n),
            "failed_attempts": np.random.randint(0, 2,  n),
            "outbound_ratio":  np.random.uniform(0.3,   0.7,             n),
            "syn_flag_ratio":  np.random.uniform(0.05,  0.2,             n),
            "label":           np.zeros(n, dtype=int),
            "attack_type":     ["normal_email"] * n,
        })

    # ── Step 4: 공격 트래픽 생성 (적응형) ────────────────────────────────────

    def _generate_attacks(self, n_total: int, cycle: int) -> pd.DataFrame:
        """
        적응형 가중치 비율로 11개 공격 유형 생성.
        Recall 낮은 유형 → 샘플 수 증가 + 분포 확장으로 다양성 추가.
        """
        total_weight = sum(self._attack_weights[a] for a in ATTACK_TYPES)
        dfs = []
        counts = {}
        for i, attack in enumerate(ATTACK_TYPES):
            weight = self._attack_weights[attack]
            n = int(n_total * weight / total_weight)
            if n < 1:
                n = 1
            counts[attack] = n

            recall = self._prev_recall.get(attack)
            # 취약 유형은 분포 확장 (더 어렵고 다양한 샘플)
            difficulty = 1.0 if recall is None else max(0.5, min(2.0, 1.0 + (TARGET_RECALL - recall) * 2))
            dfs.append(self._gen_attack(attack, n, cycle, difficulty))

        # 수 보정 (rounding 오차)
        actual = sum(counts.values())
        if actual < n_total:
            extra = n_total - actual
            dfs.append(self._gen_attack(ATTACK_TYPES[0], extra, cycle, 1.0))

        return pd.concat(dfs, ignore_index=True)

    def _gen_attack(self, attack_type: str, n: int, cycle: int, difficulty: float) -> pd.DataFrame:
        """
        attack_type에 맞는 패킷 생성.
        difficulty > 1.0이면 탐지 경계에 가까운 "어려운" 샘플 생성.
        """
        rng = np.random.default_rng()

        def _u(lo, hi): return rng.uniform(lo, hi, n)
        def _i(lo, hi): return rng.integers(lo, hi, n)

        # difficulty가 높을수록 경계값에 가깝게 (탐지 어렵게)
        # 예: syn_flag_ratio의 하한을 올려서 탐지기가 구분하기 어렵게 만듦
        d = difficulty  # 약칭

        if attack_type == "synflood":
            conn = _i(500, 5001)
            df = pd.DataFrame({
                "duration":        _u(0.01, 1),
                "protocol":        np.zeros(n, dtype=int),
                "src_port":        _i(1024, 65535),
                "dst_port":        np.random.choice([80, 443, 8080], n),
                "packet_size":     _u(40, 60),
                "packets_per_sec": _u(1000 / d, 10000),   # difficulty 높으면 낮은 pps (탐지 어렵게)
                "bytes_per_sec":   _u(100000, 5_000_000),
                "unique_dst_ports":_i(1, 4),
                "connection_count":conn,
                "failed_attempts": (conn * rng.uniform(0.85 / d, 0.95, n)).astype(int),
                "outbound_ratio":  _u(0.4, 0.7),
                "syn_flag_ratio":  _u(max(0.55, 0.85 / d), 0.99),  # difficulty 높으면 낮은 syn ratio
                "label":           np.ones(n, dtype=int),
                "attack_type":     [attack_type] * n,
            })

        elif attack_type == "ddos":
            df = pd.DataFrame({
                "duration":        _u(0.1, 5),
                "protocol":        np.random.choice([0, 2], n, p=[0.7, 0.3]),
                "src_port":        _i(1024, 65535),
                "dst_port":        np.random.choice([80, 443, 8080], n),
                "packet_size":     _u(40, 100),
                "packets_per_sec": _u(500 / d, 5000),
                "bytes_per_sec":   _u(1_000_000, 50_000_000),
                "unique_dst_ports":_i(1, 4),
                "connection_count":_i(300, 2001),
                "failed_attempts": _i(0, 20),
                "outbound_ratio":  _u(0.3, 0.7),
                "syn_flag_ratio":  _u(max(0.3, 0.5 / d), 0.9),
                "label":           np.ones(n, dtype=int),
                "attack_type":     [attack_type] * n,
            })

        elif attack_type == "portscan":
            df = pd.DataFrame({
                "duration":        _u(0.001, 0.1),
                "protocol":        np.random.choice([0, 1], n, p=[0.8, 0.2]),
                "src_port":        _i(1024, 65535),
                "dst_port":        _i(1, 65535),
                "packet_size":     _u(40, 80),
                "packets_per_sec": _u(10, 100),
                "bytes_per_sec":   _u(1000, 50000),
                "unique_dst_ports":_i(max(10, int(100 / d)), 1025),   # difficulty 높으면 적은 포트
                "connection_count":_i(50, 501),
                "failed_attempts": _i(max(5, int(40 / d)), 201),
                "outbound_ratio":  _u(0.5, 0.9),
                "syn_flag_ratio":  _u(0.6, 0.9),
                "label":           np.ones(n, dtype=int),
                "attack_type":     [attack_type] * n,
            })

        elif attack_type == "bruteforce":
            df = pd.DataFrame({
                "duration":        _u(0.1, 1),
                "protocol":        np.zeros(n, dtype=int),
                "src_port":        _i(1024, 65535),
                "dst_port":        np.random.choice([22, 3389, 21, 23], n),
                "packet_size":     _u(64, 200),
                "packets_per_sec": _u(2, 20),
                "bytes_per_sec":   _u(500, 20000),
                "unique_dst_ports":np.ones(n, dtype=int),
                "connection_count":_i(1, 6),
                "failed_attempts": _i(max(5, int(50 / d)), 501),
                "outbound_ratio":  _u(0.4, 0.6),
                "syn_flag_ratio":  _u(0.2, 0.5),
                "label":           np.ones(n, dtype=int),
                "attack_type":     [attack_type] * n,
            })

        elif attack_type == "exfiltration":
            df = pd.DataFrame({
                "duration":        _u(60, 600),
                "protocol":        np.zeros(n, dtype=int),
                "src_port":        _i(1024, 65535),
                "dst_port":        np.random.choice([443, 80, 8080], n),
                "packet_size":     _u(1000, 1500),
                "packets_per_sec": _u(10, 100),
                "bytes_per_sec":   _u(max(1e6, 5e6 / d), 1e8),
                "unique_dst_ports":_i(1, 4),
                "connection_count":_i(1, 10),
                "failed_attempts": _i(0, 5),
                "outbound_ratio":  _u(max(0.7, 0.85 / d), 0.99),
                "syn_flag_ratio":  _u(0.05, 0.2),
                "label":           np.ones(n, dtype=int),
                "attack_type":     [attack_type] * n,
            })

        elif attack_type == "dns_tunneling":
            df = pd.DataFrame({
                "duration":        _u(30, 600),
                "protocol":        np.ones(n, dtype=int),
                "src_port":        _i(1024, 65535),
                "dst_port":        np.full(n, 53),
                "packet_size":     _u(max(200, 400 / d), 1400),   # difficulty 높으면 정상 DNS 크기에 가깝게
                "packets_per_sec": _u(5, 50),
                "bytes_per_sec":   _u(50000, 500000),
                "unique_dst_ports":np.ones(n, dtype=int),
                "connection_count":_i(1, 10),
                "failed_attempts": _i(0, 5),
                "outbound_ratio":  _u(0.6, 0.95),
                "syn_flag_ratio":  np.zeros(n),
                "label":           np.ones(n, dtype=int),
                "attack_type":     [attack_type] * n,
            })

        elif attack_type == "http_flood":
            df = pd.DataFrame({
                "duration":        _u(0.5, 10),
                "protocol":        np.zeros(n, dtype=int),
                "src_port":        _i(1024, 65535),
                "dst_port":        np.random.choice([80, 443], n),
                "packet_size":     _u(200, 800),
                "packets_per_sec": _u(max(50, 200 / d), 2000),
                "bytes_per_sec":   _u(max(1e5, 5e5 / d), 1e7),
                "unique_dst_ports":_i(1, 3),
                "connection_count":_i(max(10, int(100 / d)), 1000),
                "failed_attempts": _i(0, 10),
                "outbound_ratio":  _u(0.4, 0.7),
                "syn_flag_ratio":  _u(0.1, 0.4),
                "label":           np.ones(n, dtype=int),
                "attack_type":     [attack_type] * n,
            })

        elif attack_type == "slowloris":
            df = pd.DataFrame({
                "duration":        _u(60, 900),
                "protocol":        np.zeros(n, dtype=int),
                "src_port":        _i(1024, 65535),
                "dst_port":        np.random.choice([80, 443], n),
                "packet_size":     _u(40, 100),
                "packets_per_sec": _u(0.01, max(0.5, 0.5 * d)),  # difficulty 높으면 빠른 pps (탐지 어렵게)
                "bytes_per_sec":   _u(10, 500),
                "unique_dst_ports":_i(1, 3),
                "connection_count":_i(max(50, int(200 / d)), 2000),
                "failed_attempts": _i(0, 5),
                "outbound_ratio":  _u(max(0.5, 0.8 / d), 0.99),
                "syn_flag_ratio":  _u(0.05, 0.15),
                "label":           np.ones(n, dtype=int),
                "attack_type":     [attack_type] * n,
            })

        elif attack_type == "botnet_c2":
            df = pd.DataFrame({
                "duration":        _u(0.1, 2),
                "protocol":        np.random.choice([0, 1], n, p=[0.6, 0.4]),
                "src_port":        _i(1024, 65535),
                "dst_port":        np.random.choice([4444, 6667, 1080, 8443, 9001, 443, 80], n),  # difficulty 높으면 정상 포트 포함
                "packet_size":     _u(64, 300),
                "packets_per_sec": _u(0.1, max(2, 5 * d)),
                "bytes_per_sec":   _u(100, 10000),
                "unique_dst_ports":_i(1, 4),
                "connection_count":_i(1, 10),
                "failed_attempts": _i(0, 3),
                "outbound_ratio":  _u(0.5, 0.9),
                "syn_flag_ratio":  _u(0.1, 0.3),
                "label":           np.ones(n, dtype=int),
                "attack_type":     [attack_type] * n,
            })

        elif attack_type == "ransomware":
            df = pd.DataFrame({
                "duration":        _u(1, 60),
                "protocol":        np.zeros(n, dtype=int),
                "src_port":        _i(1024, 65535),
                "dst_port":        np.random.choice([445, 139, 3389, 135], n),
                "packet_size":     _u(500, 1500),
                "packets_per_sec": _u(50, 500),
                "bytes_per_sec":   _u(max(2e5, 1e6 / d), 2e7),
                "unique_dst_ports":_i(max(5, int(50 / d)), 300),
                "connection_count":_i(max(5, int(50 / d)), 500),
                "failed_attempts": _i(max(1, int(10 / d)), 100),
                "outbound_ratio":  _u(0.3, 0.6),
                "syn_flag_ratio":  _u(0.3, 0.6),
                "label":           np.ones(n, dtype=int),
                "attack_type":     [attack_type] * n,
            })

        elif attack_type == "arp_spoofing":
            df = pd.DataFrame({
                "duration":        _u(0.001, 0.05),
                "protocol":        np.full(n, 2),
                "src_port":        np.zeros(n, dtype=int),
                "dst_port":        np.zeros(n, dtype=int),
                "packet_size":     _u(28, 60),
                "packets_per_sec": _u(max(10, 100 / d), 1000),
                "bytes_per_sec":   _u(10000, 500000),
                "unique_dst_ports":_i(max(1, int(5 / d)), 50),
                "connection_count":_i(max(2, int(20 / d)), 200),
                "failed_attempts": _i(max(0, int(5 / d)), 50),
                "outbound_ratio":  _u(0.5, 0.8),
                "syn_flag_ratio":  np.zeros(n),
                "label":           np.ones(n, dtype=int),
                "attack_type":     [attack_type] * n,
            })

        else:
            # 알 수 없는 유형 — 기본 이상 패턴
            df = pd.DataFrame({
                "duration":        _u(0.1, 10),
                "protocol":        _i(0, 3),
                "src_port":        _i(1024, 65535),
                "dst_port":        _i(1, 65535),
                "packet_size":     _u(40, 1500),
                "packets_per_sec": _u(10, 1000),
                "bytes_per_sec":   _u(10000, 1_000_000),
                "unique_dst_ports":_i(1, 100),
                "connection_count":_i(10, 500),
                "failed_attempts": _i(5, 100),
                "outbound_ratio":  _u(0.5, 0.9),
                "syn_flag_ratio":  _u(0.4, 0.9),
                "label":           np.ones(n, dtype=int),
                "attack_type":     [attack_type] * n,
            })

        return df

    # ── Step 5: 경계 샘플 생성 ────────────────────────────────────────────────

    def _generate_boundary_samples(self, n: int, cycle: int) -> pd.DataFrame:
        """
        탐지 경계선(decision boundary)에 가까운 어려운 샘플 생성.
        정상처럼 보이지만 공격인 샘플 → 탐지기 강인성 향상.

        전략:
          - 공격 피처를 정상 범위와 겹치는 구간으로 생성
          - 사이클이 올라갈수록 더 많은 경계 샘플 생성
        """
        if n <= 0:
            return pd.DataFrame()

        n_per_type = max(1, n // 4)
        dfs = []

        # 경계 샘플 유형 1: 느린 포트스캔 (unique_dst_ports 적게)
        dfs.append(pd.DataFrame({
            "duration":        np.random.uniform(0.1, 5,    n_per_type),
            "protocol":        np.zeros(n_per_type, dtype=int),
            "src_port":        np.random.randint(1024, 65535, n_per_type),
            "dst_port":        np.random.randint(1, 65535,    n_per_type),
            "packet_size":     np.random.uniform(40, 80,    n_per_type),
            "packets_per_sec": np.random.uniform(1, 10,     n_per_type),
            "bytes_per_sec":   np.random.uniform(1000, 20000, n_per_type),
            "unique_dst_ports":np.random.randint(10, 50,    n_per_type),  # 정상과 겹치는 범위
            "connection_count":np.random.randint(20, 80,    n_per_type),
            "failed_attempts": np.random.randint(15, 50,    n_per_type),
            "outbound_ratio":  np.random.uniform(0.5, 0.7,  n_per_type),
            "syn_flag_ratio":  np.random.uniform(0.4, 0.6,  n_per_type),
            "label":           np.ones(n_per_type, dtype=int),
            "attack_type":     ["portscan"] * n_per_type,
        }))

        # 경계 샘플 유형 2: 저속 DDoS (packets_per_sec 낮게)
        dfs.append(pd.DataFrame({
            "duration":        np.random.uniform(5, 30,     n_per_type),
            "protocol":        np.random.choice([0, 2], n_per_type),
            "src_port":        np.random.randint(1024, 65535, n_per_type),
            "dst_port":        np.random.choice([80, 443],  n_per_type),
            "packet_size":     np.random.uniform(40, 200,   n_per_type),
            "packets_per_sec": np.random.uniform(50, 150,   n_per_type),  # 정상과 겹치는 범위
            "bytes_per_sec":   np.random.uniform(100000, 1_000_000, n_per_type),
            "unique_dst_ports":np.random.randint(1, 5,      n_per_type),
            "connection_count":np.random.randint(100, 300,  n_per_type),
            "failed_attempts": np.random.randint(0, 10,     n_per_type),
            "outbound_ratio":  np.random.uniform(0.3, 0.6,  n_per_type),
            "syn_flag_ratio":  np.random.uniform(0.3, 0.5,  n_per_type),
            "label":           np.ones(n_per_type, dtype=int),
            "attack_type":     ["ddos"] * n_per_type,
        }))

        # 경계 샘플 유형 3: 위장 exfiltration (outbound_ratio 낮게)
        dfs.append(pd.DataFrame({
            "duration":        np.random.uniform(30, 300,   n_per_type),
            "protocol":        np.zeros(n_per_type, dtype=int),
            "src_port":        np.random.randint(1024, 65535, n_per_type),
            "dst_port":        np.random.choice([443, 80],  n_per_type),
            "packet_size":     np.random.uniform(500, 1500, n_per_type),
            "packets_per_sec": np.random.uniform(5, 30,     n_per_type),
            "bytes_per_sec":   np.random.uniform(500000, 3_000_000, n_per_type),
            "unique_dst_ports":np.random.randint(1, 4,      n_per_type),
            "connection_count":np.random.randint(1, 8,      n_per_type),
            "failed_attempts": np.random.randint(0, 3,      n_per_type),
            "outbound_ratio":  np.random.uniform(0.65, 0.75, n_per_type),  # 정상 FTP와 겹치는 구간
            "syn_flag_ratio":  np.random.uniform(0.05, 0.15, n_per_type),
            "label":           np.ones(n_per_type, dtype=int),
            "attack_type":     ["exfiltration"] * n_per_type,
        }))

        # 경계 샘플 유형 4: 정상처럼 보이는 Botnet C2 (정상 포트 사용)
        dfs.append(pd.DataFrame({
            "duration":        np.random.uniform(0.5, 5,    n_per_type),
            "protocol":        np.zeros(n_per_type, dtype=int),
            "src_port":        np.random.randint(1024, 65535, n_per_type),
            "dst_port":        np.random.choice([443, 80, 8080], n_per_type),  # 정상 포트 사용
            "packet_size":     np.random.uniform(100, 500,  n_per_type),
            "packets_per_sec": np.random.uniform(0.5, 3,    n_per_type),
            "bytes_per_sec":   np.random.uniform(500, 5000, n_per_type),
            "unique_dst_ports":np.random.randint(1, 3,      n_per_type),
            "connection_count":np.random.randint(3, 15,     n_per_type),
            "failed_attempts": np.random.randint(0, 2,      n_per_type),
            "outbound_ratio":  np.random.uniform(0.6, 0.8,  n_per_type),
            "syn_flag_ratio":  np.random.uniform(0.1, 0.25, n_per_type),
            "label":           np.ones(n_per_type, dtype=int),
            "attack_type":     ["botnet_c2"] * n_per_type,
        }))

        return pd.concat(dfs, ignore_index=True)

    # ── 출력 ──────────────────────────────────────────────────────────────────

    def _print_summary(self, df: pd.DataFrame, filename: str, cycle: int) -> None:
        n_normal = int((df["label"] == 0).sum())
        n_attack = int((df["label"] == 1).sum())

        print(f"\n[Agent-00] AI 적응형 패킷 생성 완료 — 사이클 {cycle}")
        print(f"  파일: {filename}")
        print(f"  총 건수: {len(df):,}건")
        print(f"  정상: {n_normal:,}건 ({n_normal/len(df)*100:.0f}%)")
        print(f"  비정상: {n_attack:,}건 ({n_attack/len(df)*100:.0f}%)")

        # 적응형 가중치 요약
        boosted = [(a, w) for a, w in self._attack_weights.items() if w > 1.1]
        if boosted:
            print(f"\n  [적응형] 강화된 공격 유형 (Recall 취약):")
            for a, w in sorted(boosted, key=lambda x: -x[1]):
                recall = self._prev_recall.get(a, "N/A")
                recall_str = f"{recall:.3f}" if isinstance(recall, float) else recall
                print(f"    {a:20s}  가중치 ×{w:.2f}  (이전 Recall: {recall_str})")
        else:
            print(f"\n  [적응형] 모든 공격 유형 균등 분배 (첫 사이클 또는 목표 달성)")

        # 공격 유형별 건수
        print(f"\n  공격 유형별 건수:")
        for atype in ATTACK_TYPES:
            cnt = int((df["attack_type"] == atype).sum())
            bar = "█" * (cnt // 10)
            print(f"    {atype:20s}: {cnt:4d}건  {bar}")

        # 경계 샘플 건수
        boundary_total = sum((df["attack_type"] == a).sum() for a in ["portscan", "ddos", "exfiltration", "botnet_c2"])
        print(f"\n  경계 샘플 포함: ~{int(len(df)*0.05):,}건 (전체의 5%)")
        print(f"OUTPUT_FILE:{filename}")
