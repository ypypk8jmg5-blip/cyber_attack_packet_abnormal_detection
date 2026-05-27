#!/usr/bin/env python3
"""
패킷생성기 v2 — 정상 5종 + 비정상 11종
"""
import argparse, os, time
import numpy as np
import pandas as pd
from datetime import datetime

# ── 현실적 테스트 데이터 변환 헬퍼 ───────────────────────────────────────────

_NUMERIC_FEATS = [
    'duration', 'packet_size', 'packets_per_sec', 'bytes_per_sec',
    'unique_dst_ports', 'connection_count', 'failed_attempts',
    'outbound_ratio', 'syn_flag_ratio',
]

def _add_noise(df: pd.DataFrame, noise_frac: float = 0.15) -> pd.DataFrame:
    """모든 수치 피처에 가우시안 노이즈(σ=noise_frac×값) 추가.
    outbound_ratio, syn_flag_ratio는 [0,1] 클리핑,
    나머지 양수 피처는 0 이하 클리핑.
    """
    df = df.copy()
    for col in _NUMERIC_FEATS:
        if col not in df.columns:
            continue
        sigma = np.abs(df[col].values) * noise_frac
        df[col] = df[col] + np.random.normal(0, sigma)
        if col in ('outbound_ratio', 'syn_flag_ratio'):
            df[col] = df[col].clip(0.0, 1.0)
        else:
            df[col] = df[col].clip(0.0)
    return df


def _make_borderline_attacks(df_attack: pd.DataFrame, frac: float = 0.30) -> pd.DataFrame:
    """공격 데이터의 frac 비율을 '저강도 변종'으로 교체.

    각 공격 유형별 핵심 식별자(가장 극단적인 피처)를 정상 경계 쪽으로
    30~60% 줄여 모델이 분류하기 어려운 경계 사례를 만든다.

    규칙:
      ddos       : packets_per_sec → 100~500 (정상 max 50, 전형적 min 500)
      synflood   : syn_flag_ratio  → 0.50~0.85 (정상 max 0.25, 전형적 min 0.85)
      portscan   : unique_dst_ports→ 4~30  (정상 max 3, 전형적 min 100)
      bruteforce : failed_attempts → 5~20  (정상 max 2, 전형적 min 50)
      exfiltration: bytes_per_sec → 1M~5M + outbound_ratio 0.70~0.85
      dns_tunneling: packet_size  → 200~400
      http_flood : packets_per_sec→ 50~200 + bytes_per_sec 100K~500K
      slowloris  : connection_count→50~200 + duration 30~60
      botnet_c2  : 피처 노이즈만 (포트 기반 탐지라 강도 조절 불가)
      ransomware : unique_dst_ports→ 5~50
      arp_spoofing: packets_per_sec→ 20~100
    """
    df_attack = df_attack.copy()
    n_total = len(df_attack)
    border_idx = df_attack.sample(frac=frac, random_state=None).index

    for idx in border_idx:
        atype = df_attack.at[idx, 'attack_type']
        if atype == 'ddos':
            df_attack.at[idx, 'packets_per_sec']  = np.random.uniform(100, 500)
            df_attack.at[idx, 'connection_count'] = np.random.randint(30, 300)
        elif atype == 'synflood':
            df_attack.at[idx, 'syn_flag_ratio']   = np.random.uniform(0.50, 0.85)
            df_attack.at[idx, 'packets_per_sec']  = np.random.uniform(100, 1000)
        elif atype == 'portscan':
            df_attack.at[idx, 'unique_dst_ports'] = np.random.randint(4, 30)
            df_attack.at[idx, 'connection_count'] = np.random.randint(10, 50)
            df_attack.at[idx, 'failed_attempts']  = np.random.randint(5, 40)
        elif atype == 'bruteforce':
            df_attack.at[idx, 'failed_attempts']  = np.random.randint(5, 20)
        elif atype == 'exfiltration':
            df_attack.at[idx, 'bytes_per_sec']    = np.random.uniform(1_000_000, 5_000_000)
            df_attack.at[idx, 'outbound_ratio']   = np.random.uniform(0.70, 0.85)
        elif atype == 'dns_tunneling':
            df_attack.at[idx, 'packet_size']      = np.random.uniform(200, 400)
        elif atype == 'http_flood':
            df_attack.at[idx, 'packets_per_sec']  = np.random.uniform(50, 200)
            df_attack.at[idx, 'bytes_per_sec']    = np.random.uniform(100_000, 500_000)
        elif atype == 'slowloris':
            df_attack.at[idx, 'connection_count'] = np.random.randint(100, 500)  # 정상 최대(15)보다 훨씬 높음
            df_attack.at[idx, 'duration']         = np.random.uniform(30, 60)
            df_attack.at[idx, 'failed_attempts']  = np.random.randint(10, 50)  # 경계선에서도 유지
        elif atype == 'ransomware':
            df_attack.at[idx, 'unique_dst_ports'] = np.random.randint(5, 50)
            df_attack.at[idx, 'bytes_per_sec']    = np.random.uniform(200_000, 1_000_000)
        elif atype == 'arp_spoofing':
            df_attack.at[idx, 'packets_per_sec']  = np.random.uniform(20, 100)
        elif atype == 'cryptomining':
            df_attack.at[idx, 'duration']          = np.random.uniform(600, 3600)  # 짧아진 연결
            df_attack.at[idx, 'bytes_per_sec']     = np.random.uniform(3_000, 10_000)  # 낮아진 전송량
        elif atype == 'dns_amplification':
            df_attack.at[idx, 'packet_size']       = np.random.uniform(400, 1000)  # 증폭률 감소
            df_attack.at[idx, 'bytes_per_sec']     = np.random.uniform(500_000, 5_000_000)
        elif atype == 'credential_stuffing':
            df_attack.at[idx, 'connection_count']  = np.random.randint(10, 50)   # 적은 계정
            df_attack.at[idx, 'failed_attempts']   = np.random.randint(1, 5)     # 거의 정상처럼

    return df_attack


def _make_heavy_normals(df_normal: pd.DataFrame, frac: float = 0.15) -> pd.DataFrame:
    """정상 데이터의 frac 비율을 '고부하 정상'으로 교체.

    피처 값을 공격 경계 근처로 올려 FP(오탐) 가능성을 재현한다.
      - 비디오스트리밍: bytes_per_sec 1.5M~2.5M (HTTP Flood 경계)
      - 파일전송:       bytes_per_sec 700K~1.2M (exfiltration 경계)
      - DNS 조회:       packet_size   180~280   (DNS 터널링 경계)
      - 웹브라우징:     packets_per_sec 40~80   (DDoS 경계 근처)
    """
    df_normal = df_normal.copy()
    target = df_normal.sample(frac=frac, random_state=None)

    for idx in target.index:
        atype = df_normal.at[idx, 'attack_type']
        if atype == 'normal_stream':
            df_normal.at[idx, 'bytes_per_sec']   = np.random.uniform(1_500_000, 2_500_000)
            df_normal.at[idx, 'packets_per_sec'] = np.random.uniform(40, 55)
        elif atype == 'normal_ftp':
            df_normal.at[idx, 'bytes_per_sec']   = np.random.uniform(700_000, 1_200_000)
            df_normal.at[idx, 'outbound_ratio']  = np.random.uniform(0.65, 0.80)
        elif atype == 'normal_dns':
            df_normal.at[idx, 'packet_size']     = np.random.uniform(180, 280)
        elif atype == 'normal_web':
            df_normal.at[idx, 'packets_per_sec'] = np.random.uniform(40, 80)
            df_normal.at[idx, 'connection_count']= np.random.randint(15, 30)
        elif atype == 'normal_backup':
            df_normal.at[idx, 'bytes_per_sec']   = np.random.uniform(1_500_000, 2_500_000)
            df_normal.at[idx, 'outbound_ratio']  = np.random.uniform(0.68, 0.78)
        elif atype == 'normal_gaming':
            df_normal.at[idx, 'packets_per_sec'] = np.random.uniform(45, 55)   # DDoS 경계 근처
        elif atype == 'normal_voip':
            df_normal.at[idx, 'packets_per_sec'] = np.random.uniform(44, 50)

    return df_normal

# ── 정상 트래픽 (10종) ────────────────────────────────────────────────────────
def gen_web_browsing(n):
    return pd.DataFrame({
        'duration': np.random.uniform(0.5, 30, n),
        'protocol': np.zeros(n, dtype=int),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([80, 443, 8080], n),
        'packet_size': np.random.uniform(200, 1500, n),
        'packets_per_sec': np.random.uniform(1, 30, n),
        'bytes_per_sec': np.random.uniform(5000, 100000, n),
        'unique_dst_ports': np.random.randint(1, 4, n),
        'connection_count': np.random.randint(1, 15, n),
        'failed_attempts': np.random.randint(0, 2, n),
        'outbound_ratio': np.random.uniform(0.3, 0.6, n),
        'syn_flag_ratio': np.random.uniform(0.05, 0.2, n),
        'label': np.zeros(n, dtype=int),
        'attack_type': ['normal_web'] * n,
    })

def gen_dns_query(n):
    return pd.DataFrame({
        'duration': np.random.uniform(0.001, 0.5, n),
        'protocol': np.ones(n, dtype=int),   # UDP
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.full(n, 53),
        'packet_size': np.random.uniform(40, 200, n),
        'packets_per_sec': np.random.uniform(1, 10, n),
        'bytes_per_sec': np.random.uniform(100, 5000, n),
        'unique_dst_ports': np.ones(n, dtype=int),
        'connection_count': np.random.randint(1, 5, n),
        'failed_attempts': np.zeros(n, dtype=int),
        'outbound_ratio': np.random.uniform(0.4, 0.6, n),
        'syn_flag_ratio': np.zeros(n),
        'label': np.zeros(n, dtype=int),
        'attack_type': ['normal_dns'] * n,
    })

def gen_file_transfer(n):
    return pd.DataFrame({
        'duration': np.random.uniform(10, 300, n),
        'protocol': np.zeros(n, dtype=int),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([21, 22, 990, 2049], n),  # 445 제거: 랜섬웨어와 포트 충돌 방지
        'packet_size': np.random.uniform(1000, 1500, n),
        'packets_per_sec': np.random.uniform(5, 45, n),      # NORMAL_RANGES 상한(50) 이내 유지
        'bytes_per_sec': np.random.uniform(50000, 500_000, n),   # exfiltration(5M~)과 명확히 분리
        'unique_dst_ports': np.ones(n, dtype=int),
        'connection_count': np.random.randint(1, 5, n),
        'failed_attempts': np.random.randint(0, 2, n),
        'outbound_ratio': np.random.uniform(0.3, 0.65, n),       # exfiltration(0.85~)과 분리
        'syn_flag_ratio': np.random.uniform(0.05, 0.15, n),
        'label': np.zeros(n, dtype=int),
        'attack_type': ['normal_ftp'] * n,
    })

def gen_video_stream(n):
    return pd.DataFrame({
        'duration': np.random.uniform(60, 3600, n),
        'protocol': np.zeros(n, dtype=int),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([443, 1935, 8080], n),
        'packet_size': np.random.uniform(800, 1500, n),
        'packets_per_sec': np.random.uniform(5, 45, n),       # 정상 범위(1~50) 내 유지
        'bytes_per_sec': np.random.uniform(100000, 2_000_000, n),  # http_flood(5M~)과 분리
        'unique_dst_ports': np.random.randint(1, 3, n),
        'connection_count': np.random.randint(1, 8, n),
        'failed_attempts': np.zeros(n, dtype=int),
        'outbound_ratio': np.random.uniform(0.05, 0.3, n),
        'syn_flag_ratio': np.random.uniform(0.1, 0.25, n),    # 정상 범위 내
        'label': np.zeros(n, dtype=int),
        'attack_type': ['normal_stream'] * n,
    })

def gen_email(n):
    return pd.DataFrame({
        'duration': np.random.uniform(1, 30, n),
        'protocol': np.zeros(n, dtype=int),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([25, 110, 143, 465, 993], n),
        'packet_size': np.random.uniform(100, 1000, n),
        'packets_per_sec': np.random.uniform(1, 20, n),
        'bytes_per_sec': np.random.uniform(1000, 50000, n),
        'unique_dst_ports': np.random.randint(1, 3, n),
        'connection_count': np.random.randint(1, 5, n),
        'failed_attempts': np.random.randint(0, 2, n),
        'outbound_ratio': np.random.uniform(0.3, 0.7, n),
        'syn_flag_ratio': np.random.uniform(0.05, 0.2, n),
        'label': np.zeros(n, dtype=int),
        'attack_type': ['normal_email'] * n,
    })

def gen_voip(n):
    """VoIP/화상통화: 일정한 소형 UDP 패킷 (RTP 스트림)"""
    return pd.DataFrame({
        'duration': np.random.uniform(60, 3600, n),
        'protocol': np.ones(n, dtype=int),   # UDP (RTP)
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([3478, 5004, 8801, 19302], n),
        'packet_size': np.random.uniform(80, 250, n),
        'packets_per_sec': np.random.uniform(20, 50, n),
        'bytes_per_sec': np.random.uniform(15_000, 150_000, n),
        'unique_dst_ports': np.random.randint(1, 3, n),
        'connection_count': np.random.randint(1, 4, n),
        'failed_attempts': np.zeros(n, dtype=int),
        'outbound_ratio': np.random.uniform(0.45, 0.55, n),  # 양방향 균등
        'syn_flag_ratio': np.zeros(n),                        # UDP
        'label': np.zeros(n, dtype=int),
        'attack_type': ['normal_voip'] * n,
    })

def gen_gaming(n):
    """온라인 게임: 소형 고빈도 UDP 패킷"""
    return pd.DataFrame({
        'duration': np.random.uniform(600, 14400, n),
        'protocol': np.ones(n, dtype=int),   # UDP
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([27015, 27016, 3074, 25565], n),
        'packet_size': np.random.uniform(40, 200, n),
        'packets_per_sec': np.random.uniform(10, 48, n),   # NORMAL_RANGES 상한(50) 이내
        'bytes_per_sec': np.random.uniform(5_000, 80_000, n),
        'unique_dst_ports': np.random.randint(1, 3, n),
        'connection_count': np.random.randint(1, 5, n),
        'failed_attempts': np.random.randint(0, 2, n),
        'outbound_ratio': np.random.uniform(0.4, 0.6, n),
        'syn_flag_ratio': np.zeros(n),
        'label': np.zeros(n, dtype=int),
        'attack_type': ['normal_gaming'] * n,
    })

def gen_iot(n):
    """IoT 센서: 주기적 소형 패킷 (MQTT/CoAP)"""
    return pd.DataFrame({
        'duration': np.random.uniform(0.01, 1, n),
        'protocol': np.random.choice([0, 1], n, p=[0.5, 0.5]),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([1883, 8883, 5683], n),  # MQTT, CoAP
        'packet_size': np.random.uniform(20, 100, n),
        'packets_per_sec': np.random.uniform(0.1, 5, n),
        'bytes_per_sec': np.random.uniform(10, 2_000, n),
        'unique_dst_ports': np.ones(n, dtype=int),
        'connection_count': np.random.randint(1, 3, n),
        'failed_attempts': np.zeros(n, dtype=int),
        'outbound_ratio': np.random.uniform(0.6, 0.9, n),
        'syn_flag_ratio': np.random.uniform(0.0, 0.05, n),
        'label': np.zeros(n, dtype=int),
        'attack_type': ['normal_iot'] * n,
    })

def gen_backup(n):
    """백업/클라우드동기화: 대용량 지속 전송"""
    return pd.DataFrame({
        'duration': np.random.uniform(300, 7200, n),
        'protocol': np.zeros(n, dtype=int),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([443, 873, 2049, 636], n),   # HTTPS, rsync, NFS, LDAPS (8443은 C2_PORTS 충돌)
        'packet_size': np.random.uniform(1000, 1500, n),
        'packets_per_sec': np.random.uniform(10, 45, n),   # NORMAL_RANGES 이내
        'bytes_per_sec': np.random.uniform(200_000, 2_000_000, n),  # exfiltration(5M~)과 충분한 차이
        'unique_dst_ports': np.random.randint(1, 3, n),
        'connection_count': np.random.randint(1, 5, n),
        'failed_attempts': np.random.randint(0, 2, n),
        'outbound_ratio': np.random.uniform(0.5, 0.72, n),   # exfiltration(0.85~)과 충분한 차이
        'syn_flag_ratio': np.random.uniform(0.03, 0.1, n),
        'label': np.zeros(n, dtype=int),
        'attack_type': ['normal_backup'] * n,
    })

def gen_ssh(n):
    """SSH 관리 세션: 대화형 원격 접속"""
    return pd.DataFrame({
        'duration': np.random.uniform(30, 3600, n),
        'protocol': np.zeros(n, dtype=int),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.full(n, 22),
        'packet_size': np.random.uniform(100, 600, n),
        'packets_per_sec': np.random.uniform(1, 20, n),
        'bytes_per_sec': np.random.uniform(500, 50_000, n),
        'unique_dst_ports': np.ones(n, dtype=int),
        'connection_count': np.random.randint(1, 4, n),
        'failed_attempts': np.random.randint(0, 2, n),  # 정상 SSH는 실패 거의 없음
        'outbound_ratio': np.random.uniform(0.35, 0.6, n),
        'syn_flag_ratio': np.random.uniform(0.05, 0.2, n),
        'label': np.zeros(n, dtype=int),
        'attack_type': ['normal_ssh'] * n,
    })

# ── 비정상 트래픽 (14종) ──────────────────────────────────────────────────────
def gen_ddos(n):
    return pd.DataFrame({
        'duration': np.random.uniform(0.1, 5, n),
        'protocol': np.random.choice([0, 2], n, p=[0.7, 0.3]),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([80, 443, 8080], n),
        'packet_size': np.random.uniform(40, 100, n),
        'packets_per_sec': np.random.uniform(500, 5000, n),
        'bytes_per_sec': np.random.uniform(1_000_000, 50_000_000, n),
        'unique_dst_ports': np.random.randint(1, 4, n),
        'connection_count': np.random.randint(300, 2001, n),
        'failed_attempts': np.random.randint(0, 20, n),
        'outbound_ratio': np.random.uniform(0.3, 0.7, n),
        'syn_flag_ratio': np.random.uniform(0.5, 0.9, n),
        'label': np.ones(n, dtype=int),
        'attack_type': ['ddos'] * n,
    })

def gen_portscan(n):
    return pd.DataFrame({
        'duration': np.random.uniform(0.001, 0.1, n),
        'protocol': np.random.choice([0, 1], n, p=[0.8, 0.2]),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.randint(1, 65535, n),
        'packet_size': np.random.uniform(40, 80, n),
        'packets_per_sec': np.random.uniform(10, 100, n),
        'bytes_per_sec': np.random.uniform(1000, 50000, n),
        'unique_dst_ports': np.random.randint(100, 1025, n),
        'connection_count': np.random.randint(50, 501, n),
        'failed_attempts': np.random.randint(40, 201, n),
        'outbound_ratio': np.random.uniform(0.5, 0.9, n),
        'syn_flag_ratio': np.random.uniform(0.6, 0.9, n),
        'label': np.ones(n, dtype=int),
        'attack_type': ['portscan'] * n,
    })

def gen_bruteforce(n):
    return pd.DataFrame({
        'duration': np.random.uniform(0.1, 1, n),
        'protocol': np.zeros(n, dtype=int),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([22, 3389, 21, 23], n),
        'packet_size': np.random.uniform(64, 200, n),
        'packets_per_sec': np.random.uniform(2, 20, n),
        'bytes_per_sec': np.random.uniform(500, 20000, n),
        'unique_dst_ports': np.ones(n, dtype=int),
        'connection_count': np.random.randint(1, 6, n),
        'failed_attempts': np.random.randint(50, 501, n),
        'outbound_ratio': np.random.uniform(0.4, 0.6, n),
        'syn_flag_ratio': np.random.uniform(0.2, 0.5, n),
        'label': np.ones(n, dtype=int),
        'attack_type': ['bruteforce'] * n,
    })

def gen_exfiltration(n):
    return pd.DataFrame({
        'duration': np.random.uniform(60, 600, n),
        'protocol': np.zeros(n, dtype=int),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([443, 80, 8080], n),
        'packet_size': np.random.uniform(1000, 1500, n),
        'packets_per_sec': np.random.uniform(10, 100, n),
        'bytes_per_sec': np.random.uniform(5_000_000, 100_000_000, n),
        'unique_dst_ports': np.random.randint(1, 4, n),
        'connection_count': np.random.randint(1, 10, n),
        'failed_attempts': np.random.randint(0, 5, n),
        'outbound_ratio': np.random.uniform(0.85, 0.99, n),
        'syn_flag_ratio': np.random.uniform(0.05, 0.2, n),
        'label': np.ones(n, dtype=int),
        'attack_type': ['exfiltration'] * n,
    })

def gen_synflood(n):
    conn = np.random.randint(500, 5001, n)
    return pd.DataFrame({
        'duration': np.random.uniform(0.01, 1, n),
        'protocol': np.zeros(n, dtype=int),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([80, 443, 8080], n),
        'packet_size': np.random.uniform(40, 60, n),
        'packets_per_sec': np.random.uniform(1000, 10000, n),
        'bytes_per_sec': np.random.uniform(100000, 5_000_000, n),
        'unique_dst_ports': np.random.randint(1, 4, n),
        'connection_count': conn,
        'failed_attempts': (conn * np.random.uniform(0.85, 0.95, n)).astype(int),
        'outbound_ratio': np.random.uniform(0.4, 0.7, n),
        'syn_flag_ratio': np.random.uniform(0.85, 0.99, n),
        'label': np.ones(n, dtype=int),
        'attack_type': ['synflood'] * n,
    })

def gen_dns_tunneling(n):
    """DNS 터널링: DNS(53) 포트에 비정상적으로 큰 페이로드"""
    return pd.DataFrame({
        'duration': np.random.uniform(30, 600, n),
        'protocol': np.ones(n, dtype=int),  # UDP
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.full(n, 53),
        'packet_size': np.random.uniform(400, 1400, n),   # DNS치고 비정상적으로 큼
        'packets_per_sec': np.random.uniform(5, 50, n),
        'bytes_per_sec': np.random.uniform(500_000, 5_000_000, n),  # 정상 DNS(100~5000)와 명확히 분리
        'unique_dst_ports': np.ones(n, dtype=int),
        'connection_count': np.random.randint(5, 30, n),  # 정상 DNS(1~5)보다 높음
        'failed_attempts': np.random.randint(0, 5, n),
        'outbound_ratio': np.random.uniform(0.7, 0.99, n),  # 높은 외부 전송 비율
        'syn_flag_ratio': np.zeros(n),
        'label': np.ones(n, dtype=int),
        'attack_type': ['dns_tunneling'] * n,
    })

def gen_http_flood(n):
    """HTTP 플러드: 정상처럼 보이지만 엄청난 양의 HTTP 요청"""
    return pd.DataFrame({
        'duration': np.random.uniform(0.5, 10, n),
        'protocol': np.zeros(n, dtype=int),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([80, 443], n),
        'packet_size': np.random.uniform(200, 800, n),
        'packets_per_sec': np.random.uniform(200, 2000, n),
        'bytes_per_sec': np.random.uniform(500000, 10_000_000, n),
        'unique_dst_ports': np.random.randint(1, 3, n),
        'connection_count': np.random.randint(100, 1000, n),
        'failed_attempts': np.random.randint(0, 10, n),
        'outbound_ratio': np.random.uniform(0.4, 0.7, n),
        'syn_flag_ratio': np.random.uniform(0.1, 0.4, n),
        'label': np.ones(n, dtype=int),
        'attack_type': ['http_flood'] * n,
    })

def gen_slowloris(n):
    """Slowloris: 연결을 맺고 아주 천천히 전송 — 서버 연결 고갈"""
    return pd.DataFrame({
        'duration': np.random.uniform(60, 900, n),   # 매우 긴 연결
        'protocol': np.zeros(n, dtype=int),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([80, 443], n),
        'packet_size': np.random.uniform(40, 100, n),
        'packets_per_sec': np.random.uniform(0.01, 0.5, n),  # 극단적으로 낮음
        'bytes_per_sec': np.random.uniform(10, 500, n),
        'unique_dst_ports': np.random.randint(1, 3, n),
        'connection_count': np.random.randint(200, 2000, n),  # 연결 수는 많음
        'failed_attempts': np.random.randint(20, 100, n),  # 미완료 연결 → 높은 실패 수
        'outbound_ratio': np.random.uniform(0.8, 0.99, n),
        'syn_flag_ratio': np.random.uniform(0.05, 0.15, n),
        'label': np.ones(n, dtype=int),
        'attack_type': ['slowloris'] * n,
    })

def gen_botnet_c2(n):
    """봇넷 C2: 주기적인 소량의 비콘 통신"""
    return pd.DataFrame({
        'duration': np.random.uniform(0.1, 2, n),
        'protocol': np.random.choice([0, 1], n, p=[0.6, 0.4]),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([4444, 6667, 1080, 8443, 9001], n),  # 비정상 포트
        'packet_size': np.random.uniform(64, 300, n),
        'packets_per_sec': np.random.uniform(0.1, 5, n),
        'bytes_per_sec': np.random.uniform(100, 10000, n),
        'unique_dst_ports': np.random.randint(1, 4, n),
        'connection_count': np.random.randint(1, 10, n),
        'failed_attempts': np.random.randint(0, 3, n),
        'outbound_ratio': np.random.uniform(0.5, 0.9, n),
        'syn_flag_ratio': np.random.uniform(0.1, 0.3, n),
        'label': np.ones(n, dtype=int),
        'attack_type': ['botnet_c2'] * n,
    })

def gen_ransomware(n):
    """랜섬웨어: 내부망 전파 + 대량 SMB/파일 접근"""
    return pd.DataFrame({
        'duration': np.random.uniform(1, 60, n),
        'protocol': np.zeros(n, dtype=int),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([445, 139, 3389, 135], n),  # SMB/RDP
        'packet_size': np.random.uniform(500, 1500, n),
        'packets_per_sec': np.random.uniform(50, 500, n),
        'bytes_per_sec': np.random.uniform(1_000_000, 20_000_000, n),
        'unique_dst_ports': np.random.randint(50, 300, n),
        'connection_count': np.random.randint(50, 500, n),
        'failed_attempts': np.random.randint(10, 100, n),
        'outbound_ratio': np.random.uniform(0.3, 0.6, n),
        'syn_flag_ratio': np.random.uniform(0.3, 0.6, n),
        'label': np.ones(n, dtype=int),
        'attack_type': ['ransomware'] * n,
    })

def gen_arp_spoofing(n):
    """ARP 스푸핑: ICMP 집중, 브로드캐스트 패킷 다수"""
    return pd.DataFrame({
        'duration': np.random.uniform(0.001, 0.05, n),
        'protocol': np.full(n, 2),  # ICMP
        'src_port': np.zeros(n, dtype=int),
        'dst_port': np.zeros(n, dtype=int),
        'packet_size': np.random.uniform(28, 60, n),  # ARP 패킷 크기
        'packets_per_sec': np.random.uniform(100, 1000, n),
        'bytes_per_sec': np.random.uniform(10000, 500000, n),
        'unique_dst_ports': np.random.randint(5, 50, n),
        'connection_count': np.random.randint(20, 200, n),
        'failed_attempts': np.random.randint(5, 50, n),
        'outbound_ratio': np.random.uniform(0.5, 0.8, n),
        'syn_flag_ratio': np.zeros(n),
        'label': np.ones(n, dtype=int),
        'attack_type': ['arp_spoofing'] * n,
    })

def gen_cryptomining(n):
    """크립토마이닝: 마이닝풀 지속 연결 — 낮고 일정한 아웃바운드"""
    return pd.DataFrame({
        'duration': np.random.uniform(3600, 86400, n),   # 수 시간~수 일 지속
        'protocol': np.zeros(n, dtype=int),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([3333, 14444, 45700, 9999], n),  # 마이닝풀 포트
        'packet_size': np.random.uniform(200, 800, n),
        'packets_per_sec': np.random.uniform(1, 10, n),   # 낮고 일정
        'bytes_per_sec': np.random.uniform(10_000, 200_000, n),
        'unique_dst_ports': np.ones(n, dtype=int),        # 단일 풀
        'connection_count': np.random.randint(1, 4, n),
        'failed_attempts': np.zeros(n, dtype=int),
        'outbound_ratio': np.random.uniform(0.7, 0.95, n),  # 채굴 결과 전송
        'syn_flag_ratio': np.random.uniform(0.05, 0.15, n),
        'label': np.ones(n, dtype=int),
        'attack_type': ['cryptomining'] * n,
    })

def gen_dns_amplification(n):
    """DNS 증폭 DDoS: 소형 쿼리 → 대용량 응답 (피해자 관점)"""
    return pd.DataFrame({
        'duration': np.random.uniform(1, 60, n),
        'protocol': np.ones(n, dtype=int),   # UDP
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.full(n, 53),
        'packet_size': np.random.uniform(1000, 4000, n),  # 증폭된 대용량 응답
        'packets_per_sec': np.random.uniform(100, 5000, n),
        'bytes_per_sec': np.random.uniform(5_000_000, 100_000_000, n),
        'unique_dst_ports': np.ones(n, dtype=int),
        'connection_count': np.random.randint(100, 5001, n),
        'failed_attempts': np.random.randint(0, 10, n),
        'outbound_ratio': np.random.uniform(0.05, 0.25, n),  # 피해자는 주로 수신
        'syn_flag_ratio': np.zeros(n),
        'label': np.ones(n, dtype=int),
        'attack_type': ['dns_amplification'] * n,
    })

def gen_credential_stuffing(n):
    """크리덴셜 스터핑: 유출 계정정보 저속 분산 시도 (브루트포스와 구별)"""
    return pd.DataFrame({
        'duration': np.random.uniform(0.1, 2, n),
        'protocol': np.zeros(n, dtype=int),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice([80, 443, 22, 25], n),
        'packet_size': np.random.uniform(200, 600, n),
        'packets_per_sec': np.random.uniform(1, 15, n),   # 저속 — 탐지 회피
        'bytes_per_sec': np.random.uniform(500, 10_000, n),
        'unique_dst_ports': np.random.randint(1, 3, n),
        'connection_count': np.random.randint(50, 500, n),  # 다수 계정 시도
        'failed_attempts': np.random.randint(3, 20, n),    # 낮음 (브루트포스 50~500과 구별)
        'outbound_ratio': np.random.uniform(0.4, 0.65, n),
        'syn_flag_ratio': np.random.uniform(0.1, 0.3, n),
        'label': np.ones(n, dtype=int),
        'attack_type': ['credential_stuffing'] * n,
    })

# ── 생성 함수 매핑 ────────────────────────────────────────────────────────────
NORMAL_GENERATORS = [
    gen_web_browsing, gen_dns_query, gen_file_transfer, gen_video_stream, gen_email,
    gen_voip, gen_gaming, gen_iot, gen_backup, gen_ssh,
]

ATTACK_GENERATORS = {
    'ddos': gen_ddos,
    'portscan': gen_portscan,
    'bruteforce': gen_bruteforce,
    'exfiltration': gen_exfiltration,
    'synflood': gen_synflood,
    'dns_tunneling': gen_dns_tunneling,
    'http_flood': gen_http_flood,
    'slowloris': gen_slowloris,
    'botnet_c2': gen_botnet_c2,
    'ransomware': gen_ransomware,
    'arp_spoofing': gen_arp_spoofing,
    'cryptomining': gen_cryptomining,
    'dns_amplification': gen_dns_amplification,
    'credential_stuffing': gen_credential_stuffing,
}

ATTACK_LABELS_KO = {
    'ddos': 'DDoS',
    'portscan': 'Port Scan',
    'bruteforce': 'Brute Force',
    'exfiltration': 'Exfiltration',
    'synflood': 'SYN Flood',
    'dns_tunneling': 'DNS Tunneling',
    'http_flood': 'HTTP Flood',
    'slowloris': 'Slowloris',
    'botnet_c2': 'Botnet C&C',
    'ransomware': 'Ransomware',
    'arp_spoofing': 'ARP Spoofing',
    'cryptomining': 'Cryptomining',
    'dns_amplification': 'DNS Amplif.',
    'credential_stuffing': 'Cred. Stuffing',
}


def main():
    parser = argparse.ArgumentParser(description='네트워크 패킷 데이터 생성기 v2')
    parser.add_argument('--cycle', type=int, default=1)
    parser.add_argument('--size', type=int, default=0, help='0이면 사이클 기준 자동 설정')
    parser.add_argument('--mode', type=str, default='train', choices=['train', 'test'])
    parser.add_argument('--ai', action='store_true',
                        help='AI 적응형 생성 모드 (Agent-00): 이전 사이클 Recall 피드백 반영')
    args = parser.parse_args()

    import time as _time
    start = _time.time()

    # ── AI 적응형 생성 모드 (Agent-00) ─────────────────────────────────────
    if args.ai:
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from agents.layer0_generation.adaptive_packet_generator import AdaptivePacketGenerator

        if args.size == 0:
            if args.cycle <= 3:   total_size = 6000
            elif args.cycle <= 6: total_size = 8000
            elif args.cycle <= 9: total_size = 10000
            else:                 total_size = 12000
        else:
            total_size = args.size

        gen = AdaptivePacketGenerator()
        gen.generate(
            total_size=total_size,
            normal_ratio=0.65,
            cycle=args.cycle,
            output_dir='data/packets',
            mode=args.mode,
        )
        return

    # ── 기존 고정 분포 생성 모드 (하위호환) ────────────────────────────────
    # 사이클 기준 크기 (이전 대비 ~35% 증가 — 데이터 증량 학습)
    if args.size == 0:
        if args.mode == 'test':
            total_size = 1200   # 테스트는 작게 (학습과 독립)
        elif args.cycle <= 3:   total_size = 8000
        elif args.cycle <= 6:   total_size = 12000
        elif args.cycle <= 9:   total_size = 15000
        else:                   total_size = 18000
    else:
        total_size = args.size

    n_normal = int(total_size * 0.65)
    n_attack_total = total_size - n_normal

    # 정상 트래픽 (5종 균등 분배)
    normal_dfs = []
    n_per_normal = n_normal // len(NORMAL_GENERATORS)
    for g in NORMAL_GENERATORS:
        normal_dfs.append(g(n_per_normal))

    # 비정상 트래픽 (11종 가중 분배 — 탐지 어려운 유형 2x 증량)
    # dns_tunneling, slowloris: packet_size 외 특징이 정상과 겹쳐 더 많은 학습 샘플 필요
    ATTACK_WEIGHTS = {atype: 1 for atype in ATTACK_GENERATORS}
    ATTACK_WEIGHTS['dns_tunneling'] = 2
    ATTACK_WEIGHTS['slowloris'] = 2
    total_weight = sum(ATTACK_WEIGHTS.values())

    attack_dfs = []
    counts = {}
    allocated = 0
    atypes = list(ATTACK_GENERATORS.keys())
    for i, atype in enumerate(atypes):
        if i < len(atypes) - 1:
            n = max(1, round(n_attack_total * ATTACK_WEIGHTS[atype] / total_weight))
        else:
            n = max(1, n_attack_total - allocated)
        attack_dfs.append(ATTACK_GENERATORS[atype](n))
        counts[atype] = n
        allocated += n

    df_normal = pd.concat(normal_dfs, ignore_index=True)
    df_attack = pd.concat(attack_dfs, ignore_index=True)

    # ── 테스트 모드: 현실적 변환 적용 ─────────────────────────────────────
    if args.mode == 'test':
        # ① 공격 30% → 경계선 저강도 변종
        df_attack = _make_borderline_attacks(df_attack, frac=0.30)
        # ② 정상 15% → 고부하 정상 (FP 유발 가능성)
        df_normal = _make_heavy_normals(df_normal, frac=0.15)
        # ③ 전체 가우시안 노이즈 σ=15%
        df_attack = _add_noise(df_attack, noise_frac=0.15)
        df_normal = _add_noise(df_normal, noise_frac=0.10)
        # ④ 라벨 노이즈 2% (현실 라벨링 오류 재현)
        df_all_tmp = pd.concat([df_normal, df_attack], ignore_index=True)
        flip_idx = df_all_tmp.sample(frac=0.02, random_state=None).index
        df_all_tmp.loc[flip_idx, 'label'] = 1 - df_all_tmp.loc[flip_idx, 'label']
        df = df_all_tmp.sample(frac=1, random_state=None).reset_index(drop=True)
    else:
        # ── 훈련 모드: 경계 사례 20% 포함 — 모델이 저강도 변종도 학습 ──
        df_attack = _make_borderline_attacks(df_attack, frac=0.20)
        df_normal = _make_heavy_normals(df_normal, frac=0.12)
        df_attack = _add_noise(df_attack, noise_frac=0.10)
        df_normal = _add_noise(df_normal, noise_frac=0.08)
        df = pd.concat([df_normal, df_attack], ignore_index=True)
        df = df.sample(frac=1, random_state=None).reset_index(drop=True)

    os.makedirs('data/packets', exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    if args.mode == 'test':
        out = f'data/packets/test_{ts}.csv'
    else:
        out = f'data/packets/train_cycle{args.cycle}_{ts}.csv'
    df.to_csv(out, index=False)

    elapsed = _time.time() - start
    actual_normal = int((df['label'] == 0).sum())
    actual_attack = int((df['label'] == 1).sum())

    print(f"[패킷생성기 v2] {'현실적 테스트 데이터' if args.mode == 'test' else '학습 데이터'} 생성 완료")
    print(f"  파일: {out}")
    print(f"  총 건수: {len(df):,}건")
    print(f"  정상 트래픽: {actual_normal:,}건 ({actual_normal/len(df)*100:.0f}%)")
    if args.mode == 'test':
        print(f"    ※ 고부하 정상 15% 포함 (FP 유발 가능)")
    else:
        print(f"    - 웹브라우징 / DNS조회 / 파일전송 / 영상스트리밍 / 이메일")
    print(f"  비정상 트래픽: {actual_attack:,}건 ({actual_attack/len(df)*100:.0f}%)")
    if args.mode == 'test':
        print(f"    ※ 경계선 저강도 변종 30% 포함 + 노이즈 + 라벨노이즈 2%")
    else:
        for atype, cnt in counts.items():
            print(f"    - {ATTACK_LABELS_KO[atype]}: {cnt}건")
    print(f"  소요시간: {elapsed:.1f}s")
    print(f"OUTPUT_FILE:{out}")


if __name__ == '__main__':
    main()
