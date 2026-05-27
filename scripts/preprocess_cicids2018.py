#!/usr/bin/env python3
"""
CIC-IDS2018 전처리기
─────────────────────────────────────────────────────────────────────────────
데이터 출처:
  https://www.unb.ca/cic/datasets/ids-2018.html
  AWS S3: s3://cic-ids2018/  (공개)
  또는 Kaggle: https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv

다운로드 후 data/cicids2018/raw/ 에 CSV 파일 배치:
  data/cicids2018/raw/
    ├── Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv
    ├── Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv
    ├── Friday-16-02-2018_TrafficForML_CICFlowMeter.csv
    ├── Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv
    ├── Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv
    ├── Friday-23-02-2018_TrafficForML_CICFlowMeter.csv
    └── ...

피처 매핑 (CIC-IDS2018 → 자체 12 피처):
  duration         ← Flow Duration (μs → s)
  protocol         ← Protocol (IANA: 6→0/TCP, 17→1/UDP, else→2)
  src_port         ← Src Port
  dst_port         ← Dst Port
  packet_size      ← Pkt Size Avg (bytes)
  packets_per_sec  ← Flow Pkts/s
  bytes_per_sec    ← Flow Byts/s
  unique_dst_ports ← Src IP별 고유 Dst Port 수 (윈도우 집계)
  connection_count ← Src IP별 총 플로우 수 (윈도우 집계)
  failed_attempts  ← RST Flag Cnt (연결 거부/실패 지표)
  outbound_ratio   ← Tot Fwd Pkts / (Tot Fwd Pkts + Tot Bwd Pkts)
  syn_flag_ratio   ← SYN Flag Cnt / (Tot Fwd Pkts + Tot Bwd Pkts)

레이블 매핑 (CIC-IDS2018 → 자체 공격 유형):
  Benign                → label=0, attack_type='normal'
  Bot                   → botnet_c2
  Brute Force -Web      → bruteforce
  Brute Force -XSS      → bruteforce
  FTP-BruteForce        → bruteforce
  SSH-Bruteforce        → bruteforce
  SQL Injection         → bruteforce
  DDOS attack-HOIC      → ddos
  DDOS attack-LOIC-UDP  → ddos
  DDoS attacks-LOIC-HTTP→ ddos
  DoS attacks-GoldenEye → http_flood
  DoS attacks-Hulk      → http_flood
  DoS attacks-SlowHTTPTest → slowloris
  DoS attacks-Slowloris → slowloris
  Infilteration         → exfiltration  (데이터셋 오타 포함)
  Infiltration          → exfiltration
"""

import argparse
import glob
import os
import sys
import warnings
from datetime import datetime

import numpy as np
import pandas as pd

warnings.filterwarnings('ignore')

# ── 경로 설정 ──────────────────────────────────────────────────────────────
RAW_DIR       = 'data/cicids2018/raw'
PROCESSED_DIR = 'data/cicids2018/processed'

# ── 우리 모델의 피처 컬럼 ───────────────────────────────────────────────────
FEATURE_COLS = [
    'duration', 'protocol', 'src_port', 'dst_port', 'packet_size',
    'packets_per_sec', 'bytes_per_sec', 'unique_dst_ports',
    'connection_count', 'failed_attempts', 'outbound_ratio', 'syn_flag_ratio'
]

# ── CIC-IDS2018 컬럼명 정규화 매핑 ─────────────────────────────────────────
# CICFlowMeter 출력 컬럼명은 공백과 대소문자가 불규칙함 → 소문자+공백→언더스코어 정규화
CIC_COL_MAP = {
    'flow duration':            'flow_duration',
    'protocol':                 'protocol',
    'src port':                 'src_port',
    'dst port':                 'dst_port',
    'pkt size avg':             'pkt_size_avg',
    'flow pkts/s':              'flow_pkts_s',
    'flow byts/s':              'flow_byts_s',
    'tot fwd pkts':             'tot_fwd_pkts',
    'tot bwd pkts':             'tot_bwd_pkts',
    'rst flag cnt':             'rst_flag_cnt',
    'syn flag cnt':             'syn_flag_cnt',
    'src ip':                   'src_ip',
    'dst ip':                   'dst_ip',
    'timestamp':                'timestamp',
    'label':                    'label_raw',
}

# ── 레이블 매핑 ────────────────────────────────────────────────────────────
LABEL_MAP = {
    # 정상
    'benign':                       ('normal',    0),
    # DDoS / 대량 트래픽
    'ddos attack-hoic':             ('ddos',      1),
    'ddos attack-loic-udp':         ('ddos',      1),
    'ddos attacks-loic-http':       ('ddos',      1),
    'ddos attack-loic-http':        ('ddos',      1),
    # DoS
    'dos attacks-goldeneye':        ('http_flood', 1),
    'dos attacks-hulk':             ('http_flood', 1),
    'dos attacks-slowhttptest':     ('slowloris',  1),
    'dos attacks-slowloris':        ('slowloris',  1),
    # 봇넷
    'bot':                          ('botnet_c2',  1),
    # 브루트포스
    'brute force -web':             ('bruteforce', 1),
    'brute force -xss':             ('bruteforce', 1),
    'ftp-bruteforce':               ('bruteforce', 1),
    'ssh-bruteforce':               ('bruteforce', 1),
    'sql injection':                ('bruteforce', 1),
    # 침투/데이터유출
    'infilteration':                ('exfiltration', 1),  # 데이터셋 오타
    'infiltration':                 ('exfiltration', 1),
}

# 매핑 안 된 레이블 → unknown 공격
UNKNOWN_ATTACK = ('unknown', 1)


# ── 유틸 함수 ──────────────────────────────────────────────────────────────

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """컬럼명을 소문자 + 공백→언더스코어로 정규화 후 필요 컬럼만 rename"""
    df.columns = [c.strip().lower() for c in df.columns]
    rename = {}
    for orig, target in CIC_COL_MAP.items():
        if orig in df.columns:
            rename[orig] = target
    df = df.rename(columns=rename)
    return df


def map_protocol(proto_series: pd.Series) -> pd.Series:
    """IANA 프로토콜 번호 → 자체 인코딩 (0=TCP, 1=UDP, 2=기타)"""
    return proto_series.map({6: 0, 17: 1}).fillna(2).astype(int)


def map_labels(label_series: pd.Series) -> pd.DataFrame:
    """레이블 문자열 → (attack_type, label) 컬럼"""
    normalized = label_series.str.strip().str.lower()
    attack_types = normalized.map(lambda x: LABEL_MAP.get(x, UNKNOWN_ATTACK)[0])
    labels       = normalized.map(lambda x: LABEL_MAP.get(x, UNKNOWN_ATTACK)[1])
    return pd.DataFrame({'attack_type': attack_types, 'label': labels})


def aggregate_src_ip_features(df: pd.DataFrame, fwd: pd.Series, bwd: pd.Series) -> pd.DataFrame:
    """
    Src IP 기준 윈도우 집계:
      unique_dst_ports  ← Src IP별 고유 Dst Port 수
      connection_count  ← Src IP별 총 플로우 수
    Kaggle 버전(src_ip 없음): connection_count = Tot Fwd Pkts + Tot Bwd Pkts 로 대체.
    """
    if 'src_ip' not in df.columns:
        df['unique_dst_ports'] = 1
        df['connection_count'] = (fwd + bwd).clip(lower=1).astype(int)
        return df

    agg = df.groupby('src_ip').agg(
        unique_dst_ports=('dst_port', 'nunique'),
        connection_count=('dst_port', 'count'),
    ).reset_index()
    df = df.merge(agg, on='src_ip', how='left')
    return df


def clean_numeric(df: pd.DataFrame, cols: list) -> pd.DataFrame:
    """Inf/NaN 제거 및 클리핑"""
    for col in cols:
        if col not in df.columns:
            df[col] = 0.0
            continue
        df[col] = pd.to_numeric(df[col], errors='coerce')
        df[col] = df[col].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=cols)
    # 비정상 값 클리핑
    df['packets_per_sec']  = df['packets_per_sec'].clip(0, 1e6)
    df['bytes_per_sec']    = df['bytes_per_sec'].clip(0, 1e9)
    df['duration']         = df['duration'].clip(0, 1e6)
    df['packet_size']      = df['packet_size'].clip(0, 65535)
    df['outbound_ratio']   = df['outbound_ratio'].clip(0.0, 1.0)
    df['syn_flag_ratio']   = df['syn_flag_ratio'].clip(0.0, 1.0)
    df['failed_attempts']  = df['failed_attempts'].clip(0, 10000).astype(int)
    df['unique_dst_ports'] = df['unique_dst_ports'].clip(1, 65535).astype(int)
    df['connection_count'] = df['connection_count'].clip(1, 100000).astype(int)
    return df


def process_file(fpath: str) -> pd.DataFrame | None:
    """단일 CIC-IDS2018 CSV 파일 처리"""
    print(f"  로드: {os.path.basename(fpath)}", end='', flush=True)
    try:
        df = pd.read_csv(fpath, encoding='utf-8', low_memory=False)
    except UnicodeDecodeError:
        df = pd.read_csv(fpath, encoding='latin-1', low_memory=False)

    print(f" ({len(df):,}행)", flush=True)
    df = normalize_columns(df)

    # 필수 컬럼 존재 확인 (src_port는 Kaggle 버전에 없으므로 제외)
    required = ['flow_duration', 'protocol', 'dst_port', 'label_raw']
    missing = [c for c in required if c not in df.columns]
    if missing:
        print(f"  [SKIP] 필수 컬럼 없음: {missing}")
        return None

    # 피처 파생
    df['flow_duration']   = pd.to_numeric(df['flow_duration'], errors='coerce')
    df['duration']        = df['flow_duration'] / 1e6       # μs → s
    df['protocol']        = map_protocol(df['protocol'])
    # src_port: Kaggle 버전에 없음 → 0으로 채움
    if 'src_port' in df.columns:
        df['src_port'] = pd.to_numeric(df['src_port'], errors='coerce').fillna(0).astype(int)
    else:
        df['src_port'] = 0
    df['dst_port']        = pd.to_numeric(df['dst_port'],  errors='coerce').fillna(0).astype(int)
    df['packet_size']     = pd.to_numeric(df.get('pkt_size_avg', 0), errors='coerce').fillna(0)
    df['packets_per_sec'] = pd.to_numeric(df.get('flow_pkts_s',  0), errors='coerce').fillna(0)
    df['bytes_per_sec']   = pd.to_numeric(df.get('flow_byts_s',  0), errors='coerce').fillna(0)
    df['failed_attempts'] = pd.to_numeric(df.get('rst_flag_cnt', 0), errors='coerce').fillna(0)

    # outbound_ratio: 순방향 패킷 / 전체 패킷
    fwd = pd.to_numeric(df.get('tot_fwd_pkts', 1), errors='coerce').fillna(1).clip(lower=0)
    bwd = pd.to_numeric(df.get('tot_bwd_pkts', 0), errors='coerce').fillna(0).clip(lower=0)
    total_pkts = fwd + bwd
    total_pkts = total_pkts.replace(0, 1)
    df['outbound_ratio'] = (fwd / total_pkts).clip(0.0, 1.0)

    # syn_flag_ratio: SYN 플래그 수 / 전체 패킷
    syn = pd.to_numeric(df.get('syn_flag_cnt', 0), errors='coerce').fillna(0).clip(lower=0)
    df['syn_flag_ratio'] = (syn / total_pkts).clip(0.0, 1.0)

    # Src IP 기준 집계 피처 (fwd/bwd는 connection_count 프록시로 사용)
    df = aggregate_src_ip_features(df, fwd, bwd)

    # 숫자 클리닝
    df = clean_numeric(df, FEATURE_COLS)

    # 레이블 매핑
    label_df = map_labels(df['label_raw'])
    df['label']       = label_df['label'].values
    df['attack_type'] = label_df['attack_type'].values

    # 최종 컬럼 선택
    out_cols = FEATURE_COLS + ['label', 'attack_type']
    # src_ip 컬럼이 있으면 같이 저장 (탐지기에서 활용)
    if 'src_ip' in df.columns:
        out_cols = out_cols + ['src_ip']
    df = df[out_cols].reset_index(drop=True)
    return df


def summarize(df: pd.DataFrame):
    """전처리 결과 요약 출력"""
    n_total   = len(df)
    n_normal  = (df['label'] == 0).sum()
    n_attack  = (df['label'] == 1).sum()
    print(f"\n  총 샘플: {n_total:,}  (정상: {n_normal:,} | 공격: {n_attack:,})")
    print("  공격 유형별 샘플 수:")
    counts = df[df['label'] == 1]['attack_type'].value_counts()
    for atype, cnt in counts.items():
        print(f"    {atype:<25s}: {cnt:>8,}")
    unmapped = (df['attack_type'] == 'unknown').sum()
    if unmapped:
        print(f"  [주의] 매핑 안 된 공격: {unmapped:,}건")


def main():
    parser = argparse.ArgumentParser(description='CIC-IDS2018 전처리기')
    parser.add_argument('--raw-dir',    default=RAW_DIR,       help='원본 CSV 디렉토리')
    parser.add_argument('--out-dir',    default=PROCESSED_DIR, help='출력 디렉토리')
    parser.add_argument('--sample',     type=int, default=0,
                        help='클래스별 최대 샘플 수 (0=전체, 논문 실험용 균형 샘플링)')
    parser.add_argument('--split',      type=float, default=0.2, help='테스트셋 비율')
    parser.add_argument('--files',      nargs='*', help='처리할 파일명 (기본: raw-dir 전체)')
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # 파일 목록
    if args.files:
        fpaths = [os.path.join(args.raw_dir, f) for f in args.files]
    else:
        fpaths = sorted(glob.glob(os.path.join(args.raw_dir, '*.csv')))

    if not fpaths:
        print(f"[ERROR] {args.raw_dir} 에 CSV 파일이 없습니다.")
        print()
        print("=== 데이터 다운로드 방법 ===")
        print("1. AWS CLI (권장):")
        print("   aws s3 sync --no-sign-request s3://cic-ids2018/ data/cicids2018/raw/")
        print()
        print("2. 직접 다운로드:")
        print("   https://www.unb.ca/cic/datasets/ids-2018.html")
        print()
        print("3. Kaggle (소용량 subset):")
        print("   https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv")
        sys.exit(1)

    print(f"[전처리기] CIC-IDS2018 처리 시작 — {len(fpaths)}개 파일")
    print(f"  raw_dir : {args.raw_dir}")
    print(f"  out_dir : {args.out_dir}")
    print(f"  샘플링  : {'전체' if args.sample == 0 else f'클래스별 최대 {args.sample:,}건'}")
    if args.sample == 0:
        total_size = sum(os.path.getsize(f) for f in fpaths if os.path.exists(f))
        if total_size > 2 * 1024**3:
            print(f"  [경고] 전체 데이터 크기 {total_size/1024**3:.1f}GB — 메모리 부족 시 --sample 50000 권장")
    print()

    all_dfs = []
    for fp in fpaths:
        df = process_file(fp)
        if df is not None:
            all_dfs.append(df)

    if not all_dfs:
        print("[ERROR] 처리된 파일 없음")
        sys.exit(1)

    combined = pd.concat(all_dfs, ignore_index=True)
    print(f"\n[전처리기] 전체 병합 완료: {len(combined):,}행")
    summarize(combined)

    # 클래스 균형 샘플링 (선택)
    if args.sample > 0:
        print(f"\n[전처리기] 균형 샘플링 (클래스별 최대 {args.sample:,}건)...")
        parts = []
        # 정상 트래픽
        normal = combined[combined['label'] == 0]
        parts.append(normal.sample(min(len(normal), args.sample), random_state=42))
        # 공격 유형별
        for atype in combined[combined['label'] == 1]['attack_type'].unique():
            sub = combined[combined['attack_type'] == atype]
            parts.append(sub.sample(min(len(sub), args.sample), random_state=42))
        combined = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=42)
        print(f"  샘플링 후: {len(combined):,}행")
        summarize(combined)

    # 학습/테스트 분할
    from sklearn.model_selection import train_test_split
    train_df, test_df = train_test_split(
        combined, test_size=args.split, random_state=42, stratify=combined['label']
    )
    print(f"\n[전처리기] 학습/테스트 분할")
    print(f"  학습: {len(train_df):,}행  |  테스트: {len(test_df):,}행")

    # 저장
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    train_path = os.path.join(args.out_dir, f'cicids2018_train_{ts}.csv')
    test_path  = os.path.join(args.out_dir, f'cicids2018_test_{ts}.csv')
    # 최신 파일 심볼릭 링크용 고정 경로도 저장
    train_latest = os.path.join(args.out_dir, 'cicids2018_train_latest.csv')
    test_latest  = os.path.join(args.out_dir, 'cicids2018_test_latest.csv')

    train_df.to_csv(train_path,  index=False)
    test_df.to_csv(test_path,    index=False)
    train_df.to_csv(train_latest, index=False)
    test_df.to_csv(test_latest,   index=False)

    print(f"\n[전처리기] 저장 완료")
    print(f"  학습 데이터: {train_path}")
    print(f"  테스트 데이터: {test_path}")
    print(f"  최신 링크: {train_latest}, {test_latest}")
    print(f"\nOUTPUT_TRAIN:{train_path}")
    print(f"OUTPUT_TEST:{test_path}")


if __name__ == '__main__':
    main()
