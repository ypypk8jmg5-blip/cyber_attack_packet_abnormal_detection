#!/usr/bin/env python3
"""
CIC-IDS2018 파이프라인 검증기
─────────────────────────────────────────────────────────────────────────────
실제 CIC-IDS2018 데이터 없이 전처리 로직과 벤치마크를 검증.
CIC-IDS2018과 동일한 컬럼 구조의 더미 CSV를 생성해 전처리 → 벤치마크 전체 흐름 테스트.
논문 실험 전 파이프라인 오류를 사전에 잡기 위한 용도.
"""

import os
import sys
import subprocess
import tempfile

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# CIC-IDS2018 CICFlowMeter 컬럼 (실제 데이터셋 헤더와 동일)
CICIDS_COLUMNS = [
    'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration',
    'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
    'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
    'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std',
    'Flow Byts/s', 'Flow Pkts/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Len', 'Bwd Header Len',
    'Fwd Pkts/s', 'Bwd Pkts/s',
    'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt',
    'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt',
    'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg',
    'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg',
    'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg',
    'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
    'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
    'Src IP', 'Src Port', 'Dst IP',
    'Label',
]

LABEL_DISTRIBUTION = {
    'Benign': 600,
    'Bot': 50,
    'Brute Force -Web': 40,
    'FTP-BruteForce': 30,
    'SSH-Bruteforce': 30,
    'DDOS attack-HOIC': 60,
    'DDoS attacks-LOIC-HTTP': 50,
    'DoS attacks-GoldenEye': 40,
    'DoS attacks-Hulk': 40,
    'DoS attacks-Slowloris': 30,
    'DoS attacks-SlowHTTPTest': 30,
    'Infilteration': 25,
}


def make_dummy_cicids(n_per_label: dict, seed: int = 42) -> pd.DataFrame:
    """CIC-IDS2018과 동일한 스키마의 더미 데이터 생성"""
    rng = np.random.default_rng(seed)
    rows = []

    for label, n in n_per_label.items():
        is_attack = (label != 'Benign')
        for _ in range(n):
            fwd = rng.integers(1, 500)
            bwd = rng.integers(0, 300)
            total = max(fwd + bwd, 1)
            pkt_size = rng.uniform(40, 1500)
            duration_us = rng.uniform(1000, 60_000_000)
            flow_pkts_s = total / max(duration_us / 1e6, 1e-6)
            flow_byts_s = pkt_size * flow_pkts_s

            row = {col: 0 for col in CICIDS_COLUMNS}
            row.update({
                'Src IP':         f"192.168.{rng.integers(1,5)}.{rng.integers(1,254)}",
                'Dst IP':         f"10.0.0.{rng.integers(1,10)}",
                'Src Port':       int(rng.integers(1024, 65535)),
                'Dst Port':       int(rng.choice([80, 443, 22, 53, 3389, 8080, 445])),
                'Protocol':       int(rng.choice([6, 17, 1])),
                'Timestamp':      '2018-02-14 09:00:00',
                'Flow Duration':  float(duration_us),
                'Tot Fwd Pkts':   int(fwd),
                'Tot Bwd Pkts':   int(bwd),
                'TotLen Fwd Pkts': float(fwd * pkt_size),
                'TotLen Bwd Pkts': float(bwd * pkt_size * 0.5),
                'Pkt Size Avg':   float(pkt_size),
                'Pkt Len Mean':   float(pkt_size),
                'Flow Pkts/s':    float(flow_pkts_s),
                'Flow Byts/s':    float(flow_byts_s),
                'SYN Flag Cnt':   int(rng.integers(0, 5)) if is_attack else int(rng.integers(0, 2)),
                'RST Flag Cnt':   int(rng.integers(0, 20)) if is_attack else int(rng.integers(0, 2)),
                'FIN Flag Cnt':   int(rng.integers(0, 3)),
                'ACK Flag Cnt':   int(rng.integers(0, 10)),
                'Label':          label,
            })
            rows.append(row)

    df = pd.DataFrame(rows, columns=CICIDS_COLUMNS)
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)


def run_test():
    print("=" * 60)
    print("CIC-IDS2018 파이프라인 검증 (더미 데이터)")
    print("=" * 60)

    # 1. 더미 CSV 생성
    with tempfile.TemporaryDirectory() as tmpdir:
        raw_dir  = os.path.join(tmpdir, 'raw')
        proc_dir = os.path.join(tmpdir, 'processed')
        os.makedirs(raw_dir)
        os.makedirs(proc_dir)

        dummy_path = os.path.join(raw_dir, 'Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv')
        df_dummy = make_dummy_cicids(LABEL_DISTRIBUTION)
        df_dummy.to_csv(dummy_path, index=False)
        print(f"\n[1] 더미 CSV 생성: {len(df_dummy)}행")

        # 2. 전처리 실행
        print("\n[2] preprocess_cicids2018.py 실행...")
        res = subprocess.run(
            [sys.executable, 'scripts/preprocess_cicids2018.py',
             '--raw-dir', raw_dir, '--out-dir', proc_dir,
             '--sample', '200'],
            capture_output=True, text=True, cwd=os.getcwd()
        )
        if res.returncode != 0:
            print("  [FAIL] 전처리 오류:")
            print(res.stderr[-2000:])
            return False
        print("  [OK] 전처리 완료")

        # 3. 출력 파일 검증
        train_path = os.path.join(proc_dir, 'cicids2018_train_latest.csv')
        test_path  = os.path.join(proc_dir, 'cicids2018_test_latest.csv')
        assert os.path.exists(train_path), "학습 CSV 미생성"
        assert os.path.exists(test_path),  "테스트 CSV 미생성"

        train_df = pd.read_csv(train_path)
        test_df  = pd.read_csv(test_path)

        FEATURE_COLS = [
            'duration', 'protocol', 'src_port', 'dst_port', 'packet_size',
            'packets_per_sec', 'bytes_per_sec', 'unique_dst_ports',
            'connection_count', 'failed_attempts', 'outbound_ratio', 'syn_flag_ratio'
        ]
        print(f"\n[3] 컬럼 검증")
        for col in FEATURE_COLS + ['label', 'attack_type']:
            assert col in train_df.columns, f"컬럼 누락: {col}"
        print(f"  [OK] 12 피처 + label + attack_type 모두 존재")
        print(f"  학습: {len(train_df)}행  |  테스트: {len(test_df)}행")
        print(f"  레이블 분포: {train_df['label'].value_counts().to_dict()}")
        print(f"  공격 유형: {sorted(train_df[train_df['label']==1]['attack_type'].unique())}")

        # 4. NaN/Inf 검증
        assert not train_df[FEATURE_COLS].isnull().any().any(), "NaN 존재"
        assert not np.isinf(train_df[FEATURE_COLS].values).any(), "Inf 존재"
        print(f"  [OK] NaN/Inf 없음")

        # 5. 벤치마크 실행
        print("\n[4] benchmark_cicids2018.py 실행 (--skip-a)...")
        res2 = subprocess.run(
            [sys.executable, 'scripts/benchmark_cicids2018.py',
             '--train', train_path, '--test', test_path,
             '--skip-a'],
            capture_output=True, text=True, cwd=os.getcwd()
        )
        if res2.returncode != 0:
            print("  [FAIL] 벤치마크 오류:")
            print(res2.stderr[-2000:])
            return False

        # 결과 검증
        for line in res2.stdout.splitlines():
            if 'AdaptiveNIDS' in line or 'F1' in line or '완료' in line:
                print(f"  {line}")

        print("\n[OK] 전체 파이프라인 검증 완료")
        return True


if __name__ == '__main__':
    ok = run_test()
    sys.exit(0 if ok else 1)
