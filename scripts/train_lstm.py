#!/usr/bin/env python3
"""
LSTM Autoencoder 학습기
- 비지도 학습: 정상 트래픽만으로 학습
- 학습 방법: 시계열 패킷 시퀀스 → 압축(Encoder) → 복원(Decoder)
- 탐지 원리: 정상 패턴은 잘 복원, 공격 패턴은 복원 오차(MSE) 큼
- 출력: data/models/lstm_autoencoder.pt + 임계값 자동 보정
"""
import argparse
import glob
import json
import os
import sys
import time

import numpy as np
import pandas as pd

# 에이전트 모듈에서 LSTMAutoencoder 클래스 import (pickle 직렬화 가능)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agents.layer2_analysis.deep_learning_agent import LSTMAutoencoder

FEATURE_COLS = [
    'duration', 'protocol', 'src_port', 'dst_port', 'packet_size',
    'packets_per_sec', 'bytes_per_sec', 'unique_dst_ports',
    'connection_count', 'failed_attempts', 'outbound_ratio', 'syn_flag_ratio'
]

SEQ_LEN    = 20     # 시퀀스 길이 (IP당 최근 N패킷)
HIDDEN_DIM = 32     # LSTM 은닉 차원
BATCH_SIZE = 64
EPOCHS     = 30
LR         = 1e-3
THRESHOLD_PERCENTILE = 95   # 정상 데이터 재구성 오차의 95백분위 → 임계값


# ── 모델 생성 ─────────────────────────────────────────────────────────────────
def build_model(n_features: int, hidden: int = HIDDEN_DIM):
    return LSTMAutoencoder(n_features=n_features, hidden=hidden)


# ── 데이터 준비 ───────────────────────────────────────────────────────────────
def load_normal_sequences(data_dir: str = 'data/packets', min_seq: int = 5) -> np.ndarray:
    """
    정상 패킷(label=0)만 로드하여 슬라이딩 윈도우 시퀀스로 변환.
    IP 정보가 없으면 글로벌 순서 기반 슬라이딩 윈도우 사용.
    """
    files = sorted(glob.glob(os.path.join(data_dir, 'train_cycle*.csv')))
    if not files:
        files = sorted(glob.glob(os.path.join(data_dir, '*.csv')))
    if not files:
        raise FileNotFoundError(f"패킷 파일 없음: {data_dir}")

    # 최근 3개 사이클 파일 사용
    files = files[-3:]
    df = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)

    # 정상 트래픽만 추출
    normal_df = df[df['label'] == 0][FEATURE_COLS].copy()
    print(f"  정상 패킷: {len(normal_df):,}건 (전체 {len(df):,}건 중)")

    # 피처 정규화 (MinMaxScaler: 0~1 범위)
    feat_min = normal_df.min()
    feat_max = normal_df.max()
    feat_range = (feat_max - feat_min).replace(0, 1)
    normal_norm = (normal_df - feat_min) / feat_range
    values = normal_norm.values.astype(np.float32)

    # 슬라이딩 윈도우로 시퀀스 생성
    sequences = []
    for i in range(len(values) - SEQ_LEN + 1):
        sequences.append(values[i:i + SEQ_LEN])

    seqs = np.array(sequences)
    print(f"  생성된 시퀀스: {len(seqs):,}개 (길이={SEQ_LEN}, 피처={len(FEATURE_COLS)})")

    # 정규화 파라미터 저장 (추론 시 동일 정규화 적용)
    norm_params = {
        'feat_min': feat_min.to_dict(),
        'feat_max': feat_max.to_dict(),
    }
    os.makedirs('data/models', exist_ok=True)
    with open('data/models/lstm_norm_params.json', 'w') as f:
        json.dump(norm_params, f, indent=2)

    return seqs, norm_params


def load_attack_sequences(data_dir: str = 'data/packets') -> np.ndarray:
    """임계값 검증용 공격 시퀀스 로드."""
    files = sorted(glob.glob(os.path.join(data_dir, 'train_cycle*.csv')))[-3:]
    if not files:
        return np.array([])
    df = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)
    attack_df = df[df['label'] == 1][FEATURE_COLS].copy()

    # 동일한 MinMax 정규화 (저장된 파라미터 사용)
    with open('data/models/lstm_norm_params.json') as f:
        norm_params = json.load(f)
    feat_min = pd.Series(norm_params['feat_min'])
    feat_max = pd.Series(norm_params['feat_max'])
    feat_range = (feat_max - feat_min).replace(0, 1)
    attack_norm = (attack_df - feat_min) / feat_range
    values = attack_norm.values.astype(np.float32)

    sequences = [values[i:i + SEQ_LEN] for i in range(len(values) - SEQ_LEN + 1)]
    return np.array(sequences) if sequences else np.array([])


# ── 학습 루프 ─────────────────────────────────────────────────────────────────
def train(model, sequences: np.ndarray, epochs: int, batch_size: int, lr: float):
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset

    dataset = TensorDataset(torch.tensor(sequences))
    loader  = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.MSELoss()

    best_loss = float('inf')
    history = []

    print(f"\n  {'Epoch':>5}  {'Train Loss':>12}  {'상태':>6}")
    print(f"  {'-'*40}")

    for epoch in range(1, epochs + 1):
        model.train()
        epoch_loss = 0.0
        for (batch,) in loader:
            optimizer.zero_grad()
            recon = model(batch)
            loss = criterion(recon, batch)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item() * len(batch)

        avg_loss = epoch_loss / len(sequences)
        history.append(avg_loss)

        if avg_loss < best_loss:
            best_loss = avg_loss
            status = "▼ best"
        else:
            status = ""

        if epoch % 5 == 0 or epoch == 1:
            bar = '█' * int((1 - min(avg_loss / 0.1, 1)) * 20)
            print(f"  {epoch:>5}  {avg_loss:>12.6f}  {status}")

    return history, best_loss


# ── 임계값 보정 ───────────────────────────────────────────────────────────────
def calibrate_threshold(model, normal_seqs: np.ndarray, attack_seqs: np.ndarray) -> float:
    import torch
    import torch.nn.functional as F

    model.eval()

    # 정상 패킷 재구성 오차 분포
    normal_mses = []
    with torch.no_grad():
        for i in range(0, min(len(normal_seqs), 2000), BATCH_SIZE):
            batch = torch.tensor(normal_seqs[i:i+BATCH_SIZE])
            recon = model(batch)
            mse = F.mse_loss(recon, batch, reduction='none').mean(dim=[1, 2])
            normal_mses.extend(mse.numpy().tolist())

    normal_mses = np.array(normal_mses)
    threshold = float(np.percentile(normal_mses, THRESHOLD_PERCENTILE))

    print(f"\n  [임계값 보정]")
    print(f"  정상 MSE — 평균: {normal_mses.mean():.6f}  std: {normal_mses.std():.6f}")
    print(f"  정상 MSE — P50: {np.percentile(normal_mses, 50):.6f}  P95: {np.percentile(normal_mses, 95):.6f}  P99: {np.percentile(normal_mses, 99):.6f}")
    print(f"  임계값 ({THRESHOLD_PERCENTILE}백분위): {threshold:.6f}")

    # 공격 패킷 탐지율 검증
    if len(attack_seqs) > 0:
        attack_mses = []
        with torch.no_grad():
            for i in range(0, min(len(attack_seqs), 2000), BATCH_SIZE):
                batch = torch.tensor(attack_seqs[i:i+BATCH_SIZE])
                recon = model(batch)
                mse = F.mse_loss(recon, batch, reduction='none').mean(dim=[1, 2])
                attack_mses.extend(mse.numpy().tolist())

        attack_mses = np.array(attack_mses)
        detection_rate = float((attack_mses > threshold).mean())
        fp_rate = float((normal_mses > threshold).mean())

        print(f"\n  [성능 검증]")
        print(f"  공격 MSE — 평균: {attack_mses.mean():.6f}  (정상 대비 {attack_mses.mean()/max(normal_mses.mean(),1e-9):.1f}배)")
        print(f"  탐지율 (TPR):  {detection_rate:.4f} ({detection_rate*100:.1f}%)")
        print(f"  오탐율 (FPR):  {fp_rate:.4f}  ({fp_rate*100:.1f}%)  ← {THRESHOLD_PERCENTILE}백분위 설정으로 최대 {100-THRESHOLD_PERCENTILE}% 허용")

    return threshold


# ── 메인 ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='LSTM Autoencoder 학습기')
    parser.add_argument('--data-dir',  default='data/packets', help='패킷 CSV 디렉터리')
    parser.add_argument('--epochs',    type=int,   default=EPOCHS,     help='학습 에폭')
    parser.add_argument('--batch-size',type=int,   default=BATCH_SIZE, help='배치 크기')
    parser.add_argument('--lr',        type=float, default=LR,         help='학습률')
    parser.add_argument('--hidden',    type=int,   default=HIDDEN_DIM, help='LSTM 은닉 차원')
    parser.add_argument('--output',    default='data/models/lstm_autoencoder.pt')
    args = parser.parse_args()

    try:
        import torch
    except ImportError:
        print("[ERROR] PyTorch 미설치: pip install torch")
        sys.exit(1)

    start = time.time()
    print("=" * 55)
    print(" LSTM Autoencoder 학습 시작")
    print(f" 입력: {args.data_dir}")
    print(f" 에폭: {args.epochs} | 배치: {args.batch_size} | LR: {args.lr}")
    print(f" 구조: 입력({len(FEATURE_COLS)}) → LSTM({args.hidden}) → 복원({len(FEATURE_COLS)})")
    print(f" 학습 방식: 비지도 (정상 패킷만 사용)")
    print("=" * 55)

    # 1. 데이터 로드
    print("\n[1/4] 데이터 로드 중...")
    normal_seqs, norm_params = load_normal_sequences(args.data_dir)
    attack_seqs = load_attack_sequences(args.data_dir)

    if len(normal_seqs) < 100:
        print(f"[ERROR] 정상 시퀀스 부족: {len(normal_seqs)}개 (최소 100개 필요)")
        print("  먼저 패킷 생성: python3 scripts/generate_packets.py --cycle 1")
        sys.exit(1)

    # train/val 분리 (80/20)
    n_val = max(int(len(normal_seqs) * 0.2), 50)
    idx = np.random.permutation(len(normal_seqs))
    train_seqs = normal_seqs[idx[n_val:]]
    val_seqs   = normal_seqs[idx[:n_val]]
    print(f"  학습: {len(train_seqs):,}개 / 검증: {len(val_seqs):,}개")

    # 2. 모델 빌드
    print(f"\n[2/4] 모델 구성 중...")
    model = build_model(len(FEATURE_COLS), args.hidden)
    n_params = sum(p.numel() for p in model.parameters())
    print(f"  파라미터 수: {n_params:,}개")
    print(f"  구조: Encoder LSTM({len(FEATURE_COLS)}→{args.hidden}) + Decoder LSTM({args.hidden}→{len(FEATURE_COLS)})")

    # 3. 학습
    print(f"\n[3/4] 학습 중... ({args.epochs} 에폭)")
    history, best_loss = train(model, train_seqs, args.epochs, args.batch_size, args.lr)

    # 4. 임계값 보정
    print(f"\n[4/4] 임계값 보정 중...")
    threshold = calibrate_threshold(model, val_seqs, attack_seqs)

    # 5. 저장
    import torch
    os.makedirs('data/models', exist_ok=True)
    torch.save(model, args.output)

    # 임계값을 별도 파일로도 저장 (Agent-07에서 로드용)
    threshold_path = 'data/models/lstm_threshold.json'
    with open(threshold_path, 'w') as f:
        json.dump({
            'threshold': threshold,
            'percentile': THRESHOLD_PERCENTILE,
            'best_train_loss': best_loss,
            'n_train_seqs': len(train_seqs),
            'seq_len': SEQ_LEN,
            'hidden_dim': args.hidden,
        }, f, indent=2)

    elapsed = time.time() - start
    m, s = divmod(int(elapsed), 60)

    print(f"\n{'='*55}")
    print(f" 학습 완료")
    print(f" 모델 저장: {args.output}")
    print(f" 임계값:    {threshold:.6f}  → {threshold_path}")
    print(f" 소요시간:  {m}m {s}s")
    print(f" 최종 손실: {best_loss:.6f}")
    print(f"{'='*55}")
    print(f"OUTPUT_MODEL:{args.output}")
    print(f"LSTM_THRESHOLD:{threshold:.6f}")


if __name__ == '__main__':
    main()
