#!/usr/bin/env python3
"""
Continual Learning 비교 — 리뷰어 지적 #4 (Chou et al. [9]와의 실험적 비교)
─────────────────────────────────────────────────────────────────────────────
class-incremental 시나리오에서 두 적응 전략을 동일 백본(SGD)으로 비교:
  (A) Continual (Chou-style): 새 단계 데이터로만 partial_fit (데이터 미보존)
  (B) Periodic full-retrain (AdaptiveNIDS): 누적 데이터 전체로 매 단계 재학습

백본을 SGD로 통일해 '전략' 효과만 격리. 참고로 AdaptiveNIDS 실제 배포
구성인 RF full-retrain 수치도 함께 보고.

3단계로 공격 유형이 점진적으로 등장:
  Stage 1: ddos, portscan, bruteforce, synflood, exfiltration
  Stage 2: + dns_tunneling, http_flood, slowloris, botnet_c2
  Stage 3: + ransomware, arp_spoofing, cryptomining, dns_amplification,
             credential_stuffing
정상 트래픽은 모든 단계에 포함.

핵심 측정: 최종 단계에서 Stage-1(초기) 공격 recall = catastrophic forgetting 척도.

사용법:
  python3 scripts/continual_comparison.py
"""

import argparse
import json
import os
import sys
import warnings
from datetime import datetime

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from generate_packets import ATTACK_GENERATORS, NORMAL_GENERATORS  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.linear_model import SGDClassifier  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402
from sklearn.metrics import f1_score, recall_score  # noqa: E402

warnings.filterwarnings('ignore')

FEATURE_COLS = [
    'duration', 'protocol', 'src_port', 'dst_port', 'packet_size',
    'packets_per_sec', 'bytes_per_sec', 'unique_dst_ports',
    'connection_count', 'failed_attempts', 'outbound_ratio', 'syn_flag_ratio'
]
BENCHMARK_DIR = 'data/benchmark'

STAGES = [
    ['ddos', 'portscan', 'bruteforce', 'synflood', 'exfiltration'],
    ['dns_tunneling', 'http_flood', 'slowloris', 'botnet_c2'],
    ['ransomware', 'arp_spoofing', 'cryptomining', 'dns_amplification',
     'credential_stuffing'],
]


def gen_normal(n, seed):
    np.random.seed(seed)
    per = max(1, n // len(NORMAL_GENERATORS))
    return pd.concat([g(per) for g in NORMAL_GENERATORS], ignore_index=True)


def gen_attacks(types, n_per, seed):
    np.random.seed(seed)
    return pd.concat([ATTACK_GENERATORS[t](n_per) for t in types], ignore_index=True)


def stage_data(types, seed, n_per=400, n_normal=800):
    atk = gen_attacks(types, n_per, seed)
    nrm = gen_normal(n_normal, seed + 1)
    df = pd.concat([atk, nrm], ignore_index=True).sample(frac=1, random_state=seed)
    return df.reset_index(drop=True)


def build_testset(seed=99, n_per=300, n_normal=2000):
    all_types = [t for s in STAGES for t in s]
    atk = gen_attacks(all_types, n_per, seed)
    nrm = gen_normal(n_normal, seed + 1)
    df = pd.concat([atk, nrm], ignore_index=True).sample(frac=1, random_state=seed)
    return df.reset_index(drop=True)


def per_stage_recall(y_true, y_pred, attack_types):
    out = {}
    for si, types in enumerate(STAGES, 1):
        mask = np.isin(attack_types, types)
        out[f'stage{si}'] = (round(float(recall_score(y_true[mask], y_pred[mask],
                             zero_division=0)), 4) if mask.sum() else None)
    return out


def run(seeds):
    test_df = build_testset()
    scaler = StandardScaler()
    # 스케일러는 전체 피처 분포로 고정(공정 비교)
    full_types = [t for s in STAGES for t in s]
    fit_ref = pd.concat([gen_attacks(full_types, 100, 7), gen_normal(500, 8)],
                        ignore_index=True)
    scaler.fit(fit_ref[FEATURE_COLS].values)
    X_te = scaler.transform(test_df[FEATURE_COLS].values)
    y_te = test_df['label'].values
    at_te = test_df['attack_type'].values

    agg = {'continual': [], 'full_sgd': [], 'full_rf': []}
    for seed in seeds:
        # 누적 데이터(full-retrain 용)
        accumulated = []
        # 단계별 데이터
        stage_dfs = [stage_data(STAGES[i], seed + 10 * i) for i in range(len(STAGES))]

        # (A) Continual SGD: 새 단계로만 partial_fit
        sgd_c = SGDClassifier(loss='log_loss', random_state=seed)
        for i, sdf in enumerate(stage_dfs):
            Xs = scaler.transform(sdf[FEATURE_COLS].values)
            ys = sdf['label'].values
            if i == 0:
                sgd_c.partial_fit(Xs, ys, classes=np.array([0, 1]))
            else:
                sgd_c.partial_fit(Xs, ys)
        yc = sgd_c.predict(X_te)

        # (B) Full-retrain SGD: 누적 전체로 재학습
        all_df = pd.concat(stage_dfs, ignore_index=True)
        Xa = scaler.transform(all_df[FEATURE_COLS].values)
        sgd_f = SGDClassifier(loss='log_loss', random_state=seed)
        sgd_f.fit(Xa, all_df['label'].values)
        yf = sgd_f.predict(X_te)

        # (C) Full-retrain RF (AdaptiveNIDS 실제 구성)
        rf = RandomForestClassifier(n_estimators=150, max_depth=15,
             min_samples_split=5, class_weight='balanced',
             random_state=seed, n_jobs=-1).fit(Xa, all_df['label'].values)
        yr = rf.predict(X_te)

        for key, yp in [('continual', yc), ('full_sgd', yf), ('full_rf', yr)]:
            agg[key].append({
                'f1': f1_score(y_te, yp, zero_division=0),
                'recall': recall_score(y_te, yp, zero_division=0),
                **per_stage_recall(y_te, yp, at_te),
            })
    return agg


def summarize(agg):
    out = {}
    for key, runs in agg.items():
        keys = runs[0].keys()
        out[key] = {}
        for k in keys:
            vals = [r[k] for r in runs if r[k] is not None]
            arr = np.array(vals)
            out[key][k] = round(float(arr.mean()), 4)
            out[key][k + '_std'] = round(float(arr.std(ddof=1)) if len(arr) > 1 else 0.0, 4)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--seeds', type=int, nargs='+', default=[42, 43, 44])
    args = ap.parse_args()
    os.makedirs(BENCHMARK_DIR, exist_ok=True)

    print("[Continual 비교] class-incremental, 3 stages, "
          f"seeds={args.seeds}\n")
    agg = run(args.seeds)
    s = summarize(agg)

    labels = {'continual': 'Continual (partial_fit, SGD)',
              'full_sgd': 'Full-retrain (SGD)',
              'full_rf': 'Full-retrain RF (AdaptiveNIDS)'}
    print(f"{'Strategy':<32} {'F1':>8} {'Recall':>8} "
          f"{'St1 Rec':>9} {'St2 Rec':>9} {'St3 Rec':>9}")
    print("-" * 80)
    for key in ['continual', 'full_sgd', 'full_rf']:
        d = s[key]
        print(f"{labels[key]:<32} {d['f1']:>8.4f} {d['recall']:>8.4f} "
              f"{d['stage1']:>9.4f} {d['stage2']:>9.4f} {d['stage3']:>9.4f}")
    print("-" * 80)
    fc = s['continual']['stage1']; ff = s['full_rf']['stage1']
    print(f"\nStage-1(초기) 공격 recall: Continual={fc:.4f} vs Full-RF={ff:.4f}  "
          f"→ forgetting gap = {ff - fc:+.4f}")

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out = {'timestamp': ts, 'config': {'seeds': args.seeds, 'stages': STAGES},
           'summary': s}
    path = os.path.join(BENCHMARK_DIR, f'continual_comparison_{ts}.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\n[완료] {path}\nOUTPUT_RESULT:{path}")


if __name__ == '__main__':
    main()
