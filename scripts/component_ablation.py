#!/usr/bin/env python3
"""
컴포넌트 기여도 분석 — 리뷰어 지적 #1(pre-filter) & #2(model-agnostic)
─────────────────────────────────────────────────────────────────────────────
실험 A (model-agnostic): BAT 증강이 RF 외 분류기에서도 효과가 있는가?
  - 5개 분류기(RF/XGB/LGB/DT/LR) × {baseline, BAT-full} 비교
  - hard test set, 3시드 평균

실험 B (pre-filter/deterministic 컴포넌트): 라이브 탐지기의 규칙 기반
  컴포넌트(C2-포트 시그니처 오버라이드)의 기여도 정량화.
  - ML-only  vs  ML + C2 시그니처
  - Table V(ablation)는 ML-only임을 명확화

사용법:
  python3 scripts/component_ablation.py
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
from ablation_study import (  # noqa: E402
    FEATURE_COLS, generate_base, generate_hard_testset, eval_metrics,
    build_dataset,
)
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.tree import DecisionTreeClassifier  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402
from sklearn.metrics import recall_score  # noqa: E402

warnings.filterwarnings('ignore')

try:
    import xgboost as xgb
    HAS_XGB = True
except ImportError:
    HAS_XGB = False
try:
    import lightgbm as lgb
    HAS_LGB = True
except ImportError:
    HAS_LGB = False

BENCHMARK_DIR = 'data/benchmark'
C2_PORTS = {4444, 6667, 1080, 8443, 9001}


def make_models(seed):
    m = {
        'RF': RandomForestClassifier(n_estimators=150, max_depth=15,
              min_samples_split=5, class_weight='balanced',
              random_state=seed, n_jobs=-1),
        'Decision Tree': DecisionTreeClassifier(max_depth=15,
              class_weight='balanced', random_state=seed),
        'Logistic Reg.': LogisticRegression(max_iter=1000,
              class_weight='balanced', random_state=seed, n_jobs=-1),
    }
    if HAS_XGB:
        m['XGBoost'] = xgb.XGBClassifier(n_estimators=150, max_depth=8,
              learning_rate=0.1, use_label_encoder=False,
              eval_metric='logloss', random_state=seed, n_jobs=-1)
    if HAS_LGB:
        m['LightGBM'] = lgb.LGBMClassifier(n_estimators=150, max_depth=8,
              learning_rate=0.1, class_weight='balanced',
              random_state=seed, n_jobs=-1, verbose=-1)
    return m


def ms(vals):
    a = np.array(vals)
    return round(float(a.mean()), 4), round(float(a.std(ddof=1)) if len(a) > 1 else 0.0, 4)


# ── 실험 A: model-agnostic 증강 파이프라인 ──────────────────────────────
# Cond ①(Baseline) vs Cond ④(Full: BAT borderline + noise + heavy normals + weights)
# = Table V의 실제 방법을 RF 외 분류기로 확장
COND_FULL = dict(borderline_frac=0.20, heavy_normal_frac=0.12,
                 noise_frac_attack=0.10, noise_frac_normal=0.08,
                 attack_weights=True, smote_type='none')


def experiment_model_agnostic(seeds, n_train):
    print("=== 실험 A: model-agnostic 증강 (Cond① Baseline vs Cond④ Full) ===")
    print(f"{'Model':<14} {'F1(base)':>10} {'F1(full)':>10} {'ΔF1':>8} "
          f"{'FPR(base)':>10} {'FPR(full)':>10} {'ΔFPR':>8}")
    print("-" * 76)
    rows = []
    model_names = list(make_models(42).keys())
    for mname in model_names:
        base_f1s, full_f1s, base_fprs, full_fprs = [], [], [], []
        for seed in seeds:
            nrm, atk = generate_base(n_train, seed)
            test_df = generate_hard_testset(n=2000, seed=99)
            X_te = test_df[FEATURE_COLS].values
            y_te = test_df['label'].values

            for variant in ('base', 'full'):
                if variant == 'base':
                    train_df = build_dataset(nrm, atk)  # 증강 없음
                else:
                    train_df = build_dataset(nrm, atk, **COND_FULL)
                scaler = StandardScaler()
                X_tr = scaler.fit_transform(train_df[FEATURE_COLS].values)
                X_te_s = scaler.transform(X_te)
                clf = make_models(seed)[mname]
                clf.fit(X_tr, train_df['label'].values)
                m = eval_metrics(y_te, clf.predict(X_te_s))
                if variant == 'base':
                    base_f1s.append(m['f1']); base_fprs.append(m['fpr'])
                else:
                    full_f1s.append(m['f1']); full_fprs.append(m['fpr'])

        bf1, bf1s = ms(base_f1s); tf1, tf1s = ms(full_f1s)
        bfp, _ = ms(base_fprs);   tfp, _ = ms(full_fprs)
        rows.append({'model': mname, 'f1_base': bf1, 'f1_base_std': bf1s,
                     'f1_full': tf1, 'f1_full_std': tf1s,
                     'fpr_base': bfp, 'fpr_full': tfp,
                     'delta_f1': round(tf1 - bf1, 4), 'delta_fpr': round(tfp - bfp, 4)})
        print(f"{mname:<14} {bf1:>10.4f} {tf1:>10.4f} {tf1-bf1:>+8.4f} "
              f"{bfp:>10.4f} {tfp:>10.4f} {tfp-bfp:>+8.4f}")
    return rows


# ── 실험 B: 결정론적 시그니처(C2 포트) 기여도 ────────────────────────────
def apply_c2_override(df, y_pred):
    dp = df['dst_port'].astype(int).values
    mask = np.isin(dp, list(C2_PORTS))
    y_pred = y_pred.copy()
    y_pred[mask] = 1
    return y_pred


def experiment_prefilter(seeds, n_train):
    print("\n=== 실험 B: 결정론적 C2-포트 시그니처 기여도 (RF 백본) ===")
    print(f"{'Config':<22} {'F1':>14} {'Recall':>14} {'FPR':>14} {'BotnetRec':>14}")
    print("-" * 82)
    configs = ['ML-only', 'ML + C2 signature']
    agg = {c: {'f1': [], 'recall': [], 'fpr': [], 'botnet': []} for c in configs}
    for seed in seeds:
        nrm, atk = generate_base(n_train, seed)
        train_df = pd.concat([nrm, atk], ignore_index=True).sample(frac=1, random_state=seed)
        scaler = StandardScaler()
        X_tr = scaler.fit_transform(train_df[FEATURE_COLS].values)
        clf = RandomForestClassifier(n_estimators=150, max_depth=15,
              min_samples_split=5, class_weight='balanced',
              random_state=seed, n_jobs=-1).fit(X_tr, train_df['label'].values)

        test_df = generate_hard_testset(n=2000, seed=99)
        X_te = scaler.transform(test_df[FEATURE_COLS].values)
        y_te = test_df['label'].values
        at = test_df['attack_type'].values
        bmask = at == 'botnet_c2'
        y_pred_ml = clf.predict(X_te)

        for cfg in configs:
            y_pred = y_pred_ml if cfg == 'ML-only' else apply_c2_override(test_df, y_pred_ml)
            m = eval_metrics(y_te, y_pred)
            agg[cfg]['f1'].append(m['f1']); agg[cfg]['recall'].append(m['recall'])
            agg[cfg]['fpr'].append(m['fpr'])
            agg[cfg]['botnet'].append(recall_score(y_te[bmask], y_pred[bmask], zero_division=0)
                                     if bmask.sum() else 0.0)
    rows = []
    for cfg in configs:
        f1, f1s = ms(agg[cfg]['f1']); r, _ = ms(agg[cfg]['recall'])
        fp, _ = ms(agg[cfg]['fpr']); bn, _ = ms(agg[cfg]['botnet'])
        rows.append({'config': cfg, 'f1': f1, 'recall': r, 'fpr': fp, 'botnet_recall': bn})
        print(f"{cfg:<22} {f1:.4f}±{f1s:.4f} {r:>14.4f} {fp:>14.4f} {bn:>14.4f}")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--seeds', type=int, nargs='+', default=[42, 43, 44])
    ap.add_argument('--n-train', type=int, default=6000)
    args = ap.parse_args()
    os.makedirs(BENCHMARK_DIR, exist_ok=True)

    a = experiment_model_agnostic(args.seeds, args.n_train)
    b = experiment_prefilter(args.seeds, args.n_train)

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out = {'timestamp': ts, 'config': {'seeds': args.seeds, 'n_train': args.n_train},
           'model_agnostic': a, 'prefilter': b}
    path = os.path.join(BENCHMARK_DIR, f'component_ablation_{ts}.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\n[완료] {path}\nOUTPUT_RESULT:{path}")


if __name__ == '__main__':
    main()
