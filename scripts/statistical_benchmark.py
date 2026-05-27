#!/usr/bin/env python3
"""
통계적 엄밀성 벤치마크 — 다중 시드 / 교차검증 / 유의성 검정
─────────────────────────────────────────────────────────────────────────────
리뷰어 지적 대응:
  (1) 단일 시드(random_state=42) → 다중 시드 반복 측정
  (2) 신뢰구간/표준편차 없음 → 평균 ± 표준편차 + 95% CI 보고
  (3) "within cross-validation variance" 주장하면서 CV 결과 미제시
      → RepeatedStratifiedKFold 결과 제시
  (4) 통계적 유의성 검정 없음
      → AdaptiveNIDS vs XGBoost: paired t-test + Wilcoxon signed-rank

방법:
  - train+test 결합 후 RepeatedStratifiedKFold(n_splits=5, n_repeats=2)
    = 모델당 10개 독립 측정값
  - 각 fold 마다 모델 random_state 도 fold 인덱스로 변경 (모델 무작위성 포함)
  - 모든 모델은 동일 fold 에서 학습/평가 (paired 비교 가능)

출력:
  data/benchmark/statistical_results_<ts>.json
  data/benchmark/statistical_table_<ts>.csv

사용법:
  python3 scripts/statistical_benchmark.py
  python3 scripts/statistical_benchmark.py --n-splits 5 --n-repeats 2
"""

import argparse
import json
import os
import warnings
from datetime import datetime

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
)
from sklearn.model_selection import RepeatedStratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

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

FEATURE_COLS = [
    'duration', 'protocol', 'src_port', 'dst_port', 'packet_size',
    'packets_per_sec', 'bytes_per_sec', 'unique_dst_ports',
    'connection_count', 'failed_attempts', 'outbound_ratio', 'syn_flag_ratio'
]
BENCHMARK_DIR = 'data/benchmark'
METRICS = ['f1', 'recall', 'precision', 'accuracy', 'fpr', 'auc']


def build_models(seed: int) -> dict:
    """seed 마다 모델 random_state 변경 (모델 자체 무작위성 포함)."""
    models = {
        'AdaptiveNIDS (RF)': RandomForestClassifier(
            n_estimators=150, max_depth=15, min_samples_split=5,
            class_weight='balanced', random_state=seed, n_jobs=-1
        ),
        'Decision Tree': DecisionTreeClassifier(
            max_depth=15, class_weight='balanced', random_state=seed
        ),
        'Logistic Regression': LogisticRegression(
            max_iter=1000, class_weight='balanced', random_state=seed, n_jobs=-1
        ),
    }
    if HAS_XGB:
        models['XGBoost'] = xgb.XGBClassifier(
            n_estimators=150, max_depth=8, learning_rate=0.1,
            use_label_encoder=False, eval_metric='logloss',
            random_state=seed, n_jobs=-1
        )
    if HAS_LGB:
        models['LightGBM'] = lgb.LGBMClassifier(
            n_estimators=150, max_depth=8, learning_rate=0.1,
            class_weight='balanced', random_state=seed, n_jobs=-1, verbose=-1
        )
    return models


def eval_metrics(y_true, y_pred, y_prob) -> dict:
    fpr = (y_pred[y_true == 0] == 1).sum() / max((y_true == 0).sum(), 1)
    try:
        auc = roc_auc_score(y_true, y_prob)
    except Exception:
        auc = 0.0
    return {
        'f1':        f1_score(y_true, y_pred, zero_division=0),
        'recall':    recall_score(y_true, y_pred, zero_division=0),
        'precision': precision_score(y_true, y_pred, zero_division=0),
        'accuracy':  accuracy_score(y_true, y_pred),
        'fpr':       float(fpr),
        'auc':       float(auc),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--train', default='data/cicids2018/processed/cicids2018_train_latest.csv')
    ap.add_argument('--test',  default='data/cicids2018/processed/cicids2018_test_latest.csv')
    ap.add_argument('--n-splits',  type=int, default=5)
    ap.add_argument('--n-repeats', type=int, default=2)
    ap.add_argument('--base-seed', type=int, default=42)
    args = ap.parse_args()

    os.makedirs(BENCHMARK_DIR, exist_ok=True)

    print("[데이터 로드]")
    tr = pd.read_csv(args.train)
    te = pd.read_csv(args.test)
    df = pd.concat([tr, te], ignore_index=True)
    X = df[FEATURE_COLS].values.astype(float)
    y = df['label'].values.astype(int)
    # Inf/NaN 방어
    X = np.nan_to_num(np.clip(X, -1e8, 1e8), posinf=1e8, neginf=-1e8)
    print(f"  결합 데이터: {df.shape}, 양성률={y.mean():.3f}")

    n_folds = args.n_splits * args.n_repeats
    rskf = RepeatedStratifiedKFold(
        n_splits=args.n_splits, n_repeats=args.n_repeats, random_state=args.base_seed
    )
    print(f"\n[RepeatedStratifiedKFold] {args.n_splits}-fold × {args.n_repeats} = {n_folds} 측정/모델\n")

    # per_model[model][metric] = list of fold measurements
    per_model = {}

    for fold_idx, (tr_i, te_i) in enumerate(rskf.split(X, y)):
        seed = args.base_seed + fold_idx
        X_tr, X_te = X[tr_i], X[te_i]
        y_tr, y_te = y[tr_i], y[te_i]

        scaler = StandardScaler()
        X_tr_s = scaler.fit_transform(X_tr)
        X_te_s = scaler.transform(X_te)

        models = build_models(seed)
        line = f"  fold {fold_idx+1:>2}/{n_folds} (seed={seed}): "
        for name, clf in models.items():
            clf.fit(X_tr_s, y_tr)
            y_pred = clf.predict(X_te_s)
            y_prob = (clf.predict_proba(X_te_s)[:, 1]
                      if hasattr(clf, 'predict_proba') else y_pred.astype(float))
            m = eval_metrics(y_te, y_pred, y_prob)
            per_model.setdefault(name, {k: [] for k in METRICS})
            for k in METRICS:
                per_model[name][k].append(m[k])
            line += f"{name.split()[0]}={m['f1']:.4f} "
        print(line)

    # ── 요약 통계 ────────────────────────────────────────────────────────
    summary = {}
    for name, mdict in per_model.items():
        summary[name] = {}
        for k in METRICS:
            arr = np.array(mdict[k])
            mean, std = arr.mean(), arr.std(ddof=1)
            # 95% CI (t-분포)
            sem = std / np.sqrt(len(arr))
            ci = stats.t.ppf(0.975, len(arr) - 1) * sem
            summary[name][k] = {
                'mean': round(float(mean), 4),
                'std':  round(float(std), 4),
                'ci95': round(float(ci), 4),
                'values': [round(float(v), 4) for v in arr],
            }

    print("\n" + "=" * 78)
    print(f"{'Model':<22} {'F1 (mean±std)':>20} {'Recall':>16} {'AUC':>16}")
    print("-" * 78)
    for name in sorted(per_model, key=lambda n: summary[n]['f1']['mean'], reverse=True):
        s = summary[name]
        print(f"{name:<22} "
              f"{s['f1']['mean']:.4f}±{s['f1']['std']:.4f}    "
              f"{s['recall']['mean']:.4f}±{s['recall']['std']:.4f}  "
              f"{s['auc']['mean']:.4f}±{s['auc']['std']:.4f}")
    print("=" * 78)

    # ── 통계적 유의성 검정: AdaptiveNIDS vs XGBoost ─────────────────────
    sig = {}
    a_name = 'AdaptiveNIDS (RF)'
    if a_name in per_model and 'XGBoost' in per_model:
        print("\n[유의성 검정] AdaptiveNIDS (RF) vs XGBoost — paired, n="
              f"{n_folds}")
        for k in ['f1', 'recall', 'auc']:
            a = np.array(per_model[a_name][k])
            b = np.array(per_model['XGBoost'][k])
            diff = a - b
            t_stat, t_p = stats.ttest_rel(a, b)
            try:
                w_stat, w_p = stats.wilcoxon(a, b)
            except ValueError:
                w_stat, w_p = float('nan'), 1.0  # 모든 차이가 0이면
            # Cohen's d (paired)
            d = diff.mean() / (diff.std(ddof=1) + 1e-12)
            sig[k] = {
                'mean_diff': round(float(diff.mean()), 5),
                'paired_t_stat': round(float(t_stat), 4),
                'paired_t_p': round(float(t_p), 4),
                'wilcoxon_stat': round(float(w_stat), 4),
                'wilcoxon_p': round(float(w_p), 4),
                'cohens_d': round(float(d), 4),
            }
            verdict = "유의미(p<0.05)" if t_p < 0.05 else "유의차 없음(p≥0.05)"
            print(f"  {k:<10}: Δ={diff.mean():+.5f}  "
                  f"t={t_stat:+.3f} (p={t_p:.4f})  "
                  f"Wilcoxon p={w_p:.4f}  d={d:+.3f}  → {verdict}")

    # ── 저장 ─────────────────────────────────────────────────────────────
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out = {
        'timestamp': ts,
        'config': {'n_splits': args.n_splits, 'n_repeats': args.n_repeats,
                   'n_folds': n_folds, 'base_seed': args.base_seed,
                   'n_samples': int(len(y)), 'positive_rate': round(float(y.mean()), 4)},
        'summary': summary,
        'significance_vs_xgboost': sig,
    }
    jpath = os.path.join(BENCHMARK_DIR, f'statistical_results_{ts}.json')
    with open(jpath, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    # CSV (논문 테이블용: mean±std)
    rows = []
    for name in per_model:
        row = {'model': name}
        for k in METRICS:
            row[f'{k}_mean'] = summary[name][k]['mean']
            row[f'{k}_std']  = summary[name][k]['std']
        rows.append(row)
    cpath = os.path.join(BENCHMARK_DIR, f'statistical_table_{ts}.csv')
    pd.DataFrame(rows).to_csv(cpath, index=False)

    print(f"\n[완료] JSON: {jpath}\n        CSV : {cpath}")
    print(f"OUTPUT_RESULT:{jpath}")


if __name__ == '__main__':
    main()
