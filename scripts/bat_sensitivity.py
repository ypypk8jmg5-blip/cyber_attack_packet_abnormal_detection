#!/usr/bin/env python3
"""
BAT 하이퍼파라미터 민감도 분석 — 논문 Eq.(1) 충실 구현
─────────────────────────────────────────────────────────────────────────────
리뷰어 지적 대응:
  (1) r_b, σ 민감도 분석이 future work로 이월됨
      → 그리드 r_b∈{0.10,0.20,0.30} × σ∈{0.0,0.05,0.10} 결과 제시
  (2) α 범위 [0.2,0.4]의 정당화 부재
      → α∈{[0.1,0.5],[0.1,0.3],[0.2,0.4],[0.3,0.5]} 비교로 선택 근거 제시

BAT (논문 Eq.1):  x_b = (1-α)·x_i + α·µ_n + ε
  - r_b 비율의 공격 샘플을 경계 변종으로 교체
  - α ~ U(α_lo, α_hi)
  - ε ~ N(0, σ·|x_i|)  (피처별 상대 가우시안 노이즈)
  - µ_n : 정상 트래픽 피처 중심(centroid)

평가: 난이도 높은 hard test set (경계 30% + heavy normal 15% + 노이즈),
      안정성을 위해 3개 시드 평균.

사용법:
  python3 scripts/bat_sensitivity.py
  python3 scripts/bat_sensitivity.py --seeds 42 43 44
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
    FEATURE_COLS, generate_base, generate_hard_testset,
    train_rf, eval_metrics, HARD_ATTACKS,
)
from sklearn.preprocessing import StandardScaler  # noqa: E402
from sklearn.metrics import recall_score  # noqa: E402

warnings.filterwarnings('ignore')

BENCHMARK_DIR = 'data/benchmark'
RATIO_FEATS = {'outbound_ratio', 'syn_flag_ratio'}


def bat_inject(attack_df: pd.DataFrame, normal_df: pd.DataFrame,
               rb: float, sigma: float,
               alpha_lo: float = 0.2, alpha_hi: float = 0.4,
               rng: np.random.Generator = None) -> pd.DataFrame:
    """논문 Eq.(1) 충실 구현: x_b = (1-α)x_i + α·µ_n + ε."""
    if rng is None:
        rng = np.random.default_rng(0)
    atk = attack_df.copy().reset_index(drop=True)
    mu_n = normal_df[FEATURE_COLS].values.mean(axis=0)   # 정상 centroid

    if rb <= 0:
        return atk
    n_border = max(1, int(len(atk) * rb))
    border_idx = rng.choice(len(atk), size=n_border, replace=False)

    X = atk[FEATURE_COLS].values.astype(float)
    for i in border_idx:
        x_i = X[i]
        alpha = rng.uniform(alpha_lo, alpha_hi)
        eps = rng.normal(0.0, sigma * np.abs(x_i)) if sigma > 0 else 0.0
        x_b = (1.0 - alpha) * x_i + alpha * mu_n + eps
        X[i] = x_b

    # 정수형 컬럼 → float 캐스팅 후 컬럼별 할당 (dtype 충돌 방지)
    for j, c in enumerate(FEATURE_COLS):
        col = X[:, j]
        if c in RATIO_FEATS:
            col = np.clip(col, 0.0, 1.0)
        else:
            col = np.clip(col, 0.0, None)
        atk[c] = col.astype(float)
    return atk


def run_one(rb: float, sigma: float, alpha_lo: float, alpha_hi: float,
            seeds: list, n_train: int) -> dict:
    """주어진 (rb, σ, α범위)에서 시드 평균 성능."""
    f1s, recs, pres, fprs, hard_recs = [], [], [], [], []
    for seed in seeds:
        rng = np.random.default_rng(seed)
        nrm, atk = generate_base(n_train, seed)
        atk_bat = bat_inject(atk, nrm, rb, sigma, alpha_lo, alpha_hi, rng)
        train_df = pd.concat([nrm, atk_bat], ignore_index=True)
        train_df = train_df.sample(frac=1, random_state=seed).reset_index(drop=True)

        test_df = generate_hard_testset(n=2000, seed=99)

        scaler = StandardScaler()
        X_tr = scaler.fit_transform(train_df[FEATURE_COLS].values)
        y_tr = train_df['label'].values
        X_te = scaler.transform(test_df[FEATURE_COLS].values)
        y_te = test_df['label'].values

        clf = train_rf(X_tr, y_tr)
        y_pred = clf.predict(X_te)
        m = eval_metrics(y_te, y_pred)
        f1s.append(m['f1']); recs.append(m['recall'])
        pres.append(m['precision']); fprs.append(m['fpr'])

        # hard-attack 재현율 (경계 효과가 두드러진 6종)
        at = test_df['attack_type'].values
        mask = np.isin(at, HARD_ATTACKS)
        hard_recs.append(recall_score(y_te[mask], y_pred[mask], zero_division=0))

    def ms(a):
        a = np.array(a)
        return round(float(a.mean()), 4), round(float(a.std(ddof=1)) if len(a) > 1 else 0.0, 4)

    f1_m, f1_s = ms(f1s); r_m, r_s = ms(recs)
    p_m, p_s = ms(pres);  fp_m, fp_s = ms(fprs); hr_m, hr_s = ms(hard_recs)
    return {
        'rb': rb, 'sigma': sigma, 'alpha': [alpha_lo, alpha_hi],
        'f1': f1_m, 'f1_std': f1_s,
        'recall': r_m, 'recall_std': r_s,
        'precision': p_m, 'precision_std': p_s,
        'fpr': fp_m, 'fpr_std': fp_s,
        'hard_recall': hr_m, 'hard_recall_std': hr_s,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--seeds', type=int, nargs='+', default=[42, 43, 44])
    ap.add_argument('--n-train', type=int, default=6000)
    args = ap.parse_args()
    os.makedirs(BENCHMARK_DIR, exist_ok=True)

    print(f"[BAT 민감도] seeds={args.seeds}, n_train={args.n_train}\n")

    # ── 그리드 1: r_b × σ (α 고정 [0.2,0.4]) ──────────────────────────
    rb_grid = [0.10, 0.20, 0.30]
    sigma_grid = [0.0, 0.05, 0.10]
    print("=== Grid 1: r_b × σ  (α∈U[0.2,0.4]) ===")
    print(f"{'r_b':>5} {'σ':>5} | {'F1':>14} {'Recall':>14} {'Prec':>14} {'FPR':>14} {'HardRec':>14}")
    print("-" * 90)
    grid_results = []
    for rb in rb_grid:
        for sg in sigma_grid:
            r = run_one(rb, sg, 0.2, 0.4, args.seeds, args.n_train)
            grid_results.append(r)
            print(f"{rb:>5.2f} {sg:>5.2f} | "
                  f"{r['f1']:.4f}±{r['f1_std']:.4f} "
                  f"{r['recall']:.4f}±{r['recall_std']:.4f} "
                  f"{r['precision']:.4f}±{r['precision_std']:.4f} "
                  f"{r['fpr']:.4f}±{r['fpr_std']:.4f} "
                  f"{r['hard_recall']:.4f}±{r['hard_recall_std']:.4f}")

    # ── 그리드 2: α 범위 (r_b=0.20, σ=0.05 고정) ──────────────────────
    alpha_grid = [(0.1, 0.5), (0.1, 0.3), (0.2, 0.4), (0.3, 0.5)]
    print("\n=== Grid 2: α range  (r_b=0.20, σ=0.05) ===")
    print(f"{'α range':>12} | {'F1':>14} {'Recall':>14} {'Prec':>14} {'FPR':>14} {'HardRec':>14}")
    print("-" * 90)
    alpha_results = []
    for lo, hi in alpha_grid:
        r = run_one(0.20, 0.05, lo, hi, args.seeds, args.n_train)
        alpha_results.append(r)
        print(f"  [{lo:.1f},{hi:.1f}]   | "
              f"{r['f1']:.4f}±{r['f1_std']:.4f} "
              f"{r['recall']:.4f}±{r['recall_std']:.4f} "
              f"{r['precision']:.4f}±{r['precision_std']:.4f} "
              f"{r['fpr']:.4f}±{r['fpr_std']:.4f} "
              f"{r['hard_recall']:.4f}±{r['hard_recall_std']:.4f}")

    # best
    best = max(grid_results, key=lambda x: (x['f1'], -x['fpr']))
    print(f"\n[Grid1 최적] r_b={best['rb']}, σ={best['sigma']}  "
          f"→ F1={best['f1']}, FPR={best['fpr']}")

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out = {
        'timestamp': ts,
        'config': {'seeds': args.seeds, 'n_train': args.n_train,
                   'test': 'hard_testset(n=2000, seed=99)',
                   'equation': 'x_b = (1-alpha)*x_i + alpha*mu_n + eps; eps~N(0, sigma*|x_i|)'},
        'grid_rb_sigma': grid_results,
        'grid_alpha': alpha_results,
        'best_rb_sigma': {'rb': best['rb'], 'sigma': best['sigma'],
                          'f1': best['f1'], 'fpr': best['fpr']},
    }
    path = os.path.join(BENCHMARK_DIR, f'bat_sensitivity_{ts}.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\n[완료] {path}\nOUTPUT_RESULT:{path}")


if __name__ == '__main__':
    main()
