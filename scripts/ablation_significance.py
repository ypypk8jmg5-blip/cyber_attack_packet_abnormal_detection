#!/usr/bin/env python3
"""
Ablation 유의성 검정 — 리뷰어 지적 #2 (BAT vs SMOTE-family 마진의 통계적 검증)
─────────────────────────────────────────────────────────────────────────────
Cond.④ Full/BAT, Cond.⑤ Full/SMOTE, Cond.⑥ Full/BL-SMOTE 를 다중 시드로 반복,
overall F1 / FPR / cryptomining recall 의 mean±std 와
BAT vs BL-SMOTE, BAT vs SMOTE 의 paired t-test + Wilcoxon 를 보고.

hard test set(seed=99 고정)으로 평가. 모든 조건 동일 train 시드.

사용법:
  python3 scripts/ablation_significance.py --seeds 42 43 44 45 46
"""
import argparse, json, os, sys, warnings
from datetime import datetime
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ablation_study import (  # noqa: E402
    FEATURE_COLS, generate_base, generate_hard_testset, build_dataset,
    train_rf, eval_metrics,
)
from sklearn.preprocessing import StandardScaler  # noqa: E402
from sklearn.metrics import recall_score  # noqa: E402
from scipy import stats  # noqa: E402

warnings.filterwarnings('ignore')
BENCHMARK_DIR = 'data/benchmark'

CONDS = {
    'BAT':      dict(borderline_frac=0.20, heavy_normal_frac=0.12,
                     noise_frac_attack=0.10, noise_frac_normal=0.08,
                     attack_weights=True, smote_type='none'),
    'SMOTE':    dict(borderline_frac=0.0,  heavy_normal_frac=0.12,
                     noise_frac_attack=0.10, noise_frac_normal=0.08,
                     attack_weights=True, smote_type='smote'),
    'BL-SMOTE': dict(borderline_frac=0.0,  heavy_normal_frac=0.12,
                     noise_frac_attack=0.10, noise_frac_normal=0.08,
                     attack_weights=True, smote_type='borderline_smote'),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--seeds', type=int, nargs='+', default=[42, 43, 44, 45, 46])
    ap.add_argument('--n-train', type=int, default=6000)
    args = ap.parse_args()
    os.makedirs(BENCHMARK_DIR, exist_ok=True)

    test_df = generate_hard_testset(n=2000, seed=99)
    X_te = test_df[FEATURE_COLS].values
    y_te = test_df['label'].values
    at_te = test_df['attack_type'].values
    crypto_mask = at_te == 'cryptomining'

    rec = {c: {'f1': [], 'fpr': [], 'recall': [], 'crypto': []} for c in CONDS}
    print(f"[Ablation 유의성] seeds={args.seeds}\n")
    for seed in args.seeds:
        nrm, atk = generate_base(args.n_train, seed)
        line = f"  seed {seed}: "
        for cname, params in CONDS.items():
            train_df = build_dataset(nrm, atk, **params)
            sc = StandardScaler()
            X_tr = sc.fit_transform(train_df[FEATURE_COLS].values)
            X_te_s = sc.transform(X_te)
            clf = train_rf(X_tr, train_df['label'].values)
            yp = clf.predict(X_te_s)
            m = eval_metrics(y_te, yp)
            cr = recall_score(y_te[crypto_mask], yp[crypto_mask], zero_division=0) if crypto_mask.sum() else 0.0
            rec[cname]['f1'].append(m['f1']); rec[cname]['fpr'].append(m['fpr'])
            rec[cname]['recall'].append(m['recall']); rec[cname]['crypto'].append(cr)
            line += f"{cname} F1={m['f1']:.4f} "
        print(line)

    def ms(a):
        a = np.array(a); return round(float(a.mean()), 4), round(float(a.std(ddof=1)), 4)

    print("\n" + "=" * 72)
    print(f"{'Condition':<12} {'F1 (mean±std)':>18} {'FPR':>16} {'Crypto Rec.':>16}")
    print("-" * 72)
    summary = {}
    for c in CONDS:
        f1m, f1s = ms(rec[c]['f1']); fpm, fps = ms(rec[c]['fpr'])
        rm, rs = ms(rec[c]['recall']); cm, cs = ms(rec[c]['crypto'])
        summary[c] = dict(f1=f1m, f1_std=f1s, fpr=fpm, fpr_std=fps,
                          recall=rm, recall_std=rs, crypto=cm, crypto_std=cs)
        print(f"{c:<12} {f1m:.4f}±{f1s:.4f}    {fpm:.4f}±{fps:.4f}   {cm:.4f}±{cs:.4f}")
    print("=" * 72)

    # paired tests: BAT vs BL-SMOTE, BAT vs SMOTE
    sig = {}
    for other in ['BL-SMOTE', 'SMOTE']:
        sig[other] = {}
        print(f"\n[Paired test] BAT vs {other} (n={len(args.seeds)}):")
        for metric in ['f1', 'fpr', 'crypto']:
            a = np.array(rec['BAT'][metric]); b = np.array(rec[other][metric])
            d = a - b
            t, p = stats.ttest_rel(a, b)
            try:
                w, wp = stats.wilcoxon(a, b)
            except ValueError:
                w, wp = float('nan'), 1.0
            sig[other][metric] = dict(delta=round(float(d.mean()), 5),
                                      t=round(float(t), 4), p=round(float(p), 4),
                                      wilcoxon_p=round(float(wp), 4))
            verdict = "유의(p<0.05)" if p < 0.05 else "유의차 없음"
            print(f"  {metric:<8} Δ={d.mean():+.5f}  t={t:+.3f} p={p:.4f}  W_p={wp:.4f}  → {verdict}")

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out = dict(timestamp=ts, seeds=args.seeds, n_train=args.n_train,
               summary=summary, significance=sig)
    path = os.path.join(BENCHMARK_DIR, f'ablation_significance_{ts}.json')
    json.dump(out, open(path, 'w'), ensure_ascii=False, indent=2)
    print(f"\n[완료] {path}\nOUTPUT_RESULT:{path}")


if __name__ == '__main__':
    main()
