#!/usr/bin/env python3
"""
Capture-day retrain-recovery 실험 — 리뷰어 지적 #6 (retraining loop가 실제로
capture-day shift를 복구하는지 입증)
─────────────────────────────────────────────────────────────────────────────
시나리오 (AdaptiveNIDS 운영 루프 모사):
  Stage A (배포): 1차 capture-day(02-14,02-15,02-20)로 RF 학습
                  → 2차 capture-day(02-22,02-16,02-21) 평가 = degradation 감지
  Stage B (재학습): 2차 capture-day의 일부(라벨 확보분, 기본 30%)를 누적해 RF 재학습
                  → 2차의 나머지(70%) 평가 = 복구 측정

출력: F1_before vs F1_after (per-class recall 포함)

사용법:
  python3 scripts/capture_day_retrain.py
"""
import argparse, json, os, sys, warnings
from datetime import datetime
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from preprocess_cicids2018 import process_file, FEATURE_COLS  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402
from sklearn.metrics import f1_score, recall_score, precision_score  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402

warnings.filterwarnings('ignore')
RAW = 'data/cicids2018/raw'
BENCH = 'data/benchmark'
FIRST_DAYS  = ['02-14-2018.csv', '02-15-2018.csv', '02-20-2018.csv']
SECOND_DAYS = ['02-22-2018.csv', '02-16-2018.csv', '02-21-2018.csv']


def load_days(files, cap_per_class=8000, seed=42):
    dfs = []
    for f in files:
        p = os.path.join(RAW, f)
        if not os.path.exists(p):
            print(f"  [skip] {f} 없음"); continue
        d = process_file(p)
        if d is not None and len(d):
            dfs.append(d)
    if not dfs:
        return None
    df = pd.concat(dfs, ignore_index=True)
    # 클래스별 캡 (속도)
    parts = []
    for atype, g in df.groupby('attack_type'):
        parts.append(g.sample(min(len(g), cap_per_class), random_state=seed))
    return pd.concat(parts, ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)


def clean(X):
    return np.nan_to_num(np.clip(X.astype(float), -1e8, 1e8), posinf=1e8, neginf=-1e8)


def build_models(seed):
    m = {'AdaptiveNIDS (RF)': RandomForestClassifier(
            n_estimators=150, max_depth=15, min_samples_split=5,
            class_weight='balanced', random_state=seed, n_jobs=-1)}
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.linear_model import LogisticRegression
    m['Decision Tree'] = DecisionTreeClassifier(max_depth=15, class_weight='balanced', random_state=seed)
    m['Logistic Reg.'] = LogisticRegression(max_iter=1000, class_weight='balanced', random_state=seed, n_jobs=-1)
    try:
        import xgboost as xgb
        m['XGBoost'] = xgb.XGBClassifier(n_estimators=150, max_depth=8, learning_rate=0.1,
                        use_label_encoder=False, eval_metric='logloss', random_state=seed, n_jobs=-1)
    except ImportError:
        pass
    try:
        import lightgbm as lgb
        m['LightGBM'] = lgb.LGBMClassifier(n_estimators=150, max_depth=8, learning_rate=0.1,
                         class_weight='balanced', random_state=seed, n_jobs=-1, verbose=-1)
    except ImportError:
        pass
    return m


def train_eval_all(train_df, test_df, seed=42):
    sc = StandardScaler()
    Xtr = sc.fit_transform(clean(train_df[FEATURE_COLS].values))
    Xte = sc.transform(clean(test_df[FEATURE_COLS].values))
    yt = test_df['label'].values
    from sklearn.metrics import roc_auc_score
    out = {}
    for name, clf in build_models(seed).items():
        clf.fit(Xtr, train_df['label'].values)
        yp = clf.predict(Xte)
        yprob = clf.predict_proba(Xte)[:, 1] if hasattr(clf, 'predict_proba') else yp.astype(float)
        fpr = (yp[yt == 0] == 1).sum() / max((yt == 0).sum(), 1)
        try:
            auc = roc_auc_score(yt, yprob)
        except Exception:
            auc = 0.0
        out[name] = dict(f1=round(f1_score(yt, yp, zero_division=0), 4),
                         recall=round(recall_score(yt, yp, zero_division=0), 4),
                         precision=round(precision_score(yt, yp, zero_division=0), 4),
                         auc=round(float(auc), 4), fpr=round(float(fpr), 4))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--retrain-frac', type=float, default=0.30)
    ap.add_argument('--seed', type=int, default=42)
    args = ap.parse_args()
    os.makedirs(BENCH, exist_ok=True)

    print("[로드] 1차 capture-day...")
    first = load_days(FIRST_DAYS, seed=args.seed)
    print("[로드] 2차 capture-day...")
    second = load_days(SECOND_DAYS, seed=args.seed)

    # within-class temporal split: 두 기간에 공통으로 등장하는 공격 클래스만 유지
    a1 = set(first[first['label'] == 1]['attack_type'])
    a2 = set(second[second['label'] == 1]['attack_type'])
    common = a1 & a2
    print(f"  공통 공격 클래스(within-class): {sorted(common)}")
    keep = lambda d: d[(d['label'] == 0) | (d['attack_type'].isin(common))].reset_index(drop=True)
    first, second = keep(first), keep(second)
    print(f"  1차: {len(first)}행, 양성률={first['label'].mean():.3f}")
    print(f"  2차: {len(second)}행, 양성률={second['label'].mean():.3f}")

    # 2차를 retrain용 / 평가용으로 분할 (stratified)
    retr, evald = train_test_split(second, test_size=1 - args.retrain_frac,
                                   stratify=second['label'], random_state=args.seed)
    print(f"  2차 분할: retrain {len(retr)}행 / eval {len(evald)}행")

    # Stage A: 1차 학습 → 2차 held-out 평가 (배포 후 degradation), 5개 모델
    before = train_eval_all(first, evald, args.seed)
    # Stage B: 1차 + 2차 retrain분 누적 재학습 → 2차 held-out 평가 (복구), 5개 모델
    accumulated = pd.concat([first, retr], ignore_index=True)
    after = train_eval_all(accumulated, evald, args.seed)

    order = ['AdaptiveNIDS (RF)', 'XGBoost', 'LightGBM', 'Decision Tree', 'Logistic Reg.']
    print(f"\n{'Model':<20} {'F1 before':>10} {'F1 after':>10} {'ΔF1':>8} "
          f"{'Rec before':>11} {'Rec after':>10}")
    print('-' * 74)
    for m in order:
        if m not in before:
            continue
        b, a = before[m], after[m]
        print(f"{m:<20} {b['f1']:>10.4f} {a['f1']:>10.4f} {a['f1']-b['f1']:>+8.4f} "
              f"{b['recall']:>11.4f} {a['recall']:>10.4f}")

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out = dict(timestamp=ts, retrain_frac=args.retrain_frac, seed=args.seed,
               first_days=FIRST_DAYS, second_days=SECOND_DAYS,
               common_classes=sorted(common),
               n_first=len(first), n_second=len(second),
               n_retrain=len(retr), n_eval=len(evald),
               before=before, after=after)
    path = os.path.join(BENCH, f'capture_day_retrain_{ts}.json')
    json.dump(out, open(path, 'w'), ensure_ascii=False, indent=2)
    print(f"\n[완료] {path}\nOUTPUT_RESULT:{path}")


if __name__ == '__main__':
    main()
