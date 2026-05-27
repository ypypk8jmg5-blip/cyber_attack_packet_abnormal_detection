#!/usr/bin/env python3
"""
CIC-IDS2018 벤치마크 — 논문용 비교 실험
─────────────────────────────────────────────────────────────────────────────
실험 A: 자체 학습 데이터(합성) → CIC-IDS2018 테스트셋 (전이 학습 평가)
실험 B: CIC-IDS2018 학습 → CIC-IDS2018 테스트셋 (5개 모델 비교)
  - Random Forest (AdaptiveNIDS, 제안 모델)
  - XGBoost
  - LightGBM
  - Decision Tree (baseline)
  - Logistic Regression (baseline)

출력:
  data/benchmark/results_<timestamp>.json   — 수치 결과
  data/benchmark/results_<timestamp>.csv    — 논문 테이블용
  data/benchmark/figures/                   — 시각화 PNG

사용법:
  # CIC-IDS2018 전처리 완료 후
  python3 scripts/benchmark_cicids2018.py
  python3 scripts/benchmark_cicids2018.py --train data/cicids2018/processed/cicids2018_train_latest.csv
"""

import argparse
import json
import os
import sys
import time
import warnings
from datetime import datetime

import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.font_manager as _fm

# ── 한글 폰트 설정 ────────────────────────────────────────────────────────────
_KO_CANDIDATES = [
    'Apple SD Gothic Neo', 'AppleGothic', 'Nanum Gothic',
    'NanumGothic', 'Malgun Gothic', 'NanumBarunGothic',
]
_available = {f.name for f in _fm.fontManager.ttflist}
_ko_font = next((f for f in _KO_CANDIDATES if f in _available), None)
if _ko_font:
    plt.rcParams['font.family'] = _ko_font
plt.rcParams['axes.unicode_minus'] = False
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score, roc_auc_score, roc_curve
)
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

# ── 상수 ──────────────────────────────────────────────────────────────────
FEATURE_COLS = [
    'duration', 'protocol', 'src_port', 'dst_port', 'packet_size',
    'packets_per_sec', 'bytes_per_sec', 'unique_dst_ports',
    'connection_count', 'failed_attempts', 'outbound_ratio', 'syn_flag_ratio'
]

BENCHMARK_DIR = 'data/benchmark'
FIGURES_DIR   = os.path.join(BENCHMARK_DIR, 'figures')

ATTACK_LABELS_KO = {
    'ddos': 'DDoS', 'botnet_c2': 'Botnet C&C', 'bruteforce': 'Brute Force',
    'exfiltration': 'Exfiltration', 'http_flood': 'HTTP Flood',
    'slowloris': 'Slowloris', 'normal': 'Benign', 'unknown': 'Unknown',
}

# ── 모델 정의 ──────────────────────────────────────────────────────────────

def build_models():
    models = {
        'AdaptiveNIDS (RF)': RandomForestClassifier(
            n_estimators=150, max_depth=15, min_samples_split=5,
            class_weight='balanced', random_state=42, n_jobs=-1
        ),
        'Decision Tree': DecisionTreeClassifier(
            max_depth=15, class_weight='balanced', random_state=42
        ),
        'Logistic Regression': LogisticRegression(
            max_iter=1000, class_weight='balanced', random_state=42, n_jobs=-1
        ),
    }
    if HAS_XGB:
        models['XGBoost'] = xgb.XGBClassifier(
            n_estimators=150, max_depth=8, learning_rate=0.1,
            use_label_encoder=False, eval_metric='logloss',
            random_state=42, n_jobs=-1
        )
    if HAS_LGB:
        models['LightGBM'] = lgb.LGBMClassifier(
            n_estimators=150, max_depth=8, learning_rate=0.1,
            class_weight='balanced', random_state=42, n_jobs=-1, verbose=-1
        )
    return models


# ── 평가 함수 ──────────────────────────────────────────────────────────────

def evaluate(y_true, y_pred, y_prob, name: str) -> dict:
    f1  = f1_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    pre = precision_score(y_true, y_pred, zero_division=0)
    acc = accuracy_score(y_true, y_pred)
    fpr_arr = (y_pred[y_true == 0] == 1).sum() / max((y_true == 0).sum(), 1)
    try:
        auc = roc_auc_score(y_true, y_prob)
    except Exception:
        auc = 0.0
    return {
        'model':     name,
        'f1':        round(f1,  4),
        'recall':    round(rec, 4),
        'precision': round(pre, 4),
        'accuracy':  round(acc, 4),
        'fpr':       round(float(fpr_arr), 4),
        'auc':       round(auc, 4),
    }


def per_attack_recall(y_true, y_pred, attack_types) -> dict:
    result = {}
    for atype in np.unique(attack_types):
        if atype == 'normal':
            continue
        mask = attack_types == atype
        if mask.sum() == 0:
            continue
        result[atype] = round(recall_score(y_true[mask], y_pred[mask], zero_division=0), 4)
    return result


# ── 시각화 ─────────────────────────────────────────────────────────────────

def plot_comparison_table(results: list, save_path: str):
    """논문용 성능 비교 테이블 시각화"""
    fig, ax = plt.subplots(figsize=(10, len(results) * 0.6 + 1.5))
    ax.axis('off')
    cols = ['Model', 'F1', 'Recall', 'Precision', 'Accuracy', 'FPR', 'AUC']
    data = [[r['model'], f"{r['f1']:.4f}", f"{r['recall']:.4f}",
             f"{r['precision']:.4f}", f"{r['accuracy']:.4f}",
             f"{r['fpr']:.4f}", f"{r['auc']:.4f}"] for r in results]
    tbl = ax.table(cellText=data, colLabels=cols, loc='center', cellLoc='center')
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    tbl.scale(1.2, 1.8)
    # AdaptiveNIDS 행 강조
    for i, r in enumerate(results):
        if 'AdaptiveNIDS' in r['model']:
            for j in range(len(cols)):
                tbl[i + 1, j].set_facecolor('#dbeafe')
    ax.set_title('Performance Comparison on CIC-IDS2018', fontsize=13, pad=15)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()


def plot_roc_curves(roc_data: list, save_path: str):
    """ROC 곡선 비교"""
    fig, ax = plt.subplots(figsize=(7, 6))
    colors = ['#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c']
    for i, rd in enumerate(roc_data):
        ax.plot(rd['fpr'], rd['tpr'],
                label=f"{rd['model']} (AUC={rd['auc']:.3f})",
                color=colors[i % len(colors)], lw=2)
    ax.plot([0, 1], [0, 1], 'k--', lw=1, label='Random')
    ax.set_xlabel('False Positive Rate', fontsize=11)
    ax.set_ylabel('True Positive Rate', fontsize=11)
    ax.set_title('ROC Curve Comparison — CIC-IDS2018', fontsize=12)
    ax.legend(fontsize=9, loc='lower right')
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()


def plot_per_attack_recall(recall_dict: dict, model_name: str, save_path: str):
    """공격 유형별 재현율 막대 그래프"""
    atypes = list(recall_dict.keys())
    values = list(recall_dict.values())
    labels = [ATTACK_LABELS_KO.get(a, a) for a in atypes]
    colors = ['#2ecc71' if v >= 0.90 else ('#f39c12' if v >= 0.70 else '#e74c3c')
              for v in values]

    fig, ax = plt.subplots(figsize=(8, max(4, len(atypes) * 0.5 + 1)))
    bars = ax.barh(labels, values, color=colors, height=0.6)
    ax.axvline(x=0.90, color='#e74c3c', linestyle='--', lw=1.5, label='목표 0.90')
    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + 0.01, bar.get_y() + bar.get_height() / 2,
                f'{val:.3f}', va='center', fontsize=9)
    ax.set_xlim(0, 1.12)
    ax.set_xlabel('Recall', fontsize=11)
    ax.set_title(f'Per-Attack Recall — {model_name}\n(CIC-IDS2018)', fontsize=12)
    ax.legend(fontsize=9)
    ax.grid(axis='x', alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()


def plot_confusion_matrix(y_true, y_pred, model_name: str, save_path: str):
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(cm, cmap='Blues')
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(['Normal', 'Attack']); ax.set_yticklabels(['Normal', 'Attack'])
    ax.set_xlabel('Predicted'); ax.set_ylabel('True')
    ax.set_title(f'Confusion Matrix — {model_name}')
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f'{cm[i,j]:,}', ha='center', va='center',
                    color='white' if cm[i,j] > cm.max()/2 else 'black', fontsize=11)
    plt.colorbar(im, ax=ax)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()


# ── 실험 A: 전이 학습 평가 (합성 → 실제 데이터) ──────────────────────────

def experiment_a_transfer(test_df: pd.DataFrame, best_model_path: str) -> dict:
    """
    우리 파이프라인으로 학습된 모델(합성 데이터)을 CIC-IDS2018 테스트셋에 적용.
    논문의 핵심 기여: 합성 데이터 기반 모델의 실제 데이터 일반화 성능
    """
    print("\n[실험 A] 전이 학습 평가 (합성 → CIC-IDS2018)")
    if not os.path.exists(best_model_path):
        print(f"  [SKIP] best_model.pkl 없음: {best_model_path}")
        return {}

    bundle = joblib.load(best_model_path)
    clf, scaler = bundle['model'], bundle['scaler']

    X = test_df[FEATURE_COLS].values
    y_true = test_df['label'].values
    X_s = scaler.transform(X)
    y_prob = clf.predict_proba(X_s)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    result = evaluate(y_true, y_pred, y_prob, 'AdaptiveNIDS (Transfer)')
    attack_types = test_df['attack_type'].values
    result['per_attack_recall'] = per_attack_recall(y_true, y_pred, attack_types)

    print(f"  F1={result['f1']:.4f}  Recall={result['recall']:.4f}  "
          f"Precision={result['precision']:.4f}  AUC={result['auc']:.4f}")
    print("  공격 유형별 재현율:")
    for atype, rec in result['per_attack_recall'].items():
        ko = ATTACK_LABELS_KO.get(atype, atype)
        print(f"    {ko:<15s}: {rec:.4f}")

    return result


# ── 실험 B: CIC-IDS2018 학습/평가 비교 ─────────────────────────────────────

def experiment_b_comparison(train_df: pd.DataFrame, test_df: pd.DataFrame) -> list:
    """5개 모델을 동일 데이터로 학습/평가 → 논문 비교 테이블"""
    print("\n[실험 B] 모델 비교 실험 (CIC-IDS2018 학습/테스트)")

    X_train = train_df[FEATURE_COLS].values
    y_train = train_df['label'].values
    X_test  = test_df[FEATURE_COLS].values
    y_test  = test_df['label'].values
    attack_types_test = test_df['attack_type'].values

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    models  = build_models()
    results = []
    roc_data = []
    trained_models = {}

    for name, clf in models.items():
        print(f"\n  [{name}] 학습 중...", end='', flush=True)
        t0 = time.time()

        # LightGBM/XGBoost는 스케일링 불필요하지만 통일성을 위해 동일하게 적용
        clf.fit(X_train_s, y_train)
        elapsed = time.time() - t0
        print(f" {elapsed:.1f}s 완료")

        y_pred = clf.predict(X_test_s)
        if hasattr(clf, 'predict_proba'):
            y_prob = clf.predict_proba(X_test_s)[:, 1]
        else:
            y_prob = y_pred.astype(float)

        res = evaluate(y_test, y_pred, y_prob, name)
        res['train_time_sec'] = round(elapsed, 2)
        res['per_attack_recall'] = per_attack_recall(y_test, y_pred, attack_types_test)
        results.append(res)
        trained_models[name] = (clf, scaler, y_pred, y_prob)

        print(f"    F1={res['f1']:.4f}  Recall={res['recall']:.4f}  "
              f"Precision={res['precision']:.4f}  AUC={res['auc']:.4f}  "
              f"FPR={res['fpr']:.4f}")

        # ROC 데이터 저장
        fpr_arr, tpr_arr, _ = roc_curve(y_test, y_prob)
        roc_data.append({'model': name, 'fpr': fpr_arr.tolist(),
                         'tpr': tpr_arr.tolist(), 'auc': res['auc']})

    return results, roc_data, trained_models, (X_test_s, y_test, attack_types_test)


# ── 메인 ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='CIC-IDS2018 벤치마크')
    parser.add_argument('--train',      default='data/cicids2018/processed/cicids2018_train_latest.csv')
    parser.add_argument('--test',       default='data/cicids2018/processed/cicids2018_test_latest.csv')
    parser.add_argument('--best-model', default='data/models/best_model.pkl')
    parser.add_argument('--skip-a',     action='store_true', help='전이 학습 실험 건너뜀')
    parser.add_argument('--skip-b',     action='store_true', help='비교 실험 건너뜀')
    args = parser.parse_args()

    os.makedirs(BENCHMARK_DIR, exist_ok=True)
    os.makedirs(FIGURES_DIR,   exist_ok=True)

    # 데이터 로드
    if not os.path.exists(args.train) or not os.path.exists(args.test):
        print("[ERROR] 전처리된 CIC-IDS2018 데이터 없음.")
        print("  먼저 실행: python3 scripts/preprocess_cicids2018.py")
        sys.exit(1)

    print(f"[벤치마크] 데이터 로드...")
    train_df = pd.read_csv(args.train)
    test_df  = pd.read_csv(args.test)
    print(f"  학습: {len(train_df):,}행  |  테스트: {len(test_df):,}행")

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    all_results = {'timestamp': ts, 'experiment_a': {}, 'experiment_b': []}

    # 실험 A
    if not args.skip_a:
        res_a = experiment_a_transfer(test_df, args.best_model)
        all_results['experiment_a'] = res_a
        if res_a:
            plot_per_attack_recall(
                res_a.get('per_attack_recall', {}),
                'AdaptiveNIDS (Transfer)',
                os.path.join(FIGURES_DIR, f'per_attack_transfer_{ts}.png')
            )

    # 실험 B
    if not args.skip_b:
        res_b, roc_data, trained_models, test_data = experiment_b_comparison(
            train_df, test_df
        )
        all_results['experiment_b'] = res_b
        X_test_s, y_test, attack_types_test = test_data

        # 시각화
        plot_comparison_table(
            res_b,
            os.path.join(FIGURES_DIR, f'comparison_table_{ts}.png')
        )
        plot_roc_curves(
            roc_data,
            os.path.join(FIGURES_DIR, f'roc_curves_{ts}.png')
        )

        # AdaptiveNIDS 상세 시각화
        for name, (clf, scaler, y_pred, y_prob) in trained_models.items():
            if 'AdaptiveNIDS' in name:
                plot_per_attack_recall(
                    next(r['per_attack_recall'] for r in res_b if r['model'] == name),
                    name,
                    os.path.join(FIGURES_DIR, f'per_attack_adaptiveniids_{ts}.png')
                )
                plot_confusion_matrix(
                    y_test, y_pred, name,
                    os.path.join(FIGURES_DIR, f'confusion_matrix_{ts}.png')
                )
                break

        # 결과 요약 테이블 출력
        print("\n" + "=" * 75)
        print(f"{'Model':<28} {'F1':>6} {'Recall':>7} {'Prec':>7} {'Acc':>7} {'FPR':>7} {'AUC':>7}")
        print("-" * 75)
        for r in sorted(res_b, key=lambda x: x['f1'], reverse=True):
            marker = " ◀" if 'AdaptiveNIDS' in r['model'] else ""
            print(f"{r['model']:<28} {r['f1']:>6.4f} {r['recall']:>7.4f} "
                  f"{r['precision']:>7.4f} {r['accuracy']:>7.4f} "
                  f"{r['fpr']:>7.4f} {r['auc']:>7.4f}{marker}")
        print("=" * 75)

    # JSON 저장
    result_path = os.path.join(BENCHMARK_DIR, f'results_{ts}.json')
    # roc fpr/tpr는 list이므로 직접 저장 가능
    with open(result_path, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)

    # CSV 저장 (논문 테이블용)
    if all_results['experiment_b']:
        csv_rows = []
        for r in all_results['experiment_b']:
            csv_rows.append({k: v for k, v in r.items() if k != 'per_attack_recall'})
        pd.DataFrame(csv_rows).to_csv(
            os.path.join(BENCHMARK_DIR, f'comparison_table_{ts}.csv'), index=False
        )

    print(f"\n[벤치마크] 완료")
    print(f"  결과 JSON  : {result_path}")
    print(f"  시각화 PNG : {FIGURES_DIR}/")
    print(f"OUTPUT_RESULT:{result_path}")


if __name__ == '__main__':
    main()
