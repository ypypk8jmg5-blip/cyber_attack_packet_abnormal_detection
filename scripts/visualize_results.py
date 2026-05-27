#!/usr/bin/env python3
"""
논문용 시각화 생성기 — Figure 1~7
─────────────────────────────────────────────────────────────────────────────
Figure 1: 시스템 아키텍처 개요도
Figure 2: 14종 공격 유형별 재현율 (현재 best_model.pkl)
Figure 3: 학습 수렴 곡선 (F1/Recall/Precision vs 사이클)
Figure 4: 피처 중요도 Top-12
Figure 5: ROC / Precision-Recall 곡선 (합성 테스트셋)
Figure 6: 데이터셋 크기 vs 성능 (Learning Curve)
Figure 7: 정상/공격 피처 분포 박스플롯

출력: data/benchmark/figures/fig{N}_*.png
"""

import json
import os
import sys
import warnings

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    roc_curve, precision_recall_curve, auc,
    f1_score, recall_score, precision_score
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings('ignore')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.generate_packets import (
    NORMAL_GENERATORS, ATTACK_GENERATORS, ATTACK_LABELS_KO
)

FEATURE_COLS = [
    'duration', 'protocol', 'src_port', 'dst_port', 'packet_size',
    'packets_per_sec', 'bytes_per_sec', 'unique_dst_ports',
    'connection_count', 'failed_attempts', 'outbound_ratio', 'syn_flag_ratio'
]

FEATURE_LABELS_KO = {
    'duration': 'Duration(s)', 'protocol': 'Protocol',
    'src_port': 'Src Port', 'dst_port': 'Dst Port',
    'packet_size': 'Pkt Size', 'packets_per_sec': 'Pkts/s',
    'bytes_per_sec': 'Bytes/s', 'unique_dst_ports': 'Uniq Dst Ports',
    'connection_count': 'Conn Count', 'failed_attempts': 'Failed Attempts',
    'outbound_ratio': 'Outbound Ratio', 'syn_flag_ratio': 'SYN Ratio',
}

FIGURES_DIR   = 'data/benchmark/figures'
BENCHMARK_DIR = 'data/benchmark'
BEST_MODEL    = 'data/models/best_model.pkl'
HISTORY_PATH  = 'data/metrics/history.json'
LATEST_PATH   = 'data/metrics/latest.json'

# ── 한글 폰트 설정 ────────────────────────────────────────────────────────────
import matplotlib.font_manager as _fm
_KO_CANDIDATES = [
    'Apple SD Gothic Neo', 'AppleGothic', 'Nanum Gothic',
    'NanumGothic', 'Malgun Gothic', 'NanumBarunGothic',
]
_available = {f.name for f in _fm.fontManager.ttflist}
_ko_font = next((f for f in _KO_CANDIDATES if f in _available), None)
if _ko_font:
    plt.rcParams['font.family'] = _ko_font
plt.rcParams['axes.unicode_minus'] = False   # 마이너스 기호 깨짐 방지

# ── 공통 스타일 ──────────────────────────────────────────────────────────────
PLT_STYLE = {
    'axes.facecolor':    '#f8f9fa',
    'figure.facecolor':  'white',
    'axes.grid':         True,
    'grid.alpha':        0.35,
    'axes.spines.top':   False,
    'axes.spines.right': False,
    'font.size':         10,
}
plt.rcParams.update(PLT_STYLE)


def _save(fig, name: str):
    path = os.path.join(FIGURES_DIR, name)
    fig.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  [저장] {path}")
    return path


# ── Figure 1: 시스템 아키텍처 ────────────────────────────────────────────────

def fig1_architecture():
    """AdaptiveNIDS 7-Layer 파이프라인 다이어그램"""
    fig, ax = plt.subplots(figsize=(12, 7))
    ax.set_xlim(0, 12); ax.set_ylim(0, 7)
    ax.axis('off')
    ax.set_facecolor('white')

    layers = [
        (6.4, '① Traffic Generation (Layer 0)',  '#3498db', '14 Attack + 10 Normal Types\nBorderline 20% + Heavy Normal 12%'),
        (5.2, '② Preprocessing / Scaling (Layer 1)', '#2ecc71', '12-Feature Vector Extraction\nStandardScaler'),
        (4.0, '③ Detection Model (Layer 2)',     '#9b59b6', 'RandomForest (n_est=150~300)\n5-Fold CV · class_weight=balanced'),
        (2.8, '④ Evaluation / Decision (Layer 3)', '#e67e22', 'F1≥0.92 · Recall≥0.90 · Prec≥0.88\n14-Class Per-Attack Recall'),
        (1.6, '⑤ Alert System (Layer 4)',        '#e74c3c', 'CRITICAL/HIGH/MEDIUM/LOW Classification\nC2 Port Signature Override'),
    ]

    arrows_x = 6.0
    for y, title, color, desc in layers:
        # 박스
        rect = mpatches.FancyBboxPatch((1.0, y - 0.45), 10, 0.90,
                                        boxstyle='round,pad=0.05',
                                        facecolor=color, alpha=0.15,
                                        edgecolor=color, linewidth=2)
        ax.add_patch(rect)
        ax.text(1.4, y, title, fontsize=10, fontweight='bold', va='center', color=color)
        ax.text(6.5, y, desc, fontsize=8.5, va='center', color='#2c3e50')
        # 화살표
        if y > 1.6:
            ax.annotate('', xy=(arrows_x, y - 0.55), xytext=(arrows_x, y - 0.45),
                        arrowprops=dict(arrowstyle='->', color='#7f8c8d', lw=1.5))

    # 재학습 루프
    ax.annotate('', xy=(0.6, 5.8), xytext=(0.6, 2.2),
                arrowprops=dict(arrowstyle='<-', color='#c0392b', lw=2,
                                connectionstyle='arc3,rad=0.0'))
    ax.text(0.05, 4.0, 'Retrain\nLoop', fontsize=8, color='#c0392b', rotation=90, va='center')

    ax.set_title('AdaptiveNIDS: MLOps-Driven Network Intrusion Detection Pipeline',
                 fontsize=13, fontweight='bold', pad=12)
    return _save(fig, 'fig1_architecture.png')


# ── Figure 2: 14종 공격 유형별 재현율 ──────────────────────────────────────────

def fig2_per_attack_recall():
    if not os.path.exists(LATEST_PATH):
        print("  [SKIP] latest.json 없음"); return
    with open(LATEST_PATH) as f:
        data = json.load(f)
    par = data.get('per_attack_recall', {})
    if not par:
        print("  [SKIP] per_attack_recall 없음"); return

    atypes = list(par.keys())
    values = [par[a] for a in atypes]
    ko     = [ATTACK_LABELS_KO.get(a, a) for a in atypes]
    colors = ['#2ecc71' if v >= 0.90 else ('#f39c12' if v >= 0.70 else '#e74c3c')
              for v in values]

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.barh(ko, values, color=colors, height=0.6, edgecolor='white', linewidth=0.5)
    ax.axvline(x=0.90, color='#e74c3c', ls='--', lw=1.5, label='Target Recall = 0.90')
    ax.axvline(x=1.00, color='#95a5a6', ls=':',  lw=1.0)
    for bar, v in zip(bars, values):
        ax.text(min(v + 0.008, 1.02), bar.get_y() + bar.get_height() / 2,
                f'{v:.3f}', va='center', fontsize=9)
    ax.set_xlim(0, 1.10)
    ax.set_xlabel('Recall', fontsize=11)
    ax.set_title(f'Per-Attack Type Recall — AdaptiveNIDS\n'
                 f'(14 Attack Types, F1={data["metrics"]["f1_score"]:.4f})', fontsize=12)
    ax.legend(fontsize=9)
    # 범례 패치
    patches = [
        mpatches.Patch(color='#2ecc71', label='≥ 0.90 (Target Met)'),
        mpatches.Patch(color='#f39c12', label='0.70–0.90 (Needs Improvement)'),
        mpatches.Patch(color='#e74c3c', label='< 0.70 (Below Target)'),
    ]
    ax.legend(handles=patches, fontsize=8, loc='lower right')
    plt.tight_layout()
    return _save(fig, 'fig2_per_attack_recall.png')


# ── Figure 3: 학습 수렴 곡선 ──────────────────────────────────────────────────

def fig3_learning_convergence():
    if not os.path.exists(HISTORY_PATH):
        print("  [SKIP] history.json 없음"); return
    with open(HISTORY_PATH) as f:
        hist = json.load(f)
    cycles = hist.get('cycles', [])
    if len(cycles) < 2:
        print("  [SKIP] 사이클 데이터 부족"); return

    xs  = [c['cycle']     for c in cycles]
    f1s = [c['f1']        for c in cycles]
    rcs = [c['recall']    for c in cycles]
    prs = [c.get('precision', c['f1']) for c in cycles]

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot(xs, f1s, 'o-', color='#3498db', lw=2, ms=4, label='F1 Score')
    ax.plot(xs, rcs, 's-', color='#2ecc71', lw=2, ms=4, label='Recall')
    ax.plot(xs, prs, '^-', color='#e67e22', lw=2, ms=4, label='Precision')
    ax.axhline(y=0.92, color='#3498db', ls='--', lw=1, alpha=0.5)
    ax.axhline(y=0.90, color='#2ecc71', ls='--', lw=1, alpha=0.5)
    ax.axhline(y=0.88, color='#e67e22', ls='--', lw=1, alpha=0.5)
    ax.fill_between(xs, 0.88, 1.0, alpha=0.04, color='#2ecc71')
    ax.set_xlim(min(xs) - 0.2, max(xs) + 0.2)
    ax.set_ylim(max(0.5, min(f1s + rcs + prs) - 0.05), 1.02)
    ax.set_xlabel('Training Cycle', fontsize=11)
    ax.set_ylabel('Score', fontsize=11)
    ax.set_title('Learning Convergence Curve — AdaptiveNIDS\n'
                 '(Dashed lines: F1≥0.92 / Recall≥0.90 / Precision≥0.88)', fontsize=12)
    ax.legend(fontsize=10)
    plt.tight_layout()
    return _save(fig, 'fig3_convergence.png')


# ── Figure 4: 피처 중요도 ─────────────────────────────────────────────────────

def fig4_feature_importance():
    if not os.path.exists(BEST_MODEL):
        print("  [SKIP] best_model.pkl 없음"); return
    bundle = joblib.load(BEST_MODEL)
    clf    = bundle['model']
    if not hasattr(clf, 'feature_importances_'):
        print("  [SKIP] feature_importances_ 없음"); return
    imps  = clf.feature_importances_
    pairs = sorted(zip(FEATURE_COLS, imps), key=lambda x: x[1], reverse=True)
    feats = [FEATURE_LABELS_KO.get(p[0], p[0]) for p in pairs]
    vals  = [p[1] for p in pairs]
    colors = plt.cm.Blues(np.linspace(0.4, 0.9, len(feats)))[::-1]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.barh(feats[::-1], vals[::-1], color=colors, height=0.6,
                   edgecolor='white', linewidth=0.5)
    for bar, v in zip(bars, vals[::-1]):
        ax.text(bar.get_width() + 0.002, bar.get_y() + bar.get_height() / 2,
                f'{v:.4f}', va='center', fontsize=9)
    ax.set_xlabel('Feature Importance (Gini)', fontsize=11)
    ax.set_title('Feature Importance — RandomForest Classifier\n'
                 '(AdaptiveNIDS, 12-Feature Vector)', fontsize=12)
    ax.set_xlim(0, max(vals) * 1.15)
    plt.tight_layout()
    return _save(fig, 'fig4_feature_importance.png')


# ── Figure 5: ROC / PR 곡선 ───────────────────────────────────────────────────

def fig5_roc_pr():
    if not os.path.exists(BEST_MODEL):
        print("  [SKIP] best_model.pkl 없음"); return

    bundle = joblib.load(BEST_MODEL)
    clf, scaler = bundle['model'], bundle['scaler']

    # 테스트 데이터 생성
    from scripts.generate_packets import _make_borderline_attacks, _make_heavy_normals, _add_noise
    n_per = 100
    normal_dfs = [g(n_per) for g in NORMAL_GENERATORS]
    attack_dfs = [g(n_per) for g in ATTACK_GENERATORS.values()]
    nrm = pd.concat(normal_dfs, ignore_index=True)
    atk = pd.concat(attack_dfs, ignore_index=True)
    atk = _make_borderline_attacks(atk, frac=0.30)
    nrm = _make_heavy_normals(nrm, frac=0.15)
    test_df = pd.concat([nrm, atk], ignore_index=True).sample(frac=1, random_state=42)

    X = scaler.transform(test_df[FEATURE_COLS].values)
    y_true = test_df['label'].values
    y_prob = clf.predict_proba(X)[:, 1]

    fpr_arr, tpr_arr, _ = roc_curve(y_true, y_prob)
    roc_auc = auc(fpr_arr, tpr_arr)
    prec_arr, rec_arr, _ = precision_recall_curve(y_true, y_prob)
    pr_auc = auc(rec_arr, prec_arr)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # ROC
    ax1.plot(fpr_arr, tpr_arr, color='#3498db', lw=2, label=f'AdaptiveNIDS (AUC={roc_auc:.4f})')
    ax1.plot([0, 1], [0, 1], 'k--', lw=1, label='Random Classifier')
    ax1.fill_between(fpr_arr, tpr_arr, alpha=0.10, color='#3498db')
    ax1.set_xlabel('False Positive Rate', fontsize=11)
    ax1.set_ylabel('True Positive Rate', fontsize=11)
    ax1.set_title('ROC Curve', fontsize=12)
    ax1.legend(fontsize=9); ax1.set_xlim(-0.02, 1.02); ax1.set_ylim(-0.02, 1.02)

    # PR
    ax2.plot(rec_arr, prec_arr, color='#e74c3c', lw=2, label=f'AdaptiveNIDS (AP={pr_auc:.4f})')
    ax2.axhline(y=y_true.mean(), color='k', ls='--', lw=1, label=f'Baseline (prevalence={y_true.mean():.2f})')
    ax2.fill_between(rec_arr, prec_arr, alpha=0.10, color='#e74c3c')
    ax2.set_xlabel('Recall', fontsize=11)
    ax2.set_ylabel('Precision', fontsize=11)
    ax2.set_title('Precision-Recall Curve', fontsize=12)
    ax2.legend(fontsize=9); ax2.set_xlim(-0.02, 1.02); ax2.set_ylim(-0.02, 1.02)

    fig.suptitle('ROC and Precision-Recall Curves — AdaptiveNIDS\n'
                 '(Evaluated on Hard Test Set with 30% Borderline Variants)', fontsize=12)
    plt.tight_layout()
    return _save(fig, 'fig5_roc_pr.png')


# ── Figure 6: Learning Curve (데이터셋 크기 vs 성능) ─────────────────────────

def fig6_learning_curve():
    """학습 샘플 수 증가에 따른 성능 변화"""
    print("  [학습 중] Learning Curve 계산 (수 분 소요)...")
    from scripts.generate_packets import _make_borderline_attacks, _make_heavy_normals, _add_noise

    sizes = [500, 1000, 2000, 4000, 6000, 8000, 12000]
    seed = 42

    # 공통 테스트셋
    n_test = 1000
    test_normal = pd.concat([g(n_test // len(NORMAL_GENERATORS)) for g in NORMAL_GENERATORS], ignore_index=True)
    test_attack = pd.concat([g(n_test // len(ATTACK_GENERATORS)) for g in ATTACK_GENERATORS.values()], ignore_index=True)
    test_attack = _make_borderline_attacks(test_attack, frac=0.30)
    test_df = pd.concat([test_normal, test_attack], ignore_index=True).sample(frac=1, random_state=99)
    X_test_raw = test_df[FEATURE_COLS].values
    y_test = test_df['label'].values

    results = {'size': [], 'f1': [], 'recall': [], 'precision': []}

    for size in sizes:
        n_normal = int(size * 0.65)
        n_attack = size - n_normal
        nrm = pd.concat([g(max(1, n_normal // len(NORMAL_GENERATORS))) for g in NORMAL_GENERATORS], ignore_index=True)
        atk = pd.concat([g(max(1, n_attack // len(ATTACK_GENERATORS))) for g in ATTACK_GENERATORS.values()], ignore_index=True)
        atk = _make_borderline_attacks(atk, frac=0.20)
        nrm = _make_heavy_normals(nrm, frac=0.12)
        atk = _add_noise(atk, noise_frac=0.10)
        nrm = _add_noise(nrm, noise_frac=0.08)
        train_df = pd.concat([nrm, atk], ignore_index=True)

        scaler = StandardScaler()
        X_tr = scaler.fit_transform(train_df[FEATURE_COLS].values)
        X_te = scaler.transform(X_test_raw)
        y_tr = train_df['label'].values

        clf = RandomForestClassifier(n_estimators=100, max_depth=15,
                                     class_weight='balanced', random_state=seed, n_jobs=-1)
        clf.fit(X_tr, y_tr)
        y_pred = clf.predict(X_te)

        results['size'].append(size)
        results['f1'].append(round(f1_score(y_test, y_pred, zero_division=0), 4))
        results['recall'].append(round(recall_score(y_test, y_pred, zero_division=0), 4))
        results['precision'].append(round(precision_score(y_test, y_pred, zero_division=0), 4))
        print(f"    n={size:>6,} → F1={results['f1'][-1]:.4f}  Recall={results['recall'][-1]:.4f}")

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot(results['size'], results['f1'],        'o-', color='#3498db', lw=2, ms=6, label='F1 Score')
    ax.plot(results['size'], results['recall'],    's-', color='#2ecc71', lw=2, ms=6, label='Recall')
    ax.plot(results['size'], results['precision'], '^-', color='#e67e22', lw=2, ms=6, label='Precision')
    ax.axhline(y=0.92, color='#3498db', ls='--', lw=1, alpha=0.5)
    ax.axhline(y=0.90, color='#2ecc71', ls='--', lw=1, alpha=0.5)
    ax.axhline(y=0.88, color='#e67e22', ls='--', lw=1, alpha=0.5)
    for size in [8000, 12000]:
        ax.axvline(x=size, color='#95a5a6', ls=':', lw=1)
    ax.set_xlabel('Training Set Size (samples)', fontsize=11)
    ax.set_ylabel('Score', fontsize=11)
    ax.set_title('Learning Curve — AdaptiveNIDS\n'
                 '(Performance vs Training Data Size, Hard Test Set)', fontsize=12)
    ax.legend(fontsize=10)
    ax.set_ylim(max(0, min(results['f1'] + results['recall'] + results['precision']) - 0.05), 1.02)
    plt.tight_layout()
    return _save(fig, 'fig6_learning_curve.png')


# ── Figure 7: 피처 분포 박스플롯 ────────────────────────────────────────────────

def fig7_feature_distributions():
    """정상 vs 공격 트래픽의 핵심 피처 분포"""
    n = 500
    normal_df = pd.concat([g(n // len(NORMAL_GENERATORS)) for g in NORMAL_GENERATORS])
    attack_df = pd.concat([g(n // len(ATTACK_GENERATORS)) for g in ATTACK_GENERATORS.values()])
    normal_df['class'] = 'Normal'
    attack_df['class'] = 'Attack'
    df = pd.concat([normal_df, attack_df], ignore_index=True)

    # 구분력 높은 피처 6개만 선택
    key_feats = ['packets_per_sec', 'bytes_per_sec', 'failed_attempts',
                 'connection_count', 'syn_flag_ratio', 'outbound_ratio']
    key_labels = [FEATURE_LABELS_KO[f] for f in key_feats]

    fig, axes = plt.subplots(2, 3, figsize=(13, 7))
    axes = axes.flatten()

    for ax, feat, label in zip(axes, key_feats, key_labels):
        normal_vals = df[df['class'] == 'Normal'][feat].clip(
            upper=df[feat].quantile(0.99))
        attack_vals = df[df['class'] == 'Attack'][feat].clip(
            upper=df[feat].quantile(0.99))
        bp = ax.boxplot([normal_vals, attack_vals],
                        labels=['Normal', 'Attack'],
                        patch_artist=True,
                        medianprops=dict(color='black', lw=2))
        bp['boxes'][0].set_facecolor('#3498db')
        bp['boxes'][0].set_alpha(0.6)
        bp['boxes'][1].set_facecolor('#e74c3c')
        bp['boxes'][1].set_alpha(0.6)
        ax.set_title(label, fontsize=10, fontweight='bold')
        ax.set_ylabel('Value', fontsize=9)

    fig.suptitle('Feature Distribution: Normal vs Attack Traffic\n'
                 '(Whiskers: 1.5×IQR, clipped at 99th percentile)', fontsize=12)
    plt.tight_layout()
    return _save(fig, 'fig7_feature_dist.png')


# ── 메인 ───────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(FIGURES_DIR, exist_ok=True)
    from datetime import datetime

    print("=" * 55)
    print("논문용 시각화 생성 (Figure 1~7)")
    print("=" * 55)
    print(f"출력 디렉토리: {FIGURES_DIR}/")
    print()

    tasks = [
        ("Figure 1: 시스템 아키텍처",        fig1_architecture),
        ("Figure 2: 14종 공격 재현율",        fig2_per_attack_recall),
        ("Figure 3: 학습 수렴 곡선",          fig3_learning_convergence),
        ("Figure 4: 피처 중요도",             fig4_feature_importance),
        ("Figure 5: ROC / PR 곡선",          fig5_roc_pr),
        ("Figure 6: Learning Curve",         fig6_learning_curve),
        ("Figure 7: 피처 분포 박스플롯",       fig7_feature_distributions),
    ]

    generated = []
    for name, fn in tasks:
        print(f"[{name}]")
        try:
            path = fn()
            if path:
                generated.append(path)
        except Exception as e:
            print(f"  [ERROR] {e}")
        print()

    print(f"완료: {len(generated)}/{len(tasks)}개 생성")
    for p in generated:
        print(f"  {p}")


if __name__ == '__main__':
    main()
