#!/usr/bin/env python3
"""
Ablation Study — Borderline-Aware Training 효과 검증
─────────────────────────────────────────────────────────────────────────────
논문 실험: 4가지 조건의 학습 전략 비교
  (1) Baseline       : 순수 합성 데이터, 증강 없음
  (2) +Noise         : (1) + 가우시안 노이즈
  (3) +Borderline    : (2) + 경계선 변종 공격 20%
  (4) Full (제안)    : (3) + Heavy Normal 12% + ATTACK_WEIGHTS

각 조건을 동일한 난이도의 테스트셋으로 평가:
  - 테스트셋: 경계선 변종 30% + heavy normal 15% + 노이즈 포함 (현실 근사)

출력:
  data/benchmark/ablation_results.json
  data/benchmark/figures/ablation_*.png
"""

import json
import os
import sys
import time
import warnings

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.font_manager as _fm
import matplotlib.patches as mpatches

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
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings('ignore')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.neighbors import NearestNeighbors
from scripts.generate_packets import (
    NORMAL_GENERATORS, ATTACK_GENERATORS, ATTACK_LABELS_KO,
    _make_borderline_attacks, _make_heavy_normals, _add_noise
)

FEATURE_COLS = [
    'duration', 'protocol', 'src_port', 'dst_port', 'packet_size',
    'packets_per_sec', 'bytes_per_sec', 'unique_dst_ports',
    'connection_count', 'failed_attempts', 'outbound_ratio', 'syn_flag_ratio'
]

BENCHMARK_DIR = 'data/benchmark'
FIGURES_DIR   = os.path.join(BENCHMARK_DIR, 'figures')

# 논문에서 강조할 탐지 어려운 공격 유형 (borderline 효과가 두드러진 유형)
HARD_ATTACKS = ['dns_tunneling', 'slowloris', 'cryptomining', 'credential_stuffing',
                'exfiltration', 'botnet_c2']


# ── 데이터 생성 ────────────────────────────────────────────────────────────

def generate_base(n_total: int, seed: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    """증강 없는 기본 데이터 (공격/정상 분리 반환)"""
    rng = np.random.default_rng(seed)
    n_normal = int(n_total * 0.65)
    n_attack = n_total - n_normal

    # 정상 (10종 균등)
    n_per = n_normal // len(NORMAL_GENERATORS)
    normal_df = pd.concat([g(n_per) for g in NORMAL_GENERATORS], ignore_index=True)

    # 공격 (14종 균등, ablation에서는 가중치 없이 공평 비교)
    n_per_attack = n_attack // len(ATTACK_GENERATORS)
    attack_df = pd.concat(
        [g(max(1, n_per_attack)) for g in ATTACK_GENERATORS.values()],
        ignore_index=True
    )
    return normal_df, attack_df


# ── SMOTE / Borderline-SMOTE 구현 ──────────────────────────────────────────

def _make_smote_attacks(attack_df: pd.DataFrame, frac: float = 0.20,
                        k: int = 5, random_state: int = 42) -> pd.DataFrame:
    """Standard SMOTE: 공격 샘플 매니폴드 내부에서 보간 생성.
    x_syn = x_i + λ·(x_j − x_i),  x_j ∈ k-NN of x_i (attack only), λ~U[0,1]
    """
    rng = np.random.default_rng(random_state)
    X = attack_df[FEATURE_COLS].values
    n_syn = max(1, int(len(X) * frac))

    k_eff = min(k, len(X) - 1)
    nn = NearestNeighbors(n_neighbors=k_eff + 1, algorithm='ball_tree').fit(X)
    _, indices = nn.kneighbors(X)          # shape (N, k_eff+1)

    rows = []
    for _ in range(n_syn):
        i = rng.integers(0, len(X))
        j = indices[i, rng.integers(1, k_eff + 1)]   # skip self (index 0)
        lam = rng.uniform(0, 1)
        x_syn = X[i] + lam * (X[j] - X[i])
        row = dict(zip(FEATURE_COLS, x_syn))
        row['label'] = 1
        row['attack_type'] = attack_df.iloc[i]['attack_type']
        rows.append(row)

    syn_df = pd.DataFrame(rows)
    return pd.concat([attack_df, syn_df], ignore_index=True)


def _make_borderline_smote_attacks(attack_df: pd.DataFrame,
                                   normal_df: pd.DataFrame,
                                   frac: float = 0.20,
                                   k: int = 5,
                                   random_state: int = 42) -> pd.DataFrame:
    """Borderline SMOTE: k-NN이 majority(normal)-dominated인 'danger' 공격 샘플을
    선택해 그 샘플들 사이에서 보간.
    → 경계 근처 공격 매니폴드 *내부* 보간 (BAT와 달리 normal centroid를 향하지 않음).
    """
    rng = np.random.default_rng(random_state)
    X_atk = attack_df[FEATURE_COLS].values
    X_nrm = normal_df[FEATURE_COLS].values
    X_all = np.vstack([X_atk, X_nrm])
    y_all = np.array([1] * len(X_atk) + [0] * len(X_nrm))

    k_eff = min(k, len(X_all) - 1)
    nn_all = NearestNeighbors(n_neighbors=k_eff + 1, algorithm='ball_tree').fit(X_all)
    _, idx_all = nn_all.kneighbors(X_atk)   # neighbors for each attack sample

    # Danger: >k/2 neighbors are normal
    danger_mask = np.array([
        (y_all[idx_all[i, 1:]]==0).sum() > k_eff // 2
        for i in range(len(X_atk))
    ])
    danger_idx = np.where(danger_mask)[0]
    if len(danger_idx) == 0:
        danger_idx = np.arange(len(X_atk))   # fallback: all attack

    X_danger = X_atk[danger_idx]
    k_d = min(k, len(X_danger) - 1) if len(X_danger) > 1 else 1
    nn_d = NearestNeighbors(n_neighbors=k_d + 1, algorithm='ball_tree').fit(X_danger)
    _, idx_d = nn_d.kneighbors(X_danger)

    n_syn = max(1, int(len(X_atk) * frac))
    rows = []
    for _ in range(n_syn):
        di = rng.integers(0, len(danger_idx))
        oi = danger_idx[di]
        if k_d >= 1:
            ni = idx_d[di, rng.integers(1, k_d + 1)]
            oi_n = danger_idx[ni]
        else:
            oi_n = oi
        lam = rng.uniform(0, 1)
        x_syn = X_atk[oi] + lam * (X_atk[oi_n] - X_atk[oi])
        row = dict(zip(FEATURE_COLS, x_syn))
        row['label'] = 1
        row['attack_type'] = attack_df.iloc[oi]['attack_type']
        rows.append(row)

    syn_df = pd.DataFrame(rows)
    return pd.concat([attack_df, syn_df], ignore_index=True)


def build_dataset(normal_df: pd.DataFrame, attack_df: pd.DataFrame,
                  borderline_frac: float = 0.0,
                  heavy_normal_frac: float = 0.0,
                  noise_frac_attack: float = 0.0,
                  noise_frac_normal: float = 0.0,
                  attack_weights: bool = False,
                  smote_type: str = 'none') -> pd.DataFrame:
    """조건별 데이터셋 조립"""
    atk = attack_df.copy()
    nrm = normal_df.copy()

    # BAT 경계선 주입
    if borderline_frac > 0:
        atk = _make_borderline_attacks(atk, frac=borderline_frac)

    # SMOTE 계열 (BAT 대신 적용하는 비교 조건)
    if smote_type == 'smote':
        atk = _make_smote_attacks(atk, frac=borderline_frac if borderline_frac > 0 else 0.20)
    elif smote_type == 'borderline_smote':
        atk = _make_borderline_smote_attacks(atk, nrm,
                                              frac=borderline_frac if borderline_frac > 0 else 0.20)

    if heavy_normal_frac > 0:
        nrm = _make_heavy_normals(nrm, frac=heavy_normal_frac)
    if noise_frac_attack > 0:
        atk = _add_noise(atk, noise_frac=noise_frac_attack)
    if noise_frac_normal > 0:
        nrm = _add_noise(nrm, noise_frac=noise_frac_normal)

    if attack_weights:
        # dns_tunneling, slowloris 2x 오버샘플링
        extras = []
        for atype in ['dns_tunneling', 'slowloris']:
            sub = atk[atk['attack_type'] == atype]
            if len(sub) > 0:
                extras.append(sub.sample(len(sub), replace=True))
        if extras:
            atk = pd.concat([atk] + extras, ignore_index=True)

    df = pd.concat([nrm, atk], ignore_index=True)
    return df.sample(frac=1, random_state=42).reset_index(drop=True)


def generate_hard_testset(n: int = 2000, seed: int = 99) -> pd.DataFrame:
    """논문 평가용 난이도 높은 테스트셋 (경계선 30% + heavy 15% + 노이즈)"""
    nrm, atk = generate_base(n, seed)
    return build_dataset(
        nrm, atk,
        borderline_frac=0.30,
        heavy_normal_frac=0.15,
        noise_frac_attack=0.15,
        noise_frac_normal=0.10,
    )


# ── 학습 / 평가 ────────────────────────────────────────────────────────────

def train_rf(X_train, y_train, n_estimators: int = 150) -> RandomForestClassifier:
    clf = RandomForestClassifier(
        n_estimators=n_estimators, max_depth=15, min_samples_split=5,
        class_weight='balanced', random_state=42, n_jobs=-1
    )
    clf.fit(X_train, y_train)
    return clf


def eval_metrics(y_true, y_pred) -> dict:
    return {
        'f1':        round(f1_score(y_true, y_pred, zero_division=0), 4),
        'recall':    round(recall_score(y_true, y_pred, zero_division=0), 4),
        'precision': round(precision_score(y_true, y_pred, zero_division=0), 4),
        'accuracy':  round(accuracy_score(y_true, y_pred), 4),
        'fpr':       round(float((y_pred[y_true == 0] == 1).mean()), 4),
    }


def per_attack_recall(y_true, y_pred, attack_types) -> dict:
    result = {}
    for atype in ATTACK_GENERATORS.keys():
        mask = np.array(attack_types) == atype
        if mask.sum() == 0:
            result[atype] = None
            continue
        result[atype] = round(float(recall_score(y_true[mask], y_pred[mask], zero_division=0)), 4)
    return result


# ── 시각화 ─────────────────────────────────────────────────────────────────

def plot_overall_comparison(results: list, save_path: str):
    """전체 지표 비교 막대 그래프"""
    conditions = [r['condition'] for r in results]
    metrics = ['f1', 'recall', 'precision', 'fpr']
    labels  = ['F1', 'Recall', 'Precision', 'FPR']
    colors  = ['#3498db', '#2ecc71', '#e67e22', '#e74c3c']

    x = np.arange(len(conditions))
    width = 0.18
    fig, ax = plt.subplots(figsize=(11, 5))

    for i, (metric, label, color) in enumerate(zip(metrics, labels, colors)):
        vals = [r[metric] for r in results]
        bars = ax.bar(x + i * width, vals, width, label=label, color=color, alpha=0.85)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.003,
                    f'{v:.3f}', ha='center', va='bottom', fontsize=7.5, rotation=45)

    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(conditions, fontsize=9)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel('Score', fontsize=11)
    ax.set_title('Ablation Study — Overall Performance Comparison\n(Evaluated on Hard Test Set)',
                 fontsize=12)
    ax.legend(fontsize=9, loc='lower right')
    ax.axhline(y=0.90, color='gray', linestyle='--', lw=1, alpha=0.5, label='Target 0.90')
    ax.grid(axis='y', alpha=0.3)
    # 제안 모델(Full) 열 강조
    full_idx = next((i for i, r in enumerate(results) if 'Full' in r['condition']), None)
    if full_idx is not None:
        ax.axvspan(full_idx - 0.15, full_idx + 0.75, alpha=0.08, color='gold')
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  저장: {save_path}")


def plot_per_attack_recall_heatmap(results: list, save_path: str):
    """공격 유형 × 학습 조건 재현율 히트맵"""
    atypes  = HARD_ATTACKS
    conds   = [r['condition'] for r in results]
    matrix  = np.zeros((len(atypes), len(conds)))

    for j, r in enumerate(results):
        par = r.get('per_attack_recall', {})
        for i, atype in enumerate(atypes):
            v = par.get(atype)
            matrix[i, j] = v if v is not None else 0.0

    ko_labels = [ATTACK_LABELS_KO.get(a, a) for a in atypes]
    fig, ax = plt.subplots(figsize=(9, 5))
    im = ax.imshow(matrix, cmap='RdYlGn', vmin=0.0, vmax=1.0, aspect='auto')

    ax.set_xticks(range(len(conds)))
    ax.set_xticklabels(conds, fontsize=9)
    ax.set_yticks(range(len(atypes)))
    ax.set_yticklabels(ko_labels, fontsize=10)
    ax.set_title('Per-Attack Recall Heatmap (Hard-to-Detect Attacks)\n'
                 'Green ≥ 0.90  |  Yellow 0.70–0.90  |  Red < 0.70', fontsize=11)

    for i in range(len(atypes)):
        for j in range(len(conds)):
            v = matrix[i, j]
            color = 'white' if v < 0.4 else 'black'
            ax.text(j, i, f'{v:.2f}', ha='center', va='center', fontsize=9, color=color)

    plt.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    # 제안 모델 열 테두리
    full_idx = next((j for j, c in enumerate(conds) if 'Full' in c), None)
    if full_idx is not None:
        for i in range(len(atypes)):
            ax.add_patch(plt.Rectangle(
                (full_idx - 0.5, i - 0.5), 1, 1,
                fill=False, edgecolor='gold', lw=2
            ))
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  저장: {save_path}")


def plot_recall_delta(results: list, save_path: str):
    """Baseline 대비 재현율 향상량 (delta) 막대 그래프"""
    baseline = results[0]
    others   = results[1:]
    atypes   = HARD_ATTACKS
    ko_labels = [ATTACK_LABELS_KO.get(a, a) for a in atypes]

    x = np.arange(len(atypes))
    width = 0.22
    colors = ['#3498db', '#2ecc71', '#e74c3c']
    fig, ax = plt.subplots(figsize=(10, 5))

    for i, (res, color) in enumerate(zip(others, colors)):
        deltas = []
        for atype in atypes:
            base_v = baseline['per_attack_recall'].get(atype) or 0
            cur_v  = res['per_attack_recall'].get(atype) or 0
            deltas.append(cur_v - base_v)
        bars = ax.bar(x + i * width, deltas, width, label=res['condition'],
                      color=color, alpha=0.85)
        for bar, d in zip(bars, deltas):
            if abs(d) > 0.005:
                ax.text(bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + (0.005 if d >= 0 else -0.03),
                        f'{d:+.3f}', ha='center', va='bottom', fontsize=8)

    ax.axhline(y=0, color='black', lw=0.8)
    ax.set_xticks(x + width)
    ax.set_xticklabels(ko_labels, fontsize=9)
    ax.set_ylabel('Recall Δ vs Baseline', fontsize=11)
    ax.set_title('Recall Improvement over Baseline\n(Hard-to-Detect Attack Types)',
                 fontsize=12)
    ax.legend(fontsize=9)
    ax.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  저장: {save_path}")


# ── 메인 ───────────────────────────────────────────────────────────────────

def main():
    os.makedirs(BENCHMARK_DIR, exist_ok=True)
    os.makedirs(FIGURES_DIR,   exist_ok=True)

    N_TRAIN = 10000
    SEED    = 42

    print("=" * 65)
    print("Ablation Study: Borderline-Aware Training 효과 분석")
    print("=" * 65)
    print(f"학습 샘플: {N_TRAIN:,}  |  테스트: Hard Set (경계선 30%+노이즈)")
    print()

    # 공통 테스트셋 (모든 조건에 동일 적용)
    print("[준비] Hard 테스트셋 생성...")
    test_df = generate_hard_testset(n=2000, seed=99)
    X_test_raw = test_df[FEATURE_COLS].values
    y_test     = test_df['label'].values
    attack_types_test = test_df['attack_type'].values

    # 6가지 학습 조건 정의 (⑤⑥은 SMOTE 비교 기준선)
    conditions = [
        {
            'name':                '① Baseline',
            'borderline_frac':     0.0,
            'heavy_normal_frac':   0.0,
            'noise_frac_attack':   0.0,
            'noise_frac_normal':   0.0,
            'attack_weights':      False,
            'smote_type':          'none',
        },
        {
            'name':                '② +Noise',
            'borderline_frac':     0.0,
            'heavy_normal_frac':   0.0,
            'noise_frac_attack':   0.10,
            'noise_frac_normal':   0.08,
            'attack_weights':      False,
            'smote_type':          'none',
        },
        {
            'name':                '③ +Borderline',
            'borderline_frac':     0.20,
            'heavy_normal_frac':   0.0,
            'noise_frac_attack':   0.10,
            'noise_frac_normal':   0.08,
            'attack_weights':      False,
            'smote_type':          'none',
        },
        {
            'name':                '④ Full (Proposed)',
            'borderline_frac':     0.20,
            'heavy_normal_frac':   0.12,
            'noise_frac_attack':   0.10,
            'noise_frac_normal':   0.08,
            'attack_weights':      True,
            'smote_type':          'none',
        },
        # ── SMOTE 비교 기준선 (④와 동일 설정, borderline_frac → smote_type 대체) ──
        {
            'name':                '⑤ +SMOTE',
            'borderline_frac':     0.0,      # BAT 주입 없음
            'heavy_normal_frac':   0.12,
            'noise_frac_attack':   0.10,
            'noise_frac_normal':   0.08,
            'attack_weights':      True,
            'smote_type':          'smote',  # 대신 SMOTE 적용 (frac=0.20)
        },
        {
            'name':                '⑥ +BL-SMOTE',
            'borderline_frac':     0.0,      # BAT 주입 없음
            'heavy_normal_frac':   0.12,
            'noise_frac_attack':   0.10,
            'noise_frac_normal':   0.08,
            'attack_weights':      True,
            'smote_type':          'borderline_smote',
        },
    ]

    # 공통 기본 데이터 (노이즈/증강 적용 전)
    print("[데이터] 기본 데이터셋 생성...")
    base_normal, base_attack = generate_base(N_TRAIN, SEED)

    all_results = []

    for cond in conditions:
        print(f"\n[학습] {cond['name']}")
        t0 = time.time()

        # 조건별 데이터셋 조립
        train_df = build_dataset(
            base_normal.copy(), base_attack.copy(),
            borderline_frac   = cond['borderline_frac'],
            heavy_normal_frac = cond['heavy_normal_frac'],
            noise_frac_attack = cond['noise_frac_attack'],
            noise_frac_normal = cond['noise_frac_normal'],
            attack_weights    = cond['attack_weights'],
            smote_type        = cond.get('smote_type', 'none'),
        )

        X_train = train_df[FEATURE_COLS].values
        y_train = train_df['label'].values

        scaler = StandardScaler()
        X_train_s = scaler.fit_transform(X_train)
        X_test_s  = scaler.transform(X_test_raw)

        clf = train_rf(X_train_s, y_train)
        elapsed = time.time() - t0

        y_pred = clf.predict(X_test_s)
        metrics = eval_metrics(y_test, y_pred)
        par = per_attack_recall(y_test, y_pred, attack_types_test)

        result = {
            'condition': cond['name'],
            **metrics,
            'train_size': len(train_df),
            'train_time': round(elapsed, 2),
            'per_attack_recall': par,
        }
        all_results.append(result)

        print(f"  F1={metrics['f1']:.4f}  Recall={metrics['recall']:.4f}  "
              f"Precision={metrics['precision']:.4f}  FPR={metrics['fpr']:.4f}  "
              f"({elapsed:.1f}s)")
        print("  공격 유형별 재현율 (어려운 유형):")
        for atype in HARD_ATTACKS:
            v = par.get(atype)
            ko = ATTACK_LABELS_KO.get(atype, atype)
            flag = "✓" if (v or 0) >= 0.90 else ("△" if (v or 0) >= 0.70 else "✗")
            print(f"    {flag} {ko:<15s}: {v:.4f}" if v is not None else f"    — {ko}")

    # 결과 요약 테이블
    print("\n" + "=" * 65)
    print(f"{'조건':<18} {'F1':>6} {'Recall':>7} {'Prec':>7} {'FPR':>7}")
    print("-" * 65)
    for r in all_results:
        marker = " ◀" if '제안' in r['condition'] else ""
        print(f"{r['condition']:<18} {r['f1']:>6.4f} {r['recall']:>7.4f} "
              f"{r['precision']:>7.4f} {r['fpr']:>7.4f}{marker}")
    print("=" * 65)

    # 시각화
    from datetime import datetime
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    print("\n[시각화] 그래프 생성...")
    plot_overall_comparison(
        all_results,
        os.path.join(FIGURES_DIR, f'ablation_overall_{ts}.png')
    )
    plot_per_attack_recall_heatmap(
        all_results,
        os.path.join(FIGURES_DIR, f'ablation_heatmap_{ts}.png')
    )
    plot_recall_delta(
        all_results,
        os.path.join(FIGURES_DIR, f'ablation_delta_{ts}.png')
    )

    # JSON 저장
    result_path = os.path.join(BENCHMARK_DIR, f'ablation_results_{ts}.json')
    with open(result_path, 'w', encoding='utf-8') as f:
        json.dump({'timestamp': ts, 'conditions': all_results}, f,
                  ensure_ascii=False, indent=2)
    print(f"\n[완료] 결과: {result_path}")
    print(f"[완료] 그래프: {FIGURES_DIR}/ablation_*_{ts}.png")
    print(f"OUTPUT_RESULT:{result_path}")


if __name__ == '__main__':
    main()
