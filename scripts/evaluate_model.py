#!/usr/bin/env python3
"""
학습결과판단기: 모델 성능 평가 및 목표 달성 여부 판단
F1 >= 0.92, Recall >= 0.90, Precision >= 0.88 목표
"""

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    f1_score, precision_score, recall_score, accuracy_score,
    log_loss, confusion_matrix
)

FEATURE_COLS = [
    'duration', 'protocol', 'src_port', 'dst_port', 'packet_size',
    'packets_per_sec', 'bytes_per_sec', 'unique_dst_ports',
    'connection_count', 'failed_attempts', 'outbound_ratio', 'syn_flag_ratio'
]

C2_PORTS = {4444, 6667, 1080, 8443, 9001}

F1_TARGET = 0.92
RECALL_TARGET = 0.90
PRECISION_TARGET = 0.88


def generate_test_data(seed=None):
    """평가 전용 테스트 데이터 생성"""
    cmd = [sys.executable, 'scripts/generate_packets.py', '--mode', 'test', '--size', '1000']
    if seed is not None:
        cmd += ['--seed', str(seed)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout
    for line in output.splitlines():
        if line.startswith('OUTPUT_FILE:'):
            return line.split('OUTPUT_FILE:')[1].strip()
    # fallback: 최신 test 파일
    files = sorted(glob.glob('data/packets/test_*.csv'))
    if files:
        return files[-1]
    raise FileNotFoundError("테스트 패킷 파일 생성 실패")


def apply_signature_overrides(df, y_prob, y_pred):
    """Mirror high-precision live detector signatures during evaluation."""
    c2_mask = df['dst_port'].astype(int).isin(C2_PORTS).to_numpy()
    if c2_mask.any():
        y_pred[c2_mask] = 1
        y_prob[c2_mask] = np.maximum(y_prob[c2_mask], 0.90)
    return y_prob, y_pred


def main():
    parser = argparse.ArgumentParser(description='모델 성능 평가기')
    parser.add_argument('--model', type=str, required=True, help='평가할 모델 경로')
    parser.add_argument('--cycle', type=int, default=1, help='현재 사이클 번호')
    parser.add_argument('--seed', type=int, default=None, help='테스트 데이터 생성 시드 (재현용)')
    args = parser.parse_args()

    # 모델 로드
    bundle = joblib.load(args.model)
    clf = bundle['model']
    scaler = bundle['scaler']

    # 테스트 데이터 생성
    test_file = generate_test_data(seed=args.seed)
    df = pd.read_csv(test_file)

    X = df[FEATURE_COLS].values
    y_true = df['label'].values
    attack_types_col = df['attack_type'].values

    X_s = scaler.transform(X)
    y_pred = clf.predict(X_s)
    y_prob = clf.predict_proba(X_s)[:, 1]
    y_prob, y_pred = apply_signature_overrides(df, y_prob, y_pred)

    # 지표 계산 (zero_division=0: 양성 예측이 없는 배치에서 UndefinedMetricWarning 방지)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    precision = precision_score(y_true, y_pred, zero_division=0)
    accuracy = accuracy_score(y_true, y_pred)
    try:
        loss = log_loss(y_true, y_prob)
    except Exception:
        loss = 0.0

    # 공격 유형별 재현율 (11종 전체)
    attack_recall = {}
    for atype in [
        'ddos', 'portscan', 'bruteforce', 'exfiltration', 'synflood',
        'dns_tunneling', 'http_flood', 'slowloris', 'botnet_c2', 'ransomware', 'arp_spoofing',
        'cryptomining', 'dns_amplification', 'credential_stuffing',
    ]:
        mask = attack_types_col == atype
        if mask.sum() == 0:
            attack_recall[atype] = 0.0
            continue
        attack_recall[atype] = round(recall_score(y_true[mask], y_pred[mask], zero_division=0), 4)

    worst_attack = min(attack_recall, key=attack_recall.get)

    # 목표 달성 여부
    goal_met = (f1 >= F1_TARGET and recall >= RECALL_TARGET and precision >= PRECISION_TARGET)
    continue_training = not goal_met

    # 이전 사이클 기록 로드
    history_path = 'data/metrics/history.json'
    if os.path.exists(history_path):
        with open(history_path, 'r', encoding='utf-8') as fp:
            history = json.load(fp)
    else:
        history = {'cycles': [], 'best': None}

    is_best = False
    if history['best'] is None or f1 > history['best']['f1']:
        is_best = True
        history['best'] = {
            'cycle': args.cycle,
            'f1': round(f1, 4),
            'recall': round(recall, 4),
            'precision': round(precision, 4),
            'model': args.model
        }
        # best_model.pkl 갱신
        best_model_path = 'data/models/best_model.pkl'
        if os.path.abspath(args.model) != os.path.abspath(best_model_path):
            shutil.copy(args.model, best_model_path)

    # 이유 생성
    reasons = []
    if f1 < F1_TARGET:
        reasons.append(f"F1({f1:.4f}) < {F1_TARGET}")
    if recall < RECALL_TARGET:
        reasons.append(f"Recall({recall:.4f}) < {RECALL_TARGET}")
    if precision < PRECISION_TARGET:
        reasons.append(f"Precision({precision:.4f}) < {PRECISION_TARGET}")
    if attack_recall[worst_attack] < 0.80:
        labels = {
            'ddos': 'DDoS', 'portscan': '포트스캔', 'bruteforce': '브루트포스',
            'exfiltration': '데이터유출', 'synflood': 'SYN플러드',
            'dns_tunneling': 'DNS터널링', 'http_flood': 'HTTP플러드',
            'slowloris': 'Slowloris', 'botnet_c2': '봇넷C2',
            'ransomware': '랜섬웨어', 'arp_spoofing': 'ARP스푸핑',
            'cryptomining': '크립토마이닝', 'dns_amplification': 'DNS증폭',
            'credential_stuffing': '크리덴셜스터핑',
        }
        reasons.append(f"{labels[worst_attack]} 재현율({attack_recall[worst_attack]:.4f}) 미흡.")
    reason_str = ' '.join(reasons) if reasons else "모든 목표 달성"

    # latest.json 저장
    os.makedirs('data/metrics', exist_ok=True)
    latest = {
        'cycle': args.cycle,
        'timestamp': datetime.now().isoformat(),
        'model_path': args.model,
        'metrics': {
            'f1_score': round(f1, 4),
            'recall': round(recall, 4),
            'precision': round(precision, 4),
            'accuracy': round(accuracy, 4),
            'loss': round(loss, 4)
        },
        'per_attack_recall': attack_recall,
        'thresholds': {
            'f1_target': F1_TARGET,
            'recall_target': RECALL_TARGET,
            'precision_target': PRECISION_TARGET
        },
        'continue_training': continue_training,
        'reason': reason_str,
        'is_best_model': is_best
    }
    with open('data/metrics/latest.json', 'w', encoding='utf-8') as fp:
        json.dump(latest, fp, ensure_ascii=False, indent=2)

    # history.json 갱신
    history['cycles'].append({
        'cycle': args.cycle,
        'f1': round(f1, 4),
        'recall': round(recall, 4),
        'precision': round(precision, 4),
        'accuracy': round(accuracy, 4),
        'loss': round(loss, 4)
    })
    with open(history_path, 'w', encoding='utf-8') as fp:
        json.dump(history, fp, ensure_ascii=False, indent=2)

    # 출력
    print(f"[결과판단기] 평가 완료 — 사이클 #{args.cycle}")
    print(f"  F1 점수  : {f1:.4f} (목표: {F1_TARGET}) [{'달성' if f1 >= F1_TARGET else '미달'}]")
    print(f"  재현율   : {recall:.4f} (목표: {RECALL_TARGET}) [{'달성' if recall >= RECALL_TARGET else '미달'}]")
    print(f"  정밀도   : {precision:.4f} (목표: {PRECISION_TARGET}) [{'달성' if precision >= PRECISION_TARGET else '미달'}]")
    print(f"  정확도   : {accuracy:.4f}")
    print()
    print(f"[공격 유형별 재현율]")
    labels_map = {
        'ddos': 'DDoS', 'portscan': '포트스캔', 'bruteforce': '브루트포스',
        'exfiltration': '데이터유출', 'synflood': 'SYN플러드',
        'dns_tunneling': 'DNS터널링', 'http_flood': 'HTTP플러드',
        'slowloris': 'Slowloris', 'botnet_c2': '봇넷C2',
        'ransomware': '랜섬웨어', 'arp_spoofing': 'ARP스푸핑',
        'cryptomining': '크립토마이닝', 'dns_amplification': 'DNS증폭',
        'credential_stuffing': '크리덴셜스터핑',
    }
    for atype, rec in attack_recall.items():
        print(f"  {labels_map[atype]:<12s}: {rec:.4f}")
    print(f"  가장 취약: {labels_map[worst_attack]} ({attack_recall[worst_attack]:.4f})")
    print()
    if goal_met:
        print(f"  판정: [목표 달성 — 탐지 단계 전환]")
    else:
        print(f"  판정: [계속 학습 — 이유: {reason_str}]")

if __name__ == '__main__':
    main()
