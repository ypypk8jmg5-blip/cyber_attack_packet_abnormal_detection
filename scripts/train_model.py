#!/usr/bin/env python3
"""
AI 학습기: RandomForest 이진 분류 모델 학습
패킷 데이터를 읽어 정상/비정상 분류 모델 학습 및 저장
"""

import argparse
import glob
import json
import os
import shutil
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler


FEATURE_COLS = [
    'duration', 'protocol', 'src_port', 'dst_port', 'packet_size',
    'packets_per_sec', 'bytes_per_sec', 'unique_dst_ports',
    'connection_count', 'failed_attempts', 'outbound_ratio', 'syn_flag_ratio'
]


def load_data(input_pattern):
    files = sorted(glob.glob(input_pattern))
    if not files:
        raise FileNotFoundError(f"패킷 파일 없음: {input_pattern}")
    df = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)
    return df


def main():
    parser = argparse.ArgumentParser(description='AI 모델 학습기')
    parser.add_argument('--input', type=str, required=True, help='입력 패킷 파일 (glob 패턴 가능)')
    parser.add_argument('--cycle', type=int, default=1, help='현재 사이클 번호')
    args = parser.parse_args()

    start_time = time.time()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')

    # 데이터 로드
    try:
        df = load_data(args.input)
    except FileNotFoundError as e:
        print(f"[ERROR] 패킷 파일 없음 — 패킷생성기 먼저 실행 필요: {e}")
        raise SystemExit(1)

    X = df[FEATURE_COLS].values
    y = df['label'].values

    # 전처리
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    # n_estimators: 기본 150, 사이클마다 +20 (최대 300) — 데이터 증량에 맞춰 기본값 상향
    n_estimators = min(150 + (args.cycle - 1) * 20, 300)

    print(f"[AI학습기] 학습 시작")
    print(f"  입력 파일: {args.input}")
    print(f"  총 샘플: {len(df):,}건 (학습: {len(X_train):,} | 검증: {len(X_test):,})")
    print(f"  모델: RandomForest (n_estimators={n_estimators})")
    print()

    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=15,
        min_samples_split=5,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )

    # 5-fold 교차검증
    print(f"[AI학습기] 학습 진행 중...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = []
    for fold_idx, (tr_idx, val_idx) in enumerate(cv.split(X_train_s, y_train), 1):
        X_tr, X_val = X_train_s[tr_idx], X_train_s[val_idx]
        y_tr, y_val = y_train[tr_idx], y_train[val_idx]
        clf_fold = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=15,
            min_samples_split=5,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        clf_fold.fit(X_tr, y_tr)
        train_acc = clf_fold.score(X_tr, y_tr)
        val_acc = clf_fold.score(X_val, y_val)
        cv_scores.append(val_acc)
        print(f"  [{fold_idx}/5 fold] Train acc: {train_acc:.4f} | Val acc: {val_acc:.4f}")

    cv_mean = np.mean(cv_scores)
    cv_std = np.std(cv_scores)
    print(f"  평균 CV 정확도: {cv_mean:.4f} ± {cv_std:.4f}")
    print()

    # 최종 모델 학습 (전체 학습 데이터)
    clf.fit(X_train_s, y_train)

    # 피처 중요도
    importances = sorted(
        zip(FEATURE_COLS, clf.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    print("[피처 중요도]")
    for rank, (feat, imp) in enumerate(importances[:5], 1):
        print(f"  {rank}. {feat:<20s}: {imp:.4f}")

    # 저장
    os.makedirs('data/models', exist_ok=True)
    model_path = f'data/models/model_cycle{args.cycle}_{timestamp}.pkl'
    model_bundle = {'model': clf, 'scaler': scaler, 'features': FEATURE_COLS}
    joblib.dump(model_bundle, model_path)

    # best_model.pkl — 이 시점엔 일단 저장 (evaluator가 덮어쓸 것)
    best_path = 'data/models/best_model.pkl'
    if not os.path.exists(best_path):
        shutil.copy(model_path, best_path)

    elapsed = time.time() - start_time
    m, s = divmod(int(elapsed), 60)

    # 메타 JSON 저장
    meta = {
        'cycle': args.cycle,
        'timestamp': datetime.now().isoformat(),
        'model_path': model_path,
        'input_file': args.input,
        'n_samples': len(df),
        'n_features': len(FEATURE_COLS),
        'n_estimators': n_estimators,
        'cv_accuracy_mean': round(cv_mean, 4),
        'cv_accuracy_std': round(cv_std, 4),
        'training_time_sec': round(elapsed, 1),
        'feature_importance': {f: round(i, 4) for f, i in importances}
    }
    meta_path = f'data/models/training_meta_{timestamp}.json'
    with open(meta_path, 'w', encoding='utf-8') as fp:
        json.dump(meta, fp, ensure_ascii=False, indent=2)

    print()
    print(f"[AI학습기] 학습 완료")
    print(f"  모델 저장: {model_path}")
    print(f"  소요시간: {m}m {s}s")
    print(f"OUTPUT_MODEL:{model_path}")

if __name__ == '__main__':
    main()
