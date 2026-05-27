"""
공통 pytest 픽스처
"""
import os
import sys
import tempfile

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# 프로젝트 루트를 sys.path에 추가
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

FEATURE_COLS = [
    'duration', 'protocol', 'src_port', 'dst_port', 'packet_size',
    'packets_per_sec', 'bytes_per_sec', 'unique_dst_ports',
    'connection_count', 'failed_attempts', 'outbound_ratio', 'syn_flag_ratio',
]


@pytest.fixture(scope='session')
def project_root():
    return PROJECT_ROOT


@pytest.fixture(scope='session')
def tiny_model(tmp_path_factory):
    """
    빠른 테스트용 소형 모델 (n_estimators=10, n=800샘플).
    세션 전체에서 한 번만 학습.
    """
    from scripts.generate_packets import (
        ATTACK_GENERATORS, NORMAL_GENERATORS,
    )

    rng = np.random.default_rng(0)
    dfs = []
    n_per = 40
    for gen in NORMAL_GENERATORS:
        dfs.append(gen(n_per))
    for gen in ATTACK_GENERATORS.values():
        dfs.append(gen(n_per))

    df = pd.concat(dfs, ignore_index=True).sample(frac=1, random_state=0).reset_index(drop=True)
    X = df[FEATURE_COLS].values
    y = df['label'].values

    scaler = StandardScaler()
    X_s = scaler.fit_transform(X)

    clf = RandomForestClassifier(n_estimators=10, max_depth=8, random_state=0, n_jobs=-1)
    clf.fit(X_s, y)

    tmp_dir = tmp_path_factory.mktemp('model')
    model_path = str(tmp_dir / 'tiny_model.pkl')
    joblib.dump({'model': clf, 'scaler': scaler, 'features': FEATURE_COLS}, model_path)
    return model_path


@pytest.fixture(scope='session')
def real_model_path(project_root):
    """data/models/best_model.pkl 이 존재하면 경로 반환, 없으면 None."""
    path = os.path.join(project_root, 'data', 'models', 'best_model.pkl')
    return path if os.path.exists(path) else None
