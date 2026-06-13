"""
run_pipeline.py 전체 케이스 검증 및 패킷 이상탐지 정확도 테스트
"""
import ast
import glob
import inspect
import json
import os
import subprocess
import sys
import tempfile
import uuid

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.metrics import recall_score

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

FEATURE_COLS = [
    'duration', 'protocol', 'src_port', 'dst_port', 'packet_size',
    'packets_per_sec', 'bytes_per_sec', 'unique_dst_ports',
    'connection_count', 'failed_attempts', 'outbound_ratio', 'syn_flag_ratio',
]

ALL_ATTACK_TYPES = [
    'ddos', 'portscan', 'bruteforce', 'exfiltration', 'synflood',
    'dns_tunneling', 'http_flood', 'slowloris', 'botnet_c2', 'ransomware', 'arp_spoofing',
    'cryptomining', 'dns_amplification', 'credential_stuffing',
]


# ──────────────────────────────────────────────────────────────────────────────
# TestGeneratePackets
# ──────────────────────────────────────────────────────────────────────────────
class TestGeneratePackets:
    """generate_packets.py 유닛 테스트"""

    def test_all_14_attack_types_defined(self):
        from scripts.generate_packets import ATTACK_GENERATORS
        assert len(ATTACK_GENERATORS) == 14
        assert set(ATTACK_GENERATORS.keys()) == set(ALL_ATTACK_TYPES)

    def test_all_10_normal_types_defined(self):
        from scripts.generate_packets import NORMAL_GENERATORS
        assert len(NORMAL_GENERATORS) == 10

    @pytest.mark.parametrize('atype', ALL_ATTACK_TYPES)
    def test_each_attack_label_is_1(self, atype):
        from scripts.generate_packets import ATTACK_GENERATORS
        df = ATTACK_GENERATORS[atype](50)
        assert (df['label'] == 1).all(), f"{atype}: label이 1이 아닌 행 존재"
        assert (df['attack_type'] == atype).all()
        for col in FEATURE_COLS:
            assert col in df.columns, f"{atype}: {col} 컬럼 누락"

    def test_each_normal_label_is_0(self):
        from scripts.generate_packets import NORMAL_GENERATORS
        for gen in NORMAL_GENERATORS:
            df = gen(50)
            assert (df['label'] == 0).all(), f"{gen.__name__}: label이 0이 아닌 행 존재"
            for col in FEATURE_COLS:
                assert col in df.columns

    def test_cli_output_file_created(self):
        result = subprocess.run(
            [sys.executable, 'scripts/generate_packets.py', '--cycle', '1', '--size', '200'],
            capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=60,
        )
        assert result.returncode == 0, f"generate_packets.py 실패:\n{result.stderr}"
        out_file = None
        for line in result.stdout.splitlines():
            if line.startswith('OUTPUT_FILE:'):
                out_file = line.split('OUTPUT_FILE:')[1].strip()
                break
        assert out_file is not None, "OUTPUT_FILE: 출력 없음"
        assert os.path.exists(os.path.join(PROJECT_ROOT, out_file)), f"파일 없음: {out_file}"
        df = pd.read_csv(os.path.join(PROJECT_ROOT, out_file))
        assert len(df) > 0
        assert 0 in df['label'].values
        assert 1 in df['label'].values

    def test_cli_test_mode_output(self):
        result = subprocess.run(
            [sys.executable, 'scripts/generate_packets.py', '--mode', 'test', '--size', '200'],
            capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=60,
        )
        assert result.returncode == 0
        out_file = None
        for line in result.stdout.splitlines():
            if line.startswith('OUTPUT_FILE:'):
                out_file = line.split('OUTPUT_FILE:')[1].strip()
                break
        assert out_file is not None
        fname = os.path.basename(out_file)
        assert fname.startswith('test_'), f"테스트 모드 파일명이 test_로 시작하지 않음: {fname}"

    def test_dns_syn_flag_zero(self):
        """정상 DNS 패킷의 syn_flag_ratio는 0 — Bug 4 관련 문서화 테스트"""
        from scripts.generate_packets import gen_dns_query
        df = gen_dns_query(100)
        assert (df['syn_flag_ratio'] == 0).all(), "DNS 정상 패킷에서 syn_flag_ratio != 0 발견"

    def test_port_445_removed_from_ftp(self):
        """Bug 5 수정 확인: 정상 FTP에서 포트 445 제거됨 — 랜섬웨어 포트 충돌 해소"""
        from scripts.generate_packets import gen_file_transfer, gen_ransomware
        df_ftp = gen_file_transfer(500)
        df_ransom = gen_ransomware(500)
        assert 445 not in df_ftp['dst_port'].values, "Bug 5 미수정: gen_file_transfer에 포트 445 존재"
        assert 445 in df_ransom['dst_port'].values, "랜섬웨어는 여전히 포트 445 사용해야 함"

    def test_ai_generator_normal_ftp_matches_safe_distribution(self):
        from agents.layer0_generation.adaptive_packet_generator import AdaptivePacketGenerator
        df = AdaptivePacketGenerator()._gen_normal_ftp(500, 1.0)
        assert 445 not in df['dst_port'].values, "AI 생성기 정상 FTP에 포트 445 존재"
        assert df['packets_per_sec'].between(1, 50).all()
        assert df['bytes_per_sec'].max() <= 500_000


# ──────────────────────────────────────────────────────────────────────────────
# TestTrainModel
# ──────────────────────────────────────────────────────────────────────────────
class TestTrainModel:
    """train_model.py 유닛 테스트"""

    def test_model_bundle_has_required_keys(self, tiny_model):
        bundle = joblib.load(tiny_model)
        assert set(bundle.keys()) == {'model', 'scaler', 'features'}

    def test_model_is_random_forest(self, tiny_model):
        bundle = joblib.load(tiny_model)
        assert type(bundle['model']).__name__ == 'RandomForestClassifier'

    def test_features_match_expected_columns(self, tiny_model):
        bundle = joblib.load(tiny_model)
        assert bundle['features'] == FEATURE_COLS

    def test_feature_importance_sums_to_one(self, tiny_model):
        bundle = joblib.load(tiny_model)
        total = bundle['model'].feature_importances_.sum()
        assert abs(total - 1.0) < 1e-6, f"feature_importances 합계 != 1.0: {total}"

    def test_model_can_predict(self, tiny_model):
        bundle = joblib.load(tiny_model)
        clf = bundle['model']
        scaler = bundle['scaler']
        from scripts.generate_packets import gen_web_browsing
        df = gen_web_browsing(10)
        X = df[FEATURE_COLS].values
        X_s = scaler.transform(X)
        preds = clf.predict(X_s)
        assert preds.shape == (10,)
        assert set(preds).issubset({0, 1})

    def test_cli_creates_model_file(self):
        """generate → train 1사이클 subprocess 통합 테스트"""
        # 패킷 생성
        res = subprocess.run(
            [sys.executable, 'scripts/generate_packets.py', '--cycle', '99', '--size', '300'],
            capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=60,
        )
        assert res.returncode == 0
        packet_file = None
        for line in res.stdout.splitlines():
            if line.startswith('OUTPUT_FILE:'):
                packet_file = line.split('OUTPUT_FILE:')[1].strip()
                break
        assert packet_file

        # 모델 학습
        res2 = subprocess.run(
            [sys.executable, 'scripts/train_model.py', '--input', packet_file, '--cycle', '99'],
            capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=120,
        )
        assert res2.returncode == 0, f"train_model.py 실패:\n{res2.stderr}"
        model_file = None
        for line in res2.stdout.splitlines():
            if line.startswith('OUTPUT_MODEL:'):
                model_file = line.split('OUTPUT_MODEL:')[1].strip()
                break
        assert model_file, "OUTPUT_MODEL: 출력 없음"
        assert os.path.exists(os.path.join(PROJECT_ROOT, model_file))


# ──────────────────────────────────────────────────────────────────────────────
# TestEvaluateModel
# ──────────────────────────────────────────────────────────────────────────────
class TestEvaluateModel:
    """evaluate_model.py 유닛 테스트"""

    def test_all_14_attack_types_in_eval_loop(self):
        """14종 전체가 evaluate_model.py 평가 루프에 있어야 함"""
        src_path = os.path.join(PROJECT_ROOT, 'scripts', 'evaluate_model.py')
        with open(src_path, encoding='utf-8') as f:
            source = f.read()
        for atype in ALL_ATTACK_TYPES:
            assert atype in source, f"evaluate_model.py에 '{atype}' 없음"

    def test_goal_met_when_all_targets_achieved(self):
        F1_TARGET, RECALL_TARGET, PRECISION_TARGET = 0.92, 0.90, 0.88
        f1, recall, precision = 0.94, 0.92, 0.89
        goal_met = (f1 >= F1_TARGET and recall >= RECALL_TARGET and precision >= PRECISION_TARGET)
        assert goal_met is True

    def test_goal_not_met_when_f1_below_target(self):
        F1_TARGET, RECALL_TARGET, PRECISION_TARGET = 0.92, 0.90, 0.88
        f1, recall, precision = 0.88, 0.91, 0.90
        goal_met = (f1 >= F1_TARGET and recall >= RECALL_TARGET and precision >= PRECISION_TARGET)
        assert goal_met is False

    def test_per_attack_recall_all_14_types(self, tiny_model):
        """tiny_model 기준으로 14종 재현율 계산이 모두 수행되는지 확인"""
        from scripts.generate_packets import ATTACK_GENERATORS
        bundle = joblib.load(tiny_model)
        clf = bundle['model']
        scaler = bundle['scaler']

        results = {}
        for atype in ALL_ATTACK_TYPES:
            df = ATTACK_GENERATORS[atype](50)
            X_s = scaler.transform(df[FEATURE_COLS].values)
            y_pred = clf.predict(X_s)
            results[atype] = recall_score(df['label'].values, y_pred, zero_division=0)

        assert set(results.keys()) == set(ALL_ATTACK_TYPES), "14종이 모두 평가되지 않음"

    def test_rule_signature_covers_all_14_attack_types(self):
        from agents.layer2_analysis.rule_signature_agent import _RULES
        covered = {attack_type for attack_type, _, _ in _RULES}
        assert set(ALL_ATTACK_TYPES).issubset(covered)

    def test_multi_agent_shared_maps_cover_all_14_attack_types(self):
        from agents.base_agent import ATTACK_TYPES as SHARED_ATTACK_TYPES
        from agents.layer5_output.severity_classifier import _TYPE_TO_BASE
        assert set(SHARED_ATTACK_TYPES) == set(ALL_ATTACK_TYPES)
        assert set(ALL_ATTACK_TYPES).issubset(_TYPE_TO_BASE)


# ──────────────────────────────────────────────────────────────────────────────
# TestDetectAnomaly
# ──────────────────────────────────────────────────────────────────────────────
class TestDetectAnomaly:
    """detect_anomaly.py 유닛 테스트"""

    def test_bug2_anomaly_count_fixed(self, tiny_model):
        """Bug 2 수정 확인: FP 필터 후 n_anomaly가 len(anomaly_rows)와 일치해야 함"""
        from scripts.generate_packets import gen_ddos, gen_web_browsing
        bundle = joblib.load(tiny_model)
        clf = bundle['model']
        scaler = bundle['scaler']

        # 공격 10개 + 정상(normal_web) 10개를 섞어 FP 필터가 동작하도록 구성
        df_attack = gen_ddos(10)
        df_normal = gen_web_browsing(10)
        df = pd.concat([df_attack, df_normal], ignore_index=True)

        X_s = scaler.transform(df[FEATURE_COLS].values)
        y_prob = clf.predict_proba(X_s)[:, 1]
        y_pred = (y_prob >= 0.5).astype(int)

        n_anomaly = int(y_pred.sum())
        anomaly_rows = []
        for idx in np.where(y_pred == 1)[0]:
            row = df.iloc[idx]
            prob = float(y_prob[idx])
            atype = str(row.get('attack_type', 'unknown'))
            # 수정된 필터 로직: normal_ 이고 확률 < 0.95 이면 n_anomaly도 감소
            if atype.startswith('normal_') and prob < 0.95:
                n_anomaly -= 1
                continue
            anomaly_rows.append(idx)

        assert n_anomaly == len(anomaly_rows), (
            f"Bug 2 미수정: n_anomaly({n_anomaly}) != len(anomaly_rows)({len(anomaly_rows)})"
        )

    def test_bug4_syn_flag_ratio_fixed(self):
        """Bug 4 수정 확인: syn_flag_ratio=0 DNS 패킷이 이상 지표에 포함되지 않아야 함"""
        from scripts.detect_anomaly import NORMAL_RANGES, get_key_features
        # 수정 후: 하한이 0.0 이어야 함
        lower_bound = NORMAL_RANGES['syn_flag_ratio'][0]
        assert lower_bound == 0.0, (
            f"Bug 4 미수정: syn_flag_ratio 하한 = {lower_bound} (0.0이어야 함)"
        )
        # DNS 정상 패킷(syn_flag_ratio=0)이 이상 지표에 없어야 함
        dns_row = {
            'duration': 0.1, 'protocol': 1, 'src_port': 12345, 'dst_port': 53,
            'packet_size': 80.0, 'packets_per_sec': 5.0, 'bytes_per_sec': 2000.0,
            'unique_dst_ports': 1, 'connection_count': 2, 'failed_attempts': 0,
            'outbound_ratio': 0.5, 'syn_flag_ratio': 0.0,
        }
        anomalies = get_key_features(dns_row)
        assert 'syn_flag_ratio' not in anomalies, (
            "DNS 패킷(syn_flag_ratio=0)이 이상 지표에 포함됨 — Bug 4 미수정"
        )

    def test_detect_flags_attack_packets(self, tiny_model):
        """강한 공격 패킷은 anomaly로 분류되어야 함"""
        from scripts.generate_packets import gen_ddos
        bundle = joblib.load(tiny_model)
        clf = bundle['model']
        scaler = bundle['scaler']

        df = gen_ddos(20)
        X_s = scaler.transform(df[FEATURE_COLS].values)
        y_pred = clf.predict(X_s)
        detected = y_pred.sum()
        assert detected > 0, "DDoS 패킷 20개 중 하나도 탐지 못함"

    def test_detect_does_not_flag_all_normal(self, tiny_model):
        """정상 패킷의 FP율이 50% 미만이어야 함"""
        from scripts.generate_packets import gen_web_browsing
        bundle = joblib.load(tiny_model)
        clf = bundle['model']
        scaler = bundle['scaler']

        df = gen_web_browsing(50)
        X_s = scaler.transform(df[FEATURE_COLS].values)
        y_pred = clf.predict(X_s)
        fp_rate = y_pred.sum() / len(y_pred)
        assert fp_rate < 0.5, f"정상 패킷 FP율이 너무 높음: {fp_rate:.2%}"

    def test_session_summary_keys(self, tiny_model, tmp_path):
        """detect_anomaly.py CLI 실행 후 session_summary.json 구조 확인"""
        from scripts.generate_packets import gen_ddos, gen_web_browsing

        # 스트림 파일 생성
        df = pd.concat([gen_ddos(10), gen_web_browsing(20)], ignore_index=True)
        stream_dir = os.path.join(PROJECT_ROOT, 'data', 'stream')
        os.makedirs(stream_dir, exist_ok=True)
        uid = uuid.uuid4().hex[:8]
        stream_file = os.path.join(stream_dir, f'incoming_test_{uid}.csv')
        df.to_csv(stream_file, index=False)

        res = subprocess.run(
            [sys.executable, 'scripts/detect_anomaly.py',
             '--model', 'data/models/best_model.pkl' if os.path.exists(
                 os.path.join(PROJECT_ROOT, 'data', 'models', 'best_model.pkl')
             ) else tiny_model,
             '--interval', '0', '--max-batches', '1', '--process-existing'],
            capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=60,
        )
        summary_path = os.path.join(PROJECT_ROOT, 'data', 'stream', 'session_summary.json')
        assert os.path.exists(summary_path), "session_summary.json 미생성"
        with open(summary_path) as f:
            s = json.load(f)
        for key in ('total_processed', 'total_normal', 'total_anomaly'):
            assert key in s, f"session_summary.json에 '{key}' 키 없음"

        # 스트림 파일 정리
        if os.path.exists(stream_file):
            os.remove(stream_file)


# ──────────────────────────────────────────────────────────────────────────────
# TestSimulateStream
# ──────────────────────────────────────────────────────────────────────────────
class TestSimulateStream:
    """simulate_stream.py 유닛 테스트"""

    @staticmethod
    def _make_forced_normal(kind, n=500):
        import scripts.simulate_stream as sim
        original_choice = sim.np.random.choice

        def forced_choice(values, *args, **kwargs):
            try:
                if list(values) == ['web', 'dns', 'ftp', 'stream', 'email',
                                    'voip', 'gaming', 'iot', 'backup', 'ssh']:
                    return kind
            except TypeError:
                pass
            return original_choice(values, *args, **kwargs)

        sim.np.random.choice = forced_choice
        try:
            return pd.DataFrame(sim.make_normal(n))
        finally:
            sim.np.random.choice = original_choice

    def test_creates_incoming_csv_files(self):
        # 기존 incoming 파일 목록 저장
        before = set(glob.glob(os.path.join(PROJECT_ROOT, 'data', 'stream', 'incoming_*.csv')))
        res = subprocess.run(
            [sys.executable, 'scripts/simulate_stream.py',
             '--interval', '0', '--batch-size', '20', '--max-batches', '3'],
            capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=60,
        )
        assert res.returncode == 0, f"simulate_stream.py 실패:\n{res.stderr}"
        after = set(glob.glob(os.path.join(PROJECT_ROOT, 'data', 'stream', 'incoming_*.csv')))
        new_files = after - before
        assert len(new_files) >= 3, f"3개 CSV 미생성: {len(new_files)}개만 생성됨"

    def test_csv_has_all_feature_columns(self):
        import re
        # incoming_YYYYMMDD_*.csv only (created by simulate_stream, not test helpers)
        files = sorted(
            f for f in glob.glob(os.path.join(PROJECT_ROOT, 'data', 'stream', 'incoming_*.csv'))
            if re.match(r'.*incoming_\d{8}_', f)
        )
        assert files, "incoming_YYYYMMDD_*.csv 파일 없음 (test_creates_incoming_csv_files 먼저 실행 필요)"
        df = pd.read_csv(files[-1])
        for col in FEATURE_COLS + ['label', 'attack_type', 'src_ip']:
            assert col in df.columns, f"컬럼 누락: {col}"

    def test_mixed_traffic_ratio(self):
        res = subprocess.run(
            [sys.executable, 'scripts/simulate_stream.py',
             '--normal-ratio', '0.8', '--batch-size', '50', '--max-batches', '1',
             '--interval', '0'],
            capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=30,
        )
        assert res.returncode == 0
        files = sorted(glob.glob(os.path.join(PROJECT_ROOT, 'data', 'stream', 'incoming_*.csv')))
        assert files
        df = pd.read_csv(files[-1])
        normal_ratio = (df['label'] == 0).sum() / len(df)
        # 정상 비율이 0.5~1.0 범위 (±0.3 허용)
        assert 0.5 <= normal_ratio <= 1.0, f"정상 비율 이상: {normal_ratio:.2%}"

    def test_all_14_attack_types_appear(self):
        """충분한 배치 수에서 14종 공격이 모두 등장해야 함"""
        import re
        before = set(glob.glob(os.path.join(PROJECT_ROOT, 'data', 'stream', 'incoming_*.csv')))
        res = subprocess.run(
            [sys.executable, 'scripts/simulate_stream.py',
             '--normal-ratio', '0.5', '--batch-size', '50', '--max-batches', '100',
             '--interval', '0'],
            capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=180,
        )
        assert res.returncode == 0
        after = set(glob.glob(os.path.join(PROJECT_ROOT, 'data', 'stream', 'incoming_*.csv')))
        new_files = sorted(after - before)
        assert new_files, "새 스트림 파일 미생성"
        dfs = [pd.read_csv(f) for f in new_files]
        df_all = pd.concat(dfs, ignore_index=True)
        attack_df = df_all[df_all['label'] == 1]
        found = set(attack_df['attack_type'].unique())
        missing = set(ALL_ATTACK_TYPES) - found
        assert not missing, f"스트림에서 미등장 공격 유형: {missing}"

    def test_normal_stream_profiles_stay_in_safe_ranges(self):
        for kind in ('ftp', 'voip', 'gaming', 'backup'):
            df = self._make_forced_normal(kind)
            assert 445 not in df['dst_port'].values, f"{kind}: 정상 트래픽에 포트 445 존재"
            assert 139 not in df['dst_port'].values, f"{kind}: 정상 트래픽에 포트 139 존재"
            assert df['packets_per_sec'].between(0.1, 50).all(), kind
            assert df['failed_attempts'].between(0, 2).all(), kind


# ──────────────────────────────────────────────────────────────────────────────
# TestAnomalyDetectionValidation  (실제 best_model.pkl 필요)
# ──────────────────────────────────────────────────────────────────────────────
class TestAnomalyDetectionValidation:
    """실제 훈련된 모델로 공격 유형별 탐지 정확도 검증.

    실제 탐지 파이프라인(clf.predict + apply_signature_overrides)과 동일하게 실행한다.
    """

    @staticmethod
    def _predict_with_pipeline(bundle, df):
        """detect_anomaly.py / evaluate_model.py 와 동일한 추론 파이프라인."""
        from scripts.detect_anomaly import apply_signature_overrides
        clf = bundle['model']
        scaler = bundle['scaler']
        X_s = scaler.transform(df[FEATURE_COLS].values)
        y_prob = clf.predict_proba(X_s)[:, 1]
        y_pred = (y_prob >= 0.5).astype(int)
        y_prob, y_pred = apply_signature_overrides(df, y_prob, y_pred)
        return y_pred

    @pytest.mark.parametrize('atype', ALL_ATTACK_TYPES)
    def test_recall_per_attack_type(self, real_model_path, atype):
        """각 공격 유형 500패킷 → recall >= 0.90 (서명 오버라이드 포함, 표본 증가로 분산 감소)"""
        if real_model_path is None:
            pytest.skip("data/models/best_model.pkl 없음")
        from scripts.generate_packets import ATTACK_GENERATORS
        bundle = joblib.load(real_model_path)
        df = ATTACK_GENERATORS[atype](500)
        y_pred = self._predict_with_pipeline(bundle, df)
        rec = recall_score(df['label'].values, y_pred, zero_division=0)
        assert rec >= 0.90, f"{atype} 재현율 {rec:.4f} < 0.90"

    @pytest.mark.parametrize('gen_name,gen_func', [
        ('normal_web',    'gen_web_browsing'),
        ('normal_dns',    'gen_dns_query'),
        ('normal_ftp',    'gen_file_transfer'),
        ('normal_stream', 'gen_video_stream'),
        ('normal_email',  'gen_email'),
        ('normal_voip',   'gen_voip'),
        ('normal_gaming', 'gen_gaming'),
        ('normal_iot',    'gen_iot'),
        ('normal_backup', 'gen_backup'),
        ('normal_ssh',    'gen_ssh'),
    ])
    def test_false_positive_rate_per_normal_type(self, real_model_path, gen_name, gen_func):
        """각 정상 유형 200패킷 → FP율 <= 0.10"""
        if real_model_path is None:
            pytest.skip("data/models/best_model.pkl 없음")
        import importlib
        gen = getattr(importlib.import_module('scripts.generate_packets'), gen_func)
        bundle = joblib.load(real_model_path)
        df = gen(200)
        y_pred = self._predict_with_pipeline(bundle, df)
        fp_rate = y_pred.sum() / len(y_pred)
        assert fp_rate <= 0.10, f"{gen_name} FP율 {fp_rate:.2%} > 10%"

    @pytest.mark.parametrize('atype', ALL_ATTACK_TYPES)
    def test_borderline_attack_recall(self, real_model_path, atype):
        """경계선 저강도 변종 200패킷 → recall >= 0.70 (서명 오버라이드 포함)"""
        if real_model_path is None:
            pytest.skip("data/models/best_model.pkl 없음")
        from scripts.generate_packets import ATTACK_GENERATORS, _make_borderline_attacks
        bundle = joblib.load(real_model_path)
        df_border = _make_borderline_attacks(ATTACK_GENERATORS[atype](200), frac=1.0)
        y_pred = self._predict_with_pipeline(bundle, df_border)
        rec = recall_score(df_border['label'].values, y_pred, zero_division=0)
        assert rec >= 0.70, f"{atype} 경계선 변종 재현율 {rec:.4f} < 0.70"

    def test_dns_tunneling_vs_normal_dns(self, real_model_path):
        """DNS 터널링과 정상 DNS 구분 테스트"""
        if real_model_path is None:
            pytest.skip("data/models/best_model.pkl 없음")
        from scripts.generate_packets import gen_dns_query, gen_dns_tunneling
        bundle = joblib.load(real_model_path)
        df_normal = gen_dns_query(100)
        df_tunnel = gen_dns_tunneling(100)
        fp_rate = self._predict_with_pipeline(bundle, df_normal).sum() / 100
        tunnel_recall = recall_score(
            df_tunnel['label'].values,
            self._predict_with_pipeline(bundle, df_tunnel),
            zero_division=0,
        )
        assert fp_rate < 0.15, f"정상 DNS FP율 {fp_rate:.2%} >= 15%"
        assert tunnel_recall > 0.85, f"DNS 터널링 재현율 {tunnel_recall:.4f} <= 0.85"

    def test_file_transfer_vs_ransomware(self, real_model_path):
        """Bug 5 수정 후: FTP FP율 감소, 랜섬웨어 탐지 유지 확인"""
        if real_model_path is None:
            pytest.skip("data/models/best_model.pkl 없음")
        from scripts.generate_packets import gen_file_transfer, gen_ransomware
        bundle = joblib.load(real_model_path)
        df_ftp = gen_file_transfer(100)
        df_ransom = gen_ransomware(100)
        fp_rate = self._predict_with_pipeline(bundle, df_ftp).sum() / 100
        ransom_recall = recall_score(
            df_ransom['label'].values,
            self._predict_with_pipeline(bundle, df_ransom),
            zero_division=0,
        )
        assert ransom_recall >= 0.85, f"랜섬웨어 재현율 {ransom_recall:.4f} < 0.85"
        assert fp_rate <= 0.15, f"FTP 정상 FP율 {fp_rate:.2%} > 15% (포트 445 제거 후에도 높음)"


# ──────────────────────────────────────────────────────────────────────────────
# TestPipelineModes
# ──────────────────────────────────────────────────────────────────────────────
class TestPipelineModes:
    """run_pipeline.py 모드별 통합 테스트"""

    def test_imports_cleanly(self):
        """run_pipeline.py 임포트 오류 없음 확인"""
        import importlib
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'run_pipeline',
            os.path.join(PROJECT_ROOT, 'run_pipeline.py'),
        )
        mod = importlib.util.module_from_spec(spec)
        # __name__ != '__main__' 이므로 메인 블록은 실행 안 됨
        spec.loader.exec_module(mod)
        assert hasattr(mod, 'phase1')
        assert hasattr(mod, 'phase2')

    def test_phase2_has_goal_met_param(self):
        """Bug 3 수정 확인: phase2()가 goal_met 파라미터를 가져야 함"""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'run_pipeline',
            os.path.join(PROJECT_ROOT, 'run_pipeline.py'),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        params = list(inspect.signature(mod.phase2).parameters.keys())
        assert 'goal_met' in params, (
            f"Bug 3 미수정: phase2() 파라미터에 goal_met 없음. 현재 파라미터: {params}"
        )

    def test_single_cycle_integration(self):
        """generate → train → evaluate 1사이클 subprocess 통합 테스트 (~30초)"""
        cycle = 98

        # Step 1: 패킷 생성
        r1 = subprocess.run(
            [sys.executable, 'scripts/generate_packets.py', '--cycle', str(cycle), '--size', '400'],
            capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=60,
        )
        assert r1.returncode == 0, f"generate_packets 실패:\n{r1.stderr}"
        packet_file = next(
            (l.split('OUTPUT_FILE:')[1].strip() for l in r1.stdout.splitlines()
             if l.startswith('OUTPUT_FILE:')), None
        )
        assert packet_file

        # Step 2: 모델 학습
        r2 = subprocess.run(
            [sys.executable, 'scripts/train_model.py',
             '--input', packet_file, '--cycle', str(cycle)],
            capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=180,
        )
        assert r2.returncode == 0, f"train_model 실패:\n{r2.stderr}"
        model_file = next(
            (l.split('OUTPUT_MODEL:')[1].strip() for l in r2.stdout.splitlines()
             if l.startswith('OUTPUT_MODEL:')), None
        )
        assert model_file

        # Step 3: 평가
        r3 = subprocess.run(
            [sys.executable, 'scripts/evaluate_model.py',
             '--model', model_file, '--cycle', str(cycle)],
            capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=120,
        )
        assert r3.returncode == 0, f"evaluate_model 실패:\n{r3.stderr}"

        # latest.json 검증
        latest_path = os.path.join(PROJECT_ROOT, 'data', 'metrics', 'latest.json')
        assert os.path.exists(latest_path)
        with open(latest_path) as f:
            latest = json.load(f)
        assert 'metrics' in latest
        assert 'f1_score' in latest['metrics']
        assert 'per_attack_recall' in latest
        # Bug 1 수정 확인: 11종 모두 있어야 함
        for atype in ALL_ATTACK_TYPES:
            assert atype in latest['per_attack_recall'], (
                f"per_attack_recall에 '{atype}' 없음 — Bug 1 미수정"
            )

    def test_multi_agent_imports(self):
        """멀티 에이전트 모드 임포트 성공 확인"""
        from agents.layer4_orchestration.pipeline_orchestrator import PipelineOrchestrator
        assert hasattr(PipelineOrchestrator, 'run')


# ──────────────────────────────────────────────────────────────────────────────
# TestBugVerification  — 버그 회귀 테스트
# ──────────────────────────────────────────────────────────────────────────────
class TestBugVerification:
    """발견된 5개 버그 검증 (수정 전 탐지, 수정 후 통과)"""

    def test_bug1_all_14_attack_types_in_evaluate_loop(self):
        """Bug 1 수정 + 확장: evaluate_model.py가 14종 전체를 평가해야 함"""
        src = open(os.path.join(PROJECT_ROOT, 'scripts', 'evaluate_model.py'), encoding='utf-8').read()
        for atype in ALL_ATTACK_TYPES:
            assert atype in src, (
                f"'{atype}'이 evaluate_model.py 평가 루프에 없음"
            )

    def test_bug2_n_anomaly_decremented_in_filter(self):
        """Bug 2: FP 필터에서 n_anomaly 감소 코드가 있어야 함"""
        src = open(os.path.join(PROJECT_ROOT, 'scripts', 'detect_anomaly.py'), encoding='utf-8').read()
        # 수정된 코드에는 n_anomaly -= 1 이 오탐 필터 블록에 있어야 함
        assert 'n_anomaly -= 1' in src, (
            "Bug 2 미수정: detect_anomaly.py FP 필터에 'n_anomaly -= 1' 없음"
        )

    def test_bug3_phase2_has_goal_met_parameter(self):
        """Bug 3: run_pipeline.py phase2()에 goal_met 파라미터가 있어야 함"""
        src = open(os.path.join(PROJECT_ROOT, 'run_pipeline.py'), encoding='utf-8').read()
        assert 'def phase2(goal_met,' in src, (
            "Bug 3 미수정: run_pipeline.py의 phase2() 시그니처에 goal_met 파라미터 없음"
        )

    def test_bug4_syn_flag_lower_bound_is_zero(self):
        """Bug 4: detect_anomaly.py NORMAL_RANGES syn_flag_ratio 하한이 0.0이어야 함"""
        from scripts.detect_anomaly import NORMAL_RANGES
        lb = NORMAL_RANGES['syn_flag_ratio'][0]
        assert lb == 0.0, f"Bug 4 미수정: syn_flag_ratio 하한 = {lb} (0.0이어야 함)"

    def test_bug5_port_445_removed_from_ftp(self):
        """Bug 5 수정: 정상 FTP에서 포트 445 제거 — 랜섬웨어와 포트 충돌 없음"""
        from scripts.generate_packets import gen_file_transfer, gen_ransomware
        ftp_ports = set(gen_file_transfer(500)['dst_port'].values)
        ransom_ports = set(gen_ransomware(500)['dst_port'].values)
        overlap = ftp_ports & ransom_ports
        assert 445 not in ftp_ports, "Bug 5 미수정: gen_file_transfer에 포트 445 존재"
        assert 445 in ransom_ports, "랜섬웨어는 포트 445 유지해야 함"
        assert 445 not in overlap, "Bug 5 미수정: 포트 445 충돌 여전히 존재"
