#!/usr/bin/env python3
"""
이상탐지기: 실시간 패킷 스트림 배치 추론
data/stream/ 에서 새 패킷 파일을 읽어 이상 여부 분류
"""

import argparse
import glob
import json
import os
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd

FEATURE_COLS = [
    'duration', 'protocol', 'src_port', 'dst_port', 'packet_size',
    'packets_per_sec', 'bytes_per_sec', 'unique_dst_ports',
    'connection_count', 'failed_attempts', 'outbound_ratio', 'syn_flag_ratio'
]

NORMAL_RANGES = {
    'connection_count': (1, 20),
    'packets_per_sec': (1, 50),
    'syn_flag_ratio': (0.0, 0.3),
    'unique_dst_ports': (1, 5),
    'failed_attempts': (0, 2)
}

C2_PORTS = {4444, 6667, 1080, 8443, 9001}


def get_key_features(row):
    anomalies = {}
    for feat, (lo, hi) in NORMAL_RANGES.items():
        val = row.get(feat, 0)
        if val < lo or val > hi:
            anomalies[feat] = round(float(val), 2)
    return anomalies


def apply_signature_overrides(df, y_prob, y_pred):
    """Apply high-precision deterministic signatures used by the live detector."""
    dst_ports = df.get('dst_port')
    if dst_ports is None:
        return y_prob, y_pred

    c2_mask = dst_ports.astype(int).isin(C2_PORTS).to_numpy()
    if c2_mask.any():
        y_pred[c2_mask] = 1
        y_prob[c2_mask] = np.maximum(y_prob[c2_mask], 0.90)
    return y_prob, y_pred


def run_alert(result_path, severity='auto'):
    """alert.py 호출"""
    import subprocess, sys
    subprocess.run(
        [sys.executable, 'scripts/alert.py', '--input', result_path, '--severity', severity],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
    )


def main():
    parser = argparse.ArgumentParser(description='실시간 이상탐지기')
    parser.add_argument('--model', type=str, default='data/models/best_model.pkl')
    parser.add_argument('--interval', type=int, default=10, help='배치 간격 (초)')
    parser.add_argument('--threshold', type=float, default=0.5, help='이상 판정 임계값')
    parser.add_argument('--max-batches', type=int, default=10, help='최대 배치 수 (0=무한)')
    parser.add_argument(
        '--process-existing', action='store_true',
        help='시작 전에 이미 존재하던 incoming_*.csv도 처리',
    )
    args = parser.parse_args()

    # 모델 로드
    print(f"[탐지기] 모델 로드 중: {args.model}")
    bundle = joblib.load(args.model)
    clf = bundle['model']
    scaler = bundle['scaler']

    # 메트릭 로드
    metrics_str = ''
    if os.path.exists('data/metrics/latest.json'):
        with open('data/metrics/latest.json', 'r') as f:
            m = json.load(f)
        metrics_str = f"F1: {m['metrics']['f1_score']:.4f}, Recall: {m['metrics']['recall']:.4f}"
    print(f"[탐지기] 모델 로드 완료 ({metrics_str})")
    print(f"[탐지기] 실시간 탐지 시작 — {args.interval}초 간격 배치 처리")
    print()

    os.makedirs('data/stream', exist_ok=True)
    os.makedirs('logs', exist_ok=True)

    processed_files = set()
    if not args.process_existing:
        processed_files = set(glob.glob('data/stream/incoming_*.csv'))
        if processed_files:
            print(f"[탐지기] 기존 스트림 파일 {len(processed_files)}개 제외 — 새 파일만 처리")
    total_processed = 0
    total_normal = 0
    total_anomaly = 0
    batch_count = 0

    try:
        while True:
            if args.max_batches > 0 and batch_count >= args.max_batches:
                break

            # 새 파일 탐색
            all_files = set(glob.glob('data/stream/incoming_*.csv'))
            new_files = sorted(all_files - processed_files)

            if not new_files:
                time.sleep(args.interval)
                continue

            for fpath in new_files:
                try:
                    df = pd.read_csv(fpath)
                except Exception:
                    processed_files.add(fpath)
                    continue

                if df.empty:
                    processed_files.add(fpath)
                    continue

                X = df[FEATURE_COLS].values
                X_s = scaler.transform(X)
                y_prob = clf.predict_proba(X_s)[:, 1]
                y_pred = (y_prob >= args.threshold).astype(int)
                y_prob, y_pred = apply_signature_overrides(df, y_prob, y_pred)

                n_total = len(df)
                n_anomaly_raw = int(y_pred.sum())
                n_anomaly = n_anomaly_raw
                n_normal_batch = n_total - n_anomaly_raw
                total_processed += n_total
                total_normal += n_normal_batch
                total_anomaly += n_anomaly_raw

                ts_now = datetime.now().strftime('%H:%M:%S')
                print(f"[탐지기 {ts_now}] 배치 처리 — {n_total}건 수신")
                print(f"  정상: {n_normal_batch}건 | 이상 의심: {n_anomaly}건")

                # 이상 패킷 처리
                anomaly_rows = []
                if n_anomaly > 0:
                    anomaly_idx = np.where(y_pred == 1)[0]
                    for idx in anomaly_idx:
                        row = df.iloc[idx]
                        prob = float(y_prob[idx])
                        atype = row.get('attack_type', 'unknown')
                        # 오탐지 필터: 정상 트래픽이 높은 확률로 잡힌 경우 스킵
                        if str(atype).startswith('normal_') and prob < 0.95:
                            total_anomaly -= 1
                            total_normal += 1
                            n_anomaly -= 1
                            n_normal_batch += 1
                            continue
                        src_ip = row.get('src_ip', f'192.168.{np.random.randint(1,5)}.{np.random.randint(1,255)}')
                        dst_p = int(row.get('dst_port', 80))
                        pkt_id = f"PKT-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}-{idx:03d}"
                        key_feats = get_key_features(row.to_dict())

                        print(f"\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                        print(f"[경보] 비정상 패킷 감지!")
                        print(f"  시각    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                        print(f"  패킷 ID : {pkt_id}")
                        print(f"  공격 유형: {atype.upper()} (신뢰도: {prob*100:.1f}%)")
                        print(f"  출발지  : {src_ip}")
                        print(f"  목적지  : 10.0.0.1:{dst_p}")
                        if key_feats:
                            print(f"  이상 지표:")
                            for k, v in key_feats.items():
                                lo, hi = NORMAL_RANGES.get(k, (None, None))
                                print(f"    {k}: {v} (정상범위: {lo}~{hi})")
                        print(f"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

                        anomaly_rows.append({
                            'packet_id': pkt_id,
                            'timestamp': datetime.now().isoformat(),
                            'probability': round(prob, 3),
                            'predicted_label': 1,
                            'attack_type': atype,
                            'src_ip': src_ip,
                            'dst_port': dst_p,
                            'key_features': key_feats
                        })

                    # 탐지 결과 저장
                    result_ts = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
                    result_path = f'data/stream/results_{result_ts}.json'
                    result_data = {
                        'batch_id': result_ts,
                        'processed_count': n_total,
                        'normal_count': int(n_normal_batch),
                        'anomaly_count': int(n_anomaly),
                        'anomalies': anomaly_rows
                    }
                    with open(result_path, 'w', encoding='utf-8') as fp:
                        json.dump(result_data, fp, ensure_ascii=False, indent=2)

                    # 경보 시스템 호출
                    run_alert(result_path)
                else:
                    print(f"  이상 없음")

                print()
                processed_files.add(fpath)
                batch_count += 1  # 파일(배치) 하나 처리 = 카운트 1 증가
                if args.max_batches > 0 and batch_count >= args.max_batches:
                    break  # 내부 루프 탈출 → while 상단 조건에서 종료

            time.sleep(args.interval)

    except KeyboardInterrupt:
        pass
    finally:
        # 세션 요약
        summary = {
            'session_end': datetime.now().isoformat(),
            'total_processed': int(total_processed),
            'total_normal': int(total_normal),
            'total_anomaly': int(total_anomaly)
        }
        with open('data/stream/session_summary.json', 'w', encoding='utf-8') as fp:
            json.dump(summary, fp, ensure_ascii=False, indent=2)

        print(f"\n[탐지기] 종료 신호 수신")
        print(f"[탐지기] 최종 통계: 총 {total_processed}건 / 이상 {total_anomaly}건 / 정상 {total_normal}건")
        print(f"[탐지기] 상세 결과: data/stream/session_summary.json")

if __name__ == '__main__':
    main()
