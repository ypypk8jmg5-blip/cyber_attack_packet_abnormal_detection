#!/usr/bin/env python3
"""
알림 시스템: 탐지 결과를 경보로 출력하고 이력 관리
CRITICAL/HIGH/MEDIUM/LOW 등급별 경보 발생
"""

import argparse
import json
import os
from datetime import datetime


SEVERITY_MAP = {
    # CRITICAL — 즉각 대응 필요
    'ddos':                'CRITICAL',
    'synflood':            'CRITICAL',
    'ransomware':          'CRITICAL',
    'http_flood':          'CRITICAL',
    'dns_amplification':   'CRITICAL',
    # HIGH — 즉시 조사
    'portscan':            'HIGH',
    'arp_spoofing':        'HIGH',
    'dns_tunneling':       'HIGH',
    'cryptomining':        'HIGH',
    # MEDIUM — 강화 모니터링
    'bruteforce':          'MEDIUM',
    'exfiltration':        'MEDIUM',
    'botnet_c2':           'MEDIUM',
    'credential_stuffing': 'MEDIUM',
    # LOW — 기록 및 관찰
    'slowloris':           'LOW',
    'unknown':             'LOW',
}

RECOMMENDATIONS = {
    'CRITICAL': '출발지 IP 즉시 차단 및 트래픽 차단 검토',
    'HIGH':     '즉시 조사 필요 — 방화벽 규칙 점검 및 패킷 캡처',
    'MEDIUM':   '모니터링 강화 — 패턴 추적 및 계정 잠금 검토',
    'LOW':      '로그 기록 — 지속 관찰 및 임계값 재확인',
}


def load_result(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


_SESSION_MARKER = 'data/alerts/.session_id'


def _current_run_id() -> str:
    """run_pipeline.py 시작 시 기록된 세션 ID 반환. 없으면 빈 문자열."""
    if os.path.exists(_SESSION_MARKER):
        with open(_SESSION_MARKER) as f:
            return f.read().strip()
    return ''


def load_summary() -> dict:
    """summary.json 로드.

    run_pipeline.py가 Phase2 시작 시 .session_id 파일을 갱신한다.
    summary.json 안의 session_id와 다르면 새 파이프라인 실행으로 간주하고
    카운터를 초기화한다 (순차 모드 누적 방지).
    """
    path = 'data/alerts/summary.json'
    fresh = {
        'session_id':    _current_run_id(),
        'session_start': datetime.now().isoformat(),
        'last_updated':  datetime.now().isoformat(),
        'total_alerts':  0,
        'by_severity':   {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
        'by_attack_type': {},
        'top_src_ips':   [],
        'false_positive_feedback': 0,
        'mode': 'sequential',
    }
    if not os.path.exists(path):
        return fresh
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # 세션 ID가 바뀌었으면 초기화
        if data.get('session_id', '') != _current_run_id():
            return fresh
        return data
    except Exception:
        return fresh


def save_summary(summary):
    os.makedirs('data/alerts', exist_ok=True)
    with open('data/alerts/summary.json', 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)


def print_alert(anomaly, severity, alert_id):
    attack_type = anomaly.get('attack_type', 'unknown').upper()
    confidence = anomaly.get('probability', 0) * 100
    src_ip = anomaly.get('src_ip', 'N/A')
    dst_port = anomaly.get('dst_port', 0)
    key_feats = anomaly.get('key_features', {})
    feat_str = ', '.join(f"{k}={v}" for k, v in list(key_feats.items())[:3])
    rec = RECOMMENDATIONS.get(severity, '')
    ts = anomaly.get('timestamp', datetime.now().isoformat())[:19].replace('T', ' ')

    if severity == 'CRITICAL':
        print(f"╔══════════════════════════════════════════════════════╗")
        print(f"║  [{severity}] 비정상 패킷 감지 — 즉시 대응 필요!       ║")
        print(f"╠══════════════════════════════════════════════════════╣")
        print(f"║  시각     : {ts:<40s}║")
        print(f"║  공격유형 : {attack_type} (신뢰도: {confidence:.1f}%){'':>30s}║")
        print(f"║  출발지   : {src_ip:<40s}║")
        print(f"║  목적지   : 10.0.0.1:{dst_port:<33d}║")
        if feat_str:
            print(f"║  이상징후 : {feat_str[:40]:<40s}║")
        print(f"║  권고사항 : {rec:<40s}║")
        print(f"╚══════════════════════════════════════════════════════╝")
    elif severity == 'HIGH':
        print(f"[HIGH] 비정상 패킷 감지")
        print(f"  {ts} | {attack_type} | {src_ip} → 10.0.0.1:{dst_port}")
        if feat_str:
            print(f"  {feat_str}")
        print(f"  → 상세: data/alerts/{alert_id}.json")
    else:
        print(f"[{severity}] {ts} | {attack_type} | {src_ip}:{dst_port} → 로그 기록")


def main():
    parser = argparse.ArgumentParser(description='알림 시스템')
    parser.add_argument('--input', type=str, required=True, help='탐지 결과 JSON 파일')
    parser.add_argument('--severity', type=str, default='auto', help='경보 등급')
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[ERROR] 탐지 결과 파일 없음 — 탐지기 실행 확인 필요: {args.input}")
        return

    try:
        result = load_result(args.input)
    except json.JSONDecodeError:
        print(f"[ERROR] JSON 파싱 오류: {args.input}")
        return

    os.makedirs('data/alerts', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    summary = load_summary()

    # 최신 모델 정보
    model_version = 'unknown'
    if os.path.exists('data/metrics/latest.json'):
        with open('data/metrics/latest.json', 'r') as f:
            mdata = json.load(f)
        model_version = os.path.basename(mdata.get('model_path', 'unknown'))

    for anomaly in result.get('anomalies', []):
        attack_type = anomaly.get('attack_type', 'unknown').lower()
        if args.severity == 'auto':
            severity = SEVERITY_MAP.get(attack_type, 'LOW')
        else:
            severity = args.severity.upper()

        ts_str = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        alert_id = f"ALT-{ts_str}-{anomaly.get('packet_id', '001')[-3:]}"

        # 콘솔 경보 출력
        print_alert(anomaly, severity, alert_id)

        # 개별 경보 파일 저장
        alert_data = {
            'alert_id': alert_id,
            'timestamp': anomaly.get('timestamp', datetime.now().isoformat()),
            'severity': severity,
            'attack_type': attack_type,
            'confidence': anomaly.get('probability', 0),
            'src_ip': anomaly.get('src_ip', 'N/A'),
            'dst_port': anomaly.get('dst_port', 0),
            'key_features': anomaly.get('key_features', {}),
            'recommendation': RECOMMENDATIONS.get(severity, ''),
            'model_version': model_version
        }
        alert_path = f'data/alerts/alert_{alert_id}.json'
        with open(alert_path, 'w', encoding='utf-8') as f:
            json.dump(alert_data, f, ensure_ascii=False, indent=2)

        # 통계 업데이트
        summary['total_alerts'] += 1
        summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
        summary['by_attack_type'][attack_type] = summary['by_attack_type'].get(attack_type, 0) + 1
        summary['last_updated'] = datetime.now().isoformat()

        # IP 통계
        src_ip = anomaly.get('src_ip', 'N/A')
        ip_found = False
        for ip_entry in summary['top_src_ips']:
            if ip_entry['ip'] == src_ip:
                ip_entry['count'] += 1
                ip_entry['last_seen'] = datetime.now().isoformat()
                ip_found = True
                break
        if not ip_found:
            summary['top_src_ips'].append({
                'ip': src_ip,
                'count': 1,
                'last_seen': datetime.now().isoformat()
            })
        summary['top_src_ips'].sort(key=lambda x: x['count'], reverse=True)
        summary['top_src_ips'] = summary['top_src_ips'][:10]

        # detection.log 기록
        with open('logs/detection.log', 'a', encoding='utf-8') as f:
            ts_log = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            conf = anomaly.get('probability', 0) * 100
            f.write(
                f"{ts_log} [{severity}] {attack_type.upper()} | "
                f"{src_ip} → 10.0.0.1:{anomaly.get('dst_port', 0)} | "
                f"신뢰도:{conf:.1f}% | {alert_id}\n"
            )

    save_summary(summary)

if __name__ == '__main__':
    main()
