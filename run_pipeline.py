#!/usr/bin/env python3
"""
네트워크 이상탐지 MLOps 오케스트레이터
Phase 1: 학습 루프 (F1 >= 0.92, Recall >= 0.90, Precision >= 0.88 달성까지 자동 반복)
Phase 2: 실시간 탐지 모드 진입
"""

import glob
import csv
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime

# ─── 설정 ────────────────────────────────────────────────────────────────────
MAX_CYCLES = 20
F1_TARGET = 0.92
RECALL_TARGET = 0.90
PRECISION_TARGET = 0.88

PYTHON = sys.executable
SCRIPTS = 'scripts'


# ─── 유틸 ─────────────────────────────────────────────────────────────────────
def run_script(cmd, label):
    """스크립트 실행 후 stdout 반환. 실패 시 None."""
    try:
        result = subprocess.run(
            [PYTHON, '-u'] + cmd,
            capture_output=True, text=True, timeout=600
        )
        if result.returncode != 0:
            print(f"[ERROR] {label} 실패:", flush=True)
            print(result.stderr[-500:] if result.stderr else '(no stderr)', flush=True)
            return None
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"[ERROR] {label} 타임아웃 (10분 초과)", flush=True)
        return None


def extract_output_line(stdout, prefix):
    """OUTPUT_FILE: / OUTPUT_MODEL: 등 특수 라인 추출"""
    for line in (stdout or '').splitlines():
        if line.startswith(prefix):
            return line.split(prefix, 1)[1].strip()
    return None


def latest_file(pattern):
    files = sorted(glob.glob(pattern))
    return files[-1] if files else None


def count_packet_labels(packet_file):
    """Return (normal_count, anomaly_count) from the generated CSV labels."""
    normal = anomaly = 0
    try:
        with open(packet_file, 'r', encoding='utf-8', newline='') as fp:
            reader = csv.DictReader(fp)
            for row in reader:
                label = str(row.get('label', '')).strip()
                if label in {'1', '1.0'}:
                    anomaly += 1
                elif label in {'0', '0.0'}:
                    normal += 1
    except Exception:
        return 0, 0
    return normal, anomaly


def progress_bar(current, target, width=10):
    ratio = min(current / target, 1.0)
    filled = int(ratio * width)
    bar = '█' * filled + '░' * (width - filled)
    return f"[{bar}]"


def write_log(msg):
    os.makedirs('logs', exist_ok=True)
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open('logs/training_progress.log', 'a', encoding='utf-8') as f:
        f.write(f"{ts} {msg}\n")


def update_dashboard(data):
    os.makedirs('logs', exist_ok=True)
    with open('logs/dashboard.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ─── Phase 1: 학습 루프 ───────────────────────────────────────────────────────
def phase1(use_ai_gen: bool = False):
    start_time = time.time()
    ts_str = datetime.now().isoformat()

    # 초기화
    dashboard = {
        'start_time': ts_str,
        'current_cycle': 0,
        'best_f1': 0,
        'best_recall': 0,
        'best_cycle': 0,
        'status': 'running',
        'cycles': []
    }
    update_dashboard(dashboard)
    write_log("=" * 60)
    write_log("네트워크 이상탐지 MLOps — 학습 시작")

    print("=" * 60)
    print(" 네트워크 이상탐지 MLOps — 학습 시작")
    print(f" 시작 시각: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" 목표: F1 >= {F1_TARGET} | Recall >= {RECALL_TARGET} | Precision >= {PRECISION_TARGET}")
    print("=" * 60)
    print()

    best_f1 = 0.0
    best_recall = 0.0
    best_cycle = 0

    for cycle in range(1, MAX_CYCLES + 1):
        cycle_start = time.time()
        dashboard['current_cycle'] = cycle
        update_dashboard(dashboard)

        # ── Step 1: 패킷 생성 ───────────────────────────────────────────
        gen_mode = 'AI 적응형' if use_ai_gen else '고정 분포'
        print(f"\n[사이클 {cycle} | Step 1/3] 패킷 생성 중... ({gen_mode})")
        write_log(f"[사이클 {cycle}] Step 1/3 패킷 생성 시작 ({gen_mode})")

        gen_cmd = [f'{SCRIPTS}/generate_packets.py', '--cycle', str(cycle)]
        if use_ai_gen:
            gen_cmd.append('--ai')

        stdout = run_script(gen_cmd, '패킷생성기')
        if stdout is None:
            print(f"[ERROR] 패킷 생성 실패 — 사이클 {cycle} 재시도 생략")
            write_log(f"[ERROR] 패킷 생성 실패 — 사이클 {cycle}")
            continue

        print(stdout.rstrip(), flush=True)
        packet_file = extract_output_line(stdout, 'OUTPUT_FILE:')
        if not packet_file:
            packet_file = latest_file(f'data/packets/train_cycle{cycle}_*.csv')
        if not packet_file:
            print(f"[ERROR] 패킷 파일을 찾을 수 없음")
            continue

        # 정상/비정상 건수는 출력 문구 대신 CSV label 기준으로 계산한다.
        n_normal, n_abnormal = count_packet_labels(packet_file)
        write_log(f"[사이클 {cycle} | Step 1/3] 패킷 생성 완료 — 정상 {n_normal}건, 비정상 {n_abnormal}건")
        print(f"[사이클 {cycle} | Step 1/3] 패킷 생성 완료 — 정상 {n_normal:,}건, 비정상 {n_abnormal:,}건")

        # ── Step 2: AI 학습 ─────────────────────────────────────────────
        print(f"\n[사이클 {cycle} | Step 2/3] AI 모델 학습 중...")
        write_log(f"[사이클 {cycle}] Step 2/3 학습 시작")
        train_start = time.time()

        stdout = run_script(
            [f'{SCRIPTS}/train_model.py', '--input', packet_file, '--cycle', str(cycle)],
            'AI학습기'
        )
        if stdout is None:
            print(f"[ERROR] 학습 실패 — 사이클 {cycle}")
            write_log(f"[ERROR] 학습 실패 — 사이클 {cycle}")
            continue

        print(stdout.rstrip(), flush=True)
        model_file = extract_output_line(stdout, 'OUTPUT_MODEL:')
        if not model_file:
            model_file = latest_file(f'data/models/model_cycle{cycle}_*.pkl')
        if not model_file:
            print(f"[ERROR] 모델 파일을 찾을 수 없음")
            continue

        train_elapsed = time.time() - train_start
        m, s = divmod(int(train_elapsed), 60)
        write_log(f"[사이클 {cycle} | Step 2/3] 학습 완료 — 소요시간: {m}m {s}s | 모델: {model_file}")
        print(f"[사이클 {cycle} | Step 2/3] 학습 완료 — 소요시간: {m}m {s}s | 모델: {os.path.basename(model_file)}")

        # ── Step 3: 평가 ────────────────────────────────────────────────
        print(f"\n[사이클 {cycle} | Step 3/3] 성능 평가 중...")
        write_log(f"[사이클 {cycle}] Step 3/3 평가 시작")

        stdout = run_script(
            [f'{SCRIPTS}/evaluate_model.py', '--model', model_file, '--cycle', str(cycle)],
            '결과판단기'
        )
        if stdout is None:
            print(f"[ERROR] 평가 실패 — 사이클 {cycle}")
            write_log(f"[ERROR] 평가 실패 — 사이클 {cycle}")
            continue

        print(stdout.rstrip(), flush=True)

        # latest.json 읽기
        if not os.path.exists('data/metrics/latest.json'):
            print(f"[ERROR] latest.json 없음")
            continue

        with open('data/metrics/latest.json', 'r', encoding='utf-8') as f:
            metrics = json.load(f)

        f1 = metrics['metrics']['f1_score']
        recall = metrics['metrics']['recall']
        precision = metrics['metrics']['precision']
        accuracy = metrics['metrics']['accuracy']
        loss = metrics['metrics']['loss']
        continue_training = metrics['continue_training']

        if f1 > best_f1:
            best_f1 = f1
            best_cycle = cycle
        if recall > best_recall:
            best_recall = recall

        cycle_elapsed = time.time() - cycle_start
        cm, cs = divmod(int(cycle_elapsed), 60)
        n_packets = n_normal + n_abnormal

        verdict = '목표 달성!' if not continue_training else '계속 학습'

        # 대시보드 출력
        print()
        print("-" * 60)
        print(f" 사이클 #{cycle} 결과")
        print("-" * 60)
        print(f" F1 점수  : {f1:.4f}  (최고: {best_f1:.4f} @ 사이클 {best_cycle})")
        print(f" 재현율   : {recall:.4f}  (목표: {RECALL_TARGET})")
        print(f" 정밀도   : {precision:.4f}  (목표: {PRECISION_TARGET})")
        print(f" 손실값   : {loss:.4f}")
        print(f" 패킷 수  : {n_packets:,}건")
        print(f" 소요시간 : {cm}m {cs}s")
        print(f" 판정     : [{verdict}]")
        print("-" * 60)
        bar = progress_bar(f1, F1_TARGET)
        print(f" 누적 진행: {bar} F1 {f1:.4f} / {F1_TARGET}")
        remaining_cycles = max(0, int((F1_TARGET - f1) / max(f1 - (best_f1 - 0.05), 0.01)))
        remaining_cycles = min(remaining_cycles, MAX_CYCLES - cycle)
        print(f" 예상 잔여: ~{remaining_cycles} 사이클")
        print("=" * 60)

        # 대시보드 업데이트
        dashboard['best_f1'] = best_f1
        dashboard['best_recall'] = best_recall
        dashboard['best_cycle'] = best_cycle
        dashboard['cycles'].append({
            'cycle': cycle,
            'f1': f1, 'recall': recall, 'precision': precision,
            'elapsed_sec': round(cycle_elapsed, 1)
        })
        update_dashboard(dashboard)
        write_log(f"[사이클 {cycle}] F1={f1:.4f} Recall={recall:.4f} Precision={precision:.4f} 판정=[{verdict}]")

        if not continue_training:
            return True, cycle, f1, recall, precision

        if cycle >= MAX_CYCLES:
            print(f"[WARNING] 최대 사이클 초과 — 최고 성능 모델로 탐지 단계 진입")
            write_log(f"[WARNING] 최대 사이클 초과 — 최고 성능 모델로 탐지 단계 진입")
            return False, cycle, best_f1, best_recall, 0.0

    return False, MAX_CYCLES, best_f1, best_recall, 0.0


# ─── Phase 2: 실시간 탐지 ─────────────────────────────────────────────────────
def phase2(goal_met, total_cycles, f1, recall, precision, max_batches=5):
    print()
    print("=" * 60)
    if goal_met:
        print(" [완료] 학습 목표 달성!")
    else:
        print(" [경고] 최대 사이클 초과 — 최고 성능 모델로 탐지 진입")
    print(" 최종 모델: data/models/best_model.pkl")
    print(f" F1: {f1:.4f} | Recall: {recall:.4f} | Precision: {precision:.4f}")
    print(f" 총 소요: {total_cycles} 사이클")
    print("=" * 60)
    print(" Phase 2: 실시간 탐지 모드 진입 중...")
    print("=" * 60)

    # ── 새 세션 ID 기록 (alert.py 중복 누적 방지) ──────────────────────────
    _session_marker = 'data/alerts/.session_id'
    os.makedirs('data/alerts', exist_ok=True)
    _new_sid = str(uuid.uuid4())
    with open(_session_marker, 'w') as _f:
        _f.write(_new_sid)
    print(f"[오케스트레이터] 새 탐지 세션 시작 (ID: {_new_sid[:8]}...)", flush=True)

    detect_max_batches = max_batches if max_batches > 0 else 5
    sim_max_batches = max(8, detect_max_batches + 3)

    # 스트림 시뮬레이터 백그라운드 실행
    print("\n[오케스트레이터] 패킷 스트림 시뮬레이터 시작...", flush=True)
    sim_proc = subprocess.Popen(
        [PYTHON, '-u', f'{SCRIPTS}/simulate_stream.py',
         '--normal-ratio', '0.85', '--interval', '3', '--batch-size', '50',
         '--max-batches', str(sim_max_batches)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(2)  # 스트림 생성 대기

    # 탐지기 실시간 스트리밍 실행 (capture_output 사용 안 함 → 줄별 즉시 출력)
    print(f"[오케스트레이터] 탐지기 시작 ({detect_max_batches}회 배치 처리 후 자동 종료)...\n", flush=True)
    detect_proc = subprocess.Popen(
        [PYTHON, '-u', f'{SCRIPTS}/detect_anomaly.py',
         '--model', 'data/models/best_model.pkl',
         '--interval', '4', '--max-batches', str(detect_max_batches)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1
    )
    try:
        for line in detect_proc.stdout:
            print(line, end='', flush=True)
    finally:
        detect_proc.wait()

    # 시뮬레이터 종료
    try:
        sim_proc.terminate()
    except Exception:
        pass

    # 경보 통계 출력
    if os.path.exists('data/alerts/summary.json'):
        with open('data/alerts/summary.json', 'r', encoding='utf-8') as f:
            summary = json.load(f)

        print()
        print("=" * 40)
        print(f" 탐지 요약 보고 — {datetime.now().strftime('%H:%M:%S')}")
        print("=" * 40)
        print(f" 총 경보: {summary['total_alerts']}건")
        sev = summary.get('by_severity', {})
        print(f" 경보 등급: CRITICAL {sev.get('CRITICAL',0)} | HIGH {sev.get('HIGH',0)} | MEDIUM {sev.get('MEDIUM',0)} | LOW {sev.get('LOW',0)}")
        atk = summary.get('by_attack_type', {})
        if atk:
            print(f" 공격 유형: {', '.join(f'{k}={v}' for k,v in atk.items())}")
        print("=" * 40)


# ─── 메인 ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='네트워크 이상탐지 MLOps 파이프라인')
    parser.add_argument(
        '--multi-agent', action='store_true',
        help='32개 멀티 에이전트 시스템(Agent-17 PipelineOrchestrator)으로 실행',
    )
    parser.add_argument(
        '--max-batches', type=int, default=0,
        help='Phase2 처리할 최대 배치 수 (순차 모드 0=기본 5, 멀티 에이전트 0=무한)',
    )
    parser.add_argument(
        '--ai-gen', action='store_true',
        help='Agent-00 AI 적응형 패킷 생성기 사용 (이전 사이클 Recall 피드백 반영)',
    )
    args = parser.parse_args()

    if args.multi_agent:
        # ── 멀티 에이전트 모드: Agent-17 PipelineOrchestrator 사용 ──
        print("=" * 60)
        if args.ai_gen:
            print(" AI 적응형 생성 + 멀티 에이전트 모드")
            print(" Agent-00 (AI 패킷 생성) + Agent-17 (32개 에이전트 파이프라인)")
        else:
            print(" 멀티 에이전트 모드 (32개 에이전트, 7개 레이어)")
        print("=" * 60)
        from agents.layer4_orchestration.pipeline_orchestrator import PipelineOrchestrator
        orchestrator = PipelineOrchestrator(use_ai_gen=args.ai_gen)
        orchestrator.run(max_batches=args.max_batches)
    else:
        # ── 기존 순차 모드 (하위호환) ──
        os.makedirs('data/packets', exist_ok=True)
        os.makedirs('data/models', exist_ok=True)
        os.makedirs('data/metrics', exist_ok=True)
        os.makedirs('data/alerts', exist_ok=True)
        os.makedirs('data/stream', exist_ok=True)
        os.makedirs('logs', exist_ok=True)

        if args.ai_gen:
            print("=" * 60)
            print(" AI 적응형 패킷 생성 모드 활성화 (Agent-00)")
            print(" 이전 사이클 Recall → 취약 공격 유형 자동 강화")
            print("=" * 60)

        goal_met, total_cycles, best_f1, best_recall, best_precision = phase1(
            use_ai_gen=args.ai_gen
        )
        phase2(goal_met, total_cycles, best_f1, best_recall, best_precision, args.max_batches)

    print("\n[종료] MLOps 파이프라인 완료")
    print(f"  학습 로그  : logs/training_progress.log")
    print(f"  대시보드   : logs/dashboard.json")
    print(f"  탐지 로그  : logs/detection.log")
    print(f"  경보 통계  : data/alerts/summary.json")
