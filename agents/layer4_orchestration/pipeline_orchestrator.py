"""
Agent-17: PipelineOrchestrator  (Main Orchestrator)
Role: Govern Phase 1 (training loop) and Phase 2 (real-time detection).
      Coordinates all layers via a sequential pipeline for each packet batch.
State machine: IDLE → TRAINING_LOOP → DETECTION_ACTIVE → SHUTDOWN
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from enum import Enum, auto
from typing import Optional

from agents.layer1_ingestion.packet_receiver import PacketReceiver
from agents.layer1_ingestion.normalizer import Normalizer
from agents.layer1_ingestion.feature_extractor import FeatureExtractor
from agents.layer1_ingestion.enricher import Enricher
from agents.layer3_decision.evidence_aggregator import EvidenceAggregator
from agents.layer3_decision.conflict_resolver import ConflictResolver
from agents.layer3_decision.confidence_scorer import ConfidenceScorer
from agents.layer3_decision.threshold_manager import ThresholdManager
from agents.layer4_orchestration.analysis_sub_orchestrator import AnalysisSubOrchestrator
from agents.layer4_orchestration.priority_scheduler import PriorityScheduler
from agents.layer5_output.severity_classifier import SeverityClassifier
from agents.layer5_output.alert_generator import AlertGenerator
from agents.layer5_output.alert_deduplicator import AlertDeduplicator
from agents.layer5_output.context_enricher import ContextEnricher
from agents.layer7_evaluation.metrics_calculator import MetricsCalculator


class PipelineState(Enum):
    IDLE = auto()
    TRAINING_LOOP = auto()
    DETECTION_ACTIVE = auto()
    SHUTDOWN = auto()


METRICS_PATH = "data/metrics/latest.json"
DASHBOARD_PATH = "logs/dashboard.json"

# Training targets (identical to existing run_pipeline.py)
TARGET_F1 = 0.92
TARGET_RECALL = 0.90
TARGET_PRECISION = 0.88
MAX_CYCLES = 20


class PipelineOrchestrator:
    agent_id = "agent-17-pipeline-orchestrator"

    def __init__(self, use_ai_gen: bool = False):
        self._state = PipelineState.IDLE
        self._cycle = 0
        self._best_f1 = 0.0
        self._best_cycle = 0
        self._use_ai_gen = use_ai_gen

        # Layer 1
        self._receiver = PacketReceiver()
        self._normalizer = Normalizer()
        self._extractor = FeatureExtractor()
        self._enricher = Enricher()

        # Layer 2 + sub-orchestrator
        self._sub_orch = AnalysisSubOrchestrator()

        # Layer 3
        self._aggregator = EvidenceAggregator()
        self._resolver = ConflictResolver()
        self._scorer = ConfidenceScorer()
        self._threshold_mgr = ThresholdManager()

        # Layer 4 helpers
        self._scheduler = PriorityScheduler()

        # Layer 5
        self._severity = SeverityClassifier()
        self._alert_gen = AlertGenerator()
        self._dedup = AlertDeduplicator()
        self._enricher_ctx = ContextEnricher()

        # Layer 7
        self._metrics_calc = MetricsCalculator()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, max_batches: int = 0) -> None:
        """Entry point — Phase 1 then Phase 2."""
        self._init_dirs()
        mode_tag = " [AI적응형+멀티에이전트]" if self._use_ai_gen else " [멀티에이전트]"
        print(f"[{self.agent_id}] Starting pipeline{mode_tag} — state={self._state.name}")

        self._phase1_training()
        self._phase2_detection(max_batches=max_batches)

        self._state = PipelineState.SHUTDOWN
        print(f"[{self.agent_id}] Pipeline complete.")

    # ------------------------------------------------------------------
    # Phase 1: Training loop (delegates to existing scripts)
    # ------------------------------------------------------------------

    def _phase1_training(self) -> None:
        self._state = PipelineState.TRAINING_LOOP
        print(f"\n[{self.agent_id}] === PHASE 1: TRAINING LOOP ===")
        # Phase1 관련 에이전트 활성화 알림 (GUI 에이전트 상태 업데이트용)
        for aid in ["agent-29-metrics-calculator", "agent-30-false-positive-analyzer",
                    "agent-31-attack-coverage", "agent-32-report-generator"]:
            print(f"[{aid}] Phase1 평가 대기")

        for cycle in range(1, MAX_CYCLES + 1):
            self._cycle = cycle
            print(f"\n[{self.agent_id}] --- Cycle {cycle}/{MAX_CYCLES} ---")
            cycle_start = time.time()

            # Step 1: 패킷 생성
            gen_cmd = ["scripts/generate_packets.py", "--cycle", str(cycle)]
            if self._use_ai_gen:
                gen_cmd.append("--ai")  # generate_packets.py의 실제 플래그
            stdout = self._run_script(gen_cmd, label="패킷생성기(AI적응형)" if self._use_ai_gen else "패킷생성기")
            if stdout is None:
                print(f"[{self.agent_id}] 패킷 생성 실패 — 사이클 {cycle} 건너뜀")
                continue

            packet_file = self._extract_line(stdout, "OUTPUT_FILE:")
            if not packet_file:
                packet_file = self._latest_file(f"data/packets/train_cycle{cycle}_*.csv")
            if not packet_file:
                print(f"[{self.agent_id}] 패킷 파일을 찾을 수 없음")
                continue

            # Step 2: 모델 학습
            stdout = self._run_script(
                ["scripts/train_model.py", "--input", packet_file, "--cycle", str(cycle)],
                label="AI학습기"
            )
            if stdout is None:
                print(f"[{self.agent_id}] 학습 실패 — 사이클 {cycle} 건너뜀")
                continue

            model_file = self._extract_line(stdout, "OUTPUT_MODEL:")
            if not model_file:
                model_file = self._latest_file(f"data/models/model_cycle{cycle}_*.pkl")
            if not model_file:
                print(f"[{self.agent_id}] 모델 파일을 찾을 수 없음")
                continue

            # Step 3: 모델 평가
            stdout = self._run_script(
                ["scripts/evaluate_model.py", "--model", model_file, "--cycle", str(cycle)],
                label="결과판단기"
            )
            if stdout is None:
                print(f"[{self.agent_id}] 평가 실패 — 사이클 {cycle} 건너뜀")
                continue

            metrics = self._read_metrics()
            f1        = metrics.get("metrics", {}).get("f1_score", 0.0)
            recall    = metrics.get("metrics", {}).get("recall", 0.0)
            precision = metrics.get("metrics", {}).get("precision", 0.0)

            if f1 > self._best_f1:
                self._best_f1 = f1
                self._best_cycle = cycle

            elapsed = time.time() - cycle_start
            self._update_dashboard(cycle, f1, recall, elapsed)

            print(f"[{self.agent_id}] Cycle {cycle}: F1={f1:.4f} Recall={recall:.4f} Precision={precision:.4f}")

            if f1 >= TARGET_F1 and recall >= TARGET_RECALL and precision >= TARGET_PRECISION:
                print(f"[{self.agent_id}] Targets met at cycle {cycle}!")
                break

            if metrics.get("continue_training") is False:
                print(f"[{self.agent_id}] Evaluator flagged training complete.")
                break

        print(f"[{self.agent_id}] Phase 1 done. Best F1={self._best_f1:.4f} at cycle {self._best_cycle}")

    # ------------------------------------------------------------------
    # Phase 2: Real-time detection
    # ------------------------------------------------------------------

    def _phase2_detection(self, max_batches: int = 0) -> None:
        self._state = PipelineState.DETECTION_ACTIVE

        # max_batches=0이면 기본값 5 적용 (무한루프 방지)
        effective_max = max_batches if max_batches > 0 else 5
        IDLE_TIMEOUT_SEC = 30   # 새 배치 없이 이 시간 초과 시 자동 종료

        print(f"\n[{self.agent_id}] === PHASE 2: REAL-TIME DETECTION ===")
        print(f"[{self.agent_id}] 최대 배치: {effective_max}  |  유휴 타임아웃: {IDLE_TIMEOUT_SEC}s")

        # Phase2 시작 시 관련 에이전트 활성화 알림 (GUI 에이전트 상태 업데이트용)
        _phase2_agents = [
            "agent-01-packet-receiver", "agent-02-normalizer",
            "agent-03-feature-extractor", "agent-04-enricher",
            "agent-18-analysis-sub-orchestrator", "agent-19-load-balancer",
            "agent-20-priority-scheduler",
            "agent-21-severity-classifier", "agent-22-alert-generator",
            "agent-23-alert-deduplicator", "agent-24-context-enricher",
            "agent-13-evidence-aggregator", "agent-14-conflict-resolver",
            "agent-15-confidence-scorer", "agent-16-threshold-manager",
        ]
        for aid in _phase2_agents:
            print(f"[{aid}] Phase2 활성화")

        batches_processed = 0
        packets_processed = 0
        anomalies_total   = 0
        last_batch_time   = time.time()
        stream_proc = self._start_stream_simulator(max_batches=effective_max + 3)

        # Layer2 분석 에이전트 ID 목록 (배치마다 첫 번째 배치에서만 출력)
        _layer2_agents = [
            "agent-05-statistical-analyzer", "agent-06-ml-classifier",
            "agent-07-deep-learning",         "agent-08-rule-signature",
            "agent-09-behavioral-profile",    "agent-10-temporal-pattern",
            "agent-11-protocol-specific",     "agent-12-flow-correlation",
        ]

        try:
            while True:
                batch = self._receiver.process()

                if batch is None:
                    idle_sec = time.time() - last_batch_time
                    if idle_sec >= IDLE_TIMEOUT_SEC:
                        print(f"[{self.agent_id}] 유휴 {IDLE_TIMEOUT_SEC}s 초과 — 탐지 종료")
                        break
                    time.sleep(1.0)
                    continue

                last_batch_time = time.time()

                # Layer2 에이전트 첫 배치에서 한 번만 ACTIVE 알림
                if batches_processed == 0:
                    for aid in _layer2_agents:
                        print(f"[{aid}] 분석 시작")

                packets   = self._normalizer.process(batch)
                envelopes = self._extractor.process(packets)
                enriched  = self._enricher.process(envelopes)

                self._scheduler.push_batch(enriched)
                to_analyze = self._scheduler.pop_batch(len(enriched))

                anomaly_count = 0
                for ep in to_analyze:
                    votes  = self._sub_orch.analyze(ep)
                    agg    = self._aggregator.process(votes)
                    agg    = self._resolver.process(agg)
                    final  = self._scorer.process(agg, ep)
                    final  = self._threshold_mgr.process(final)
                    self._write_decision_debug(ep, agg, final)

                    if final.is_anomaly_final:
                        anomaly_count += 1
                        severity_result = self._severity.process(final)
                        alert = self._alert_gen.process(severity_result)
                        if alert and self._dedup.process(alert):
                            self._enricher_ctx.process(alert)

                batches_processed += 1
                packets_processed += len(to_analyze)
                anomalies_total   += anomaly_count

                # summary.json 배치 통계 갱신
                self._alert_gen.update_batch_stats(
                    batches_processed, packets_processed, anomalies_total)

                print(f"[{self.agent_id}] 배치 {batches_processed}/{effective_max} "
                      f"— {len(to_analyze)}건 처리, 이상 {anomaly_count}건 탐지")

                if batches_processed >= effective_max:
                    print(f"[{self.agent_id}] 최대 배치 {effective_max}회 완료 — 탐지 종료")
                    break

        finally:
            if stream_proc:
                stream_proc.terminate()
            self._sub_orch.shutdown()

        print(f"[{self.agent_id}] Phase 2 done. Batches processed: {batches_processed}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _run_script(self, cmd: list, label: str = "", retries: int = 3):
        """스크립트를 최대 retries회 실행. 성공 시 stdout 반환, 실패 시 None."""
        for attempt in range(1, retries + 1):
            try:
                result = subprocess.run(
                    [sys.executable] + cmd,
                    capture_output=True, text=True, timeout=600
                )
                if result.returncode == 0:
                    return result.stdout
                print(f"[{self.agent_id}] {label} 실패 (attempt {attempt}/{retries}): "
                      f"{result.stderr[-200:] if result.stderr else '(no stderr)'}")
            except subprocess.TimeoutExpired:
                print(f"[{self.agent_id}] {label} 타임아웃 (attempt {attempt}/{retries})")
            except Exception as e:
                print(f"[{self.agent_id}] {label} 오류 (attempt {attempt}/{retries}): {e}")

            if attempt < retries:
                time.sleep(2)
        return None

    @staticmethod
    def _extract_line(stdout: str, prefix: str) -> str:
        """stdout에서 prefix로 시작하는 라인의 값 추출."""
        for line in (stdout or "").splitlines():
            if line.startswith(prefix):
                return line.split(prefix, 1)[1].strip()
        return ""

    @staticmethod
    def _latest_file(pattern: str) -> str:
        """glob 패턴에 매칭되는 가장 최신 파일 반환."""
        import glob as _glob
        files = sorted(_glob.glob(pattern))
        return files[-1] if files else ""

    def _start_stream_simulator(self, max_batches: int = 8) -> Optional[subprocess.Popen]:
        try:
            return subprocess.Popen(
                [sys.executable, "scripts/simulate_stream.py",
                 "--normal-ratio", "0.85",
                 "--interval",    "2",
                 "--batch-size",  "50",
                 "--max-batches", str(max_batches)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            return None

    def _read_metrics(self) -> dict:
        if not os.path.exists(METRICS_PATH):
            return {}
        try:
            with open(METRICS_PATH) as f:
                return json.load(f)
        except Exception:
            return {}

    def _update_dashboard(self, cycle: int, f1: float, recall: float, elapsed: float) -> None:
        try:
            os.makedirs(os.path.dirname(DASHBOARD_PATH), exist_ok=True)
            data = {}
            if os.path.exists(DASHBOARD_PATH):
                with open(DASHBOARD_PATH) as f:
                    data = json.load(f)
            data.setdefault("cycles", [])
            data["current_cycle"] = cycle
            data["best_f1"] = self._best_f1
            data["best_cycle"] = self._best_cycle
            data["cycles"].append({
                "cycle": cycle, "f1": f1, "recall": recall, "elapsed_sec": round(elapsed, 1)
            })
            with open(DASHBOARD_PATH, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def _write_decision_debug(self, ep, agg, final) -> None:
        try:
            os.makedirs("logs", exist_ok=True)
            row = {
                "timestamp": datetime.now().isoformat(),
                "packet_id": final.packet_id,
                "label": ep.metadata.get("label"),
                "attack_type": ep.metadata.get("attack_type"),
                "aggregate_score": round(float(final.aggregate_score), 4),
                "calibrated_confidence": round(float(final.calibrated_confidence), 4),
                "is_anomaly_final": bool(final.is_anomaly_final),
                "attack_type_final": final.attack_type_final,
                "vote_count_anomaly": agg.vote_count_anomaly,
                "vote_count_normal": agg.vote_count_normal,
                "votes": agg.vote_summary,
            }
            with open("logs/multi_agent_decisions.jsonl", "a", encoding="utf-8") as fp:
                fp.write(json.dumps(row, ensure_ascii=False) + "\n")
        except Exception:
            pass

    @staticmethod
    def _init_dirs() -> None:
        for d in ["data/packets", "data/models", "data/metrics", "data/stream",
                  "data/alerts", "data/feedback", "data/reports", "logs"]:
            os.makedirs(d, exist_ok=True)
