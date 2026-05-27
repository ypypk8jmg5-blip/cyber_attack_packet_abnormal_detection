"""
Agent-32: ReportGenerator
Role: Synthesise training metrics, detection performance, FP analysis,
      coverage, and drift status into a comprehensive report.
Stateless, runs after each evaluation cycle and hourly during detection.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

REPORTS_DIR = "data/reports"
DASHBOARD_PATH = "logs/dashboard.json"
ALERTS_SUMMARY_PATH = "data/alerts/summary.json"


class ReportGenerator:
    agent_id = "agent-32-report-generator"

    def process(
        self,
        metrics_result: Optional[Dict] = None,
        fp_result: Optional[Dict] = None,
        coverage_result: Optional[Dict] = None,
        drift_psi: Optional[float] = None,
        perf_stats: Optional[Dict] = None,
        cycle: int = 1,
    ) -> Dict[str, Any]:

        ts = datetime.utcnow().isoformat()
        report_id = f"RPT-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

        training_status = self._training_status(metrics_result, cycle)
        detection_perf = self._detection_performance(perf_stats)
        top_threats = self._top_threats()
        drift_status = self._drift_status(drift_psi)
        recommended_actions = self._aggregate_actions(fp_result, coverage_result)

        report: Dict[str, Any] = {
            "report_id":           report_id,
            "generated_at":        ts,
            "cycle":               cycle,
            "training_status":     training_status,
            "detection_performance": detection_perf,
            "attack_coverage":     coverage_result or {},
            "false_positive_analysis": fp_result or {},
            "drift_status":        drift_status,
            "top_threats":         top_threats,
            "recommended_actions": recommended_actions,
            "agent_health":        perf_stats.get("agent_health", {}) if perf_stats else {},
        }

        self._save(report)
        self._print_summary(report)
        return report

    # ------------------------------------------------------------------

    def _training_status(self, metrics: Optional[Dict], cycle: int) -> Dict:
        if not metrics:
            return {"cycle": cycle, "goal_achieved": False}
        m = metrics.get("metrics", {})
        return {
            "cycle":          cycle,
            "f1_score":       m.get("f1_score"),
            "recall":         m.get("recall"),
            "precision":      m.get("precision"),
            "auc_roc":        m.get("auc_roc"),
            "goal_achieved":  not metrics.get("continue_training", True),
            "is_best_model":  metrics.get("is_best_model", False),
        }

    def _detection_performance(self, perf: Optional[Dict]) -> Dict:
        if not perf:
            return {}
        return {
            "packets_processed":    perf.get("packets_processed", 0),
            "throughput_pps":       perf.get("throughput_pps", 0),
            "e2e_p95_ms":           perf.get("e2e_latency_p95_ms", 0),
            "alert_count":          perf.get("alert_count", 0),
            "false_positive_rate":  perf.get("false_positive_rate", 0),
        }

    def _top_threats(self) -> List[Dict]:
        if not os.path.exists(ALERTS_SUMMARY_PATH):
            return []
        try:
            with open(ALERTS_SUMMARY_PATH) as f:
                summary = json.load(f)
            by_type = summary.get("by_attack_type", {})
            return [
                {"attack_type": k, "count": v}
                for k, v in sorted(by_type.items(), key=lambda x: -x[1])[:5]
            ]
        except Exception:
            return []

    def _drift_status(self, psi: Optional[float]) -> str:
        if psi is None:
            return "unknown"
        if psi >= 0.30:
            return f"SEVERE (PSI={psi:.3f}) — 즉시 재학습 필요"
        if psi >= 0.20:
            return f"MODERATE (PSI={psi:.3f}) — 재학습 검토"
        if psi >= 0.10:
            return f"MILD (PSI={psi:.3f}) — 모니터링 강화"
        return f"NONE (PSI={psi:.3f})"

    def _aggregate_actions(self, fp: Optional[Dict], cov: Optional[Dict]) -> List[str]:
        actions = []
        if fp:
            actions.extend(fp.get("recommendations", []))
        if cov:
            for gap in cov.get("gaps", [])[:3]:
                if gap.get("status") in {"partial", "poor", "no_data"}:
                    actions.append(gap.get("recommended_action", ""))
        return [a for a in actions if a]

    def _save(self, report: Dict[str, Any]) -> None:
        try:
            os.makedirs(REPORTS_DIR, exist_ok=True)
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
            path = os.path.join(REPORTS_DIR, f"report_{ts}.json")
            with open(path, "w") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def _print_summary(self, report: Dict[str, Any]) -> None:
        ts = report["generated_at"]
        cycle = report["cycle"]
        training = report["training_status"]
        perf = report["detection_performance"]
        print(f"\n{'='*60}")
        print(f"[Agent-32] 평가 보고서  {ts}  (사이클 {cycle})")
        print(f"{'='*60}")
        if training:
            goal = "✓ 달성" if training.get("goal_achieved") else "✗ 미달"
            print(f"  학습 목표: {goal}  "
                  f"F1={training.get('f1_score')}  "
                  f"Recall={training.get('recall')}  "
                  f"Precision={training.get('precision')}")
        if perf:
            print(f"  처리량: {perf.get('throughput_pps')} pps  "
                  f"P95 지연: {perf.get('e2e_p95_ms')} ms  "
                  f"FPR: {perf.get('false_positive_rate')}")
        for i, action in enumerate(report.get("recommended_actions", [])[:3], 1):
            print(f"  권고 {i}: {action}")
        print(f"{'='*60}\n")
