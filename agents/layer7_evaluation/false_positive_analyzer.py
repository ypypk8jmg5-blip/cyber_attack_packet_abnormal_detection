"""
Agent-30: FalsePositiveAnalyzer
Role: Deep analysis of false-positive patterns; generates rule-tuning
      and threshold-adjustment recommendations.
Stateless, runs after each evaluation cycle.
"""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from agents._timeutil import utcnow
from typing import Any, Dict, List, Optional

FP_REPORT_DIR = "data/metrics"


class FalsePositiveAnalyzer:
    agent_id = "agent-30-false-positive-analyzer"

    def process(self, feedback_path: str = "data/feedback/feedback_log.jsonl",
                cycle: int = 1) -> Dict[str, Any]:
        feedback = self._load_feedback(feedback_path)
        fp_entries = [e for e in feedback if e.get("feedback_type") == "false_positive"]

        if not fp_entries:
            return {"cycle": cycle, "total_fp": 0, "patterns": [], "recommendations": []}

        by_predicted = Counter(e.get("predicted_attack_type", "unknown") for e in fp_entries)
        by_true = Counter(e.get("corrected_attack_type", "unknown") for e in fp_entries)

        # Find common feature patterns in FP cases
        patterns = self._find_patterns(fp_entries)
        recommendations = self._generate_recommendations(by_predicted, by_true, patterns)

        result = {
            "cycle":                    cycle,
            "total_fp":                 len(fp_entries),
            "fp_by_predicted_attack":   dict(by_predicted.most_common(10)),
            "fp_by_true_class":         dict(by_true.most_common(10)),
            "top_patterns":             patterns[:5],
            "recommendations":          recommendations,
            "timestamp":                utcnow().isoformat(),
        }

        self._save(result, cycle)
        return result

    def _find_patterns(self, fp_entries: List[Dict]) -> List[Dict]:
        """Identify feature ranges common to FP cases."""
        patterns = []
        grouped = defaultdict(list)
        for e in fp_entries:
            key = (e.get("predicted_attack_type"), e.get("corrected_attack_type"))
            grouped[key].append(e.get("packet_features", {}))

        for (predicted, true_class), feature_groups in grouped.items():
            if len(feature_groups) < 3:
                continue
            # Compute average feature values for this FP pattern
            all_keys = set()
            for fg in feature_groups:
                all_keys.update(fg.keys())
            avg = {}
            for k in all_keys:
                vals = [fg[k] for fg in feature_groups if k in fg]
                if vals:
                    avg[k] = round(sum(vals) / len(vals), 4)

            patterns.append({
                "predicted": predicted,
                "true_class": true_class,
                "frequency": len(feature_groups),
                "avg_features": avg,
            })

        return sorted(patterns, key=lambda x: -x["frequency"])

    def _generate_recommendations(self, by_predicted: Counter, by_true: Counter,
                                   patterns: List[Dict]) -> List[str]:
        recs = []
        # Most common FP type
        if by_predicted:
            top_fp_pred, count = by_predicted.most_common(1)[0]
            recs.append(
                f"'{top_fp_pred}' 공격 유형 임계값 상향 조정 검토 (FP {count}건)"
            )

        # Normal traffic mislabeled
        for true_class, count in by_true.most_common(5):
            if "normal_" in (true_class or ""):
                recs.append(
                    f"정상 트래픽 '{true_class}' 시그니처 예외 규칙 추가 필요 ({count}건 오탐)"
                )

        # Pattern-based recommendations
        for p in patterns[:3]:
            if p["frequency"] >= 10:
                recs.append(
                    f"'{p['predicted']}' → '{p['true_class']}' 오탐 패턴 ({p['frequency']}건): "
                    f"피처 임계값 재조정 필요"
                )
        return recs

    def _load_feedback(self, path: str) -> List[Dict]:
        if not os.path.exists(path):
            return []
        try:
            with open(path) as f:
                return [json.loads(line) for line in f if line.strip()]
        except Exception:
            return []

    def _save(self, result: Dict[str, Any], cycle: int) -> None:
        try:
            os.makedirs(FP_REPORT_DIR, exist_ok=True)
            ts = utcnow().strftime("%Y%m%d_%H%M%S_%f")
            path = os.path.join(FP_REPORT_DIR, f"fp_analysis_{ts}.json")
            with open(path, "w") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
