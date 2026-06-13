"""
Agent-31: AttackCoverageAgent
Role: Measure per-attack recall across all 11 types; classify as
      fully/partially/poorly covered; recommend improvements for gaps.
Stateless, runs after evaluation cycle.
"""
from __future__ import annotations

import json
import os
from agents._timeutil import utcnow
from typing import Any, Dict, List

from agents.base_agent import ATTACK_TYPES

COVERAGE_DIR = "data/metrics"
TARGET_RECALL = 0.90


class AttackCoverageAgent:
    agent_id = "agent-31-attack-coverage"

    def process(self, per_attack_recall: Dict[str, float], cycle: int = 1) -> Dict[str, Any]:
        fully: List[str] = []
        partially: List[str] = []
        poorly: List[str] = []
        gaps: List[Dict] = []

        for attack in ATTACK_TYPES:
            recall = per_attack_recall.get(attack)
            if recall is None:
                poorly.append(attack)
                gaps.append({
                    "attack_type":        attack,
                    "current_recall":     0.0,
                    "target_recall":      TARGET_RECALL,
                    "status":             "no_data",
                    "recommended_action": f"테스트 데이터에 '{attack}' 샘플 추가 필요",
                })
                continue

            if recall >= TARGET_RECALL:
                fully.append(attack)
            elif recall >= 0.75:
                partially.append(attack)
                gaps.append({
                    "attack_type":        attack,
                    "current_recall":     recall,
                    "target_recall":      TARGET_RECALL,
                    "status":             "partial",
                    "recommended_action": self._recommendation(attack, recall),
                })
            else:
                poorly.append(attack)
                gaps.append({
                    "attack_type":        attack,
                    "current_recall":     recall,
                    "target_recall":      TARGET_RECALL,
                    "status":             "poor",
                    "recommended_action": self._recommendation(attack, recall),
                })

        overall_coverage = len(fully) / len(ATTACK_TYPES) if ATTACK_TYPES else 0.0

        result = {
            "cycle":             cycle,
            "timestamp":         utcnow().isoformat(),
            "overall_coverage":  round(overall_coverage, 4),
            "coverage_summary": {
                "fully_covered":    fully,
                "partially_covered": partially,
                "poorly_covered":   poorly,
            },
            "per_attack_recall": per_attack_recall,
            "gaps":              gaps,
        }

        self._save(result)
        return result

    def _recommendation(self, attack: str, recall: float) -> str:
        recs = {
            "slowloris":      "duration>60s AND pps<0.5 AND connection_count>200 룰 추가",
            "botnet_c2":      "비콘 주기 탐지 강화 (TemporalPatternAgent 가중치 상향)",
            "arp_spoofing":   "ICMP 짧은 duration 룰 임계값 조정",
            "dns_tunneling":  "DNS 패킷 크기 임계값 하향 조정 (400→300B)",
            "exfiltration":   "아웃바운드 비율 임계값 재조정",
        }
        base = recs.get(attack, f"'{attack}' 훈련 샘플 증가 및 피처 임계값 재조정")
        return f"{base} (현재 recall={recall:.3f})"

    def _save(self, result: Dict[str, Any]) -> None:
        try:
            os.makedirs(COVERAGE_DIR, exist_ok=True)
            ts = utcnow().strftime("%Y%m%d_%H%M%S_%f")
            path = os.path.join(COVERAGE_DIR, f"coverage_{ts}.json")
            with open(path, "w") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
