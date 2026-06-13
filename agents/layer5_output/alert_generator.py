"""
Agent-22: AlertGenerator
Role: Produce structured alert JSON backward-compatible with existing data/alerts/ schema.
      Adds multi_agent_context field for new metadata.
Stateless, I/O-bound, < 5ms.
"""
from __future__ import annotations

import json
import logging
import os
from agents._timeutil import utcnow
from typing import Any, Dict, Optional

from agents.layer5_output.severity_classifier import SeverityResult

ALERTS_DIR = "data/alerts"
LOG_PATH = "logs/detection.log"

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_log = logging.getLogger("detection")


def _build_alert(result: SeverityResult) -> Dict[str, Any]:
    decision = result.final_decision
    ep = decision.enriched_packet
    ts = utcnow().strftime("%Y%m%d_%H%M%S_%f")

    src_ip = ep.metadata.get("src_ip", "unknown") if ep else "unknown"
    dst_port = ep.metadata.get("dst_port", 0) if ep else 0

    # Key features for the alert (top 5 from feature vector)
    key_features: Dict[str, Any] = {}
    if ep:
        for name, val in zip(ep.feature_names, ep.feature_vector):
            key_features[name] = round(val, 4)

    return {
        # --- backward-compatible fields ---
        "alert_id":        f"ALT-{ts}",
        "timestamp":       utcnow().isoformat(),
        "severity":        result.severity,
        "attack_type":     result.attack_type or "unknown",
        "confidence":      round(result.confidence, 4),
        "src_ip":          src_ip,
        "dst_port":        dst_port,
        "key_features":    key_features,
        "recommendation":  _recommendation(result.attack_type),
        # --- new multi-agent context ---
        "multi_agent_context": {
            "aggregate_score":     round(decision.aggregate_score, 4),
            "calibrated_confidence": round(decision.calibrated_confidence, 4),
            "confidence_band":     decision.confidence_band,
            "agents_voted_anomaly": decision.vote_summary and sum(
                1 for v in decision.vote_summary.values() if v.get("is_anomaly")),
            "low_confidence_flag": result.low_confidence_detection,
            "severity_rationale":  result.severity_rationale,
        },
    }


_RECOMMENDATIONS = {
    "ddos":          "출발지 IP 즉시 차단 및 DDoS 스크러빙 서비스 활성화",
    "synflood":      "SYN 쿠키 활성화, 연결 속도 제한 적용",
    "http_flood":    "웹 방화벽(WAF) 속도 제한 강화",
    "ransomware":    "SMB/RDP 포트 즉시 차단, 엔드포인트 격리",
    "portscan":      "출발지 IP 모니터링 강화, 방화벽 규칙 검토",
    "arp_spoofing":  "동적 ARP 검사(DAI) 활성화",
    "dns_tunneling": "DNS 쿼리 크기 제한, DNS 필터링 적용",
    "bruteforce":    "계정 잠금 정책 적용, MFA 활성화",
    "exfiltration":  "아웃바운드 트래픽 검사 강화, DLP 솔루션 점검",
    "botnet_c2":     "C2 포트 차단, 엔드포인트 악성코드 스캔",
    "slowloris":     "연결 타임아웃 단축, 연결 수 제한 적용",
}


def _recommendation(attack_type: Optional[str]) -> str:
    return _RECOMMENDATIONS.get(attack_type or "", "보안 이벤트 조사 및 로그 검토 필요")


SUMMARY_PATH = "data/alerts/summary.json"


class AlertGenerator:
    agent_id = "agent-22-alert-generator"

    def __init__(self, alerts_dir: str = ALERTS_DIR):
        self._alerts_dir = alerts_dir
        os.makedirs(alerts_dir, exist_ok=True)
        os.makedirs("logs", exist_ok=True)
        # 세션 시작 시 누적 카운터 초기화
        self._summary: Dict[str, Any] = {
            "session_start":      utcnow().isoformat(),
            "last_updated":       utcnow().isoformat(),
            "total_alerts":       0,
            "by_severity":        {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "by_attack_type":     {},
            "batches_processed":  0,
            "packets_processed":  0,
            "anomalies_detected": 0,
            "top_src_ips":        {},
        }
        self._write_summary()

    def process(self, result: SeverityResult) -> Optional[Dict[str, Any]]:
        alert = _build_alert(result)
        self._write(alert)
        self._accumulate(alert)
        _log.info(
            "[%s] %s confidence=%.3f src=%s dst_port=%s",
            alert["severity"], alert["attack_type"],
            alert["confidence"], alert["src_ip"], alert["dst_port"],
        )
        return alert

    def update_batch_stats(self, batches: int, packets: int, anomalies: int) -> None:
        """Phase2 배치 처리 현황을 summary.json에 갱신 (PipelineOrchestrator 호출용)."""
        self._summary["batches_processed"]  = batches
        self._summary["packets_processed"]  = packets
        self._summary["anomalies_detected"] = anomalies
        self._summary["last_updated"] = utcnow().isoformat()
        self._write_summary()

    def _accumulate(self, alert: Dict[str, Any]) -> None:
        s = self._summary
        sev = alert.get("severity", "LOW")
        atype = alert.get("attack_type", "unknown")
        src_ip = alert.get("src_ip", "unknown")
        s["total_alerts"] += 1
        s["by_severity"][sev] = s["by_severity"].get(sev, 0) + 1
        s["by_attack_type"][atype] = s["by_attack_type"].get(atype, 0) + 1
        s["top_src_ips"][src_ip] = s["top_src_ips"].get(src_ip, 0) + 1
        s["anomalies_detected"] = s["total_alerts"]
        s["last_updated"] = utcnow().isoformat()
        self._write_summary()

    def _write_summary(self) -> None:
        try:
            # top_src_ips를 리스트로 변환
            top_ips = sorted(
                self._summary["top_src_ips"].items(), key=lambda x: x[1], reverse=True
            )[:10]
            out = dict(self._summary)
            out["top_src_ips"] = [
                {"ip": ip, "count": cnt, "last_seen": self._summary["last_updated"]}
                for ip, cnt in top_ips
            ]
            with open(SUMMARY_PATH, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def _write(self, alert: Dict[str, Any]) -> None:
        ts = utcnow().strftime("%Y%m%d_%H%M%S_%f")
        path = os.path.join(self._alerts_dir, f"alert_{ts}.json")
        try:
            with open(path, "w") as f:
                json.dump(alert, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
