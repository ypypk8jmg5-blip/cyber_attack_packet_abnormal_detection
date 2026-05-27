"""
Agent-24: ContextEnricher
Role: Attach MITRE ATT&CK mapping and remediation playbook to final alerts.
Stateless, static knowledge base, < 2ms.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

THREAT_CONTEXT: Dict[str, Dict] = {
    "ddos": {
        "mitre_tactic":    "Impact",
        "mitre_technique": "T1498 - Network Denial of Service",
        "remediation_steps": [
            "1. 출발지 IP를 경계 방화벽에서 즉시 차단",
            "2. 대상 포트에 속도 제한(Rate Limiting) 적용",
            "3. DDoS 완화 스크러빙 서비스 활성화",
        ],
        "ioc_type": "IP address with volumetric traffic",
    },
    "synflood": {
        "mitre_tactic":    "Impact",
        "mitre_technique": "T1499.002 - Service Exhaustion Flood",
        "remediation_steps": [
            "1. TCP SYN 쿠키 활성화",
            "2. 연결 속도 제한(SYN Rate Limit) 적용",
            "3. 방화벽에서 반감쇠 타임아웃 단축",
        ],
        "ioc_type": "High SYN flag ratio",
    },
    "http_flood": {
        "mitre_tactic":    "Impact",
        "mitre_technique": "T1499.003 - Application Exhaustion Flood",
        "remediation_steps": [
            "1. WAF 속도 제한 규칙 강화",
            "2. CAPTCHA / 챌린지 페이지 적용",
            "3. CDN 엣지에서 트래픽 필터링",
        ],
        "ioc_type": "High HTTP request rate",
    },
    "ransomware": {
        "mitre_tactic":    "Impact",
        "mitre_technique": "T1486 - Data Encrypted for Impact",
        "remediation_steps": [
            "1. 감염 의심 호스트 즉시 네트워크 격리",
            "2. SMB/RDP 포트 방화벽 차단",
            "3. 백업 무결성 확인 및 복구 절차 준비",
        ],
        "ioc_type": "Lateral movement via SMB/RDP",
    },
    "portscan": {
        "mitre_tactic":    "Reconnaissance",
        "mitre_technique": "T1046 - Network Service Discovery",
        "remediation_steps": [
            "1. 출발지 IP 모니터링 목록 추가",
            "2. 불필요한 포트 방화벽 차단",
            "3. 허니팟(Honeypot) 배치 검토",
        ],
        "ioc_type": "Rapid multi-port access from single IP",
    },
    "arp_spoofing": {
        "mitre_tactic":    "Credential Access",
        "mitre_technique": "T1557.002 - ARP Cache Poisoning",
        "remediation_steps": [
            "1. 스위치에서 동적 ARP 검사(DAI) 활성화",
            "2. 정적 ARP 테이블 항목 설정",
            "3. 네트워크 세그멘테이션 강화",
        ],
        "ioc_type": "Anomalous ICMP/ARP traffic",
    },
    "dns_tunneling": {
        "mitre_tactic":    "Command and Control",
        "mitre_technique": "T1071.004 - Application Layer Protocol: DNS",
        "remediation_steps": [
            "1. DNS 쿼리 크기 및 빈도 제한",
            "2. DNS 보안 확장(DNSSEC) 적용",
            "3. 외부 DNS 서버 접근 차단, 내부 DNS 전용 사용",
        ],
        "ioc_type": "Oversized DNS packets",
    },
    "bruteforce": {
        "mitre_tactic":    "Credential Access",
        "mitre_technique": "T1110 - Brute Force",
        "remediation_steps": [
            "1. 연속 로그인 실패 후 계정 잠금 정책 적용",
            "2. MFA(다중 인증) 활성화",
            "3. 출발지 IP 차단 목록 추가",
        ],
        "ioc_type": "High failed authentication attempts",
    },
    "exfiltration": {
        "mitre_tactic":    "Exfiltration",
        "mitre_technique": "T1041 - Exfiltration Over C2 Channel",
        "remediation_steps": [
            "1. 아웃바운드 트래픽 DLP(데이터 유출 방지) 솔루션 점검",
            "2. 대용량 전송 경보 임계값 하향 조정",
            "3. 관련 계정 및 시스템 즉시 감사",
        ],
        "ioc_type": "High outbound data ratio",
    },
    "botnet_c2": {
        "mitre_tactic":    "Command and Control",
        "mitre_technique": "T1095 - Non-Application Layer Protocol",
        "remediation_steps": [
            "1. 알려진 C2 포트(4444, 6667 등) 방화벽 차단",
            "2. 감염 의심 호스트 엔드포인트 악성코드 스캔",
            "3. 네트워크 플로우 분석으로 비콘 패턴 추가 확인",
        ],
        "ioc_type": "Connection to known C2 ports",
    },
    "slowloris": {
        "mitre_tactic":    "Impact",
        "mitre_technique": "T1499 - Endpoint Denial of Service",
        "remediation_steps": [
            "1. 웹 서버 연결 타임아웃 단축 설정",
            "2. IP당 최대 동시 연결 수 제한",
            "3. 리버스 프록시(Nginx/HAProxy) 앞단 배치",
        ],
        "ioc_type": "Long idle connections with slow transfer",
    },
}


class ContextEnricher:
    agent_id = "agent-24-context-enricher"

    def process(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        attack = alert.get("attack_type", "unknown")
        ctx = THREAT_CONTEXT.get(attack, {
            "mitre_tactic":    "Unknown",
            "mitre_technique": "Unknown",
            "remediation_steps": ["보안 이벤트 조사 및 로그 검토 필요"],
            "ioc_type":        "Unknown",
        })
        alert["mitre_tactic"] = ctx["mitre_tactic"]
        alert["mitre_technique"] = ctx["mitre_technique"]
        alert["remediation_steps"] = ctx["remediation_steps"]
        alert["ioc_type"] = ctx["ioc_type"]
        return alert
