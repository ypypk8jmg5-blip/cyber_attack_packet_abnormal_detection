# 비정상 패킷 탐지 멀티 에이전트 시스템 — 연구문제 정의 프레임워크

> **대상 시스템**: anomaly-detection-mlops (32개 에이전트, 7개 레이어)  
> **작성일**: 2026-04-30  
> **목적**: AI 에이전트·스킬파일·워크플로우·페르소나 4개 관점에서 연구문제를 체계적으로 정의

---

## 목차

1. [핵심 연구문제 (RQ-1 ~ RQ-5)](#1-핵심-연구문제)
2. [AI 에이전트 관점](#2-ai-에이전트-관점)
3. [스킬 파일 명세](#3-스킬-파일-명세)
4. [워크플로우 설계](#4-워크플로우-설계)
5. [페르소나 정의](#5-페르소나-정의)
6. [통합 연구 프레임워크](#6-통합-연구-프레임워크)
7. [연구 로드맵](#7-연구-로드맵)

---

## 1. 핵심 연구문제

| 번호 | 연구문제 | 측정 지표 | 목표값 |
|------|---------|---------|--------|
| **RQ-1** | 8개 이질적 분석 에이전트의 가중 앙상블이 단일 RandomForest 대비 탐지 정확도를 유의미하게 향상시키는가? | F1, TPR, FPR | F1 ≥ 0.92, TPR ≥ 0.90, FPR ≤ 0.05 |
| **RQ-2** | 각 에이전트의 스킬 파일이 11개 공격 유형을 충분히 커버하는가? (스킬 충분성) | 공격 유형별 리콜 | 전 유형 Recall ≥ 0.90 |
| **RQ-3** | 100ms SLA 내에서 fan-out/fan-in 워크플로우가 안정적으로 처리 가능한가? | E2E P95 지연, 처리량 | P95 < 100ms, ≥ 50 pps |
| **RQ-4** | Rule Veto 메커니즘과 ConflictResolver가 에이전트 페르소나 충돌을 올바르게 중재하는가? | Veto 정확도, 충돌 해소율 | Veto FP < 5%, 충돌 해소율 > 95% |
| **RQ-5** | 피드백 루프(Layer 6)가 개념 표류(concept drift) 발생 시 자동으로 모델을 갱신하여 탐지 성능을 유지하는가? | PSI 감지 정확도, 재학습 후 F1 회복 속도 | PSI 감지 정확도 > 90%, 회복 ≤ 3 사이클 |

---

## 2. AI 에이전트 관점

### 2.1 에이전트 존재 정의 3요소

```
┌─────────────────────────────────────────────┐
│           AI 에이전트 = P + R + A            │
├─────────────┬─────────────┬─────────────────┤
│ Perception  │  Reasoning  │     Action      │
│ (인식)       │  (추론)      │    (행동)        │
├─────────────┼─────────────┼─────────────────┤
│ 패킷 피처    │ 스킬 실행    │ AnalysisVote    │
│ 12차원 벡터  │ 알고리즘     │ 반환 (확률값)   │
│ 컨텍스트     │ 상태 갱신    │ 상태 저장       │
└─────────────┴─────────────┴─────────────────┘
```

### 2.2 자율성 스펙트럼

| 레벨 | 유형 | 해당 에이전트 | 특성 |
|------|------|-------------|------|
| L1 | **Stateless 반응형** | Agent-02, 03, 08, 11 | 입력→출력, 내부 상태 없음, 결정론적 |
| L2 | **Stateful 적응형** | Agent-05, 06, 09, 10, 12 | 슬라이딩 윈도우·프로파일 유지, 점진 학습 |
| L3 | **Strategic 자율형** | Agent-17 (PipelineOrchestrator) | 상태 머신, 장기 목표 관리, 에이전트 재시작 |

### 2.3 에이전트 의존성 그래프

```
Agent-01 → Agent-02 → Agent-03 → Agent-04
                                     │ (fan-out)
          ┌──────────┬──────────┬────┼────┬──────────┬──────────┬──────────┐
      [05]     [06]     [07]     [08]    [09]      [10]      [11]      [12]
          └──────────┴──────────┴────┼────┴──────────┴──────────┴──────────┘
                                     │ (fan-in)
                                 Agent-13 → Agent-14 → Agent-15 → Agent-16
                                                                       │
                                 Agent-21 → Agent-22 → Agent-23 → Agent-24
                                     │
                        ┌────────────┴──────────────┐
                    Layer-6 (학습)              Layer-7 (평가)
               Agent-25~28                   Agent-29~32
```

### 2.4 RQ-1 세부 연구 설계

**실험 설계**:
- **통제군**: 단일 RandomForest (Agent-06만 사용)
- **실험군 A**: 8개 에이전트 균등 가중치 앙상블
- **실험군 B**: 최적화 가중치 앙상블 (RF=0.35, Rule=0.25, DL=0.20, ...)
- **실험군 C**: Rule Veto 포함 실험군 B

**측정 방법**: 10-fold 교차 검증, McNemar 검정으로 유의성 확인 (p < 0.05)

---

## 3. 스킬 파일 명세

### 3.1 스킬 정의 원칙

스킬(Skill)은 에이전트가 보유한 **원자적 능력 단위**로 정의:
- `name`: 스킬 고유 식별자
- `input_schema`: 입력 데이터 타입
- `output_schema`: 반환 데이터 타입
- `preconditions`: 실행 조건
- `performance_sla`: 처리 시간 목표
- `covered_attacks`: 탐지 가능한 공격 유형

---

### 3.2 Layer 2 분석 에이전트 스킬

#### Agent-05 스킬: `statistical_anomaly_detection`

```yaml
skill:
  name: statistical_anomaly_detection
  agent: agent-05-statistical-analyzer
  weight: 0.10

input_schema:
  feature_vector: float[12]
  packet_id: str

output_schema: AnalysisVote

algorithm:
  method: Z-score (Welford online)
  threshold: 3.5σ
  window: 1000 packets
  state: sliding_window_mean_variance

preconditions:
  - warmup_packets >= 30

performance_sla:
  p50_ms: 5
  p95_ms: 5

covered_attacks:
  primary: [syn_flood, ddos, port_scan]
  secondary: [http_flood, brute_force]
  weakness: [slowloris, botnet_c2]  # 느린 저강도 공격 미탐
```

#### Agent-06 스킬: `ml_binary_classification`

```yaml
skill:
  name: ml_binary_classification
  agent: agent-06-ml-classifier
  weight: 0.35  # 앙상블 최고 가중치

input_schema:
  feature_vector: float[12]
  packet_id: str

output_schema: AnalysisVote

algorithm:
  method: RandomForest (100 estimators)
  model_file: data/models/best_model.pkl
  hot_reload: true  # mtime 변경 감지 시 자동 재로드

preconditions:
  - model_file_exists: data/models/best_model.pkl

performance_sla:
  p50_ms: 10
  p95_ms: 10

covered_attacks:
  primary: [syn_flood, port_scan, brute_force, ddos, ransomware]
  secondary: [http_flood, dns_tunneling, exfiltration]
  weakness: [slowloris, botnet_c2]  # 장기 저속 공격 미탐 가능
```

#### Agent-07 스킬: `lstm_autoencoder_reconstruction`

```yaml
skill:
  name: lstm_autoencoder_reconstruction
  agent: agent-07-deep-learning
  weight: 0.20

input_schema:
  feature_vector: float[12]
  packet_id: str
  src_ip: str  # 시퀀스 버퍼 키

output_schema: AnalysisVote

algorithm:
  method: LSTM Autoencoder
  sequence_length: 20
  threshold: reconstruction_error > mean + 3σ
  state: per_ip_sequence_buffer (deque maxlen=20)
  warmup: 200 packets

preconditions:
  - pytorch_available: true  # 미설치 시 neutral vote 반환
  - sequence_length >= 5

performance_sla:
  p50_ms: 30
  p95_ms: 50

covered_attacks:
  primary: [botnet_c2, slowloris]  # 시계열 패턴 특화
  secondary: [exfiltration, ransomware]
```

#### Agent-08 스킬: `rule_signature_matching`

```yaml
skill:
  name: rule_signature_matching
  agent: agent-08-rule-signature
  weight: 0.25

input_schema:
  feature_vector: float[12]
  packet_id: str

output_schema: AnalysisVote

algorithm:
  method: Deterministic rule matching (11 rules)
  matched_confidence: 0.95
  no_match_confidence: 0.05
  veto_threshold: 0.92  # 이 신뢰도 이상이면 앙상블 floor 0.75 강제

rules:
  syn_flood:    "syn_flag_ratio > 0.85 AND packets_per_sec > 1000"
  ddos:         "packets_per_sec > 5000 AND connection_count > 500"
  port_scan:    "connection_count > 100 AND duration < 5"
  brute_force:  "failed_attempts > 50 AND duration < 60"
  exfiltration: "bytes_per_sec > 1e6 AND outbound_ratio > 0.9"
  dns_tunneling: "protocol == UDP AND bytes_per_packet > 400"
  http_flood:   "packets_per_sec > 500 AND protocol == TCP"
  slowloris:    "duration > 60 AND packets_per_sec < 0.5 AND connection_count > 200"
  botnet_c2:    "connection_count > 50 AND duration > 300 AND packets_per_sec < 2"
  ransomware:   "bytes_per_sec > 5e5 AND failed_attempts > 20 AND src_port < 1024"
  arp_spoofing: "protocol == ICMP AND duration < 1 AND packets_per_sec > 100"

performance_sla:
  p50_ms: 0.003
  p95_ms: 0.003  # 최고속

covered_attacks:
  primary: [all 11 types]  # 모든 공격 커버 (단, 변종 취약)
  weakness: [zero_day, obfuscated_attacks]
```

#### Agent-09 스킬: `behavioral_profile_tracking`

```yaml
skill:
  name: behavioral_profile_tracking
  agent: agent-09-behavioral-profile
  weight: 0.15

input_schema:
  feature_vector: float[12]
  packet_id: str
  src_ip: str

output_schema: AnalysisVote

algorithm:
  method: EWMA (Exponentially Weighted Moving Average)
  alpha: 0.1  # 감쇠 계수
  deviation_threshold: 4.0σ
  state: per_ip_ewma_profile
  expiry: 24 hours inactivity

performance_sla:
  p50_ms: 3
  p95_ms: 3

covered_attacks:
  primary: [exfiltration, botnet_c2]  # 점진적 이상 특화
  secondary: [slowloris, ransomware]
```

#### Agent-10 스킬: `temporal_burst_beacon_detection`

```yaml
skill:
  name: temporal_burst_beacon_detection
  agent: agent-10-temporal-pattern
  weight: 0.05

input_schema:
  feature_vector: float[12]
  packet_id: str
  timestamp: float

output_schema: AnalysisVote

algorithm:
  burst_detection: CUSUM (cumulative sum control chart)
  beacon_detection: FFT (30s, 60s, 300s 주기 탐지)
  window: 60 seconds (1초 해상도)

performance_sla:
  p50_ms: 5
  p95_ms: 5

covered_attacks:
  primary: [ddos, botnet_c2]  # 버스트·주기적 통신 특화
  secondary: [syn_flood]
```

#### Agent-11 스킬: `protocol_violation_detection`

```yaml
skill:
  name: protocol_violation_detection
  agent: agent-11-protocol-specific
  weight: 0.00  # 독립 분류가 아닌 attack_type 보정 역할

input_schema:
  feature_vector: float[12]
  packet_id: str
  protocol: str

output_schema: AnalysisVote (attack_type 필드 정정)

role: attack_type_correction  # 다른 에이전트의 공격 유형 필드를 정정

protocol_rules:
  TCP: [syn_flood, brute_force, ransomware, http_flood, slowloris, exfiltration]
  UDP: [dns_tunneling, ddos]
  ICMP: [arp_spoofing, port_scan]
```

#### Agent-12 스킬: `flow_level_correlation`

```yaml
skill:
  name: flow_level_correlation
  agent: agent-12-flow-correlation
  weight: 0.00  # 플로우 레벨 집계, 개별 패킷 판단 보조

input_schema:
  feature_vector: float[12]
  packet_id: str
  src_ip: str
  dst_port: int

output_schema: AnalysisVote

algorithm:
  method: Flow table aggregation (src_ip, dst_port)
  port_scan_detection: "single IP → many ports within 10s"
  ddos_aggregation: "flow-level packet rate"
  beacon_detection: "inter-arrival variance < threshold"
  state: flow_table (5 min expiry)

performance_sla:
  p50_ms: 20
  p95_ms: 20

covered_attacks:
  primary: [port_scan, ddos, botnet_c2]  # 플로우 레벨 탐지 특화
```

---

### 3.3 Layer 3 결정 에이전트 스킬

#### Agent-13 스킬: `weighted_ensemble_aggregation`

```yaml
skill:
  name: weighted_ensemble_aggregation
  agent: agent-13-evidence-aggregator

input_schema:
  votes: List[AnalysisVote]  # 최대 8개

output_schema: AggregatedDecision

algorithm:
  weights: {rf: 0.35, rule: 0.25, dl: 0.20, behavioral: 0.15, stat: 0.10, temporal: 0.05}
  veto: "rule confidence >= 0.92 → score floor = 0.75"
  timeout_handling: "missing votes excluded, weights renormalized"
  attack_type: "majority vote among anomaly-detecting agents"
```

#### Agent-14 스킬: `conflict_resolution`

```yaml
skill:
  name: conflict_resolution
  agent: agent-14-conflict-resolver

conflict_rules:
  priority_1: "Rule(≥0.90) vs RF disagreement → Rule wins"
  priority_2: "RF(≥0.70) + Behavioral(≥0.70) → score +0.05 boost"
  priority_3: "Statistical-only flag → confidence capped at 0.35"
  priority_4: "DL strong normal(≤0.20) vs Rule anomaly → log conflict"
```

---

### 3.4 스킬 보완성 매트릭스

| 공격 유형 | Rule(08) | RF(06) | DL(07) | Stat(05) | Behav(09) | Temp(10) | Proto(11) | Flow(12) |
|---------|---------|--------|--------|---------|---------|---------|---------|---------|
| SYN Flood | ✅ 주 | ✅ 주 | ➖ | ✅ 부 | ➖ | ✅ 부 | ✅ 보정 | ✅ 부 |
| DDoS | ✅ 주 | ✅ 주 | ➖ | ✅ 부 | ➖ | ✅ 주 | ✅ 보정 | ✅ 주 |
| Port Scan | ✅ 주 | ✅ 주 | ➖ | ✅ 부 | ➖ | ➖ | ✅ 보정 | ✅ 주 |
| Brute Force | ✅ 주 | ✅ 주 | ➖ | ✅ 부 | ✅ 부 | ➖ | ✅ 보정 | ➖ |
| Exfiltration | ✅ 주 | ✅ 부 | ✅ 부 | ➖ | ✅ 주 | ➖ | ✅ 보정 | ➖ |
| DNS Tunneling | ✅ 주 | ✅ 부 | ➖ | ➖ | ➖ | ➖ | ✅ 보정 | ➖ |
| HTTP Flood | ✅ 주 | ✅ 주 | ➖ | ✅ 부 | ➖ | ✅ 부 | ✅ 보정 | ➖ |
| **Slowloris** | ✅ 주 | ⚠️ 취약 | ✅ 주 | ⚠️ 취약 | ✅ 부 | ➖ | ✅ 보정 | ➖ |
| **Botnet C2** | ✅ 주 | ⚠️ 취약 | ✅ 주 | ➖ | ✅ 주 | ✅ 주 | ✅ 보정 | ✅ 주 |
| Ransomware | ✅ 주 | ✅ 주 | ✅ 부 | ➖ | ✅ 부 | ➖ | ✅ 보정 | ➖ |
| ARP Spoofing | ✅ 주 | ✅ 부 | ➖ | ✅ 부 | ➖ | ➖ | ✅ 보정 | ➖ |

> ✅ 주 = 주 탐지, ✅ 부 = 보조 탐지, ⚠️ 취약 = 미탐 위험, ➖ = 비해당

**RQ-2 시사점**: Slowloris·Botnet C2는 RF 단독으로 취약 → DL+Behavioral 앙상블이 필수. 스킬 커버리지 분석이 앙상블 가중치 결정에 직접 활용됨.

---

## 4. 워크플로우 설계

### 4.1 4계층 워크플로우 계층 구조

```
[WF-L1] 시스템 생애주기 워크플로우
    └── Phase 1: 학습 루프 (F1 ≥ 0.92 달성까지)
    └── Phase 2: 실시간 탐지 루프 (무한)
    └── Phase 3: 재학습 트리거 (드리프트 감지 시)

[WF-L2] 패킷 처리 마이크로 워크플로우 (per-packet, P95 < 100ms)
    └── Ingest → Normalize → Extract → Enrich
    └── [fan-out] → 8 Analysis Agents → [fan-in]
    └── Aggregate → Resolve → Score → Threshold
    └── (anomaly only) → Classify → Generate → Deduplicate → Enrich

[WF-L3] 비동기 피드백 워크플로우 (per-feedback event)
    └── Feedback Collect → Online Update → Drift Check
    └── Performance Monitor (30s heartbeat)

[WF-L4] 주기적 평가 워크플로우 (per-training cycle)
    └── Metrics Calculate → FP Analyze → Coverage Check → Report Generate
```

### 4.2 SLA 테이블

| 워크플로우 | 트리거 | P95 목표 | 실패 처리 |
|---------|------|---------|---------|
| WF-L2 Ingest | 파일 감지 (polling 50ms) | 50ms 감지 | 재시도 없음, 다음 파일 처리 |
| WF-L2 Analysis fan-out | per-packet | 100ms (전체) | 타임아웃 에이전트 → neutral vote |
| WF-L2 Decision | fan-in 완료 후 | 5ms | 에러 시 MEDIUM severity 기본값 |
| WF-L2 Alert output | anomaly 판정 시 | 10ms | 큐잉 후 비동기 저장 |
| WF-L3 Feedback | 50건 누적 | 배치, SLA 없음 | 다음 배치로 이월 |
| WF-L3 Online update | 500건 / 6h | 백그라운드 | 실패 시 현행 모델 유지 |
| WF-L4 Evaluation | 학습 사이클 완료 | 배치, SLA 없음 | 로그 기록 후 계속 |

### 4.3 워크플로우 세부 연구문제

#### RQ-W1: 타임아웃 정책 최적화

**문제**: 100ms 예산 내에서 Agent-07 (LSTM, P95=50ms) 타임아웃 임계값이 탐지 품질과 지연시간 SLA 사이 트레이드오프에 어떤 영향을 미치는가?

**실험 변수**:
- 타임아웃 임계값: 30ms / 50ms / 80ms / 100ms
- 측정 지표: E2E P95 지연, Agent-07 참여율, Botnet C2 탐지율

**가설**: 타임아웃 50ms → LSTM 참여율 70%, Botnet C2 리콜 0.85↑, P95 < 80ms 달성 가능

#### RQ-W2: 역압(Backpressure) 메커니즘

**문제**: Agent-19 LoadBalancer의 큐 깊이 임계값(현재 1000)이 처리량 손실 없이 과부하를 방지하는 최적값인가?

**실험 변수**:
- 큐 깊이 임계값: 500 / 1000 / 2000 / 5000
- 워커 수: 4 / 8 / 16

**측정**: 최대 처리량(pps), 패킷 손실률, P99 지연

#### RQ-W3: 피드백 배치 크기

**문제**: Agent-26 OnlineModelUpdater의 피드백 배치 크기(현재 500건)가 FP 감소 속도와 모델 안정성 사이 최적 균형점인가?

**실험 변수**:
- 배치 크기: 100 / 250 / 500 / 1000 / 2000

**측정**: FP 감소까지 걸린 시간, 모델 성능 분산, 재학습 빈도

---

## 5. 페르소나 정의

페르소나(Persona)는 에이전트의 **행동 성격·전문성·편향**을 정의하여 충돌 해소와 앙상블 설계에 활용.

### 5.1 페르소나 정의 프레임워크

각 에이전트 페르소나는 다음 5개 속성으로 정의:

| 속성 | 설명 |
|------|------|
| **Identity** | 에이전트 이름 및 별칭(역할 은유) |
| **Expertise** | 핵심 전문 알고리즘 / 탐지 강점 |
| **Bias** | 편향 방향 (FP 허용형 vs FN 허용형) |
| **행동 원칙** | 판단 우선순위 기준 |
| **약점** | 취약한 시나리오 |

---

### 5.2 Layer 1: 수집 레이어 페르소나

| 에이전트 | 별칭 | 역할 | 특성 |
|---------|------|------|------|
| Agent-01 | **파수꾼** (PacketReceiver) | 파일 감시·배치 수신 | 비놓침 우선, polling 50ms 이내 |
| Agent-02 | **세관원** (Normalizer) | 유효성 검사·정규화 | 이상값 클리핑, 결측치 보정 |
| Agent-03 | **분석관** (FeatureExtractor) | 12차원 피처 벡터 생성 | bytes_per_packet, failure_rate 파생 피처 |
| Agent-04 | **브리퍼** (Enricher) | 컨텍스트 보강·fan-out | 포트→서비스 매핑, IP 분류 |

---

### 5.3 Layer 2: 분석 레이어 페르소나 (핵심)

#### Agent-05: 통계학자 (StatisticalAnalyzer)

| 속성 | 내용 |
|------|------|
| **Identity** | 통계학자 — "숫자가 거짓말하지 않는다" |
| **Expertise** | Z-score, Welford 온라인 알고리즘, 통계적 베이스라인 |
| **Bias** | **FP 허용형** — 통계적 이상치는 반드시 리포트 (정상이더라도) |
| **행동 원칙** | 3.5σ 이상 편차는 무조건 보고, 에이전트 중 가장 보수적 |
| **약점** | 단독 판단 시 오탐률 높음 → ConflictResolver에서 cap=0.35 부여 |
| **특기** | 초기 이상징후를 다른 에이전트보다 빨리 감지 |

#### Agent-06: 베테랑 형사 (MLClassifier)

| 속성 | 내용 |
|------|------|
| **Identity** | 베테랑 형사 — "과거 사례를 모두 기억한다" |
| **Expertise** | RandomForest, 학습된 패턴 인식, hot-reload |
| **Bias** | **균형형** — 학습 데이터 분포에 따라 결정, weight=0.35 최고 |
| **행동 원칙** | 학습 데이터가 곧 법전; 신규 패턴에는 보수적 |
| **약점** | 학습 데이터에 없는 변종 공격 미탐 (개념 표류 취약) |
| **특기** | 알려진 공격 유형에 가장 높은 정밀도 |

#### Agent-07: 시계열 직관가 (DeepLearningAgent)

| 속성 | 내용 |
|------|------|
| **Identity** | 시계열 직관가 — "흐름 속에 숨겨진 패턴을 본다" |
| **Expertise** | LSTM Autoencoder, 시계열 재구성 오차, per-IP 시퀀스 |
| **Bias** | **FN 허용형** — 불확실하면 neutral 반환 (warmup 200 packets) |
| **행동 원칙** | Slowloris·Botnet C2 등 장기 패턴에 집중 |
| **약점** | PyTorch 미설치 시 비활성화, 짧은 세션 탐지 불가 |
| **특기** | 다른 에이전트가 정상으로 분류한 장기 공격 탐지 |

#### Agent-08: 규칙 집행관 (RuleSignatureAgent)

| 속성 | 내용 |
|------|------|
| **Identity** | 규칙 집행관 — "법은 명확하다. 예외 없다" |
| **Expertise** | 11개 하드코딩 시그니처 룰, 결정론적 판단 |
| **Bias** | **FP 허용형 + Veto 권한** — confidence ≥ 0.92이면 앙상블 override |
| **행동 원칙** | 룰에 해당하면 확정 (0.95 신뢰도), 미해당이면 무죄 (0.05) |
| **약점** | 룰 외 Zero-day, 변종 공격에 완전히 무력 |
| **특기** | P50=0.003ms 최고속, Veto로 앙상블 전체를 결정 가능 |

#### Agent-09: 행동 심리학자 (BehavioralProfileAgent)

| 속성 | 내용 |
|------|------|
| **Identity** | 행동 심리학자 — "평소와 다르면 의심한다" |
| **Expertise** | EWMA per-IP 프로파일, 장기 행동 패턴 추적 |
| **Bias** | **균형형** — IP별 정상 행동 기준으로 상대적 판단 |
| **행동 원칙** | 4σ 이상 편차 = 비정상; 신규 IP는 보수적 판단 |
| **약점** | IP 스푸핑 시 프로파일 오염, 신규 IP warm-up 기간 blind spot |
| **특기** | 점진적 데이터 유출, 장기 Botnet 비콘 특화 탐지 |

#### Agent-10: 패턴 분석가 (TemporalPatternAgent)

| 속성 | 내용 |
|------|------|
| **Identity** | 패턴 분석가 — "리듬이 깨지면 이상이다" |
| **Expertise** | CUSUM 버스트 감지, FFT 주기성 분석 |
| **Bias** | **FP 허용형** — 버스트·비콘 패턴에 민감 반응 |
| **행동 원칙** | DDoS 급증, C2 주기적 통신 (30/60/300초) 탐지 우선 |
| **약점** | 단독 판단 시 정상 트래픽 폭증과 DDoS 구별 어려움 |
| **특기** | 가장 빠른 DDoS 조기 경보 (CUSUM) |

#### Agent-11: 프로토콜 감찰관 (ProtocolSpecificAgent)

| 속성 | 내용 |
|------|------|
| **Identity** | 프로토콜 감찰관 — "규약대로 하지 않으면 수상하다" |
| **Expertise** | TCP/UDP/ICMP 프로토콜 기대 동작 위반 감지 |
| **Bias** | **중립** — attack_type 필드 보정 역할 (가중치 0) |
| **행동 원칙** | 프로토콜 맥락 상 불가능한 공격 유형 필드 정정 |
| **약점** | 단독으로는 분류 불가, 보조 역할에 한정 |
| **특기** | 다른 에이전트의 오분류 공격 유형 교정 |

#### Agent-12: 흐름 탐정 (FlowCorrelationAgent)

| 속성 | 내용 |
|------|------|
| **Identity** | 흐름 탐정 — "한 패킷이 아닌 전체 흐름을 본다" |
| **Expertise** | (src_ip, dst_port) 플로우 집계, 포트스캔·DDoS 플로우 탐지 |
| **Bias** | **FP 허용형** — 플로우 레벨 이상은 모두 보고 |
| **행동 원칙** | 개별 패킷 정상 → 플로우 비정상 케이스 특화 |
| **약점** | 5분 플로우 테이블 → 단기 공격 추적 제한, 메모리 부담 |
| **특기** | 포트스캔 (단일 IP → 다수 포트) 가장 정확히 탐지 |

---

### 5.4 Layer 3: 결정 레이어 페르소나

| 에이전트 | 별칭 | 역할 | 페르소나 |
|---------|------|------|---------|
| Agent-13 | **배심원단장** (EvidenceAggregator) | 가중 앙상블 집계 | 8명의 의견을 공정하게 취합; Veto 존중 |
| Agent-14 | **조정관** (ConflictResolver) | 에이전트 충돌 해소 | 규칙 우선 원칙, RF+Behavioral 동시 이상 시 부스트 |
| Agent-15 | **검보정관** (ConfidenceScorer) | Platt Scaling 보정 | 원시 확률 → 실제 확률로 변환 |
| Agent-16 | **임계값 관리자** (ThresholdManager) | 동적 임계값 조정 | FPR > 5% → 임계값 ↑, FNR > 10% → 임계값 ↓ |

---

### 5.5 Layer 4: 오케스트레이션 레이어 페르소나

| 에이전트 | 별칭 | 역할 | 페르소나 |
|---------|------|------|---------|
| Agent-17 | **총지휘관** (PipelineOrchestrator) | 전체 생애주기 관리 | IDLE→TRAINING→DETECTION 상태 머신, 30초 헬스체크 |
| Agent-18 | **선발대장** (SubOrchestrator) | fan-out/fan-in 관리 | 100ms 예산 엄수, 실패 에이전트 neutral 대체 |
| Agent-19 | **교통 통제관** (LoadBalancer) | 처리량 분산·역압 | 큐 깊이 > 1000 → Agent-01 속도 제한 신호 |
| Agent-20 | **우선순위 조정관** (PriorityScheduler) | 위험 패킷 선처리 | suspicious_port(+10), UNKNOWN_service(+8), external_ip(+5) |

---

### 5.6 Layer 5: 출력 레이어 페르소나

| 에이전트 | 별칭 | 역할 | 페르소나 |
|---------|------|------|---------|
| Agent-21 | **심각도 판사** (SeverityClassifier) | CRITICAL/HIGH/MEDIUM/LOW 분류 | 신뢰도 0.50~0.60이면 한 단계 강등 |
| Agent-22 | **보고서 작성관** (AlertGenerator) | 구조화 알림 JSON 생성 | 기존 스키마 + multi_agent_context 확장 |
| Agent-23 | **중복 제거관** (AlertDeduplicator) | 60초 중복 억제 | (src_ip, attack_type) 키로 dedup |
| Agent-24 | **전술 분석가** (ContextEnricher) | MITRE ATT&CK 매핑 | 11개 공격 유형 전술·기술·대응 절차 |

---

### 5.7 Layer 6: 학습 레이어 페르소나

| 에이전트 | 별칭 | 역할 | 페르소나 |
|---------|------|------|---------|
| Agent-25 | **피드백 수집관** (FeedbackCollector) | TP/FP/FN 수집 | normal_ftp/stream 자동 FP 생성 (556건 문제 해소) |
| Agent-26 | **모델 갱신사** (OnlineModelUpdater) | 섀도우 테스트 후 모델 교체 | 1000패킷 병렬 검증, F1 +0.01↑ 시 승격 |
| Agent-27 | **표류 감지관** (DriftDetector) | PSI 기반 분포 변화 감지 | MILD/MODERATE/SEVERE 3단계 경보 |
| Agent-28 | **성능 감시관** (PerformanceMonitor) | 실시간 메트릭 수집 | P50/P95/P99 지연, FPR, 처리량 대시보드 |

---

### 5.8 Layer 7: 평가 레이어 페르소나

| 에이전트 | 별칭 | 역할 | 페르소나 |
|---------|------|------|---------|
| Agent-29 | **성적표 작성관** (MetricsCalculator) | F1/Recall/Precision/AUC 계산 | 11개 공격 유형 전부 평가, 에이전트별 기여도 행렬 |
| Agent-30 | **오탐 분석관** (FalsePositiveAnalyzer) | FP 패턴 심층 분석 | normal_ftp(215건) + normal_stream(341건) 자동 식별 |
| Agent-31 | **커버리지 검사관** (AttackCoverageAgent) | 공격 유형별 리콜 측정 | fully/partially/poorly covered 3단계 분류 |
| Agent-32 | **종합 보고관** (ReportGenerator) | 통합 보고서 생성 | 학습·탐지·FP·커버리지·드리프트 통합 |

---

### 5.9 RQ-4: 페르소나 충돌 분석 매트릭스

가장 빈번한 충돌 쌍과 해소 메커니즘:

| 충돌 쌍 | 충돌 이유 | ConflictResolver 해소 방법 | 예상 발생 빈도 |
|--------|---------|--------------------------|-------------|
| Agent-08 vs Agent-06 | 룰 매칭(HIGH) vs RF 정상(LOW) | Rule 우선 (priority_1) | 높음 (신규 변종) |
| Agent-06 + Agent-09 vs Agent-07 | RF+Behavioral 이상 vs DL 정상 | +0.05 boost (priority_2) | 중간 |
| Agent-05 단독 이상 | 나머지 7개 정상 | confidence cap 0.35 (priority_3) | 높음 (정상 폭증 시) |
| Agent-07 강한 정상 vs Agent-08 이상 | DL 재구성 오차 낮음 vs 룰 매칭 | conflict_log 기록 (priority_4) | 낮음 |

---

## 6. 통합 연구 프레임워크

### 6.1 4개 관점의 교차점

```
              ┌─────────────────────────┐
              │   AI 에이전트 관점       │
              │   (자율성·의존성 구조)   │
              └─────────┬───────────────┘
                        │
         ┌──────────────┼──────────────┐
         ▼              ▼              ▼
┌────────────┐  ┌────────────┐  ┌────────────┐
│ 스킬 파일  │  │ 앙상블     │  │ 워크플로우 │
│ 관점       │  │ 결정 엔진  │  │ 관점       │
│ (능력 정의)│  │ (Agent-13  │  │ (처리 흐름)│
│            │◄─┤  ~16)      ├─►│            │
└────────────┘  └─────┬──────┘  └────────────┘
                      │
              ┌───────▼────────┐
              │  페르소나 관점  │
              │  (행동 원칙·   │
              │   충돌 해소)   │
              └────────────────┘
```

### 6.2 연구문제 간 인과 구조

```
RQ-2 (스킬 충분성)
    │
    ▼
RQ-1 (앙상블 정확도) ─────────────────────────────────────────┐
    │                                                          │
    ▼                                                          │
RQ-4 (페르소나 충돌 해소) → 가중치·Veto 최적화 → RQ-1 개선   │
    │                                                          │
    ▼                                                          │
RQ-3 (워크플로우 효율성) → SLA 달성 → 실시간 탐지 가능        │
    │                                                          ▼
RQ-5 (자기 학습 루프) → 드리프트 적응 → 장기 RQ-1 성능 유지  ◄┘
```

---

## 7. 연구 로드맵

| 단계 | 기간 | 주요 연구문제 | 핵심 실험 | 기대 성과물 |
|------|------|-------------|---------|-----------|
| **Phase 1** 기반 검증 | Week 1-2 | RQ-2 (스킬 커버리지) | 11개 공격 유형 스킬 매핑 | 스킬 갭 리포트 |
| **Phase 2** 앙상블 최적화 | Week 3-4 | RQ-1, RQ-4 | A/B 테스트 (단일 vs 앙상블), Veto 임계값 실험 | 최적 가중치 테이블 |
| **Phase 3** 워크플로우 튜닝 | Week 5-6 | RQ-3, RQ-W1/W2 | 타임아웃·큐 깊이·워커 수 그리드 서치 | SLA 달성 설정값 |
| **Phase 4** 자기 학습 | Week 7-8 | RQ-5, RQ-W3 | 피드백 배치 크기 실험, PSI 임계값 튜닝 | 드리프트 회복 곡선 |
| **Phase 5** 통합 평가 | Week 9-10 | RQ-1 최종 | 10-fold CV, McNemar 검정 | 최종 성능 논문 |

---

## 부록: 성능 벤치마크 기준선

현재 구현 기준 측정값 (2026-04-30):

| 지표 | 측정값 | 목표값 | 상태 |
|------|--------|--------|------|
| TPR (탐지율) | 100% (11/11 유형) | ≥ 90% | ✅ 달성 |
| FPR (오탐율) | 0.00% | ≤ 5% | ✅ 달성 |
| Fan-out P50 | 28.37ms | - | 참조값 |
| Fan-out P95 | 31.14ms | < 100ms | ✅ 달성 (68.9% 여유) |
| Fan-out P99 | 59.23ms | < 100ms | ✅ 달성 |
| 처리량 | 34.8 pps | ≥ 50 pps | ⚠️ 목표 미달 |
| F1 Score | 학습 목표 | ≥ 0.92 | 진행 중 |
| Recall | 학습 목표 | ≥ 0.90 | 진행 중 |
| Precision | 학습 목표 | ≥ 0.88 | 진행 중 |

> **처리량 개선 방향**: ProcessPoolExecutor 워커 수 증가 (현재 단일 스레드 모드), Agent-19 LoadBalancer 활성화 시 목표 달성 가능

---

*이 문서는 `anomaly-detection-mlops` 멀티 에이전트 시스템의 연구문제 정의 프레임워크로, 시스템 설계·구현·평가의 이론적 기반을 제공합니다.*
