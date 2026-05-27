# MLOps 파이프라인 GUI 대시보드 — 구현 계획

> **대상 프로젝트**: anomaly-detection-mlops  
> **작성일**: 2026-05-01  
> **목적**: 32개 에이전트 멀티 에이전트 파이프라인 실행 시각화 및 제어

---

## 목차

1. [개요](#1-개요)
2. [프레임워크 선택](#2-프레임워크-선택)
3. [파일 구조](#3-파일-구조)
4. [전체 레이아웃](#4-전체-레이아웃)
5. [탭별 상세 설계](#5-탭별-상세-설계)
6. [스레드·통신 구조](#6-스레드통신-구조)
7. [위젯 명세](#7-위젯-명세)
8. [실시간 업데이트 방식](#8-실시간-업데이트-방식)
9. [구현 순서](#9-구현-순서)
10. [필요 패키지 및 실행 방법](#10-필요-패키지-및-실행-방법)
11. [잠재적 문제와 해결책](#11-잠재적-문제와-해결책)

---

## 1. 개요

### 현재 파이프라인 실행 방식 (CLI)

```bash
python3 run_pipeline.py                        # 기존 순차 모드
python3 run_pipeline.py --ai-gen               # AI 적응형 패킷 생성
python3 run_pipeline.py --multi-agent          # 32개 에이전트 모드
python3 run_pipeline.py --multi-agent --max-batches 5
```

### GUI가 제공할 기능

| 기능 | 설명 |
|------|------|
| **실행 제어** | 모드 선택, 시작/중지 버튼, 경과 시간 표시 |
| **Phase 1 시각화** | 사이클별 F1/Recall/Precision 추이 그래프, 목표 달성 여부 |
| **Phase 2 시각화** | 실시간 경보 통계, 공격 유형별 분포 차트 |
| **에이전트 상태** | 32개 에이전트를 레이어별로 시각화, 활성화 상태 표시 |
| **실시간 로그** | 학습 로그 스크롤, 색상 구분 (ERROR/WARNING/INFO) |

### 데이터 소스 (GUI가 읽는 파일)

| 파일 | 내용 | 담당 탭 |
|------|------|---------|
| `logs/dashboard.json` | 사이클 진행, best_f1, 상태 | Phase1 탭 |
| `data/metrics/latest.json` | F1/Recall/Precision/Accuracy/Loss | Phase1 탭 |
| `data/alerts/summary.json` | 총 경보, 심각도별, 공격 유형별 | Phase2 탭 |
| `logs/training_progress.log` | 텍스트 학습 로그 | 로그 탭 |
| QProcess stdout | 에이전트 실행 로그 | 에이전트 탭, 로그 탭 |

---

## 2. 프레임워크 선택

### 선택: PyQt5

```
이유:
  1. 스레드 안전 시그널-슬롯 메커니즘 (QThread, QProcess)
  2. QProcess로 외부 프로세스(run_pipeline.py) 논블로킹 제어
  3. matplotlib FigureCanvasQTAgg — 차트 위젯 내장 통합
  4. 추가 웹 서버 불필요, 단일 실행 파일
  5. Fusion 스타일로 플랫폼 독립적 UI
```

### tkinter 대비 장점

| 항목 | tkinter | PyQt5 |
|------|---------|-------|
| 스레드 안전 | 수동 처리 필요 | 시그널-슬롯으로 자동 |
| 외부 프로세스 | subprocess 직접 관리 | QProcess 이벤트 드리븐 |
| 차트 통합 | after() 루프 필요 | FigureCanvasQTAgg 내장 |
| 위젯 풍부도 | 기본 | 풍부 (QTableWidget 등) |

---

## 3. 파일 구조

```
anomaly-detection-mlops/
├── run_gui.py                          ← GUI 진입점 (프로젝트 루트에서 실행)
└── gui/
    ├── __init__.py
    ├── main.py                         ← QApplication 초기화
    ├── app_window.py                   ← QMainWindow (탭 컨테이너, 상태바)
    ├── controller.py                   ← 파이프라인 실행/중지 (QProcess)
    ├── data_monitor.py                 ← JSON 파일 폴링 워커 (QThread)
    ├── log_tailer.py                   ← 로그 파일 테일 워커 (QThread)
    │
    ├── tabs/
    │   ├── __init__.py
    │   ├── control_tab.py              ← 실행 제어 탭
    │   ├── phase1_tab.py               ← Phase1 학습 현황 탭
    │   ├── phase2_tab.py               ← Phase2 탐지 현황 탭
    │   ├── agents_tab.py               ← 32개 에이전트 상태 탭
    │   └── log_tab.py                  ← 실시간 로그 탭
    │
    └── widgets/
        ├── __init__.py
        ├── metric_card.py              ← 단일 메트릭 표시 카드
        ├── metric_chart.py             ← F1/Recall/Precision 추이 그래프
        ├── agent_layer_widget.py       ← 에이전트 레이어 그룹 위젯
        └── alert_bar_chart.py          ← 공격 유형별 경보 막대 차트
```

---

## 4. 전체 레이아웃

### 메인 윈도우

```
╔══════════════════════════════════════════════════════════════════╗
║  이상탐지 MLOps 파이프라인 대시보드    상태: PHASE1  PID: 12345  ║  ← 타이틀 + 상태바
╠══════════════════════════════════════════════════════════════════╣
║  [실행 제어]  [Phase1 학습]  [Phase2 탐지]  [에이전트]  [로그]   ║  ← 탭 바
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║                    (활성 탭 내용)                                 ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

### Tab 0: 실행 제어

```
┌─────────────────────────────────────────────────┐
│  실행 모드 선택                                   │
│  ● 기본 모드 (순차 파이프라인)                    │
│  ○ AI 적응형 생성 (--ai-gen)                     │
│  ○ 멀티 에이전트 (--multi-agent)                 │
│                                                  │
│  최대 배치 수: [  5 ▲▼]  (0 = 기본값 5)          │
│                                                  │
│  [ ▶  파이프라인 시작 ]   [ ■  중지 ]            │
│                                                  │
│  상태  : ● IDLE                                  │
│  PID   : -                                       │
│  경과  : 00:00:00                                │
└─────────────────────────────────────────────────┘
```

### Tab 1: Phase1 학습

```
┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐
│  F1  │ │Recall│ │Prec. │ │ Acc. │ │ Loss │   ← 메트릭 카드 5개
│1.000 │ │1.000 │ │1.000 │ │1.000 │ │0.003 │
│ ✓목표│ │ ✓목표│ │ ✓목표│ │      │ │      │
└──────┘ └──────┘ └──────┘ └──────┘ └──────┘

F1        [████████████████████] 108%  사이클 1/20  최고: 1.000 @ #1
Recall    [████████████████████] 111%
Precision [████████████████████] 113%

┌───────────────── F1 / Recall / Precision 추이 ─────────────────┐
│ 1.0 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ (목표 F1 0.92)              │
│ 0.8            ●──●──●                                        │
│ 0.6    ●──●──●                                                │
│ 0.4                                                           │
│      1    2    3    4    5    6   (사이클)                     │
│  — F1   ··· Recall   - - Precision                           │
└────────────────────────────────────────────────────────────────┘
```

### Tab 2: Phase2 탐지

```
┌────────┐ ┌──────────┐ ┌────────┐ ┌────────┐ ┌────────┐
│  총    │ │ CRITICAL │ │  HIGH  │ │ MEDIUM │ │  LOW   │  ← 경보 카드
│ 3,241건│ │  1,406건 │ │  679건 │ │  464건 │ │  692건 │
└────────┘ └──────────┘ └────────┘ └────────┘ └────────┘

배치 처리: 4 / 5   처리 건수: 200건   이상 탐지: 142건 (71%)

┌──────────────── 공격 유형별 경보 분포 ────────────────────────┐
│ ddos           ████████████████████  752                    │
│ synflood       █████████████         432                    │
│ portscan       ████████████          392                    │
│ normal_stream  ██████████            341  ← FP             │
│ exfiltration   ████████              272                    │
│ normal_ftp     ██████                215  ← FP             │
│ bruteforce     ██████                192                    │
│ ...                                                         │
└────────────────────────────────────────────────────────────┘
```

### Tab 3: 에이전트 상태

```
┌─ Layer 0: 생성 ─────────────────────────────────────────────┐
│  [00: AdaptivePacketGenerator  ● ACTIVE ]                   │
└─────────────────────────────────────────────────────────────┘
┌─ Layer 1: 수집 (순차) ───────────────────────────────────────┐
│  [01: PacketReceiver ●]  [02: Normalizer ●]                 │
│  [03: FeatureExtractor ●]  [04: Enricher ●]                 │
└─────────────────────────────────────────────────────────────┘
┌─ Layer 2: 분석 (8개 병렬) ───────────────────────────────────┐
│  [05: Statistical ●]  [06: MLClassifier ●]                  │
│  [07: DeepLearning ●]  [08: RuleSignature ●]                │
│  [09: Behavioral ●]  [10: Temporal ●]                       │
│  [11: Protocol ●]  [12: FlowCorr. ●]                        │
└─────────────────────────────────────────────────────────────┘
┌─ Layer 3: 결정 ──────────┐  ┌─ Layer 4: 오케스트레이션 ──────┐
│  [13] [14] [15] [16]    │  │  [17: PipelineOrch ●]         │
└──────────────────────────┘  │  [18] [19] [20]               │
┌─ Layer 5: 출력 ──────────┐  └───────────────────────────────┘
│  [21] [22] [23] [24]    │
└──────────────────────────┘
┌─ Layer 6: 학습 ─────────────────────────────────────────────┐
│  [25: FeedbackCollector ●]  [26: OnlineUpdater ●]           │
│  [27: DriftDetector ●]  [28: PerfMonitor ●]                 │
└─────────────────────────────────────────────────────────────┘
┌─ Layer 7: 평가 ─────────────────────────────────────────────┐
│  [29: MetricsCalc ●]  [30: FPAnalyzer ●]                    │
│  [31: CoverageAgent ●]  [32: ReportGen ●]                   │
└─────────────────────────────────────────────────────────────┘

에이전트 상태 범례:  ● ACTIVE (초록)   ● IDLE (회색)   ● ERROR (빨강)
```

### Tab 4: 로그

```
┌──────────────────────────────────────────────── [지우기] [저장] ─┐
│ [12:07:51] [Agent-00] 피드백 로드 — 탐지 취약 유형 4개           │
│ [12:07:52] [Agent-00] AI 적응형 패킷 생성 완료 — 6,300건         │
│ [12:07:53] [AI학습기] 학습 시작  총 샘플: 6,300건                │
│ [12:07:54] [AI학습기] [1/5 fold] Train acc: 1.0000               │
│ [12:07:54] [AI학습기] [2/5 fold] Train acc: 1.0000               │
│ [12:07:55] [결과판단기] F1=1.0000 Recall=1.0000                  │  ← 초록
│ [12:07:55] [Agent-17] Targets met at cycle 1!                    │
│ [12:07:55] [Agent-17] === PHASE 2: REAL-TIME DETECTION ===       │
│ [ERROR] 패킷 파일 없음                                            │  ← 빨강
│ [WARNING] 최대 사이클 초과                                        │  ← 주황
└──────────────────────────────────────────────────────────────────┘
```

---

## 5. 탭별 상세 설계

### control_tab.py

```python
클래스: ControlTab(QWidget)

위젯:
  - QButtonGroup (QRadioButton × 3): 실행 모드 선택
  - QSpinBox: 최대 배치 수 (0~100, 기본값 5)
  - QPushButton "▶ 시작" / "■ 중지"
  - QLabel: 상태 / PID / 경과 시간
  - QTimer (1초): 경과 시간 카운터

주요 메서드:
  _on_start_clicked()    → controller.start(mode, max_batches)
  _on_stop_clicked()     → controller.stop()
  _on_state_changed(s)   → 버튼 활성화/비활성화, 상태 레이블 색상 변경
  _tick_elapsed()        → 경과 시간 00:00:00 포맷 갱신
```

### phase1_tab.py

```python
클래스: Phase1Tab(QWidget)

위젯:
  - MetricCard × 5: F1, Recall, Precision, Accuracy, Loss
  - QProgressBar × 3: F1/Recall/Precision 목표 대비 진행률
  - QLabel: "사이클 N/20  최고: X.XXXX @ #N"
  - MetricChart: matplotlib 추이 그래프

슬롯:
  on_dashboard_updated(data: dict)
    → current_cycle, best_f1, cycles 파싱
    → 프로그레스 바 갱신 (f1 / 0.92 * 100)
    → MetricChart.add_point() 호출

  on_metrics_updated(data: dict)
    → 5개 MetricCard 값 갱신
    → 목표 달성 시 카드 테두리 초록 / 미달 시 빨강
```

### phase2_tab.py

```python
클래스: Phase2Tab(QWidget)

위젯:
  - MetricCard × 5: 총 경보, CRITICAL, HIGH, MEDIUM, LOW
  - QLabel: 배치 처리 현황 (N/M 배치, 처리 건수, 이상 건수)
  - AlertBarChart: 공격 유형별 경보 가로 막대 그래프
    * 오탐(normal_*) 항목 → 주황 강조

슬롯:
  on_alerts_updated(data: dict)
    → 카드 숫자 갱신
    → AlertBarChart.update_data(by_attack_type) 호출
```

### agents_tab.py

```python
클래스: AgentsTab(QWidget)

구조: QScrollArea → QVBoxLayout → AgentLayerWidget × 8

에이전트 상태:
  IDLE   → 배경 #95a5a6 (회색)
  ACTIVE → 배경 #2ecc71 (초록)
  ERROR  → 배경 #e74c3c (빨강)

상태 전환 트리거:
  QProcess stdout 파싱:
    "[agent-XX-name]" 패턴 감지 → ACTIVE
    "[ERROR]" + agent_id 감지 → ERROR
    파이프라인 종료 → 전체 IDLE

주요 메서드:
  _parse_stdout_line(line: str)
    → re.search(r'\[agent-(\d+)-', line) 으로 agent_id 추출
    → set_agent_state(agent_id, "ACTIVE")

  on_phase_changed(phase: str)
    → "PHASE1": Layer 0~1 강조
    → "PHASE2": Layer 1~5 강조
    → "DONE": 전체 IDLE
```

### log_tab.py

```python
클래스: LogTab(QWidget)

위젯:
  - QPlainTextEdit (읽기 전용, Monospace 폰트)
  - QPushButton "지우기" / "저장"

색상 규칙:
  [ERROR]   → 빨간색 (#e74c3c)
  [WARNING] → 주황색 (#e67e22)
  "목표 달성" / "Targets met" → 초록색 (#27ae60)
  기본 → 흰색

주요 메서드:
  on_new_lines(lines: list[str])
    → 각 줄 색상 결정 후 appendHtml()
    → 최대 5,000줄 초과 시 앞부분 제거
    → 자동 스크롤 하단 고정
```

---

## 6. 스레드·통신 구조

### 전체 구조도

```
메인 스레드 (Qt 이벤트 루프)
│
├── PipelineController (QObject)
│   └── QProcess ── run_pipeline.py 실행
│       │
│       ├── readyReadStandardOutput 시그널
│       │   ├── → LogTab.on_new_lines()       (로그 출력)
│       │   └── → AgentsTab._parse_stdout()   (에이전트 상태)
│       │
│       ├── finished 시그널
│       │   └── → state_changed("DONE")
│       │
│       └── setWorkingDirectory(프로젝트 루트)  ← 상대경로 유지
│
├── DataMonitor (QThread)  ← 파일 폴링 전용 스레드
│   │  폴링 주기: 1,500ms  /  mtime 변경 시에만 시그널 발신
│   │
│   ├── dashboard_updated  → Phase1Tab.on_dashboard_updated()
│   ├── metrics_updated    → Phase1Tab.on_metrics_updated()
│   └── alerts_updated     → Phase2Tab.on_alerts_updated()
│
└── LogTailer (QThread)    ← 로그 파일 테일 전용 스레드
       폴링 주기: 800ms  /  파일 offset 추적
       new_lines           → LogTab.on_new_lines()
```

### 시그널-슬롯 목록

| 시그널 발신자 | 시그널 이름 | 수신 슬롯 | 데이터 타입 |
|-------------|-----------|---------|-----------|
| PipelineController | `state_changed` | AppWindow, ControlTab | `str` |
| PipelineController | `stdout_line` | LogTab, AgentsTab | `str` |
| DataMonitor | `dashboard_updated` | Phase1Tab | `dict` |
| DataMonitor | `metrics_updated` | Phase1Tab | `dict` |
| DataMonitor | `alerts_updated` | Phase2Tab | `dict` |
| LogTailer | `new_lines` | LogTab | `list[str]` |

### 프로세스 종료 처리

```python
# 정상 종료 (중지 버튼)
controller.stop():
    process.terminate()          # SIGTERM
    QTimer(3000, process.kill)   # 3초 후 SIGKILL

# 창 닫기
AppWindow.closeEvent():
    controller.stop()
    data_monitor.quit()
    data_monitor.wait(2000)
    log_tailer.quit()
    log_tailer.wait(2000)
    event.accept()
```

---

## 7. 위젯 명세

### MetricCard

```python
클래스: MetricCard(QFrame)
생성자: MetricCard(title: str, target: float = None)

시각:
  ┌──────────────┐
  │     F1       │  ← title (작은 글씨)
  │    1.0000    │  ← value (큰 글씨, bold)
  │  목표: 0.92  │  ← target 표시 (있을 때만)
  │   ✓ 달성     │  ← 달성/미달 뱃지
  └──────────────┘

메서드:
  set_value(v: float, achieved: bool = False)
    → QLabel 텍스트 갱신
    → achieved=True: 테두리 초록(#2ecc71), 뱃지 "✓ 달성"
    → achieved=False (target 있을 때): 테두리 빨강(#e74c3c), 뱃지 "✗ 미달"
    → target 없음: 기본 테두리
```

### MetricChart

```python
클래스: MetricChart(FigureCanvasQTAgg)
생성자: MetricChart(max_points: int = 50)

차트 구성:
  - 3개 라인: F1(파랑), Recall(초록), Precision(주황)
  - 3개 목표 점선: 0.92(파랑), 0.90(초록), 0.88(주황)
  - X축: 사이클 번호  Y축: 0.0 ~ 1.0
  - 범례, 그리드 표시

메서드:
  add_point(cycle: int, f1: float, recall: float, precision: float)
    → 데이터 추가 후 draw_idle() 호출
    → max_points 초과 시 앞 데이터 제거 (슬라이딩 윈도우)
  clear()
    → 데이터 초기화 후 재렌더링
```

### AgentLayerWidget

```python
클래스: AgentLayerWidget(QGroupBox)
생성자: AgentLayerWidget(layer_name: str, agents: list[tuple[str, str]])
  # agents: [(agent_id, display_name), ...]

에이전트별 QLabel 스타일:
  IDLE   → background: #95a5a6; color: white; border-radius: 4px
  ACTIVE → background: #2ecc71; color: white; border-radius: 4px
  ERROR  → background: #e74c3c; color: white; border-radius: 4px

메서드:
  set_agent_state(agent_id: str, state: str)
  reset_all()   → 전체 IDLE
```

### AlertBarChart

```python
클래스: AlertBarChart(FigureCanvasQTAgg)

차트 구성:
  - 가로 막대 그래프 (barh)
  - 공격 유형 정렬: 경보 건수 내림차순
  - 색상: normal_* 항목 → 주황(#e67e22), 나머지 → 파랑(#3498db)
  - 막대 끝에 건수 숫자 표시

메서드:
  update_data(by_attack_type: dict[str, int])
    → 기존 axes 초기화 후 재렌더링
    → draw_idle() 호출
```

---

## 8. 실시간 업데이트 방식

### 데이터 소스별 전략

| 데이터 소스 | 방식 | 주기 | 갱신 조건 |
|------------|------|------|---------|
| `dashboard.json` | DataMonitor mtime 비교 | 1,500ms | 파일 수정 시각 변경 시 |
| `latest.json` | DataMonitor mtime 비교 | 1,500ms | 파일 수정 시각 변경 시 |
| `summary.json` | DataMonitor mtime 비교 | 1,500ms | 파일 수정 시각 변경 시 |
| `training_progress.log` | LogTailer offset 추적 | 800ms | 파일 크기 증가 시 |
| QProcess stdout | 이벤트 드리븐 | 즉시 | 프로세스 출력 발생 시 |

### Phase 전환 감지

```python
# dashboard.json 폴링 결과로 Phase 추론
def _infer_phase(data: dict) -> str:
    if data.get("status") == "running":
        if data.get("best_f1", 0) >= 0.92:
            return "PHASE2_IMMINENT"
        return "PHASE1"
    return "IDLE"

# summary.json의 last_updated 갱신 시작 → Phase2 활성화 확인
```

### JSON 파싱 안전 처리

```python
# 파이프라인이 JSON 쓰는 도중 읽기 충돌 방어
def _safe_load(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}   # 다음 폴링 주기에 재시도
```

---

## 9. 구현 순서

| 단계 | 작업 | 기간 | 난이도 | 검증 방법 |
|------|------|------|--------|---------|
| **1** | `gui/` 패키지 생성, 빈 탭 5개 표시 | 0.5일 | ⬛⬜⬜ 낮음 | 창이 열리고 탭 전환 가능 |
| **2** | `controller.py` + `control_tab.py` — QProcess 파이프라인 제어 | 1일 | ⬛⬛⬜ 중간 | 3가지 모드로 실제 실행/중지 |
| **3** | `data_monitor.py` + `log_tailer.py` — 워커 스레드 | 0.5일 | ⬛⬜⬜ 낮음 | 시그널 print 확인 |
| **4** | `metric_card.py` + `metric_chart.py` + `phase1_tab.py` | 1일 | ⬛⬛⬜ 중간 | 기존 JSON으로 정적 렌더링 |
| **5** | `alert_bar_chart.py` + `phase2_tab.py` | 0.5일 | ⬛⬜⬜ 낮음 | 기존 summary.json으로 확인 |
| **6** | `agent_layer_widget.py` + `agents_tab.py` | 1일 | ⬛⬛⬜ 중간 | stdout 파싱 단위 테스트 |
| **7** | `log_tab.py` — 색상 필터, 자동 스크롤 | 0.5일 | ⬛⬜⬜ 낮음 | 5000줄 성능 확인 |
| **8** | 통합 테스트 — 3가지 모드 전체 흐름 | 1일 | ⬛⬛⬜ 중간 | 창 닫기 시 프로세스 정리 |
| **합계** | | **6일** | | |

### 단계별 마일스톤

```
Day 1 말: 파이프라인을 GUI에서 시작/중지할 수 있음
Day 2 말: Phase1 메트릭이 실시간으로 갱신됨
Day 3 말: Phase2 경보 차트가 실시간으로 갱신됨
Day 4 말: 32개 에이전트 상태가 시각화됨
Day 5 말: 로그가 색상 구분으로 실시간 출력됨
Day 6 말: 모든 모드 통합 테스트 완료
```

---

## 10. 필요 패키지 및 실행 방법

### 패키지 설치

```bash
pip install PyQt5 matplotlib
```

> `matplotlib`는 이미 프로젝트에서 사용 중이므로 설치되어 있을 가능성이 높음.

### 실행

```bash
# 프로젝트 루트에서 실행
cd /Users/yunsangbeom/project/anomaly-detection-mlops
python3 run_gui.py
```

### run_gui.py (진입점)

```python
#!/usr/bin/env python3
"""GUI 대시보드 진입점"""
import sys
import os

# 프로젝트 루트를 Python 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.main import main
main()
```

---

## 11. 잠재적 문제와 해결책

| 문제 | 원인 | 해결책 |
|------|------|--------|
| **JSON 파싱 오류** | 파이프라인이 쓰는 도중 읽기 충돌 | `try/except json.JSONDecodeError` → 다음 폴링에 재시도 |
| **matplotlib 스레드 오류** | 메인 스레드 외에서 draw() 호출 | DataMonitor 시그널 → 슬롯은 항상 메인 스레드 실행 (Qt 자동 보장) |
| **가상환경 Python 경로** | GUI가 다른 Python으로 파이프라인 실행 | `sys.executable` 사용 → 현재 실행 Python 자동 선택 |
| **상대경로 문제** | 파이프라인 스크립트가 CWD 기준 상대경로 사용 | `QProcess.setWorkingDirectory(PROJECT_ROOT)` |
| **창 닫기 시 프로세스 잔존** | QProcess 미종료 | `closeEvent()`에서 `terminate()` → 3초 후 `kill()` |
| **로그 무한 증가** | QPlainTextEdit 메모리 | 최대 5,000줄 제한, 초과 시 앞부분 제거 |
| **에이전트 상태 미갱신** | 기본 모드에서는 agent_id 로그 없음 | `--multi-agent` 모드 시에만 AgentsTab 활성화, 나머지는 IDLE 고정 |
| **파이프라인 파일 미존재** | 첫 실행 or 초기화 전 | `os.path.exists()` 체크 후 None 처리, 위젯에 "대기 중" 표시 |

---

## 부록: 에이전트 ID → 표시 이름 매핑

```python
AGENT_DISPLAY = {
    "agent-00-adaptive-packet-generator": "00: AI생성기",
    "agent-01-packet-receiver":           "01: 수신",
    "agent-02-normalizer":                "02: 정규화",
    "agent-03-feature-extractor":         "03: 피처추출",
    "agent-04-enricher":                  "04: 보강",
    "agent-05-statistical-analyzer":      "05: 통계",
    "agent-06-ml-classifier":             "06: ML(RF)",
    "agent-07-deep-learning":             "07: LSTM",
    "agent-08-rule-signature":            "08: 룰",
    "agent-09-behavioral-profile":        "09: 행동",
    "agent-10-temporal-pattern":          "10: 시계열",
    "agent-11-protocol-specific":         "11: 프로토콜",
    "agent-12-flow-correlation":          "12: 플로우",
    "agent-13-evidence-aggregator":       "13: 앙상블",
    "agent-14-conflict-resolver":         "14: 충돌해소",
    "agent-15-confidence-scorer":         "15: 신뢰도",
    "agent-16-threshold-manager":         "16: 임계값",
    "agent-17-pipeline-orchestrator":     "17: 총지휘관",
    "agent-18-analysis-sub-orchestrator": "18: 분석지휘",
    "agent-19-load-balancer":             "19: 로드밸런서",
    "agent-20-priority-scheduler":        "20: 스케줄러",
    "agent-21-severity-classifier":       "21: 심각도",
    "agent-22-alert-generator":           "22: 경보생성",
    "agent-23-alert-deduplicator":        "23: 중복제거",
    "agent-24-context-enricher":          "24: MITRE매핑",
    "agent-25-feedback-collector":        "25: 피드백수집",
    "agent-26-online-model-updater":      "26: 모델갱신",
    "agent-27-drift-detector":            "27: 드리프트",
    "agent-28-performance-monitor":       "28: 성능모니터",
    "agent-29-metrics-calculator":        "29: 메트릭",
    "agent-30-false-positive-analyzer":   "30: FP분석",
    "agent-31-attack-coverage":           "31: 커버리지",
    "agent-32-report-generator":          "32: 보고서",
}
```

---

*이 문서는 `anomaly-detection-mlops` 프로젝트의 GUI 대시보드 구현 설계 문서입니다.*  
*관련 문서: [`research_framework.md`](research_framework.md)*
