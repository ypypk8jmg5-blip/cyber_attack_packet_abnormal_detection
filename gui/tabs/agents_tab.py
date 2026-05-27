"""Tab 3: 32개 에이전트 상태 시각화"""
import re
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QScrollArea, QLabel
from PyQt5.QtCore import pyqtSlot

from gui.widgets.agent_layer_widget import AgentLayerWidget

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
    "agent-29-metrics-calculator":        "29: 메트릭계산",
    "agent-30-false-positive-analyzer":   "30: FP분석",
    "agent-31-attack-coverage":           "31: 커버리지",
    "agent-32-report-generator":          "32: 보고서",
}

LAYERS = [
    ("Layer 0: 생성 (AI 적응형)", [
        ("agent-00-adaptive-packet-generator", AGENT_DISPLAY["agent-00-adaptive-packet-generator"]),
    ]),
    ("Layer 1: 수집 (순차 파이프라인)", [
        ("agent-01-packet-receiver",   AGENT_DISPLAY["agent-01-packet-receiver"]),
        ("agent-02-normalizer",        AGENT_DISPLAY["agent-02-normalizer"]),
        ("agent-03-feature-extractor", AGENT_DISPLAY["agent-03-feature-extractor"]),
        ("agent-04-enricher",          AGENT_DISPLAY["agent-04-enricher"]),
    ]),
    ("Layer 2: 분석 (8개 병렬)", [
        ("agent-05-statistical-analyzer", AGENT_DISPLAY["agent-05-statistical-analyzer"]),
        ("agent-06-ml-classifier",        AGENT_DISPLAY["agent-06-ml-classifier"]),
        ("agent-07-deep-learning",        AGENT_DISPLAY["agent-07-deep-learning"]),
        ("agent-08-rule-signature",       AGENT_DISPLAY["agent-08-rule-signature"]),
        ("agent-09-behavioral-profile",   AGENT_DISPLAY["agent-09-behavioral-profile"]),
        ("agent-10-temporal-pattern",     AGENT_DISPLAY["agent-10-temporal-pattern"]),
        ("agent-11-protocol-specific",    AGENT_DISPLAY["agent-11-protocol-specific"]),
        ("agent-12-flow-correlation",     AGENT_DISPLAY["agent-12-flow-correlation"]),
    ]),
    ("Layer 3: 의사결정", [
        ("agent-13-evidence-aggregator", AGENT_DISPLAY["agent-13-evidence-aggregator"]),
        ("agent-14-conflict-resolver",   AGENT_DISPLAY["agent-14-conflict-resolver"]),
        ("agent-15-confidence-scorer",   AGENT_DISPLAY["agent-15-confidence-scorer"]),
        ("agent-16-threshold-manager",   AGENT_DISPLAY["agent-16-threshold-manager"]),
    ]),
    ("Layer 4: 오케스트레이션", [
        ("agent-17-pipeline-orchestrator",     AGENT_DISPLAY["agent-17-pipeline-orchestrator"]),
        ("agent-18-analysis-sub-orchestrator", AGENT_DISPLAY["agent-18-analysis-sub-orchestrator"]),
        ("agent-19-load-balancer",             AGENT_DISPLAY["agent-19-load-balancer"]),
        ("agent-20-priority-scheduler",        AGENT_DISPLAY["agent-20-priority-scheduler"]),
    ]),
    ("Layer 5: 출력", [
        ("agent-21-severity-classifier", AGENT_DISPLAY["agent-21-severity-classifier"]),
        ("agent-22-alert-generator",     AGENT_DISPLAY["agent-22-alert-generator"]),
        ("agent-23-alert-deduplicator",  AGENT_DISPLAY["agent-23-alert-deduplicator"]),
        ("agent-24-context-enricher",    AGENT_DISPLAY["agent-24-context-enricher"]),
    ]),
    ("Layer 6: 학습 (피드백 루프)", [
        ("agent-25-feedback-collector",    AGENT_DISPLAY["agent-25-feedback-collector"]),
        ("agent-26-online-model-updater",  AGENT_DISPLAY["agent-26-online-model-updater"]),
        ("agent-27-drift-detector",        AGENT_DISPLAY["agent-27-drift-detector"]),
        ("agent-28-performance-monitor",   AGENT_DISPLAY["agent-28-performance-monitor"]),
    ]),
    ("Layer 7: 평가", [
        ("agent-29-metrics-calculator",      AGENT_DISPLAY["agent-29-metrics-calculator"]),
        ("agent-30-false-positive-analyzer", AGENT_DISPLAY["agent-30-false-positive-analyzer"]),
        ("agent-31-attack-coverage",         AGENT_DISPLAY["agent-31-attack-coverage"]),
        ("agent-32-report-generator",        AGENT_DISPLAY["agent-32-report-generator"]),
    ]),
]

_ID_PATTERN = re.compile(r'\[agent-([0-9]+-[\w-]+)\]', re.IGNORECASE)


class AgentsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._layer_widgets: list[AgentLayerWidget] = []
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: #1a252f; }")

        inner = QWidget()
        inner.setStyleSheet("background: #1a252f;")
        inner_layout = QVBoxLayout(inner)
        inner_layout.setSpacing(8)

        for layer_name, agents in LAYERS:
            lw = AgentLayerWidget(layer_name, agents)
            self._layer_widgets.append(lw)
            inner_layout.addWidget(lw)

        # 범례
        legend = QLabel("에이전트 상태 범례:  "
                        '<span style="color:#2ecc71">● ACTIVE</span>  '
                        '<span style="color:#95a5a6">● IDLE</span>  '
                        '<span style="color:#e74c3c">● ERROR</span>')
        legend.setStyleSheet("color: #bdc3c7; font-size: 11px; padding: 4px;")
        legend.setTextFormat(1)  # RichText
        inner_layout.addWidget(legend)
        inner_layout.addStretch()

        scroll.setWidget(inner)
        root.addWidget(scroll)

    @pyqtSlot(str)
    def on_stdout_line(self, line: str):
        """QProcess stdout 한 줄 파싱 → 에이전트 상태 갱신"""
        m = _ID_PATTERN.search(line)
        if m:
            raw = m.group(1).lower()
            agent_id = "agent-" + raw
            state = "ERROR" if "[error]" in line.lower() else "ACTIVE"
            self._set_agent_state(agent_id, state)

    def _set_agent_state(self, agent_id: str, state: str):
        for lw in self._layer_widgets:
            lw.set_agent_state(agent_id, state)

    @pyqtSlot(str)
    def on_state_changed(self, state: str):
        if state in ("DONE", "IDLE", "ERROR"):
            for lw in self._layer_widgets:
                lw.reset_all()
        elif state == "RUNNING":
            # 파이프라인 시작 시 17번 오케스트레이터 먼저 ACTIVE
            self._set_agent_state("agent-17-pipeline-orchestrator", "ACTIVE")
