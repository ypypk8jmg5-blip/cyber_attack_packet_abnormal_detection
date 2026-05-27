"""Agents Panel — 32개 에이전트 상태 (대시보드 컴팩트 버전)"""
import re
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QScrollArea, QLabel, QFrame
)
from PyQt5.QtCore import Qt, pyqtSlot
from PyQt5.QtGui import QFont

_STYLE = {
    "IDLE":   "background:#4a5568; color:#cbd5e0; border-radius:3px; padding:2px 5px; font-size:10px;",
    "ACTIVE": "background:#2ecc71; color:white;   border-radius:3px; padding:2px 5px; font-size:10px;",
    "ERROR":  "background:#e74c3c; color:white;   border-radius:3px; padding:2px 5px; font-size:10px;",
}

LAYERS = [
    ("L0 생성",  [("agent-00-adaptive-packet-generator", "00:AI생성기")]),
    ("L1 수집",  [
        ("agent-01-packet-receiver",   "01:수신"),
        ("agent-02-normalizer",        "02:정규화"),
        ("agent-03-feature-extractor", "03:피처"),
        ("agent-04-enricher",          "04:보강"),
    ]),
    ("L2 분석",  [
        ("agent-05-statistical-analyzer", "05:통계"),
        ("agent-06-ml-classifier",        "06:RF"),
        ("agent-07-deep-learning",        "07:LSTM"),
        ("agent-08-rule-signature",       "08:룰"),
        ("agent-09-behavioral-profile",   "09:행동"),
        ("agent-10-temporal-pattern",     "10:시계열"),
        ("agent-11-protocol-specific",    "11:프로토콜"),
        ("agent-12-flow-correlation",     "12:플로우"),
    ]),
    ("L3 결정",  [
        ("agent-13-evidence-aggregator", "13:앙상블"),
        ("agent-14-conflict-resolver",   "14:충돌해소"),
        ("agent-15-confidence-scorer",   "15:신뢰도"),
        ("agent-16-threshold-manager",   "16:임계값"),
    ]),
    ("L4 오케스트레이션", [
        ("agent-17-pipeline-orchestrator",     "17:총지휘"),
        ("agent-18-analysis-sub-orchestrator", "18:분석지휘"),
        ("agent-19-load-balancer",             "19:로드밸런서"),
        ("agent-20-priority-scheduler",        "20:스케줄러"),
    ]),
    ("L5 출력",  [
        ("agent-21-severity-classifier", "21:심각도"),
        ("agent-22-alert-generator",     "22:경보생성"),
        ("agent-23-alert-deduplicator",  "23:중복제거"),
        ("agent-24-context-enricher",    "24:MITRE"),
    ]),
    ("L6 학습",  [
        ("agent-25-feedback-collector",   "25:피드백"),
        ("agent-26-online-model-updater", "26:모델갱신"),
        ("agent-27-drift-detector",       "27:드리프트"),
        ("agent-28-performance-monitor",  "28:성능모니터"),
    ]),
    ("L7 평가",  [
        ("agent-29-metrics-calculator",      "29:메트릭"),
        ("agent-30-false-positive-analyzer", "30:FP분석"),
        ("agent-31-attack-coverage",         "31:커버리지"),
        ("agent-32-report-generator",        "32:보고서"),
    ]),
]

_ID_PATTERN    = re.compile(r'\[agent-([0-9]+-[\w-]+)\]', re.IGNORECASE)
# "error" 단어 단독이 아닌 [ERROR] 또는 [error] 괄호 토큰만 인식
# → stderr 내용에 포함된 "ModuleNotFoundError:" 등 오탐 방지
_ERROR_PATTERN = re.compile(r'\[error\]', re.IGNORECASE)


class AgentsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._labels: dict[str, QLabel] = {}
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 6)
        root.setSpacing(4)

        title = QLabel("에이전트 상태  (32개)")
        title.setStyleSheet("color:#ecf0f1; font-size:14px; font-weight:bold;")
        root.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none; background:#1a252f;}")

        inner = QWidget()
        inner.setStyleSheet("background:#1a252f;")
        iv = QVBoxLayout(inner)
        iv.setContentsMargins(0, 0, 0, 0)
        iv.setSpacing(3)

        for layer_name, agents in LAYERS:
            row_widget = QWidget()
            row_widget.setStyleSheet(
                "background:#22303c; border-radius:4px;")
            row_layout = QHBoxLayout(row_widget)
            row_layout.setContentsMargins(6, 4, 6, 4)
            row_layout.setSpacing(5)

            # 레이어 이름
            lyr_lbl = QLabel(layer_name)
            lyr_lbl.setStyleSheet(
                "color:#7f8c8d; font-size:10px; font-weight:bold;")
            lyr_lbl.setFixedWidth(80)
            row_layout.addWidget(lyr_lbl)

            # 에이전트 뱃지
            for agent_id, display in agents:
                badge = QLabel(display)
                badge.setStyleSheet(_STYLE["IDLE"])
                badge.setAlignment(Qt.AlignCenter)
                self._labels[agent_id] = badge
                row_layout.addWidget(badge)

            row_layout.addStretch()
            iv.addWidget(row_widget)

        # 범례
        legend = QLabel(
            '<span style="color:#2ecc71">● ACTIVE</span>'
            '  <span style="color:#4a5568">● IDLE</span>'
            '  <span style="color:#e74c3c">● ERROR</span>')
        legend.setStyleSheet("color:#bdc3c7; font-size:10px; padding:2px;")
        legend.setTextFormat(Qt.RichText)
        iv.addWidget(legend)
        iv.addStretch()

        scroll.setWidget(inner)
        root.addWidget(scroll)

    # ------------------------------------------------------------------
    @pyqtSlot(str)
    def on_stdout_line(self, line: str):
        m = _ID_PATTERN.search(line)
        if m:
            agent_id = "agent-" + m.group(1).lower()
            # [ERROR] 괄호 토큰이 명시적으로 있을 때만 ERROR 표시
            # ("ModuleNotFoundError:", "ValueError:" 등 포함 라인 오탐 방지)
            state = "ERROR" if _ERROR_PATTERN.search(line) else "ACTIVE"
            if agent_id in self._labels:
                self._labels[agent_id].setStyleSheet(_STYLE[state])

    @pyqtSlot(str)
    def on_state_changed(self, state: str):
        if state in ("DONE", "IDLE", "ERROR"):
            for lbl in self._labels.values():
                lbl.setStyleSheet(_STYLE["IDLE"])
        elif state == "RUNNING":
            aid = "agent-17-pipeline-orchestrator"
            if aid in self._labels:
                self._labels[aid].setStyleSheet(_STYLE["ACTIVE"])
