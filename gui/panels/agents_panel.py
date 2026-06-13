"""Agents Panel — 32개 에이전트 상태 (운영 compact / 발표 stage 모드)"""
import re
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QScrollArea, QLabel
)
from PyQt5.QtCore import pyqtSlot

from gui import theme
from gui.widgets.agent_cell import AgentCell

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

# 모드별 패널 치수 — compact: 운영 뷰(기존 크기 유지), stage: 발표 뷰
_MODE_UI = {
    "compact": {"title": 14, "layer_w": 80,  "layer_font": 10, "legend": 10,
                "row_pad": (6, 4), "row_radius": 4, "spacing": 3, "show_title": True},
    "stage":   {"title": 20, "layer_w": 130, "layer_font": 14, "legend": 13,
                "row_pad": (14, 9), "row_radius": 6, "spacing": 8, "show_title": False},
}


class AgentsPanel(QWidget):
    def __init__(self, mode: str = "compact", parent=None):
        super().__init__(parent)
        self._ui = _MODE_UI[mode]
        self._mode = mode
        self._cells: dict[str, AgentCell] = {}
        self._setup_ui()

    def _setup_ui(self):
        ui = self._ui
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 6)
        root.setSpacing(4)

        if ui["show_title"]:
            title = QLabel("에이전트 상태  (32개)")
            title.setStyleSheet(
                f"color:{theme.TEXT}; font-size:{ui['title']}px; font-weight:bold;")
            root.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            f"QScrollArea{{border:none; background:{theme.BG_DEEP};}}")

        inner = QWidget()
        inner.setStyleSheet(f"background:{theme.BG_DEEP};")
        iv = QVBoxLayout(inner)
        iv.setContentsMargins(0, 0, 0, 0)
        iv.setSpacing(ui["spacing"])

        pad_h, pad_v = ui["row_pad"]
        for layer_name, agents in LAYERS:
            row_widget = QWidget()
            row_widget.setStyleSheet(
                f"background:{theme.BG_CARD}; border-radius:{ui['row_radius']}px;")
            row_layout = QHBoxLayout(row_widget)
            row_layout.setContentsMargins(pad_h, pad_v, pad_h, pad_v)
            row_layout.setSpacing(ui["spacing"] + 2)

            # 레이어 이름
            lyr_lbl = QLabel(layer_name)
            lyr_lbl.setStyleSheet(
                f"color:{theme.TEXT_DIM}; font-size:{ui['layer_font']}px; font-weight:bold;")
            lyr_lbl.setFixedWidth(ui["layer_w"])
            row_layout.addWidget(lyr_lbl)

            # 에이전트 셀
            for agent_id, display in agents:
                cell = AgentCell(display, mode=self._mode)
                self._cells[agent_id] = cell
                row_layout.addWidget(cell)

            row_layout.addStretch()
            # 스테이지 모드: 행들이 세로 공간을 균등 분할 (프로젝터 화면 채움)
            iv.addWidget(row_widget, 1 if self._mode == "stage" else 0)

        # 범례
        legend = QLabel(
            f'<span style="color:{theme.GREEN}">● 활동</span>'
            f'  <span style="color:{theme.GREEN_WARM}">● 잔광</span>'
            f'  <span style="color:{theme.GRAY_IDLE_BG}">● 대기</span>'
            f'  <span style="color:{theme.RED}">● 오류</span>')
        legend.setStyleSheet(
            f"color:{theme.TEXT_MUTED}; font-size:{ui['legend']}px; padding:2px;")
        iv.addWidget(legend)
        if self._mode == "compact":
            iv.addStretch()

        scroll.setWidget(inner)
        root.addWidget(scroll)

    # ------------------------------------------------------------------
    @pyqtSlot(str)
    def on_stdout_line(self, line: str):
        m = _ID_PATTERN.search(line)
        if not m:
            return
        agent_id = "agent-" + m.group(1).lower()
        cell = self._cells.get(agent_id)
        if cell is None:
            return
        # [ERROR] 괄호 토큰이 명시적으로 있을 때만 ERROR 표시
        if _ERROR_PATTERN.search(line):
            cell.set_error()
        else:
            cell.ping()

    @pyqtSlot(str)
    def on_state_changed(self, state: str):
        if state in ("DONE", "IDLE", "ERROR"):
            self.reset_all()
        elif state == "RUNNING":
            self.reset_all()
            orchestrator = self._cells.get("agent-17-pipeline-orchestrator")
            if orchestrator:
                orchestrator.ping()

    def reset_all(self):
        for cell in self._cells.values():
            cell.reset()
