"""StagePanel — 발표 모드 스테이지 뷰

에이전트 그리드를 주인공으로 키우고, 우측 레일에는 데모 3박자에 대응하는
핵심 숫자 3개(탐지된 이상 · CRITICAL 알림 · 현재 F1)만 크게 표시한다.
제어·로그는 운영 뷰(F5/F6 전환)에 그대로 둔다.
"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame
)
from PyQt5.QtCore import Qt, pyqtSlot

from gui import theme
from gui.panels.agents_panel import AgentsPanel

_STATE_COLORS = {
    "IDLE":    "#95a5a6",
    "RUNNING": theme.GREEN,
    "DONE":    theme.BLUE,
    "ERROR":   theme.RED,
}


class _BigStat(QFrame):
    """대형 숫자 카드 — 프로젝터 원거리 가독용"""

    def __init__(self, title: str, accent: str, parent=None):
        super().__init__(parent)
        self.setStyleSheet(
            f"QFrame{{background:{theme.BG_PANEL}; border:1px solid {theme.BORDER};"
            f"border-left:6px solid {accent}; border-radius:10px;}}")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 16, 22, 18)
        layout.setSpacing(4)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(
            f"color:{theme.TEXT_MUTED}; font-size:17px; border:none;")
        self._value_lbl = QLabel("—")
        self._value_lbl.setStyleSheet(
            "color:white; font-size:54px; font-weight:bold; border:none;")

        layout.addWidget(title_lbl)
        layout.addWidget(self._value_lbl)

    def set_value(self, text: str):
        self._value_lbl.setText(text)

    def reset(self):
        self._value_lbl.setText("—")


class StagePanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 12)
        root.setSpacing(14)

        # ── 헤더: 타이틀 + 파이프라인 상태 ──────────────────────────
        header = QHBoxLayout()
        title = QLabel("AdaptiveNIDS — 32 에이전트 라이브 파이프라인")
        title.setStyleSheet(
            f"color:{theme.TEXT}; font-size:26px; font-weight:bold;")
        self._state_lbl = QLabel("● IDLE")
        self._state_lbl.setStyleSheet(
            f"color:{_STATE_COLORS['IDLE']}; font-size:18px; font-weight:bold;")
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self._state_lbl)
        root.addLayout(header)

        # ── 본문: 에이전트 그리드(주인공) | 대형 숫자 레일 ──────────
        body = QHBoxLayout()
        body.setSpacing(22)

        self.agents = AgentsPanel(mode="stage")
        body.addWidget(self.agents, 7)

        rail = QVBoxLayout()
        rail.setSpacing(16)
        self._stat_anomaly  = _BigStat("탐지된 이상",   theme.BLUE)
        self._stat_critical = _BigStat("CRITICAL 알림", theme.RED)
        self._stat_f1       = _BigStat("현재 F1",       theme.GREEN)
        for stat in (self._stat_anomaly, self._stat_critical, self._stat_f1):
            rail.addWidget(stat)
        rail.addStretch()
        body.addLayout(rail, 3)

        root.addLayout(body, 1)

        # ── 하단 힌트 (발표자용, 어둡게) ─────────────────────────────
        hint = QLabel("기동 → 탐지 → 적응   ·   F5 운영 뷰 전환  ·  Esc 전체화면 해제")
        hint.setStyleSheet(f"color:{theme.TEXT_DIM}; font-size:11px;")
        hint.setAlignment(Qt.AlignRight)
        root.addWidget(hint)

    # ------------------------------------------------------------------
    @pyqtSlot(dict)
    def on_alerts_updated(self, data: dict):
        anomalies = data.get("anomalies_detected")
        if anomalies is not None:
            self._stat_anomaly.set_value(f"{int(anomalies):,}")
        critical = data.get("by_severity", {}).get("CRITICAL")
        if critical is not None:
            self._stat_critical.set_value(f"{int(critical):,}")

    @pyqtSlot(dict)
    def on_metrics_updated(self, data: dict):
        f1 = data.get("metrics", {}).get("f1_score")
        if f1 is not None:
            self._stat_f1.set_value(f"{f1:.3f}")

    @pyqtSlot(dict)
    def on_dashboard_updated(self, data: dict):
        cycles = data.get("cycles", [])
        if cycles:
            f1 = cycles[-1].get("f1")
            if f1 is not None:
                self._stat_f1.set_value(f"{f1:.3f}")

    @pyqtSlot(str)
    def on_state_changed(self, state: str):
        color = _STATE_COLORS.get(state, "white")
        self._state_lbl.setText(f"● {state}")
        self._state_lbl.setStyleSheet(
            f"color:{color}; font-size:18px; font-weight:bold;")
        if state == "RUNNING":
            for stat in (self._stat_anomaly, self._stat_critical, self._stat_f1):
                stat.reset()
