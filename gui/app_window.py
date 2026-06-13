"""AppWindow — 운영 뷰(QSplitter) + 발표 스테이지 뷰(QStackedWidget 전환)

운영 뷰 레이아웃:
┌──────────────────────┬──────────────────────────────────────────────┐
│  실행 제어            │          Phase 1 — 학습 현황                  │
│  □ 멀티에이전트        │  [F1][Recall][Prec][Acc][Loss] + 추이 차트    │
│  □ AI 적응형          ├──────────────────────────────────────────────┤
│  [▶시작] [■중지]      │          Phase 2 — 탐지 현황                  │
├──────────────────────┤  [총][CRIT][HIGH][MED][LOW] + 공격유형 차트    │
│  에이전트 상태 (32개) │                                              │
├──────────────────────┴──────────────────────────────────────────────┤
│  실시간 로그   [지우기] [저장]                                         │
└─────────────────────────────────────────────────────────────────────┘

발표 스테이지 뷰(F5): 에이전트 그리드 중앙 + 대형 숫자 3개 + 이벤트 배너.
"""
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QSplitter, QStackedWidget, QLabel, QFrame, QShortcut
)
from PyQt5.QtCore import Qt, pyqtSlot
from PyQt5.QtGui import QKeySequence

from gui.controller import PipelineController
from gui.data_monitor import DataMonitor
from gui.log_tailer import LogTailer
from gui.event_bus import EventBus

from gui.panels.control_panel import ControlPanel
from gui.panels.phase1_panel  import Phase1Panel
from gui.panels.phase2_panel  import Phase2Panel
from gui.panels.agents_panel  import AgentsPanel
from gui.panels.log_panel     import LogPanel
from gui.panels.stage_panel   import StagePanel
from gui.widgets.banner       import BannerOverlay

_STATE_COLORS = {
    "IDLE":    "#95a5a6",
    "RUNNING": "#2ecc71",
    "DONE":    "#3498db",
    "ERROR":   "#e74c3c",
}

_PANEL_STYLE = (
    "background:#1e2d3d;"
    "border:1px solid #2c3e50;"
    "border-radius:6px;"
)


def _wrap(widget: QWidget) -> QFrame:
    """패널을 테두리 있는 QFrame으로 감싸기"""
    frame = QFrame()
    frame.setStyleSheet(_PANEL_STYLE)
    from PyQt5.QtWidgets import QVBoxLayout
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(widget)
    return frame


class AppWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("이상탐지 MLOps 파이프라인 대시보드")
        self.resize(1280, 820)
        self._setup_style()
        self._build_components()
        self._connect_signals()
        self._setup_shortcuts()
        self._start_workers()

    # ------------------------------------------------------------------
    def _setup_style(self):
        self.setStyleSheet("""
            QMainWindow  { background: #151f2b; }
            QSplitter    { background: #151f2b; }
            QSplitter::handle:horizontal { background: #2c3e50; width: 4px; }
            QSplitter::handle:vertical   { background: #2c3e50; height: 4px; }
            QStatusBar   { background: #1e2d3d; color: #bdc3c7; font-size: 12px; }
            QScrollBar:vertical {
                background: #1e2d3d; width: 8px; margin: 0;
            }
            QScrollBar::handle:vertical {
                background: #34495e; border-radius: 4px; min-height: 20px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        """)

    def _build_components(self):
        self._ctrl    = PipelineController(self)
        self._monitor = DataMonitor()
        self._tailer  = LogTailer()
        self._bus     = EventBus(self)

        # 패널 생성
        self._p_ctrl   = ControlPanel(self._ctrl)
        self._p_phase1 = Phase1Panel()
        self._p_phase2 = Phase2Panel()
        self._p_agents = AgentsPanel()
        self._p_log    = LogPanel()

        # ── 좌측 컬럼: 실행 제어 + 에이전트 상태 (수직 스플리터) ──────
        left_splitter = QSplitter(Qt.Vertical)
        left_splitter.addWidget(_wrap(self._p_ctrl))
        left_splitter.addWidget(_wrap(self._p_agents))
        left_splitter.setSizes([320, 480])
        left_splitter.setHandleWidth(5)

        # ── 우측 컬럼: Phase1 / Phase2 (수직 스플리터) ───────────────
        right_splitter = QSplitter(Qt.Vertical)
        right_splitter.addWidget(_wrap(self._p_phase1))
        right_splitter.addWidget(_wrap(self._p_phase2))
        right_splitter.setSizes([400, 380])
        right_splitter.setHandleWidth(5)

        # ── 상단 행: 수평 스플리터 (좌측 컬럼 | 우측 컬럼) ──────────
        top_splitter = QSplitter(Qt.Horizontal)
        top_splitter.addWidget(left_splitter)
        top_splitter.addWidget(right_splitter)
        top_splitter.setSizes([280, 1000])
        top_splitter.setHandleWidth(5)

        # ── 운영 뷰: 수직 스플리터 (상단 행 | 로그) ──────────────────
        ops_splitter = QSplitter(Qt.Vertical)
        ops_splitter.addWidget(top_splitter)
        ops_splitter.addWidget(_wrap(self._p_log))
        ops_splitter.setSizes([650, 160])
        ops_splitter.setHandleWidth(5)

        # ── 페이지 스택: 0 = 운영 뷰, 1 = 발표 스테이지 뷰 ───────────
        self._p_stage = StagePanel()
        self._stack = QStackedWidget()
        self._stack.addWidget(ops_splitter)
        self._stack.addWidget(self._p_stage)
        self.setCentralWidget(self._stack)

        # 이벤트 배너 (오버레이 — 두 페이지 공용)
        self._banner = BannerOverlay(self)

        # 상태바
        self._status_hint = QLabel("F5: 발표 모드")
        self._status_hint.setStyleSheet("color:#7f8c8d; padding:0 10px;")
        self._status_state = QLabel("● IDLE")
        self._status_state.setStyleSheet(
            f"color:{_STATE_COLORS['IDLE']}; font-weight:bold; padding:0 10px;")
        self._status_pid = QLabel("PID: —")
        self._status_pid.setStyleSheet("color:#bdc3c7; padding:0 10px;")
        sb = self.statusBar()
        sb.addWidget(self._status_hint)
        sb.addPermanentWidget(self._status_pid)
        sb.addPermanentWidget(self._status_state)

    def _connect_signals(self):
        ctrl = self._ctrl
        ctrl.state_changed.connect(self._on_state_changed)
        ctrl.stdout_line.connect(self._p_log.on_stdout_line)
        ctrl.stdout_line.connect(self._p_agents.on_stdout_line)
        ctrl.state_changed.connect(self._p_agents.on_state_changed)

        # 스테이지 뷰 — 동일 시그널을 같은 인터페이스로 구독
        ctrl.stdout_line.connect(self._p_stage.agents.on_stdout_line)
        ctrl.state_changed.connect(self._p_stage.agents.on_state_changed)
        ctrl.state_changed.connect(self._p_stage.on_state_changed)

        mon = self._monitor
        mon.dashboard_updated.connect(self._p_phase1.on_dashboard_updated)
        mon.metrics_updated.connect(self._p_phase1.on_metrics_updated)
        mon.alerts_updated.connect(self._p_phase2.on_alerts_updated)
        mon.dashboard_updated.connect(self._p_stage.on_dashboard_updated)
        mon.metrics_updated.connect(self._p_stage.on_metrics_updated)
        mon.alerts_updated.connect(self._p_stage.on_alerts_updated)

        # 이벤트 버스 → 배너
        ctrl.state_changed.connect(self._bus.on_state_changed)
        ctrl.stdout_line.connect(self._bus.on_stdout_line)
        mon.alerts_updated.connect(self._bus.on_alerts_updated)
        self._bus.event_detected.connect(self._banner.show_message)

        self._tailer.new_lines.connect(self._p_log.on_new_lines)

    def _setup_shortcuts(self):
        QShortcut(QKeySequence(Qt.Key_F5), self, activated=self._toggle_present)
        QShortcut(QKeySequence(Qt.Key_F6), self, activated=self._leave_present)
        QShortcut(QKeySequence(Qt.Key_Escape), self, activated=self._leave_present)

    def _start_workers(self):
        self._monitor.start()
        self._tailer.start()

    # ------------------------------------------------------------------
    # 발표 모드 전환
    def set_present(self, on: bool):
        if on:
            self._stack.setCurrentIndex(1)
            self.showFullScreen()
        else:
            self._stack.setCurrentIndex(0)
            if self.isFullScreen():
                self.showNormal()
        self._banner.reposition()

    @pyqtSlot()
    def _toggle_present(self):
        self.set_present(self._stack.currentIndex() == 0)

    @pyqtSlot()
    def _leave_present(self):
        if self._stack.currentIndex() == 1 or self.isFullScreen():
            self.set_present(False)

    # ------------------------------------------------------------------
    @pyqtSlot(str)
    def _on_state_changed(self, state: str):
        color = _STATE_COLORS.get(state, "white")
        self._status_state.setText(f"● {state}")
        self._status_state.setStyleSheet(
            f"color:{color}; font-weight:bold; padding:0 10px;")
        pid = self._ctrl.pid
        self._status_pid.setText(f"PID: {pid}" if pid else "PID: —")
        if state == "RUNNING":
            self._p_phase1.reset()
            self._p_phase2.reset()
            self._tailer.reset()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._banner.reposition()

    def closeEvent(self, event):
        self._ctrl.stop()
        self._monitor.stop()
        self._monitor.quit()
        self._monitor.wait(2000)
        self._tailer.stop()
        self._tailer.quit()
        self._tailer.wait(2000)
        event.accept()
