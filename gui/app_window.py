"""AppWindow — 단일 화면 대시보드 (QSplitter 기반)

레이아웃:
┌──────────────────────┬──────────────────────────────────────────────┐
│  실행 제어            │          Phase 1 — 학습 현황                  │
│  □ 멀티에이전트        │  [F1][Recall][Prec][Acc][Loss] + 추이 차트    │
│  □ AI 적응형          ├──────────────────────────────────────────────┤
│  [▶시작] [■중지]      │          Phase 2 — 탐지 현황                  │
├──────────────────────┤  [총][CRIT][HIGH][MED][LOW] + 공격유형 차트    │
│  에이전트 상태 (32개) │                                              │
│  L0 [AI생성기]        │                                              │
│  L1 [수신][정규화]... │                                              │
│  L2 [통계][RF][LSTM]..│                                              │
│  L3~L7 ...            │                                              │
├──────────────────────┴──────────────────────────────────────────────┤
│  실시간 로그   [지우기] [저장]                                         │
└─────────────────────────────────────────────────────────────────────┘
"""
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QSplitter, QLabel, QFrame
)
from PyQt5.QtCore import Qt, pyqtSlot

from gui.controller import PipelineController
from gui.data_monitor import DataMonitor
from gui.log_tailer import LogTailer

from gui.panels.control_panel import ControlPanel
from gui.panels.phase1_panel  import Phase1Panel
from gui.panels.phase2_panel  import Phase2Panel
from gui.panels.agents_panel  import AgentsPanel
from gui.panels.log_panel     import LogPanel

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

        # ── 전체: 수직 스플리터 (상단 행 | 로그) ─────────────────────
        main_splitter = QSplitter(Qt.Vertical)
        main_splitter.addWidget(top_splitter)
        main_splitter.addWidget(_wrap(self._p_log))
        main_splitter.setSizes([650, 160])
        main_splitter.setHandleWidth(5)

        self.setCentralWidget(main_splitter)

        # 상태바
        self._status_state = QLabel("● IDLE")
        self._status_state.setStyleSheet(
            f"color:{_STATE_COLORS['IDLE']}; font-weight:bold; padding:0 10px;")
        self._status_pid = QLabel("PID: —")
        self._status_pid.setStyleSheet("color:#bdc3c7; padding:0 10px;")
        sb = self.statusBar()
        sb.addPermanentWidget(self._status_pid)
        sb.addPermanentWidget(self._status_state)

    def _connect_signals(self):
        ctrl = self._ctrl
        ctrl.state_changed.connect(self._on_state_changed)
        ctrl.stdout_line.connect(self._p_log.on_stdout_line)
        ctrl.stdout_line.connect(self._p_agents.on_stdout_line)
        ctrl.state_changed.connect(self._p_agents.on_state_changed)

        mon = self._monitor
        mon.dashboard_updated.connect(self._p_phase1.on_dashboard_updated)
        mon.metrics_updated.connect(self._p_phase1.on_metrics_updated)
        mon.alerts_updated.connect(self._p_phase2.on_alerts_updated)

        self._tailer.new_lines.connect(self._p_log.on_new_lines)

    def _start_workers(self):
        self._monitor.start()
        self._tailer.start()

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

    def closeEvent(self, event):
        self._ctrl.stop()
        self._monitor.stop()
        self._monitor.quit()
        self._monitor.wait(2000)
        self._tailer.stop()
        self._tailer.quit()
        self._tailer.wait(2000)
        event.accept()
