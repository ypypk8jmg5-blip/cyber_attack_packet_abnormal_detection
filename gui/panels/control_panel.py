"""Control Panel — 실행 제어 (좌측 컬럼용 컴팩트 버전)"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QCheckBox, QSpinBox, QPushButton, QLabel, QFrame
)
from PyQt5.QtCore import Qt, QTimer, pyqtSlot

_STATE_COLORS = {
    "IDLE":    "#95a5a6",
    "RUNNING": "#2ecc71",
    "DONE":    "#3498db",
    "ERROR":   "#e74c3c",
}

_CB_STYLE = (
    "QCheckBox { color: #ecf0f1; font-size: 12px; spacing: 6px; }"
    "QCheckBox::indicator { width: 14px; height: 14px; }"
    "QCheckBox::indicator:unchecked { background:#2c3e50; border:2px solid #7f8c8d; border-radius:3px; }"
    "QCheckBox::indicator:checked   { background:#2980b9; border:2px solid #3498db; border-radius:3px; }"
)


class ControlPanel(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self._ctrl = controller
        self._elapsed = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick_elapsed)
        self._setup_ui()
        self._ctrl.state_changed.connect(self._on_state_changed)

    def _sep(self):
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #34495e;")
        return line

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # ── 타이틀 ──────────────────────────────────────────────────
        title = QLabel("실행 제어")
        title.setStyleSheet("color:#ecf0f1; font-size:14px; font-weight:bold;")
        root.addWidget(title)
        root.addWidget(self._sep())

        # ── 옵션 체크박스 ────────────────────────────────────────────
        self._cb_multi = QCheckBox("멀티 에이전트  (--multi-agent)")
        self._cb_ai    = QCheckBox("AI 적응형 생성  (--ai-gen)")
        self._cb_multi.setStyleSheet(_CB_STYLE)
        self._cb_ai.setStyleSheet(_CB_STYLE)
        self._cb_multi.setChecked(True)
        self._cb_multi.stateChanged.connect(self._update_hint)
        self._cb_ai.stateChanged.connect(self._update_hint)
        root.addWidget(self._cb_multi)
        root.addWidget(self._cb_ai)

        # 명령 힌트
        self._hint_lbl = QLabel()
        self._hint_lbl.setStyleSheet("color:#f39c12; font-size:10px; padding:2px 0;")
        self._hint_lbl.setWordWrap(True)
        root.addWidget(self._hint_lbl)
        self._update_hint()

        root.addWidget(self._sep())

        # ── 배치 수 ──────────────────────────────────────────────────
        batch_row = QHBoxLayout()
        batch_lbl = QLabel("최대 배치:")
        batch_lbl.setStyleSheet("color:#bdc3c7; font-size:12px;")
        self._batch_spin = QSpinBox()
        self._batch_spin.setRange(0, 100)
        self._batch_spin.setValue(5)
        self._batch_spin.setFixedWidth(60)
        self._batch_spin.setStyleSheet(
            "QSpinBox{background:#2c3e50;color:white;border:1px solid #34495e;padding:2px;font-size:12px;}")
        batch_row.addWidget(batch_lbl)
        batch_row.addWidget(self._batch_spin)
        batch_row.addStretch()
        root.addLayout(batch_row)

        # ── 버튼 ─────────────────────────────────────────────────────
        self._start_btn = QPushButton("▶  시작")
        self._start_btn.setFixedHeight(34)
        self._start_btn.setStyleSheet(
            "QPushButton{background:#27ae60;color:white;font-size:13px;border-radius:5px;}"
            "QPushButton:hover{background:#2ecc71;}"
            "QPushButton:disabled{background:#444;color:#777;}")
        self._stop_btn = QPushButton("■  중지")
        self._stop_btn.setFixedHeight(34)
        self._stop_btn.setEnabled(False)
        self._stop_btn.setStyleSheet(
            "QPushButton{background:#c0392b;color:white;font-size:13px;border-radius:5px;}"
            "QPushButton:hover{background:#e74c3c;}"
            "QPushButton:disabled{background:#444;color:#777;}")
        self._start_btn.clicked.connect(self._on_start)
        self._stop_btn.clicked.connect(self._ctrl.stop)
        root.addWidget(self._start_btn)
        root.addWidget(self._stop_btn)

        root.addWidget(self._sep())

        # ── 상태 표시 ────────────────────────────────────────────────
        def _stat_row(lbl_text):
            row = QHBoxLayout()
            l = QLabel(lbl_text)
            l.setStyleSheet("color:#95a5a6;font-size:11px;")
            l.setFixedWidth(50)
            v = QLabel("—")
            v.setStyleSheet("color:white;font-size:11px;")
            row.addWidget(l)
            row.addWidget(v)
            row.addStretch()
            root.addLayout(row)
            return v

        self._state_lbl   = _stat_row("상태:")
        self._pid_lbl     = _stat_row("PID:")
        self._elapsed_lbl = _stat_row("경과:")
        self._update_state_label("IDLE")

        root.addStretch()

    # ------------------------------------------------------------------
    def _update_hint(self):
        multi = self._cb_multi.isChecked()
        ai    = self._cb_ai.isChecked()
        if multi and ai:
            self._hint_lbl.setText("→ --multi-agent --ai-gen")
        elif multi:
            self._hint_lbl.setText("→ --multi-agent")
        elif ai:
            self._hint_lbl.setText("→ --ai-gen")
        else:
            self._hint_lbl.setText("→ 기본 순차 모드")

    @pyqtSlot()
    def _on_start(self):
        self._elapsed = 0
        self._elapsed_lbl.setText("00:00:00")
        self._timer.start(1000)
        self._ctrl.start(
            multi_agent=self._cb_multi.isChecked(),
            ai_gen=self._cb_ai.isChecked(),
            max_batches=self._batch_spin.value()
        )

    @pyqtSlot(str)
    def _on_state_changed(self, state: str):
        self._update_state_label(state)
        running = (state == "RUNNING")
        self._start_btn.setEnabled(not running)
        self._stop_btn.setEnabled(running)
        self._cb_multi.setEnabled(not running)
        self._cb_ai.setEnabled(not running)
        if running:
            pid = self._ctrl.pid
            self._pid_lbl.setText(str(pid) if pid else "—")
        else:
            self._timer.stop()
            if state in ("DONE", "ERROR"):
                self._pid_lbl.setText("—")

    def _update_state_label(self, state: str):
        color = _STATE_COLORS.get(state, "white")
        self._state_lbl.setText(
            f'<span style="color:{color};font-weight:bold;">● {state}</span>')
        self._state_lbl.setTextFormat(Qt.RichText)

    @pyqtSlot()
    def _tick_elapsed(self):
        self._elapsed += 1
        h, r = divmod(self._elapsed, 3600)
        m, s = divmod(r, 60)
        self._elapsed_lbl.setText(f"{h:02d}:{m:02d}:{s:02d}")
