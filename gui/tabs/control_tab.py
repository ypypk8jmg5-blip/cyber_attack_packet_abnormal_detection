"""Tab 0: 실행 제어"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QCheckBox, QSpinBox, QPushButton, QLabel
)
from PyQt5.QtCore import Qt, QTimer, pyqtSlot


_STATE_COLORS = {
    "IDLE":    "#95a5a6",
    "RUNNING": "#2ecc71",
    "DONE":    "#3498db",
    "ERROR":   "#e74c3c",
}

_CB_STYLE = ("QCheckBox { color: #ecf0f1; font-size: 13px; spacing: 8px; }"
             "QCheckBox::indicator { width: 16px; height: 16px; }"
             "QCheckBox::indicator:unchecked { background: #2c3e50; border: 2px solid #7f8c8d; border-radius: 3px; }"
             "QCheckBox::indicator:checked   { background: #2980b9; border: 2px solid #3498db; border-radius: 3px; }")


class ControlTab(QWidget):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self._ctrl = controller
        self._elapsed = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick_elapsed)
        self._setup_ui()
        self._ctrl.state_changed.connect(self._on_state_changed)

    # ------------------------------------------------------------------
    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(16)

        # ── 실행 옵션 (독립 체크박스) ──────────────────────────────
        mode_box = QGroupBox("실행 옵션  (중복 선택 가능)")
        mode_box.setStyleSheet(
            "QGroupBox { color: #ecf0f1; border: 1px solid #34495e; margin-top: 6px; font-size: 13px; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 8px; }")
        mode_layout = QVBoxLayout(mode_box)
        mode_layout.setSpacing(10)

        self._cb_multi = QCheckBox("멀티 에이전트  (--multi-agent)  ★ 32개 에이전트 병렬 파이프라인")
        self._cb_ai    = QCheckBox("AI 적응형 생성  (--ai-gen)  Agent-00 이전 사이클 Recall 피드백 반영")
        self._cb_multi.setStyleSheet(_CB_STYLE)
        self._cb_ai.setStyleSheet(_CB_STYLE)
        self._cb_multi.setChecked(True)

        # AI적응형은 멀티에이전트 없이도 동작하지만,
        # 상태에 따라 힌트 레이블 갱신
        self._mode_hint = QLabel("")
        self._mode_hint.setStyleSheet("color: #f39c12; font-size: 11px; padding-left: 4px;")
        self._cb_multi.stateChanged.connect(self._update_mode_hint)
        self._cb_ai.stateChanged.connect(self._update_mode_hint)

        mode_layout.addWidget(self._cb_multi)
        mode_layout.addWidget(self._cb_ai)
        mode_layout.addWidget(self._mode_hint)
        root.addWidget(mode_box)
        self._update_mode_hint()

        # ── 배치 수 ────────────────────────────────────────────────
        batch_row = QHBoxLayout()
        batch_lbl = QLabel("최대 배치 수:")
        batch_lbl.setStyleSheet("color: #ecf0f1; font-size: 13px;")
        self._batch_spin = QSpinBox()
        self._batch_spin.setRange(0, 100)
        self._batch_spin.setValue(5)
        self._batch_spin.setStyleSheet(
            "QSpinBox { background: #2c3e50; color: white; border: 1px solid #34495e; padding: 3px; }")
        self._batch_spin.setFixedWidth(80)
        hint = QLabel("(0 = 기본값 5, Phase2 적용)")
        hint.setStyleSheet("color: #95a5a6; font-size: 11px;")
        batch_row.addWidget(batch_lbl)
        batch_row.addWidget(self._batch_spin)
        batch_row.addWidget(hint)
        batch_row.addStretch()
        root.addLayout(batch_row)

        # ── 버튼 ────────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        self._start_btn = QPushButton("▶  파이프라인 시작")
        self._start_btn.setFixedHeight(40)
        self._start_btn.setStyleSheet(
            "QPushButton { background: #27ae60; color: white; font-size: 14px; border-radius: 6px; }"
            "QPushButton:hover { background: #2ecc71; }"
            "QPushButton:disabled { background: #555; color: #999; }")
        self._stop_btn = QPushButton("■  중지")
        self._stop_btn.setFixedHeight(40)
        self._stop_btn.setEnabled(False)
        self._stop_btn.setStyleSheet(
            "QPushButton { background: #c0392b; color: white; font-size: 14px; border-radius: 6px; }"
            "QPushButton:hover { background: #e74c3c; }"
            "QPushButton:disabled { background: #555; color: #999; }")
        self._start_btn.clicked.connect(self._on_start_clicked)
        self._stop_btn.clicked.connect(self._on_stop_clicked)
        btn_row.addWidget(self._start_btn)
        btn_row.addWidget(self._stop_btn)
        btn_row.addStretch()
        root.addLayout(btn_row)

        # ── 상태 표시 ──────────────────────────────────────────────
        status_box = QGroupBox("실행 상태")
        status_box.setStyleSheet(
            "QGroupBox { color: #ecf0f1; border: 1px solid #34495e; margin-top: 6px; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 8px; }")
        st_layout = QVBoxLayout(status_box)

        def _row(label_text):
            row = QHBoxLayout()
            lbl = QLabel(label_text)
            lbl.setStyleSheet("color: #bdc3c7; font-size: 13px;")
            lbl.setFixedWidth(80)
            val = QLabel("—")
            val.setStyleSheet("color: white; font-size: 13px;")
            row.addWidget(lbl)
            row.addWidget(val)
            row.addStretch()
            st_layout.addLayout(row)
            return val

        self._state_lbl   = _row("상태  :")
        self._pid_lbl     = _row("PID   :")
        self._elapsed_lbl = _row("경과  :")
        self._update_state_label("IDLE")
        root.addWidget(status_box)
        root.addStretch()

    # ------------------------------------------------------------------
    def _update_mode_hint(self):
        multi = self._cb_multi.isChecked()
        ai    = self._cb_ai.isChecked()
        if multi and ai:
            self._mode_hint.setText(
                "→ python3 run_pipeline.py --multi-agent --ai-gen  "
                "(Agent-00 AI생성 + 32개 에이전트 병렬 탐지)")
        elif multi:
            self._mode_hint.setText(
                "→ python3 run_pipeline.py --multi-agent  "
                "(32개 에이전트 병렬 탐지)")
        elif ai:
            self._mode_hint.setText(
                "→ python3 run_pipeline.py --ai-gen  "
                "(AI 적응형 패킷 생성 + 순차 파이프라인)")
        else:
            self._mode_hint.setText(
                "→ python3 run_pipeline.py  "
                "(기본 순차 파이프라인)")

    # ------------------------------------------------------------------
    @pyqtSlot()
    def _on_start_clicked(self):
        multi = self._cb_multi.isChecked()
        ai    = self._cb_ai.isChecked()
        self._elapsed = 0
        self._elapsed_lbl.setText("00:00:00")
        self._timer.start(1000)
        self._ctrl.start(
            multi_agent=multi,
            ai_gen=ai,
            max_batches=self._batch_spin.value()
        )

    @pyqtSlot()
    def _on_stop_clicked(self):
        self._ctrl.stop()

    @pyqtSlot(str)
    def _on_state_changed(self, state: str):
        self._update_state_label(state)
        if state == "RUNNING":
            self._start_btn.setEnabled(False)
            self._stop_btn.setEnabled(True)
            self._cb_multi.setEnabled(False)
            self._cb_ai.setEnabled(False)
            pid = self._ctrl.pid
            self._pid_lbl.setText(str(pid) if pid else "—")
        else:
            self._start_btn.setEnabled(True)
            self._stop_btn.setEnabled(False)
            self._cb_multi.setEnabled(True)
            self._cb_ai.setEnabled(True)
            self._timer.stop()
            if state in ("DONE", "ERROR"):
                self._pid_lbl.setText("—")

    def _update_state_label(self, state: str):
        color = _STATE_COLORS.get(state, "white")
        self._state_lbl.setText(f'<span style="color:{color}; font-weight:bold;">● {state}</span>')
        self._state_lbl.setTextFormat(Qt.RichText)

    @pyqtSlot()
    def _tick_elapsed(self):
        self._elapsed += 1
        h, rem = divmod(self._elapsed, 3600)
        m, s = divmod(rem, 60)
        self._elapsed_lbl.setText(f"{h:02d}:{m:02d}:{s:02d}")
