"""Tab 2: Phase2 탐지 현황"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGroupBox
)
from PyQt5.QtCore import pyqtSlot

from gui.widgets.metric_card import MetricCard
from gui.widgets.alert_bar_chart import AlertBarChart


class Phase2Tab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # ── 경보 카드 5개 ─────────────────────────────────────────
        cards_row = QHBoxLayout()
        self._card_total    = MetricCard("총 경보")
        self._card_critical = MetricCard("CRITICAL")
        self._card_high     = MetricCard("HIGH")
        self._card_medium   = MetricCard("MEDIUM")
        self._card_low      = MetricCard("LOW")
        for card in [self._card_total, self._card_critical, self._card_high,
                     self._card_medium, self._card_low]:
            cards_row.addWidget(card)
        cards_row.addStretch()
        root.addLayout(cards_row)

        # ── 배치 처리 현황 ─────────────────────────────────────────
        self._batch_lbl = QLabel("배치 처리: — | 처리 건수: — | 이상 탐지: —")
        self._batch_lbl.setStyleSheet("color: #ecf0f1; font-size: 13px;")
        root.addWidget(self._batch_lbl)

        # ── 공격 유형별 막대 차트 ─────────────────────────────────
        chart_box = QGroupBox("공격 유형별 경보 분포")
        chart_box.setStyleSheet("QGroupBox { color: #ecf0f1; border: 1px solid #34495e; margin-top: 6px; }"
                                "QGroupBox::title { subcontrol-origin: margin; left: 8px; }")
        chart_layout = QVBoxLayout(chart_box)
        self._chart = AlertBarChart()
        chart_layout.addWidget(self._chart)
        root.addWidget(chart_box)

    # ------------------------------------------------------------------
    @pyqtSlot(dict)
    def on_alerts_updated(self, data: dict):
        total = data.get("total_alerts", 0)
        by_sev = data.get("by_severity", {})
        by_type = data.get("by_attack_type", {})

        # 카드 업데이트
        self._card_total.set_value(total)
        self._card_critical.set_value(by_sev.get("CRITICAL", 0))
        self._card_high.set_value(by_sev.get("HIGH", 0))
        self._card_medium.set_value(by_sev.get("MEDIUM", 0))
        self._card_low.set_value(by_sev.get("LOW", 0))

        # 배치 현황
        batches   = data.get("batches_processed", "—")
        processed = data.get("packets_processed", "—")
        anomalies = data.get("anomalies_detected", "—")
        self._batch_lbl.setText(
            f"배치 처리: {batches} | 처리 건수: {processed} | 이상 탐지: {anomalies}")

        # 차트
        if by_type:
            self._chart.update_data(by_type)

    def reset(self):
        for card in [self._card_total, self._card_critical, self._card_high,
                     self._card_medium, self._card_low]:
            card.reset()
        self._batch_lbl.setText("배치 처리: — | 처리 건수: — | 이상 탐지: —")
