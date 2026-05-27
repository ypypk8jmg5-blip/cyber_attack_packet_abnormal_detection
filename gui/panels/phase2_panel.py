"""Phase2 Panel — 탐지 현황 (대시보드 내장용)"""
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel
from PyQt5.QtCore import pyqtSlot

from gui.widgets.metric_card import MetricCard
from gui.widgets.alert_bar_chart import AlertBarChart


class Phase2Panel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 6)
        root.setSpacing(6)

        title = QLabel("Phase 2 — 탐지 현황")
        title.setStyleSheet("color:#ecf0f1; font-size:14px; font-weight:bold;")
        root.addWidget(title)

        # 경보 카드
        cards_row = QHBoxLayout()
        cards_row.setSpacing(6)
        self._card_total    = MetricCard("총 경보")
        self._card_critical = MetricCard("CRITICAL")
        self._card_high     = MetricCard("HIGH")
        self._card_medium   = MetricCard("MEDIUM")
        self._card_low      = MetricCard("LOW")
        for c in [self._card_total, self._card_critical, self._card_high,
                  self._card_medium, self._card_low]:
            cards_row.addWidget(c)
        cards_row.addStretch()
        root.addLayout(cards_row)

        self._batch_lbl = QLabel("배치: —  |  처리: —  |  이상: —")
        self._batch_lbl.setStyleSheet("color:#ecf0f1; font-size:11px;")
        root.addWidget(self._batch_lbl)

        self._chart = AlertBarChart()
        root.addWidget(self._chart)

    @pyqtSlot(dict)
    def on_alerts_updated(self, data: dict):
        total   = data.get("total_alerts", 0)
        by_sev  = data.get("by_severity", {})
        by_type = data.get("by_attack_type", {})
        self._card_total.set_value(total)
        self._card_critical.set_value(by_sev.get("CRITICAL", 0))
        self._card_high.set_value(by_sev.get("HIGH", 0))
        self._card_medium.set_value(by_sev.get("MEDIUM", 0))
        self._card_low.set_value(by_sev.get("LOW", 0))
        batches   = data.get("batches_processed", "—")
        processed = data.get("packets_processed", "—")
        anomalies = data.get("anomalies_detected", "—")
        self._batch_lbl.setText(
            f"배치: {batches}  |  처리: {processed}  |  이상: {anomalies}")
        if by_type:
            self._chart.update_data(by_type)

    def reset(self):
        for c in [self._card_total, self._card_critical, self._card_high,
                  self._card_medium, self._card_low]:
            c.reset()
        self._batch_lbl.setText("배치: —  |  처리: —  |  이상: —")
