"""Tab 1: Phase1 학습 현황"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar, QGroupBox,
    QGridLayout
)
from PyQt5.QtCore import Qt, pyqtSlot

from gui.widgets.metric_card import MetricCard
from gui.widgets.metric_chart import MetricChart

TARGET_F1 = 0.92
TARGET_RECALL = 0.90
TARGET_PRECISION = 0.88

ATTACK_LABELS_KO = {
    'ddos':                'DDoS',
    'portscan':            '포트스캔',
    'bruteforce':          '브루트포스',
    'exfiltration':        '데이터유출',
    'synflood':            'SYN플러드',
    'dns_tunneling':       'DNS터널링',
    'http_flood':          'HTTP플러드',
    'slowloris':           'Slowloris',
    'botnet_c2':           '봇넷C2',
    'ransomware':          '랜섬웨어',
    'arp_spoofing':        'ARP스푸핑',
    'cryptomining':        '크립토마이닝',
    'dns_amplification':   'DNS증폭',
    'credential_stuffing': '크리덴셜스터핑',
}

ALL_ATTACK_TYPES = list(ATTACK_LABELS_KO.keys())


class Phase1Tab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._seen_cycles: set = set()
        self._recall_bars: dict = {}
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # ── 메트릭 카드 5개 ─────────────────────────────────────────
        cards_row = QHBoxLayout()
        self._card_f1   = MetricCard("F1",        target=TARGET_F1)
        self._card_rec  = MetricCard("Recall",     target=TARGET_RECALL)
        self._card_pre  = MetricCard("Precision",  target=TARGET_PRECISION)
        self._card_acc  = MetricCard("Accuracy")
        self._card_loss = MetricCard("Loss")
        for card in [self._card_f1, self._card_rec, self._card_pre,
                     self._card_acc, self._card_loss]:
            cards_row.addWidget(card)
        cards_row.addStretch()
        root.addLayout(cards_row)

        # ── 진행률 바 ───────────────────────────────────────────────
        prog_box = QGroupBox("목표 달성률")
        prog_box.setStyleSheet("QGroupBox { color: #ecf0f1; border: 1px solid #34495e; margin-top: 6px; }"
                               "QGroupBox::title { subcontrol-origin: margin; left: 8px; }")
        prog_layout = QVBoxLayout(prog_box)

        def _bar_row(label_text, color):
            row = QHBoxLayout()
            lbl = QLabel(label_text)
            lbl.setStyleSheet("color: #bdc3c7; font-size: 12px;")
            lbl.setFixedWidth(70)
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(0)
            bar.setTextVisible(True)
            bar.setStyleSheet(
                f"QProgressBar {{ background: #2c3e50; border: 1px solid #34495e; border-radius: 4px; height: 18px; color: white; }}"
                f"QProgressBar::chunk {{ background: {color}; border-radius: 3px; }}")
            bar.setFixedHeight(20)
            row.addWidget(lbl)
            row.addWidget(bar)
            prog_layout.addLayout(row)
            return bar

        self._bar_f1  = _bar_row("F1",        "#3498db")
        self._bar_rec = _bar_row("Recall",     "#2ecc71")
        self._bar_pre = _bar_row("Precision",  "#e67e22")

        self._cycle_lbl = QLabel("사이클: — / 20   최고 F1: — @ #—")
        self._cycle_lbl.setStyleSheet("color: #ecf0f1; font-size: 12px;")
        prog_layout.addWidget(self._cycle_lbl)
        root.addWidget(prog_box)

        # ── 비정상 패킷 유형별 재현율 (14종) ─────────────────────────
        recall_box = QGroupBox("비정상 패킷 유형별 재현율 (14종)")
        recall_box.setStyleSheet(
            "QGroupBox { color: #ecf0f1; border: 1px solid #34495e; margin-top: 6px; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 8px; }")
        grid = QGridLayout(recall_box)
        grid.setSpacing(4)
        grid.setContentsMargins(8, 12, 8, 8)

        for i, atype in enumerate(ALL_ATTACK_TYPES):
            row, col = divmod(i, 2)
            ko_name = ATTACK_LABELS_KO[atype]

            name_lbl = QLabel(ko_name)
            name_lbl.setStyleSheet("color: #bdc3c7; font-size: 11px;")
            name_lbl.setFixedWidth(80)

            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(0)
            bar.setFixedHeight(14)
            bar.setFormat("—")
            bar.setStyleSheet(
                "QProgressBar { background: #2c3e50; border: 1px solid #34495e; "
                "border-radius: 3px; color: white; font-size: 9px; }"
                "QProgressBar::chunk { background: #3498db; border-radius: 2px; }")
            self._recall_bars[atype] = bar

            cell = QHBoxLayout()
            cell.setSpacing(4)
            cell.addWidget(name_lbl)
            cell.addWidget(bar)
            grid.addLayout(cell, row, col)

        root.addWidget(recall_box)

        # ── 추이 차트 ────────────────────────────────────────────────
        chart_box = QGroupBox("F1 / Recall / Precision 추이")
        chart_box.setStyleSheet("QGroupBox { color: #ecf0f1; border: 1px solid #34495e; margin-top: 6px; }"
                                "QGroupBox::title { subcontrol-origin: margin; left: 8px; }")
        chart_layout = QVBoxLayout(chart_box)
        self._chart = MetricChart()
        chart_layout.addWidget(self._chart)
        root.addWidget(chart_box)

    # ------------------------------------------------------------------
    @pyqtSlot(dict)
    def on_dashboard_updated(self, data: dict):
        cycles     = data.get("cycles", [])
        best_f1    = data.get("best_f1", 0.0)
        best_cycle = data.get("best_cycle", 0)
        cur_cycle  = data.get("current_cycle", 0)

        self._cycle_lbl.setText(
            f"사이클: {cur_cycle} / 20   최고 F1: {best_f1:.4f} @ #{best_cycle}")

        for c in cycles:
            cy = c.get("cycle", 0)
            if cy not in self._seen_cycles:
                self._seen_cycles.add(cy)
                f1  = c.get("f1", 0.0)
                rec = c.get("recall", 0.0)
                pre = c.get("precision", c.get("f1", 0.0))
                self._chart.add_point(cy, f1, rec, pre)

        if cycles:
            last = cycles[-1]
            f1  = last.get("f1", 0.0)
            rec = last.get("recall", 0.0)
            self._bar_f1.setValue(min(int(f1 / TARGET_F1 * 100), 100))
            self._bar_rec.setValue(min(int(rec / TARGET_RECALL * 100), 100))
            self._bar_f1.setFormat(f"{f1:.4f}  ({int(f1/TARGET_F1*100)}%)")
            self._bar_rec.setFormat(f"{rec:.4f}  ({int(rec/TARGET_RECALL*100)}%)")

    @pyqtSlot(dict)
    def on_metrics_updated(self, data: dict):
        metrics = data.get("metrics", {})
        f1  = metrics.get("f1_score",  0.0)
        rec = metrics.get("recall",    0.0)
        pre = metrics.get("precision", 0.0)
        acc = metrics.get("accuracy",  0.0)
        loss = metrics.get("loss", metrics.get("train_loss", 0.0))

        self._card_f1.set_value(f1,  achieved=f1  >= TARGET_F1)
        self._card_rec.set_value(rec, achieved=rec >= TARGET_RECALL)
        self._card_pre.set_value(pre, achieved=pre >= TARGET_PRECISION)
        self._card_acc.set_value(acc)
        self._card_loss.set_value(loss)

        self._bar_pre.setValue(min(int(pre / TARGET_PRECISION * 100), 100))
        self._bar_pre.setFormat(f"{pre:.4f}  ({int(pre/TARGET_PRECISION*100)}%)")

        per_attack = data.get("per_attack_recall", {})
        self._update_recall_grid(per_attack)

    def _update_recall_grid(self, per_attack: dict):
        for atype, bar in self._recall_bars.items():
            val = per_attack.get(atype)
            if val is None:
                bar.setValue(0)
                bar.setFormat("—")
                bar.setStyleSheet(
                    "QProgressBar { background: #2c3e50; border: 1px solid #34495e; "
                    "border-radius: 3px; color: white; font-size: 9px; }"
                    "QProgressBar::chunk { background: #3498db; border-radius: 2px; }")
            else:
                pct = min(int(val * 100), 100)
                bar.setValue(pct)
                bar.setFormat(f"{val:.2f}")
                color = "#2ecc71" if val >= 0.90 else ("#f39c12" if val >= 0.70 else "#e74c3c")
                bar.setStyleSheet(
                    f"QProgressBar {{ background: #2c3e50; border: 1px solid #34495e; "
                    f"border-radius: 3px; color: white; font-size: 9px; }}"
                    f"QProgressBar::chunk {{ background: {color}; border-radius: 2px; }}")

    def reset(self):
        for card in [self._card_f1, self._card_rec, self._card_pre,
                     self._card_acc, self._card_loss]:
            card.reset()
        self._bar_f1.setValue(0)
        self._bar_rec.setValue(0)
        self._bar_pre.setValue(0)
        self._chart.clear()
        self._seen_cycles.clear()
        self._cycle_lbl.setText("사이클: — / 20   최고 F1: — @ #—")
        self._update_recall_grid({})
