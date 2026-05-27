"""Phase1 Panel — 학습 현황 (대시보드 내장용)"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar, QFrame,
    QGridLayout, QGroupBox
)
from PyQt5.QtCore import pyqtSlot, Qt

from gui.widgets.metric_card import MetricCard
from gui.widgets.metric_chart import MetricChart

TARGET_F1        = 0.92
TARGET_RECALL    = 0.90
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


class Phase1Panel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._seen_cycles: set = set()
        self._recall_bars: dict = {}
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 6)
        root.setSpacing(6)

        title = QLabel("Phase 1 — 학습 현황")
        title.setStyleSheet("color:#ecf0f1; font-size:14px; font-weight:bold;")
        root.addWidget(title)

        # 메트릭 카드
        cards_row = QHBoxLayout()
        cards_row.setSpacing(6)
        self._card_f1  = MetricCard("F1",       target=TARGET_F1)
        self._card_rec = MetricCard("Recall",    target=TARGET_RECALL)
        self._card_pre = MetricCard("Precision", target=TARGET_PRECISION)
        self._card_acc = MetricCard("Accuracy")
        self._card_loss= MetricCard("Loss")
        for c in [self._card_f1, self._card_rec, self._card_pre,
                  self._card_acc, self._card_loss]:
            cards_row.addWidget(c)
        cards_row.addStretch()
        root.addLayout(cards_row)

        # 진행률 바 + 사이클 정보
        prog_row = QHBoxLayout()
        prog_row.setSpacing(10)

        def _bar(color, target_name):
            col = QVBoxLayout()
            lbl = QLabel(target_name)
            lbl.setStyleSheet("color:#bdc3c7; font-size:10px;")
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(0)
            bar.setFixedHeight(14)
            bar.setStyleSheet(
                f"QProgressBar{{background:#2c3e50;border:1px solid #34495e;border-radius:3px;color:white;font-size:9px;}}"
                f"QProgressBar::chunk{{background:{color};border-radius:2px;}}")
            col.addWidget(lbl)
            col.addWidget(bar)
            return col, bar

        col_f1,  self._bar_f1  = _bar("#3498db", f"F1 (목표 {TARGET_F1})")
        col_rec, self._bar_rec = _bar("#2ecc71", f"Recall (목표 {TARGET_RECALL})")
        col_pre, self._bar_pre = _bar("#e67e22", f"Precision (목표 {TARGET_PRECISION})")
        prog_row.addLayout(col_f1,  3)
        prog_row.addLayout(col_rec, 3)
        prog_row.addLayout(col_pre, 3)

        self._cycle_lbl = QLabel("사이클: — / 20  │  최고 F1: — @ #—")
        self._cycle_lbl.setStyleSheet("color:#ecf0f1; font-size:11px;")
        prog_row.addWidget(self._cycle_lbl, 4)
        root.addLayout(prog_row)

        # 공격 유형별 재현율 그리드 (14종)
        recall_box = QGroupBox("비정상 패킷 유형별 재현율 (14종)")
        recall_box.setStyleSheet(
            "QGroupBox { color:#bdc3c7; border:1px solid #34495e; margin-top:6px; font-size:10px; }"
            "QGroupBox::title { subcontrol-origin:margin; left:8px; }")
        grid = QGridLayout(recall_box)
        grid.setSpacing(3)
        grid.setContentsMargins(6, 10, 6, 6)

        for i, atype in enumerate(ALL_ATTACK_TYPES):
            row, col = divmod(i, 2)
            ko_name = ATTACK_LABELS_KO[atype]

            name_lbl = QLabel(ko_name)
            name_lbl.setStyleSheet("color:#bdc3c7; font-size:9px;")
            name_lbl.setFixedWidth(72)

            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(0)
            bar.setFixedHeight(12)
            bar.setFormat("—")
            bar.setStyleSheet(
                "QProgressBar{background:#2c3e50;border:1px solid #34495e;"
                "border-radius:2px;color:white;font-size:8px;}"
                "QProgressBar::chunk{background:#3498db;border-radius:2px;}")
            self._recall_bars[atype] = bar

            cell = QHBoxLayout()
            cell.setSpacing(3)
            cell.addWidget(name_lbl)
            cell.addWidget(bar)

            grid.addLayout(cell, row, col)

        root.addWidget(recall_box)

        # 추이 차트
        self._chart = MetricChart()
        root.addWidget(self._chart)

    # ------------------------------------------------------------------
    @pyqtSlot(dict)
    def on_dashboard_updated(self, data: dict):
        cycles     = data.get("cycles", [])
        best_f1    = data.get("best_f1", 0.0)
        best_cycle = data.get("best_cycle", 0)
        cur_cycle  = data.get("current_cycle", 0)
        self._cycle_lbl.setText(
            f"사이클: {cur_cycle} / 20  │  최고 F1: {best_f1:.4f} @ #{best_cycle}")
        for c in cycles:
            cy = c.get("cycle", 0)
            if cy not in self._seen_cycles:
                self._seen_cycles.add(cy)
                f1  = c.get("f1", 0.0)
                rec = c.get("recall", 0.0)
                pre = c.get("precision", f1)
                self._chart.add_point(cy, f1, rec, pre)
        if cycles:
            last = cycles[-1]
            f1  = last.get("f1", 0.0)
            rec = last.get("recall", 0.0)
            self._bar_f1.setValue(min(int(f1 / TARGET_F1 * 100), 100))
            self._bar_rec.setValue(min(int(rec / TARGET_RECALL * 100), 100))
            self._bar_f1.setFormat(f"{f1:.3f} ({int(f1/TARGET_F1*100)}%)")
            self._bar_rec.setFormat(f"{rec:.3f} ({int(rec/TARGET_RECALL*100)}%)")

    @pyqtSlot(dict)
    def on_metrics_updated(self, data: dict):
        m   = data.get("metrics", {})
        f1  = m.get("f1_score",  0.0)
        rec = m.get("recall",    0.0)
        pre = m.get("precision", 0.0)
        acc = m.get("accuracy",  0.0)
        loss= m.get("loss", m.get("train_loss", 0.0))
        self._card_f1.set_value(f1,   achieved=f1  >= TARGET_F1)
        self._card_rec.set_value(rec,  achieved=rec >= TARGET_RECALL)
        self._card_pre.set_value(pre,  achieved=pre >= TARGET_PRECISION)
        self._card_acc.set_value(acc)
        self._card_loss.set_value(loss)
        self._bar_pre.setValue(min(int(pre / TARGET_PRECISION * 100), 100))
        self._bar_pre.setFormat(f"{pre:.3f} ({int(pre/TARGET_PRECISION*100)}%)")

        per_attack = data.get("per_attack_recall", {})
        self._update_recall_grid(per_attack)

    def _update_recall_grid(self, per_attack: dict):
        for atype, bar in self._recall_bars.items():
            val = per_attack.get(atype)
            if val is None:
                bar.setValue(0)
                bar.setFormat("—")
                bar.setStyleSheet(
                    "QProgressBar{background:#2c3e50;border:1px solid #34495e;"
                    "border-radius:2px;color:white;font-size:8px;}"
                    "QProgressBar::chunk{background:#3498db;border-radius:2px;}")
            else:
                pct = min(int(val * 100), 100)
                bar.setValue(pct)
                bar.setFormat(f"{val:.2f}")
                color = "#2ecc71" if val >= 0.90 else ("#f39c12" if val >= 0.70 else "#e74c3c")
                bar.setStyleSheet(
                    f"QProgressBar{{background:#2c3e50;border:1px solid #34495e;"
                    f"border-radius:2px;color:white;font-size:8px;}}"
                    f"QProgressBar::chunk{{background:{color};border-radius:2px;}}")

    def reset(self):
        for c in [self._card_f1, self._card_rec, self._card_pre,
                  self._card_acc, self._card_loss]:
            c.reset()
        self._bar_f1.setValue(0)
        self._bar_rec.setValue(0)
        self._bar_pre.setValue(0)
        self._chart.clear()
        self._seen_cycles.clear()
        self._cycle_lbl.setText("사이클: — / 20  │  최고 F1: — @ #—")
        self._update_recall_grid({})
