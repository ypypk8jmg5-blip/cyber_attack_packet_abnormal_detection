"""MetricCard — 단일 메트릭 표시 카드"""
from PyQt5.QtWidgets import QFrame, QVBoxLayout, QLabel
from PyQt5.QtCore import Qt


class MetricCard(QFrame):
    def __init__(self, title: str, target: float = None, parent=None):
        super().__init__(parent)
        self._target = target
        self._setup_ui(title)
        self._set_default_style()

    def _setup_ui(self, title: str):
        self.setFixedSize(130, 110)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(2)

        self._title_lbl = QLabel(title)
        self._title_lbl.setAlignment(Qt.AlignCenter)
        self._title_lbl.setStyleSheet("font-size: 11px; color: #bdc3c7;")

        self._value_lbl = QLabel("—")
        self._value_lbl.setAlignment(Qt.AlignCenter)
        self._value_lbl.setStyleSheet("font-size: 20px; font-weight: bold; color: white;")

        self._target_lbl = QLabel(f"목표: {self._target:.2f}" if self._target else "")
        self._target_lbl.setAlignment(Qt.AlignCenter)
        self._target_lbl.setStyleSheet("font-size: 10px; color: #95a5a6;")

        self._badge_lbl = QLabel("")
        self._badge_lbl.setAlignment(Qt.AlignCenter)
        self._badge_lbl.setStyleSheet("font-size: 11px;")

        layout.addWidget(self._title_lbl)
        layout.addWidget(self._value_lbl)
        layout.addWidget(self._target_lbl)
        layout.addWidget(self._badge_lbl)

    def _set_default_style(self):
        self.setStyleSheet("""
            MetricCard {
                background-color: #2c3e50;
                border: 2px solid #34495e;
                border-radius: 8px;
            }
        """)

    def set_value(self, v, achieved: bool = False):
        # 정수(경보 건수 등)와 소수(F1 점수 등) 모두 지원
        if isinstance(v, float) and v != int(v):
            self._value_lbl.setText(f"{v:.4f}")
        else:
            self._value_lbl.setText(f"{int(v):,}")
        if self._target is not None:
            if achieved:
                self.setStyleSheet("""
                    MetricCard {
                        background-color: #2c3e50;
                        border: 2px solid #2ecc71;
                        border-radius: 8px;
                    }
                """)
                self._badge_lbl.setText("✓ 달성")
                self._badge_lbl.setStyleSheet("font-size: 11px; color: #2ecc71;")
            else:
                self.setStyleSheet("""
                    MetricCard {
                        background-color: #2c3e50;
                        border: 2px solid #e74c3c;
                        border-radius: 8px;
                    }
                """)
                self._badge_lbl.setText("✗ 미달")
                self._badge_lbl.setStyleSheet("font-size: 11px; color: #e74c3c;")
        else:
            self._badge_lbl.setText("")

    def reset(self):
        self._value_lbl.setText("—")
        self._badge_lbl.setText("")
        self._set_default_style()
