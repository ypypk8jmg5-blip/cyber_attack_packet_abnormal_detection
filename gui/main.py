"""GUI 진입점 — QApplication 초기화"""
import sys
import os

# matplotlib 백엔드를 Qt5Agg로 고정 (import 전 설정 필수)
import matplotlib
matplotlib.use("Qt5Agg")

# 한글 폰트 설정 (macOS: AppleGothic 우선, 없으면 DejaVu)
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
_KOREAN_FONTS = ["AppleGothic", "Apple SD Gothic Neo", "NanumGothic", "Malgun Gothic", "sans-serif"]
for _fname in _KOREAN_FONTS:
    _found = [f for f in fm.fontManager.ttflist if _fname in f.name]
    if _found:
        plt.rcParams["font.family"] = _fname
        break
plt.rcParams["axes.unicode_minus"] = False  # 마이너스 부호 깨짐 방지

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt


def main(present: bool = False):
    # High-DPI 지원
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # 전역 다크 팔레트
    from PyQt5.QtGui import QPalette, QColor
    palette = QPalette()
    palette.setColor(QPalette.Window,          QColor("#1a252f"))
    palette.setColor(QPalette.WindowText,      QColor("#ecf0f1"))
    palette.setColor(QPalette.Base,            QColor("#2c3e50"))
    palette.setColor(QPalette.AlternateBase,   QColor("#34495e"))
    palette.setColor(QPalette.ToolTipBase,     QColor("#2c3e50"))
    palette.setColor(QPalette.ToolTipText,     QColor("#ecf0f1"))
    palette.setColor(QPalette.Text,            QColor("#ecf0f1"))
    palette.setColor(QPalette.Button,          QColor("#2c3e50"))
    palette.setColor(QPalette.ButtonText,      QColor("#ecf0f1"))
    palette.setColor(QPalette.Highlight,       QColor("#3498db"))
    palette.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    app.setPalette(palette)

    from gui.app_window import AppWindow
    window = AppWindow()
    window.show()
    if present:
        window.set_present(True)

    sys.exit(app.exec_())
