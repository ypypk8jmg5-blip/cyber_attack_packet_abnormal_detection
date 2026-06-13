"""BannerOverlay — 발표용 이벤트 배너 (상단 중앙 오버레이, 자동 소멸)

레이아웃에 넣지 않고 AppWindow의 자식으로 띄운다 — 표시/숨김 시
화면이 출렁이지 않도록 (resizeEvent에서 reposition() 호출 필요).
"""
from PyQt5.QtWidgets import QLabel, QGraphicsOpacityEffect
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation

from gui import theme

HOLD_MS = 3000
FADE_MS = 220


class BannerOverlay(QLabel):
    def __init__(self, parent):
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)

        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)
        self._fade = QPropertyAnimation(self._effect, b"opacity", self)

        self._hide_timer = QTimer(self)
        self._hide_timer.setSingleShot(True)
        self._hide_timer.setInterval(HOLD_MS)
        self._hide_timer.timeout.connect(self._fade_out)

        self.hide()

    # ------------------------------------------------------------------
    def show_message(self, kind: str, text: str):
        color = theme.BANNER.get(kind, theme.BANNER["launch"])
        self.setText(text)
        self.setStyleSheet(
            f"background:{color}; color:white; font-size:26px; font-weight:bold; "
            f"border-radius:12px; padding:16px 36px;")
        self.adjustSize()
        self.reposition()
        self.show()
        self.raise_()
        self._fade.stop()
        self._fade.setDuration(FADE_MS)
        self._fade.setStartValue(0.0)
        self._fade.setEndValue(1.0)
        self._fade.start()
        self._hide_timer.start()

    def reposition(self):
        # 스테이지 뷰 헤더(타이틀 행)를 가리지 않도록 그 아래에 띄운다
        parent = self.parentWidget()
        if parent:
            self.move((parent.width() - self.width()) // 2, 84)

    # ------------------------------------------------------------------
    def _fade_out(self):
        self._fade.stop()
        self._fade.setDuration(FADE_MS)
        self._fade.setStartValue(1.0)
        self._fade.setEndValue(0.0)
        try:
            self._fade.finished.disconnect()
        except TypeError:
            pass  # 연결된 슬롯 없음
        self._fade.finished.connect(self.hide)
        self._fade.start()
