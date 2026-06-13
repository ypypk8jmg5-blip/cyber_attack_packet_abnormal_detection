"""AgentCell — 점등 애니메이션이 있는 에이전트 상태 셀

상태 흐름:
  IDLE ──ping()──▶ ACTIVE(플래시→유지) ──3초 무활동──▶ WARM(잔광)
                      ▲                                   │
                      └────────────── ping() ─────────────┘
  ERROR는 set_error()로 진입, reset() 전까지 유지.
"""
from PyQt5.QtWidgets import QLabel
from PyQt5.QtCore import Qt, QTimer, QVariantAnimation, QAbstractAnimation
from PyQt5.QtGui import QColor

from gui import theme

DECAY_MS      = 3000   # 마지막 활동 후 잔광 전환까지
FLASH_MS      = 450    # 플래시 → ACTIVE 보간 시간
DECAY_ANIM_MS = 700    # ACTIVE → 잔광 보간 시간


class AgentCell(QLabel):
    def __init__(self, text: str, mode: str = "compact", parent=None):
        super().__init__(text, parent)
        self._dim = theme.CELL[mode]
        self._fg = theme.GRAY_IDLE_FG
        self._state = "IDLE"
        self.setAlignment(Qt.AlignCenter)

        self._anim = QVariantAnimation(self)
        self._anim.valueChanged.connect(self._paint_bg)

        self._decay_timer = QTimer(self)
        self._decay_timer.setSingleShot(True)
        self._decay_timer.setInterval(DECAY_MS)
        self._decay_timer.timeout.connect(self._decay)

        self._paint_bg(QColor(theme.GRAY_IDLE_BG))

    # ------------------------------------------------------------------
    def ping(self):
        """활동 신호 — 점등(플래시) 후 ACTIVE 유지, 무활동 시 잔광으로 감쇠"""
        if self._state == "ERROR":
            return
        revive = self._state != "ACTIVE"
        self._state = "ACTIVE"
        self._fg = "white"
        # 로그 폭주 시 매 라인 재시작으로 플래시에 고정되는 것 방지:
        # 재점등(IDLE/WARM 복귀)이거나 진행 중 애니메이션이 없을 때만 플래시
        if revive or self._anim.state() != QAbstractAnimation.Running:
            self._animate(theme.GREEN_FLASH, theme.GREEN, FLASH_MS)
        self._decay_timer.start()

    def set_error(self):
        self._state = "ERROR"
        self._decay_timer.stop()
        self._anim.stop()
        self._fg = "white"
        self._paint_bg(QColor(theme.RED))

    def reset(self):
        self._state = "IDLE"
        self._decay_timer.stop()
        self._anim.stop()
        self._fg = theme.GRAY_IDLE_FG
        self._paint_bg(QColor(theme.GRAY_IDLE_BG))

    # ------------------------------------------------------------------
    def _decay(self):
        if self._state != "ACTIVE":
            return
        self._state = "WARM"
        self._animate(theme.GREEN, theme.GREEN_WARM, DECAY_ANIM_MS)

    def _animate(self, c_from: str, c_to: str, ms: int):
        self._anim.stop()
        self._anim.setDuration(ms)
        self._anim.setStartValue(QColor(c_from))
        self._anim.setEndValue(QColor(c_to))
        self._anim.start()

    def _paint_bg(self, color):
        d = self._dim
        self.setStyleSheet(
            f"background:{QColor(color).name()}; color:{self._fg}; "
            f"border-radius:{d['radius']}px; "
            f"padding:{d['pad_v']}px {d['pad_h']}px; font-size:{d['font']}px;")
