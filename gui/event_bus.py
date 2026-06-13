"""EventBus — 로그·지표 변화에서 발표용 키 이벤트 감지

발표 스크립트의 3박자와 동일한 이벤트 종류를 사용한다:
  launch(기동) · detect(탐지) · adapt(적응) · success(게이트 통과)
"""
import re
import time
from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot

# "[agent-27-drift-detector]" 같은 이름 토큰이 키워드("drift")에 오탐되지 않도록
# 매칭 전에 괄호 토큰을 제거한다
_BRACKET = re.compile(r"\[[^\]]*\]")
_CYCLE   = re.compile(r"cycle\s*(\d+)")

_GATE_KEYWORDS    = ("targets met", "목표 달성")
_RETRAIN_KEYWORDS = ("drift detected", "드리프트 감지", "재학습 시작",
                     "재학습 트리거", "retrain triggered", "retraining")

DEBOUNCE_SEC = 4.0   # 같은 종류 이벤트 연속 발생 시 배너 스팸 방지


class EventBus(QObject):
    event_detected = pyqtSignal(str, str)   # (kind, message)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._last_emit: dict = {}
        self._last_critical = None   # None = 기준선 미설정 (이전 세션 파일 무시)

    # ------------------------------------------------------------------
    @pyqtSlot(str)
    def on_state_changed(self, state: str):
        if state == "RUNNING":
            self._last_emit.clear()
            self._last_critical = 0   # 새 세션 — 경보 카운트는 0부터
            self._emit("launch", "기동 — 32 에이전트 점등")

    @pyqtSlot(str)
    def on_stdout_line(self, line: str):
        body = _BRACKET.sub(" ", line).lower()
        if any(k in body for k in _GATE_KEYWORDS):
            m = _CYCLE.search(body)
            msg = (f"게이트 통과 — 사이클 {m.group(1)}, 학습 목표 달성"
                   if m else "게이트 통과 — 학습 목표 달성")
            self._emit("success", msg)
        elif any(k in body for k in _RETRAIN_KEYWORDS):
            self._emit("adapt", "적응 — 드리프트 감지, 재학습 트리거")

    @pyqtSlot(dict)
    def on_alerts_updated(self, data: dict):
        critical = data.get("by_severity", {}).get("CRITICAL", 0)
        if self._last_critical is None:
            # GUI 기동 직후 읽힌 이전 세션 파일 → 기준선만 설정
            self._last_critical = critical
            return
        if critical > self._last_critical:
            self._emit("detect", f"탐지 — CRITICAL 알림 +{critical - self._last_critical}")
        self._last_critical = critical

    # ------------------------------------------------------------------
    def _emit(self, kind: str, msg: str):
        now = time.monotonic()
        last = self._last_emit.get(kind)
        if last is not None and now - last < DEBOUNCE_SEC:
            return
        self._last_emit[kind] = now
        self.event_detected.emit(kind, msg)
