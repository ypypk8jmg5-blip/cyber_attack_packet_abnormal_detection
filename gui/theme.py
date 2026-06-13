"""테마 토큰 — 색상·치수 중앙 관리 (운영 뷰 / 발표 스테이지 뷰 공용)"""

# 배경 계열 (기존 인라인 QSS 값과 동일)
BG_WINDOW = "#151f2b"
BG_DEEP   = "#1a252f"
BG_PANEL  = "#1e2d3d"
BG_CARD   = "#22303c"
BG_INPUT  = "#2c3e50"
BORDER    = "#34495e"

# 텍스트
TEXT       = "#ecf0f1"
TEXT_MUTED = "#bdc3c7"
TEXT_DIM   = "#7f8c8d"

# 시그널 컬러
GREEN       = "#2ecc71"
GREEN_FLASH = "#7ef0ae"   # 에이전트 점등 플래시
GREEN_WARM  = "#1f8a55"   # 활동 감쇠 후 잔광
BLUE        = "#3498db"
ORANGE      = "#e67e22"
RED         = "#e74c3c"

# 에이전트 셀 (IDLE)
GRAY_IDLE_BG = "#4a5568"
GRAY_IDLE_FG = "#cbd5e0"

# 에이전트 셀 치수 — compact: 운영 뷰(기존 크기), stage: 발표 뷰
CELL = {
    "compact": {"font": 10, "pad_v": 2, "pad_h": 5,  "radius": 3},
    "stage":   {"font": 17, "pad_v": 9, "pad_h": 14, "radius": 6},
}

# 이벤트 배너 — 발표 스크립트의 3박자(기동·탐지·적응) + 게이트 통과
BANNER = {
    "launch":  "#2980b9",
    "detect":  "#c0392b",
    "adapt":   "#d35400",
    "success": "#27ae60",
}
