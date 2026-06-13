"""시간 유틸 — deprecated된 datetime.utcnow() 대체.

datetime.utcnow()는 Python 3.12+에서 deprecated이며 향후 제거 예정이다.
권장 대체(datetime.now(timezone.utc))는 tz-aware 객체라 isoformat()에
"+00:00"이 붙어 기존 출력과 달라진다. 기존 로그·JSON 형식을 그대로
유지하기 위해 tzinfo를 떼어낸 naive UTC datetime을 반환한다.
"""
from datetime import datetime, timezone


def utcnow() -> datetime:
    """naive UTC datetime (기존 datetime.utcnow()와 동일한 값·형식)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
