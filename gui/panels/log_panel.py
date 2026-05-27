"""Log Panel — 실시간 로그 (대시보드 내장용)"""
import os
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QPlainTextEdit, QLabel, QFileDialog
)
from PyQt5.QtCore import pyqtSlot
from PyQt5.QtGui import QFont, QTextCharFormat, QColor, QTextCursor

MAX_LINES = 3000

_COLOR_MAP = [
    (["[error]", "traceback", "오류", "실패", "failed"],  "#e74c3c"),
    (["[warning]", "경고", "warn"],                       "#e67e22"),
    (["targets met", "목표 달성", "완료", "done"],         "#27ae60"),
    (["=== phase", "phase 1", "phase 2"],                 "#3498db"),
]


def _line_color(line: str) -> str:
    low = line.lower()
    for keywords, color in _COLOR_MAP:
        if any(k in low for k in keywords):
            return color
    return "#ecf0f1"


class LogPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 8, 10, 6)
        root.setSpacing(4)

        # 헤더 행
        header = QHBoxLayout()
        title = QLabel("실시간 로그")
        title.setStyleSheet("color:#ecf0f1; font-size:14px; font-weight:bold;")
        header.addWidget(title)
        header.addStretch()

        for label, slot in [("지우기", self.clear), ("저장", self._save)]:
            btn = QPushButton(label)
            btn.setFixedSize(52, 24)
            btn.setStyleSheet(
                "QPushButton{background:#34495e;color:white;border-radius:3px;font-size:11px;}"
                "QPushButton:hover{background:#4a6278;}")
            btn.clicked.connect(slot)
            header.addWidget(btn)

        root.addLayout(header)

        self._text = QPlainTextEdit()
        self._text.setReadOnly(True)
        self._text.setFont(QFont("Courier New", 9))
        self._text.setMaximumBlockCount(MAX_LINES)
        self._text.setStyleSheet(
            "QPlainTextEdit{background:#0d1b2a;color:#ecf0f1;border:1px solid #2c3e50;}")
        root.addWidget(self._text)

    @pyqtSlot(list)
    def on_new_lines(self, lines: list):
        cursor = self._text.textCursor()
        for line in lines:
            ts = datetime.now().strftime("%H:%M:%S")
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(_line_color(line)))
            cursor.movePosition(QTextCursor.End)
            cursor.insertText(f"[{ts}] {line}\n", fmt)
        self._text.setTextCursor(cursor)
        self._text.ensureCursorVisible()

    @pyqtSlot(str)
    def on_stdout_line(self, line: str):
        self.on_new_lines([line])

    @pyqtSlot()
    def clear(self):
        self._text.clear()

    @pyqtSlot()
    def _save(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "로그 저장",
            f"pipeline_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;All Files (*)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._text.toPlainText())
