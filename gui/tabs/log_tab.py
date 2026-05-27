"""Tab 4: 실시간 로그"""
import os
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QPlainTextEdit, QFileDialog
)
from PyQt5.QtCore import Qt, pyqtSlot
from PyQt5.QtGui import QFont, QTextCharFormat, QColor, QTextCursor

MAX_LINES = 5000

_COLOR_MAP = [
    (["[error]", "오류", "실패", "failed", "traceback"],     "#e74c3c"),
    (["[warning]", "경고", "warn"],                          "#e67e22"),
    (["targets met", "목표 달성", "f1=1", "완료"],           "#27ae60"),
    (["phase 1", "phase 2", "=== phase"],                   "#3498db"),
]


def _line_color(line: str) -> str:
    lower = line.lower()
    for keywords, color in _COLOR_MAP:
        if any(k in lower for k in keywords):
            return color
    return "#ecf0f1"


class LogTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._line_count = 0
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # 버튼 바
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        clear_btn = QPushButton("지우기")
        clear_btn.setFixedHeight(28)
        clear_btn.setStyleSheet(
            "QPushButton { background: #34495e; color: white; border-radius: 4px; padding: 0 12px; }"
            "QPushButton:hover { background: #4a6278; }")
        save_btn = QPushButton("저장")
        save_btn.setFixedHeight(28)
        save_btn.setStyleSheet(
            "QPushButton { background: #27ae60; color: white; border-radius: 4px; padding: 0 12px; }"
            "QPushButton:hover { background: #2ecc71; }")
        clear_btn.clicked.connect(self.clear)
        save_btn.clicked.connect(self._save)
        btn_row.addWidget(clear_btn)
        btn_row.addWidget(save_btn)
        root.addLayout(btn_row)

        # 로그 텍스트 영역
        self._text = QPlainTextEdit()
        self._text.setReadOnly(True)
        self._text.setFont(QFont("Courier New", 10))
        self._text.setStyleSheet(
            "QPlainTextEdit { background: #0d1b2a; color: #ecf0f1; border: 1px solid #34495e; }")
        self._text.setMaximumBlockCount(MAX_LINES)
        root.addWidget(self._text)

    @pyqtSlot(list)
    def on_new_lines(self, lines: list):
        cursor = self._text.textCursor()
        for line in lines:
            ts = datetime.now().strftime("%H:%M:%S")
            full_line = f"[{ts}] {line}"
            color = _line_color(line)

            fmt = QTextCharFormat()
            fmt.setForeground(QColor(color))
            cursor.movePosition(QTextCursor.End)
            cursor.insertText(full_line + "\n", fmt)
            self._line_count += 1

        self._text.setTextCursor(cursor)
        self._text.ensureCursorVisible()

    @pyqtSlot(str)
    def on_stdout_line(self, line: str):
        self.on_new_lines([line])

    @pyqtSlot()
    def clear(self):
        self._text.clear()
        self._line_count = 0

    @pyqtSlot()
    def _save(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "로그 저장", f"pipeline_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;All Files (*)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._text.toPlainText())
