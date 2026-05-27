"""PipelineController — QProcess 기반 파이프라인 실행/중지"""
import sys
import os
from PyQt5.QtCore import QObject, QProcess, QProcessEnvironment, pyqtSignal, QTimer

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PipelineController(QObject):
    state_changed = pyqtSignal(str)   # IDLE / RUNNING / DONE / ERROR
    stdout_line = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._process: QProcess = None
        self._state = "IDLE"
        self._user_stopped = False   # stop() 버튼으로 종료 시 True

    # ------------------------------------------------------------------
    def start(self, multi_agent: bool = False, ai_gen: bool = False, max_batches: int = 5):
        if self._process and self._process.state() != QProcess.NotRunning:
            return
        self._user_stopped = False

        cmd_args = []
        if multi_agent:
            cmd_args += ["--multi-agent"]
        if ai_gen:
            cmd_args += ["--ai-gen"]
        if max_batches > 0:
            cmd_args += ["--max-batches", str(max_batches)]

        self._process = QProcess(self)
        self._process.setWorkingDirectory(PROJECT_ROOT)

        # PYTHONUNBUFFERED=1: Python의 stdout 블록 버퍼링 해제
        # → print()가 즉시 QProcess로 전달 (없으면 수십 초 동안 아무것도 안 보임)
        env = QProcessEnvironment.systemEnvironment()
        env.insert("PYTHONUNBUFFERED", "1")
        self._process.setProcessEnvironment(env)

        self._process.readyReadStandardOutput.connect(self._on_stdout)
        self._process.readyReadStandardError.connect(self._on_stderr)
        self._process.finished.connect(self._on_finished)

        # -u 플래그: 추가 보장 (env var와 이중 적용)
        self._process.start(sys.executable, ["-u", "run_pipeline.py"] + cmd_args)
        self._set_state("RUNNING")

    def stop(self):
        if self._process and self._process.state() != QProcess.NotRunning:
            self._user_stopped = True   # 사용자가 명시적으로 중지 → ERROR 아님
            self._process.terminate()
            QTimer.singleShot(3000, self._force_kill)

    def _force_kill(self):
        if self._process and self._process.state() != QProcess.NotRunning:
            self._process.kill()

    def _on_stdout(self):
        data = bytes(self._process.readAllStandardOutput()).decode("utf-8", errors="replace")
        for line in data.splitlines():
            if line.strip():
                self.stdout_line.emit(line)

    def _on_stderr(self):
        data = bytes(self._process.readAllStandardError()).decode("utf-8", errors="replace")
        for line in data.splitlines():
            if line.strip():
                self.stdout_line.emit(line)

    def _on_finished(self, exit_code: int, _exit_status):
        if exit_code == 0:
            self._set_state("DONE")
        elif self._user_stopped:
            self._user_stopped = False
            self._set_state("IDLE")   # 사용자 중지 → 오류 아님
        else:
            self._set_state("ERROR")

    def _set_state(self, state: str):
        self._state = state
        self.state_changed.emit(state)

    @property
    def state(self):
        return self._state

    @property
    def pid(self):
        if self._process and self._process.state() != QProcess.NotRunning:
            return self._process.processId()
        return None
