"""AgentLayerWidget — 에이전트 레이어 그룹 위젯"""
from PyQt5.QtWidgets import QGroupBox, QHBoxLayout, QLabel, QSizePolicy
from PyQt5.QtCore import Qt

_STYLE = {
    "IDLE":   "background:#95a5a6; color:white; border-radius:4px; padding:3px 6px; font-size:11px;",
    "ACTIVE": "background:#2ecc71; color:white; border-radius:4px; padding:3px 6px; font-size:11px;",
    "ERROR":  "background:#e74c3c; color:white; border-radius:4px; padding:3px 6px; font-size:11px;",
}


class AgentLayerWidget(QGroupBox):
    def __init__(self, layer_name: str, agents: list, parent=None):
        super().__init__(layer_name, parent)
        self._labels: dict[str, QLabel] = {}
        self._setup_ui(agents)
        self.setStyleSheet("QGroupBox { color: #bdc3c7; border: 1px solid #34495e; margin-top: 6px; font-size: 11px; }"
                           "QGroupBox::title { subcontrol-origin: margin; left: 8px; }")

    def _setup_ui(self, agents: list):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 12, 8, 6)
        layout.setSpacing(6)
        for agent_id, display_name in agents:
            lbl = QLabel(display_name)
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet(_STYLE["IDLE"])
            lbl.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
            self._labels[agent_id] = lbl
            layout.addWidget(lbl)
        layout.addStretch()

    def set_agent_state(self, agent_id: str, state: str):
        if agent_id in self._labels:
            self._labels[agent_id].setStyleSheet(_STYLE.get(state, _STYLE["IDLE"]))

    def reset_all(self):
        for lbl in self._labels.values():
            lbl.setStyleSheet(_STYLE["IDLE"])
