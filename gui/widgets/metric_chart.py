"""MetricChart — F1/Recall/Precision 추이 그래프"""
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
from matplotlib.figure import Figure


class MetricChart(FigureCanvasQTAgg):
    def __init__(self, max_points: int = 50, parent=None):
        self._max_points = max_points
        fig = Figure(figsize=(6, 3), facecolor="#1a252f")
        super().__init__(fig)
        self.setParent(parent)
        self._ax = fig.add_subplot(111)
        self._cycles = []
        self._f1s = []
        self._recalls = []
        self._precisions = []
        self._init_axes()

    def _init_axes(self):
        ax = self._ax
        ax.set_facecolor("#1a252f")
        ax.tick_params(colors="white", labelsize=8)
        for spine in ax.spines.values():
            spine.set_edgecolor("#34495e")
        ax.set_xlabel("사이클", color="white", fontsize=9)
        ax.set_ylabel("점수", color="white", fontsize=9)
        ax.set_ylim(0, 1.05)
        ax.grid(True, color="#2c3e50", linestyle="--", linewidth=0.5)
        ax.axhline(0.92, color="#3498db", linestyle="--", linewidth=0.8, alpha=0.6, label="F1 목표 0.92")
        ax.axhline(0.90, color="#2ecc71", linestyle="--", linewidth=0.8, alpha=0.6, label="Recall 목표 0.90")
        ax.axhline(0.88, color="#e67e22", linestyle="--", linewidth=0.8, alpha=0.6, label="Prec 목표 0.88")
        leg = ax.legend(loc="lower right", fontsize=7, facecolor="#2c3e50", edgecolor="#34495e")
        for txt in leg.get_texts():
            txt.set_color("white")
        self._line_f1, = ax.plot([], [], color="#3498db", linewidth=2, marker="o", markersize=4, label="F1")
        self._line_rec, = ax.plot([], [], color="#2ecc71", linewidth=2, marker="s", markersize=4, label="Recall")
        self._line_pre, = ax.plot([], [], color="#e67e22", linewidth=2, marker="^", markersize=4, label="Precision")
        self.figure.tight_layout(pad=1.0)

    def add_point(self, cycle: int, f1: float, recall: float, precision: float):
        self._cycles.append(cycle)
        self._f1s.append(f1)
        self._recalls.append(recall)
        self._precisions.append(precision)
        if len(self._cycles) > self._max_points:
            self._cycles = self._cycles[-self._max_points:]
            self._f1s = self._f1s[-self._max_points:]
            self._recalls = self._recalls[-self._max_points:]
            self._precisions = self._precisions[-self._max_points:]
        self._line_f1.set_data(self._cycles, self._f1s)
        self._line_rec.set_data(self._cycles, self._recalls)
        self._line_pre.set_data(self._cycles, self._precisions)
        if self._cycles:
            self._ax.set_xlim(self._cycles[0] - 0.5, self._cycles[-1] + 0.5)
        self.draw_idle()

    def clear(self):
        self._cycles.clear()
        self._f1s.clear()
        self._recalls.clear()
        self._precisions.clear()
        self._line_f1.set_data([], [])
        self._line_rec.set_data([], [])
        self._line_pre.set_data([], [])
        self._ax.set_xlim(0, 1)
        self.draw_idle()
