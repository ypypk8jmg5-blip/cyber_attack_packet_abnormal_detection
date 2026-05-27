"""AlertBarChart — 공격 유형별 경보 가로 막대 그래프"""
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
from matplotlib.figure import Figure

ATTACK_LABELS_KO = {
    'ddos':                'DDoS',
    'portscan':            '포트스캔',
    'bruteforce':          '브루트포스',
    'exfiltration':        '데이터유출',
    'synflood':            'SYN플러드',
    'dns_tunneling':       'DNS터널링',
    'http_flood':          'HTTP플러드',
    'slowloris':           'Slowloris',
    'botnet_c2':           '봇넷C2',
    'ransomware':          '랜섬웨어',
    'arp_spoofing':        'ARP스푸핑',
    'cryptomining':        '크립토마이닝',
    'dns_amplification':   'DNS증폭',
    'credential_stuffing': '크리덴셜스터핑',
    'unknown':             '미분류',
}

SEVERITY_COLORS = {
    'CRITICAL': '#e74c3c',
    'HIGH':     '#e67e22',
    'MEDIUM':   '#f39c12',
    'LOW':      '#3498db',
    'unknown':  '#95a5a6',
}

ATTACK_SEVERITY = {
    'ddos':                'CRITICAL',
    'synflood':            'CRITICAL',
    'ransomware':          'CRITICAL',
    'http_flood':          'CRITICAL',
    'dns_amplification':   'CRITICAL',
    'portscan':            'HIGH',
    'arp_spoofing':        'HIGH',
    'dns_tunneling':       'HIGH',
    'cryptomining':        'HIGH',
    'bruteforce':          'MEDIUM',
    'exfiltration':        'MEDIUM',
    'botnet_c2':           'MEDIUM',
    'credential_stuffing': 'MEDIUM',
    'slowloris':           'LOW',
}


class AlertBarChart(FigureCanvasQTAgg):
    def __init__(self, parent=None):
        fig = Figure(figsize=(6, 4), facecolor="#1a252f")
        super().__init__(fig)
        self.setParent(parent)
        self._ax = fig.add_subplot(111)
        self._init_axes()

    def _init_axes(self):
        ax = self._ax
        ax.set_facecolor("#1a252f")
        ax.tick_params(colors="white", labelsize=8)
        for spine in ax.spines.values():
            spine.set_edgecolor("#34495e")
        ax.set_xlabel("경보 건수", color="white", fontsize=9)
        ax.set_title("공격 유형별 경보 분포 (14종)", color="white", fontsize=10)
        ax.text(0.5, 0.5, "데이터 대기 중...", ha="center", va="center",
                transform=ax.transAxes, color="#95a5a6", fontsize=12)
        self.figure.subplots_adjust(left=0.22, right=0.97, top=0.92, bottom=0.10)

    def update_data(self, by_attack_type: dict):
        if not by_attack_type:
            return
        ax = self._ax
        ax.clear()
        ax.set_facecolor("#1a252f")
        ax.tick_params(colors="white", labelsize=8)
        for spine in ax.spines.values():
            spine.set_edgecolor("#34495e")

        sorted_items = sorted(by_attack_type.items(), key=lambda x: x[1])
        raw_keys = [item[0] for item in sorted_items]
        values   = [item[1] for item in sorted_items]
        labels   = [ATTACK_LABELS_KO.get(k, k) for k in raw_keys]
        colors   = [SEVERITY_COLORS.get(ATTACK_SEVERITY.get(k, 'unknown'), '#95a5a6')
                    for k in raw_keys]

        bars = ax.barh(labels, values, color=colors, height=0.6)

        max_val = max(values) if values else 1
        for bar, val in zip(bars, values):
            ax.text(bar.get_width() + max_val * 0.01,
                    bar.get_y() + bar.get_height() / 2,
                    str(val), va="center", ha="left", color="white", fontsize=8)

        ax.set_xlabel("경보 건수", color="white", fontsize=9)
        n_types = len([k for k in by_attack_type if k != 'unknown'])
        ax.set_title(f"공격 유형별 경보 분포 ({n_types}종 탐지 중)", color="white", fontsize=10)
        ax.set_xlim(0, max_val * 1.18)
        self.figure.subplots_adjust(left=0.22, right=0.97, top=0.92, bottom=0.10)
        self.draw_idle()
