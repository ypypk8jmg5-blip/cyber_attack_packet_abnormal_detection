#!/usr/bin/env python3
"""
실시간 패킷 스트림 시뮬레이터 v2 — 정상 10종 + 비정상 14종
"""
import argparse, os, time
import numpy as np
import pandas as pd
from datetime import datetime

FEATURE_COLS = [
    'duration', 'protocol', 'src_port', 'dst_port', 'packet_size',
    'packets_per_sec', 'bytes_per_sec', 'unique_dst_ports',
    'connection_count', 'failed_attempts', 'outbound_ratio', 'syn_flag_ratio'
]

# ── 정상 패킷 생성 ─────────────────────────────────────────────────────────────
def make_normal(n):
    kind = np.random.choice(['web', 'dns', 'ftp', 'stream', 'email',
                             'voip', 'gaming', 'iot', 'backup', 'ssh'])
    src_ip = f"10.0.{np.random.randint(1,20)}.{np.random.randint(1,254)}"
    if kind == 'web':
        return {'duration': np.random.uniform(0.5, 30, n),
                'protocol': np.zeros(n, int), 'src_port': np.random.randint(1024, 65535, n),
                'dst_port': np.random.choice([80, 443, 8080], n),
                'packet_size': np.random.uniform(200, 1500, n),
                'packets_per_sec': np.random.uniform(1, 30, n),
                'bytes_per_sec': np.random.uniform(5000, 100000, n),
                'unique_dst_ports': np.random.randint(1, 4, n),
                'connection_count': np.random.randint(1, 15, n),
                'failed_attempts': np.random.randint(0, 2, n),
                'outbound_ratio': np.random.uniform(0.3, 0.6, n),
                'syn_flag_ratio': np.random.uniform(0.05, 0.2, n),
                'label': np.zeros(n, int), 'attack_type': ['normal_web']*n,
                'src_ip': [src_ip]*n}
    elif kind == 'dns':
        return {'duration': np.random.uniform(0.001, 0.5, n),
                'protocol': np.ones(n, int), 'src_port': np.random.randint(1024, 65535, n),
                'dst_port': np.full(n, 53),
                'packet_size': np.random.uniform(40, 200, n),
                'packets_per_sec': np.random.uniform(1, 10, n),
                'bytes_per_sec': np.random.uniform(100, 5000, n),
                'unique_dst_ports': np.ones(n, int),
                'connection_count': np.random.randint(1, 5, n),
                'failed_attempts': np.zeros(n, int),
                'outbound_ratio': np.random.uniform(0.4, 0.6, n),
                'syn_flag_ratio': np.zeros(n),
                'label': np.zeros(n, int), 'attack_type': ['normal_dns']*n,
                'src_ip': [src_ip]*n}
    elif kind == 'ftp':
        return {'duration': np.random.uniform(10, 300, n),
                'protocol': np.zeros(n, int), 'src_port': np.random.randint(1024, 65535, n),
                'dst_port': np.random.choice([21, 22, 445], n),
                'packet_size': np.random.uniform(1000, 1500, n),
                'packets_per_sec': np.random.uniform(10, 45, n),
                'bytes_per_sec': np.random.uniform(50000, 800_000, n),
                'unique_dst_ports': np.ones(n, int),
                'connection_count': np.random.randint(1, 5, n),
                'failed_attempts': np.random.randint(0, 2, n),
                'outbound_ratio': np.random.uniform(0.3, 0.65, n),
                'syn_flag_ratio': np.random.uniform(0.05, 0.15, n),
                'label': np.zeros(n, int), 'attack_type': ['normal_ftp']*n,
                'src_ip': [src_ip]*n}
    elif kind == 'stream':
        return {'duration': np.random.uniform(60, 3600, n),
                'protocol': np.zeros(n, int), 'src_port': np.random.randint(1024, 65535, n),
                'dst_port': np.random.choice([443, 1935, 8080], n),
                'packet_size': np.random.uniform(800, 1500, n),
                'packets_per_sec': np.random.uniform(5, 45, n),
                'bytes_per_sec': np.random.uniform(100000, 2_000_000, n),
                'unique_dst_ports': np.random.randint(1, 3, n),
                'connection_count': np.random.randint(1, 8, n),
                'failed_attempts': np.zeros(n, int),
                'outbound_ratio': np.random.uniform(0.05, 0.3, n),
                'syn_flag_ratio': np.random.uniform(0.1, 0.25, n),
                'label': np.zeros(n, int), 'attack_type': ['normal_stream']*n,
                'src_ip': [src_ip]*n}
    elif kind == 'email':
        return {'duration': np.random.uniform(1, 30, n),
                'protocol': np.zeros(n, int), 'src_port': np.random.randint(1024, 65535, n),
                'dst_port': np.random.choice([25, 110, 143, 465, 993], n),
                'packet_size': np.random.uniform(100, 1000, n),
                'packets_per_sec': np.random.uniform(1, 20, n),
                'bytes_per_sec': np.random.uniform(1000, 50000, n),
                'unique_dst_ports': np.random.randint(1, 3, n),
                'connection_count': np.random.randint(1, 5, n),
                'failed_attempts': np.random.randint(0, 2, n),
                'outbound_ratio': np.random.uniform(0.3, 0.7, n),
                'syn_flag_ratio': np.random.uniform(0.05, 0.2, n),
                'label': np.zeros(n, int), 'attack_type': ['normal_email']*n,
                'src_ip': [src_ip]*n}
    elif kind == 'voip':
        return {'duration': np.random.uniform(10, 3600, n),
                'protocol': np.ones(n, int), 'src_port': np.random.randint(1024, 65535, n),
                'dst_port': np.random.choice([5060, 5061, 16384, 32767], n),
                'packet_size': np.random.uniform(100, 300, n),
                'packets_per_sec': np.random.uniform(20, 60, n),
                'bytes_per_sec': np.random.uniform(10000, 100000, n),
                'unique_dst_ports': np.random.randint(1, 3, n),
                'connection_count': np.random.randint(1, 4, n),
                'failed_attempts': np.zeros(n, int),
                'outbound_ratio': np.random.uniform(0.45, 0.55, n),
                'syn_flag_ratio': np.zeros(n),
                'label': np.zeros(n, int), 'attack_type': ['normal_voip']*n,
                'src_ip': [src_ip]*n}
    elif kind == 'gaming':
        return {'duration': np.random.uniform(600, 7200, n),
                'protocol': np.ones(n, int), 'src_port': np.random.randint(1024, 65535, n),
                'dst_port': np.random.choice([3074, 3478, 27015, 25565], n),
                'packet_size': np.random.uniform(50, 500, n),
                'packets_per_sec': np.random.uniform(20, 100, n),
                'bytes_per_sec': np.random.uniform(5000, 200000, n),
                'unique_dst_ports': np.random.randint(1, 3, n),
                'connection_count': np.random.randint(1, 6, n),
                'failed_attempts': np.zeros(n, int),
                'outbound_ratio': np.random.uniform(0.4, 0.6, n),
                'syn_flag_ratio': np.zeros(n),
                'label': np.zeros(n, int), 'attack_type': ['normal_gaming']*n,
                'src_ip': [src_ip]*n}
    elif kind == 'iot':
        return {'duration': np.random.uniform(1, 60, n),
                'protocol': np.random.choice([0, 1], n),
                'src_port': np.random.randint(1024, 65535, n),
                'dst_port': np.random.choice([1883, 8883, 5683, 8080], n),
                'packet_size': np.random.uniform(20, 200, n),
                'packets_per_sec': np.random.uniform(0.1, 5, n),
                'bytes_per_sec': np.random.uniform(100, 10000, n),
                'unique_dst_ports': np.random.randint(1, 2, n),
                'connection_count': np.random.randint(1, 3, n),
                'failed_attempts': np.zeros(n, int),
                'outbound_ratio': np.random.uniform(0.5, 0.8, n),
                'syn_flag_ratio': np.random.uniform(0, 0.1, n),
                'label': np.zeros(n, int), 'attack_type': ['normal_iot']*n,
                'src_ip': [src_ip]*n}
    elif kind == 'backup':
        return {'duration': np.random.uniform(300, 7200, n),
                'protocol': np.zeros(n, int), 'src_port': np.random.randint(1024, 65535, n),
                'dst_port': np.random.choice([873, 2049, 445, 139], n),
                'packet_size': np.random.uniform(1000, 1500, n),
                'packets_per_sec': np.random.uniform(20, 80, n),
                'bytes_per_sec': np.random.uniform(500000, 5000000, n),
                'unique_dst_ports': np.random.randint(1, 3, n),
                'connection_count': np.random.randint(1, 4, n),
                'failed_attempts': np.zeros(n, int),
                'outbound_ratio': np.random.uniform(0.7, 0.95, n),
                'syn_flag_ratio': np.random.uniform(0.05, 0.15, n),
                'label': np.zeros(n, int), 'attack_type': ['normal_backup']*n,
                'src_ip': [src_ip]*n}
    else:  # ssh
        return {'duration': np.random.uniform(10, 3600, n),
                'protocol': np.zeros(n, int), 'src_port': np.random.randint(1024, 65535, n),
                'dst_port': np.full(n, 22),
                'packet_size': np.random.uniform(100, 800, n),
                'packets_per_sec': np.random.uniform(1, 30, n),
                'bytes_per_sec': np.random.uniform(1000, 500000, n),
                'unique_dst_ports': np.ones(n, int),
                'connection_count': np.random.randint(1, 4, n),
                'failed_attempts': np.random.randint(0, 3, n),
                'outbound_ratio': np.random.uniform(0.4, 0.7, n),
                'syn_flag_ratio': np.random.uniform(0.05, 0.2, n),
                'label': np.zeros(n, int), 'attack_type': ['normal_ssh']*n,
                'src_ip': [src_ip]*n}


# ── 공격 패킷 생성 ─────────────────────────────────────────────────────────────
def make_attack(atype, n):
    src_ip = f"192.168.{np.random.randint(100, 200)}.{np.random.randint(1, 254)}"
    base = {'label': np.ones(n, int), 'attack_type': [atype]*n, 'src_ip': [src_ip]*n}

    specs = {
        'ddos': {'duration': (0.1, 5), 'protocol': 0, 'dst_port': [80, 443],
                 'packet_size': (40, 100), 'packets_per_sec': (500, 5000),
                 'bytes_per_sec': (1e6, 5e7), 'unique_dst_ports': (1, 4),
                 'connection_count': (300, 2001), 'failed_attempts': (0, 20),
                 'outbound_ratio': (0.3, 0.7), 'syn_flag_ratio': (0.5, 0.9)},
        'portscan': {'duration': (0.001, 0.1), 'protocol': 0, 'dst_port': None,
                     'packet_size': (40, 80), 'packets_per_sec': (10, 100),
                     'bytes_per_sec': (1000, 50000), 'unique_dst_ports': (100, 1025),
                     'connection_count': (50, 501), 'failed_attempts': (40, 201),
                     'outbound_ratio': (0.5, 0.9), 'syn_flag_ratio': (0.6, 0.9)},
        'bruteforce': {'duration': (0.1, 1), 'protocol': 0, 'dst_port': [22, 3389, 21, 23],
                       'packet_size': (64, 200), 'packets_per_sec': (2, 20),
                       'bytes_per_sec': (500, 20000), 'unique_dst_ports': (1, 2),
                       'connection_count': (1, 6), 'failed_attempts': (50, 501),
                       'outbound_ratio': (0.4, 0.6), 'syn_flag_ratio': (0.2, 0.5)},
        'exfiltration': {'duration': (60, 600), 'protocol': 0, 'dst_port': [443, 80, 8080],
                         'packet_size': (1000, 1500), 'packets_per_sec': (10, 100),
                         'bytes_per_sec': (5e6, 1e8), 'unique_dst_ports': (1, 4),
                         'connection_count': (1, 10), 'failed_attempts': (0, 5),
                         'outbound_ratio': (0.85, 0.99), 'syn_flag_ratio': (0.05, 0.2)},
        'synflood': {'duration': (0.01, 1), 'protocol': 0, 'dst_port': [80, 443],
                     'packet_size': (40, 60), 'packets_per_sec': (1000, 10000),
                     'bytes_per_sec': (1e5, 5e6), 'unique_dst_ports': (1, 4),
                     'connection_count': (500, 5001), 'failed_attempts': (400, 4500),
                     'outbound_ratio': (0.4, 0.7), 'syn_flag_ratio': (0.85, 0.99)},
        'dns_tunneling': {'duration': (30, 600), 'protocol': 1, 'dst_port': [53],
                          'packet_size': (400, 1400), 'packets_per_sec': (5, 50),
                          'bytes_per_sec': (50000, 500000), 'unique_dst_ports': (1, 2),
                          'connection_count': (1, 10), 'failed_attempts': (0, 5),
                          'outbound_ratio': (0.6, 0.95), 'syn_flag_ratio': (0, 0.01)},
        'http_flood': {'duration': (0.5, 10), 'protocol': 0, 'dst_port': [80, 443],
                       'packet_size': (200, 800), 'packets_per_sec': (200, 2000),
                       'bytes_per_sec': (5e5, 1e7), 'unique_dst_ports': (1, 3),
                       'connection_count': (100, 1000), 'failed_attempts': (0, 10),
                       'outbound_ratio': (0.4, 0.7), 'syn_flag_ratio': (0.1, 0.4)},
        'slowloris': {'duration': (60, 900), 'protocol': 0, 'dst_port': [80, 443],
                      'packet_size': (40, 100), 'packets_per_sec': (0.01, 0.5),
                      'bytes_per_sec': (10, 500), 'unique_dst_ports': (1, 3),
                      'connection_count': (200, 2000), 'failed_attempts': (0, 5),
                      'outbound_ratio': (0.8, 0.99), 'syn_flag_ratio': (0.05, 0.15)},
        'botnet_c2': {'duration': (0.1, 2), 'protocol': 0, 'dst_port': [4444, 6667, 1080, 8443, 9001],
                      'packet_size': (64, 300), 'packets_per_sec': (0.1, 5),
                      'bytes_per_sec': (100, 10000), 'unique_dst_ports': (1, 4),
                      'connection_count': (1, 10), 'failed_attempts': (0, 3),
                      'outbound_ratio': (0.5, 0.9), 'syn_flag_ratio': (0.1, 0.3)},
        'ransomware': {'duration': (1, 60), 'protocol': 0, 'dst_port': [445, 139, 3389, 135],
                       'packet_size': (500, 1500), 'packets_per_sec': (50, 500),
                       'bytes_per_sec': (1e6, 2e7), 'unique_dst_ports': (50, 300),
                       'connection_count': (50, 500), 'failed_attempts': (10, 100),
                       'outbound_ratio': (0.3, 0.6), 'syn_flag_ratio': (0.3, 0.6)},
        'arp_spoofing': {'duration': (0.001, 0.05), 'protocol': 2, 'dst_port': [0],
                         'packet_size': (28, 60), 'packets_per_sec': (100, 1000),
                         'bytes_per_sec': (10000, 500000), 'unique_dst_ports': (5, 50),
                         'connection_count': (20, 200), 'failed_attempts': (5, 50),
                         'outbound_ratio': (0.5, 0.8), 'syn_flag_ratio': (0, 0.01)},
        'cryptomining': {'duration': (3600, 86400), 'protocol': 0,
                         'dst_port': [3333, 14444, 45700, 9999],
                         'packet_size': (200, 800), 'packets_per_sec': (1, 20),
                         'bytes_per_sec': (10000, 200000), 'unique_dst_ports': (1, 3),
                         'connection_count': (1, 5), 'failed_attempts': (0, 2),
                         'outbound_ratio': (0.7, 0.95), 'syn_flag_ratio': (0, 0.05)},
        'dns_amplification': {'duration': (1, 60), 'protocol': 1, 'dst_port': [53],
                              'packet_size': (1000, 4000), 'packets_per_sec': (100, 10000),
                              'bytes_per_sec': (5000000, 100000000), 'unique_dst_ports': (1, 2),
                              'connection_count': (100, 5000), 'failed_attempts': (0, 5),
                              'outbound_ratio': (0.05, 0.25), 'syn_flag_ratio': (0, 0.01)},
        'credential_stuffing': {'duration': (1, 30), 'protocol': 0,
                                'dst_port': [80, 443, 22, 25],
                                'packet_size': (200, 1000), 'packets_per_sec': (1, 30),
                                'bytes_per_sec': (5000, 200000), 'unique_dst_ports': (1, 5),
                                'connection_count': (50, 500), 'failed_attempts': (3, 20),
                                'outbound_ratio': (0.4, 0.7), 'syn_flag_ratio': (0.1, 0.4)},
    }

    s = specs[atype]
    row = {
        'duration': np.random.uniform(*s['duration'], n),
        'protocol': np.full(n, s['protocol'], int),
        'src_port': np.random.randint(1024, 65535, n),
        'dst_port': np.random.choice(s['dst_port'], n) if s['dst_port'] else np.random.randint(1, 65535, n),
        'packet_size': np.random.uniform(*s['packet_size'], n),
        'packets_per_sec': np.random.uniform(*s['packets_per_sec'], n),
        'bytes_per_sec': np.random.uniform(*s['bytes_per_sec'], n),
        'unique_dst_ports': np.random.randint(*s['unique_dst_ports'], n),
        'connection_count': np.random.randint(*s['connection_count'], n),
        'failed_attempts': np.random.randint(*s['failed_attempts'], n),
        'outbound_ratio': np.random.uniform(*s['outbound_ratio'], n),
        'syn_flag_ratio': np.random.uniform(*s['syn_flag_ratio'], n),
    }
    row.update(base)
    return row


ATTACK_TYPES = [
    'ddos', 'portscan', 'bruteforce', 'exfiltration', 'synflood',
    'dns_tunneling', 'http_flood', 'slowloris', 'botnet_c2', 'ransomware', 'arp_spoofing',
    'cryptomining', 'dns_amplification', 'credential_stuffing',
]


def main():
    parser = argparse.ArgumentParser(description='실시간 패킷 스트림 시뮬레이터 v2')
    parser.add_argument('--normal-ratio', type=float, default=0.85)
    parser.add_argument('--interval', type=float, default=5)
    parser.add_argument('--batch-size', type=int, default=50)
    parser.add_argument('--max-batches', type=int, default=20)
    args = parser.parse_args()

    os.makedirs('data/stream', exist_ok=True)
    print(f"[스트림시뮬레이터 v2] 시작 — {args.interval}초 간격, 배치당 {args.batch_size}건")
    print(f"  정상 10종 / 공격 14종 시뮬레이션")

    batch_count = 0
    try:
        while True:
            if args.max_batches > 0 and batch_count >= args.max_batches:
                break

            n_normal = int(args.batch_size * args.normal_ratio)
            n_attack = args.batch_size - n_normal

            dfs = [pd.DataFrame(make_normal(n_normal))]

            if n_attack > 0:
                atype = np.random.choice(ATTACK_TYPES)
                dfs.append(pd.DataFrame(make_attack(atype, n_attack)))

            df = pd.concat(dfs, ignore_index=True).sample(frac=1).reset_index(drop=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            df.to_csv(f'data/stream/incoming_{ts}.csv', index=False)

            batch_count += 1
            time.sleep(args.interval)

    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n[스트림시뮬레이터] 종료 — 총 {batch_count}개 배치 생성")


if __name__ == '__main__':
    main()
