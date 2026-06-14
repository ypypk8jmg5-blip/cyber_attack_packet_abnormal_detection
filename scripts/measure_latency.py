"""Reproduce Table II: inference-only latency (preprocessing + RF prediction).

Measures wall-clock latency of feature-scaling + RandomForest.predict over
20 repeated runs per batch size, mirroring the paper's protocol. Alert
generation is intentionally excluded (inference-only).

Usage:
    python3 scripts/measure_latency.py
    python3 scripts/measure_latency.py --runs 20 --batches 100 1000 10000

Output: prints the latency table and writes data/benchmark/latency_<ts>.json
"""
import sys, os, json, time, argparse
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
from sklearn.preprocessing import StandardScaler
from ablation_study import (FEATURE_COLS, generate_base, build_dataset, train_rf)

FULL = dict(borderline_frac=0.20, heavy_normal_frac=0.12, noise_frac_attack=0.10,
            noise_frac_normal=0.08, attack_weights=True, smote_type='none')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--runs', type=int, default=20, help='timed repetitions per batch')
    ap.add_argument('--batches', type=int, nargs='+', default=[100, 1000, 10000])
    ap.add_argument('--seed', type=int, default=42)
    args = ap.parse_args()

    # Train the deployed RF detector (Full/BAT) on a seeded training set
    nrm, atk = generate_base(10000, args.seed)
    tr = build_dataset(nrm, atk, **FULL)
    scaler = StandardScaler()
    X_tr = scaler.fit_transform(tr[FEATURE_COLS].values)
    clf = train_rf(X_tr, tr['label'].values)

    rng = np.random.default_rng(args.seed)
    rows = []
    print(f"{'Batch':>7} {'Avg(ms)':>9} {'P95(ms)':>9} {'Throughput(flows/s)':>20}")
    print('-' * 50)
    for n in args.batches:
        # synthesize a representative batch of n flows
        base = tr[FEATURE_COLS].values
        idx = rng.integers(0, len(base), size=n)
        X_raw = base[idx]
        times = []
        # warmup
        for _ in range(3):
            clf.predict(scaler.transform(X_raw))
        for _ in range(args.runs):
            t0 = time.perf_counter()
            Xs = scaler.transform(X_raw)
            clf.predict(Xs)
            times.append((time.perf_counter() - t0) * 1000.0)  # ms
        times = np.array(times)
        avg = times.mean()
        p95 = np.percentile(times, 95)
        thr = n / (avg / 1000.0)
        rows.append(dict(batch=n, avg_ms=round(avg, 1), p95_ms=round(p95, 1),
                         throughput=int(thr)))
        print(f"{n:>7} {avg:>9.1f} {p95:>9.1f} {thr:>20,.0f}")

    out = dict(timestamp=datetime.now().strftime('%Y%m%d_%H%M%S'),
               runs=args.runs, seed=args.seed, rows=rows)
    os.makedirs('data/benchmark', exist_ok=True)
    path = f"data/benchmark/latency_{out['timestamp']}.json"
    json.dump(out, open(path, 'w'), indent=2)
    print(f"\n[done] {path}")


if __name__ == '__main__':
    main()
