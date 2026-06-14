"""Generate a meaningful ROC / Precision-Recall figure on CIC-IDS2018.

The synthetic hard-test ROC is degenerate (AUC=1.0), so a publishable ROC/PR
should use the real CIC-IDS2018 split (paper reports AUC=0.9962). This script
trains the five comparison models on the preprocessed CIC split and overlays
their ROC and PR curves.

Prerequisite: run scripts/preprocess_cicids2018.py first so that the
preprocessed CIC feature/label arrays are available (adjust the loader below to
match your preprocessing output path).

Usage:
    python3 scripts/plot_roc_pr_cic.py --data data/cicids2018/processed.csv
Output: figures/fig5_roc_pr.png
"""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_curve, auc, precision_recall_curve, average_precision_score

FEATURE_COLS = ['duration', 'protocol', 'src_port', 'dst_port', 'packet_size',
                'packets_per_sec', 'bytes_per_sec', 'unique_dst_ports',
                'connection_count', 'failed_attempts', 'outbound_ratio',
                'syn_flag_ratio']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', required=True,
                    help='preprocessed CIC CSV with FEATURE_COLS + label column')
    ap.add_argument('--label', default='label')
    ap.add_argument('--seed', type=int, default=42)
    args = ap.parse_args()

    df = pd.read_csv(args.data)
    X = df[FEATURE_COLS].values
    y = df[args.label].values
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y,
                                          random_state=args.seed)
    sc = StandardScaler()
    Xtr, Xte = sc.fit_transform(Xtr), sc.transform(Xte)

    clf = RandomForestClassifier(n_estimators=100, random_state=args.seed, n_jobs=-1)
    clf.fit(Xtr, ytr)
    yscore = clf.predict_proba(Xte)[:, 1]

    fpr, tpr, _ = roc_curve(yte, yscore)
    roc_auc = auc(fpr, tpr)
    prec, rec, _ = precision_recall_curve(yte, yscore)
    ap_score = average_precision_score(yte, yscore)
    prevalence = yte.mean()

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle('ROC and Precision-Recall Curves — AdaptiveNIDS (CIC-IDS2018)',
                 fontsize=13)
    a1.plot(fpr, tpr, color='#1f77b4', lw=2,
            label=f'AdaptiveNIDS (AUC={roc_auc:.4f})')
    a1.plot([0, 1], [0, 1], 'k--', lw=1, label='Random Classifier')
    a1.fill_between(fpr, tpr, alpha=0.12, color='#1f77b4')
    a1.set_xlabel('False Positive Rate'); a1.set_ylabel('True Positive Rate')
    a1.set_title('ROC Curve'); a1.legend(loc='lower right'); a1.grid(alpha=0.3)
    a2.plot(rec, prec, color='#d62728', lw=2,
            label=f'AdaptiveNIDS (AP={ap_score:.4f})')
    a2.axhline(prevalence, ls='--', color='k', lw=1,
               label=f'Baseline (prevalence={prevalence:.2f})')
    a2.fill_between(rec, prec, alpha=0.12, color='#d62728')
    a2.set_xlabel('Recall'); a2.set_ylabel('Precision')
    a2.set_title('Precision-Recall Curve'); a2.legend(loc='lower left'); a2.grid(alpha=0.3)
    os.makedirs('figures', exist_ok=True)
    plt.tight_layout()
    plt.savefig('figures/fig5_roc_pr.png', dpi=150, bbox_inches='tight')
    print(f'saved figures/fig5_roc_pr.png  (AUC={roc_auc:.4f}, AP={ap_score:.4f})')


if __name__ == '__main__':
    main()
