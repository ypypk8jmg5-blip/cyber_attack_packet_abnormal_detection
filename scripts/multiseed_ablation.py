"""6-condition ablation × multi-seed, deterministic (seed-fix patch applied).
Outputs JSON with per-seed overall metrics and per-attack recall."""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
from sklearn.preprocessing import StandardScaler
from ablation_study import (FEATURE_COLS, HARD_ATTACKS, generate_base, build_dataset,
                            generate_hard_testset, train_rf, eval_metrics, per_attack_recall)

SEEDS = [42, 43, 44, 45, 46]
N_TRAIN = 10000
CONDS = [
 ('1_Baseline',   dict(borderline_frac=0.0,  heavy_normal_frac=0.0,  noise_frac_attack=0.0,  noise_frac_normal=0.0,  attack_weights=False, smote_type='none')),
 ('2_Noise',      dict(borderline_frac=0.0,  heavy_normal_frac=0.0,  noise_frac_attack=0.10, noise_frac_normal=0.08, attack_weights=False, smote_type='none')),
 ('3_Borderline', dict(borderline_frac=0.20, heavy_normal_frac=0.0,  noise_frac_attack=0.10, noise_frac_normal=0.08, attack_weights=False, smote_type='none')),
 ('4_FullBAT',    dict(borderline_frac=0.20, heavy_normal_frac=0.12, noise_frac_attack=0.10, noise_frac_normal=0.08, attack_weights=True,  smote_type='none')),
 ('5_FullSMOTE',  dict(borderline_frac=0.0,  heavy_normal_frac=0.12, noise_frac_attack=0.10, noise_frac_normal=0.08, attack_weights=True,  smote_type='smote')),
 ('6_FullBLSMOTE',dict(borderline_frac=0.0,  heavy_normal_frac=0.12, noise_frac_attack=0.10, noise_frac_normal=0.08, attack_weights=True,  smote_type='borderline_smote')),
]

test_df = generate_hard_testset(n=2000, seed=99)
X_te_raw = test_df[FEATURE_COLS].values
y_te = test_df['label'].values
at_te = test_df['attack_type'].values

out = {c[0]: [] for c in CONDS}
for seed in SEEDS:
    for cname, kw in CONDS:
        t0 = time.time()
        nrm, atk = generate_base(N_TRAIN, seed)   # re-seeds global RNG -> matched per condition
        tr = build_dataset(nrm, atk, **kw)
        sc = StandardScaler()
        X_tr = sc.fit_transform(tr[FEATURE_COLS].values)
        clf = train_rf(X_tr, tr['label'].values)
        y_pred = clf.predict(sc.transform(X_te_raw))
        m = eval_metrics(y_te, y_pred)
        m['per_attack'] = per_attack_recall(y_te, y_pred, at_te)
        m['seed'] = seed
        out[cname].append(m)
        print(f"seed {seed} {cname}: F1={m['f1']} FPR={m['fpr']} crypto={m['per_attack'].get('cryptomining')} ({time.time()-t0:.1f}s)", flush=True)

json.dump(out, open('/tmp/multiseed_results.json', 'w'), indent=1)
print("DONE")
