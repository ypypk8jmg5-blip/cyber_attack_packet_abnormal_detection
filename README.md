# AdaptiveNIDS

**An MLOps-driven Network Intrusion Detection System with Borderline-Aware Training (BAT) and multi-agent orchestration.**

AdaptiveNIDS treats a network intrusion detector not as a one-shot offline artifact
but as an *operational* component: it continuously monitors detection quality,
hardens its decision boundary against evasive (borderline) traffic, and triggers
controlled retraining when per-class recall or F1 degrades. The system is evaluated
on synthetic traffic and on the public **CIC-IDS2018** benchmark.

> Research prototype accompanying the *AdaptiveNIDS* paper. The LaTeX sources and the
> raw datasets are not included in this repository (see [Data](#data) and
> [Notes](#notes)).

---

## Key ideas

- **Borderline-Aware Training (BAT).** Attack samples are interpolated toward the
  benign-traffic centroid, `x_b = (1−α)·x_i + α·μ_n + ε`, so the classifier is
  trained directly on the attack/normal boundary where evasive variants live.
- **Quality-gate feedback loop.** Training repeats (up to `MAX_CYCLES = 20`) until the
  configurable gates are met (default **F1 ≥ 0.92, recall ≥ 0.90, precision ≥ 0.88**);
  in deployment, recall degradation triggers retraining.
- **Multi-agent orchestration.** A 32-agent, 7-layer pipeline decouples ingestion,
  preprocessing, inference, decision, orchestration, output, learning, and evaluation.
- **Reproducible evaluation.** Ablation, multi-seed cross-validation with significance
  tests, BAT hyperparameter sensitivity, model-agnostic augmentation, continual-vs-
  retraining comparison, and capture-day holdout + retraining-recovery experiments.

## Architecture

Two operating modes share the same building blocks:

- **Sequential pipeline** (`run_pipeline.py`) — Phase 1 adaptive training loop →
  Phase 2 near-real-time batch detection.
- **Multi-agent pipeline** (`run_pipeline.py --multi-agent`) — the same workflow
  realized as independent agents communicating via event-driven queues.

| Layer | Function | Agents |
|------:|----------|:------:|
| L0 | Adaptive generation (optional, `--ai-gen`) | 1 |
| L1 | Sensor / ingestion | 4 |
| L2 | Analysis / detection (RF, LSTM, rule, behavioral, statistical, temporal, protocol, flow) | 8 |
| L3 | Decision (evidence aggregation, conflict resolution, confidence, threshold) | 4 |
| L4 | Orchestration (pipeline/sub orchestrator, load balancer, scheduler) | 4 |
| L5 | Output (severity, alert generation, dedup, context enrichment) | 4 |
| L6 | Learning (feedback, model update, drift detection, performance monitor) | 4 |
| L7 | Evaluation (metrics, FP analysis, attack coverage, reporting) | 4 |

The **Random Forest** detector is the primary classifier used for all reported metrics.

## Threat & attack coverage

- **12-dimensional flow feature vector:** `duration, protocol, src_port, dst_port,
  packet_size, packets_per_sec, bytes_per_sec, unique_dst_ports, connection_count,
  failed_attempts, outbound_ratio, syn_flag_ratio`.
- **14 attack categories:** DDoS, SYN flood, port scan, brute force, data exfiltration,
  DNS tunneling, HTTP flood, Slowloris, botnet C&C, ransomware, ARP spoofing,
  cryptomining, DNS amplification, credential stuffing.
- **10 benign service types:** DNS, HTTP, HTTPS, FTP, SMTP, SSH, NTP, VoIP, streaming
  media, database.

## Repository layout

```
agents/        32-agent, 7-layer orchestration (layer0_generation … layer7_evaluation)
scripts/       traffic generation, training, evaluation, detection, and experiments
gui/           PyQt5 real-time dashboard (panels, tabs, widgets)
tests/         pytest suite
tools/         helper utilities
run_pipeline.py   main MLOps pipeline entry point
run_gui.py        dashboard entry point
```
> `data/`, `logs/`, `paper/`, the virtualenv, and binary artifacts are intentionally
> excluded from version control (see `.gitignore`).

## Installation

Requires **Python 3.11+** (developed on 3.14).

```bash
git clone https://github.com/ypypk8jmg5-blip/cyber_attack_packet_abnormal_detection.git
cd cyber_attack_packet_abnormal_detection

python3 -m venv .venv && source .venv/bin/activate
pip install scikit-learn pandas numpy scipy matplotlib joblib \
            xgboost lightgbm torch PyQt5
```

| Purpose | Packages |
|---------|----------|
| Core ML / data | `scikit-learn`, `pandas`, `numpy`, `scipy`, `joblib` |
| Baselines | `xgboost`, `lightgbm` |
| Deep detector (LSTM autoencoder) | `torch` |
| GUI / plots | `PyQt5`, `matplotlib` |

## Usage

### Run the pipeline

```bash
# Sequential mode (Phase 1 training + Phase 2 detection, 5 batches by default)
python3 run_pipeline.py

# Multi-agent mode (32 agents, 7 layers)
python3 run_pipeline.py --multi-agent --max-batches 5

# AI-adaptive generation (Agent-00 uses previous-cycle recall feedback)
python3 run_pipeline.py --ai-gen
```

Outputs are written to `logs/dashboard.json`, `data/metrics/latest.json`, and
`data/alerts/summary.json`.

### Real-time dashboard

```bash
python3 run_gui.py            # operations view
python3 run_gui.py --present  # presentation stage view (fullscreen)
```
A PyQt5 dashboard shows Phase-1 training metrics, Phase-2 detection/alerts, the
32-agent status grid, and a live log. It launches and monitors `run_pipeline.py`.
`--present` (or `F5` at runtime) switches to a fullscreen stage view for demos:
an enlarged 32-agent grid with activity flash/decay animations, key-event banners
(launch / detection / retraining), and three large headline stats. `Esc` exits.

### Individual stages

```bash
python3 scripts/generate_packets.py      # synthetic flow records
python3 scripts/train_model.py           # train Random Forest (5-fold CV selection)
python3 scripts/evaluate_model.py        # per-attack recall + quality gates
python3 scripts/simulate_stream.py       # stream batches to a watched directory
python3 scripts/detect_anomaly.py        # batch detection + alerting
```

### Experiments (paper)

```bash
python3 scripts/ablation_study.py          # 6-condition ablation (BAT vs SMOTE family)
python3 scripts/ablation_significance.py   # multi-seed paired significance of BAT
python3 scripts/bat_sensitivity.py         # r_b × σ grid + α-range sweep
python3 scripts/statistical_benchmark.py   # repeated stratified CV + paired t/Wilcoxon
python3 scripts/component_ablation.py      # model-agnostic augmentation + signature
python3 scripts/continual_comparison.py    # continual learning vs periodic retraining
python3 scripts/capture_day_retrain.py     # capture-day holdout degradation + recovery
python3 scripts/benchmark_cicids2018.py    # 5-model comparison on CIC-IDS2018
```

### Tests

```bash
pytest tests/ -v
```

## Data

The **CIC-IDS2018** dataset is **not** redistributed here. Download it (e.g., the
Kaggle release) into `data/cicids2018/raw/`, then preprocess:

```bash
python3 scripts/preprocess_cicids2018.py
```
Synthetic traffic, by contrast, is generated on the fly by
`scripts/generate_packets.py` (rule- and statistics-based) and requires no download.

## Notes

- All reported quantitative results use the **Random Forest** detector in isolation;
  auxiliary detectors in the analysis layer are part of the deployment architecture
  and are scoped accordingly.
- This is a research prototype. The retraining trigger is an operator-configurable
  workflow event, not unconditional autonomous model replacement.

## License

No license has been specified yet. All rights reserved by the authors unless a license
file is added.
