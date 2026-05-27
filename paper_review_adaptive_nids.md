# AdaptiveNIDS Paper Review Notes

Reviewed file: `/Users/yunsangbeom/Library/Mobile Documents/com~apple~CloudDocs/WORKS/AdaptiveNIDS/adapativeiids_overleaf.pdf`

Review date: 2026-05-04

## Overall Assessment

The manuscript has a promising direction. The strongest positioning is not as a pure model-performance paper, but as an **operational adaptive NIDS framework** combining:

- Borderline-Aware Training (BAT)
- Synthetic-to-real domain-gap analysis
- MLOps-driven retraining and deployment loop
- Multi-agent orchestration for detection, monitoring, and alerting

The current draft is already structured like a paper, but several claims are stronger than the supporting evidence. Tightening those claims and adding a few targeted experiments would make the paper much more defensible.

## Strongest Contributions

### 1. Borderline-Aware Training (BAT)

This is currently the strongest contribution.

The ablation result is persuasive:

| Setting | F1 | Recall | Precision | FPR |
|---|---:|---:|---:|---:|
| Baseline | 0.9475 | 0.9929 | 0.9061 | 5.54% |
| Full BAT + Noise | 0.9993 | 0.9986 | 1.0000 | 0.00% |

Recommendation:

- Put BAT more clearly at the center of the paper.
- Always qualify the 0.00% FPR claim as applying to the **hard synthetic test set**, not all operational traffic.

### 2. Synthetic-to-Real Domain Gap

The transfer-learning experiment is valuable:

- Synthetic-only model on CIC-IDS2018: F1 = 0.2962
- After adaptation/retraining: F1 = 0.9938

This is a strong justification for the adaptive retraining loop.

Recommendation:

- Present this as evidence that synthetic coverage alone is insufficient.
- Emphasize that adaptive retraining is a functional necessity, not only a performance optimization.

### 3. MLOps-Driven NIDS Pipeline

The pipeline contribution is meaningful because it connects:

- data generation
- training
- evaluation
- model promotion
- simulated real-time detection
- alert generation
- retraining trigger logic

Recommendation:

- Frame this as an **operational prototype contribution**.
- Avoid implying that the orchestration itself has been fully proven to improve detection accuracy unless a dedicated ablation is added.

## Claims That Need Tightening

### 1. Normal and Attack Category Count

The manuscript states:

> synthetic traffic generation covering 10 normal and 14 attack categories

But the current implementation discussed earlier primarily used 5 normal classes, while the latest fixed generator uses 14 attack classes.

Action:

- Either update the generator and documentation to truly support 10 normal classes, or revise the paper to say **five benign traffic classes**.
- Make the dataset description, abstract, tables, and implementation consistent.

### 2. "Broadest Coverage Reported in the Literature"

The manuscript claims:

> the broadest coverage reported in the literature

This is risky. Reviewers may challenge it immediately.

Safer wording:

> broader than several commonly used benchmark settings

or:

> a broader synthetic taxonomy than the public benchmark used in our evaluation

### 3. Multi-Agent Contribution Is Not Yet Isolated

The manuscript emphasizes a 32-agent, 7-layer architecture, but the experiments mostly validate RF, BAT, and retraining.

Missing evidence:

- RF-only vs RF + rule signature
- RF + BAT vs RF + BAT + multi-agent fusion
- orchestration off vs orchestration on
- retraining trigger latency
- alert consistency
- batch latency

Recommendation:

- Treat multi-agent orchestration as a system architecture contribution unless additional experiments are added.

### 4. Real-Time Performance Claim Needs Support

The manuscript states that latency is under 2 seconds per batch at 1,000 flows/batch.

Needed table:

| Batch Size | Avg Latency | P95 Latency | Throughput | CPU | Memory |
|---:|---:|---:|---:|---:|---:|
| 100 | TBD | TBD | TBD | TBD | TBD |
| 1,000 | TBD | TBD | TBD | TBD | TBD |
| 10,000 | TBD | TBD | TBD | TBD | TBD |

Recommendation:

- Add repeated measurements.
- Report machine specs and whether alert generation is included in latency.

### 5. CIC-IDS2018 Feature Mapping Limitation

The Kaggle version of CIC-IDS2018 lacks source IP addresses. The paper maps:

- `unique_dst_ports = 1`
- `connection_count = Tot Fwd Pkts + Tot Bwd Pkts`

This approximation is important and may affect:

- portscan detection
- lateral movement behavior
- botnet behavior
- distributed attack analysis

Recommendation:

- Move this limitation into the method discussion, not only the limitation section.
- Explain how it may bias results.
- If possible, repeat experiments with a CIC-IDS2018 source that preserves IP-level fields.

## Recommended Additional Experiments

### 1. BAT Sensitivity Analysis

Vary the borderline ratio and noise scale.

Suggested grid:

```text
rb = 0.00, 0.05, 0.10, 0.20, 0.30
sigma = 0.00, 0.01, 0.05, 0.10
```

Report:

- F1
- Recall
- Precision
- FPR
- per-attack recall

Purpose:

- Justify why `rb = 0.20` and `sigma = 0.05` were selected.

### 2. Adaptive Loop Learning Curve

Add a cycle-by-cycle curve:

| Cycle | F1 | Recall | Precision | Worst Attack | Worst-Attack Recall |
|---:|---:|---:|---:|---|---:|
| 0 | TBD | TBD | TBD | TBD | TBD |
| 1 | TBD | TBD | TBD | TBD | TBD |
| 2 | TBD | TBD | TBD | TBD | TBD |

Purpose:

- Show that the MLOps loop improves weak attack classes over time.

### 3. Multi-Agent Ablation

Suggested conditions:

| Condition | Description |
|---|---|
| RF only | Primary RandomForest classifier |
| RF + signature | Adds deterministic C2/rule overrides |
| RF + BAT | Trained with BAT |
| RF + BAT + multi-agent fusion | Full detection stack |
| RF + BAT + multi-agent + retraining trigger | Full operational loop |

Purpose:

- Quantify the unique value of the multi-agent design.

### 4. Confusion Matrix and Error Analysis

Add per-attack confusion matrices or top confusion pairs.

Focus especially on:

- exfiltration
- botnet C&C
- HTTP flood
- cryptomining

Purpose:

- Improve analytical depth beyond headline metrics.

### 5. Operational Metrics

Add operational evaluation:

- alert count consistency
- false alerts per 1,000 benign flows
- batch processing latency
- model reload time
- retraining trigger time
- queue depth if a queue-based pipeline is added

## Writing and Citation Issues

### Citation Placeholder

The text contains:

```text
KDD Cup 1999 dataset [?]
```

Action:

- Replace `[?]` with a proper citation.

### Duplicate / Inconsistent IDSGAN References

IDSGAN appears in both [11] and [15] with different metadata.

Action:

- Verify the correct venue/year.
- Remove duplication or clarify if one is an arXiv version and the other is a conference version.

### Strong Phrases to Soften

Current phrase:

> eliminates false positives entirely

Safer:

> eliminates false positives on the hard synthetic test set

Current phrase:

> absent from all compared baselines

Safer:

> not provided by the standalone classifier baselines considered in this study

Current phrase:

> continuously self-updates without operator intervention

Safer:

> supports automated retraining triggers under configurable quality gates

## Suggested Contribution Paragraph

The current contribution paragraph can be tightened as follows:

```text
This paper makes three contributions. First, we propose Borderline-Aware Training, a simple but effective hardening strategy that augments synthetic flow-level training data with attack variants near the benign manifold. Second, we design a feedback-driven MLOps loop that uses per-class recall degradation as a trigger for adaptive data generation and retraining. Third, we implement AdaptiveNIDS, a prototype multi-agent orchestration pipeline that connects generation, training, evaluation, live detection, and alerting, and evaluate it through ablation, synthetic-to-real transfer, and CIC-IDS2018 benchmark experiments.
```

## Recommended Paper Positioning

Best positioning:

> AdaptiveNIDS is an operational adaptive NIDS framework that combines BAT, synthetic-to-real adaptation, and MLOps-based retraining.

Avoid positioning it as:

> The best-performing classifier on CIC-IDS2018.

Reason:

- XGBoost slightly outperforms AdaptiveNIDS in F1.
- The stronger novelty is operational adaptivity, not raw benchmark superiority.

## Priority Checklist

### High Priority

- [ ] Fix 10 normal vs 5 normal inconsistency.
- [ ] Replace risky "broadest coverage" claim.
- [ ] Add or soften claims about 32-agent orchestration.
- [ ] Add latency/throughput evidence for real-time claims.
- [ ] Fix `[?]` citation.
- [ ] Clarify CIC-IDS2018 feature-mapping limitations.

### Medium Priority

- [ ] Add BAT sensitivity analysis.
- [ ] Add adaptive loop cycle curve.
- [ ] Add multi-agent ablation.
- [ ] Add per-attack confusion/error analysis.
- [ ] Clean up duplicate IDSGAN references.

### Low Priority

- [ ] Improve figure captions with more implementation details.
- [ ] Add architecture pseudocode for BAT and retraining trigger.
- [ ] Add a short threat-to-MITRE mapping table.

## Final Judgment

The manuscript is promising and has a coherent research direction. The best contribution story is:

```text
BAT improves robustness against borderline variants.
Synthetic-to-real transfer exposes a serious domain gap.
Adaptive MLOps retraining closes that gap.
Multi-agent orchestration provides an operational path from model training to live detection.
```

With claim tightening and a few targeted experiments, this can become a much stronger and more defensible NIDS/MLOps paper.
