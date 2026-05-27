# AdaptiveNIDS Paper Review Notes - A1 Version

Reviewed file: `/Users/yunsangbeom/Library/Mobile Documents/com~apple~CloudDocs/WORKS/AdaptiveNIDS/adapativeiids_overleaf_a1.pdf`

Review date: 2026-05-04

## Overall Assessment

The A1 version is stronger than the previous draft. Several earlier issues were improved:

- The `[?]` citation placeholder for KDD Cup 1999 was fixed.
- The contribution paragraph is clearer and better focused.
- The "broadest coverage" claim was softened to a safer statement.
- The abstract now better qualifies the system as supporting automated self-improvement under configurable quality gates.
- The CIC-IDS2018 feature-mapping limitation is discussed more transparently.
- Latency results and figures were added.

However, the current PDF has **serious layout problems** that should be fixed before submission. In addition, a few claims still need stronger experimental support or safer wording.

## Highest-Priority Issues

### 1. PDF Layout Problems

This is the most urgent issue. Several tables/figures overflow or overlap in the IEEE two-column layout.

#### Page 3: Table II is clipped

Table II, "12-Dimensional Feature Vector", exceeds the right column width. The rightmost "CIC-IDS2018 Source" column is visibly clipped at the page edge.

Observed problem:

- Column content such as `Tot Fwd / (Fwd+Bw...` and `SYN Flag / (Fwd+B...` is cut off.
- The table is too wide for a single column.

Recommended fixes:

- Make Table II span both columns using `table*`.
- Reduce font size only if needed after spanning.
- Use shorter column labels:
  - `Feature`
  - `Description`
  - `CIC Source`
- Wrap long CICFlowMeter source expressions manually.

#### Page 4: Table III is clipped

Table III, "Inference Latency", has the `Memory` column clipped on the right.

Observed problem:

- The memory values appear as `195 M...`, `196 M...`, `202 M...`, with the right side cut.

Recommended fixes:

- Shorten `Throughput (flows/s)` to `Throughput`.
- Shorten `Batch Size` to `Batch`.
- Use `\resizebox{\columnwidth}{!}{...}` or convert to `table*`.
- Alternatively remove the `Memory` column and mention memory in text.

#### Page 5: Table VI overlaps the right column text

Table VI, "Model Comparison on CIC-IDS2018", crosses into the right column and overlaps the Discussion section text.

Observed problem:

- The FPR column overlaps with text beginning "traffic. AdaptiveNIDS treats..."
- This is a submission-blocking layout defect.

Recommended fixes:

- Convert Table VI to `table*` across both columns.
- Move it to the top of the next page if necessary.
- Reduce column labels:
  - `Precision` -> `Prec.`
  - `Recall` -> `Rec.`
  - `AdaptiveNIDS (RF)` -> `AdaptiveNIDS`

#### Page 4: Figure/Table density is high

Page 4 contains Table III, Table IV, Fig. 2, Fig. 3, and the start of the Experiments text. It is visually dense.

Recommended fixes:

- Move Fig. 3 to the next page or make Fig. 2/3 smaller and place them sequentially.
- Consider removing either Fig. 2 or Table IV if page budget is tight, since both show related ablation information.

## Content Improvements Since Previous Version

### Improved Contribution Paragraph

The new contribution paragraph is better:

- BAT is clearly defined.
- The feedback-driven loop is framed around per-class recall degradation.
- The prototype contribution is described as a multi-agent orchestration pipeline rather than overclaiming raw model superiority.

This is a good direction.

### Improved Claim Safety

The phrase:

> broader than the public benchmarks used in our evaluation

is much safer than claiming "broadest coverage reported in the literature."

Keep this wording.

### Improved Limitations

The paper now clearly acknowledges that the Kaggle CIC-IDS2018 version lacks source IP addresses and that `unique_dst_ports` and `connection_count` are approximated.

This is important and should remain.

## Remaining Content Concerns

### 1. "10 Normal Service Types" Still Needs Verification

The manuscript repeatedly states that the synthetic generator produces:

> 10 normal service types

Listed as:

```text
DNS, HTTP, HTTPS, FTP, SMTP, SSH, NTP, VoIP, streaming media, database
```

This must match the implementation and experiment artifacts.

Action:

- If the code now truly generates these 10 normal classes, add a small table listing the normal classes and their main feature ranges.
- If the implementation still mainly supports 5 normal classes, revise the paper to avoid the 10-class claim.

Why it matters:

- A reviewer may compare the code release with the manuscript.
- Inconsistency between paper and code weakens credibility.

### 2. "32-Agent" Contribution Still Needs an Ablation

The paper explains the 32-agent architecture, but the experiments still do not isolate its contribution.

Current evidence mainly supports:

- RandomForest performance
- BAT effectiveness
- Synthetic-to-real retraining
- Latency of inference

It does not yet prove that the multi-agent architecture improves:

- detection quality
- operational stability
- retraining speed
- alert quality
- scalability

Recommended additional ablation:

| Condition | Purpose |
|---|---|
| RF only | Baseline detector |
| RF + C2/rule override | Rule contribution |
| RF + BAT | Training contribution |
| RF + BAT + multi-agent orchestration | Orchestration contribution |
| Full system with retraining trigger | End-to-end operational contribution |

If this experiment cannot be added, position the multi-agent pipeline as a **software architecture contribution**, not a proven detection-performance contribution.

### 3. Latency Claim Needs Consistency

Table III reports:

- 1,000 flows: 17.5 ms average
- preprocessing + model prediction
- alert generation not included

But Section VI-C says:

> end-to-end latency from packet capture to alert generation is under 2 s per batch at 1,000 flows/batch

These are different measurements.

Action:

- Make the distinction explicit:
  - Table III: inference-only latency
  - Discussion: end-to-end pipeline latency
- Add an end-to-end latency table if claiming packet capture to alert generation.

Suggested wording:

```text
Table III measures preprocessing and model prediction only. In a separate simulated pipeline measurement, end-to-end latency from batch availability to alert record generation remained below 2 s for 1,000-flow batches.
```

Even better:

| Stage | Avg Latency | P95 Latency |
|---|---:|---:|
| Feature preprocessing | TBD | TBD |
| Model inference | TBD | TBD |
| Agent fusion | TBD | TBD |
| Alert generation | TBD | TBD |
| End-to-end | TBD | TBD |

### 4. Parameter Selection Is Still Not Fully Supported

The paper now adds a "Parameter selection" paragraph for `rb = 0.20` and `sigma = 0.05`.

This is helpful, but it says:

> A full sensitivity grid is left to future work.

That is acceptable, but the current wording still implies empirical tuning beyond the four-condition ablation.

Recommended improvement:

- Add at least a small supplemental sensitivity table, or soften the explanation:

```text
We set rb = 0.20 and sigma = 0.05 based on preliminary tuning and the ablation trends in Section V-B.
```

### 5. CIC-IDS2018 Attack Mapping Needs More Detail

The paper says CIC-IDS2018 covers six attack families mapped to the taxonomy.

Recommended addition:

Add a mapping table:

| CIC-IDS2018 Label | AdaptiveNIDS Taxonomy |
|---|---|
| DDoS HOIC/LOIC | DDoS |
| DoS Slowloris | Slowloris |
| DoS Hulk/GoldenEye | HTTP Flood / DoS |
| FTP/SSH Brute Force | Brute Force |
| Bot | Botnet C&C |
| Infiltration | Exfiltration/Infiltration |

Why:

- The mapping from CIC labels to AdaptiveNIDS labels is non-trivial.
- It improves reproducibility.

### 6. "Generalizes Across the Full 14-Class Taxonomy" Is Slightly Strong

Section V-E states:

> support the claim that AdaptiveNIDS generalizes across the full 14-class taxonomy

But eight classes are evaluated only synthetically.

Safer wording:

```text
support the internal consistency of the full 14-class synthetic taxonomy
```

or:

```text
suggest that the trained model can distinguish the remaining synthetic classes, although real-world validation for these categories remains future work.
```

## Suggested Claim Adjustments

### Current

> There is no system that autonomously monitors production recall and triggers retraining against configurable quality gates.

Concern:

- Very broad "no system" claim.

Safer:

```text
Few existing NIDS studies evaluate an end-to-end pipeline that couples detection-quality monitoring with automated retraining triggers under configurable quality gates.
```

### Current

> The orchestrator detects the recall drop, schedules retraining, and autonomously closes the gap within a single cycle.

Concern:

- This sounds like production live recall is available, but in practice recall requires labels.

Safer:

```text
When labeled evaluation data are available, the orchestrator detects recall degradation, schedules retraining, and closes the measured domain gap within a single cycle in our benchmark setting.
```

### Current

> real-time detection

Concern:

- The implementation appears to use batch/flow records, not raw line-rate packet capture.

Safer:

```text
near-real-time batch detection
```

or:

```text
simulated real-time flow-batch detection
```

## Recommended Additional Experiments

### 1. Multi-Agent Ablation

Purpose:

- Prove that the orchestration layer adds measurable value.

Metrics:

- F1
- recall
- FPR
- alert consistency
- latency
- retraining trigger delay

### 2. End-to-End Latency Breakdown

Purpose:

- Support the real-time/near-real-time claim.

Metrics:

- preprocessing latency
- model inference latency
- agent orchestration latency
- alert generation latency
- total latency

### 3. Small Sensitivity Study

Purpose:

- Support `rb = 0.20` and `sigma = 0.05`.

Grid:

```text
rb = 0.00, 0.10, 0.20, 0.30
sigma = 0.00, 0.05, 0.10
```

### 4. CIC-IDS2018 Mapping Table

Purpose:

- Improve reproducibility and reviewer confidence.

### 5. Real-World Validation Plan

If no new real-world data can be collected, add a short subsection:

```text
Operational Deployment Considerations
```

Include:

- required telemetry source
- feature extractor assumptions
- label availability issue for recall monitoring
- alert verification process

## Figures and Tables Checklist

### Must Fix

- [ ] Table II clipped on page 3.
- [ ] Table III memory column clipped on page 4.
- [ ] Table VI overlaps with Discussion text on page 5.

### Should Improve

- [ ] Reduce density on page 4.
- [ ] Consider making Table II and Table VI two-column-wide `table*`.
- [ ] Ensure all table captions and figure captions have enough vertical spacing.
- [ ] Verify that all figures remain readable after shrinking.

## Priority Checklist

### High Priority

- [ ] Fix table clipping/overlap layout issues.
- [ ] Verify and align the "10 normal service types" claim with the implementation.
- [ ] Clarify inference-only vs end-to-end latency measurements.
- [ ] Add CIC-IDS2018-to-AdaptiveNIDS attack mapping table.
- [ ] Soften "production recall" and "autonomously closes the gap" wording.

### Medium Priority

- [ ] Add multi-agent ablation or weaken orchestration-performance claims.
- [ ] Add a small BAT sensitivity table.
- [ ] Replace "generalizes across full 14-class taxonomy" with a synthetic-scope-qualified claim.
- [ ] Add stage-level latency breakdown.

### Low Priority

- [ ] Add pseudocode for BAT.
- [ ] Add pseudocode for the retraining trigger.
- [ ] Add a short operational deployment subsection.
- [ ] Add a MITRE ATT&CK coverage table if space permits.

## Revised Contribution Framing

Recommended contribution framing:

```text
This paper contributes: (1) Borderline-Aware Training, a synthetic flow-level augmentation protocol for hardening NIDS against near-boundary evasive variants; (2) a feedback-driven MLOps loop that uses labeled evaluation feedback to trigger adaptive retraining under configurable quality gates; and (3) AdaptiveNIDS, a prototype multi-agent orchestration pipeline that connects generation, training, evaluation, near-real-time flow-batch detection, and alerting.
```

This is safer than claiming complete production autonomy.

## Final Judgment

The A1 version is materially improved and closer to a defensible paper. The main intellectual story is now clear:

```text
BAT improves robustness on hard synthetic variants.
Synthetic-to-real transfer exposes a serious domain gap.
Adaptive retraining closes the measured gap on CIC-IDS2018.
The multi-agent pipeline provides an operational architecture around the detector.
```

The biggest remaining blocker is **format/layout quality**. The table clipping and overlap issues on pages 3 to 5 should be fixed before any submission. After layout correction, the next most important improvement is to either add a multi-agent ablation or soften claims about the measurable contribution of the 32-agent orchestration layer.
