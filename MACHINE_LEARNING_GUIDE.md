# APEX-IDS2026: Machine Learning Guide

**A Practitioner's Reference for Training and Evaluating Intrusion Detection Models on APEX-IDS2026**

---

## 1. Introduction

This guide is written for researchers and data scientists who intend to use APEX-IDS2026 to train, evaluate, or benchmark machine learning models for network intrusion detection. It covers the dataset's structural properties, recommended data loading procedures, feature engineering considerations, strategies for handling class imbalance, suitable model architectures, and evaluation best practices.

Readers are assumed to have familiarity with supervised learning and basic network security terminology. Prior experience with NetFlow-based datasets is helpful but not required.

---

## 2. Understanding the Dataset's Unique Structure

### 2.1 The 3-Tier Label System is Not Optional Context

Most practitioners accustomed to binary IDS datasets will be tempted to immediately collapse `attack` and `suspicious` into a single positive class and treat `normal` as the negative class. This is a valid approach, but it discards what makes APEX-IDS2026 unique.

The three tiers represent qualitatively different evidence strengths:

| Tier | `label` | Evidence | Recommended Use |
|------|---------|----------|-----------------|
| 1 | `attack` | Deterministic, zero false positive | Primary positive class for supervised learning |
| 2 | `suspicious` | High confidence, attacker-confirmed but port-unmatched | Semi-supervised, anomaly detection, recon detection |
| 3 | `normal` | Benign — no honeypot interaction | Negative class |

Treating Tier 2 as noise wastes a significant and scientifically valuable portion of the data. Section 5 describes how to exploit it.

### 2.2 Temporal Correlation Within Windows

Flows within a single 6-minute nfcapd window are temporally correlated. Multiple flows from the same source IP scanning multiple ports will appear in the same window. If you split train/test by randomly shuffling individual rows, flows from the same attacker will appear in both sets, causing data leakage and inflated evaluation metrics.

Always split by **time window** (i.e., by `flow_file`), not by row.

### 2.3 High Cardinality of Source IP

`src_ip` has extremely high cardinality (hundreds of unique attacker IPs per window, thousands across the full dataset) and should not be used as a raw feature. It should be excluded from model inputs entirely. Its use is restricted to join operations during data loading.

Similarly, `dst_ip` and `flow_file` are identifiers, not features.

### 2.4 Class Imbalance

The class distribution within each window is severely imbalanced:

| Class | Approximate Count per Window |
|-------|------------------------------|
| Tier 3 (normal) | 5,000 |
| Tier 1 (attack) | 700–1,200 |
| Tier 2 (suspicious) | 800–1,100 |
| Total traffic in window | 465,000–660,000 |

Note that the normal sample is artificially limited to 5,000 flows, while the underlying benign traffic volume is orders of magnitude larger. The actual ratio of attack to normal traffic in the raw nfcapd file is approximately 0.33% — reflecting the true internet-scale background. Any evaluation that does not account for this imbalance will produce misleadingly high accuracy scores.

---

## 3. Data Loading

### 3.1 Recommended Loading Pattern

```python
import pandas as pd
import glob
from pathlib import Path

LABELED_DIR = Path("/data/flows/labeled")

def load_tier(tier_suffix, date_range=None):
    """
    Load all files matching a given tier suffix.
    tier_suffix: '_attacks', '_suspicious', or '_normal'
    date_range: optional tuple of ('YYYY-MM-DD', 'YYYY-MM-DD') for filtering
    """
    pattern = str(LABELED_DIR / "**" / f"*{tier_suffix}.csv")
    files = sorted(glob.glob(pattern, recursive=True))

    if date_range:
        start, end = pd.Timestamp(date_range[0]), pd.Timestamp(date_range[1])
        files = [
            f for f in files
            if start <= pd.Timestamp(Path(f).parent.name) <= end
        ]

    return pd.concat(
        [pd.read_csv(f, low_memory=False) for f in files],
        ignore_index=True
    )

attacks    = load_tier("_attacks")
suspicious = load_tier("_suspicious")
normal     = load_tier("_normal")
```

### 3.2 Temporal Train/Test Split

```python
# Get all unique time windows
all_windows = sorted(attacks["flow_file"].unique())

split_idx   = int(len(all_windows) * 0.8)
train_files = set(all_windows[:split_idx])
test_files  = set(all_windows[split_idx:])

def split_by_window(df, train_files, test_files):
    return (
        df[df["flow_file"].isin(train_files)].copy(),
        df[df["flow_file"].isin(test_files)].copy()
    )

train_attacks,    test_attacks    = split_by_window(attacks,    train_files, test_files)
train_suspicious, test_suspicious = split_by_window(suspicious, train_files, test_files)
train_normal,     test_normal     = split_by_window(normal,     train_files, test_files)
```

This ensures no time window appears in both training and evaluation sets.

---

## 4. Feature Engineering

### 4.1 Columns to Exclude from Model Input

The following columns are identifiers or derivable from other columns and must be excluded from feature matrices:

```python
EXCLUDE_COLS = [
    "src_ip", "dst_ip", "flow_file",
    "label", "attack_type", "attack_category",
    "mitre_technique", "mitre_tactic",
    "confidence", "evidence_source",
    "flow_start",   # Use duration features instead
    "tcp_flags",    # Use flag_* binary columns instead
]
```

### 4.2 Recommended Feature Set

The following 20 features are recommended as the primary input for tabular models:

**Continuous features (11):**
```
duration_s, packets, bytes,
bytes_per_sec, packets_per_sec, bytes_per_packet,
src_port, dst_port, tos
```

**Binary TCP flag features (6):**
```
flag_syn, flag_ack, flag_fin, flag_rst, flag_psh, flag_urg
```

**Categorical features requiring encoding (3):**
```
protocol, src_port_category, dst_port_category
```

### 4.3 Protocol Encoding

`protocol` takes values `TCP`, `UDP`, `ICMP`, and occasionally `GRE` or `ESP`. One-hot encode with a sparse representation:

```python
df = pd.get_dummies(df, columns=["protocol"], drop_first=False)
```

### 4.4 Port Category Encoding

`src_port_category` and `dst_port_category` are ordinal categories reflecting IANA port range classification:
- `well-known` (0–1023): services
- `registered` (1024–49151): applications  
- `dynamic` (49152–65535): ephemeral

Encode as ordinal integers (0, 1, 2) or one-hot depending on the model type.

### 4.5 Log-Transforming Rate Features

`bytes`, `packets`, `bytes_per_sec`, `packets_per_sec`, and `bytes_per_packet` span multiple orders of magnitude and are heavily right-skewed. Apply a log1p transform before using with linear models or distance-based algorithms:

```python
import numpy as np

skewed_cols = ["bytes", "packets", "bytes_per_sec",
               "packets_per_sec", "bytes_per_packet"]
for col in skewed_cols:
    df[col] = np.log1p(df[col].clip(lower=0))
```

Tree-based models (Random Forest, XGBoost, LightGBM) are invariant to monotonic transforms and do not require this step.

### 4.6 Handling Zero-Duration Flows

A proportion of flows will have `duration_s = 0` (typically SYN-only or RST flows). The computed rate features (`bytes_per_sec`, `packets_per_sec`) are set to 0 for such flows by the pipeline. These flows are valid data — they represent connection attempts that were immediately rejected. Do not filter them out.

---

## 5. Experimental Configurations

### 5.1 Configuration A — Binary Attack Detection

**Objective:** Train a classifier to distinguish attack traffic from benign traffic.

```python
df_train = pd.concat([
    train_attacks.assign(y=1),
    train_normal.assign(y=0)
])
df_test = pd.concat([
    test_attacks.assign(y=1),
    test_normal.assign(y=0)
])
```

**Notes:**
- This configuration uses only Tier 1 and Tier 3 data.
- Tier 1 labels carry 0% false positives, making this the cleanest possible binary classification problem.
- Class imbalance is approximately 1:4 (attacks to normal) in the sampled data. For real-world evaluation, apply the full 1:500+ imbalance ratio as described in Section 6.

### 5.2 Configuration B — Multi-Class Attack Type Classification

**Objective:** Given that a flow is malicious, classify it into one of the named attack categories.

```python
df_train = train_attacks.copy()
# Target: attack_type (e.g., SSH-Brute, HTTP-Probe, Port-8080-Scan)
# or attack_category (e.g., brute-force, web-attack, reconnaissance)
```

**Notes:**
- Over 300 distinct `attack_type` values are observed in practice. For initial experiments, using `attack_category` (6 classes) is recommended.
- Classes are not uniformly distributed. Port scan categories (`Port-N-Scan`) are by far the most common. Brute-force categories (SSH, RDP, MySQL) are less frequent but more valuable for detection research.
- Consider grouping rare port scan categories into a single `Port-Scan-Generic` class if evaluating on small data volumes.

### 5.3 Configuration C — Three-Class Threat Level Classification

**Objective:** Train a model to distinguish between verified attacks, attacker reconnaissance, and normal traffic.

```python
df_train = pd.concat([
    train_attacks.assign(y=2),       # Confirmed attack
    train_suspicious.assign(y=1),    # Attacker recon
    train_normal.assign(y=0)         # Benign
])
```

**Notes:**
- This configuration is the most scientifically novel use of APEX-IDS2026 and has no equivalent in existing datasets.
- A model that achieves high accuracy on the `suspicious` class has learned to identify the reconnaissance signature of confirmed threat actors — a form of behavioral threat intelligence that is practically valuable for proactive defense.

### 5.4 Configuration D — Temporal Generalization Benchmark

**Objective:** Evaluate how well a model trained on early data generalizes to later data — testing resilience to threat actor evolution.

Train on windows from the first 30 days of collection. Evaluate on windows from days 31–60. Evaluate again on days 61–90. Report the performance trajectory over time as a measure of temporal generalization.

---

## 6. Handling Class Imbalance

### 6.1 The Sampled vs. Real-World Distribution

APEX-IDS2026's Tier 3 (normal) data is downsampled to 5,000 flows per window for practical storage reasons. The actual network contains approximately 500,000–650,000 total flows per window, of which roughly 0.33% are attack flows. Researchers evaluating "real-world" performance should test at the true distribution (1:500+ imbalance) rather than the sampled 1:4 ratio.

To simulate the real distribution, sample additional normal flows from the raw nfcapd files using nfdump and append them to the Tier 3 CSVs.

### 6.2 Recommended Imbalance Strategies

**For tree-based models (Random Forest, XGBoost, LightGBM):**
Use the `class_weight` or `scale_pos_weight` parameter to weight the minority class inversely proportional to its frequency. This is computationally efficient and generally effective.

```python
from sklearn.ensemble import RandomForestClassifier

# For binary classification at sampled ratio (~1:4)
clf = RandomForestClassifier(class_weight="balanced", n_estimators=200)

# For real-world ratio (~1:500)
clf = RandomForestClassifier(class_weight={0: 1, 1: 500}, n_estimators=200)
```

**For neural networks:**
Use weighted cross-entropy loss. Alternatively, apply SMOTE (Synthetic Minority Oversampling Technique) only on the training set, never the test set.

**For evaluation:**
Never use accuracy as the primary metric on imbalanced data. Use:
- **Area Under ROC Curve (AUC-ROC):** Threshold-independent, measures discriminative power
- **Precision-Recall Curve (AUC-PR):** More informative than ROC when the positive class is rare
- **F1 Score:** Harmonic mean of precision and recall at the operating threshold
- **Matthews Correlation Coefficient (MCC):** Stable for extreme imbalance

---

## 7. Recommended Model Architectures

### 7.1 Gradient Boosted Trees (Primary Recommendation)

XGBoost, LightGBM, and CatBoost consistently achieve state-of-the-art performance on tabular network flow data. They handle mixed continuous/categorical features natively, are robust to outliers, require minimal preprocessing, and are interpretable via SHAP values.

```python
import xgboost as xgb

model = xgb.XGBClassifier(
    n_estimators=500,
    max_depth=6,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=4,   # Adjust for class imbalance
    use_label_encoder=False,
    eval_metric="aucpr",
    random_state=42
)
```

### 7.2 Random Forest (Strong Baseline)

Random Forest provides a computationally inexpensive, highly interpretable baseline. Its feature importance scores are useful for ablation studies examining which flow features contribute most to classification.

### 7.3 Multilayer Perceptron (Deep Learning Baseline)

For researchers interested in neural network approaches, a shallow MLP (2–3 hidden layers, 128–256 units, ReLU activations, batch normalization, dropout 0.3) provides a reasonable deep learning baseline. Deep architectures beyond 4 layers do not typically improve performance on tabular NetFlow data.

### 7.4 LSTM / Temporal Models (For Sequence Analysis)

If flows are grouped into sequences by Source IP and sorted by timestamp, LSTM or Transformer models can learn sequential attack patterns (e.g., an attacker that probes port 22 before pivoting to port 3389). This approach requires constructing per-IP flow sequences from the labeled CSVs and is the recommended methodology for the Configuration C (three-class) experiment.

---

## 8. Evaluation Protocol

### 8.1 Standard Metrics

Report the following metrics for all experiments:

| Metric | Why It Matters |
|--------|---------------|
| AUC-ROC | Threshold-independent discriminative power |
| AUC-PR | Relevant when positive class is rare |
| Precision @ threshold | Fraction of flagged flows that are genuinely malicious |
| Recall @ threshold | Fraction of genuine attacks that are detected |
| F1 Score | Balanced measure of precision and recall |
| MCC | Reliable for extreme imbalance |
| FP Rate | Critical for operational deployment decisions |

### 8.2 Tier-Separated Evaluation

When reporting results, disaggregate performance by tier. Report separately:
- Precision and recall on Tier 1 flows (ground truth attacks)
- Precision and recall on Tier 2 flows (reconnaissance)
- Whether the model learns to differentiate Tiers 1 and 2, or collapses them

### 8.3 Temporal Hold-Out Requirement

As noted in Section 3.2, splitting must be done by time window, not by row. Report the date range of training data and the date range of evaluation data explicitly in all publications.

### 8.4 Comparison Baselines

When comparing against prior work, note that APEX-IDS2026 presents a fundamentally harder generalization challenge than lab datasets, because the test distribution includes novel attacker IPs, new port combinations, and evolving campaign tactics not seen during training. Direct comparison of absolute metrics against results reported on CICIDS2017 or NSL-KDD is methodologically inadvisable without correction for distribution shift.

---

## 9. MITRE ATT&CK Integration

APEX-IDS2026 includes `mitre_technique` and `mitre_tactic` labels, enabling researchers to evaluate detectors in terms of the MITRE ATT&CK framework coverage. Researchers can report:

- Detection rate per ATT&CK tactic (e.g., credential-access vs. discovery)
- Coverage across techniques (which T-codes are detectable vs. which evade the classifier)
- Confusion between similar tactics (e.g., whether the model confuses service probes with web attacks)

This framing allows direct comparison with production SIEM and EDR system coverage claims.

---

## 10. Reproducing Published Experiments

All experiments performed using APEX-IDS2026 should report:

1. The date range of training windows and test windows (by `flow_file` prefix date)
2. The tiers included (Tier 1 only, Tier 1+3, Tier 1+2+3)
3. The class weighting or sampling strategy applied
4. The exact feature set used (list all included columns)
5. Whether the nfdump extended format was available (30+ features) or basic format (10 features + computed)
6. The train/test split methodology (temporal window split required)

This information is necessary for reproducibility and comparison across research groups.
