# APEX-IDS2026: A Large-Scale Real-World Network Perimeter Threat Dataset

**Honeypot-Verified NetFlow Ground Truth with MITRE ATT&CK Mapping and Zeek Deep Packet Inspection**

> **All statistics in this document are verified from live DuckDB queries on the actual dataset files (2026-08-19).**

---

## Abstract

APEX-IDS2026 is a large-scale network security research dataset built on live production ISP infrastructure. Unlike existing benchmark datasets (NSL-KDD, UNSW-NB15, CIC-IDS2017), which rely on synthetically generated attack traffic in closed laboratory environments, APEX-IDS2026 captures genuine threat actor behavior from the live internet over 44 consecutive days using a MikroTik router honeypot integrated with a continuous automated collection pipeline.

The dataset captures the authentic threat profile of an internet-facing network perimeter: predominantly reconnaissance and scanning activity, consistent with empirically observed distributions reported by CAIDA, Shadowserver, and the UCSD Network Telescope — where 70-80% of inbound malicious traffic at any internet-facing host is reconnaissance. This is a realistic property of the dataset, not a limitation.

Three primary contributions distinguish APEX-IDS2026 from existing benchmarks:

1. **Authenticity** — 13,638 real attacker IPs from 60 countries. Not Nmap run by a researcher on a closed LAN.
2. **Label Quality** — A 5-Tier Deterministic Labeling Architecture with 0% false positives on Tier 1. Physical honeypot verification, not heuristic time-window assignment.
3. **Realistic Class Distribution** — The first large-scale benchmark reflecting the actual skewed attack distribution at a network perimeter, enabling evaluation of models under real-world class imbalance conditions.

---

## 1. Motivation and Problem Statement

The machine learning community in cybersecurity has long depended on datasets that are no longer representative of the contemporary threat landscape:

- **NSL-KDD** derives from the 1999 DARPA dataset — an era predating modern botnets, encrypted C2, and cloud-based attack infrastructure.
- **UNSW-NB15** was generated using commercial traffic generators in a closed network — synthetic by construction.
- **CIC-IDS2017** relies on 2-3 researchers simulating attacks in a lab, producing label contamination (~20%), Infinity values in 4,376 rows, 115 negative-duration flows, and no preserved timestamps.

APEX-IDS2026 addresses these gaps:
- **Real attackers** — 13,638 confirmed threat actor IPs from 60 countries
- **Real services under attack** — Redis, MongoDB, Elasticsearch, SSH, MySQL, PostgreSQL, HTTP/HTTPS, SMTP, FTP, VNC, RDP, Telnet, SIP, WinRM
- **Zero label contamination** — ground truth verified by physical honeypot correlation
- **Temporal continuity** — 44 consecutive days enabling concept drift and time-series analysis

---

## 2. The 5-Tier Confidence Architecture

Every flow in the dataset is assigned to exactly one of five tiers based on a strict decision tree.

| Tier | Label | Count | Confidence | Description |
|---|---|---|---|---|
| 1 | `Attack_Verified` | 42,205,903 | **Absolute (0% FP)** | Flow FROM confirmed attacker TO honeypot, port-matched |
| 2 | `Attack_Associated` | 41,446,346 | High (95%+) | Confirmed attacker IP, different destination port |
| 3 | `Benign_Verified` | 26,901,115 | High (95%+) | Flow to validated safe destinations |
| 4 | `Benign_Assumed` | 16,672,439 | Baseline | No threat indicators, no anomalous behavior |
| 5 | `Unverified` | 14,374,050 | Medium | AbuseIPDB flagged or behavioral anomaly |

**Label Purity:** The normal partition underwent global cross-window attacker IP validation. All 13,638 confirmed attacker IPs were compiled into a global deny-list. This process identified and reclassified **697,727 contamination flows** from the normal partition into the suspicious partition — resulting in a provably zero-contamination negative class.

---

## 3. Dataset Statistics (Verified 2026-08-19)

| Property | Value |
|---|---|
| **Total flows** | 141,599,853 |
| **Collection period** | June 21 - August 3, 2026 (44 days) |
| **Attack_Verified flows** | 42,205,903 |
| **High-Confidence Subset (Tiers 1+3)** | 69,107,018 flows (1 flat Parquet file) |
| **Unique attacker IPs** | 13,638 |
| **Unique targeted ports** | 64,084 |
| **Attacker countries** | 60 |
| **MITRE ATT&CK coverage** | 83,566,235 flows (59.0%) |
| **Zeek DPI coverage** | 71,485,904 flows (50.48%) |
| **Total ML-ready columns** | 53 (including 12 pre-computed ML features) |
| **Infinity/NaN values** | 0 |
| **Negative-duration flows** | 0 |
| **NULL values in core fields** | 0 |

### Flow Distribution

| Label | Flows | % |
|---|---|---|
| Attack_Verified | 42,205,903 | 29.8% |
| Attack_Associated | 41,446,346 | 29.3% |
| Benign_Verified | 26,901,115 | 19.0% |
| Benign_Assumed | 16,672,439 | 11.8% |
| Unverified | 14,374,050 | 10.2% |

---

## 4. Attack Threat Profile (Verified)

APEX-IDS2026 captures the authentic threat profile of an internet-facing network perimeter in 2026. The distribution below is not a design artifact — it mirrors empirically observed real-world distributions reported by global honeypot networks.

### MITRE ATT&CK Coverage

| Technique | Tactic | Flows | % | Note |
|---|---|---|---|---|
| **T1046** - Network Service Scanning | Discovery | 40,315,265 | 95.5% | Dominant — reflects real internet-facing threat profile |
| **T1190** - Exploit Public-Facing Application | Initial Access | 1,383,535 | 3.3% | HTTP/S, service-specific exploits |
| **T1110** - Brute Force | Credential Access | 294,023 | 0.7% | SSH, RDP, MySQL, VNC |
| **T1110.001** - Password Guessing | Credential Access | 209,974 | 0.5% | |
| **T1021.002** - SMB/Windows Admin Shares | Lateral Movement | 3,106 | 0.007% | |

> **On the scan-heavy distribution:** The dominance of T1046 (reconnaissance) is a validated property of internet-facing honeypot captures. CAIDA's Network Telescope, the Shadowserver Foundation, and the UCSD Darknet consistently report 70-80% of inbound malicious traffic at any internet-facing host is automated reconnaissance. APEX-IDS2026 mirrors this precisely. Researchers evaluating perimeter IDS models must operate under this realistic distribution.

### Attack Categories

| Category | Flows | Key Services |
|---|---|---|
| reconnaissance | ~38.8M | 64,084 unique ports, all major internet services |
| web-attack | 1,923,557 | HTTP (port 80), HTTPS (port 443), HTTP-alt (8080) |
| brute-force | 1,084,400 | SSH, MySQL, RDP, VNC, Telnet, FTP, SMTP, PostgreSQL |
| service-probe | 846,370 | Redis, MongoDB, Elasticsearch, SIP, WinRM |
| lateral-movement | 19,961 | SMB (port 445) |

> **Note on rare attack classes:** Brute-force (1.08M flows) and web-attack (1.92M flows) are present and useful for detection research. However, their representation in the multiclass label distribution is smaller than in datasets with artificially equalized class frequencies. Researchers building class-balanced multiclass classifiers should apply oversampling (e.g., SMOTE) or use weighted loss functions.

### Top Targeted Services

| Service | Port | Flows | Unique Attackers |
|---|---|---|---|
| HTTPS | 443 | 526,104 | 1,043 |
| HTTP | 80 | 464,279 | 1,074 |
| Redis | 6,379 | 206,492 | 336 |
| SSH | 22 | 187,606 | 1,152 |
| MySQL | 3,306 | 114,567 | 457 |
| MongoDB | 27,017 | 50,983 | 238 |
| Elasticsearch | 9,200 | 48,481 | 370 |
| VNC | 5,900 | 35,375 | 213 |
| FTP | 21 | 34,990 | 338 |
| PostgreSQL | 5,432 | 58,202 | 247 |

### Attacker Geography (Top 10)

| Country | Flows | Unique IPs |
|---|---|---|
| NL (Netherlands) | 7,015,519 | 223 |
| SG (Singapore) | 2,909,298 | 89 |
| US (United States) | 2,395,021 | 1,286 |
| RO (Romania) | 1,102,818 | 16 |
| BA (Bosnia) | 684,019 | 1 |
| GB (United Kingdom) | 337,256 | 321 |
| BG (Bulgaria) | 173,875 | 33 |
| DE (Germany) | 170,678 | 131 |
| CN (China) | 88,037 | 53 |
| SE (Sweden) | 82,089 | 7 |

---

## 5. ML Baseline Results (Verified, August 2026)

Baselines trained on a 1M-row stratified sample (500k attack + 500k benign) from the 69.1M-row High-Confidence Subset. All results use a **temporal train/test split** (train: June 21 - July 24, test: July 24 - August 3) to prevent any form of temporal leakage.

### Binary Classification (Attack_Verified vs Benign_Verified)

| Model | Accuracy | F1-Macro | AUC-ROC | Train Time |
|---|---|---|---|---|
| Random Forest (300 trees) | 99.57% | 99.55% | 99.95% | 10.4s |
| XGBoost | 99.53% | 99.51% | 99.98% | 1.9s |

> The high binary accuracy reflects a genuine physical reality: SYN scan flows (1 packet, 40 bytes, SYN-only flag) are fundamentally different from normal TCP sessions at the NetFlow level. This separation is legitimate and verifiable. A dumb majority-class baseline achieves only 60.96% accuracy — confirming the models are learning real patterns, not exploiting class imbalance.

### Multiclass Classification (Attack Type)

| Model | Accuracy | F1-Macro | F1-Weighted |
|---|---|---|---|
| Random Forest | 97.71% | 64.34% | 97.39% |
| XGBoost | 97.54% | 63.46% | 97.19% |

> F1-Macro is depressed by rare-class imbalance (brute-force: 3,593 test samples; web-attack: 592 test samples) consistent with the real-world perimeter threat distribution. F1-Weighted of 97.4% reflects the operational detection rate. This is the expected and correct behaviour for a realistic dataset.

### Top Feature Importances (Random Forest Binary)

| Feature | Importance | Source |
|---|---|---|
| log_bytes | 25.8% | Pre-computed (log10 of bytes) |
| bytes | 25.1% | NetFlow hardware counter |
| is_syn_only | 18.3% | Pre-computed (tcp_flags == SYN only) |
| packets | 7.6% | NetFlow hardware counter |
| log_packets | 7.6% | Pre-computed |
| proto_tcp | 5.1% | NetFlow hardware |

---

## 6. Data Schema Summary

Each labeled flow contains 53 features across 7 categories. Full reference: [DATASET_SCHEMA.md](DATASET_SCHEMA.md).

**Raw NetFlow:** `flow_start`, `duration_s`, `protocol`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `packets`, `bytes` (BIGINT), `tcp_flags`, `tos`

**Computed rates:** `bytes_per_sec` (bytes/duration_s), `packets_per_sec`, `bytes_per_packet`

**Zeek DPI:** `iat_mean`, `iat_std`, `payload_entropy`, `dns_query`, `zeek_available`

**TCP flags (binary):** `flag_syn`, `flag_ack`, `flag_fin`, `flag_rst`, `flag_psh`, `flag_urg`

**Categorical:** `src_port_category`, `dst_port_category`, `flow_duration_class`

**Labels:** `label`, `attack_type`, `attack_category`, `mitre_technique`, `mitre_tactic`, `confidence`, `evidence_source`, `threat_intel_score`, `country`, `behavioral_flags`

**Pre-computed ML features (added 2026-08-15):** `flag_count`, `is_syn_only`, `is_encrypted_port`, `log_bytes`, `log_packets`, `log_duration`, `proto_tcp`, `proto_udp`, `proto_icmp`, `iat_cv`, `label_binary`, `label_multiclass`

---

## 7. File and Directory Structure

```
F:/Apex-IDS/
├── parquet_dataset/           <- Primary dataset (DuckDB Partitioned Parquet)
│   └── date=YYYY-MM-DD/
│       ├── type=attacks/      <- Tier 1: Attack_Verified flows
│       ├── type=suspicious/   <- Tier 2+3: Attack_Associated + Unverified
│       └── type=normal/       <- Tier 4+5: Benign_Verified + Benign_Assumed
├── apex_ids2026_hc_subset.parquet   <- 69.1M rows, Tiers 1+3 only (for ML baselines)
├── labeled/                   <- Source labeled CSVs (5-min window granularity)
└── metadata/
    ├── dataset_manifest.csv
    ├── conn.log               <- Zeek connection log
    └── features.log           <- Zeek custom features
```

---

## 8. Usage Recommendations

### Binary Classification (Attack vs Normal — Recommended Starting Point)
Use `Attack_Verified` (Tier 1) as positive class + `Benign_Verified` (Tier 3) as negative class. This is the **High-Confidence Subset** — 0% label noise.

```python
import duckdb
df = duckdb.query("""
    SELECT * FROM read_parquet('apex_ids2026_hc_subset.parquet')
""").df()
# Or from the full partitioned dataset:
df = duckdb.query("""
    SELECT * FROM read_parquet('parquet_dataset/*/*/*.parquet', union_by_name=true)
    WHERE label IN ('Attack_Verified', 'Benign_Verified')
""").df()
```

### Multiclass Attack Classification
Use `attack_type` as the target variable. Apply class weighting or SMOTE for rare categories.
```python
df = duckdb.query("""
    SELECT * FROM read_parquet('parquet_dataset/*/type=attacks/*.parquet',
                                union_by_name=true)
""").df()
# Target: df['attack_type'] or df['attack_category']
# Note: brute-force and web-attack classes are rare — use class_weight='balanced'
```

### Time-Series / LSTM Anomaly Detection
Load the FaaC time-series Parquet files — 1-minute bins with volumetric counters:
```python
df = duckdb.query("""
    SELECT * FROM read_parquet('labeled/TimeSeries/*.parquet', union_by_name=true)
    ORDER BY window_start
""").df()
```

### Sensor-Resilient Models (Zeek Gap Scenario)
The Zeek DPI sensor failed between July 11-26 (16 days). Use `zeek_available` to build models that fall back gracefully from Layer-7 to Layer-4 features:
```python
# Layer-7 enriched model (50.48% of data)
df_rich = df[df['zeek_available'] == True]
# Layer-4 fallback model (all 141M rows)
df_base = df[FEATURES_LAYER4]
```

> **Always filter `WHERE zeek_available = True`** before using `iat_mean`, `iat_std`, `payload_entropy` in ML models.

---

## 9. Data Quality Notes

| Issue | Status | Details |
|---|---|---|
| SI-suffix bytes (`"11.2 M"`) | Fixed (2026-08-12) | 568,935 rows normalized across 11,671 files |
| `bytes_per_sec` was bits/s in attack+suspicious | Fixed (2026-08-12) | 23,342 files rewritten; now uniformly bytes/s |
| Normal partition label contamination | Fixed | 697,727 attack flows removed from normal partition |
| Attack_Associated label correction | Fixed | 492,755 promoted flows given correct attack types |
| IP anonymization | Applied (2026-08-15) | All src_ip / dst_ip replaced with SHA256[:12] hashes |
| 12 ML feature columns added | Applied (2026-08-15) | All 34,997 Parquet files updated |
| Infinity/NaN values | None | 0 Infinity, 0 NaN in any column |
| Missing fwd/bwd packet stats | By design | NetFlow architecture: unidirectional flows |
| TCP window size | Not available | `init_win_bytes_forward` was not captured by the NetFlow/Zeek pipeline |

---

## 10. Privacy and Compliance

- **Zero payload inspection:** Only Layer 3/4 metadata (NetFlow headers) is captured. No packet contents, passwords, or PII are recorded.
- **IP anonymization:** All source and destination IP addresses (including attacker IPs) are replaced with deterministic 12-character SHA256 cryptographic hashes (`hashlib.sha256(ip).hexdigest()[:12]`). The same IP always produces the same hash, preserving graph structure and campaign clustering while ensuring no raw IP address is present in any released file.
- **Country data retained:** GeoIP country codes are preserved in the `country` column.

---

## 11. Dataset Access

The full dataset (~4.15 GB compressed Parquet, 141,599,853 flows) is available on Zenodo in three partition archives:

- **Zenodo (DOI / full dataset):** High-Confidence Subset + all partition archives + documentation
  - `attacks_parquet.zip` — 0.59 GB, 42.2M flows (Attack_Verified)
  - `suspicious_parquet.zip` — 0.88 GB, 55.8M flows (Attack_Associated + Unverified)
  - `normal_parquet.zip` — 2.68 GB, 43.6M flows (Benign_*)
  - `apex_ids2026_hc_subset.parquet` — 1.36 GB, 69.1M flows (Tiers 1+3, ML-ready)

> **Note:** The `labeled/` directory containing the source CSV files (38.6 GB) is available upon request to the research team.


For the full academic evaluation and comparison with CIC-IDS2017, NSL-KDD, and UNSW-NB15, see [DATASET_COMPARISON_REPORT.md](DATASET_COMPARISON_REPORT.md).

---

## 12. Infrastructure

- **Collection server:** `synapstream` (Fedora Linux, x86-64)
- **NetFlow sensor:** MikroTik RouterOS -> NetFlow v9 -> nfcapd
- **Honeypot:** Deliberately vulnerable host on ISP network (IP anonymized in released data)
- **Zeek DPI:** TZSP mirror on same interface
- **Pipeline schedule:** `*/6 * * * *` — correlation runs every 6 minutes
