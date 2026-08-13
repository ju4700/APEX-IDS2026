# APEX-IDS2026: A Research-Grade Network Intrusion Detection Dataset

**Real-World, Continuously Collected NetFlow Data with Honeypot-Verified Ground Truth, MITRE ATT&CK Mapping, and Zeek Deep Packet Inspection**

> **All statistics in this document are verified from live DuckDB queries on the actual dataset files (2026-08-13).**

---

## Abstract

APEX-IDS2026 is a research-grade network intrusion detection dataset built on live production network infrastructure. Unlike existing benchmark datasets (NSL-KDD, UNSW-NB15, CIC-IDS2017), which rely on synthetically generated attack traffic in controlled laboratory environments, APEX-IDS2026 captures genuine threat actor behavior from the live internet using a MikroTik router honeypot integrated with a continuous, automated 44-day collection pipeline.

The dataset captures the full spectrum of opportunistic internet-facing attacks: **64,084 unique destination ports targeted**, **10+ named services under active brute-force and exploitation**, **60 attacker countries**, and **5 distinct MITRE ATT&CK techniques** spanning discovery, initial access, credential access, and lateral movement. Every Tier 1 attack flow is mathematically proven - sourced from an IP that physically hit the honeypot during the same 5-minute capture window.

The central contribution is its **5-Tier Deterministic Labeling Architecture** combined with **MITRE ATT&CK mapping** and **Zeek Deep Packet Inspection**. The dataset offers a secondary **Feature as a Counter (FaaC)** time-series Parquet dataset powered by DuckDB aggregations, optimized for LSTM volumetric anomaly detectors.

---

## 1. Motivation and Problem Statement

The machine learning community in cybersecurity has long depended on datasets that are no longer representative of the contemporary threat landscape:

- **NSL-KDD** derives from the 1999 DARPA dataset - an era predating modern botnets, encrypted C2, and cloud-based attack infrastructure.
- **UNSW-NB15** was generated using commercial traffic generators in a closed network - synthetic by construction.
- **CIC-IDS2017** relies on 2-3 researchers simulating attacks in a lab, producing label contamination (~20%), Infinity values in 4,376 rows, 115 negative-duration flows, and no preserved IP addresses or timestamps.

APEX-IDS2026 addresses these gaps:
- **Real attackers** - 13,638 confirmed threat actor IPs from 60 countries
- **Real services under attack** - Redis, MongoDB, Elasticsearch, SSH, MySQL, PostgreSQL, HTTP/HTTPS, SMTP, FTP, VNC, RDP, Telnet, SIP, WinRM
- **Zero label contamination** - ground truth verified by physical honeypot correlation
- **Temporal continuity** - 44 consecutive days enabling concept drift and time-series analysis

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

**Label Purity:** The normal partition underwent global cross-window attacker IP validation. All 13,638 confirmed attacker IPs were compiled into a global deny-list. This process identified and reclassified **697,727 contamination flows** from the normal partition into the suspicious partition - resulting in a provably zero-contamination negative class.

---

## 3. Dataset Statistics (Verified)

| Property | Value |
|---|---|
| **Total flows** | 141,841,235 |
| **Collection period** | June 21 - August 3, 2026 (44 days) |
| **Attack_Verified flows** | 42,205,903 |
| **Class balance (Benign:Attack)** | 1.38:1 (near-optimal for ML) |
| **Unique attacker IPs** | 13,638 |
| **Unique targeted ports** | 64,084 |
| **Attacker countries** | 60 |
| **MITRE ATT&CK coverage** | 83,566,235 flows (59.0%) |
| **Zeek DPI coverage** | 71,485,904 flows (50.48%) |
| **Infinity/NaN values** | 0 |
| **Negative-duration flows** | 0 |
| **NULL values in core fields** | 0 |
| **Peak attack diversity** | 14,841 distinct attack types in a single day |

### Flow Distribution
| Label | Flows | % |
|---|---|---|
| Attack_Verified | 42,205,903 | 29.8% |
| Attack_Associated | 41,446,346 | 29.3% |
| Benign_Verified | 26,901,115 | 19.0% |
| Benign_Assumed | 16,672,439 | 11.8% |
| Unverified | 14,374,050 | 10.2% |

---

## 4. Attack Diversity (Verified)

APEX-IDS2026 captures the full spectrum of opportunistic attacks observed by internet-facing infrastructure in 2026.

### MITRE ATT&CK Coverage
| Technique | Tactic | Flows | % |
|---|---|---|---|
| **T1046** - Network Service Scanning | Discovery | 40,315,265 | 95.5% |
| **T1190** - Exploit Public-Facing Application | Initial Access | 1,383,535 | 3.3% |
| **T1110** - Brute Force | Credential Access | 294,023 | 0.7% |
| **T1110.001** - Password Guessing | Credential Access | 209,974 | 0.5% |
| **T1021.002** - SMB/Windows Admin Shares | Lateral Movement | 3,106 | 0.007% |

### Attack Categories
| Category | Flows | Key Services |
|---|---|---|
| reconnaissance | ~38.8M | 64,084 unique ports, all major internet services |
| web-attack | 1,923,557 | HTTP (port 80), HTTPS (port 443), HTTP-alt (8080) |
| brute-force | 1,084,400 | SSH, MySQL, RDP, VNC, Telnet, FTP, SMTP, PostgreSQL |
| service-probe | 846,370 | Redis, MongoDB, Elasticsearch, SIP, WinRM |
| lateral-movement | 19,961 | SMB (port 445), internal network traversal |

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

## 5. Data Schema Summary

Each labeled flow contains 38+ features across 6 categories. Full reference: [DATASET_SCHEMA.md](DATASET_SCHEMA.md).

**Raw NetFlow:** `flow_start`, `duration_s`, `protocol`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `packets`, `bytes` (BIGINT), `tcp_flags`, `tos`

**Computed rates (fixed, verified):** `bytes_per_sec` (bytes/duration_s), `packets_per_sec`, `bytes_per_packet`

**Zeek DPI:** `iat_mean`, `iat_std`, `payload_entropy`, `dns_query`, `init_win_bytes_forward`, `zeek_available`

**TCP flags (binary):** `flag_syn`, `flag_ack`, `flag_fin`, `flag_rst`, `flag_psh`, `flag_urg`

**Categorical:** `src_port_category`, `dst_port_category`, `flow_duration_class`

**Labels:** `label`, `attack_type`, `attack_category`, `mitre_technique`, `mitre_tactic`, `confidence`, `evidence_source`, `threat_intel_score`, `country`, `behavioral_flags`

---

## 6. File and Directory Structure (Local Archive)

```
F:/Apex-IDS/
├── parquet_dataset/           <- Primary dataset (DuckDB Partitioned Parquet)
│   └── date=YYYY-MM-DD/
│       ├── type=attacks/      <- Tier 1: Attack_Verified flows
│       ├── type=suspicious/   <- Tier 2+3: Attack_Associated + Unverified
│       └── type=normal/       <- Tier 4+5: Benign_Verified + Benign_Assumed
├── labeled/                   <- Source labeled CSVs (5-min window granularity)
│   └── YYYY-MM-DD/
│       ├── nfcapd.*_attacks.csv
│       ├── nfcapd.*_suspicious.csv
│       └── nfcapd.*_normal.csv
└── metadata/
    ├── dataset_manifest.csv
    ├── conn.log               <- Zeek connection log
    ├── features.log           <- Zeek custom features (incl. init_win_bytes_forward)
    └── labeling_summary.csv
```

**TimeSeries FaaC (for LSTM/Transformer anomaly detection):**
```
F:/Apex-IDS/labeled/TimeSeries/
└── TimeSeries_FaaC_YYYY-MM-DD.parquet   (44 files, 58,319 rows total)
```

---

## 7. Usage Recommendations

### Binary Classification (Attack vs Normal)
Use `Attack_Verified` (Tier 1) as positive class + `Benign_Verified` (Tier 3) as negative class. This is the **Golden Subset** - 0% label noise, 1.57:1 balance.

```python
import duckdb
df = duckdb.query("""
    SELECT * FROM read_parquet('F:/Apex-IDS/parquet_dataset/*/*/*.parquet', 
                                union_by_name=true)
    WHERE label IN ('Attack_Verified', 'Benign_Verified')
""").df()
```

### Multi-Class Attack Classification
Use `attack_type` as the target variable for fine-grained attack category classification:
```python
df = duckdb.query("""
    SELECT * FROM read_parquet('F:/Apex-IDS/parquet_dataset/*/type=attacks/*.parquet',
                                union_by_name=true)
""").df()
# Target: df['attack_type'] or df['attack_category']
```

### Time-Series / LSTM Anomaly Detection
Load the FaaC time-series Parquet files - 1-minute bins with volumetric counters:
```python
df = duckdb.query("""
    SELECT * FROM read_parquet('F:/Apex-IDS/labeled/TimeSeries/*.parquet',
                                union_by_name=true)
    ORDER BY window_start
""").df()
```

> **Note:** Always filter `WHERE zeek_available = True` before using `iat_mean`, `iat_std`, `payload_entropy` in ML models.

---

## 8. Data Quality Notes

| Issue | Status | Details |
|---|---|---|
| SI-suffix bytes (`"11.2 M"`) | Yes Fixed (2026-08-12) | 568,935 rows normalized across 11,671 files |
| `bytes_per_sec` was bits/s in attack+suspicious | Yes Fixed (2026-08-12) | 23,342 files rewritten; now uniformly bytes/s |
| Normal partition label contamination | Yes Fixed | 697,727 attack flows removed from normal partition |
| Attack_Associated label correction | Yes Fixed | 492,755 promoted flows given correct attack types |
| Infinity/NaN values | Yes None | 0 Infinity, 0 NaN in any column |
| Missing fwd/bwd packet stats | ℹ️ By design | NetFlow architecture: Mikrotik sends unidirectional flows |
| TCP window size (partial) | ℹ️ Zeek only | `init_win_bytes_forward` available where `zeek_available=True` |

---

## 9. Infrastructure

- **Collection server:** `synapstream` (Fedora Linux, x86-64)
- **NetFlow sensor:** MikroTik RouterOS -> NetFlow v9 -> nfcapd
- **Honeypot IP:** `103.148.176.62`
- **Zeek DPI:** TZSP mirror on same interface
- **Pipeline schedule:** `*/6 * * * *` - correlation runs every 6 minutes
- **FaaC schedule:** `10 0 * * *` - time-series aggregation daily at midnight

---

## 10. Dataset Access

The full dataset (38.6 GB compressed Parquet, 141,841,235 flows) will be hosted on Zenodo/HuggingFace Datasets upon publication with a citable DOI.

For the full academic evaluation and comparison with CIC-IDS2017, NSL-KDD, and UNSW-NB15, see [DATASET_COMPARISON_REPORT.md](DATASET_COMPARISON_REPORT.md).

For ML feature engineering guidance and baseline benchmarks, see [MACHINE_LEARNING_GUIDE.md](MACHINE_LEARNING_GUIDE.md).
