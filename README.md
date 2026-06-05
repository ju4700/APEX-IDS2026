# APEX-IDS2026: A Research-Grade Network Intrusion Detection Dataset

**Real-World, Deterministic, Continuously Collected NetFlow Data with Honeypot-Verified Ground Truth**

---

## Abstract

APEX-IDS2026 is a research-grade network intrusion detection dataset built on live production network infrastructure. Unlike existing benchmark datasets (NSL-KDD, UNSW-NB15, CIC-IDS2017), which rely on synthetically generated attack traffic in controlled laboratory environments, APEX-IDS2026 captures genuine threat actor behavior from the live internet using a MikroTik router honeypot integrated with a continuous NetFlow collection pipeline.

The central contribution of this dataset is its **3-Tier Deterministic Labeling Architecture**, which uses port-based correlation between honeypot event logs and nfcapd binary captures to produce ground-truth labels that carry a mathematically guaranteed 0% false positive rate for Tier 1 (Honeypot-Verified) flows. The pipeline operates autonomously via a 6-minute cron cycle, making this the first self-sustaining, longitudinal IDS dataset designed for continuous academic use.

---

## 1. Motivation and Problem Statement

The machine learning community in cybersecurity has long depended on datasets that are no longer representative of the contemporary threat landscape:

- **NSL-KDD** derives from the 1999 DARPA dataset and contains simulated attacks from an era predating modern botnets, ransomware, and large-scale internet scanning campaigns.
- **UNSW-NB15** was generated over 31 hours using the IXIA PerfectStorm commercial traffic generator in a closed network — synthetic by construction.
- **CIC-IDS2017** uses CICFlowMeter-based heuristic labeling on 5 days of lab traffic, where the "attackers" were researchers executing scripts on isolated virtual machines.

Training intrusion detection models on such data produces classifiers that generalize poorly to real-world deployments. Network flows on a live internet-facing server exhibit structural properties — timing distributions, flag combinations, packet-to-byte ratios, and port scan diversity — that are qualitatively different from those produced by simulation tools.

APEX-IDS2026 addresses this gap by capturing flows from live threat actors and providing labels anchored to hardware-level honeypot evidence rather than statistical heuristics.

---

## 2. The 3-Tier Confidence Architecture

### 2.1 Tier 1 — Honeypot-Verified (Ground Truth)

| Field | Value |
|-------|-------|
| `label` | `attack` |
| `confidence` | `honeypot-verified` |
| `evidence_source` | `honeypot:port-match` |
| **False Positive Rate** | **0%** |

A flow is assigned Tier 1 if and only if two conditions are simultaneously satisfied:

1. The flow's **Source IP** is present in the parsed MikroTik honeypot event log — meaning this IP was caught attacking the honeypot at some point during the same 6-minute time window.
2. The flow's **Destination Port** exactly matches the port that specific IP targeted in the honeypot log entry.

This uses **Port-Based Matching**, a technique developed specifically to remain immune to NAT translation and interface-capture asymmetries that would otherwise cause IP-based matching to fail silently. The label is not an inference — it is a direct, deterministic consequence of two independently logged facts.

### 2.2 Tier 2 — Attacker-Associated (Peripheral Reconnaissance)

| Field | Value |
|-------|-------|
| `label` | `suspicious` |
| `confidence` | `attacker-associated` |
| `evidence_source` | `honeypot:port-mismatch` |

A flow is Tier 2 if its Source IP is a confirmed attacker (Tier 1 criteria satisfied on another port) but its Destination Port does not match the honeypot-logged port. These flows represent the lateral reconnaissance activity of a confirmed threat actor probing other services on the network — the behavioral fingerprint that precedes and follows a targeted attack. This tier is unique to APEX-IDS2026 and has no equivalent in existing datasets.

### 2.3 Tier 3 — Normal-Sampled (Benign Baseline)

| Field | Value |
|-------|-------|
| `label` | `normal` |
| `confidence` | `normal-sampled` |

A stratified random sample of 5,000 flows per 6-minute window from Source IPs with zero honeypot interactions in that window. This constitutes the benign class for supervised learning tasks.

---

## 3. Dataset Characteristics

| Property | Value |
|----------|-------|
| Collection period | June – August 2026 (90 days, ongoing) |
| Time window resolution | ~6 minutes per file |
| Flows per window (total) | 465,000 – 660,000 |
| Tier 1 flows per window | 700 – 1,200 (verified attacks) |
| Tier 2 flows per window | 800 – 1,100 (attacker reconnaissance) |
| Tier 3 flows per window | 5,000 (normal sample) |
| Attack types observed | 300+ distinct port scan and service probe categories |
| Named attack types | SSH-Brute, RDP-Brute, FTP-Brute, HTTP-Probe, HTTPS-Probe, MySQL-Brute, Redis-Probe, MongoDB-Probe, and 15+ others |
| MITRE ATT&CK coverage | T1046, T1110, T1110.001, T1190, T1021.002 |
| Output columns per flow | 30+ |
| Labeling latency | < 6 minutes from flow capture to labeled CSV |

---

## 4. File and Directory Structure

```
/data/flows/
|
|-- raw/
|   |-- nfcapd.202606060110        (NetFlow binary, window 01:10-01:15)
|   |-- nfcapd.202606060115        (NetFlow binary, window 01:15-01:21)
|   `-- nfcapd.current             (Active file, never processed)
|
|-- compressed/
|   `-- nfcapd.202606060104.gz     (Post-processed archive)
|
|-- metadata/
|   |-- dataset_manifest.csv       (Master time-window index)
|   |-- honeypot_hits.csv          (Parsed MikroTik honeypot events)
|   |-- labeling_summary.csv       (Per-file labeling statistics)
|   |-- honeypot_parse_offset.txt  (Byte-offset cursor for log parsing)
|   |-- pipeline.log               (Per-stage operational log)
|   `-- pipeline_cron.log          (Cron-level timing and skip log)
|
|-- labeled/
|   `-- 2026-06-06/
|       |-- nfcapd.202606060110_attacks.csv      (Tier 1)
|       |-- nfcapd.202606060110_suspicious.csv   (Tier 2)
|       `-- nfcapd.202606060110_normal.csv       (Tier 3)
|
`-- scripts/
    |-- pipeline_runner.sh          (Master cron orchestrator)
    |-- parse_honeypot.py           (MikroTik log parser)
    |-- manifest_update.sh          (NetFlow file indexer)
    |-- correlate_honeypot_flows.py (Core labeling engine)
    `-- compress_flows.sh           (Archival compressor)
```

---

## 5. Data Schema Summary

Each labeled CSV contains 30+ features. A complete column reference is in [DATASET_SCHEMA.md](docs/DATASET_SCHEMA.md).

**Raw NetFlow fields:** `flow_start`, `duration_s`, `protocol`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `packets`, `bytes`, `tcp_flags`, `tos`

**Computed rate features:** `bytes_per_sec`, `packets_per_sec`, `bytes_per_packet`

**Binary TCP flag decomposition:** `flag_syn`, `flag_ack`, `flag_fin`, `flag_rst`, `flag_psh`, `flag_urg`

**Categorical features:** `src_port_category`, `dst_port_category`, `flow_duration_class`

**Label columns:** `label`, `attack_type`, `attack_category`, `mitre_technique`, `mitre_tactic`, `confidence`, `evidence_source`, `flow_file`

---

## 6. Usage Recommendations

**Binary Classification (Attack Detection):**
Combine Tier 1 (`_attacks.csv`) as the positive class with Tier 3 (`_normal.csv`) as the negative class. This configuration provides the cleanest possible label quality with 0% label noise in the positive class.

**Multi-Class Attack Classification:**
Use Tier 1 with the `attack_type` column as the target variable. This supports fine-grained classification across brute-force, service probe, web attack, and reconnaissance categories.

**Threat-Hunting and Anomaly Detection:**
Use all three tiers with `label` as a 3-class target (`attack`, `suspicious`, `normal`). This configuration trains models to detect the pre-attack reconnaissance signature of confirmed threat actors — a capability not available in any existing dataset.

**Temporal Analysis:**
Files are organized chronologically by date directory. Researchers can train on earlier windows and evaluate on later ones for realistic temporal generalization testing.

For detailed feature engineering recommendations, class imbalance strategies, and baseline benchmarks, refer to [MACHINE_LEARNING_GUIDE.md](docs/MACHINE_LEARNING_GUIDE.md).

---

## 7. Documentation Index

| Document | Purpose |
|----------|---------|
| [DATASET_SCHEMA.md](docs/DATASET_SCHEMA.md) | Full column reference, MITRE ATT&CK mapping table, and comparison against existing datasets |
| [PIPELINE_ARCHITECTURE.md](docs/PIPELINE_ARCHITECTURE.md) | Technical specification of the 5-stage automated pipeline |
| [RESEARCH_JOURNAL.md](docs/RESEARCH_JOURNAL.md) | Chronological development log covering hypotheses, architectural challenges, and resolutions |
| [MACHINE_LEARNING_GUIDE.md](docs/MACHINE_LEARNING_GUIDE.md) | Guidance for training and evaluating machine learning models on APEX-IDS2026 |

---

## 8. Infrastructure Notes

- **Collection server:** `synapstream` (Linux, x86-64)
- **NetFlow sensor:** MikroTik RouterOS exporting NetFlow v5/v9 to nfcapd
- **Honeypot log source:** `/var/log/honeypot_raw.log` (syslog from MikroTik firewall)
- **Cron schedule:** `*/6 * * * *` with `flock`-based concurrency protection
- **Compression:** `pigz` (parallel gzip) after labeling is confirmed
- **Processing time budget:** 240 seconds maximum per cron cycle to prevent overlap
