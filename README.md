# APEX-IDS2026: A Research-Grade Network Intrusion Detection Dataset

**Real-World, Deterministic, Continuously Collected NetFlow Data with Honeypot-Verified Ground Truth**

---

## Abstract

APEX-IDS2026 is a research-grade network intrusion detection dataset built on live production network infrastructure. Unlike existing benchmark datasets (NSL-KDD, UNSW-NB15, CIC-IDS2017), which rely on synthetically generated attack traffic in controlled laboratory environments, APEX-IDS2026 captures genuine threat actor behavior from the live internet using a MikroTik router honeypot integrated with a continuous NetFlow collection pipeline.

The central contribution of this dataset is its **5-Tier Deterministic Labeling Architecture**, which uses port-based correlation between honeypot event logs and nfcapd binary captures to produce ground-truth labels that carry a mathematically guaranteed 0% false positive rate for Tier 1 (Honeypot-Verified) flows. This is further validated by a Behavioral Anomaly Engine and Threat Intelligence integrations (AbuseIPDB), making this the first self-sustaining, longitudinal IDS dataset designed for continuous academic use.

---

## 1. Motivation and Problem Statement

The machine learning community in cybersecurity has long depended on datasets that are no longer representative of the contemporary threat landscape:

- **NSL-KDD** derives from the 1999 DARPA dataset and contains simulated attacks from an era predating modern botnets, ransomware, and large-scale internet scanning campaigns.
- **UNSW-NB15** was generated over 31 hours using the IXIA PerfectStorm commercial traffic generator in a closed network — synthetic by construction.
- **CIC-IDS2017** uses CICFlowMeter-based heuristic labeling on 5 days of lab traffic, where the "attackers" were researchers executing scripts on isolated virtual machines.

Training intrusion detection models on such data produces classifiers that generalize poorly to real-world deployments. Network flows on a live internet-facing server exhibit structural properties — timing distributions, flag combinations, packet-to-byte ratios, and port scan diversity — that are qualitatively different from those produced by simulation tools.

APEX-IDS2026 addresses this gap by capturing flows from live threat actors and providing labels anchored to hardware-level honeypot evidence rather than statistical heuristics.

---

## 2. The 5-Tier Confidence Architecture

### 2.1 Tier 1 — Honeypot-Verified (Ground Truth)

| Field | Value |
|-------|-------|
| `label` | `Attack_Verified` |
| `confidence` | `honeypot-verified` |
| `evidence_source` | `honeypot:port-match` |
| **False Positive Rate** | **0%** |

A flow is assigned Tier 1 if its **Source IP** attacked the honeypot in the same time window, AND its **Destination Port** exactly matches the port targeted in the honeypot log entry. The label is a direct, deterministic consequence of hardware-level logging.

### 2.2 Tier 2 — Attacker-Associated (Peripheral Reconnaissance)

| Field | Value |
|-------|-------|
| `label` | `Attack_Associated` |
| `confidence` | `attacker-associated` |
| `evidence_source` | `honeypot:port-mismatch` |

A flow is Tier 2 if its Source IP is a confirmed attacker (Tier 1 criteria satisfied on another port) but its Destination Port does not match the honeypot-logged port. These flows represent the lateral reconnaissance activity of a confirmed threat actor.

### 2.3 Tier 3 — Unverified (Threat-Intel Flagged or Behavioral Anomaly)

| Field | Value |
|-------|-------|
| `label` | `Unverified` |
| `confidence` | `threat-intel-flagged` OR `behavioral-anomaly` |

Flows that did *not* hit the honeypot but were flagged by either:
1. **AbuseIPDB Threat Intelligence** (Score >= 50)
2. **Behavioral Anomaly Engine** (Single-packet TCP scans, SYN-only probes, Port sweeps, or Network sweeps)

This tier catches "stealth" scanners and known-bad IPs that would otherwise pollute the benign dataset.

### 2.4 Tier 4 — Benign_Verified (Safe Destination)

| Field | Value |
|-------|-------|
| `label` | `Benign_Verified` |
| `confidence` | `destination-verified` |

Flows targeting known-safe internal subnets or specific services (e.g., internal DNS, IPTV streams) that have zero threat intelligence flags and zero behavioral anomalies.

### 2.5 Tier 5 — Benign_Assumed (Clean Baseline)

| Field | Value |
|-------|-------|
| `label` | `Benign_Assumed` |
| `confidence` | `no-threat-indicators` |

Flows with no honeypot interaction, no threat intelligence flags, no behavioral anomalies, but destined for general unverified IP space.

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
| Output columns per flow | 33 (including country code & threat intel) |
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

**Validation layers:** `threat_intel_score`, `country` (ISO Code), `behavioral_flags`

**Label columns:** `label`, `attack_type`, `attack_category`, `mitre_technique`, `mitre_tactic`, `confidence`, `evidence_source`, `flow_file`

---

## 6. Usage Recommendations

**Binary Classification (Attack Detection):**
Combine Tier 1 (`_attacks.csv`) as the positive class with Tier 3 (`_normal.csv`) as the negative class. This configuration provides the cleanest possible label quality with 0% label noise in the positive class.

**Multi-Class Attack Classification:**
Use Tier 1 with the `attack_type` column as the target variable. This supports fine-grained classification across brute-force, service probe, web attack, and reconnaissance categories.

**Threat-Hunting and Anomaly Detection:**
Use all tiers with `label` as a 5-class target. This configuration trains models to detect the pre-attack reconnaissance signature of confirmed threat actors and identify stealthy scanners caught by behavioral rules.

**Geographic Analysis:**
Utilize the `country` column to map the geographic origin of verified attacks compared to benign traffic.

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

- **Collection server:** Fedora Server (Linux, x86-64)
- **NetFlow sensor:** MikroTik RouterOS exporting NetFlow v5/v9 to nfcapd
- **Honeypot log source:** `/var/log/honeypot_raw.log` (syslog from MikroTik firewall)
- **Cron schedule:** `*/6 * * * *` with `flock`-based concurrency protection
- **Compression:** `pigz` (parallel gzip) after labeling is confirmed
- **Processing time budget:** 240 seconds maximum per cron cycle to prevent overlap
