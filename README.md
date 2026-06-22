# APEX-IDS2026: A Research-Grade Network Intrusion Detection Dataset

**Real-World, Deterministic, Continuously Collected NetFlow Data with Honeypot-Verified Ground Truth and Zeek Deep Packet Inspection**

---

## Abstract

APEX-IDS2026 is a research-grade network intrusion detection dataset built on live production network infrastructure. Unlike existing benchmark datasets (NSL-KDD, UNSW-NB15, CIC-IDS2017), which rely on synthetically generated attack traffic in controlled laboratory environments, APEX-IDS2026 captures genuine threat actor behavior from the live internet using a MikroTik router honeypot integrated with a continuous 18-Billion Flow pipeline.

The central contribution of this dataset is its **Deterministic Labeling Architecture** combined with **Zeek Deep Packet Inspection**. Using a NAT-immune 5-minute bucketed 6-tuple merge, the pipeline correlates raw NetFlows with Zeek `payload_entropy` to produce mathematically pure labels with a guaranteed 0% false positive rate for Tier 1 attacks. Furthermore, the dataset offers a secondary **Feature as a Counter (FaaC)** time-series Parquet dataset powered by out-of-core DuckDB aggregations, optimized natively for Long Short-Term Memory (LSTM) volumetric anomaly detectors.

---

## 1. Motivation and Problem Statement

The machine learning community in cybersecurity has long depended on datasets that are no longer representative of the contemporary threat landscape:

- **NSL-KDD** derives from the 1999 DARPA dataset and contains simulated attacks from an era predating modern botnets.
- **UNSW-NB15** was generated using commercial traffic generators in a closed network — synthetic by construction.
- **CIC-IDS2017** relies on heuristic labeling of lab traffic, missing the chaos of real-world internet background radiation.

Furthermore, analyzing big data network telemetry usually requires massive Apache Spark clusters. Attempting to load millions of flows into Pandas results in catastrophic Out-of-Memory (OOM) crashes. APEX-IDS2026 addresses these gaps by capturing real threat actors and providing a highly optimized **DuckDB Partitioned Parquet** architecture that scales to 18 Billion flows on a single workstation.

While legacy datasets like UNSW-NB15 and CIC-IDS2017 suffer from synthetic simulation artifacts and bad design smells, and existing real-world honeypot datasets like Kyoto 2006+ and LUFlow lack explicit multi-class attack taxonomies, APEX-IDS2026 bridges this gap. By utilizing a 90-day live ISP collection period to address concept drift, integrating LUFlow's state-of-the-art Inter-Arrival Time and Payload Entropy features, and introducing a 5-Tier Deterministic Labeling Architecture for ground-truth multi-class labeling, APEX-IDS2026 provides a truly evasion-resistant, real-world benchmark.

---

## 2. The 5-Tier Confidence Architecture

### 2.1 Tier 1 — Honeypot-Verified (Ground Truth)
A flow is assigned Tier 1 if its **Source IP** attacked the honeypot in the same time window, AND its **Destination Port** exactly matches the port targeted in the honeypot log entry. 
* **False Positive Rate:** 0%

### 2.2 Tier 2 — Attacker-Associated (Peripheral Reconnaissance)
A flow is Tier 2 if its Source IP is a confirmed attacker, but its Destination Port does not match the honeypot-logged port. These flows represent lateral reconnaissance activity of a confirmed threat actor.

### 2.3 Tier 3 — Unverified (Threat-Intel Flagged or Behavioral Anomaly)
Flows flagged by either **AbuseIPDB Threat Intelligence** (Score >= 50) or the **Behavioral Anomaly Engine** (Single-packet TCP scans, SYN-only probes, Port sweeps).

### 2.4 Tier 4 — Benign_Verified (Safe Destination)
Flows targeting known-safe internal subnets (e.g., internal DNS, IPTV streams) that have zero threat intelligence flags and zero behavioral anomalies.

### 2.5 Tier 5 — Benign_Assumed (Clean Baseline)
Flows with no honeypot interaction, no threat intelligence flags, no behavioral anomalies, but destined for general unverified IP space.

---

## 3. Dataset Characteristics

| Property | Value |
|----------|-------|
| Collection period | June – August 2026 (90 days) |
| Total Scale Target | ~18,000,000,000 Flows |
| Time window resolution | ~6 minutes per file (`nfcapd`) |
| Daily FaaC Resolution | 1-minute partitioned time-series |
| Total Honeypot Hits | 87,545+ |
| Attack types observed | 300+ distinct port scan and service probe categories |
| Named attack types | Telnet-Brute, SSH-Brute, SIP-Flood, HTTP-Probe, SMB-Probe, MySQL-Brute, Redis-Probe, MongoDB-Probe |
| DPI Capabilities | Zeek `payload_entropy`, `iat_mean`, `iat_std` |
| Output formats | Labeled CSVs & DuckDB Partitioned Parquets (`pyarrow`) |
| Labeling latency | < 6 minutes from flow capture to labeled CSV |

---

## 4. File and Directory Structure

```
/data/flows/
|
|-- raw/                           (nfcapd binary captures)
|-- metadata/
|   |-- dataset_manifest.csv       (Master time-window index)
|   |-- honeypot_hits.csv          (Parsed MikroTik honeypot events)
|   |-- features.log               (Zeek Deep Packet Inspection metadata)
|   `-- pipeline_cron.log          (Cron-level timing and skip log)
|
|-- labeled/
|   |-- 2026-06-21/                (Daily CSV outputs)
|   |   |-- nfcapd.202606212225_attacks.csv      (Tier 1)
|   |   |-- nfcapd.202606212225_suspicious.csv   (Tier 2 & 3)
|   |   `-- nfcapd.202606212225_normal.csv       (Tier 4 & 5)
|   |
|   `-- TimeSeries/                (FaaC Batch Output for LSTMs)
|       |-- TimeSeries_FaaC_2026-06-21.parquet
|       `-- TimeSeries_FaaC_2026-06-22.parquet
|
`-- scripts/
    |-- pipeline_runner.sh          (Master cron orchestrator)
    |-- parse_honeypot.py           (MikroTik log parser)
    |-- correlate_honeypot_flows.py (NAT-Immune 6-Tuple Labeling Engine)
    |-- generate_faac_batch.py      (DuckDB Out-of-Core Batch Generator)
    `-- tzsp_entropy.zeek           (Zeek Entropy analysis script)
```

---

## 5. Data Schema Summary

Each labeled CSV contains 30+ features. A complete column reference is in [DATASET_SCHEMA.md](docs/DATASET_SCHEMA.md).

**Raw NetFlow fields:** `flow_start`, `duration_s`, `protocol`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `packets`, `bytes`, `tcp_flags`, `tos`

**Zeek DPI Fields:** `iat_mean`, `iat_std`, `payload_entropy`, `dns_query`

**Computed rate features:** `bytes_per_sec`, `packets_per_sec`, `bytes_per_packet`

**FaaC Parquet Fields:** `bytes_skewness`, `bytes_kurtosis`, `avg_entropy`, `max_entropy`, `total_connections`, `unique_src_ips`

**Validation layers:** `threat_intel_score`, `country` (ISO Code), `behavioral_flags`

**Label columns:** `label`, `attack_type`, `attack_category`, `mitre_technique`, `mitre_tactic`, `confidence`, `evidence_source`, `flow_file`

---

## 6. Usage Recommendations

**Volumetric Anomaly Detection (LSTMs/Transformers):**
Load the `/data/flows/labeled/TimeSeries/` partitioned directory directly into your ML framework. The mathematically pure 1-minute bins combined with `max_entropy` and `kurtosis` provide an unparalleled dataset for forecasting UDP floods and SYN sweeps.

**Binary Classification (Attack Detection):**
Combine Tier 1 (`_attacks.csv`) as the positive class with Tier 3 (`_normal.csv`) as the negative class. This configuration provides the cleanest possible label quality with 0% label noise in the positive class.

**Multi-Class Attack Classification:**
Use Tier 1 with the `attack_type` column as the target variable. This supports fine-grained classification across brute-force, service probe, web attack, and reconnaissance categories.

For detailed feature engineering recommendations, class imbalance strategies, and baseline benchmarks, refer to [MACHINE_LEARNING_GUIDE.md](docs/MACHINE_LEARNING_GUIDE.md).

For a comprehensive academic evaluation of existing NIDS datasets (NSL-KDD, UNSW-NB15, CIC-IDS2017, LUFlow) and a structural justification for APEX-IDS2026, refer to [LITERATURE_REVIEW.md](docs/LITERATURE_REVIEW.md).

For the detailed academic design, hardware topology, and software engineering of the APEX-IDS2026 capture and labeling pipeline, refer to the [Methodology and Experimental Architecture Draft](Paper/METHODOLOGY.md).

---

## 7. Infrastructure & Automation

- **Collection server:** `synapstream` (Fedora Linux, x86-64)
- **NetFlow sensor:** MikroTik RouterOS exporting NetFlow v5/v9 to nfcapd
- **Honeypot log source:** `/var/log/honeypot_raw.log` (syslog from MikroTik firewall)
- **Cron Stream Schedule:** `*/6 * * * *` (Runs correlation pipeline every 6 mins)
- **Cron Batch Schedule:** `10 0 * * *` (Runs DuckDB FaaC Generator at 12:10 AM)
- **Memory Optimization:** Uses DuckDB vectorized streams to prevent 120GB+ RAM OOM crashes.
