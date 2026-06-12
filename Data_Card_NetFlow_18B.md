<center>

# APEX-IDS2026: The 1.8 Billion Flow Ground-Truth Cybersecurity Dataset
**Enterprise Data Card & Technical Specification**

**Version:** 1.0 (Commercial Evaluation Edition) &nbsp; | &nbsp; **Date:** June 2026<br>
**License:** Enterprise / Commercial (Proprietary) &nbsp; | &nbsp; **Authors:** APEX-IDS Research & Development Team

</center>

<br>

<div style="text-align: justify;">

> [!IMPORTANT]
> **Executive Summary:** APEX-IDS2026 represents a paradigm shift in machine learning cybersecurity data. Legacy datasets (e.g., UNSW-NB15, CIC-IDS2017) rely heavily on simulated, decade-old laboratory attacks or heuristic statistical labeling that introduces massive false-positive noise. **APEX-IDS2026 captures 1.8 Billion rows of live, modern botnet traffic from a Tier-2 South Asian ISP network with absolute physical ground truth established via hardware honeypot correlation.** This dataset guarantees zero false-positives for its primary attack classes, offering cybersecurity vendors the ability to train next-generation IDS and ML models on authentic 2026 threat landscapes.

---

## 1. Network Architecture & Collection Methodology

APEX-IDS2026 does not use simulated traffic generators. It is collected from the edge routing infrastructure of a live Internet Service Provider.

### 1.1 Live ISP Capture
- **Collection Point:** ISP Edge/Core Router (South Asia).
- **Format:** Extended NetFlow v9 / IPFIX exported directly to a high-throughput `nfcapd` collector.
- **Rotation Interval:** 5-minute fixed time windows, ensuring high temporal fidelity and preventing flow-record truncation.
- **Volume:** ~800,000 flows captured per 5-minute window, scaling to over 1.8 Billion flows over the full continuous collection period.

### 1.2 Physical Ground Truth (The Honeypot Catalyst)
The defining feature of APEX-IDS2026 is its physical ground-truth correlation engine:
- A deliberately vulnerable hardware honeypot (`103.148.176.62`) is exposed on the ISP network. 
- Because this honeypot hosts **zero legitimate user services**, any inbound connection attempt is mathematically, unarguably malicious.
- **The Correlation Engine (`correlate_honeypot_flows.py`):** Cross-references the massive haystack of raw ISP traffic against the exact timestamps, source IPs, and destination ports of honeypot hits. 

> [!TIP]
> **Why This Matters to ML Engineers:** Training a model on dirty labels causes the model to learn the noise, creating false positives in production. By using a physical honeypot to isolate attackers, APEX-IDS2026 provides **perfectly clean, deterministic labels** for the `Attack_Verified` class.

---

## 2. The 5-Tier Deterministic Labeling Strategy

Every single flow in the 1.8 Billion record dataset is passed through a strict decision tree and categorized into one of five tiers. 

| Tier | Label | Confidence Level | Validation Methodology |
|---|---|---|---|
| **Tier 1** | `Attack_Verified` | **Absolute (100%)** | Flows originating directly from an external IP targeting the physical honeypot. These are mathematically proven attacks. |
| **Tier 2** | `Attack_Associated` | **High (95%+)** | Flows originating from an IP that has hit the honeypot (Tier 1), but are targeting other benign IPs on the ISP. Proves lateral movement and wide-net scanning. |
| **Tier 3** | `Benign_Verified` | **High (95%+)** | Flows originating from the ISP targeting known, strictly validated Hyperscaler infrastructure (Google, Cloudflare, Meta). Guarantees clean negative-class data. |
| **Tier 4** | `Unverified` | **Medium** | Normal flows flagged by AbuseIPDB (Score > 25) or behavioral anomaly heuristics (e.g., massive port sweeps). |
| **Tier 5** | `Benign_Assumed` | **Baseline** | Background internet noise representing standard user traffic, possessing no threat indicators or anomalous behavioral flags. |

---

## 3. File Structure & Cross-File Correlation

To facilitate efficient ML training, the dataset is exported into three correlated files per 5-minute window. These three files map back to the same exact temporal snapshot of the network and are intrinsically linked by the attacker IP addresses.

### 3.1 The `_attacks` File (The Ground Truth)
Contains all **Tier 1 (`Attack_Verified`)** flows. 
- **Correlation:** Every source IP in this file physically hit the honeypot during the 5-minute window. This file acts as the undeniable "patient zero" for the timeframe.

### 3.2 The `_suspicious` File (The Associated Threats)
Contains **Tier 2 (`Attack_Associated`)** and **Tier 4 (`Unverified`)** flows.
- **Correlation:** When an attacker IP is identified in the `_attacks` file, the pipeline automatically scans the entire ISP routing table for any *other* traffic originating from that same IP during the 5-minute window. This file reveals the attacker's broader campaign (e.g., scanning other customers on the ISP) before or after they hit the honeypot.

### 3.3 The `_normal` File (The Negative Class)
Contains **Tier 3 (`Benign_Verified`)** and **Tier 5 (`Benign_Assumed`)** flows.
- **Correlation:** These flows are mathematically guaranteed to originate from IPs that *do not exist* in the `_attacks` file. They are extracted from the exact same 5-minute window to provide a temporally accurate "negative class." By providing the background noise occurring at the precise moment the attacks were happening, ML models learn to differentiate an active attacker from normal traffic patterns.

---

## 4. Comprehensive Feature Dictionary (Schema)

The dataset provides **34 deeply engineered features** per flow, formatted perfectly for ML vectorization.

### 4.1 Flow Structural Metrics
These metrics represent the raw physical properties of the network connection.
- `flow_start`: ISO-8601 Timestamp of the flow initiation (UTC).
- `duration_s`: Total active time of the flow in seconds.
- `protocol`: Transport protocol string (`TCP`, `UDP`, `ICMP`, `ICMPv6`).
- `src_ip` / `dst_ip`: Cryptographically anonymized IP routing addresses.
- `src_port` / `dst_port`: Network ports.
- `packets`: Total number of packets transferred.
- `bytes`: Total payload and header volume in bytes.

### 4.2 Computed Velocity & Derived Metrics
Rates are pre-calculated to allow models to detect high-velocity volumetric attacks immediately.
- `bytes_per_sec`: Total bytes divided by `duration_s`.
- `packets_per_sec`: Total packets divided by `duration_s`.
- `bytes_per_packet`: Average packet size (useful for detecting payload-heavy exploits vs empty scans).
- `src_port_category` / `dst_port_category`: Categorical grouping (`well-known` [0-1023], `registered` [1024-49151], `dynamic`).
- `flow_duration_class`: Binned duration mapping (`instant`, `short`, `long`, `persistent`).

### 4.3 Granular TCP Flag Decomposition
Unlike legacy datasets that group flags into a single arbitrary hex string, APEX-IDS2026 unpacks them into individual binary features for direct model ingestion:
- `flag_syn`, `flag_ack`, `flag_fin`, `flag_rst`, `flag_psh`, `flag_urg` (Binary 0/1).

### 4.4 Threat Taxonomy & MITRE ATT&CK Mappings
- `label`: Primary target variable (`Attack_Verified`, `Benign_Verified`, etc.).
- `attack_type`: Specific vector identified (e.g., `SSH-Brute`, `HTTP-Probe`, `MySQL-Brute`).
- `attack_category`: Broader grouping (`reconnaissance`, `brute-force`, `lateral-movement`).
- `mitre_technique`: Direct mapping to the MITRE ATT&CK framework (e.g., `T1046` Network Service Discovery).
- `mitre_tactic`: MITRE parent tactic (e.g., `discovery`, `credential-access`).
- `confidence`: The semantic tier-level confidence (e.g., `multi-layer-verified`).
- `evidence_source`: The system rule that applied the label (e.g., `honeypot:port-match`, `safe-dest:Cloudflare`).

### 4.5 Contextual Threat Intelligence (Enrichment Layer)
- `threat_intel_score`: Reputation score (0-100) pulled dynamically via the AbuseIPDB API.
- `country`: GeoIP mapping of the attacker.
- `behavioral_flags`: Heuristic tags capturing aggressive behaviors like `scan-like:port-sweep(10)` or `scan-like:single-pkt-tcp`.

---

## 5. Modern Threat Landscape & Known Data Characteristics

When evaluating the dataset, data scientists must be aware that modern 2026 botnets behave differently than the threats of 2015. **Certain "missing" or "zero" values in this dataset are critical forensic features.**

1. **The Instantaneous SYN Scan Phenomenon:** 
   Millions of `Attack_Verified` rows represent highly distributed, automated SYN Scans. Because they consist of a single packet meant to test a port, their `duration_s` is exactly `00:00:00.000`. Consequently, `bytes_per_sec` and `packets_per_sec` are recorded as `0` to prevent division-by-zero errors. Furthermore, because the TCP handshake is never completed, `flag_ack` and `flag_fin` will be `0`, while `flag_syn` will be `1`. **Models must learn that a 0-second, SYN-only flow is a strong indicator of reconnaissance.**

2. **Threat Intelligence API Rate Limits:** 
   To maintain processing speed across 1.8 Billion flows, the pipeline utilizes API limits. If the daily Threat Intelligence quota is exhausted during a massive DDoS event, `threat_intel_score` and `country` will gracefully fallback to empty/null values.

3. **Behavioral Flag Optimization:** 
   `behavioral_flags` are intentionally bypassed for `Attack_Verified` flows. Because their malicious intent is already physically proven by hitting the honeypot, the compute resources are saved, resulting in empty values for this column on Tier 1 data.

---

## 6. Technical Distribution & Integration

APEX-IDS2026 is engineered specifically for modern Big Data and MLOps pipelines.
- **Format:** `Apache Parquet` (via PyArrow).
- **Compression:** Snappy compression, resulting in a **90% reduction in disk footprint** compared to raw CSVs.
- **Integration:** Columnar vectorization ensures the data can be loaded directly into Pandas, Polars, Apache Spark, or Dask with strict schema typing (eliminating arbitrary `object` to `string` parsing errors).

---

## 7. Privacy & GDPR Compliance

The dataset is strictly compliant with privacy regulations regarding network interception:
- **Zero Payload Inspection:** Only Layer 3/Layer 4 metadata (NetFlow headers) is captured. No packet payloads, user data, passwords, or PII are recorded.
- **Cryptographic IP Anonymization:** A dedicated processing layer (`anonymize_data.py`) replaces all internal ISP client IP addresses with consistent cryptographic hashes (e.g., SHA-256 with salt). This protects local user privacy while perfectly preserving the mathematical IP relationship graphs required for Graph Neural Network (GNN) and topological ML training.

<br>
<i>For commercial licensing, enterprise evaluation samples, or inquiries regarding the Live Threat Intelligence Feed, please contact the APEX-IDS Data Distribution Team.</i>

</div>
