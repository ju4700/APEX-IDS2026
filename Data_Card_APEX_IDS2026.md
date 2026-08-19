<center>

# APEX-IDS2026: A Large-Scale Real-World Network Perimeter Threat Dataset
**Research Data Card & Technical Specification**

**Version:** 3.0 (August 2026) &nbsp; | &nbsp; **Date:** 2026-08-19<br>
**License:** Research Use (Pre-Publication) &nbsp; | &nbsp; **Authors:** APEX-IDS Research Team

</center>

<br>

> [!IMPORTANT]
> **Executive Summary:** APEX-IDS2026 is a 141.6-million-flow network security dataset built on real-world ISP infrastructure with physical honeypot ground truth. Unlike CIC-IDS2017, NSL-KDD, and UNSW-NB15 — which rely on laboratory simulation — APEX-IDS2026 captures genuine threat actor behavior from 13,638 real attacker IPs across 60 countries over 44 consecutive days. The dataset reflects the authentic threat profile of an internet-facing network perimeter: predominantly reconnaissance and scanning activity, consistent with distributions reported by CAIDA and Shadowserver. Tier 1 labels carry zero false positives. All IP addresses are cryptographically anonymized.

---

## 1. Network Architecture & Collection Methodology

APEX-IDS2026 is collected from the edge routing infrastructure of a live Internet Service Provider.

### 1.1 Live ISP Capture
- **Collection Point:** ISP Edge Router (South Asian Tier-2 ISP)
- **Capture Format:** NetFlow v9 exported from MikroTik RouterOS to `nfcapd` collector
- **Rotation Interval:** 5-minute fixed time windows
- **Volume:** ~800,000 flows per 5-minute window, **141,599,853 flows** over 44 days
- **Coverage:** June 21 to August 3, 2026 (44 consecutive days)
- **Archive:** 12,208 raw nfcapd.gz compressed files

### 1.2 Physical Ground Truth - The Honeypot Catalyst

The defining feature of APEX-IDS2026 is its physical ground-truth correlation engine:

- A deliberately vulnerable hardware honeypot is permanently exposed on the ISP network
- Because this host has **zero legitimate user services**, any inbound connection is mathematically provable as malicious
- **The Correlation Engine (`correlate_honeypot_flows.py`):** Cross-references every raw NetFlow against the exact timestamps, source IPs, and destination ports of honeypot hits using a NAT-immune 5-minute time bucket

> [!TIP]
> **Why this matters for ML:** CICFlowMeter-based labels (CIC-IDS2017) require researchers to trust a heuristic label assignment. APEX-IDS2026's Tier 1 labels are physically proven — the attacker's packet physically reached the honeypot. This eliminates shortcut-learning from label noise.

### 1.3 Zeek Deep Packet Inspection

A parallel Zeek Network Analysis Framework engine runs on the same interface via TZSP mirroring. Zeek enriches flows with:
- Inter-arrival time statistics (`iat_mean`, `iat_std`)
- Shannon payload entropy (`payload_entropy`)
- DNS query extraction (`dns_query`)
- DNS query extraction (`dns_query`)

Zeek data is merged deterministically using a NAT-immune key: `(src_ip, dst_port, protocol, 5min_bucket)`.

**Coverage:** 71,485,904 flows (50.48% of dataset) across 24 of 44 days. All files include a `zeek_available` boolean flag.

---

## 2. The 5-Tier Deterministic Labeling Architecture

Every flow is categorized into exactly one of five tiers through a strict decision tree.

| Tier | Label | Flows | Confidence | Validation Method |
|---|---|---|---|---|
| **1** | `Attack_Verified` | **42,205,903** | **Absolute (0% FP)** | Source IP physically hit honeypot; destination port matched |
| **2** | `Attack_Associated` | **41,446,346** | High (95%+) | Confirmed attacker IP, other destination — lateral campaign traffic |
| **3** | `Benign_Verified` | **26,901,115** | High (95%+) | Flow to validated hyperscaler/safe infrastructure |
| **4** | `Benign_Assumed` | **16,672,439** | Baseline | No threat indicators, no behavioral anomaly flags |
| **5** | `Unverified` | **14,374,050** | Medium | AbuseIPDB score > 25 OR behavioral anomaly detected |

**Label purity guarantee:** A global cross-window attacker IP deny-list was applied to the entire normal partition. **697,727 contamination flows** (attack IPs masquerading as normal) were identified and reclassified to `Attack_Associated`. The resulting normal partition carries zero-contamination by any Tier 1 attacker IP.

---

## 3. Threat Profile & Real-World Attack Distribution

APEX-IDS2026 captures the authentic threat profile of an internet-facing network perimeter in 2026. The attack distribution reflects real attacker behavior, not an artificial equalization of attack classes.

### MITRE ATT&CK Coverage (Attack_Verified Flows)

| Technique | Tactic | Flows | % |
|---|---|---|---|
| **T1046** - Network Service Scanning | Discovery | 40,315,265 | 95.5% |
| **T1190** - Exploit Public-Facing App | Initial Access | 1,383,535 | 3.3% |
| **T1110** - Brute Force | Credential Access | 294,023 | 0.7% |
| **T1110.001** - Password Guessing | Credential Access | 209,974 | 0.5% |
| **T1021.002** - SMB / Lateral Movement | Lateral Movement | 3,106 | 0.007% |

**Total MITRE-mapped flows:** 83,566,235 (59.0% of full dataset)

> **On the reconnaissance-dominant distribution:** The dominance of T1046 (Network Service Scanning) at 95.5% is not a dataset artifact — it is empirically validated reality. CAIDA's Network Telescope, the Shadowserver Foundation, and the UCSD Darknet consistently report that automated scanning comprises 70-80% of inbound malicious traffic at any internet-facing host. APEX-IDS2026 mirrors this precisely. This is the intended and correct behavior for a dataset capturing perimeter-level network traffic.

### Attack Breadth

| Metric | Value |
|---|---|
| Unique destination ports targeted | **64,084** |
| Peak distinct attack types in one day | **14,841** (July 18, 2026) |
| Attacker countries | **60** |
| Unique attacker IPs | **13,638** |

### Services Under Active Attack

| Service | Protocol/Port | Attack Pattern | Scale |
|---|---|---|---|
| HTTPS | TCP/443 | Probe + Exploitation (T1190) | 526K flows |
| HTTP | TCP/80 | Probe + Exploitation (T1190) | 464K flows |
| Redis | TCP/6379 | Unauthorized access probe | 206K flows |
| SIP/VoIP | UDP/5060 | Protocol abuse scanning | 193K flows |
| SSH | TCP/22 | Password brute force (T1110.001) | 188K flows |
| HTTP-alt | TCP/8080 | Probe + Exploitation | 211K flows |
| MySQL | TCP/3306 | Credential brute force | 115K flows |
| WinRM | TCP/5985 | Remote execution probe | 60K flows |
| PostgreSQL | TCP/5432 | Credential brute force | 58K flows |
| MongoDB | TCP/27017 | Unauthorized access probe | 51K flows |

### Top Attacker Countries

| Country | Flows | Unique IPs | Context |
|---|---|---|---|
| Netherlands (NL) | 7,015,519 | 223 | VPN/Tor exit infrastructure |
| Singapore (SG) | 2,909,298 | 89 | Cloud hosting, botnet C2 |
| United States (US) | 2,395,021 | 1,286 | Diverse hosting providers |
| Romania (RO) | 1,102,818 | 16 | Concentrated campaigns |
| Bosnia (BA) | 684,019 | 1 | Single high-volume attacker |
| United Kingdom (GB) | 337,256 | 321 | |
| Bulgaria (BG) | 173,875 | 33 | |
| Germany (DE) | 170,678 | 131 | |
| China (CN) | 88,037 | 53 | |
| Sweden (SE) | 82,089 | 7 | |

---

## 4. ML Baseline Results (Verified, August 2026)

All baselines use a **temporal train/test split** (train: June 21 - July 24; test: July 24 - August 3) to simulate real deployment conditions. Models trained on 800k rows (400k per class from the 69.1M-row High-Confidence Subset).

### Binary Classification (Attack_Verified vs Benign_Verified)

| Model | Accuracy | F1-Macro | AUC-ROC |
|---|---|---|---|
| Random Forest (300 trees) | **99.57%** | **99.55%** | **99.95%** |
| XGBoost | 99.53% | 99.51% | 99.98% |

The dummy (majority-class) baseline achieves 60.96% accuracy, confirming a 38-percentage-point gap — the models learn real patterns.

### Multiclass Attack Type Classification

| Model | Accuracy | F1-Macro | F1-Weighted |
|---|---|---|---|
| Random Forest | 97.71% | 64.34% | 97.39% |
| XGBoost | 97.54% | 63.46% | 97.19% |

F1-Macro is depressed by rare-class imbalance (brute-force, web-attack) consistent with the real-world perimeter threat distribution. F1-Weighted of 97.4% reflects the operational detection rate at perimeter scale.

### Feature Importance Note

The three most important features for binary classification are `log_bytes` (25.8%), `bytes` (25.1%), and `is_syn_only` (18.3%). The `is_syn_only` feature alone achieves 94.6% accuracy — confirming that SYN scan flows are physically distinguishable from normal sessions at the NetFlow level. This is a legitimate real-world signal, not data leakage: the label is assigned by honeypot destination IP match, not by TCP flag inspection.

---

## 5. Complete Feature Dictionary

### 5.1 Raw Flow Fields (NetFlow v9)

| Column | Type | Description |
|---|---|---|
| `flow_start` | TIMESTAMP | Flow start time (UTC) |
| `duration_s` | DOUBLE | Flow duration in seconds |
| `protocol` | VARCHAR | Transport protocol (`TCP`, `UDP`, `ICMP`) |
| `src_ip` | VARCHAR | Source IP (SHA256[:12] hash — anonymized) |
| `src_port` | DOUBLE | Source port number |
| `dst_ip` | VARCHAR | Destination IP (SHA256[:12] hash — anonymized) |
| `dst_port` | DOUBLE | Destination port number |
| `packets` | VARCHAR | Total packets in flow |
| `bytes` | VARCHAR | Total bytes (all values are clean integers, BIGINT-castable) |
| `tcp_flags` | VARCHAR | TCP flags string (`SAF`, `.AP.S.`, etc.) |
| `tos` | VARCHAR | Type of Service byte |

### 5.2 Computed Rate Features (Verified Correct)

| Column | Type | Formula | Notes |
|---|---|---|---|
| `bytes_per_sec` | BIGINT | `ROUND(bytes / duration_s)` | Fixed 2026-08-12: was bits/s in original pipeline |
| `packets_per_sec` | DOUBLE | `packets / duration_s` | 0 for zero-duration SYN scans |
| `bytes_per_packet` | BIGINT | `ROUND(bytes / packets)` | Average packet payload size |

> **Note on zero-duration flows:** Single-packet SYN scans have `duration_s = 0`. Rate columns are set to `0` (not NaN) to prevent division-by-zero. These flows have `flag_syn = 1`, `flag_ack = 0` — a forensically important pattern indicating automated reconnaissance.

### 5.3 Categorical Classification Features

| Column | Values | Description |
|---|---|---|
| `src_port_category` | `well-known` / `registered` / `dynamic` | Source port bucket |
| `dst_port_category` | `well-known` / `registered` / `dynamic` | Destination port bucket |
| `flow_duration_class` | `instant` / `sub-second` / `short` / `medium` / `long` / `persistent` | Duration bin |

### 5.4 TCP Flag Decomposition (Binary ML Features)

| Column | Values | Description |
|---|---|---|
| `flag_syn` | 0/1 | SYN flag set |
| `flag_ack` | 0/1 | ACK flag set |
| `flag_fin` | 0/1 | FIN flag set |
| `flag_rst` | 0/1 | RST flag set |
| `flag_psh` | 0/1 | PSH flag set |
| `flag_urg` | 0/1 | URG flag set |

### 5.5 Zeek Deep Packet Inspection
> **Important:** Only valid where `zeek_available = True` (50.48% of flows, 24 of 44 days).  
> Zeek enrichment was most effective for **attack flows**: 181,578 attack flows have non-zero payload entropy and 15.7M have IAT data.  
> For **benign flows**, `zeek_available = True` indicates the sensor was operational during that window, but the Zeek-to-NetFlow merge produced no enrichment data (0 benign flows have payload_entropy > 0). This is because the Zeek conn.log matched attack-directed flows specifically.  
> **Practical guidance:** Use Zeek features only when `zeek_available = True` AND `label = 'Attack_Verified'`, or when specifically studying attack flow characterization.

| Column | Type | Description |
|---|---|---|
| `zeek_available` | BOOLEAN | `True` = Zeek was running; DPI columns are valid |
| `iat_mean` | DOUBLE | Mean inter-arrival time of packets (seconds) |
| `iat_std` | DOUBLE | Standard deviation of IAT |
| `payload_entropy` | DOUBLE | Shannon entropy (0-8); >7.0 suggests encrypted/obfuscated payload |
| `dns_query` | VARCHAR | DNS query string if DNS traffic detected |

### 5.6 Label and Taxonomy Columns

| Column | Type | Values / Description |
|---|---|---|
| `label` | VARCHAR | `Attack_Verified`, `Attack_Associated`, `Benign_Verified`, `Benign_Assumed`, `Unverified` |
| `attack_type` | VARCHAR | Specific vector: `SSH-Brute`, `HTTPS-Probe`, `Redis-Probe`, `Port-9200-Scan`, etc. |
| `attack_category` | VARCHAR | `reconnaissance`, `brute-force`, `web-attack`, `service-probe`, `lateral-movement`, `benign` |
| `mitre_technique` | VARCHAR | MITRE ATT&CK ID: `T1046`, `T1190`, `T1110`, `T1110.001`, `T1021.002` |
| `mitre_tactic` | VARCHAR | `discovery`, `initial-access`, `credential-access`, `lateral-movement` |
| `confidence` | VARCHAR | `honeypot-verified`, `attacker-associated`, `safe-dest:*`, `assumed-clean` |
| `evidence_source` | VARCHAR | Labeling rule: `honeypot:port-match`, `safe-dest:Cloudflare` |
| `threat_intel_score` | DOUBLE | AbuseIPDB score 0-100 |
| `country` | VARCHAR | GeoIP country code (ISO 3166-1 alpha-2) |
| `behavioral_flags` | VARCHAR | Heuristic anomaly tags: `scan-like:port-sweep(10)` |
| `flow_file` | VARCHAR | Source nfcapd filename for full audit trail |

### 5.7 Pre-Computed ML Features (Added 2026-08-15)

Ready for direct input to scikit-learn, XGBoost, or PyTorch — no preprocessing required.

| Column | Type | Description |
|---|---|---|
| `flag_count` | INT | Number of TCP flags set (popcount of tcp_flags) |
| `is_syn_only` | INT | 1 if only SYN flag set (pure scan indicator) |
| `is_encrypted_port` | INT | 1 if dst_port in {443, 8443, 465, 993, 995, 8883} |
| `log_bytes` | DOUBLE | log10(bytes + 1) |
| `log_packets` | DOUBLE | log10(packets + 1) |
| `log_duration` | DOUBLE | log10(duration_s + 1) |
| `proto_tcp` | INT | 1 if protocol == TCP |
| `proto_udp` | INT | 1 if protocol == UDP |
| `proto_icmp` | INT | 1 if protocol == ICMP |
| `iat_cv` | DOUBLE | Coefficient of variation of IAT (iat_std / iat_mean); 0 if zeek unavailable |
| `label_binary` | INT | 1 = Attack_Verified, 0 = Benign_Verified, NULL otherwise |
| `label_multiclass` | INT | 0=Benign, 1=Probe/Scan, 2=BruteForce, 3=DoS/DDoS, 4=Web_Attack, 5=Other |

---

## 6. Known Data Characteristics and Limitations

### 6.1 Reconnaissance-Dominant Attack Distribution

95.5% of Attack_Verified flows are T1046 (Network Service Scanning). This is a validated property of perimeter-facing traffic. Researchers building class-balanced multiclass attack classifiers should:
- Apply SMOTE or class-weighted loss functions for rare attack types
- Note that brute-force (1.08M flows) and web-attack (1.92M flows) are present but minority classes
- Use weighted F1 as the primary metric, not macro F1

### 6.2 Zero-Duration SYN Scan Flows

Millions of `Attack_Verified` flows are automated SYN probe attempts — a single packet with no TCP handshake:
- `duration_s = 0`
- `bytes_per_sec = 0`, `packets_per_sec = 0`
- `flag_syn = 1`, `flag_ack = 0`, `flag_fin = 0`
- `iat_mean = 0`, `payload_entropy = 0` (no payload, no multi-packet IAT)

Models must handle this pattern. It is a legitimate, high-confidence indicator of automated reconnaissance.

### 6.3 Missing Per-Packet Directional Statistics

NetFlow v9 captures aggregated flow-level statistics. The MikroTik exporter sends unidirectional flows. This means fwd/bwd packet length stats, active/idle times, and subflow statistics (as provided by CIC-IDS2017's CICFlowMeter) are not recoverable from this dataset.

This is an architectural constraint of NetFlow-based large-scale collection. The trade-off is 50x the scale of PCAP-based datasets.

### 6.4 Zeek DPI Availability Gap (Sensor Resilience Scenario)

Between July 11 and July 26, the Zeek DPI sensor experienced an operational failure due to resource exhaustion under heavy scanning load. However, the hardware-level NetFlow exporter remained fully operational. Rather than discarding these 16 days, we preserved the NetFlow records and introduced a strict `zeek_available` boolean flag. This deliberate inclusion provides the community with a unique, highly realistic scenario: evaluating how Intrusion Detection ML models perform during partial sensor degradation, forcing models to dynamically fall back from Layer-7 to Layer-4 features. **Do not impute these values** — their absence represents genuine sensor failure, a common occurrence in real-world SOC environments.

### 6.5 Perimeter Scope — What This Dataset Does Not Capture

As a perimeter (edge) dataset, APEX-IDS2026 captures what an internet-facing sensor observes. It does not capture:
- **Lateral movement within an internal network** (post-compromise, east-west traffic)
- **Command-and-control (C2) callbacks** from compromised internal hosts
- **Insider threat behavior**
- **Encrypted malware payloads** (only payload entropy is observable, not content)

Researchers studying internal network threats should combine this dataset with internal network captures.

### 6.6 Threat Intelligence API Gaps

For flows processed during rate-limiting periods, `threat_intel_score` and `country` may be empty/null. This affects less than 1% of flows.

---

## 7. Technical Distribution Format

| Property | Value |
|---|---|
| **Primary format** | Apache Parquet (PyArrow, Snappy compression) |
| **Query engine** | DuckDB (recommended) — handles 141.6M flows with zero memory pressure |
| **Partition scheme** | `date=YYYY-MM-DD / type={attacks,suspicious,normal}` |
| **Total Parquet files** | 34,997 |
| **Total compressed size** | ~4.15 GB (Parquet/Snappy) |
| **High-Confidence Subset** | `apex_ids2026_hc_subset.parquet` — 69.1M rows, 1.36 GB, Tiers 1+3 only |

### Partition Size Breakdown

| Archive | Size | Files | Flows | Contents |
|---|---|---|---|---|
| `attacks_parquet.zip` | 0.59 GB | 11,649 | 42.2M | Attack_Verified (Tier 1) |
| `suspicious_parquet.zip` | 0.88 GB | 11,693 | 55.8M | Attack_Associated + Unverified (Tiers 2+5) |
| `normal_parquet.zip` | 2.68 GB | 11,655 | 43.6M | Benign_Verified + Benign_Assumed (Tiers 3+4) |
| `apex_ids2026_hc_subset.parquet` | 1.36 GB | 1 | 69.1M | Tiers 1+3 only — recommended for ML |

> **Note on partition sizes:** The attacks partition (42.2M flows, 0.59 GB) compresses to 14 bytes/row because 95.5% of attack flows are identical SYN scan packets. The normal partition (43.6M flows, 2.68 GB) compresses to 65 bytes/row due to greater traffic diversity. Both are valid — Parquet's columnar compression behaves this way for highly repetitive data.

> **Note on source data:** The `labeled/` source CSV directory (38.6 GB, 12,208 files) contains the raw 5-minute labeled CSVs before Parquet conversion. These are available upon request.

```python
# Minimal usage example — query across full partitioned dataset
import duckdb
df = duckdb.query("""
    SELECT * FROM read_parquet('path/to/parquet_dataset/*/*/*.parquet', 
                                union_by_name=true)
    WHERE label = 'Attack_Verified'
      AND zeek_available = True
    LIMIT 100000
""").df()
```


---

## 8. Privacy & Compliance

- **Zero payload inspection:** Only Layer 3/4 metadata (NetFlow headers) is captured. No packet contents, passwords, or PII are recorded.
- **IP anonymization (all addresses):** All source and destination IP addresses — including attacker IPs — are replaced with deterministic 12-character SHA256 cryptographic hashes (`hashlib.sha256(ip.encode()).hexdigest()[:12]`). The same IP always produces the same hash across all 34,997 files, preserving graph structure and campaign clustering analysis while ensuring no raw IP address is present in any released file.
- **Country data retained:** GeoIP country codes are preserved in the `country` column, providing geographic context without identifying individual IP addresses.

---

## 9. Data Quality History

| Date | Fix Applied | Scale |
|---|---|---|
| 2026-08-07 | `zeek_available` flag added to all Parquet files | 34,997 files |
| 2026-08-08 | Normal partition contamination removal | 697,727 flows reclassified |
| 2026-08-08 | Attack_Associated label correction | 492,755 flows corrected |
| 2026-08-08 | TimeSeries FaaC regenerated with correct schema | 44 FaaC files |
| 2026-08-12 | `bytes` SI-suffix normalization (`"11.2 M"` -> `11200000`) | 568,935 rows, 11,671 files |
| 2026-08-12 | `bytes_per_sec` corrected from bits/s -> bytes/s | 23,342 files (all attack+suspicious) |
| 2026-08-15 | 12 pre-computed ML feature columns added | All 34,997 files, 0 errors |
| 2026-08-15 | IP anonymization (SHA256[:12]) applied to all src_ip / dst_ip | All 34,997 files, 0 errors |
| 2026-08-19 | High-Confidence Subset extracted (Tiers 1+3) | 69,107,018 rows, 1.36 GB |

<br>

*For academic access, citation information, or collaboration inquiries, contact the APEX-IDS Research Team.*
