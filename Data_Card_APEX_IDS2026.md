<center>

# APEX-IDS2026: The 141.8 Million Flow Ground-Truth Cybersecurity Dataset
**Research Data Card & Technical Specification**

**Version:** 2.0 (August 2026) &nbsp; | &nbsp; **Date:** August 2026<br>
**License:** Research Use (Pre-Publication) &nbsp; | &nbsp; **Authors:** APEX-IDS Research Team

</center>

<br>

> [!IMPORTANT]
> **Executive Summary:** APEX-IDS2026 is a 141.8-million-flow network intrusion detection dataset built on real-world ISP infrastructure with physical honeypot ground truth. Unlike CIC-IDS2017, NSL-KDD, and UNSW-NB15 - which rely on laboratory simulation - APEX-IDS2026 captures genuine threat actor behavior from 13,638 real attacker IPs across 60 countries over 44 consecutive days. Tier 1 labels carry zero false positives. The dataset covers 64,084 unique attack targets, five MITRE ATT&CK tactics, and provides MITRE-mapped multi-class taxonomies unavailable in any existing public IDS dataset.

---

## 1. Network Architecture & Collection Methodology

APEX-IDS2026 is collected from the edge routing infrastructure of a live Internet Service Provider.

### 1.1 Live ISP Capture
- **Collection Point:** ISP Edge Router (South Asian Tier-2 ISP)
- **Capture Format:** NetFlow v9 exported from MikroTik RouterOS to `nfcapd` collector
- **Rotation Interval:** 5-minute fixed time windows (~6 minute files in practice)
- **Volume:** ~800,000 flows per 5-minute window, **141,841,235 flows** over 44 days
- **Coverage:** June 21 to August 3, 2026 (44 consecutive days)
- **Archive:** 12,208 raw nfcapd.gz compressed files (~219 GB before compression)

### 1.2 Physical Ground Truth - The Honeypot Catalyst

The defining feature of APEX-IDS2026 is its physical ground-truth correlation engine:

- A deliberately vulnerable hardware honeypot (`103.148.176.62`) is permanently exposed on the ISP network
- Because this IP hosts **zero legitimate user services**, any inbound connection is mathematically provable as malicious
- **The Correlation Engine (`correlate_honeypot_flows.py`):** Cross-references every raw NetFlow against the exact timestamps, source IPs, and destination ports of honeypot hits using a NAT-immune 5-minute time bucket

> [!TIP]
> **Why this matters for ML:** CICFlowMeter-based labels (CIC-IDS2017) require researchers to trust a heuristic label assignment. APEX-IDS2026's Tier 1 labels are physically proven - the attacker's packet physically reached the honeypot. This eliminates shortcut-learning from label noise.

### 1.3 Zeek Deep Packet Inspection

A parallel Zeek Network Analysis Framework engine runs on the same interface via TZSP mirroring. Zeek enriches flows with:
- Inter-arrival time statistics (`iat_mean`, `iat_std`)
- Shannon payload entropy (`payload_entropy`)
- DNS query extraction (`dns_query`)
- Initial TCP window size (`init_win_bytes_forward`)

Zeek data is merged deterministically using a NAT-immune key: `(src_ip, dst_port, protocol, 5min_bucket)`.

**Coverage:** 71,485,904 flows (50.48% of dataset) across 24 of 44 days. All files include a `zeek_available` boolean flag.

---

## 2. The 5-Tier Deterministic Labeling Architecture

Every flow is categorized into exactly one of five tiers through a strict decision tree.

| Tier | Label | Flows | Confidence | Validation Method |
|---|---|---|---|---|
| **1** | `Attack_Verified` | **42,205,903** | **Absolute (0% FP)** | Source IP physically hit honeypot; destination port matched |
| **2** | `Attack_Associated` | **41,446,346** | High (95%+) | Confirmed attacker IP, other destination - lateral campaign traffic |
| **3** | `Benign_Verified` | **26,901,115** | High (95%+) | Flow to validated hyperscaler/safe infrastructure |
| **4** | `Benign_Assumed` | **16,672,439** | Baseline | No threat indicators, no behavioral anomaly flags |
| **5** | `Unverified` | **14,374,050** | Medium | AbuseIPDB score > 25 OR behavioral anomaly detected |

**Label purity guarantee:** A global cross-window attacker IP deny-list was applied to the entire normal partition. **697,727 contamination flows** (attack IPs masquerading as normal) were identified and reclassified to `Attack_Associated`. The resulting normal partition carries zero-contamination by any Tier 1 attacker IP.

---

## 3. Attack Diversity & Real-World Threat Landscape

APEX-IDS2026 captures the full spectrum of opportunistic attacks faced by internet-connected infrastructure in 2026. This is not laboratory simulation - these are real campaigns from real threat actors.

### MITRE ATT&CK Coverage (Attack_Verified Flows)

| Technique | Tactic | Flows | % |
|---|---|---|---|
| **T1046** - Network Service Scanning | Discovery | 40,315,265 | 95.5% |
| **T1190** - Exploit Public-Facing App | Initial Access | 1,383,535 | 3.3% |
| **T1110** - Brute Force | Credential Access | 294,023 | 0.7% |
| **T1110.001** - Password Guessing | Credential Access | 209,974 | 0.5% |
| **T1021.002** - SMB / Lateral Movement | Lateral Movement | 3,106 | 0.007% |

**Total MITRE-mapped flows:** 83,566,235 (59.0% of full dataset)

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
| Elasticsearch | TCP/9200 | Data exfiltration probe | 48K flows |
| VNC | TCP/5900 | Credential brute force | 35K flows |
| FTP | TCP/21 | Credential brute force | 35K flows |

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

## 4. Complete Feature Dictionary

### 4.1 Raw Flow Fields (NetFlow v9)

| Column | Type | Description |
|---|---|---|
| `flow_start` | TIMESTAMP | Flow start time (UTC) |
| `duration_s` | DOUBLE | Flow duration in seconds |
| `protocol` | VARCHAR | Transport protocol (`TCP`, `UDP`, `ICMP`) |
| `src_ip` | VARCHAR | Source IP address |
| `src_port` | DOUBLE | Source port number |
| `dst_ip` | VARCHAR | Destination IP address |
| `dst_port` | DOUBLE | Destination port number |
| `packets` | VARCHAR | Total packets in flow |
| `bytes` | VARCHAR | Total bytes (all values are clean integers, BIGINT-castable) |
| `tcp_flags` | VARCHAR | TCP flags string (`SAF`, `.AP.S.`, etc.) |
| `tos` | VARCHAR | Type of Service byte |

### 4.2 Computed Rate Features (Verified Correct)

| Column | Type | Formula | Notes |
|---|---|---|---|
| `bytes_per_sec` | BIGINT | `ROUND(bytes / duration_s)` | Fixed 2026-08-12: was bits/s in original pipeline |
| `packets_per_sec` | DOUBLE | `packets / duration_s` | 0 for zero-duration SYN scans |
| `bytes_per_packet` | BIGINT | `ROUND(bytes / packets)` | Average packet payload size |

> **Note on zero-duration flows:** Single-packet SYN scans have `duration_s = 0`. Rate columns are set to `0` (not NaN) to prevent division-by-zero. These flows have `flag_syn = 1`, `flag_ack = 0` - a forensically important pattern indicating automated reconnaissance.

### 4.3 Categorical Classification Features

| Column | Values | Description |
|---|---|---|
| `src_port_category` | `well-known` / `registered` / `dynamic` | Source port bucket |
| `dst_port_category` | `well-known` / `registered` / `dynamic` | Destination port bucket |
| `flow_duration_class` | `instant` / `sub-second` / `short` / `medium` / `long` / `persistent` | Duration bin |

### 4.4 TCP Flag Decomposition (Binary ML Features)

| Column | Values | Description |
|---|---|---|
| `flag_syn` | 0/1 | SYN flag set |
| `flag_ack` | 0/1 | ACK flag set |
| `flag_fin` | 0/1 | FIN flag set |
| `flag_rst` | 0/1 | RST flag set |
| `flag_psh` | 0/1 | PSH flag set |
| `flag_urg` | 0/1 | URG flag set |

### 4.5 Zeek Deep Packet Inspection Features

Available where `zeek_available = True` (50.48% of flows, 24 of 44 days).

| Column | Type | Description |
|---|---|---|
| `zeek_available` | BOOLEAN | `True` = Zeek was running; DPI columns are valid |
| `iat_mean` | DOUBLE | Mean inter-arrival time of packets (seconds) |
| `iat_std` | DOUBLE | Standard deviation of IAT |
| `payload_entropy` | DOUBLE | Shannon entropy (0-8); >7.0 suggests encrypted/obfuscated payload |
| `dns_query` | VARCHAR | DNS query string if DNS traffic detected |
| `init_win_bytes_forward` | DOUBLE | Initial TCP window size - useful for OS fingerprinting |

### 4.6 Label and Taxonomy Columns

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

---

## 5. Known Data Characteristics

### 5.1 Zero-Duration SYN Scan Flows
Millions of `Attack_Verified` flows are automated SYN probe attempts - a single packet with no TCP handshake:
- `duration_s = 0`
- `bytes_per_sec = 0`, `packets_per_sec = 0`
- `flag_syn = 1`, `flag_ack = 0`, `flag_fin = 0`
- `iat_mean = 0`, `payload_entropy = 0` (no payload, no multi-packet IAT)

**Models must learn this pattern.** A zero-duration, SYN-only flow is a high-confidence indicator of automated reconnaissance.

### 5.2 Missing Per-Packet Directional Statistics
NetFlow v9 captures aggregated flow-level statistics. The Mikrotik exporter sends unidirectional flows (confirmed by binary nfcapd analysis). This means fwd/bwd packet length stats, active/idle times, and subflow statistics - as provided by CIC-IDS2017's CICFlowMeter - are not recoverable from this dataset.

This is an architectural constraint of NetFlow-based large-scale collection. The trade-off is 50x the scale of PCAP-based datasets.

### 5.3 Zeek DPI Availability Gap
The Zeek DPI engine had a silent crash between July 11-26 (16 days) and was not running on June 21-22, August 1, and August 3. DPI columns are `0.0` / `null` on these days. The `zeek_available` flag distinguishes valid DPI data from missing data. **Never impute these values** - their absence is itself a feature (the network had no layer-7 visibility during those days, a realistic operational scenario).

### 5.4 Threat Intelligence API Gaps
For flows processed during rate-limiting periods, `threat_intel_score` and `country` may be empty/null. This affects less than 1% of flows.

---

## 6. Technical Distribution Format

| Property | Value |
|---|---|
| **Primary format** | Apache Parquet (PyArrow, Snappy compression) |
| **Query engine** | DuckDB (recommended) - handles 141.8M flows with zero memory pressure |
| **Partition scheme** | `date=YYYY-MM-DD / type={attacks,suspicious,normal}` |
| **Total Parquet files** | 34,997 |
| **Total compressed size** | ~38.6 GB |
| **TimeSeries FaaC** | 44 Parquet files, 58,319 1-minute bins |

```python
# Minimal usage example
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

## 7. Privacy & Compliance

- **Zero payload inspection:** Only Layer 3/4 metadata (NetFlow headers) is captured. No packet contents, passwords, or PII are recorded.
- **IP anonymization:** Internal ISP client IP addresses are replaced with consistent cryptographic hashes, preserving graph structure while protecting user privacy.
- **Attacker IPs:** External attacker IPs are preserved in full, as these represent confirmed threat actor infrastructure with no privacy protection expectation.

---

## 8. Data Quality History

| Date | Fix Applied | Scale |
|---|---|---|
| 2026-08-07 | `zeek_available` flag added to all Parquet files | 34,997 files |
| 2026-08-08 | Normal partition contamination removal | 697,727 flows reclassified |
| 2026-08-08 | Attack_Associated label correction | 492,755 flows corrected |
| 2026-08-08 | TimeSeries FaaC regenerated with correct schema | 44 FaaC files |
| 2026-08-12 | `bytes` SI-suffix normalization (`"11.2 M"` -> `11200000`) | 568,935 rows, 11,671 files |
| 2026-08-12 | `bytes_per_sec` corrected from bits/s -> bytes/s | 23,342 files (all attack+suspicious) |

<br>

*For academic access, citation information, or collaboration inquiries, contact the APEX-IDS Research Team.*
