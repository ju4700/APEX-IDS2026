# APEX-IDS2026: Dataset Schema Reference

> **All column types and statistics verified from live DuckDB queries (2026-08-13).**

## Overview

APEX-IDS2026 is a research-grade network intrusion detection dataset built from **real-world NetFlow traffic** collected from a live production ISP network with an integrated MikroTik honeypot. All Tier 1 attacks are verified by physical honeypot correlation - zero false positives.

| Property | Value |
|---|---|
| Collection period | 44 days - June 21 to August 3, 2026 |
| Total flows | 141,841,235 |
| Collection point | MikroTik RouterOS -> NetFlow v9 -> nfcapd |
| Honeypot IP | 103.148.176.62 |
| Labeling method | Honeypot correlation + 5-tier confidence architecture |
| Parquet files | 34,997 files across 3 partition types |

---

## Labeling Tiers

| Tier | Label | Flows | Confidence | Description | FP Rate |
|---|---|---|---|---|---|
| 1 | `Attack_Verified` | 42,205,903 | Absolute | Flow FROM attacker IP TO honeypot, destination port matched | **0%** |
| 2 | `Attack_Associated` | 41,446,346 | High (95%+) | Same attacker IP, different destination | Very low |
| 3 | `Benign_Verified` | 26,901,115 | High (95%+) | Flows to validated safe infrastructure | Low |
| 4 | `Benign_Assumed` | 16,672,439 | Baseline | No threat indicators, no anomaly flags | Lowest |
| 5 | `Unverified` | 14,374,050 | Medium | AbuseIPDB flagged OR behavioral anomaly detected | Unknown |

**Normal partition purity:** A global cross-window IP deny-list containing all 13,638 confirmed attacker IPs was applied. **697,727 contamination flows** were removed from the normal partition and reclassified to Attack_Associated, resulting in a provably zero-contamination negative class.

---

## Parquet Partition Structure

```
parquet_dataset/
└── date=YYYY-MM-DD/           <- 44 date partitions
    ├── type=attacks/          <- Attack_Verified flows
    ├── type=suspicious/       <- Attack_Associated + Unverified flows
    └── type=normal/           <- Benign_Verified + Benign_Assumed flows
```

**Load example:**
```python
import duckdb
con = duckdb.connect()
df = con.execute("""
    SELECT * FROM read_parquet('path/to/parquet_dataset/*/*/*.parquet',
                                union_by_name=true)
    WHERE date BETWEEN '2026-06-23' AND '2026-07-10'  -- Zeek Golden Era 1
""").df()
```

---

## Column Schema (38 columns)

### 1. Raw Flow Fields (from nfdump / NetFlow v9)

| Column | Type | Description | Example |
|---|---|---|---|
| `flow_start` | TIMESTAMP | Flow start time (UTC) | `2026-06-23 14:22:05.431` |
| `duration_s` | DOUBLE | Flow duration in seconds | `0.352` |
| `protocol` | VARCHAR | Transport protocol | `TCP`, `UDP`, `ICMP` |
| `src_ip` | VARCHAR | Source IP address | `45.227.253.130` |
| `src_port` | DOUBLE | Source port | `54321` |
| `dst_ip` | VARCHAR | Destination IP address | `103.148.176.62` |
| `dst_port` | DOUBLE | Destination port | `22` |
| `packets` | VARCHAR | Total packets in flow | `6` |
| `bytes` | VARCHAR | Total bytes in flow (BIGINT-castable) | `480` |
| `tcp_flags` | VARCHAR | TCP flag string from nfdump | `.AP.SF` |
| `tos` | VARCHAR | Type of Service / DSCP byte | `0` |

> **Note on `bytes` type:** The column is stored as `VARCHAR` in Parquet (for cross-partition compatibility) but all values are clean integers castable to `BIGINT`. SI-suffix values (`"11.2 M"`) were normalized in a data quality pass on 2026-08-12. Use `TRY_CAST(bytes AS BIGINT)` in queries.

---

### 2. Computed Rate Features

All three columns were recomputed from the fixed bytes values and are uniformly correct across all partitions.

| Column | Type | Description | Formula |
|---|---|---|---|
| `bytes_per_sec` | BIGINT | Throughput in bytes per second | `ROUND(bytes / duration_s)` |
| `packets_per_sec` | DOUBLE | Packet rate | `packets / duration_s` |
| `bytes_per_packet` | BIGINT | Average packet size in bytes | `ROUND(bytes / packets)` |

> **Data quality fix (2026-08-12):** The original pipeline stored `bytes_per_sec` as bits/second (bytes x 8 / duration) in the `attacks` and `suspicious` partitions. This was corrected across all 23,342 affected files. The column now uniformly contains bytes/second.

> **Zero-duration flows:** Single-packet SYN scans have `duration_s = 0`. For these, `bytes_per_sec = 0` and `packets_per_sec = 0` (division-by-zero prevention). This is intentional and forensically meaningful - SYN-only, zero-duration flows are a strong indicator of automated reconnaissance.

---

### 3. Zeek Deep Packet Inspection (DPI)

Zeek data is merged deterministically using a NAT-immune 5-minute time bucket key: `(src_ip, dst_port, protocol, time_bucket)`.

> [!IMPORTANT]
> **`zeek_available` flag:** Zeek DPI was not running for all 44 days. DPI columns (`iat_mean`, `iat_std`, `payload_entropy`, `dns_query`, `init_win_bytes_forward`) are `0.0` / `null` on days where `zeek_available = False`. **Always filter `WHERE zeek_available = True` before using DPI features in ML models.**

| Column | Type | Description | Example |
|---|---|---|---|
| `zeek_available` | BOOLEAN | True = Zeek was running; DPI columns are valid | `True` |
| `iat_mean` | DOUBLE | Mean inter-arrival time (seconds) | `0.045` |
| `iat_std` | DOUBLE | Std deviation of IAT | `0.012` |
| `payload_entropy` | DOUBLE | Shannon entropy of payload (0-8) | `4.057` |
| `dns_query` | VARCHAR | Extracted DNS query (if applicable) | `none` |
| `init_win_bytes_forward` | DOUBLE | Initial TCP window size (forward direction) | `64240` |

**Zeek DPI coverage:**

| Period | Dates | `zeek_available` | Flows |
|---|---|---|---|
| Zeek offline (startup) | Jun 21-22 | `False` | 4.3M |
| **Golden Era 1** | Jun 23 - Jul 10 | **`True`** | **55.8M** |
| Zeek silent crash | Jul 11 - Jul 26 | `False` | 59.3M |
| **Golden Era 2** | Jul 27 - Aug 2 | **`True`** | **15.8M** |
| Collection end | Aug 1, Aug 3 | `False` | 3.6M |

---

### 4. TCP Flag Decomposition (binary)

| Column | Type | Description |
|---|---|---|
| `flag_syn` | INTEGER | SYN flag (1 = present) |
| `flag_ack` | INTEGER | ACK flag |
| `flag_fin` | INTEGER | FIN flag |
| `flag_rst` | INTEGER | RST flag |
| `flag_psh` | INTEGER | PSH flag |
| `flag_urg` | INTEGER | URG flag |

---

### 5. Categorical Classification Features

| Column | Type | Values | Description |
|---|---|---|---|
| `src_port_category` | VARCHAR | `well-known`, `registered`, `dynamic` | Source port range bucket |
| `dst_port_category` | VARCHAR | `well-known`, `registered`, `dynamic` | Destination port range bucket |
| `flow_duration_class` | VARCHAR | `instant`, `sub-second`, `short`, `medium`, `long`, `persistent` | Duration bin |

**Destination port category distribution (Attack_Verified):**
- `registered` (1024-49151): 69.2% of attack flows
- `well-known` (0-1023): 24.6% of attack flows
- `dynamic` (49152+): 6.2% of attack flows

---

### 6. Label and Taxonomy Columns

| Column | Type | Description | Example |
|---|---|---|---|
| `label` | VARCHAR | Primary tier label | `Attack_Verified`, `Benign_Assumed` |
| `attack_type` | VARCHAR | Specific attack vector | `SSH-Brute`, `HTTPS-Probe`, `Redis-Probe` |
| `attack_category` | VARCHAR | Attack category | `brute-force`, `reconnaissance`, `web-attack`, `service-probe`, `lateral-movement` |
| `mitre_technique` | VARCHAR | MITRE ATT&CK technique ID | `T1046`, `T1190`, `T1110.001` |
| `mitre_tactic` | VARCHAR | MITRE ATT&CK tactic | `discovery`, `initial-access`, `credential-access`, `lateral-movement` |
| `confidence` | VARCHAR | Labeling confidence tier | `honeypot-verified`, `attacker-associated` |
| `evidence_source` | VARCHAR | Rule that applied the label | `honeypot:port-match`, `safe-dest:Cloudflare` |
| `threat_intel_score` | DOUBLE | AbuseIPDB reputation score (0-100) | `87.0` |
| `country` | VARCHAR | GeoIP country code (ISO 3166-1) | `NL`, `SG`, `US` |
| `behavioral_flags` | VARCHAR | Heuristic tags | `scan-like:port-sweep(10)` |
| `flow_file` | VARCHAR | Source nfcapd filename | `nfcapd.202606232040` |

---

## MITRE ATT&CK Mapping (Verified)

| Attack Type | Technique | Tactic | Category | Flows |
|---|---|---|---|---|
| Port-\*-Scan (any port) | T1046 | discovery | reconnaissance | 40,315,265 |
| HTTP-Probe, HTTPS-Probe | T1190 | initial-access | web-attack | 1,383,535 |
| SSH-Brute, RDP-Brute | T1110.001 | credential-access | brute-force | 209,974 |
| MySQL-Brute, VNC-Brute, Telnet-Brute, FTP-Brute, SMTP | T1110 | credential-access | brute-force | 294,023 |
| SMB-Probe (port 445) | T1021.002 | lateral-movement | lateral-movement | 3,106 |
| Redis-Probe, MongoDB-Probe, Elasticsearch-Probe | T1046 | discovery | service-probe | part of T1046 |

**MITRE coverage:** 83,566,235 flows (59.0% of total) have a MITRE technique assigned.

---

## TimeSeries FaaC Parquet (for LSTM/Transformer)

A secondary time-series Parquet dataset aggregates all flows into 1-minute bins for volumetric anomaly detection.

**Location:** `F:/Apex-IDS/labeled/TimeSeries/TimeSeries_FaaC_YYYY-MM-DD.parquet`

| Column | Description |
|---|---|
| `window_start` | 1-minute bin start time |
| `total_bytes` | Sum of all bytes in the window |
| `total_packets` | Sum of all packets |
| `total_connections` | Count of distinct flows |
| `unique_src_ips` | Unique source IP count |
| `attack_count` | Attack_Verified flows in window |
| `bytes_skewness` | Skewness of bytes distribution |
| `bytes_kurtosis` | Kurtosis of bytes distribution |
| `avg_entropy` | Mean payload entropy (Zeek windows only) |
| `max_entropy` | Max payload entropy |

---

## Data Quality History

| Date | Fix | Files Affected | Rows Affected |
|---|---|---|---|
| 2026-08-07 | Zeek gap flag (`zeek_available`) added | 34,997 | 141.8M |
| 2026-08-08 | Normal partition contamination removal | Normal partition | 697,727 reclassified |
| 2026-08-08 | Attack_Associated label correction | attacks+suspicious | 492,755 corrected |
| 2026-08-08 | TimeSeries FaaC regeneration | 44 FaaC files | 58,319 rows |
| 2026-08-12 | bytes SI-suffix normalization | 11,671 files | 568,935 rows fixed |
| 2026-08-12 | bytes_per_sec bits->bytes fix | 23,342 files | All attack+suspicious |

---

## Comparison with CIC-IDS2017

| Feature | APEX-IDS2026 | CIC-IDS2017 |
|---|---|---|
| Traffic source | Real internet (live ISP) | Lab simulation |
| Attack source | 13,638 real attacker IPs | 6 researchers simulating |
| Label method | Physical honeypot ground truth | CICFlowMeter heuristic |
| False positive rate | 0% (Tier 1) | Unknown (contamination confirmed) |
| Collection period | 44 days | 5 days |
| Total flows | 141,841,235 | ~2,830,743 |
| Class balance | 1.38:1 | ~5.4:1 |
| Infinity values | 0 | 4,376 |
| Negative durations | 0 | 115 |
| MITRE ATT&CK | Yes 5 techniques | No |
| Zeek L7 DPI | Yes (5 features, 50.48% coverage) | No |
| Temporal span | 44 days (time-series capable) | 5 days |
| IP addresses preserved | Yes | No (hashed) |
| GeoIP enrichment | Yes 60 countries | No |
| Fwd/bwd packet stats | No (NetFlow limitation) | Yes (PCAP-based) |
