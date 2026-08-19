# APEX-IDS2026 — Dataset Schema Reference

> Quick-reference column dictionary for all 53 fields in the Parquet dataset.  
> Full technical specification: [Data_Card_APEX_IDS2026.md](Data_Card_APEX_IDS2026.md)

---

## Column Groups

### Group 1: Raw NetFlow Fields (11 columns)

| Column | Type | Unit | Description |
|---|---|---|---|
| `flow_start` | TIMESTAMP | UTC | Flow start time |
| `duration_s` | DOUBLE | seconds | Flow duration. 0 for single-packet SYN scans |
| `protocol` | VARCHAR | — | Transport protocol: `TCP`, `UDP`, `ICMP` |
| `src_ip` | VARCHAR | — | Source IP address (SHA256[:12] hash — anonymized) |
| `src_port` | DOUBLE | — | Source port number |
| `dst_ip` | VARCHAR | — | Destination IP address (SHA256[:12] hash — anonymized) |
| `dst_port` | DOUBLE | — | Destination port number |
| `packets` | VARCHAR | count | Total packets in flow |
| `bytes` | VARCHAR | bytes | Total bytes in flow. All values are clean integers (BIGINT-castable). |
| `tcp_flags` | VARCHAR | — | TCP flags string (e.g., `S`, `SA`, `.AP.S.`) |
| `tos` | VARCHAR | — | Type of Service (DSCP) byte |

---

### Group 2: Computed Rate Features (3 columns)

| Column | Type | Unit | Formula | Notes |
|---|---|---|---|---|
| `bytes_per_sec` | BIGINT | bytes/s | `ROUND(bytes / duration_s)` | 0 for zero-duration flows |
| `packets_per_sec` | DOUBLE | pkts/s | `packets / duration_s` | 0 for zero-duration flows |
| `bytes_per_packet` | BIGINT | bytes/pkt | `ROUND(bytes / packets)` | Average packet size |

---

### Group 3: Categorical Features (3 columns)

| Column | Type | Values | Description |
|---|---|---|---|
| `src_port_category` | VARCHAR | `well-known` / `registered` / `dynamic` | Source port range bucket |
| `dst_port_category` | VARCHAR | `well-known` / `registered` / `dynamic` | Destination port range bucket |
| `flow_duration_class` | VARCHAR | `instant` / `sub-second` / `short` / `medium` / `long` / `persistent` | Duration classification |

---

### Group 4: TCP Flag Decomposition (6 columns)

All flags are binary integers (0 or 1), derived from `tcp_flags`.

| Column | TCP Flag | Description |
|---|---|---|
| `flag_syn` | SYN | Connection initiation |
| `flag_ack` | ACK | Acknowledgement |
| `flag_fin` | FIN | Connection teardown |
| `flag_rst` | RST | Connection reset |
| `flag_psh` | PSH | Push data |
| `flag_urg` | URG | Urgent data |

---

### Group 5: Zeek Deep Packet Inspection (4 columns)

> **Important:** Only valid where `zeek_available = True` (50.48% of flows, 24 of 44 days).  
> Always filter `WHERE zeek_available = True` before using these features in ML models.

| Column | Type | Range | Description |
|---|---|---|---|
| `zeek_available` | BOOLEAN | True/False | Whether Zeek DPI was running during this flow's capture window |
| `iat_mean` | DOUBLE | ≥ 0 | Mean inter-arrival time between packets (seconds) |
| `iat_std` | DOUBLE | ≥ 0 | Standard deviation of inter-arrival time |
| `payload_entropy` | DOUBLE | 0.0 – 8.0 | Shannon entropy of payload. Values > 7.0 suggest encrypted or obfuscated content |
| `dns_query` | VARCHAR | — | DNS query domain name, if flow is DNS traffic. NULL otherwise |

---

### Group 6: Label and Taxonomy (11 columns)

| Column | Type | Values / Description |
|---|---|---|
| `label` | VARCHAR | `Attack_Verified`, `Attack_Associated`, `Benign_Verified`, `Benign_Assumed`, `Unverified` |
| `attack_type` | VARCHAR | Fine-grained attack vector: `SSH-Brute`, `HTTPS-Probe`, `Redis-Probe`, `Port-9200-Scan`, etc. NULL for benign. |
| `attack_category` | VARCHAR | `reconnaissance`, `brute-force`, `web-attack`, `service-probe`, `lateral-movement`, `benign` |
| `mitre_technique` | VARCHAR | MITRE ATT&CK technique ID: `T1046`, `T1190`, `T1110`, `T1110.001`, `T1021.002`. NULL for benign. |
| `mitre_tactic` | VARCHAR | `discovery`, `initial-access`, `credential-access`, `lateral-movement`. NULL for benign. |
| `confidence` | VARCHAR | Labeling confidence class: `honeypot-verified`, `attacker-associated`, `safe-dest:Cloudflare`, `assumed-clean`, etc. |
| `evidence_source` | VARCHAR | Specific labeling rule: `honeypot:port-match`, `safe-dest:Cloudflare`, `abuseipdb:score>50` |
| `threat_intel_score` | DOUBLE | 0 – 100 | AbuseIPDB confidence score. NULL for unqueried flows. |
| `country` | VARCHAR | ISO 3166-1 alpha-2 | GeoIP country code of source IP. NULL where GeoIP lookup failed. |
| `behavioral_flags` | VARCHAR | — | Heuristic anomaly tags: `scan-like:port-sweep(10)`, `high-entropy`. NULL if no anomaly detected. |
| `flow_file` | VARCHAR | — | Source nfcapd filename for full audit trail (e.g., `nfcapd.202606212040`) |

---

### Group 7: Pre-Computed ML Features (12 columns)

> Ready for direct input to scikit-learn, XGBoost, or PyTorch.  
> No string parsing or preprocessing required.

| Column | Type | Range | Description |
|---|---|---|---|
| `flag_count` | INT | 0 – 6 | Number of TCP flags set (popcount of tcp_flags bitmap) |
| `is_syn_only` | INT | 0 / 1 | 1 if the ONLY flag set is SYN. Strong indicator of automated port scanning. |
| `is_encrypted_port` | INT | 0 / 1 | 1 if dst_port in {443, 8443, 465, 993, 995, 8883} |
| `log_bytes` | DOUBLE | ≥ 0 | log10(bytes + 1). Normalizes heavy-tailed byte distribution. |
| `log_packets` | DOUBLE | ≥ 0 | log10(packets + 1). Normalizes heavy-tailed packet distribution. |
| `log_duration` | DOUBLE | ≥ 0 | log10(duration_s + 1). Normalizes skewed duration distribution. |
| `proto_tcp` | INT | 0 / 1 | 1 if protocol == TCP |
| `proto_udp` | INT | 0 / 1 | 1 if protocol == UDP |
| `proto_icmp` | INT | 0 / 1 | 1 if protocol == ICMP |
| `iat_cv` | DOUBLE | ≥ 0 | Coefficient of variation of IAT: iat_std / iat_mean. 0 if zeek_available = False. |
| `label_binary` | INT | 0 / 1 / NULL | 1 = Attack_Verified, 0 = Benign_Verified, NULL for all other tiers |
| `label_multiclass` | INT | 0 – 5 | 0=Benign, 1=Probe/Scan, 2=BruteForce, 3=DoS/DDoS, 4=Web_Attack, 5=Other |

---

## Label Tier Reference

| Tier | Label | Flows | Confidence | Assignment Method |
|---|---|---|---|---|
| 1 | `Attack_Verified` | 42,205,903 | Absolute (0% FP) | Source IP hit honeypot; destination port matched |
| 2 | `Attack_Associated` | 41,446,346 | High (95%+) | Confirmed attacker IP, different destination |
| 3 | `Benign_Verified` | 26,901,115 | High (95%+) | Destination is validated safe infrastructure |
| 4 | `Benign_Assumed` | 16,672,439 | Baseline | No threat indicators or anomaly flags |
| 5 | `Unverified` | 14,374,050 | Medium | AbuseIPDB score > 25 or behavioral anomaly |

---

## Quick Usage Examples

```python
import duckdb

con = duckdb.connect()

# Load the High-Confidence Subset (Tiers 1+3) — best for ML baselines
df = con.execute("""
    SELECT * FROM read_parquet('apex_ids2026_hc_subset.parquet')
""").df()

# Load all 141M flows with union schema (for full analysis)
df = con.execute("""
    SELECT * FROM read_parquet('parquet_dataset/*/*/*.parquet', union_by_name=true)
    LIMIT 100000
""").df()

# Use only Zeek-enriched flows (50.48% of data)
df = con.execute("""
    SELECT iat_mean, iat_std, payload_entropy, label
    FROM read_parquet('parquet_dataset/*/*/*.parquet', union_by_name=true)
    WHERE zeek_available = True
      AND label = 'Attack_Verified'
""").df()

# Cast bytes and packets for arithmetic
df = con.execute("""
    SELECT 
        CAST(bytes AS BIGINT) as bytes,
        CAST(packets AS BIGINT) as packets,
        duration_s, label
    FROM read_parquet('apex_ids2026_hc_subset.parquet')
""").df()
```

---

## Column Count Summary

| Group | Columns |
|---|---|
| Raw NetFlow | 11 |
| Computed Rates | 3 |
| Categorical | 3 |
| TCP Flags | 6 |
| Zeek DPI | 5 |
| Labels & Taxonomy | 11 |
| Pre-computed ML | 12 |
| **Total** | **52** |

> Note: Total Parquet schema = 53 columns. One column (`zeek_available`) is counted in Group 5 and also serves as a flag for Group 7's `iat_cv`.
