# APEX-IDS2026: Dataset Schema Reference

## Overview

APEX-IDS2026 is a research-grade network intrusion detection dataset
built from **real-world NetFlow traffic** collected from a live production
network with an integrated MikroTik honeypot. Unlike lab-generated datasets
(CICIDS2017, NSL-KDD), all attacks are real and labels carry zero false
positives via honeypot ground truth.

**Collection period:** 90 days (June–August 2026)
**Collection point:** MikroTik router → nfcapd (NetFlow v5/v9)
**Honeypot IP:** 103.148.176.62
**Labeling method:** Honeypot correlation with multi-tier confidence

## File Structure

```
labeled/
  YYYY-MM-DD/
    nfcapd.YYYYMMDDHHMI_attacks.csv      ← Tier 1: honeypot-verified
    nfcapd.YYYYMMDDHHMI_suspicious.csv   ← Tier 2: attacker-associated
    nfcapd.YYYYMMDDHHMI_normal.csv       ← Tier 3: normal-sampled
```

## Labeling Tiers

| Tier | Label | Confidence | Description | FP Rate |
|------|-------|-----------|-------------|---------|
| 1 | `attack` | `honeypot-verified` | Flows FROM attacker TO honeypot IP | **0%** (ground truth) |
| 2 | `suspicious` | `attacker-associated` | ALL other flows FROM confirmed attacker IP in same window | Very low |
| 3 | `normal` | `normal-sampled` | Random sample of flows NOT from any known attacker | Low FN possible |

## Column Schema (38 columns)

### Raw Flow Fields (from nfdump)

| Column | Type | Description | Example |
|--------|------|-------------|---------|
| `flow_start` | timestamp | Flow start time | `2026-06-05 18:23:45.123` |
| `duration_s` | float | Flow duration in seconds | `0.352` |
| `protocol` | string | Transport protocol | `TCP`, `UDP`, `ICMP` |
| `src_ip` | string | Source IP address | `45.227.253.130` |
| `src_port` | int | Source port | `54321` |
| `dst_ip` | string | Destination IP address | `103.148.176.62` |
| `dst_port` | int | Destination port | `22` |
| `packets` | int | Total packets in flow | `6` |
| `bytes` | int | Total bytes in flow | `480` |
| `tcp_flags` | string | TCP flag string from nfdump | `.AP.S.` |
| `tos` | int | Type of Service / DSCP byte | `0` |

### Computed Rate Features

| Column | Type | Description | Formula |
|--------|------|-------------|---------|
| `bytes_per_sec` | float | Throughput | bytes / duration |
| `packets_per_sec` | float | Packet rate | packets / duration |
| `bytes_per_packet` | float | Average payload size | bytes / packets |

### Deep Packet Inspection (Zeek Integration)

*Merged deterministically using a NAT-immune `(src_ip, dst_port, protocol, 5min_time_bucket)` key.*

| Column | Type | Description | Example |
|--------|------|-------------|---------|
| `iat_mean` | float | Mean inter-arrival time (s) | `0.045` |
| `iat_std` | float | Standard deviation of IAT | `0.012` |
| `payload_entropy` | float | Shannon entropy of payload (0-8) | `4.057` |
| `dns_query` | string | Extracted DNS resolution request | `none` |
| `init_win_bytes_forward` | int | Initial TCP window size (forward) | `64240` |

### TCP Flag Decomposition (binary features)

| Column | Type | Description |
|--------|------|-------------|
| `flag_syn` | 0/1 | SYN flag present |
| `flag_ack` | 0/1 | ACK flag present |
| `flag_fin` | 0/1 | FIN flag present |
| `flag_rst` | 0/1 | RST flag present |
| `flag_psh` | 0/1 | PSH flag present |
| `flag_urg` | 0/1 | URG flag present |

### Categorical Features

| Column | Type | Values | Description |
|--------|------|--------|-------------|
| `src_port_category` | string | `well-known`, `registered`, `dynamic` | Source port range classification |
| `dst_port_category` | string | `well-known`, `registered`, `dynamic` | Destination port range classification |
| `flow_duration_class` | string | `instant`, `sub-second`, `short`, `medium`, `long`, `persistent` | Duration bucket |

### Label Columns

| Column | Type | Description |
|--------|------|-------------|
| `label` | string | Primary label: `Attack_Verified`, `Attack_Associated`, etc. |
| `attack_type` | string | Specific type: `SSH-Brute`, `Port-445-Scan`, `normal`, etc. |
| `attack_category` | string | Category: `brute-force`, `reconnaissance`, `web-attack`, `service-probe`, `lateral-movement`, `benign` |
| `mitre_technique` | string | MITRE ATT&CK technique ID: `T1110`, `T1046`, `T1190`, etc. |
| `mitre_tactic` | string | MITRE ATT&CK tactic: `credential-access`, `discovery`, `initial-access`, etc. |
| `confidence` | string | Labeling confidence tier |
| `evidence_source` | string | How the label was derived: `honeypot:port-match` |
| `threat_intel_score`| float | AbuseIPDB reputation score (0-100) |
| `country` | string | Attacker GeoIP |
| `behavioral_flags` | string | Heuristic tags (e.g., `scan-like:port-sweep`) |
| `flow_file` | string | Source nfcapd file name |

## MITRE ATT&CK Mapping

| Attack Type | Technique | Tactic | Category |
|-------------|-----------|--------|----------|
| SSH-Brute | T1110.001 | credential-access | brute-force |
| Telnet-Brute | T1110 | credential-access | brute-force |
| FTP-Brute | T1110 | credential-access | brute-force |
| RDP-Brute | T1110.001 | credential-access | brute-force |
| MSSQL-Brute | T1110 | credential-access | brute-force |
| MySQL-Brute | T1110 | credential-access | brute-force |
| VNC-Brute | T1110 | credential-access | brute-force |
| HTTP-Probe | T1190 | initial-access | web-attack |
| HTTPS-Probe | T1190 | initial-access | web-attack |
| SMB-Probe | T1021.002 | lateral-movement | lateral-movement |
| Port-*-Scan | T1046 | discovery | reconnaissance |
| Redis-Probe | T1046 | discovery | service-probe |
| MongoDB-Probe | T1046 | discovery | service-probe |

## Advantages Over Existing Datasets

| Feature | APEX-IDS2026 | CICIDS2017 | NSL-KDD | UNSW-NB15 |
|---------|---------------|------------|---------|-----------|
| Traffic source | Real-world | Lab | Lab (1999) | Lab |
| Attack source | Real attackers | Synthetic | Synthetic | Synthetic |
| Label method | Honeypot ground truth | CICFlowMeter | Manual | IXIA |
| False positive rate | 0% (Tier 1) | Unknown | Unknown | Unknown |
| Collection period | 90 days | 5 days | N/A | 31 hours |
| Multi-tier confidence | ✓ | ✗ | ✗ | ✗ |
| MITRE ATT&CK mapping | ✓ | ✗ | ✗ | ✗ |
| Normal flow samples | ✓ | ✓ | ✓ | ✓ |
| TCP flag decomposition | ✓ | ✓ | Partial | ✓ |
| Zeek Layer 7 DPI | ✓ (5 new features) | ✗ | ✗ | ✗ |
| Real-time collection | ✓ (5-min windows) | ✗ | ✗ | ✗ |
