# APEX-IDS2026: Research and Development Journal

**Chronological Engineering Record — Hypotheses, Challenges, Pivots, and Milestones**

---

## Preface

This document serves as the primary research journal for the APEX-IDS2026 dataset project. It records the scientific rationale, key architectural decisions, technical obstacles encountered, and the reasoning behind each design pivot. It is intended to provide full transparency into how the dataset was constructed and to serve as a reference for researchers evaluating the integrity and reproducibility of the labeling methodology.

All entries are written in chronological order of occurrence.

---

## Entry 1: Problem Formulation and Initial Hypothesis

**Date:** June 2026

**Observation:**
A survey of the dominant intrusion detection datasets used in machine learning research revealed a consistent structural deficiency: none of them are grounded in contemporary, in-the-wild network traffic. NSL-KDD (2009 reprocessing of 1999 DARPA data), UNSW-NB15 (generated via IXIA PerfectStorm in a closed lab over 31 hours), and CIC-IDS2017 (5 days of scripted attacks on isolated virtual machines) all simulate attacks rather than observing them.

The machine learning models trained on these datasets perform artificially well on held-out splits from the same distribution but generalize poorly when deployed against live network traffic. This gap arises because the statistical properties of synthetic attack traffic — timing jitter, port distribution, packet-to-byte ratios, flag combinations — differ systematically from those produced by real automated scanners and botnets operating under real internet conditions.

**Hypothesis:**
A research-grade IDS dataset can be constructed by integrating a MikroTik router honeypot directly into a live production network and automatically correlating its hardware-level firewall logs with a continuous NetFlow (nfcapd) capture stream. The honeypot provides a deterministic ground truth anchor: any IP that triggers a honeypot log entry is, by definition, a threat actor. Any NetFlow record from that IP, in the same time window, carries a verifiable label.

**Design Goals Established:**
1. Zero false positives for the primary (Tier 1) attack class.
2. Full automation — no manual labeling or annotation required.
3. Rotation-agnosticism — the system must not break if the NetFlow rotation interval changes.
4. Longitudinal collection — the system must run unattended for 90+ days.

---

## Entry 2: Initial Architecture Design

**Date:** Early June 2026

**Architecture V1 — Filename-Timestamp Matching:**
The first architecture attempted to match honeypot events to nfcapd files by parsing the timestamp embedded in the filename (e.g., `nfcapd.202606060115` encodes `01:15`). For each honeypot hit at timestamp `T`, the system attempted to construct the expected filename and query it.

**Flaw Identified:**
NetFlow sensors maintain a flow cache with a configurable active timeout and inactive timeout. Flows that begin in one rotation window may not be exported to nfcapd until the following window. Additionally, the MikroTik rotation interval was observed to vary between 5m 40s and 6m 20s under traffic load — the nominal 6-minute boundary was not reliable.

The result: honeypot events near the boundary of a rotation window were systematically missed, as the correlator searched the wrong file.

**Resolution — Rotation-Agnostic Manifest Engine:**
The architecture was redesigned around a manifest that records the actual `First Flow` and `Last Flow` timestamps read directly from the nfcapd binary via `nfdump -I`. The correlator no longer derives filenames from timestamps. Instead, it asks: "which file's absolute time window contains this hit?" This approach is correct regardless of rotation interval variability.

---

## Entry 3: Scale-Up Validation and Discovery of the NAT IP Mismatch

**Date:** June 5–6, 2026

**Context:**
After the manifest-based architecture was validated at small scale (single file, manual verification), the cron-based pipeline was deployed and an initial run processed approximately 12 hours of historical nfcapd files.

**Critical Anomaly Observed:**
Examination of `labeling_summary.csv` revealed an unexpected pattern across all processed windows:

```
tier1_flows: 0
tier2_flows: 1,200–1,800 per window
tier3_flows: 5,000 per window
```

Tier 1 flows — the honeypot-verified ground truth — were entirely absent. Tier 2 flows (attacker-associated) were being produced correctly, confirming that the attacker IP lookup was functioning. However, the IP-based Destination filter that was supposed to isolate Tier 1 was returning 0 results.

**Root Cause Analysis:**
The Tier 1 filter was implemented as:

```python
t1_filter = f"dst ip {HONEYPOT_IP}"
```

Where `HONEYPOT_IP = "103.148.176.62"` (the router's public WAN IP).

This filter was applied to NetFlow data captured on the LAN interface of the router. Because the MikroTik router performs NAT (Port Address Translation) before forwarding packets to the internal server, the NetFlow records on the LAN side show the Destination IP as the internal server's private IP address — not the public WAN IP that the honeypot logs record. The two addresses do not match, so the filter silently returns zero records.

This failure mode is not specific to this deployment. Any production network that uses NAT — which is the overwhelming majority of real-world deployments — would exhibit the same behavior. IP-based Destination filtering is fundamentally incompatible with NAT environments when the honeypot and the NetFlow sensor are on different sides of the translation boundary.

**Architectural Pivot — Port-Based Matching:**
The Tier 1/Tier 2 distinction was redesigned to avoid Destination IP entirely. The new logic:

1. Extract all flows originating from confirmed attacker IPs (Source IP filter only — no Destination filter).
2. For each extracted flow, compare the flow's `dst_port` against the set of ports that specific attacker was observed targeting in the honeypot logs.
3. If `dst_port` is in the attacker's known port set: assign Tier 1.
4. If `dst_port` is not in the attacker's known port set: assign Tier 2.

This approach requires no knowledge of the Destination IP. It is immune to NAT, port forwarding, double NAT, and interface asymmetry. The only requirement is that the honeypot log records the correct Destination Port — which it does, because the MikroTik firewall log captures the port before NAT translation on the WAN interface.

**Supporting changes:**
The `match_hits_to_windows()` function was updated to track `ports` (a set of `dst_port` values) for each attacker IP per window, in addition to `types` (the set of attack type strings). The `attacker_data` dictionary passed to `process_window()` was changed from a flat list to a structured dictionary with `types` and `ports` keys.

---

## Entry 4: Validation of Port-Based Matching

**Date:** June 6, 2026 — 02:25 UTC

**Action:**
The corrected correlator script was deployed to the production server and executed with `--reprocess` to re-label all existing windows using the new port-based logic.

**Results from `labeling_summary (2).csv`:**

| Window | Total Flows | Tier 1 | Tier 2 | Attackers |
|--------|-------------|--------|--------|-----------|
| `nfcapd.202606060110` | 656,110 | 1,203 | 939 | 67 |
| `nfcapd.202606060115` | 612,835 | 851 | 963 | 48 |
| `nfcapd.202606060120` | 579,291 | 973 | 975 | 47 |
| `nfcapd.202606060125` | 565,179 | 674 | 1,043 | 38 |
| `nfcapd.202606060130` | 551,579 | 772 | 866 | 40 |

Tier 1 flows are now correctly populated with 674–1,203 ground-truth verified attack flows per 6-minute window. The architecture is confirmed to be functioning correctly.

**Observations:**
- The ratio of Tier 1 to Tier 2 flows varies between windows, reflecting natural variation in attacker behavior: some actors launch focused attacks on a single port, generating high Tier 1 and low Tier 2 counts; others engage in wide-port reconnaissance after their initial hit, generating lower Tier 1 but higher Tier 2.
- The attack type diversity across windows (300+ distinct port-scan categories per window) confirms that the dataset captures the full breadth of automated internet scanning — not just the handful of attack types represented in existing datasets.

---

## Entry 5: Dataset Naming and Documentation

**Date:** June 6, 2026

**Decision:**
The dataset was formally named **APEX-IDS2026** to reflect its intent as an apex-tier, state-of-the-art intrusion detection dataset for the year 2026. The name is designed to be memorable and distinctive in academic citations.

**Documentation suite created:**
- `README.md` — Project overview, architecture summary, usage guidance
- `docs/PIPELINE_ARCHITECTURE.md` — Full technical specification of all 5 pipeline stages
- `docs/RESEARCH_JOURNAL.md` — This document
- `docs/DATASET_SCHEMA.md` — Complete column reference and MITRE ATT&CK mapping table
- `docs/MACHINE_LEARNING_GUIDE.md` — Guidance for researchers applying ML to this dataset

---

## Entry 6: Ongoing Collection and Anticipated Future Work

**Date:** June 2026 — Ongoing

**Current State:**
The pipeline is fully operational, running autonomously every 6 minutes under cron. Each cycle produces approximately 700–1,200 Tier 1 labeled attack flows, 800–1,100 Tier 2 reconnaissance flows, and 5,000 normal flows.

**Anticipated future work:**

**6.1 Honeypot Expansion:**
The current honeypot captures all traffic to a single public IP. Expanding to a /28 or /29 address block (a "darknet" subnet) would increase the volume and diversity of captured scan traffic significantly, as many automated scanners sweep entire CIDR ranges.

**6.2 Deep Packet Inspection Integration:**
For specific protocols (SSH, HTTP, TLS), integrating application-layer logs alongside the NetFlow records would enable more granular attack classification — distinguishing, for example, between a dictionary attack on SSH and a credential-stuffing attack using a leaked database.

**6.3 Attacker Attribution and Campaign Clustering:**
The dataset contains sufficient temporal resolution to perform IP-level campaign clustering. Attackers that reappear across multiple 6-minute windows over hours or days — particularly those using consistent port sweep patterns — may represent coordinated botnet campaigns or persistent threat actors. Automated clustering of these behavioral fingerprints is a natural extension.

**6.4 Formal Publication:**
Upon accumulation of sufficient data (target: 90 days of continuous collection), the dataset is intended for submission to an appropriate academic venue alongside a formal data descriptor paper detailing the collection methodology, statistical characteristics, and validation experiments.
