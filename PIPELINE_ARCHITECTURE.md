# APEX-IDS2026: Pipeline Architecture

**Technical Specification — Five-Stage Automated Ingestion and Correlation Engine**

---

## 1. Overview

The APEX-IDS2026 labeling pipeline is a fully automated, file-driven system that transforms raw MikroTik honeypot syslog entries and binary nfcapd NetFlow captures into research-grade labeled flow records. The pipeline is orchestrated by a single shell script (`pipeline_runner.sh`) executed on a `*/6 * * * *` cron schedule and completes end-to-end within a guaranteed 240-second time budget.

The architecture is designed around three core principles:

1. **Rotation-agnosticism:** The pipeline makes no assumptions about the NetFlow file rotation interval. It derives time windows from the binary content of each file, not from the filename timestamp.
2. **NAT-immunity:** Flow matching does not rely on Destination IP comparison, which fails silently in NAT environments. Instead, it relies on Attacker Source IP combined with the exact Destination Port, which is stable across all network translation boundaries.
3. **Idempotency and concurrency safety:** Every stage is safe to re-run. A file-lock (`flock`) prevents concurrent pipeline executions. Manifest entries prevent duplicate indexing. Labeled windows are skipped unless `--reprocess` is explicitly requested.

---

## 2. Execution Context

### 2.1 Cron Schedule and Lock

The pipeline is registered in the system crontab as follows:

```
*/6 * * * * bash /data/flows/scripts/pipeline_runner.sh
```

Upon launch, `pipeline_runner.sh` attempts to acquire an exclusive file lock on `/tmp/bdnet_pipeline.lock` using bash's `flock -n` (non-blocking). If the lock is held by a prior run (which may happen during a processing backlog), the new invocation logs a skip event and exits with code 0. This guarantees that only a single pipeline instance operates at any time, preventing file corruption and double-labeling.

### 2.2 Directory Bootstrap

On every execution — including the very first — the runner unconditionally creates all required directories:

```bash
mkdir -p /data/flows/raw
mkdir -p /data/flows/compressed
mkdir -p /data/flows/labeled
mkdir -p /data/flows/metadata
mkdir -p /data/flows/docs
```

This makes the pipeline fresh-start safe: the entire system can be rebuilt from scratch by deleting the state files and re-running the cron. No manual directory provisioning is required.

### 2.3 Four-Stage Sequential Execution

```
[Stage 1] parse_honeypot.py        --> honeypot_hits.csv
[Stage 2] manifest_update.sh       --> dataset_manifest.csv
[Stage 3] correlate_honeypot_flows.py --> labeled/YYYY-MM-DD/*.csv
[Stage 4] compress_flows.sh        --> compressed/*.gz
```

Each stage is invoked sequentially, and stdout/stderr are piped to the cron log. The ordering is strict: the correlator depends on up-to-date honeypot hits and manifest entries, and the compressor must run last to ensure raw files are only archived after labeling is confirmed.

---

## 3. Stage 1 — Ground Truth Extraction (`parse_honeypot.py`)

### 3.1 Purpose

This stage is responsible for converting the raw MikroTik router syslog into a structured, machine-readable ground truth record. The output of this stage is the single authoritative source of truth for the entire labeling system: `honeypot_hits.csv`.

### 3.2 Input

The MikroTik router is configured with a firewall rule that logs all inbound packets that hit a designated honeypot chain before DROP. These events are forwarded via syslog to the collection server at `/var/log/honeypot_raw.log`. A representative log line has the following structure:

```
Jun  6 01:12:33 kernel: HONEYPOT: in:ether1 out:(none), mac ...,
src-mac ..., proto TCP (SYN), 45.227.253.130:54731->103.148.176.62:22, len 60
```

### 3.3 Offset-Based Incremental Reading

A critical design decision is that the parser uses a **byte offset cursor** stored in `/data/flows/metadata/honeypot_parse_offset.txt`. On each invocation, the parser opens the log file, seeks to the stored offset, reads only the new bytes, and then updates the offset to the current end of file.

This mechanism provides two guarantees:
- No honeypot hit is ever parsed twice, even if the cron fires multiple times.
- The parser handles arbitrarily large log files without reading from the beginning.

### 3.4 Regex Pattern and Field Extraction

The parser applies the following compiled regular expression to each new log line:

```python
PATTERN = re.compile(
    r"HONEYPOT:.*?"
    r"in:(\S+)\s+"
    r"out:[^,]+,\s*"
    r".*?"
    r"proto\s+(\w+)"
    r"(?:\s+\(([^)]*)\))?"
    r",\s*"
    r"(\d+\.\d+\.\d+\.\d+):(\d+)"
    r"->"
    r"(\d+\.\d+\.\d+\.\d+):(\d+)"
    r",\s*len\s+(\d+)",
    re.IGNORECASE,
)
```

From each match, the following fields are extracted:

| Field | Source |
|-------|--------|
| `timestamp` | Syslog date prefix (re-parsed into ISO 8601) |
| `interface_in` | Ingress interface name (e.g., `ether1`) |
| `protocol` | Transport protocol (TCP, UDP, ICMP) |
| `tcp_flags` | Optional flag string (e.g., `SYN`) |
| `src_ip` | Attacker's public source IP |
| `src_port` | Attacker's ephemeral source port |
| `dst_ip` | Honeypot destination IP (public WAN) |
| `dst_port` | Targeted service port — the key correlation field |
| `packet_len` | Packet length in bytes |
| `attack_type` | Derived from `dst_port` via the attack taxonomy dictionary |

### 3.5 Attack Taxonomy

Port-to-attack-type mapping is defined statically. Known service ports receive named attack categories; all others receive a generic `Port-{N}-Scan` label that preserves the exact port number:

```
21   -> FTP-Brute         22   -> SSH-Brute
23   -> Telnet-Brute      25   -> SMTP-Probe
53   -> DNS-Probe         80   -> HTTP-Probe
443  -> HTTPS-Probe       445  -> SMB-Probe
1433 -> MSSQL-Brute       3306 -> MySQL-Brute
3389 -> RDP-Brute         5432 -> PostgreSQL-Probe
6379 -> Redis-Probe       8080 -> HTTP-Alt-Probe
8443 -> HTTPS-Alt-Probe   27017-> MongoDB-Probe
8333 -> Bitcoin-Probe     9051 -> Tor-Probe
N    -> Port-N-Scan       (all other ports)
```

### 3.6 Output Schema

The extracted records are appended to `/data/flows/metadata/honeypot_hits.csv` with the following columns:

```
timestamp, src_ip, dst_ip, src_port, dst_port,
protocol, tcp_flags, interface_in, packet_len,
attack_type, raw_log
```

---

## 4. Stage 2 — NetFlow File Indexing (`manifest_update.sh`)

### 4.1 Purpose

`manifest_update.sh` enumerates all completed nfcapd files in `/data/flows/raw/` and builds a time-window index in `dataset_manifest.csv`. This index is what allows the correlator to operate in a fully rotation-agnostic manner.

### 4.2 The "Skip Latest File" Rule

The nfcapd process continuously writes to the newest file in `raw/`. Reading this file with nfdump while it is being written produces incomplete and potentially corrupted records. The manifest updater identifies the newest file with:

```bash
LATEST=$(ls -t "$RAW_DIR"/nfcapd.20* 2>/dev/null | head -1)
```

All other files (i.e., all files except the most recently modified one) are considered complete and eligible for indexing. This approach is strictly safer than using a minimum age threshold (e.g., `-mmin +7`), which would discard valid files during periods of low network activity.

### 4.3 Time Window Extraction via `nfdump -I`

For each eligible, un-indexed file, the script runs `nfdump -I` to extract the ground-truth time boundaries:

```bash
STATS=$(nfdump -r "$FILEPATH" -I 2>/dev/null)
TIME_LINE=$(nfdump -r "$FILEPATH" 2>/dev/null | grep "Time window")
START=$(echo "$TIME_LINE" | awk '{print $3" "$4}' | tr -d ',')
END=$(echo   "$TIME_LINE" | awk '{print $6" "$7}' | tr -d ',')
DURATION=$(( $(date -d "$END" +%s) - $(date -d "$START" +%s) ))
```

The actual duration is computed from the timestamp difference rather than assumed from the rotation interval. This handles variable-length windows transparently.

Additional statistics extracted per file:

| Field | Method |
|-------|--------|
| `flows` | `nfdump -I` → `Flows:` key |
| `bytes` | `nfdump -I` → `Bytes:` key |
| `packets` | `nfdump -I` → `Packets:` key |
| `src_ips` | `nfdump -A srcip -q` unique count |
| `dst_ips` | `nfdump -A dstip -q` unique count |

### 4.4 Compressed File Backfill

The script also handles the case where a compressed `.gz` file in `compressed/` is not yet in the manifest (e.g., files compressed in a previous run before indexing completed). It decompresses each such file to a temporary path using `pigz`, indexes it, and removes the temporary file.

### 4.5 Manifest Schema

```
file_name, start_time, end_time, duration_s, flows,
src_ips, dst_ips, bytes, packets,
label, attack_type, notes
```

---

## 5. Stage 3 — Deterministic Port-Based Correlation (`correlate_honeypot_flows.py`)

This is the central and most technically sophisticated stage of the pipeline. It implements the 3-Tier Labeling Architecture and produces the final labeled CSVs.

### 5.1 Time Window Construction

The correlator builds a sorted list of `(start, end, file_name)` tuples from the manifest. Where a file has valid `start_time` and `end_time` entries, those are used directly. For any file where timestamps are missing (a rare edge case for very short or corrupt files), the correlator estimates the window using the median rotation interval computed from all other files in the manifest.

### 5.2 Honeypot Hit-to-Window Matching

Each honeypot hit from `honeypot_hits.csv` is matched to the file window that temporally contains it. A 30-second buffer is applied to both ends of each window to account for timestamp drift between the router clock and the nfcapd server clock:

```python
if (w_start - timedelta(seconds=30)) <= hit_ts <= (w_end + timedelta(seconds=30)):
    window_attackers[w_file][src_ip]["types"].add(atk_type)
    window_attackers[w_file][src_ip]["ports"].add(dst_port)
    matched = True
    break
```

For each file window, this produces a dictionary mapping each confirmed attacker IP to the set of attack types and the set of exact ports they targeted.

### 5.3 The Port-Based Matching Engine

#### Problem: IP-Based Matching Fails in NAT Environments

The initial design of the correlator used Destination IP filtering — querying nfdump for flows where `dst ip == <honeypot_public_ip>`. This approach failed silently in the APEX-IDS2026 production environment.

The root cause: MikroTik logs honeypot hits on the WAN interface (public IP: `103.148.176.62`). However, the nfcapd sensor captures NetFlow data on the internal LAN interface, where NAT has already translated the destination IP to the internal server address. The result was 0 Tier 1 flows despite thousands of honeypot hits being correctly parsed.

#### Solution: Port-Based Deterministic Matching

The solution avoids Destination IP filtering entirely. Instead:

1. All flows originating from a known attacker IP are extracted from the nfcapd file without any destination filter.
2. Each extracted flow's `dst_port` is compared against the set of ports that attacker was logged as targeting in the honeypot.
3. If `dst_port` is in the attacker's `hit_ports` set: the flow is **Tier 1**.
4. If `dst_port` is not in the attacker's `hit_ports` set: the flow is **Tier 2**.

This approach is immune to NAT, port forwarding, double NAT, interface capture direction, and any other IP routing topology.

### 5.4 nfdump Query Execution

Flow extraction uses nfdump with an extended format string that captures computed rates directly from the binary:

```
fmt:%ts,%td,%pr,%sa,%sp,%da,%dp,%pkt,%byt,%fl,%flg,%tos,%bps,%pps,%bpp
```

For each attacker IP list, nfdump is invoked with an `ip` filter constructed dynamically:

```bash
nfdump -r <file> -o "fmt:..." "src ip 1.2.3.4 or src ip 5.6.7.8 ..."
```

The script auto-detects whether the nfdump binary on the target system supports extended format output by running a test query on the first available file, falling back to a basic 10-field format if needed.

### 5.5 MITRE ATT&CK Classification

After tier assignment, each flow is annotated via `classify_attack()`, which maps `dst_port` to a 4-tuple of `(attack_type, attack_category, mitre_technique, mitre_tactic)`:

```python
ATTACK_TAXONOMY = {
    "22":    ("SSH-Brute",    "brute-force",   "T1110.001", "credential-access"),
    "3389":  ("RDP-Brute",   "brute-force",   "T1110.001", "credential-access"),
    "80":    ("HTTP-Probe",  "web-attack",    "T1190",     "initial-access"),
    "445":   ("SMB-Probe",   "lateral-movement","T1021.002","lateral-movement"),
    # ... 20+ named entries; all others -> Port-N-Scan, T1046, discovery
}
```

### 5.6 Feature Engineering

During annotation, the following derived features are computed per flow:

**Rate features:**
- `bytes_per_sec = bytes / max(duration_s, 0.001)`
- `packets_per_sec = packets / max(duration_s, 0.001)`
- `bytes_per_packet = bytes / max(packets, 1)`

**Binary TCP flag decomposition** (parsed from nfdump raw flag string):
- `flag_syn`, `flag_ack`, `flag_fin`, `flag_rst`, `flag_psh`, `flag_urg`

**Port range classification:**
- Ports 0–1023: `well-known`
- Ports 1024–49151: `registered`
- Ports 49152–65535: `dynamic`

**Duration bucketing:**
- `< 0.001s`: `instant`
- `0.001–1s`: `sub-second`
- `1–10s`: `short`
- `10–60s`: `medium`
- `60–600s`: `long`
- `> 600s`: `persistent`

### 5.7 Normal Traffic Sampling (Tier 3)

A random sample of 5,000 flows is extracted from each file using flows whose Source IP does not appear in the current window's confirmed attacker set. This is implemented by fetching a stratified sample via nfdump without any IP filter, then excluding flows matching any attacker IP in post-processing.

### 5.8 Output and State Management

Labeled flows are written to date-partitioned CSV files:

```
labeled/YYYY-MM-DD/nfcapd.<timestamp>_attacks.csv    (Tier 1)
labeled/YYYY-MM-DD/nfcapd.<timestamp>_suspicious.csv (Tier 2)
labeled/YYYY-MM-DD/nfcapd.<timestamp>_normal.csv     (Tier 3)
```

A per-window summary entry is written to `labeling_summary.csv`, recording flow counts, attack percentage, unique attacker count, and the full set of observed attack types for that window.

The manifest entry's `labeling_status` field is updated to `labeled`, which causes the window to be skipped in future runs (unless `--reprocess` is passed).

The manifest is written atomically via a `.tmp` rename to prevent corruption on interrupt.

### 5.9 Time Budget Enforcement

The correlator tracks elapsed wall-clock time. If processing approaches the 240-second budget, it logs the number of deferred windows and exits cleanly. Deferred windows are automatically picked up in the next cron invocation.

---

## 6. Stage 4 — Archival Compression (`compress_flows.sh`)

### 6.1 Purpose

Raw nfcapd files are large binary objects (typically 50–150 MB per 6-minute window). After labeling, the raw files are no longer needed for the primary pipeline but must be retained for retrospective re-processing, audit, and reproducibility.

`compress_flows.sh` applies `pigz` (parallel gzip) to eligible raw files, achieving typically 75–85% size reduction while keeping the files fully queryable by nfdump on decompression.

### 6.2 Eligibility Criteria

A raw file is eligible for compression if and only if all three conditions hold:

1. It is **not** the currently active nfcapd file (identified by modification time, same as Stage 2).
2. It **is** present in `dataset_manifest.csv` (confirming it has been indexed).
3. A corresponding `.gz` file does **not** already exist in `compressed/`.

This three-condition gate ensures that files are never compressed before they are indexed, and never compressed twice.

### 6.3 Compression and Cleanup

```bash
pigz -c "$FILEPATH" > "$COMP_DIR/$(basename "$FILEPATH").gz"
rm -f "$FILEPATH"
```

The source file is removed only after the compressed output is successfully created. If `pigz` fails, the source file is preserved and an error is logged.

---

## 7. Concurrency and Failure Handling

| Scenario | Behavior |
|----------|----------|
| Cron fires while pipeline is running | New invocation detects lock, logs skip, exits 0 |
| nfdump not available for a file | Stage 2 skips the file; Stage 3 logs "file not found" and moves on |
| Honeypot log has no new entries | Stage 1 reads 0 bytes, writes nothing, exits normally |
| No un-labeled windows available | Stage 3 logs "No new windows to process" and exits |
| Manifest write interrupted | Atomic `.tmp` rename ensures no partial writes are visible |
| Disk full during compression | `pigz` fails; source file is retained; error logged |

---

## 8. Operational Monitoring

| Log File | Contents |
|----------|----------|
| `metadata/pipeline_cron.log` | Per-run start/end timestamps, elapsed time, skip events |
| `metadata/pipeline.log` | Detailed per-stage output: files indexed, windows correlated, flows labeled |
| `metadata/labeling_summary.csv` | Queryable summary table: flows per tier, attack types, attacker counts |
| `metadata/dataset_manifest.csv` | Full index of all known nfcapd files and their labeling status |
