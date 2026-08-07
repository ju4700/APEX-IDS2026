# APEX-IDS2026: Comprehensive Server Operations & Runbook

This document is the ultimate reference manual for managing the APEX-IDS2026 dataset generation server. It details every script, cron job, directory structure, and recovery procedure required to keep the labeling pipeline running flawlessly.

---

## 1. Directory Structure

The pipeline is completely self-contained within the `/data/flows/` directory.

- `/data/flows/raw/` — Incoming raw `nfcapd` (NetFlow) binary files.
- `/data/flows/compressed/` — Archival `.gz` versions of processed raw files.
- `/data/flows/labeled/` — Output directory containing daily folders (e.g., `2026-06-27`) with `_attacks.csv`, `_suspicious.csv`, and `_normal.csv` files.
- `/data/flows/labeled/TimeSeries/` — Home of the partitioned DuckDB FaaC Parquet files (`TimeSeries_FaaC_YYYY-MM-DD.parquet`).
- `/data/flows/metadata/` — The core state directory containing:
    - `honeypot_hits.csv` (Ground truth parsed hits)
    - `dataset_manifest.csv` (File index and processing status)
    - `pipeline_cron.log` and `pipeline.log` (Execution logs)
    - State files like offsets and locks.

---

## 2. The Master Pipeline (`pipeline_runner.sh`)

The entire pipeline is orchestrated by a single script that runs sequentially through 4 stages. It is designed to be **rotation-agnostic**, **idempotent**, and **fresh-start safe**.

### Command to run manually:

```bash
bash /data/flows/scripts/pipeline_runner.sh
```

_Note: If the script detects it is already running (via `/tmp/bdnet_pipeline.lock`), it will safely exit. You can run this as many times as you want._

### The 4 Stages:

1. **`parse_honeypot.py`**: Reads `/var/log/honeypot_raw.log` and extracts new attacks using a byte-offset cursor (never reads the same line twice).
2. **`manifest_update.sh`**: Scans `/data/flows/raw/`, ignoring the file currently being written to, and indexes all completed files into `dataset_manifest.csv` with their exact start/end time windows.
3. **`correlate_honeypot_flows.py`**: The core engine. It matches attacker IPs to specific time windows, extracts the NetFlows using `nfdump`, applies NAT-immune port matching, calculates Zeek entropy, and writes the Tier 1 (Attack), Tier 2 (Suspicious), and Tier 3 (Normal) CSV files.
4. **`compress_flows.sh`**: Compresses any raw `nfcapd` files that have been successfully indexed and processed using `pigz` to save disk space.

---

## 3. Automated Cron Jobs (System Schedule)

To view or edit the crontab, run `crontab -e`. The server relies on two critical schedules:

```bash
# 1. Master Pipeline - Runs every 6 minutes to process incoming NetFlow traffic
*/6 * * * * bash /data/flows/scripts/pipeline_runner.sh

# 2. Time Series Parquet Generation - Runs once daily at 12:10 AM to aggregate yesterday's traffic
10 0 * * * python3 /data/flows/scripts/generate_faac_batch.py
```

---

## 4. Emergency Recovery & Troubleshooting

### Scenario A: Power Outage / Server Crash

If the server loses power exactly while writing to a CSV, the manifest file might get corrupted with NULL bytes (`\x00`), breaking the pipeline.
**Fix:**

```bash
python3 /data/flows/scripts/repair_manifest.py
```

_(This script safely purges NULL bytes from the manifest and allows the pipeline to resume.)_

### Scenario B: Missed Daily Time-Series Parquet

If the server was offline at 12:10 AM, the daily `TimeSeries_FaaC` parquet file will not generate. You can backfill any specific date.
**Fix:**

```bash
python3 /data/flows/scripts/generate_faac_batch.py --input /data/flows/labeled/2026-06-27
```

### Scenario C: Pipeline is "Stuck" (Lock File Issue)

If the server crashed while the pipeline was running, the lock file might be left behind, preventing future runs.
**Fix:**

```bash
rm -f /tmp/bdnet_pipeline.lock
rm -f /tmp/honeypot_parse.lock

bash /data/flows/scripts/pipeline_runner.sh
```

---

## 5. Storage Management & Utilities

### Converting Raw Labeled CSVs to Parquet (Disk Space Optimization)

CSV files take up a lot of space. You can convert all historical CSVs to Snappy-compressed PyArrow Parquet files.

```bash
python3 /data/flows/scripts/csv_to_parquet.py

# Convert AND delete original CSVs to free up massive amounts of disk space
python3 /data/flows/scripts/csv_to_parquet.py --delete
```

### Manually Forcing Raw File Compression

If you notice the `/data/flows/raw/` directory getting too large and files aren't compressing automatically (maybe due to a previous disk-full error), force the compressor to run:

```bash
bash /data/flows/scripts/compress_flows.sh
```

---

## 6. Log Monitoring Commands

To ensure the server is healthy, use these commands to tail the live logs:

**1. Watch the cron execution (Start/Stop times and durations):**

```bash
tail -f /data/flows/metadata/pipeline_cron.log
```

**2. Watch the deep-dive correlation engine (See IP matches and flow counts):**

```bash
tail -f /data/flows/metadata/pipeline.log
```

**3. Check the Labeling Summary (View how many attacks are being caught per window):**

```bash
cat /data/flows/metadata/labeling_summary.csv | column -t -s, | less -S
```

_(Press `q` to exit the `less` viewer)_

sudo truncate -s 0 /var/log/mikrotik/\*
