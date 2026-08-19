#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# pipeline_runner.sh — Master orchestrator for BDNET-IDS2025
#
# Cron: */6 * * * * bash /data/flows/scripts/pipeline_runner.sh
#
# Pipeline order (file-driven, rotation-agnostic):
#   1. Parse honeypot logs      → honeypot_hits.csv
#   2. Index new raw files      → dataset_manifest.csv
#   3. Correlate & label flows  → labeled/*.csv (reads RAW directly)
#   4. Compress processed files → compressed/*.gz (LAST)
# ─────────────────────────────────────────────────────────────────────────────

LOCK_FILE="/tmp/bdnet_pipeline.lock"
LOGDIR="/data/flows/metadata"
LOG_FILE="$LOGDIR/pipeline_cron.log"

# Ensure ALL directories exist (fresh start safe)
mkdir -p /data/flows/raw
mkdir -p /data/flows/compressed
mkdir -p /data/flows/labeled
mkdir -p /data/flows/metadata
mkdir -p /data/flows/docs

# Prevent concurrent pipeline runs
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] Pipeline already running, skipping." >> "$LOG_FILE"
    exit 0
fi

START_TIME=$(date +%s)
echo "" >> "$LOG_FILE"
echo "=== Pipeline Start: $(date -u '+%Y-%m-%dT%H:%M:%SZ') ===" >> "$LOG_FILE"

# ── Step 1: Parse honeypot logs ──────────────────────────────────────────────
echo "--> [1/4] Parsing honeypot hits..." >> "$LOG_FILE"
python3 /data/flows/scripts/parse_honeypot.py 2>&1 | tail -5 >> "$LOG_FILE"

# ── Step 2: Index new raw files into manifest ───────────────────────────────
echo "--> [2/4] Indexing new files..." >> "$LOG_FILE"
bash /data/flows/scripts/manifest_update.sh 2>&1

# ── Step 3: Correlate honeypot hits with flow files ─────────────────────────
echo "--> [3/4] Running correlation..." >> "$LOG_FILE"
python3 /data/flows/scripts/correlate_honeypot_flows.py 2>&1 | tail -20 >> "$LOG_FILE"

# ── Step 4: Compress old processed files ────────────────────────────────────
echo "--> [4/4] Compressing processed files..." >> "$LOG_FILE"
bash /data/flows/scripts/compress_flows.sh 2>&1

# ── Done ─────────────────────────────────────────────────────────────────────
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
echo "=== Pipeline Complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ') (${ELAPSED}s) ===" >> "$LOG_FILE"
