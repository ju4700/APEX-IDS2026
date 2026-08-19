#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# compress_flows.sh — Compress processed raw nfcapd files (runs LAST)
#
# Only compresses files that:
#   1. Are NOT the latest file (still being written by nfcapd)
#   2. Already exist in the manifest (fully indexed)
#   3. Don't already have a .gz in compressed/
# ─────────────────────────────────────────────────────────────────────────────

RAW_DIR="/data/flows/raw"
COMP_DIR="/data/flows/compressed"
MANIFEST="/data/flows/metadata/dataset_manifest.csv"
LOG="/data/flows/metadata/pipeline.log"

mkdir -p "$COMP_DIR"
mkdir -p "$(dirname "$LOG")"

log_msg() {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [compress] $1" | tee -a "$LOG"
}

# Don't run if manifest doesn't exist yet
if [ ! -s "$MANIFEST" ]; then
    exit 0
fi

COMPRESSED=0

# The latest file is the one nfcapd is currently writing — never touch it
LATEST=$(ls -t "$RAW_DIR"/nfcapd.20* 2>/dev/null | head -1)

for FILEPATH in $(find "$RAW_DIR" -type f -name "nfcapd.20*" ! -name "*.gz" ! -name "nfcapd.current*" 2>/dev/null | sort); do

    [ "$FILEPATH" = "$LATEST" ] && continue

    BASENAME=$(basename "$FILEPATH")
    DEST="$COMP_DIR/$BASENAME.gz"

    # Skip if already compressed
    [ -f "$DEST" ] && continue

    # Only compress if fully processed (exists in manifest)
    grep -q "^$BASENAME," "$MANIFEST" 2>/dev/null || continue

    pigz -9 -c "$FILEPATH" > "$DEST" 2>/dev/null

    if [ $? -eq 0 ] && [ -s "$DEST" ]; then
        rm -f "$FILEPATH"
        log_msg "Compressed: $BASENAME"
        COMPRESSED=$((COMPRESSED + 1))
    else
        rm -f "$DEST"
        log_msg "ERROR: Compression failed for $BASENAME"
    fi
done

if [ "$COMPRESSED" -gt 0 ]; then
    log_msg "Compressed $COMPRESSED files"
fi
