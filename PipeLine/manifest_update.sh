#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# manifest_update.sh — Index raw nfcapd files into dataset_manifest.csv
#
# Uses nfdump -I for clean stats. Calculates actual duration from time
# window (not hardcoded). Rotation-interval agnostic.
#
# Skips only the newest file (the one nfcapd is actively writing to).
# All other completed files are processed immediately.
# ─────────────────────────────────────────────────────────────────────────────

RAW_DIR="/data/flows/raw"
COMP_DIR="/data/flows/compressed"
MANIFEST="/data/flows/metadata/dataset_manifest.csv"
LOG="/data/flows/metadata/pipeline.log"

mkdir -p "$(dirname "$MANIFEST")"
mkdir -p "$COMP_DIR"

log_msg() {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [manifest] $1" | tee -a "$LOG"
}

# Write CSV header if manifest doesn't exist or is empty
if [ ! -s "$MANIFEST" ]; then
    echo "file_name,start_time,end_time,duration_s,flows,src_ips,dst_ips,bytes,packets,label,attack_type,notes" > "$MANIFEST"
    log_msg "Created new manifest with header"
fi

ADDED=0

# ─── Index completed raw files ───────────────────────────────────────────────
# Only skip the SINGLE file nfcapd is currently writing (the newest one).
# Everything else is complete and ready to process immediately.
LATEST=$(ls -t "$RAW_DIR"/nfcapd.20* 2>/dev/null | head -1)

for FILEPATH in $(find "$RAW_DIR" -name "nfcapd.20*" -type f ! -name "*.gz" ! -name "nfcapd.current*" 2>/dev/null | sort); do

    # Skip the file nfcapd is actively writing to
    [ "$FILEPATH" = "$LATEST" ] && continue

    FILE=$(basename "$FILEPATH")

    # Skip if already in manifest
    grep -q "^$FILE," "$MANIFEST" 2>/dev/null && continue

    # ── Get stats using nfdump -I (clean key=value output) ───────────
    STATS=$(nfdump -r "$FILEPATH" -I 2>/dev/null)

    FLOWS=$(echo "$STATS"   | grep "^Flows:"   | awk '{print $2}')
    BYTES=$(echo "$STATS"   | grep "^Bytes:"   | awk '{print $2}')
    PACKETS=$(echo "$STATS" | grep "^Packets:" | awk '{print $2}')

    # ── Get actual time window and compute real duration ─────────────
    TIME_LINE=$(nfdump -r "$FILEPATH" 2>/dev/null | grep "Time window")
    START=$(echo "$TIME_LINE" | awk '{print $3" "$4}' | tr -d ',')
    END=$(echo "$TIME_LINE"   | awk '{print $6" "$7}' | tr -d ',')

    # Calculate actual duration from timestamps (not hardcoded)
    DURATION=0
    if [ -n "$START" ] && [ -n "$END" ]; then
        START_EPOCH=$(date -d "$START" +%s 2>/dev/null || echo 0)
        END_EPOCH=$(date -d "$END" +%s 2>/dev/null || echo 0)
        if [ "$START_EPOCH" -gt 0 ] && [ "$END_EPOCH" -gt 0 ]; then
            DURATION=$((END_EPOCH - START_EPOCH))
        fi
    fi

    # ── Unique IP counts ─────────────────────────────────────────────
    SRCIPS=$(nfdump -r "$FILEPATH" -A srcip -q 2>/dev/null | grep -vc "^$")
    DSTIPS=$(nfdump -r "$FILEPATH" -A dstip -q 2>/dev/null | grep -vc "^$")

    # ── Append to manifest ───────────────────────────────────────────
    echo "$FILE,$START,$END,${DURATION:-0},${FLOWS:-0},${SRCIPS:-0},${DSTIPS:-0},${BYTES:-0},${PACKETS:-0},normal,none,auto" \
        >> "$MANIFEST"

    log_msg "Indexed: $FILE (${FLOWS:-0} flows, ${DURATION}s, ${BYTES:-0} bytes)"
    ADDED=$((ADDED + 1))
done

# ─── Also index compressed files not yet in manifest ─────────────────────────
for FILEPATH in $(find "$COMP_DIR" -name "nfcapd.20*.gz" -type f 2>/dev/null | sort); do

    FILE=$(basename "$FILEPATH" .gz)
    grep -q "^$FILE," "$MANIFEST" 2>/dev/null && continue

    TMPFILE=$(mktemp)
    pigz -dc "$FILEPATH" > "$TMPFILE" 2>/dev/null

    STATS=$(nfdump -r "$TMPFILE" -I 2>/dev/null)
    FLOWS=$(echo "$STATS"   | grep "^Flows:"   | awk '{print $2}')
    BYTES=$(echo "$STATS"   | grep "^Bytes:"   | awk '{print $2}')
    PACKETS=$(echo "$STATS" | grep "^Packets:" | awk '{print $2}')

    TIME_LINE=$(nfdump -r "$TMPFILE" 2>/dev/null | grep "Time window")
    START=$(echo "$TIME_LINE" | awk '{print $3" "$4}' | tr -d ',')
    END=$(echo "$TIME_LINE"   | awk '{print $6" "$7}' | tr -d ',')

    DURATION=0
    if [ -n "$START" ] && [ -n "$END" ]; then
        START_EPOCH=$(date -d "$START" +%s 2>/dev/null || echo 0)
        END_EPOCH=$(date -d "$END" +%s 2>/dev/null || echo 0)
        if [ "$START_EPOCH" -gt 0 ] && [ "$END_EPOCH" -gt 0 ]; then
            DURATION=$((END_EPOCH - START_EPOCH))
        fi
    fi

    SRCIPS=$(nfdump -r "$TMPFILE" -A srcip -q 2>/dev/null | grep -vc "^$")
    DSTIPS=$(nfdump -r "$TMPFILE" -A dstip -q 2>/dev/null | grep -vc "^$")

    rm -f "$TMPFILE"

    echo "$FILE,$START,$END,${DURATION:-0},${FLOWS:-0},${SRCIPS:-0},${DSTIPS:-0},${BYTES:-0},${PACKETS:-0},normal,none,auto" \
        >> "$MANIFEST"

    log_msg "Indexed (gz): $FILE (${FLOWS:-0} flows)"
    ADDED=$((ADDED + 1))
done

if [ "$ADDED" -gt 0 ]; then
    TOTAL=$(tail -n +2 "$MANIFEST" | wc -l)
    log_msg "Added $ADDED entries. Total: $TOTAL"
fi
