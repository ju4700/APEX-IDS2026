#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# extract_flags.sh — Zero-waste, single-file extraction for low disk spaces
# ─────────────────────────────────────────────────────────────────────────────

COMP_DIR="/data/flows/compressed"
OUTPUT_CSV="/data/flows/metadata/extracted_flags.csv"

# Write the clean header out first
echo "flow_start,protocol,src_ip,src_port,dst_ip,dst_port,tcp_flags" > "$OUTPUT_CSV"

echo "Starting flag extraction from compressed archives..."

# Loop through every compressed file
for FILEPATH in "$COMP_DIR"/nfcapd.20*.gz; do
    [ -e "$FILEPATH" ] || continue
    BASENAME=$(basename "$FILEPATH")
    
    # Create a local temporary name unique to this specific iteration
    TMP_UNZIPPED="${FILEPATH%.gz}.tmp"
    
    echo "Processing: $BASENAME"
    
    # 1. Unzip ONLY this file to disk
    pigz -dc "$FILEPATH" > "$TMP_UNZIPPED" 2>/dev/null
    
    # 2. Extract the features and append them straight to the output CSV
    nfdump -r "$TMP_UNZIPPED" -o "fmt:%ts,%pr,%sa,%sp,%da,%dp,%flg" | \
    grep -E '^[0-9]{4}' | \
    sed -E 's/ *, */,/g' >> "$OUTPUT_CSV"
    
    # 3. CRITICAL: Nuke the uncompressed file immediately right now
    rm -f "$TMP_UNZIPPED"
    
done

echo "Extraction complete! High-fidelity TCP features compiled safely."
echo "Total rows captured:"
wc -l "$OUTPUT_CSV"
