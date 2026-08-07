"""
add_zeek_available_flag.py

Rewrites every Parquet file in the parquet_dataset to add a
`zeek_available` boolean column. The flag is set based on the
empirical IAT coverage we measured from the 44-day dataset:

  True  → day had ≥5% of flows with a valid iat_mean (Zeek was running)
  False → day had <5% IAT coverage (Zeek was offline or unstable)

This is the honest, scientifically correct approach — we do NOT fabricate
DPI values; we simply tell downstream users when Zeek was available.

Derived from DuckDB coverage query run 2026-08-07:
  iat_pct per day (from analyze_zeek.py output)
"""

import pyarrow.parquet as pq
import pyarrow as pa
import glob
import os
import re
from tqdm import tqdm

# ── Ground-truth coverage map ──────────────────────────────────────────────
# Built from empirical iat_pct per day (threshold: ≥5% = Zeek running)
ZEEK_GOOD_DATES = {
    "2026-06-23", "2026-06-24", "2026-06-25", "2026-06-26", "2026-06-27",
    "2026-06-28", "2026-06-29", "2026-06-30",
    "2026-07-01", "2026-07-02", "2026-07-03", "2026-07-04", "2026-07-05",
    "2026-07-06", "2026-07-07", "2026-07-08", "2026-07-09", "2026-07-10",
    "2026-07-27", "2026-07-28", "2026-07-29", "2026-07-30", "2026-07-31",
    "2026-08-02",
}
# Everything else → False (June 21, June 22, July 11-26, Aug 1, Aug 3)

DATASET_ROOT = "F:/Apex-IDS/parquet_dataset"
DATE_PATTERN = re.compile(r"date=(\d{4}-\d{2}-\d{2})")

def get_date_from_path(path):
    m = DATE_PATTERN.search(path.replace("\\", "/"))
    return m.group(1) if m else None

def rewrite_with_flag(filepath, zeek_available):
    """Read a parquet file, add zeek_available column, write back in place."""
    try:
        table = pq.read_table(filepath)

        # Skip if column already exists (idempotent)
        if "zeek_available" in table.schema.names:
            return False

        flag_col = pa.chunked_array(
            [pa.array([zeek_available] * len(table), type=pa.bool_())]
        )
        table = table.append_column("zeek_available", flag_col)

        # Write back to same path (overwrite)
        pq.write_table(
            table,
            filepath,
            compression="snappy",
            use_dictionary=True,
        )
        return True

    except Exception as e:
        print(f"  [!] Error on {filepath}: {e}")
        return False


def main():
    # Discover all parquet files
    pattern = os.path.join(DATASET_ROOT, "**", "*.parquet")
    all_files = glob.glob(pattern, recursive=True)
    print(f"Found {len(all_files):,} Parquet files to process.")

    rewritten = 0
    skipped   = 0
    errors    = 0

    for filepath in tqdm(all_files, desc="Adding zeek_available", unit="file"):
        date_str = get_date_from_path(filepath)
        if date_str is None:
            print(f"  [?] Could not parse date from: {filepath}")
            errors += 1
            continue

        zeek_flag = date_str in ZEEK_GOOD_DATES
        result = rewrite_with_flag(filepath, zeek_flag)

        if result:
            rewritten += 1
        else:
            skipped += 1

    print(f"\n{'='*60}")
    print(f"  Rewritten : {rewritten:,}")
    print(f"  Skipped   : {skipped:,}  (already had column)")
    print(f"  Errors    : {errors:,}")
    print(f"{'='*60}")
    print("Done! Run the verification query to confirm coverage.")


if __name__ == "__main__":
    main()
