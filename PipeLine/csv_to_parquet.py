#!/usr/bin/env python3
"""
csv_to_parquet.py

A utility script to convert massive labeled CSV files into highly compressed
Parquet files. This is essential for Machine Learning pipelines.

Features:
- Automatically finds all .csv files in /data/flows/labeled
- Converts them to .parquet format
- Skips files that have already been converted
- Uses Pandas and PyArrow

Requirements:
    pip3 install pandas pyarrow
"""

import os
import argparse
from pathlib import Path
import pandas as pd

LABELED_DIR = Path("/data/flows/labeled")

def main():
    parser = argparse.ArgumentParser(description="Convert labeled CSVs to Parquet")
    parser.add_argument("--delete", action="store_true", help="Delete CSV after successful conversion to save disk space")
    args = parser.parse_args()

    if not LABELED_DIR.exists():
        print(f"Error: {LABELED_DIR} does not exist.")
        return

    csv_files = list(LABELED_DIR.rglob("*.csv"))
    if not csv_files:
        print(f"No CSV files found in {LABELED_DIR}")
        return

    print(f"Found {len(csv_files)} CSV files. Starting conversion...")

    converted = 0
    skipped = 0
    errors = 0

    for csv_path in csv_files:
        parquet_path = csv_path.with_suffix('.parquet')

        # Skip if parquet already exists
        if parquet_path.exists():
            skipped += 1
            continue

        try:
            # Read CSV
            df = pd.read_csv(csv_path)
            
            # If CSV is completely empty, just create an empty parquet and move on
            if df.empty:
                df.to_parquet(parquet_path, engine='pyarrow', index=False)
            else:
                # Convert object columns to strings to avoid pyarrow schema errors
                for col in df.select_dtypes(include=['object']).columns:
                    df[col] = df[col].astype(str)
                
                df.to_parquet(parquet_path, engine='pyarrow', index=False, compression='snappy')
            
            converted += 1
            print(f"[{converted}] Converted: {csv_path.name}")

            # Optionally delete the original CSV to save space
            if args.delete:
                csv_path.unlink()

        except Exception as e:
            errors += 1
            print(f"Error converting {csv_path.name}: {e}")

    print("\n" + "="*40)
    print("CONVERSION COMPLETE")
    print("="*40)
    print(f"Successfully converted: {converted}")
    print(f"Skipped (already exist): {skipped}")
    print(f"Errors: {errors}")
    if args.delete:
        print("Original CSV files were deleted to save space.")

if __name__ == "__main__":
    main()
