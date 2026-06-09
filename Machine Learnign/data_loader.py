import pandas as pd
from pathlib import Path
from typing import Tuple
from config import DATA_DIR, BINARY_LABEL_MAP, TARGET_COLUMN
import pyarrow  # ensures pyarrow is available for parquet support

def load_and_combine_data() -> pd.DataFrame:
    """
    Scans the local DATA_DIR for any downloaded CSV files from the APEX-IDS2026 dataset,
    loads them, combines them, and maps the labels to a binary target (0 or 1).
    """
    # Previously we only looked at CSV files directly under DATA_DIR, but the dataset is organized
    # into sub‑folders by date (e.g., data/2026-06-06/*.csv). Use rglob to recursively find all CSVs.
    # ---------------------------------------------------------------------
    # 1️⃣  Locate CSV files (recursively) and optionally their Parquet equivalents
    # ---------------------------------------------------------------------
    csv_files = list(DATA_DIR.rglob("*.csv"))
    parquet_dir = DATA_DIR.parent / "parquet"
    parquet_dir.mkdir(exist_ok=True)

    # Look for already‑converted parquet files that mirror the CSV structure
    parquet_files = list(parquet_dir.rglob("*.parquet"))

    if parquet_files:
        # Load parquet files – they are much faster and use less memory
        print(f"Loading {len(parquet_files)} parquet files (pre‑converted)...")
        dataframes = []
        for p_path in parquet_files:
            try:
                df = pd.read_parquet(p_path)
                dataframes.append(df)
                print(f"  ✓ Loaded {p_path.relative_to(parquet_dir)} ({len(df)} rows)")
            except Exception as e:
                print(f"  X Error loading parquet {p_path.name}: {e}")
        full_df = pd.concat(dataframes, ignore_index=True)
    else:
        # No parquet cache – fall back to CSV and create parquet files on‑the‑fly
        if not csv_files:
            raise FileNotFoundError(
                f"No CSV files found in {DATA_DIR}. "
                "Please copy a few sample `_attacks.csv` and `_normal.csv` files from your server into this folder."
            )

        print(f"Loading {len(csv_files)} CSV files and converting to parquet for future runs...")
        dataframes = []
        for file_path in csv_files:
            try:
                df = pd.read_csv(file_path, on_bad_lines='skip')
                dataframes.append(df)
                print(f"  ✓ Loaded {file_path.relative_to(DATA_DIR)} ({len(df)} rows)")
                # Write a parquet copy preserving the relative folder structure
                rel_path = file_path.relative_to(DATA_DIR).with_suffix('.parquet')
                parquet_path = parquet_dir / rel_path
                parquet_path.parent.mkdir(parents=True, exist_ok=True)
                df.to_parquet(parquet_path, index=False)
            except Exception as e:
                print(f"  X Error processing {file_path.name}: {e}")
        # Combine all loaded CSV dataframes into one massive DataFrame
        full_df = pd.concat(dataframes, ignore_index=True)
    print(f"\nTotal combined rows: {len(full_df)}")

    # Map the text labels to binary (1 = Attack, 0 = Normal)
    print("Mapping labels to Binary Classification (Attack vs Normal)...")
    full_df["target"] = full_df[TARGET_COLUMN].map(BINARY_LABEL_MAP)

    # Drop any rows where the mapping failed (just in case)
    initial_len = len(full_df)
    full_df = full_df.dropna(subset=["target"])
    dropped = initial_len - len(full_df)
    if dropped > 0:
        print(f"Dropped {dropped} rows with unknown labels.")

    # Cast target to integer
    full_df["target"] = full_df["target"].astype(int)

    # Print class balance
    attacks = len(full_df[full_df["target"] == 1])
    normal = len(full_df[full_df["target"] == 0])
    print(f"Class Balance -> Attacks: {attacks} | Normal: {normal}")

    return full_df
