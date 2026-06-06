import pandas as pd
from pathlib import Path
from typing import Tuple
from config import DATA_DIR, BINARY_LABEL_MAP, TARGET_COLUMN

def load_and_combine_data() -> pd.DataFrame:
    """
    Scans the local DATA_DIR for any downloaded CSV files from the APEX-IDS2026 dataset,
    loads them, combines them, and maps the labels to a binary target (0 or 1).
    """
    csv_files = list(DATA_DIR.glob("*.csv"))
    
    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {DATA_DIR}. "
            "Please copy a few sample `_attacks.csv` and `_normal.csv` files from your server into this folder."
        )

    print(f"Loading {len(csv_files)} dataset files...")
    
    dataframes = []
    for file_path in csv_files:
        try:
            # Handle potential missing headers or malformed rows gracefully
            df = pd.read_csv(file_path, on_bad_lines='skip')
            dataframes.append(df)
            print(f"  ✓ Loaded {file_path.name} ({len(df)} rows)")
        except Exception as e:
            print(f"  X Error loading {file_path.name}: {e}")

    # Combine all loaded files into one massive DataFrame
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
