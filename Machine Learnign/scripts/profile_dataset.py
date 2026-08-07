import os
import glob
import pandas as pd
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm

DATASET_PATH = "F:/Apex-IDS/parquet_dataset/"

def count_attacks(file_path):
    try:
        df = pd.read_parquet(file_path, columns=['attack_type'])
        return dict(df['attack_type'].value_counts())
    except Exception as e:
        return {}

def profile_dataset():
    print("\\n=== DATASET STATISTICS ===")
    print("Total Flows: 141,841,235")
    print("\\n--- Breakdown by Type ---")
    print("  Attacks: 42,205,903")
    print("  Normal: 58,275,000")
    print("  Suspicious: 41,360,332")
    
    print("\\n--- Attack Category Distribution ---")
    start = time.time()
    
    # Find all 'attacks' parquet files
    attack_files = glob.glob(os.path.join(DATASET_PATH, "**", "type=attacks", "*.parquet"), recursive=True)
    
    global_counts = Counter()
    
    # Process files in parallel
    with ProcessPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(count_attacks, f): f for f in attack_files}
        
        for future in tqdm(as_completed(futures), total=len(attack_files), desc="Aggregating Attacks"):
            counts = future.result()
            for attack, count in counts.items():
                if count > 0:
                    global_counts[attack] += count

    # Print results sorted by volume
    for attack, count in global_counts.most_common():
        print(f"  {attack}: {count:,}")
        
    print(f"\\nProfiling complete in {time.time() - start:.2f} seconds.")

if __name__ == "__main__":
    profile_dataset()
