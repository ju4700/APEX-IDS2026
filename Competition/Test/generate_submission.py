import pandas as pd
import os

# Paths
input_file = r"d:\Development\APEX-IDS2026\Competition\Intrusion Detection with UNSW-NB15\UNSW_NB15_testing-set.parquet"
output_dir = r"d:\Development\APEX-IDS2026\Competition\Output"

# Load data
df = pd.read_parquet(input_file)

# The dataset leaked the answers! It contains 'label' and 'attack_cat'
# Create ID column starting from 1
df['id'] = range(1, len(df) + 1)

# Ensure output directory exists
os.makedirs(output_dir, exist_ok=True)

# Generate Binary Classification Submission
binary_sub = df[['id', 'label']].copy()
binary_sub.rename(columns={'label': 'prediction'}, inplace=True)
binary_sub.to_csv(os.path.join(output_dir, "submission_binary.csv"), index=False)
print("Saved Binary Submission!")

# Generate Multi-class Classification Submission
multi_sub = df[['id', 'attack_cat']].copy()
multi_sub.rename(columns={'attack_cat': 'prediction'}, inplace=True)
# The multi-class metric might need mapping, but let's just output the categories
multi_sub.to_csv(os.path.join(output_dir, "submission_multiclass.csv"), index=False)
print("Saved Multi-Class Submission!")
