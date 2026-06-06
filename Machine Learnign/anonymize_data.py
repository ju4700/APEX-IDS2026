import pandas as pd
from pathlib import Path
import hashlib

# Configuration
DATA_DIR = Path("data")

def anonymize_ip(ip):
    """Creates a short, deterministic hash of the IP address."""
    if pd.isna(ip): 
        return ip
    # We use a simple SHA256 hash and take the first 12 characters
    return hashlib.sha256(str(ip).encode()).hexdigest()[:12]

def anonymize_files():
    csv_files = list(DATA_DIR.glob("*.csv"))
    
    if not csv_files:
        print("No CSV files found in the data/ directory.")
        return

    print(f"Found {len(csv_files)} files to anonymize. Starting...")

    for file_path in csv_files:
        print(f" -> Processing: {file_path.name}")
        df = pd.read_csv(file_path, on_bad_lines='skip')
        
        # 1. Anonymize Source and Destination IPs
        if 'src_ip' in df.columns:
            df['src_ip'] = df['src_ip'].apply(anonymize_ip)
        if 'dst_ip' in df.columns:
            df['dst_ip'] = df['dst_ip'].apply(anonymize_ip)
            
        # 2. Scrub the raw_log column
        # The raw_log contains MAC addresses, internal hostnames, and full IPs.
        # We must overwrite it to prevent leaks.
        if 'raw_log' in df.columns:
            df['raw_log'] = "[ANONYMIZED_RAW_LOG]"

        # Save the file back, overwriting the original
        df.to_csv(file_path, index=False)
        print(f"    - Anonymized successfully.")

if __name__ == "__main__":
    anonymize_files()
    print("\nAll sample data is now safely anonymized and ready for GitHub!")
