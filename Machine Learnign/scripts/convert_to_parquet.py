import os
import glob
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
import time

INPUT_DIR = "F:/Apex-IDS/labeled/"
OUTPUT_DIR = "F:/Apex-IDS/parquet_dataset/"
NUM_WORKERS = os.cpu_count() or 4

# Only strict categorical/string mappings to avoid casting errors on messy numeric columns
dtype_map = {
    'protocol': 'category',
    'src_ip': 'string',
    'dst_ip': 'string',
    'tcp_flags': 'string',
    'dns_query': 'string',
    'src_port_category': 'category',
    'dst_port_category': 'category',
    'flow_duration_class': 'category',
    'label': 'category',
    'attack_type': 'category',
    'attack_category': 'category',
    'mitre_technique': 'category',
    'mitre_tactic': 'category',
    'confidence': 'category',
    'evidence_source': 'category',
    'country': 'category',
    'behavioral_flags': 'string',
    'flow_file': 'string'
}

def clean_metric(series):
    """Converts strings like '1.3 M' to floats."""
    if series.dtype == 'object' or series.dtype.name == 'string':
        return pd.to_numeric(
            series.astype(str)
            .str.replace(' M', 'e6')
            .str.replace(' K', 'e3')
            .str.replace(' G', 'e9')
            .str.replace('nan', 'NaN'), 
            errors='coerce'
        )
    return series

def convert_file(csv_path):
    try:
        filename = os.path.basename(csv_path)
        date_folder = os.path.basename(os.path.dirname(csv_path))
        
        if "attacks" in filename:
            file_type = "attacks"
        elif "suspicious" in filename:
            file_type = "suspicious"
        elif "normal" in filename:
            file_type = "normal"
        else:
            file_type = "other"

        partition_dir = os.path.join(OUTPUT_DIR, f"date={date_folder}", f"type={file_type}")
        os.makedirs(partition_dir, exist_ok=True)
        
        out_file = os.path.join(partition_dir, filename.replace('.csv', '.parquet'))
        
        # Skip if already converted
        if os.path.exists(out_file):
            return True, csv_path, "Skipped (exists)"
        
        # Read CSV with low_memory=False to let Pandas safely infer numeric types
        df = pd.read_csv(csv_path, dtype=dtype_map, low_memory=False)
        
        # Clean messy columns that have "M" or "K" suffixes
        for col in ['bytes_per_sec', 'packets_per_sec', 'bytes_per_packet', 'packets', 'bytes']:
            if col in df.columns:
                df[col] = clean_metric(df[col])
        
        # Parse timestamps properly
        if 'flow_start' in df.columns:
            df['flow_start'] = pd.to_datetime(df['flow_start'], errors='coerce')
        if 'duration_s' in df.columns:
            df['duration_s'] = pd.to_timedelta(df['duration_s'], errors='coerce').dt.total_seconds().astype('float32')
            
        # Write Parquet with snappy compression
        table = pa.Table.from_pandas(df)
        pq.write_table(table, out_file, compression='snappy')
        
        return True, csv_path, f"Converted ({len(df)} rows)"
        
    except Exception as e:
        return False, csv_path, str(e)

if __name__ == "__main__":
    csv_files = []
    for root, _, files in os.walk(INPUT_DIR):
        for f in files:
            if f.endswith('.csv'):
                csv_files.append(os.path.join(root, f))
                
    print(f"Found {len(csv_files)} CSV files. Retrying failed/pending conversions...")
    
    start_time = time.time()
    success_count = 0
    fail_count = 0
    
    with ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
        futures = {executor.submit(convert_file, f): f for f in csv_files}
        
        for future in tqdm(as_completed(futures), total=len(csv_files), desc="Converting to Parquet"):
            success, path, msg = future.result()
            if success:
                success_count += 1
            else:
                fail_count += 1
                print(f"\\nError converting {os.path.basename(path)}: {msg}")

    elapsed = time.time() - start_time
    print(f"\\n=== CONVERSION COMPLETE ===")
    print(f"Time Taken: {elapsed:.2f} seconds")
    print(f"Successfully converted: {success_count} files")
    print(f"Failed conversions: {fail_count} files")
