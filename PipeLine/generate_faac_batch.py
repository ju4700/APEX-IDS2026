import os
import glob
import pandas as pd
import duckdb
from pathlib import Path
import argparse

def process_daily_directory_duckdb(day_dir, output_dir, conn):
    print(f"  Processing directory via DuckDB: {day_dir}")
    
    # Collect all labeled CSVs in this specific daily folder
    csv_files = []
    for pattern in ['**/*_attacks.csv', '**/*_suspicious.csv', '**/*_normal.csv']:
        csv_files.extend(glob.glob(os.path.join(day_dir, pattern), recursive=True))
        
    if not csv_files:
        print(f"    No labeled CSVs found in {day_dir}.")
        return
        
    # DuckDB expects a list of formatted paths
    files_list_str = "[" + ", ".join([f"'{Path(f).as_posix()}'" for f in csv_files]) + "]"
    
    try:
        # Out-of-core execution: DuckDB streams the gigabytes of daily CSVs 
        # directly from disk without blowing up RAM, returning a tiny Pandas DF.
        query = f"""
        SELECT 
            date_trunc('minute', CAST(flow_start AS TIMESTAMP)) as timestamp,
            count(*) as total_connections,
            count(DISTINCT src_ip) as unique_src_ips,
            count(DISTINCT dst_port) as unique_dst_ports,
            sum(CAST(bytes AS BIGINT)) as total_bytes,
            sum(CAST(packets AS BIGINT)) as total_packets,
            skewness(CAST(bytes AS DOUBLE)) as bytes_skewness,
            kurtosis(CAST(bytes AS DOUBLE)) as bytes_kurtosis,
            skewness(CAST(packets AS DOUBLE)) as packets_skewness,
            kurtosis(CAST(packets AS DOUBLE)) as packets_kurtosis,
            avg(CAST(payload_entropy AS DOUBLE)) as avg_entropy,
            max(CAST(payload_entropy AS DOUBLE)) as max_entropy
        FROM read_csv_auto({files_list_str}, ignore_errors=true)
        GROUP BY date_trunc('minute', CAST(flow_start AS TIMESTAMP))
        ORDER BY timestamp
        """
        
        # Execute and extract to a tiny Pandas DataFrame (max 1440 rows)
        df_day = conn.execute(query).df()
        
        if df_day.empty:
            print(f"    No rows aggregated for {day_dir}.")
            return
            
        # Format the timestamp column for consistency
        df_day['timestamp'] = df_day['timestamp'].dt.strftime("%Y-%m-%d %H:%M:%S")
        
        # Clean any NULL values that DuckDB outputs for kurtosis/skewness when count < 3
        df_day.fillna(0.0, inplace=True)
        
        # Extract the actual date from the directory name instead of the first flow
        # to prevent midnight boundary drift from overwriting the previous day's parquet
        day_str = Path(day_dir).name 
        
        out_path = Path(output_dir) / f"TimeSeries_FaaC_{day_str}.parquet"
        
        print(f"    Saving partitioned FaaC dataset to {out_path}...")
        df_day.to_parquet(out_path, engine='pyarrow', index=False)
        
    except Exception as e:
        print(f"    [ERROR] DuckDB query failed on {day_dir}: {e}")

def generate_faac_batch(input_dir, output_dir):
    print(f"Scanning {input_dir} for daily flow directories...")
    
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    subdirs = [f.path for f in os.scandir(input_dir) if f.is_dir()]
    if not subdirs:
        subdirs = [input_dir]
        
    # Use a single DuckDB connection for efficiency
    try:
        conn = duckdb.connect()
    except Exception as e:
        print(f"[FATAL] Could not initialize DuckDB: {e}")
        return
        
    # Process sequentially, outputting perfectly partitioned daily Parquet files
    for day_dir in sorted(subdirs):
        process_daily_directory_duckdb(day_dir, output_dir, conn)
            
    conn.close()
    print("Done! Partitioned FaaC generation complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate mathematically pure Partitioned FaaC Parquets via DuckDB Hybrid Batching.")
    parser.add_argument('--input', type=str, default="/data/flows/labeled", help="Base input directory containing daily labeled CSV folders")
    parser.add_argument('--output_dir', type=str, default="/data/flows/labeled/TimeSeries", help="Output directory for daily partitioned Parquet files")
    
    args = parser.parse_args()
    generate_faac_batch(args.input, args.output_dir)
