import duckdb
import time

DATASET_PATH = "F:/Apex-IDS/parquet_dataset/date=*/type=attacks/*.parquet"

def get_exact_metrics():
    print("Connecting to DuckDB and querying dataset...")
    start = time.time()
    
    con = duckdb.connect(database=':memory:')
    
    # Query exact unique attacker IPs
    ip_result = con.execute(f"SELECT COUNT(DISTINCT src_ip) FROM read_parquet('{DATASET_PATH}')").fetchone()
    unique_ips = ip_result[0]
    
    # Query exact unique targeted ports
    port_result = con.execute(f"SELECT COUNT(DISTINCT dst_port) FROM read_parquet('{DATASET_PATH}')").fetchone()
    unique_ports = port_result[0]
    
    print(f"\\n=== EXACT ATTACK METRICS ===")
    print(f"Unique Attacker IPs: {unique_ips:,}")
    print(f"Unique Targeted Ports: {unique_ports:,}")
    print(f"Query completed in {time.time() - start:.2f} seconds.")

if __name__ == "__main__":
    get_exact_metrics()
