import os
import json
import datetime as _dt
import pandas as pd
import numpy as np
from datetime import datetime, timezone
from pathlib import Path

# ==============================================================================
# ZEEK MERGER — NAT-SAFE (excludes dst_ip from merge key)
# ==============================================================================
# MikroTik DNAT rewrites dst_ip before Zeek sees the packet, so NetFlow and
# Zeek observe DIFFERENT destination IPs for the same connection:
#   NetFlow dst_ip = 103.148.176.67  (pre-NAT virtual honeypot)
#   Zeek    dst_ip = 103.148.176.62  (post-NAT real host)
#
# Additionally:
#   - src_port (ephemeral) varies per connection attempt from the same attacker
#   - nfdump flow_start and Zeek c$start_time can differ by 1-3 minutes for
#     the same connection due to TZSP mirror delay and flow aggregation timing
#
# The NAT-safe merge key is: src_ip + dst_port + protocol + 5min_timestamp
# ==============================================================================

_MERGE_KEYS = ['src_ip', 'dst_port', 'protocol', 'time_bucket']

def _get_tz_offset():
    """Get local timezone offset for converting Zeek UTC timestamps to local time."""
    return _dt.datetime.now().astimezone().utcoffset()

_LOCAL_TZ_OFFSET = None

def get_local_tz_offset():
    """Cache the local timezone offset (computed once)."""
    global _LOCAL_TZ_OFFSET
    if _LOCAL_TZ_OFFSET is None:
        _LOCAL_TZ_OFFSET = _dt.datetime.now().astimezone().utcoffset()
    return _LOCAL_TZ_OFFSET

def load_zeek_data_pandas(features_path, dns_path):
    """Load Zeek features.log and dns.log, aggregate by NAT-safe keys."""
    zeek_df = pd.DataFrame()
    f_path = Path(features_path)
    d_path = Path(dns_path)
    
    if f_path.exists() and f_path.stat().st_size > 0:
        try:
            zeek_df = pd.read_csv(f_path, sep='\t', comment='#', 
                                  names=['ts', 'uid', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'iat_mean', 'iat_std', 'payload_entropy', 'init_win_bytes_forward'],
                                  on_bad_lines='skip')
            zeek_df['protocol'] = zeek_df['protocol'].str.upper()
            zeek_df['dst_port'] = zeek_df['dst_port'].astype(str)
            zeek_df['ts'] = pd.to_numeric(zeek_df['ts'], errors='coerce')
            zeek_df = zeek_df.dropna(subset=['ts'])
            # Zeek ts is raw Unix epoch (UTC). Convert to local time exactly once
            # by adding the UTC offset, then floor to 5-minute bucket.
            # NetFlow flow_start strings are already in local time, so this
            # ensures both sides land in the same time bucket.
            offset = get_local_tz_offset()
            zeek_df['time_bucket'] = (pd.to_datetime(zeek_df['ts'], unit='s', utc=True)
                                      .dt.tz_convert(None) + offset).dt.floor('5min')
            
            zeek_df = zeek_df.groupby(_MERGE_KEYS).agg({
                'iat_mean': 'mean',
                'iat_std': 'mean',
                'payload_entropy': 'max'
            }).reset_index()
        except Exception as e:
            print(f"[ERROR] Failed to load Zeek features into Pandas: {e}")
            zeek_df = pd.DataFrame()
            
    dns_df = pd.DataFrame()
    if d_path.exists() and d_path.stat().st_size > 0:
        try:
            dns_df = pd.read_csv(d_path, sep='\t', comment='#', usecols=[0, 2, 3, 4, 5, 6, 9],
                                 names=['ts', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'dns_query'],
                                 on_bad_lines='skip')
            dns_df['protocol'] = dns_df['protocol'].str.upper()
            dns_df['dst_port'] = dns_df['dst_port'].astype(str)
            dns_df['ts'] = pd.to_numeric(dns_df['ts'], errors='coerce')
            dns_df = dns_df.dropna(subset=['ts'])
            offset = get_local_tz_offset()
            dns_df['time_bucket'] = (pd.to_datetime(dns_df['ts'], unit='s', utc=True)
                                     .dt.tz_convert(None) + offset).dt.floor('5min')
            
            dns_df['dns_query'] = dns_df['dns_query'].fillna('')
            dns_df = dns_df.groupby(_MERGE_KEYS)['dns_query'].apply(lambda x: ','.join(set(x))).reset_index()
        except Exception as e:
            print(f"[ERROR] Failed to load Zeek DNS into Pandas: {e}")
            
    if not zeek_df.empty and not dns_df.empty:
        zeek_df = pd.merge(zeek_df, dns_df, on=_MERGE_KEYS, how='left')
        zeek_df['dns_query'] = zeek_df['dns_query'].fillna('none')
    elif not zeek_df.empty:
        zeek_df['dns_query'] = 'none'
    elif not dns_df.empty:
        zeek_df = dns_df
        zeek_df['iat_mean'] = 0.0
        zeek_df['iat_std'] = 0.0
        zeek_df['payload_entropy'] = 0.0
        
    return zeek_df

def merge_zeek_pandas(flows, zeek_df):
    """Merge Zeek DPI features into nfdump flow records using NAT-safe keys."""
    if not flows:
        return []
        
    df = pd.DataFrame(flows)
    
    if zeek_df is None or zeek_df.empty:
        df['iat_mean'] = 0.0
        df['iat_std'] = 0.0
        df['payload_entropy'] = 0.0
        df['dns_query'] = 'none'
        return df.to_dict('records')
        
    # NetFlow flow_start is already in local time — floor directly, no offset needed.
    df['time_bucket'] = pd.to_datetime(df['flow_start'], errors='coerce').dt.floor('5min')
    df['dst_port'] = df['dst_port'].astype(str)
    df['protocol'] = df['protocol'].str.upper()
    
    merged = pd.merge(df, zeek_df, on=_MERGE_KEYS, how='left')
    
    merged['iat_mean'] = merged['iat_mean'].fillna(0.0)
    merged['iat_std'] = merged['iat_std'].fillna(0.0)
    merged['payload_entropy'] = merged['payload_entropy'].fillna(0.0)
    merged['dns_query'] = merged['dns_query'].fillna('none')
    
    merged = merged.drop(columns=['time_bucket'])
    return merged.to_dict('records')


# ==============================================================================


# ==============================================================================
# PHASE 5: MULTIMODAL DNS CONTROL-PLANE LOGGING
# ==============================================================================

# End of pipeline_extensions.py
