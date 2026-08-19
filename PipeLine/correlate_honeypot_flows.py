#!/usr/bin/env python3
"""
correlate_honeypot_flows.py — Research-Grade BDNET-IDS2025 Labeling Engine
══════════════════════════════════════════════════════════════════════════

FILE-DRIVEN ARCHITECTURE (rotation-agnostic):
  Instead of deriving filenames from honeypot timestamps (which breaks
  with non-5-minute rotation), this reads the manifest's actual time
  windows and matches honeypot hits to whichever file window contains
  them. Works with ANY nfcapd rotation interval (5m, 6m, 10m, etc.).

Labeling tiers:
  Tier 1 (honeypot-verified)    — FROM attacker TO honeypot. Ground truth.
  Tier 2 (attacker-associated)  — ALL other flows FROM confirmed attacker.
  Tier 3 (normal-sampled)       — Random sample of non-attacker flows.

Output: 30+ columns with TCP flag decomposition, port classification,
        MITRE ATT&CK mapping, computed rate features.

Usage:
    python3 correlate_honeypot_flows.py              # process new windows
    python3 correlate_honeypot_flows.py --reprocess   # redo all
    python3 correlate_honeypot_flows.py --stats        # show dataset stats
"""

import subprocess
import csv
import re
import argparse
import os
import fcntl
import time
import random
import tempfile
import gzip
import shutil
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import defaultdict, Counter
import ipaddress
import pipeline_extensions as pext

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

HONEYPOT_CSV   = Path("/data/flows/metadata/honeypot_hits.csv")
MANIFEST_FILE  = Path("/data/flows/metadata/dataset_manifest.csv")
LABELED_DIR    = Path("/data/flows/labeled")
COMPRESSED_DIR = Path("/data/flows/compressed")
RAW_DIR        = Path("/data/flows/raw")
SUMMARY_FILE   = Path("/data/flows/metadata/labeling_summary.csv")
PIPELINE_LOG   = Path("/data/flows/metadata/pipeline.log")
LOCK_FILE      = Path("/tmp/correlator.lock")

ZEEK_LOG_PATH  = Path("/data/flows/metadata/features.log") # Ensure Zeek runs in this dir, or outputs here
ZEEK_DNS_PATH  = Path("/data/flows/metadata/dns.log")
FAAC_PARQUET_PATH = Path("/data/flows/labeled/TimeSeries_FaaC.parquet")

HONEYPOT_IP    = "103.148.176.62"
TIME_BUDGET_S  = 300   # 4 min max per cron cycle

# Normal flow sampling: export this many normal flows per window
NORMAL_SAMPLE_SIZE = 5000

# AbuseIPDB threat intelligence (Layer 1)
ABUSEIPDB_KEY       = "9229cad785bd1dfa7d8e71666516fee56ff7de7c78c853cc47694d7ea944372a6699f5e647661044"
ABUSEIPDB_CACHE     = Path("/data/flows/metadata/abuseipdb_cache.json")
ABUSEIPDB_THRESHOLD = 25      # score >= 25 → flag as threat-intel-hit
ABUSEIPDB_CACHE_DAYS = 7      # re-check IPs older than this
ABUSEIPDB_MAX_CHECKS = 200    # max new lookups per window (rate-limit safety)

# Extended nfdump format for TCP flags, ToS, and computed rates
NFDUMP_FMT = (
    "fmt:%ts,%td,%pr,%sa,%sp,%da,%dp,%pkt,%byt,%fl,%flg,%tos,%bps,%pps,%bpp"
)

# ── Output schema ────────────────────────────────────────────────────────────

FLOW_COLS = [
    # Raw flow fields
    "flow_start", "duration_s", "protocol",
    "src_ip", "src_port", "dst_ip", "dst_port",
    "packets", "bytes", "tcp_flags", "tos",
    "iat_mean", "iat_std", "payload_entropy", "dns_query",
    # Computed rates
    "bytes_per_sec", "packets_per_sec", "bytes_per_packet",
    # Flag decomposition
    "flag_syn", "flag_ack", "flag_fin", "flag_rst", "flag_psh", "flag_urg",
    # Port classification
    "src_port_category", "dst_port_category",
    "flow_duration_class",
    # Labels
    "label", "attack_type", "attack_category",
    "mitre_technique", "mitre_tactic",
    "confidence", "evidence_source",
    # Validation layers
    "threat_intel_score", "country", "behavioral_flags",
    "flow_file",
]

SUMMARY_COLS = [
    "date", "flow_file", "total_flows",
    "tier1_flows", "tier2_flows", "tier3_flows", "unverified_flows",
    "attack_pct", "unique_attackers", "attack_types",
    "labeling_status", "updated_at",
]


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK TAXONOMY + MITRE ATT&CK MAPPING
# ═══════════════════════════════════════════════════════════════════════════════

ATTACK_TAXONOMY = {
    # port → (attack_type, attack_category, mitre_technique, mitre_tactic)
    "21":    ("FTP-Brute",        "brute-force",      "T1110",     "credential-access"),
    "22":    ("SSH-Brute",        "brute-force",      "T1110.001", "credential-access"),
    "23":    ("Telnet-Brute",     "brute-force",      "T1110",     "credential-access"),
    "25":    ("SMTP-Probe",       "service-probe",    "T1046",     "discovery"),
    "53":    ("DNS-Probe",        "service-probe",    "T1046",     "discovery"),
    "80":    ("HTTP-Probe",       "web-attack",       "T1190",     "initial-access"),
    "110":   ("POP3-Probe",       "service-probe",    "T1046",     "discovery"),
    "143":   ("IMAP-Probe",       "service-probe",    "T1046",     "discovery"),
    "443":   ("HTTPS-Probe",      "web-attack",       "T1190",     "initial-access"),
    "445":   ("SMB-Probe",        "lateral-movement", "T1021.002", "lateral-movement"),
    "1433":  ("MSSQL-Brute",      "brute-force",      "T1110",     "credential-access"),
    "1521":  ("Oracle-Probe",     "brute-force",      "T1110",     "credential-access"),
    "3306":  ("MySQL-Brute",      "brute-force",      "T1110",     "credential-access"),
    "3389":  ("RDP-Brute",        "brute-force",      "T1110.001", "credential-access"),
    "5432":  ("PostgreSQL-Probe", "brute-force",      "T1110",     "credential-access"),
    "5900":  ("VNC-Brute",        "brute-force",      "T1110",     "credential-access"),
    "6379":  ("Redis-Probe",      "service-probe",    "T1046",     "discovery"),
    "8080":  ("HTTP-Alt-Probe",   "web-attack",       "T1190",     "initial-access"),
    "8443":  ("HTTPS-Alt-Probe",  "web-attack",       "T1190",     "initial-access"),
    "27017": ("MongoDB-Probe",    "service-probe",    "T1046",     "discovery"),
    "8333":  ("Bitcoin-Probe",    "service-probe",    "T1046",     "discovery"),
    "9051":  ("Tor-Probe",        "service-probe",    "T1046",     "discovery"),
}

KNOWN_SAFE_SUBNETS = {
    # Local ISP Infrastructure (IPTV, Cache, Management)
    "103.148.176.0/22": "Exabyte Local Infrastructure",
    "57.144.142.0/24": "Local BD Cache",
    "45.113.134.0/24": "Local BD Cache",
    "59.152.108.0/24": "Local BD Cache",

    # Google (YouTube, Search, Cloud)
    "8.8.8.0/24": "Google",
    "8.8.4.0/24": "Google",
    "142.250.0.0/15": "Google",
    "172.217.0.0/16": "Google",
    "216.239.32.0/19": "Google",
    
    # Cloudflare
    "1.1.1.0/24": "Cloudflare",
    "104.16.0.0/12": "Cloudflare",
    "172.64.0.0/13": "Cloudflare",
    "162.159.0.0/16": "Cloudflare",
    "103.21.244.0/22": "Cloudflare",
    
    # Meta (Facebook, Instagram, WhatsApp)
    "31.13.24.0/21": "Meta",
    "157.240.0.0/16": "Meta",
    "69.63.176.0/20": "Meta"
}

_COMPILED_SUBNETS = []
for cidr, name in KNOWN_SAFE_SUBNETS.items():
    try:
        _COMPILED_SUBNETS.append((ipaddress.ip_network(cidr), name))
    except ValueError:
        pass

def get_safe_destination_name(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        for net, name in _COMPILED_SUBNETS:
            if ip in net:
                return name
    except ValueError:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 1: ABUSEIPDB THREAT INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════

_ABUSEIPDB_QUOTA_EXHAUSTED = False
_GLOBAL_CHECKS = 0

def _is_private_ip(ip_str):
    """Check if IP is RFC1918, loopback, or link-local."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return True


def _load_abuseipdb_cache():
    """Load cached AbuseIPDB results from disk."""
    if ABUSEIPDB_CACHE.exists():
        try:
            with open(ABUSEIPDB_CACHE) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def _save_abuseipdb_cache(cache):
    """Save AbuseIPDB cache atomically."""
    ABUSEIPDB_CACHE.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(str(ABUSEIPDB_CACHE) + ".tmp")
    with open(tmp, "w") as f:
        json.dump(cache, f)
    tmp.replace(ABUSEIPDB_CACHE)


def _check_abuseipdb_single(ip_str):
    """Query AbuseIPDB for a single IP. Returns (score, countryCode) or (-1, "") on error. (-2, "") on 429."""
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_str}&maxAgeInDays=90"
    req = urllib.request.Request(url)
    req.add_header("Key", ABUSEIPDB_KEY)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            d = data.get("data", {})
            return d.get("abuseConfidenceScore", 0), d.get("countryCode", "")
    except urllib.error.HTTPError as e:
        if e.code == 429:
            return -2, ""  # Rate limit hit
        return -1, ""
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return -1, ""


def batch_check_abuseipdb(ip_list):
    """Check IPs against AbuseIPDB with local caching.
    Skips private IPs and known-safe subnets.
    Returns dict: {ip: {"score": s, "country": c}}
    """
    global _ABUSEIPDB_QUOTA_EXHAUSTED, _GLOBAL_CHECKS
    
    cache = _load_abuseipdb_cache()
    results = {}
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=ABUSEIPDB_CACHE_DAYS)
    to_check = []

    for ip in set(ip_list):
        if not ip:
            continue
        # Skip private & known-safe — always score 0
        if _is_private_ip(ip) or get_safe_destination_name(ip):
            results[ip] = {"score": 0, "country": "Local"}
            continue
        # Use cache if fresh
        cached = cache.get(ip)
        if cached:
            try:
                checked_at = datetime.fromisoformat(cached["checked_at"])
                if checked_at > cutoff:
                    results[ip] = {
                        "score": cached["score"],
                        "country": cached.get("country", "")
                    }
                    continue
            except (KeyError, ValueError):
                pass
        to_check.append(ip)

    if not to_check:
        return results

    if _ABUSEIPDB_QUOTA_EXHAUSTED:
        log(f"    AbuseIPDB: Quota exhausted. Skipping {len(to_check)} checks.")
        for ip in to_check:
            results[ip] = {"score": 0, "country": ""}
        return results

    log(f"    AbuseIPDB: {len(to_check)} IPs to check "
        f"({len(results)} cached)...")
    checked = 0
    for ip in to_check:
        score, country = _check_abuseipdb_single(ip)
        
        if score == -2:
            _ABUSEIPDB_QUOTA_EXHAUSTED = True
            log("    AbuseIPDB: HTTP 429 Too Many Requests - Daily limit of 1,000 reached!")
            break
            
        if score >= 0:
            results[ip] = {"score": score, "country": country}
            cache[ip] = {
                "score": score,
                "country": country,
                "checked_at": now.isoformat(),
            }
            checked += 1
            _GLOBAL_CHECKS += 1
        else:
            results[ip] = {"score": 0, "country": ""}  # API error → conservative fallback
            
        time.sleep(0.1)  # Free tier easily handles 10/sec, reduce from 0.5s
        
        if checked >= ABUSEIPDB_MAX_CHECKS:
            log(f"    AbuseIPDB: Window safety cap at {checked} checks")
            break
            
        if _GLOBAL_CHECKS >= 950:
            _ABUSEIPDB_QUOTA_EXHAUSTED = True
            log(f"    AbuseIPDB: Global safety cap of 950 checks reached!")
            break

    _save_abuseipdb_cache(cache)
    flagged = sum(1 for d in results.values() if d["score"] >= ABUSEIPDB_THRESHOLD)
    log(f"    AbuseIPDB: {checked} queried, {flagged} flagged "
        f"(score≥{ABUSEIPDB_THRESHOLD})")
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER 2: BEHAVIORAL ANOMALY DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def detect_behavioral_anomalies(flows):
    """Flag scan/probe patterns from EXTERNAL source IPs.
    Internal (RFC1918) sources are skipped — client diversity is normal.
    Returns dict: {src_ip: [list of anomaly flags]}
    """
    flags = defaultdict(list)
    ip_dst_ports = defaultdict(set)
    ip_dst_ips = defaultdict(set)

    for flow in flows:
        src_ip = flow.get("src_ip", "")
        if not src_ip or _is_private_ip(src_ip):
            continue  # skip internal client traffic

        dst_port = str(flow.get("dst_port", "0"))
        dst_ip = flow.get("dst_ip", "")
        protocol = flow.get("protocol", "")
        try:
            packets = int(flow.get("packets", 0))
            bytes_val = int(flow.get("bytes", 0))
            syn = int(flow.get("flag_syn", 0))
            ack = int(flow.get("flag_ack", 0))
            fin = int(flow.get("flag_fin", 0))
            rst = int(flow.get("flag_rst", 0))
        except (ValueError, TypeError):
            continue

        ip_dst_ports[src_ip].add(dst_port)
        ip_dst_ips[src_ip].add(dst_ip)

        # Single-packet TCP with tiny payload (≤52 bytes = bare SYN/RST)
        if (protocol == "TCP" and packets == 1 and bytes_val <= 52
                and "scan-like:single-pkt-tcp" not in flags[src_ip]):
            flags[src_ip].append("scan-like:single-pkt-tcp")

        # SYN-only probe (no ACK, no FIN — never completed handshake)
        if (protocol == "TCP" and packets == 1
                and syn == 1 and ack == 0 and fin == 0
                and "scan-like:syn-only" not in flags[src_ip]):
            flags[src_ip].append("scan-like:syn-only")

    # Port sweep: external IP → ≥ 10 distinct dst_ports
    for src_ip, ports in ip_dst_ports.items():
        if len(ports) >= 10:
            flags[src_ip].append(f"scan-like:port-sweep({len(ports)})")

    # Network sweep: external IP → ≥ 15 distinct dst_ips
    for src_ip, ips in ip_dst_ips.items():
        if len(ips) >= 15:
            flags[src_ip].append(f"scan-like:net-sweep({len(ips)})")

    return dict(flags)


def classify_attack(dst_port, honeypot_types=None):
    """Return (attack_type, category, mitre_technique, mitre_tactic)."""
    port = str(dst_port)
    if port in ATTACK_TAXONOMY:
        return ATTACK_TAXONOMY[port]

    if honeypot_types:
        mc = Counter(honeypot_types).most_common(1)
        if mc:
            hp_type = mc[0][0]
            for _, (at, ac, amt, amtc) in ATTACK_TAXONOMY.items():
                if at == hp_type:
                    return (at, ac, amt, amtc)

    return (f"Port-{port}-Scan", "reconnaissance", "T1046", "discovery")


def classify_port(port_str):
    try:
        p = int(port_str)
    except (ValueError, TypeError):
        return "unknown"
    if p <= 0:     return "invalid"
    if p <= 1023:  return "well-known"
    if p <= 49151: return "registered"
    return "dynamic"


def classify_duration(dur_str):
    try:
        # Handle nfdump %td format which outputs HH:MM:SS.msec
        if ":" in str(dur_str):
            parts = str(dur_str).split(":")
            if len(parts) == 3:
                h, m, s = parts
                d = float(h) * 3600 + float(m) * 60 + float(s)
            else:
                return "unknown"
        else:
            d = float(dur_str)
    except (ValueError, TypeError):
        return "unknown"
        
    if d == 0:   return "instant"
    if d < 1:    return "sub-second"
    if d < 10:   return "short"
    if d < 60:   return "medium"
    if d < 300:  return "long"
    return "persistent"


def decompose_tcp_flags(flags_str):
    f = str(flags_str).upper() if flags_str else ""
    return {
        "flag_syn": 1 if "S" in f else 0,
        "flag_ack": 1 if "A" in f else 0,
        "flag_fin": 1 if "F" in f else 0,
        "flag_rst": 1 if "R" in f else 0,
        "flag_psh": 1 if "P" in f else 0,
        "flag_urg": 1 if "U" in f else 0,
    }


PROTO_MAP = {"6": "TCP", "17": "UDP", "1": "ICMP", "58": "ICMPv6"}

def proto_name(p):
    return PROTO_MAP.get(str(p).strip(), str(p))


# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

def log(msg):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"[{ts}] [correlate] {msg}"
    print(line)
    try:
        PIPELINE_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(PIPELINE_LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# NFDUMP INTERFACE
# ═══════════════════════════════════════════════════════════════════════════════

def find_nfcapd_file(file_name):
    """Prefer raw (no decompression overhead) over compressed."""
    raw = RAW_DIR / file_name
    if raw.exists():
        return raw
    gz = COMPRESSED_DIR / f"{file_name}.gz"
    if gz.exists():
        return gz
    return None


def run_nfdump(filepath, extra_args, filter_expr=""):
    """Run nfdump. Handles .gz with temp file + cleanup."""
    filepath = Path(filepath)
    is_gz = filepath.suffix == ".gz"
    temp_path = None

    try:
        if is_gz:
            fd, temp_path = tempfile.mkstemp(prefix="nfcapd_")
            os.close(fd)
            with gzip.open(filepath, "rb") as src, open(temp_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            target = temp_path
        else:
            target = str(filepath)

        cmd = ["nfdump", "-r", target] + extra_args
        if filter_expr:
            cmd.extend(filter_expr.split())

        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return r.stdout.strip().split("\n") if r.stdout else []

    except subprocess.TimeoutExpired:
        log(f"  Timeout: nfdump on {filepath.name}")
        return []
    except Exception as e:
        log(f"  nfdump error: {e}")
        return []
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)


def get_total_flows(filepath):
    """Get total flow count using nfdump -I."""
    for line in run_nfdump(filepath, ["-I"]):
        if line.strip().startswith("Flows:"):
            try:
                return int(line.split(":")[1].strip())
            except (ValueError, IndexError):
                pass
    return 0


# ═══════════════════════════════════════════════════════════════════════════════
# FLOW PARSING
# ═══════════════════════════════════════════════════════════════════════════════

def parse_extended_flow(line):
    """Parse nfdump custom fmt output (15 comma-separated fields)."""
    parts = [p.strip() for p in line.split(",")]
    if len(parts) < 15:
        return None
    try:
        flags = decompose_tcp_flags(parts[10])
        return {
            "flow_start":        parts[0],
            "duration_s":        parts[1],
            "protocol":          proto_name(parts[2]),
            "src_ip":            parts[3],
            "src_port":          parts[4],
            "dst_ip":            parts[5],
            "dst_port":          parts[6],
            "packets":           parts[7],
            "bytes":             parts[8],
            "tcp_flags":         parts[10],
            "tos":               parts[11],
            "bytes_per_sec":     parts[12],
            "packets_per_sec":   parts[13],
            "bytes_per_packet":  parts[14],
            **flags,
            "src_port_category": classify_port(parts[4]),
            "dst_port_category": classify_port(parts[6]),
            "flow_duration_class": classify_duration(parts[1]),
        }
    except Exception:
        return None


def parse_basic_csv(line):
    """Fallback parser for nfdump -o csv (10 fields)."""
    parts = [p.strip() for p in line.split(",")]
    if len(parts) < 10:
        return None
    try:
        dur = float(parts[1]) if parts[1] else 0
        pkts = int(parts[7]) if parts[7] else 0
        byts = int(parts[8]) if parts[8] else 0
        bpp = round(byts / max(pkts, 1))
        pps = round(pkts / max(dur, 0.001))
        bps = round(byts / max(dur, 0.001))

        return {
            "flow_start":        parts[0],
            "duration_s":        parts[1],
            "protocol":          proto_name(parts[2]),
            "src_ip":            parts[3],
            "src_port":          parts[4],
            "dst_ip":            parts[5],
            "dst_port":          parts[6],
            "packets":           parts[7],
            "bytes":             parts[8],
            "tcp_flags":         "",
            "tos":               "0",
            "bytes_per_sec":     str(bps),
            "packets_per_sec":   str(pps),
            "bytes_per_packet":  str(bpp),
            "flag_syn": 0, "flag_ack": 0, "flag_fin": 0,
            "flag_rst": 0, "flag_psh": 0, "flag_urg": 0,
            "src_port_category": classify_port(parts[4]),
            "dst_port_category": classify_port(parts[6]),
            "flow_duration_class": classify_duration(parts[1]),
        }
    except Exception:
        return None


def _detect_format(filepath):
    """Try extended fmt first; fall back to basic csv."""
    # Request a few lines to guarantee we pass the header lines
    test = run_nfdump(filepath, ["-o", NFDUMP_FMT, "-c", "5"])
    
    if test:
        for line in test:
            # Skip empty lines or known nfdump text summaries/headers
            if not line or line.startswith("Summary") or line.startswith("Time window"):
                continue
            
            parts = line.split(",")
            if len(parts) >= 15:
                return "extended"
                
    # Fallback to basic mode only if extended validation explicitly fails
    return "basic"


# ═══════════════════════════════════════════════════════════════════════════════
# FLOW EXTRACTION — BATCHED QUERIES
# ═══════════════════════════════════════════════════════════════════════════════

def _build_or_filter(ips, max_chunk=50):
    chunks = []
    for i in range(0, len(ips), max_chunk):
        batch = ips[i:i + max_chunk]
        parts = " or ".join(f"src ip {ip}" for ip in batch)
        chunks.append(f"({parts})")
    return chunks


def extract_flows(filepath, attacker_ips, dst_filter, fmt_mode):
    """Extract flows matching attacker IPs + destination filter."""
    all_flows = []
    ip_set = set(attacker_ips)

    if fmt_mode == "extended":
        out_args = ["-o", NFDUMP_FMT]
        parser = parse_extended_flow
    else:
        out_args = ["-o", "csv"]
        parser = parse_basic_csv

    for chunk in _build_or_filter(attacker_ips):
        full_filter = f"{dst_filter} and {chunk}" if dst_filter else chunk

        lines = run_nfdump(filepath, out_args, full_filter)
        for line in lines:
            if not line or line.startswith("firstSeen") or line.startswith("Summary"):
                continue
            if "No matching" in line:
                continue
            flow = parser(line)
            if flow and flow["src_ip"] in ip_set:
                all_flows.append(flow)

    return all_flows


def extract_normal_sample(filepath, attacker_ips, sample_size, fmt_mode):
    """Extract random sample of NORMAL flows (negative class for ML)."""
    if not attacker_ips:
        return []

    # Exclusion filter: NOT from any known attacker (limit to 100 for filter length)
    exclude_ips = attacker_ips[:100]
    exclude = " and ".join(f"not src ip {ip}" for ip in exclude_ips)

    if fmt_mode == "extended":
        out_args = ["-o", NFDUMP_FMT, "-c", str(sample_size * 2)]
        parser = parse_extended_flow
    else:
        out_args = ["-o", "csv", "-c", str(sample_size * 2)]
        parser = parse_basic_csv

    lines = run_nfdump(filepath, out_args, exclude)
    flows = []
    for line in lines:
        if not line or line.startswith("firstSeen") or line.startswith("Summary"):
            continue
        if "No matching" in line:
            continue
        flow = parser(line)
        if flow:
            flows.append(flow)

    if len(flows) > sample_size:
        flows = random.sample(flows, sample_size)
    return flows


# ═══════════════════════════════════════════════════════════════════════════════
# DATA LOADING
# ═══════════════════════════════════════════════════════════════════════════════

def load_honeypot_hits():
    if not HONEYPOT_CSV.exists():
        return []
    with open(HONEYPOT_CSV, newline="") as f:
        return list(csv.DictReader(f))


def load_manifest():
    if not MANIFEST_FILE.exists():
        return []
    with open(MANIFEST_FILE, newline="") as f:
        return list(csv.DictReader(f))


def load_summary():
    if not SUMMARY_FILE.exists():
        return {}
    with open(SUMMARY_FILE, newline="") as f:
        return {r["flow_file"]: r for r in csv.DictReader(f)}


# ═══════════════════════════════════════════════════════════════════════════════
# TIME WINDOW MATCHING — FILE-DRIVEN (ROTATION AGNOSTIC)
# ═══════════════════════════════════════════════════════════════════════════════

def parse_ts(ts_str):
    """Parse timestamp string into datetime."""
    if not ts_str or not ts_str.strip():
        return None
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"]:
        try:
            return datetime.strptime(ts_str.strip(), fmt)
        except ValueError:
            continue
    return None


def parse_nfcapd_filename_ts(file_name):
    """
    Extract timestamp from nfcapd filename: nfcapd.YYYYMMDDHHMI → datetime.
    This is used as a FALLBACK when manifest start_time/end_time are missing.
    """
    m = re.match(r"nfcapd\.(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})", file_name)
    if not m:
        return None
    return datetime(
        int(m.group(1)), int(m.group(2)), int(m.group(3)),
        int(m.group(4)), int(m.group(5))
    )


def build_time_windows(manifest_rows):
    """
    Build list of (start_dt, end_dt, file_name) from manifest.
    Uses actual nfdump time windows. Falls back to filename ± estimated
    rotation interval if timestamps are missing.

    This is ROTATION-AGNOSTIC — works with 5m, 6m, 10m, any interval.
    """
    windows = []
    rotation_estimate = timedelta(minutes=6)  # default estimate

    # First pass: collect files with valid timestamps to estimate rotation
    valid_timestamps = []
    for row in manifest_rows:
        fname = row.get("file_name", "").strip()
        start = parse_ts(row.get("start_time", ""))
        end   = parse_ts(row.get("end_time", ""))
        if fname and start and end:
            valid_timestamps.append((start, end, fname))

    # Estimate rotation interval from actual data
    if len(valid_timestamps) >= 2:
        valid_timestamps.sort()
        deltas = []
        for i in range(1, min(len(valid_timestamps), 10)):
            delta = valid_timestamps[i][0] - valid_timestamps[i-1][0]
            if timedelta(minutes=1) < delta < timedelta(minutes=30):
                deltas.append(delta)
        if deltas:
            rotation_estimate = sorted(deltas)[len(deltas)//2]  # median

    log(f"  Estimated rotation interval: {rotation_estimate.total_seconds():.0f}s")

    # Second pass: build windows for ALL manifest entries
    for row in manifest_rows:
        fname = row.get("file_name", "").strip()
        if not fname:
            continue

        start = parse_ts(row.get("start_time", ""))
        end   = parse_ts(row.get("end_time", ""))

        if start and end:
            windows.append((start, end, fname))
        else:
            # Fallback: derive from filename
            fn_ts = parse_nfcapd_filename_ts(fname)
            if fn_ts:
                windows.append((fn_ts, fn_ts + rotation_estimate, fname))

    windows.sort(key=lambda x: x[0])
    return windows


def match_hits_to_windows(honeypot_hits, time_windows):
    """
    Match each honeypot hit to its containing nfcapd time window.
    Returns: window_attackers (dict)

    This is the KEY function that makes the system rotation-agnostic.
    Instead of deriving filenames from timestamps, we check which
    actual time window each hit falls into.
    """
    # Now stores a dict with "types" and "ports" for each attacker
    window_attackers = defaultdict(lambda: defaultdict(lambda: {"types": set(), "ports": set()}))
    unmatched = 0

    for hit in honeypot_hits:
        hit_ts = parse_ts(hit.get("timestamp", ""))
        src_ip = hit.get("src_ip", "")
        atk_type = hit.get("attack_type", "Port-Scan")
        dst_port = str(hit.get("dst_port", "0"))

        if not hit_ts or not src_ip:
            continue

        # Find the window that contains this hit timestamp
        matched = False
        for w_start, w_end, w_file in time_windows:
            # Allow 30s buffer on each side for timestamp drift
            if (w_start - timedelta(seconds=30)) <= hit_ts <= (w_end + timedelta(seconds=30)):
                window_attackers[w_file][src_ip]["types"].add(atk_type)
                window_attackers[w_file][src_ip]["ports"].add(dst_port)
                matched = True
                break

        if not matched:
            unmatched += 1

    if unmatched:
        log(f"  Unmatched hits (outside any time window): {unmatched}")

    return window_attackers


# ═════════════════════════════════════════════════════════════════════════════
# WINDOW PROCESSING — MULTI-TIER LABELING
# ═══════════════════════════════════════════════════════════════════════════════

def _label_flows(flows, attacker_data, label, confidence, flow_file,
                 evidence_source="honeypot:port-match",
                 abuseipdb_data=None, behavioral_flags=None):
    """Annotate flows with 5-tier labels, MITRE mapping, and validation layers.

    5-Tier Label System:
        Attack_Verified  — honeypot-matched + port-matched   (★★★★★)
        Attack_Associated — honeypot-matched + different port (★★★★☆)
        Benign_Verified  — safe dest + clean intel + clean behavior (★★★★☆)
        Benign_Assumed   — no threat indicators, unverified dest   (★★★☆☆)
        Unverified       — threat intel flagged OR behavioral anomaly (★★☆☆☆)
    """
    rows = []
    for flow in flows:
        src_ip = flow.get("src_ip", "")
        dst_ip = flow.get("dst_ip", "")
        attacker_info = attacker_data.get(src_ip, {})
        hp_types = list(attacker_info.get("types", [])) if attacker_info else []

        atype, acat, amt, amtac = classify_attack(
            flow.get("dst_port", "0"), hp_types
        )

        current_label = label
        current_confidence = confidence
        current_evidence = evidence_source
        ti_score = ""
        country = ""
        bf_str = ""

        # Global lookup for Threat Intel
        if abuseipdb_data is not None and src_ip in abuseipdb_data:
            ti_data = abuseipdb_data[src_ip]
            ti_score = str(ti_data.get("score", 0))
            country = ti_data.get("country", "")
        
        # ── Attack tiers (unchanged logic) ────────────────────────────
        if label == "attack":
            current_label = "Attack_Verified"
        elif label == "suspicious":
            current_label = "Attack_Associated"

        # ── Normal tier → 5-tier decision tree ────────────────────────
        elif label == "normal":
            atype, acat, amt, amtac = "normal", "benign", "", ""

            abuse_score = 0
            if abuseipdb_data is not None and src_ip in abuseipdb_data:
                abuse_score = abuseipdb_data[src_ip].get("score", 0)
                
            src_flags = (behavioral_flags or {}).get(src_ip, [])
            safe_name = get_safe_destination_name(dst_ip)

            bf_str = ";".join(src_flags) if src_flags else ""

            # Decision: most suspicious first
            if abuse_score >= ABUSEIPDB_THRESHOLD:
                current_label = "Unverified"
                current_confidence = "threat-intel-flagged"
                current_evidence = f"abuseipdb:score={abuse_score}"
            elif src_flags:
                current_label = "Unverified"
                current_confidence = "behavioral-anomaly"
                current_evidence = ";".join(src_flags)
            elif safe_name:
                current_label = "Benign_Verified"
                if abuseipdb_data is not None:
                    current_confidence = "multi-layer-verified"
                    current_evidence = f"clean-intel+safe-dest:{safe_name}"
                else:
                    current_confidence = "destination-verified"
                    current_evidence = f"safe-dest:{safe_name}"
            else:
                current_label = "Benign_Assumed"
                current_confidence = "no-threat-indicators"
                current_evidence = "unverified-destination"

        rows.append({
            **flow,
            "label":              current_label,
            "attack_type":        atype,
            "attack_category":    acat,
            "mitre_technique":    amt,
            "mitre_tactic":       amtac,
            "confidence":         current_confidence,
            "evidence_source":    current_evidence,
            "threat_intel_score": ti_score,
            "country":            country,
            "behavioral_flags":   bf_str,
            "flow_file":          flow_file,
        })
    return rows


def _write_csv(filepath, rows):
    """Write labeled flows to CSV."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FLOW_COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def process_window(file_name, filepath, attacker_data, manifest_rows,
                   existing_summary, fmt_mode, use_abuseipdb=True, zeek_df=None):
    """
    Process one nfcapd time window with 5-tier gold-standard labeling.
    Layers: Honeypot correlation → AbuseIPDB → Behavioral analysis → Destination check
    Returns (t1_count, t2_count, t3_count, attacker_count, types_seen, unverified_count)
    """
    if not filepath or not filepath.exists():
        log(f"  File not found: {file_name}")
        return 0, 0, 0, 0, set(), 0

    attacker_ips = list(attacker_data.keys())
    is_raw = not filepath.name.endswith(".gz")
    log(f"  Processing: {file_name} ({len(attacker_ips)} attackers, "
        f"{'raw' if is_raw else 'compressed'})")

    # Get total flows from manifest
    manifest_row = next(
        (r for r in manifest_rows if r.get("file_name") == file_name), {}
    )
    total_flows = 0
    try:
        total_flows = int(manifest_row.get("flows", 0))
    except (ValueError, TypeError):
        total_flows = get_total_flows(filepath)

    # Date directory for output
    try:
        dd = re.search(r"nfcapd\.(\d{8})", file_name).group(1)
        date_fmt = f"{dd[:4]}-{dd[4:6]}-{dd[6:8]}"
    except Exception:
        date_fmt = "unknown"

    output_dir = LABELED_DIR / date_fmt

    # ── EXTRACT ALL ATTACKER FLOWS ───────────────────────────────────────
    # We pull everything from these IPs first to avoid IP mismatch issues.
    all_attacker_flows = extract_flows(filepath, attacker_ips, "", fmt_mode)
    
    t1_raw_flows = []
    t2_raw_flows = []
    
    # Port-based splitting
    for flow in all_attacker_flows:
        src_ip = flow.get("src_ip", "")
        dst_port = str(flow.get("dst_port", "0"))
        
        attacker_info = attacker_data.get(src_ip, {})
        hit_ports = attacker_info.get("ports", set())
        
        if dst_port in hit_ports:
            t1_raw_flows.append(flow)
        else:
            t2_raw_flows.append(flow)

    # ── TIER 3: Normal sample with multi-layer validation ────────────────
    t3_flows = extract_normal_sample(filepath, attacker_ips,
                                     NORMAL_SAMPLE_SIZE, fmt_mode)

    # ── MERGE ZEEK FEATURES & DNS (PANDAS VECTORIZED) ────────────────────
    t1_raw_flows = pext.merge_zeek_pandas(t1_raw_flows, zeek_df)
    t2_raw_flows = pext.merge_zeek_pandas(t2_raw_flows, zeek_df)
    t3_flows = pext.merge_zeek_pandas(t3_flows, zeek_df)

    # (FaaC aggregations are now handled separately via batch scripts)

    # Layer 1: AbuseIPDB threat intelligence cross-validation (All IPs)
    abuseipdb_data = None
    if use_abuseipdb and ABUSEIPDB_KEY:
        # Collect IPs from all 3 tiers so we get country data for attacks too!
        unique_src_ips = set(attacker_ips)
        unique_src_ips.update(f.get("src_ip", "") for f in t3_flows if f.get("src_ip"))
        abuseipdb_data = batch_check_abuseipdb(list(unique_src_ips))

    # ── TIER 1: Honeypot-verified (Port Matched) ─────────────────────────
    t1_rows = _label_flows(t1_raw_flows, attacker_data,
                           "attack", "honeypot-verified", file_name, "honeypot:port-match",
                           abuseipdb_data=abuseipdb_data)
    types_seen = set(r["attack_type"] for r in t1_rows)

    if t1_rows:
        _write_csv(output_dir / f"{file_name}_attacks.csv", t1_rows)
        log(f"    ✓ Tier 1: {len(t1_rows)} honeypot-verified")

    # ── TIER 2: Attacker-associated (Different Port) ─────────────────────
    t2_rows = _label_flows(t2_raw_flows, attacker_data,
                           "suspicious", "attacker-associated", file_name, "honeypot:port-mismatch",
                           abuseipdb_data=abuseipdb_data)

    if t2_rows:
        _write_csv(output_dir / f"{file_name}_suspicious.csv", t2_rows)
        log(f"    ✓ Tier 2: {len(t2_rows)} attacker-associated")

    # Layer 2: Behavioral anomaly detection
    behavior_flags = detect_behavioral_anomalies(t3_flows)
    if behavior_flags:
        log(f"    Behavioral: {len(behavior_flags)} IPs flagged")

    # Layer 3: 5-tier label assignment
    t3_rows = _label_flows(
        t3_flows, {}, "normal", "normal-sampled", file_name,
        "default-benign-assumption",
        abuseipdb_data=abuseipdb_data,
        behavioral_flags=behavior_flags,
    )

    # Count label distribution
    unverified_count = sum(1 for r in t3_rows if r.get("label") == "Unverified")
    verified_count = sum(1 for r in t3_rows if r.get("label") == "Benign_Verified")
    assumed_count = sum(1 for r in t3_rows if r.get("label") == "Benign_Assumed")

    if t3_rows:
        _write_csv(output_dir / f"{file_name}_normal.csv", t3_rows)
        log(f"    ✓ Tier 3: {len(t3_rows)} total — "
            f"{verified_count} verified, {assumed_count} assumed, "
            f"{unverified_count} unverified")

    if not t1_rows and not t2_rows:
        log(f"    No attacker flows found")

    if types_seen:
        log(f"    Types: {', '.join(sorted(types_seen))}")

    # ── Update manifest in-memory ────────────────────────────────────────
    total_labeled = len(t1_rows) + len(t2_rows)
    for row in manifest_rows:
        if row.get("file_name") == file_name:
            row["label"] = "mixed" if total_labeled > 0 else "normal"
            row["attack_type"] = ",".join(sorted(types_seen)) or "none"
            row["notes"] = (f"v:{len(t1_rows)},a:{len(t2_rows)},"
                            f"n:{len(t3_rows)},u:{unverified_count},"
                            f"t:{total_flows}")
            break

    # ── Save summary incrementally (crash-safe) ─────────────────────────
    existing_summary[file_name] = {
        "date":             date_fmt,
        "flow_file":        file_name,
        "total_flows":      total_flows,
        "tier1_flows":      len(t1_rows),
        "tier2_flows":      len(t2_rows),
        "tier3_flows":      len(t3_rows),
        "unverified_flows": unverified_count,
        "attack_pct":       round(total_labeled / max(total_flows, 1) * 100, 4),
        "unique_attackers": len(attacker_ips),
        "attack_types":     ",".join(sorted(types_seen)),
        "labeling_status":  "labeled",
        "updated_at":       datetime.now(timezone.utc).isoformat(),
    }
    SUMMARY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SUMMARY_FILE, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SUMMARY_COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(existing_summary.values())

    # ── Detect and Log Major Events ──────────────────────────────────────
    attack_percentage = round(total_labeled / max(total_flows, 1) * 100, 4)
    
    # Thresholds for logging an event
    is_major_event = False
    event_reasons = []
    
    if attack_percentage >= 20.0:
        is_major_event = True
        event_reasons.append(f"High Attack Percentage: {attack_percentage}%")
    if total_labeled >= 500000:
        is_major_event = True
        event_reasons.append(f"Massive Attack Volume: {total_labeled:,} flows")
        
    if is_major_event:
        log(f"    🚨 MAJOR EVENT DETECTED: {' | '.join(event_reasons)}")
        journal_path = Path("/data/flows/docs/collection_journal.md")
        
        # Fallback to local path if running outside the server environment for testing
        if not journal_path.parent.exists():
            journal_path = Path("d:/Development/linkup/collection_journal.md")

        try:
            journal_path.parent.mkdir(parents=True, exist_ok=True)
            mode = "a" if journal_path.exists() else "w"
            with open(journal_path, mode, encoding="utf-8") as jf:
                if mode == "w":
                    jf.write("# APEX-IDS2026 Collection Journal\n\nThis journal tracks significant network events, anomalies, and milestones captured during the live data collection phase.\n\n## Major Events\n\n")
                
                event_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                jf.write(f"### {event_time} - Automated Alert Triggered\n")
                jf.write(f"- **File**: `{file_name}`\n")
                jf.write(f"- **Scale**: {total_labeled:,} verified/associated attack flows\n")
                jf.write(f"- **Attack Percentage**: {attack_percentage}% of total file flows ({total_flows:,})\n")
                if types_seen:
                    jf.write(f"- **Attack Types**: {', '.join(sorted(types_seen))}\n")
                jf.write(f"- **Trigger Reasons**: {' | '.join(event_reasons)}\n\n")
        except Exception as e:
            log(f"    Failed to write to journal: {e}")

    return len(t1_rows), len(t2_rows), len(t3_rows), len(attacker_ips), types_seen, unverified_count


# ═══════════════════════════════════════════════════════════════════════════════
# STATS
# ═══════════════════════════════════════════════════════════════════════════════

def show_stats():
    print("\n" + "═" * 60)
    print("  BDNET-IDS2025 Dataset Statistics")
    print("═" * 60)

    if HONEYPOT_CSV.exists():
        with open(HONEYPOT_CSV, newline="") as f:
            hits = list(csv.DictReader(f))
        types   = Counter(r.get("attack_type", "") for r in hits)
        src_ips = Counter(r.get("src_ip", "")      for r in hits)
        print(f"\n  Honeypot hits:          {len(hits):,}")
        print(f"  Unique attacker IPs:    {len(src_ips):,}")
        print(f"\n  Attack type distribution:")
        for t, c in types.most_common(15):
            pct = c / len(hits) * 100
            bar = "█" * int(pct / 2)
            print(f"    {t or '(unknown)':<28} {c:>6,} ({pct:5.1f}%) {bar}")
        print(f"\n  Top 10 attacker IPs:")
        for ip, c in src_ips.most_common(10):
            print(f"    {ip:<22} {c:>6,} hits")

    t1c = t2c = t3c = 0
    t1f = list(LABELED_DIR.rglob("*_attacks.csv")) if LABELED_DIR.exists() else []
    t2f = list(LABELED_DIR.rglob("*_suspicious.csv")) if LABELED_DIR.exists() else []
    t3f = list(LABELED_DIR.rglob("*_normal.csv")) if LABELED_DIR.exists() else []
    for f in t1f:
        try:
            with open(f) as fh: t1c += sum(1 for _ in csv.DictReader(fh))
        except: pass
    for f in t2f:
        try:
            with open(f) as fh: t2c += sum(1 for _ in csv.DictReader(fh))
        except: pass
    for f in t3f:
        try:
            with open(f) as fh: t3c += sum(1 for _ in csv.DictReader(fh))
        except: pass

    print(f"\n  ─── Labeled Dataset ───")
    print(f"  Tier 1 (verified):    {len(t1f):>4} files, {t1c:>10,} flows")
    print(f"  Tier 2 (associated):  {len(t2f):>4} files, {t2c:>10,} flows")
    print(f"  Tier 3 (normal):      {len(t3f):>4} files, {t3c:>10,} flows")
    print(f"  Total:                {'':>4}        {t1c+t2c+t3c:>10,} flows")

    if MANIFEST_FILE.exists():
        with open(MANIFEST_FILE, newline="") as f:
            rows = list(csv.DictReader(f))
        mixed  = sum(1 for r in rows if r.get("label") == "mixed")
        normal = sum(1 for r in rows if r.get("label") == "normal")
        unlbl  = len(rows) - mixed - normal
        print(f"\n  ── Manifest ───")
        print(f"  Total windows:  {len(rows):,}")
        print(f"    Labeled:      {mixed + normal:,} ({mixed} mixed + {normal} normal)")
        print(f"    Pending:      {unlbl:,}")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    global TIME_BUDGET_S  # must be declared before any use in this function
    parser = argparse.ArgumentParser(
        description="BDNET-IDS2025 Research-Grade Labeling Engine"
    )
    parser.add_argument("--reprocess", action="store_true")
    parser.add_argument("--stats", action="store_true")
    parser.add_argument("--no-abuseipdb", action="store_true",
                        help="Skip AbuseIPDB checks (Layer 1)")
    parser.add_argument("--time-budget", type=int, default=TIME_BUDGET_S,
                        help="Max seconds to run (0 = unlimited). Default: 300s for cron.")
    parser.add_argument("--from-date", type=str, default=None,
                        help="Only process windows on or after this date (YYYY-MM-DD). Skips older manifest entries.")
    args = parser.parse_args()

    # Override global time budget if specified
    if args.time_budget == 0:
        TIME_BUDGET_S = 999999999  # effectively unlimited
    else:
        TIME_BUDGET_S = args.time_budget

    if args.stats:
        show_stats()
        return

    # ── Ensure directories ───────────────────────────────────────────────
    for d in [LABELED_DIR, COMPRESSED_DIR, RAW_DIR,
              PIPELINE_LOG.parent, SUMMARY_FILE.parent]:
        d.mkdir(parents=True, exist_ok=True)

    # ── Process lock ─────────────────────────────────────────────────────
    lock_fd = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log("Correlator already running. Exiting.")
        lock_fd.close()
        return

    try:
        start_time = time.time()

        hits          = load_honeypot_hits()
        manifest_rows = load_manifest()
        summary       = load_summary()

        if not hits:
            log("No honeypot hits found.")
            return
        if not manifest_rows:
            log("No manifest entries. Waiting for manifest_update.sh.")
            return

        log(f"Loaded {len(hits)} hits, {len(manifest_rows)} manifest entries")

        # ── Build time windows from manifest (rotation-agnostic) ─────────
        time_windows = build_time_windows(manifest_rows)
        log(f"  Built {len(time_windows)} time windows")

        # ── Filter out already-labeled windows BEFORE correlation ────────
        if not args.reprocess:
            time_windows = [
                w for w in time_windows 
                if summary.get(w[2], {}).get("labeling_status") != "labeled"
            ]

        # ── Apply --from-date filter if specified ────────────────────────
        if args.from_date:
            try:
                from_dt = datetime.strptime(args.from_date, "%Y-%m-%d")
                before = len(time_windows)
                time_windows = [w for w in time_windows if w[0] >= from_dt]
                log(f"  --from-date filter: skipped {before - len(time_windows)} windows before {args.from_date}")
            except ValueError:
                log(f"  WARNING: Invalid --from-date format '{args.from_date}'. Expected YYYY-MM-DD. Ignoring filter.")

        if not time_windows:
            log("No new windows to process.")
            return

        # ── Match honeypot hits to their file windows ────────────────────
        window_attackers = match_hits_to_windows(hits, time_windows)

        if not window_attackers:
            log("No new windows to process.")
            return

        log(f"Windows to process: {len(window_attackers)}")

        # ── Detect nfdump format support ─────────────────────────────────
        test_file = None
        for fname in sorted(window_attackers.keys()):
            test_file = find_nfcapd_file(fname)
            if test_file:
                break

        fmt_mode = "basic"
        if test_file:
            fmt_mode = _detect_format(test_file)
        log(f"nfdump output: {fmt_mode} "
            f"({'30+ features' if fmt_mode == 'extended' else '10+computed'})")

        # ── Process windows with time budget ─────────────────────────────
        total_t1 = total_t2 = total_t3 = total_atk = total_unv = 0
        all_types = set()
        done = 0

        # ── Load Zeek Features for Vectorized Pandas Merge ───────────────
        log("Loading Zeek features into Pandas for 6-tuple merge...")
        zeek_df = pext.load_zeek_data_pandas(ZEEK_LOG_PATH, ZEEK_DNS_PATH)
        log(f"Loaded {len(zeek_df) if zeek_df is not None and not zeek_df.empty else 0} Zeek 6-tuple buckets.")

        for file_name, attacker_data in sorted(window_attackers.items()):
            elapsed = time.time() - start_time
            if elapsed > TIME_BUDGET_S:
                remaining = len(window_attackers) - done
                log(f"Time budget ({TIME_BUDGET_S}s) reached. "
                    f"{remaining} windows deferred to next run.")
                break

            filepath = find_nfcapd_file(file_name)
            t1, t2, t3, atk, types, unv = process_window(
                file_name, filepath, dict(attacker_data),
                manifest_rows, summary, fmt_mode,
                use_abuseipdb=not args.no_abuseipdb,
                zeek_df=zeek_df
            )
            total_t1 += t1; total_t2 += t2; total_t3 += t3
            total_atk += atk; total_unv += unv
            all_types.update(types)
            done += 1

        # ── Save manifest atomically ─────────────────────────────────────
        if done > 0 and manifest_rows:
            fieldnames = list(manifest_rows[0].keys())
            tmp = Path(str(MANIFEST_FILE) + ".tmp")
            with open(tmp, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=fieldnames,
                                   extrasaction="ignore")
                w.writeheader()
                w.writerows(manifest_rows)
            tmp.replace(MANIFEST_FILE)

        elapsed = time.time() - start_time
        log(f"Done: {done} windows in {elapsed:.1f}s — "
            f"{total_t1} verified, {total_t2} associated, "
            f"{total_t3} normal ({total_unv} unverified), {total_atk} attackers")

    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


if __name__ == "__main__":
    main()
