#!/usr/bin/env python3
"""
parse_honeypot.py — Tails /var/log/honeypot_raw.log, extracts honeypot hits.
Fresh-start safe: creates all directories and files automatically.
"""

import re
import csv
import fcntl
from pathlib import Path
from datetime import datetime
from collections import Counter

# ─── CONFIG ──────────────────────────────────────────────────────────────────

RAW_LOG      = Path("/var/log/honeypot_raw.log")
CSV_FILE     = Path("/data/flows/metadata/honeypot_hits.csv")
OFFSET_FILE  = Path("/data/flows/metadata/honeypot_parse_offset.txt")
PIPELINE_LOG = Path("/data/flows/metadata/pipeline.log")
LOCK_FILE    = Path("/tmp/honeypot_parse.lock")

CSV_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "tcp_flags", "interface_in", "packet_len",
    "attack_type", "raw_log",
]

# MikroTik honeypot log pattern
PATTERN = re.compile(
    r"HONEYPOT:.*?"
    r"in:(\S+)\s+"
    r"out:[^,]+,\s*"
    r".*?"
    r"proto\s+(\w+)"
    r"(?:\s+\(([^)]*)\))?"
    r",\s*"
    r"(\d+\.\d+\.\d+\.\d+):(\d+)"
    r"->"
    r"(\d+\.\d+\.\d+\.\d+):(\d+)"
    r",\s*len\s+(\d+)",
    re.IGNORECASE,
)

ATTACK_TYPES = {
    "21":    "FTP-Brute",     "22":    "SSH-Brute",
    "23":    "Telnet-Brute",  "25":    "SMTP-Probe",
    "53":    "DNS-Probe",     "80":    "HTTP-Probe",
    "110":   "POP3-Probe",    "143":   "IMAP-Probe",
    "443":   "HTTPS-Probe",   "445":   "SMB-Probe",
    "1433":  "MSSQL-Brute",   "1521":  "Oracle-Probe",
    "3306":  "MySQL-Brute",   "3389":  "RDP-Brute",
    "5432":  "PostgreSQL-Probe",
    "5900":  "VNC-Brute",     "6379":  "Redis-Probe",
    "8080":  "HTTP-Alt-Probe","8443":  "HTTPS-Alt-Probe",
    "27017": "MongoDB-Probe", "8333":  "Bitcoin-Probe",
    "9051":  "Tor-Probe",
}

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [parser] {msg}"
    print(line)
    try:
        PIPELINE_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(PIPELINE_LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def get_offset():
    try:
        return int(OFFSET_FILE.read_text().strip())
    except Exception:
        return 0


def save_offset(offset):
    OFFSET_FILE.parent.mkdir(parents=True, exist_ok=True)
    OFFSET_FILE.write_text(str(offset))


def infer_attack_type(port):
    return ATTACK_TYPES.get(str(port), f"Port-{port}-Scan")


def parse_timestamp(line):
    try:
        parts = line[:15]
        year = datetime.now().year
        dt = datetime.strptime(f"{year} {parts}", "%Y %b %d %H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    # Ensure all directories exist (fresh-start safe)
    for d in [CSV_FILE.parent, OFFSET_FILE.parent, PIPELINE_LOG.parent]:
        d.mkdir(parents=True, exist_ok=True)

    if not RAW_LOG.exists():
        log(f"Missing {RAW_LOG}")
        return

    # Prevent concurrent runs
    with open(LOCK_FILE, "w") as lock_f:
        try:
            fcntl.flock(lock_f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log("Parser already running. Exiting.")
            return

        offset = get_offset()
        size = RAW_LOG.stat().st_size

        # Handle log rotation
        if offset > size:
            offset = 0

        rows = []
        with open(RAW_LOG, "r", errors="ignore") as f:
            f.seek(offset)
            for line in f:
                m = PATTERN.search(line)
                if not m:
                    continue

                iface, proto, flags, src_ip, src_port, dst_ip, dst_port, pkt_len = m.groups()

                rows.append({
                    "timestamp":    parse_timestamp(line),
                    "src_ip":       src_ip,
                    "dst_ip":       dst_ip,
                    "src_port":     src_port,
                    "dst_port":     dst_port,
                    "protocol":     proto.upper(),
                    "tcp_flags":    flags or "",
                    "interface_in": iface,
                    "packet_len":   pkt_len,
                    "attack_type":  infer_attack_type(dst_port),
                    "raw_log":      line.strip()[:250],
                })
            save_offset(f.tell())

        if not rows:
            return

        write_header = not CSV_FILE.exists() or CSV_FILE.stat().st_size == 0

        with open(CSV_FILE, "a", newline="") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            if write_header:
                writer.writeheader()
            writer.writerows(rows)
            fcntl.flock(f, fcntl.LOCK_UN)

        log(f"Parsed {len(rows)} honeypot hits")
        attacks   = Counter(r["attack_type"] for r in rows)
        attackers = Counter(r["src_ip"] for r in rows)
        log("Top 3 types: " + ", ".join(f"{k}:{v}" for k, v in attacks.most_common(3)))
        log("Top 3 IPs: "   + ", ".join(f"{k}:{v}" for k, v in attackers.most_common(3)))


if __name__ == "__main__":
    main()
