import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = BASE_DIR / "data"

# Ensure data directory exists so the user knows where to drop files
DATA_DIR.mkdir(exist_ok=True)

# Feature Definitions
# Features we explicitly want to keep for the Machine Learning model
NUMERICAL_FEATURES = [
    "duration_s",
    "packets",
    "bytes",
    "bytes_per_sec",
    "packets_per_sec",
    "bytes_per_packet",
    "flag_syn",
    "flag_ack",
    "flag_fin",
    "flag_rst",
    "flag_psh",
    "flag_urg"
]

CATEGORICAL_FEATURES = [
    "protocol",
    "src_port_category",
    "dst_port_category"
]

# Features that MUST be dropped to prevent data leakage (memorization)
# We do not want the model memorizing an attacker's IP or our internal flags
DROP_FEATURES = [
    "flow_start", 
    "src_ip", 
    "src_port", 
    "dst_ip", 
    "dst_port", 
    "tos", 
    "flow_duration_class", 
    "attack_type", 
    "attack_category", 
    "mitre_technique", 
    "mitre_tactic", 
    "confidence", 
    "evidence_source", 
    "threat_intel_score", 
    "behavioral_flags", 
    "flow_file",
    "tcp_flags" # We use the decomposed flag_syn, flag_ack instead
]

# The target variable we want to predict
TARGET_COLUMN = "label"

# Label mapping for Binary Classification
# 1 = Attack, 0 = Normal
BINARY_LABEL_MAP = {
    "Attack_Verified": 1,
    "Attack_Associated": 1,
    "Benign_Verified": 0,
    "Benign_Assumed": 0,
    "Unverified": 0  # Depending on strictness, we assume unverified is benign for binary detection
}
