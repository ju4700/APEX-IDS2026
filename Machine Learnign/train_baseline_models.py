"""
train_baseline_models.py
========================
Trains baseline ML models on the APEX-IDS2026 High-Confidence Subset.
Produces publication-ready results for the dataset paper.

Models trained:
  1. Random Forest (Binary: Attack vs Benign)
  2. XGBoost      (Binary: Attack vs Benign)
  3. Random Forest (Multiclass: attack_type categories)
  4. XGBoost      (Multiclass: attack_type categories)

Features used (all pre-computed, no leakage):
  duration_s, bytes, packets, bytes_per_sec, flag_count,
  is_syn_only, is_encrypted_port, log_bytes, log_packets,
  log_duration, proto_tcp, proto_udp, proto_icmp, iat_cv

Output:
  results/baseline_results.txt   -- human readable report
  results/baseline_results.json  -- machine readable for paper tables
"""

import json
import os
import sys
import time
import warnings

import duckdb
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

warnings.filterwarnings("ignore")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── Config ────────────────────────────────────────────────────────────────────
GOLDEN_SUBSET = "F:/Apex-IDS/apex_ids2026_hc_subset.parquet"
RESULTS_DIR = "results"
RANDOM_STATE = 42
TEST_SIZE = 0.20          # 80/20 train/test split
N_JOBS = -1               # Use all CPU cores
RF_N_ESTIMATORS = 300

# Features: pre-computed numeric columns only — no IP, no timestamp, no label
FEATURES = [
    "duration_s",
    "bytes",
    "packets",
    "bytes_per_sec",
    "flag_count",
    "is_syn_only",
    "is_encrypted_port",
    "log_bytes",
    "log_packets",
    "log_duration",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "iat_cv",
]

# ── Config (sampling) ─────────────────────────────────────────────────────────
# Full High-Confidence Subset has 69M rows but loading all into RAM requires ~8 GB.
# Tree-based models (RF, XGBoost) plateau after ~2-3M rows per class.
# We draw a balanced stratified sample: SAMPLE_PER_CLASS rows per label.
# Paper reports BOTH the full dataset size (69.1M) AND the training sample.
SAMPLE_PER_CLASS = 500_000   # 500k attack + 500k benign = 1M total (representative)

# ── Helpers ───────────────────────────────────────────────────────────────────
def load_data():
    print(f"Loading stratified sample ({SAMPLE_PER_CLASS:,} rows/class) from Parquet...")
    print(f"  Full High-Confidence Subset: 69,107,018 rows total")
    t0 = time.time()
    con = duckdb.connect()
    cols = ", ".join(FEATURES + ["label_binary", "label_multiclass", "attack_type"])

    # Stratified sample: DuckDB USING SAMPLE per class, then UNION ALL
    df = con.execute(f"""
        SELECT {cols} FROM (
            SELECT {cols}
            FROM read_parquet('{GOLDEN_SUBSET}')
            WHERE label_binary = 1
            USING SAMPLE {SAMPLE_PER_CLASS} ROWS
        )
        UNION ALL
        SELECT {cols} FROM (
            SELECT {cols}
            FROM read_parquet('{GOLDEN_SUBSET}')
            WHERE label_binary = 0
            USING SAMPLE {SAMPLE_PER_CLASS} ROWS
        )
    """).df()
    con.close()
    elapsed = time.time() - t0
    print(f"  Sampled {len(df):,} rows in {elapsed:.1f}s")
    return df


def clean_features(df):
    """Replace inf and fill NaN with 0 — the only safe choice for tree models."""
    df[FEATURES] = df[FEATURES].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return df


def print_section(title):
    print(f"\n{'=' * 65}")
    print(f"  {title}")
    print(f"{'=' * 65}")


def train_and_evaluate(name, model, X_train, X_test, y_train, y_test,
                       multiclass=False):
    """Train model and return metrics dict."""
    t0 = time.time()
    model.fit(X_train, y_train)
    train_time = time.time() - t0

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average="macro", zero_division=0)
    f1_weighted = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    auc = None
    if not multiclass:
        y_prob = model.predict_proba(X_test)[:, 1]
        auc = roc_auc_score(y_test, y_prob)

    report = classification_report(y_test, y_pred, zero_division=0)

    print(f"\n  Model        : {name}")
    print(f"  Train time   : {train_time:.1f}s")
    print(f"  Accuracy     : {acc:.4f}")
    print(f"  F1 (macro)   : {f1_macro:.4f}")
    print(f"  F1 (weighted): {f1_weighted:.4f}")
    if auc is not None:
        print(f"  AUC-ROC      : {auc:.4f}")
    print(f"\n{report}")

    return {
        "model": name,
        "accuracy": round(acc, 4),
        "f1_macro": round(f1_macro, 4),
        "f1_weighted": round(f1_weighted, 4),
        "auc_roc": round(auc, 4) if auc else None,
        "train_time_s": round(train_time, 1),
        "classification_report": report,
    }


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    all_results = {}

    print_section("APEX-IDS2026 Baseline ML Training")
    print(f"  High-Confidence Subset : {GOLDEN_SUBSET}")
    print(f"  Test split    : {TEST_SIZE * 100:.0f}%")
    print(f"  Random state  : {RANDOM_STATE}")
    print(f"  Features      : {len(FEATURES)} columns")

    # ── Load ──────────────────────────────────────────────────────────────────
    df = load_data()
    df = clean_features(df)

    print(f"\n  Label distribution:")
    print(df["label_binary"].value_counts().rename({0: "Benign", 1: "Attack"}).to_string())

    # ── Binary Classification ─────────────────────────────────────────────────
    print_section("Task 1: Binary Classification (Attack vs Benign)")

    X = df[FEATURES].values
    y_bin = df["label_binary"].values.astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_bin, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y_bin
    )
    print(f"  Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # Random Forest
    rf_bin = RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS, n_jobs=N_JOBS, random_state=RANDOM_STATE
    )
    all_results["rf_binary"] = train_and_evaluate(
        "Random Forest (Binary)", rf_bin, X_train, X_test, y_train, y_test
    )

    # XGBoost
    try:
        from xgboost import XGBClassifier
        xgb_bin = XGBClassifier(
            n_estimators=300, learning_rate=0.1, max_depth=6,
            n_jobs=N_JOBS, random_state=RANDOM_STATE,
            eval_metric="logloss", verbosity=0
        )
        all_results["xgb_binary"] = train_and_evaluate(
            "XGBoost (Binary)", xgb_bin, X_train, X_test, y_train, y_test
        )
    except ImportError:
        print("  [SKIP] XGBoost not installed. Run: pip install xgboost")

    # ── Multiclass Classification ─────────────────────────────────────────────
    print_section("Task 2: Multiclass Classification (Attack Type)")

    # Drop rows where multiclass label is null (should be Benign_Verified = 0)
    df_mc = df[df["label_multiclass"].notna()].copy()
    y_mc = df_mc["label_multiclass"].values.astype(int)
    X_mc = df_mc[FEATURES].values

    print(f"  Multiclass distribution:")
    mc_counts = pd.Series(y_mc).value_counts().sort_index()
    mc_labels = {0: "Benign", 1: "Probe/Scan", 2: "BruteForce",
                 3: "DoS/DDoS", 4: "Web_Attack", 5: "Other"}
    for k, v in mc_counts.items():
        print(f"    {mc_labels.get(k, k)}: {v:,}")

    X_train_mc, X_test_mc, y_train_mc, y_test_mc = train_test_split(
        X_mc, y_mc, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y_mc
    )
    print(f"\n  Train: {len(X_train_mc):,}  |  Test: {len(X_test_mc):,}")

    rf_mc = RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS, n_jobs=N_JOBS, random_state=RANDOM_STATE
    )
    all_results["rf_multiclass"] = train_and_evaluate(
        "Random Forest (Multiclass)", rf_mc, X_train_mc, X_test_mc,
        y_train_mc, y_test_mc, multiclass=True
    )

    try:
        from xgboost import XGBClassifier
        n_classes = len(np.unique(y_mc))
        xgb_mc = XGBClassifier(
            n_estimators=300, learning_rate=0.1, max_depth=6,
            objective="multi:softprob", num_class=n_classes,
            n_jobs=N_JOBS, random_state=RANDOM_STATE, verbosity=0
        )
        all_results["xgb_multiclass"] = train_and_evaluate(
            "XGBoost (Multiclass)", xgb_mc, X_train_mc, X_test_mc,
            y_train_mc, y_test_mc, multiclass=True
        )
    except ImportError:
        print("  [SKIP] XGBoost not installed.")

    # ── Feature Importance ────────────────────────────────────────────────────
    print_section("Feature Importance (Random Forest Binary)")
    importances = pd.Series(rf_bin.feature_importances_, index=FEATURES)
    importances = importances.sort_values(ascending=False)
    for feat, imp in importances.items():
        bar = "#" * int(imp * 200)
        print(f"  {feat:<25} {imp:.4f}  {bar}")

    # ── Save Results ──────────────────────────────────────────────────────────
    out_json = os.path.join(RESULTS_DIR, "baseline_results.json")
    with open(out_json, "w") as f:
        json.dump(all_results, f, indent=2)

    out_txt = os.path.join(RESULTS_DIR, "baseline_results.txt")
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write("APEX-IDS2026 Baseline Results\n")
        f.write("=" * 65 + "\n\n")
        for key, res in all_results.items():
            f.write(f"Model: {res['model']}\n")
            f.write(f"  Accuracy      : {res['accuracy']}\n")
            f.write(f"  F1 (macro)    : {res['f1_macro']}\n")
            f.write(f"  F1 (weighted) : {res['f1_weighted']}\n")
            if res.get("auc_roc"):
                f.write(f"  AUC-ROC       : {res['auc_roc']}\n")
            f.write(f"  Train time    : {res['train_time_s']}s\n")
            f.write("\n" + res["classification_report"] + "\n")
            f.write("-" * 65 + "\n\n")

    print_section("Summary Table")
    print(f"  {'Model':<30} {'Acc':>7} {'F1-Mac':>8} {'AUC':>8}")
    print(f"  {'-'*30} {'-'*7} {'-'*8} {'-'*8}")
    for key, res in all_results.items():
        auc_str = f"{res['auc_roc']:.4f}" if res.get("auc_roc") else "  N/A "
        print(
            f"  {res['model']:<30} {res['accuracy']:>7.4f} "
            f"{res['f1_macro']:>8.4f} {auc_str:>8}"
        )

    print(f"\n  Results saved to: {out_txt}")
    print(f"  JSON saved to   : {out_json}")
    print_section("Training Complete")


if __name__ == "__main__":
    main()
