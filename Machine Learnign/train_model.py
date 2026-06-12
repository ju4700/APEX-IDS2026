import time
import joblib
from pathlib import Path
from sklearn.model_selection import train_test_split
# Use XGBoost for GPU‑accelerated training when a compatible GPU is present.
# The wheel installed (`xgboost‑3.2.0‑cp313‑cp313‑win_amd64.whl`) includes GPU support
# if the system has a CUDA‑enabled GPU (e.g., RTX 5060). We fall back to the CPU
# implementation if GPU initialization fails.
try:
    from xgboost import XGBClassifier
    _XGBOOST_AVAILABLE = True
except Exception:
    _XGBOOST_AVAILABLE = False

from data_loader import load_and_combine_data
from feature_engineering import engineer_features
from evaluate import evaluate_model

# Ensure output directory exists for saving the model
BASE_DIR = Path(__file__).parent
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

def main():
    print("="*60)
    print("APEX-IDS2026: Random Forest Model Training Pipeline")
    print("="*60)

    # 1. Load Data
    try:
        raw_df = load_and_combine_data()
    except Exception as e:
        print(f"\n[!] Initialization Failed: {e}")
        return

    # 2. Feature Engineering
    X, y = engineer_features(raw_df)

    # 3. Train-Test Split (80% Train, 20% Test)
    print("\nSplitting data into 80% Training and 20% Testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)
    print(f"Training shapes   - X: {X_train.shape}, y: {y_train.shape}")
    print(f"Testing shapes    - X: {X_test.shape}, y: {y_test.shape}")

    # 4. Initialize Model – prefer XGBoost with GPU if possible
    if _XGBOOST_AVAILABLE:
        try:
            print("Initializing XGBoost classifier with GPU support (tree_method='gpu_hist')...")
            xgb_model = XGBClassifier(
                n_estimators=300,
                max_depth=8,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                objective='binary:logistic',
                eval_metric='logloss',
                tree_method='gpu_hist',  # GPU accelerated histogram algorithm
                random_state=42,
                n_jobs=-1,
                verbosity=1,
            )
            model = xgb_model
        except Exception as e:
            print(f"[!] GPU XGBoost initialization failed ({e}); falling back to CPU RandomForest.")
            from sklearn.ensemble import RandomForestClassifier
            model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1, verbose=1)
    else:
        print("XGBoost not available – using CPU RandomForest as fallback.")
        from sklearn.ensemble import RandomForestClassifier
        model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1, verbose=1)

    # 5. Train Model
    print("\nTraining Random Forest model (this may take a minute depending on data size)...")
    start_time = time.time()
    model.fit(X_train, y_train)
    duration = time.time() - start_time
    print(f"Training completed in {duration:.2f} seconds.")

    # 6. Predict on Test Set
    print("Predicting on the unseen Test set...")
    y_pred = model.predict(X_test)

    # 7. Evaluate
    evaluate_model(y_test, y_pred, X.columns, model)

    # 8. Save Model
    # Preserve the original filename for compatibility, but note the model may now be XGBoost.
    model_path = OUTPUT_DIR / "apex_ids_model.pkl"
    print(f"\nSaving trained model to disk: {model_path}")
    joblib.dump(model, model_path)
    print("Model saved successfully. Ready for real-time deployment!")

if __name__ == "__main__":
    main()
