import pandas as pd
from typing import Tuple
from config import NUMERICAL_FEATURES, CATEGORICAL_FEATURES, DROP_FEATURES

def engineer_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Cleans the dataframe, drops cheating columns, scales features, and 
    one-hot encodes categorical variables.
    Returns: (X, y)
    """
    print("\nStarting Feature Engineering...")

    # Extract target before dropping columns
    y = df["target"].copy()

    # 1. Drop the columns we know cause data leakage (memorization)
    cols_to_drop = [col for col in DROP_FEATURES if col in df.columns]
    cols_to_drop.append("target")  # CRITICAL: Drop the answer key!
    print(f"Dropping {len(cols_to_drop)} columns to prevent model cheating: {cols_to_drop}")
    X = df.drop(columns=cols_to_drop, errors="ignore")

    # 2. Handle missing numerical data
    # Some flows might have missing bytes_per_sec if duration was 0, fill with 0
    print("Handling missing numerical data...")
    for col in NUMERICAL_FEATURES:
        if col in X.columns:
            # Convert to numeric just in case pandas parsed as string
            X[col] = pd.to_numeric(X[col], errors='coerce')
            # Fill NaN with 0
            X[col] = X[col].fillna(0)

    # 3. One-Hot Encode Categorical Features
    print("One-Hot Encoding categorical features (protocol, port categories)...")
    cat_cols_present = [col for col in CATEGORICAL_FEATURES if col in X.columns]
    X = pd.get_dummies(X, columns=cat_cols_present, drop_first=True)

    # Ensure all remaining columns are strictly numeric (required by Random Forest)
    # Drop any leftover object/string columns that weren't caught
    remaining_obj_cols = X.select_dtypes(include=['object']).columns
    if len(remaining_obj_cols) > 0:
        print(f"Dropping remaining unhandled string columns: {list(remaining_obj_cols)}")
        X = X.drop(columns=remaining_obj_cols)

    print(f"Feature Engineering complete. Final feature count: {X.shape[1]}")
    return X, y
