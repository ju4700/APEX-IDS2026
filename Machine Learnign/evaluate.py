from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

# Try to ensure a standard directory for saving plots
BASE_DIR = Path(__file__).parent
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

def evaluate_model(y_true, y_pred, feature_names, model):
    """
    Prints classification report, confusion matrix, and plots Feature Importances.
    """
    print("\n" + "="*50)
    print("MODEL EVALUATION REPORT")
    print("="*50)

    # 1. Classification Report (Accuracy, Precision, Recall, F1)
    print("\n--- Classification Report ---")
    print(classification_report(y_true, y_pred, target_names=["Normal (0)", "Attack (1)"]))

    # 2. Confusion Matrix
    print("\n--- Confusion Matrix ---")
    cm = confusion_matrix(y_true, y_pred)
    print(f"True Negatives (Correctly identified Normal): {cm[0][0]}")
    print(f"False Positives (Normal flagged as Attack):   {cm[0][1]}")
    print(f"False Negatives (Attacks missed):             {cm[1][0]}")
    print(f"True Positives (Correctly identified Attack): {cm[1][1]}")

    # 3. Plot Confusion Matrix
    try:
        plt.figure(figsize=(6,5))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=["Normal", "Attack"], yticklabels=["Normal", "Attack"])
        plt.title('Confusion Matrix')
        plt.ylabel('Actual Label')
        plt.xlabel('Predicted Label')
        cm_path = OUTPUT_DIR / "confusion_matrix.png"
        plt.savefig(cm_path)
        print(f"\nSaved Confusion Matrix plot to: {cm_path}")
    except Exception as e:
        print(f"Could not plot confusion matrix (is matplotlib installed?): {e}")

    # 4. Feature Importance
    print("\n--- Top 10 Most Important Features ---")
    importances = model.feature_importances_
    
    # Pair feature names with their importance scores
    feat_importances = list(zip(feature_names, importances))
    
    # Sort descending
    feat_importances.sort(key=lambda x: x[1], reverse=True)

    for i, (feat, imp) in enumerate(feat_importances[:10]):
        print(f"{i+1}. {feat}: {imp:.4f}")
