# ==============================================================================
# src/xai.py — NetGuard IDS Production XAI Engine
# Enterprise TreeSHAP Feature Attribution Engine
# ==============================================================================

import sys
from pathlib import Path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))

import joblib
import numpy as np
import pandas as pd
import shap

from config import MODEL_PATH, SCALER_PATH, FEATURE_COLS, LABEL_NAMES
from preprocess import preprocess_inference

FIGURES_DIR = ROOT_DIR / "reports" / "figures"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)


class TreeSHAPExplainer:
    """
    Genuine Shapley Additive Explanations (TreeSHAP) for NetGuard XGBoost Classifier.
    Computes exact mathematical local and global feature attribution.
    """
    def __init__(self):
        if not MODEL_PATH.exists() or not SCALER_PATH.exists():
            raise FileNotFoundError("Trained model or scaler not found in models/.")
        
        self.model = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH)
        self.feature_names = FEATURE_COLS
        
        # Initialize TreeExplainer on XGBoost
        print("[xai] Initializing shap.TreeExplainer on XGBClassifier...")
        self.explainer = shap.TreeExplainer(self.model)

    def explain_instance(self, traffic_dict: dict, top_k: int = 5) -> dict:
        """
        Compute true SHAP feature attribution for a single real-time network flow.
        """
        X_scaled = preprocess_inference(traffic_dict)
        shap_values = self.explainer.shap_values(X_scaled)
        
        # XGBoost multi-class output shape check
        predicted_class_idx = int(self.model.predict(X_scaled)[0])
        predicted_class_name = LABEL_NAMES[predicted_class_idx]
        
        # In multi-class, shap_values can be a list of arrays (one per class) or (samples, features, classes)
        if isinstance(shap_values, list):
            class_shap = shap_values[predicted_class_idx][0]
        elif len(shap_values.shape) == 3:
            class_shap = shap_values[0, :, predicted_class_idx]
        else:
            class_shap = shap_values[0]

        # Rank features by magnitude of Shapley attribution
        abs_shap = np.abs(class_shap)
        top_indices = np.argsort(abs_shap)[::-1][:top_k]

        contributions = []
        for idx in top_indices:
            feat_name = self.feature_names[idx] if idx < len(self.feature_names) else f"Feature_{idx}"
            feat_val = traffic_dict.get(feat_name, 0)
            shap_val = float(class_shap[idx])
            contributions.append({
                "feature": feat_name,
                "value": feat_val,
                "shap_value": round(shap_val, 5),
                "impact": "positive" if shap_val > 0 else "negative",
                "importance_weight": round(float(abs_shap[idx]), 5)
            })

        return {
            "predicted_class": predicted_class_name,
            "predicted_idx": predicted_class_idx,
            "top_shap_contributions": contributions,
            "base_value": float(self.explainer.expected_value[predicted_class_idx]) if isinstance(self.explainer.expected_value, (list, np.ndarray)) else float(self.explainer.expected_value)
        }

    def generate_publication_figures(self, sample_df: pd.DataFrame, max_samples: int = 500):
        """
        Generate IEEE publication-standard figures:
        1. Global Feature Importance Bar Plot
        2. Beeswarm Summary Plot
        """
        print(f"[xai] Generating publication figures using {min(len(sample_df), max_samples)} samples...")
        available_cols = [c for c in self.feature_names if c in sample_df.columns]
        X = sample_df[available_cols].copy()
        
        # Impute missing if needed
        for col in self.feature_names:
            if col not in X.columns:
                X[col] = 0.0
        X = X[self.feature_names]
        
        X_sub = X.iloc[:max_samples]
        X_scaled = self.scaler.transform(X_sub)
        
        shap_values = self.explainer.shap_values(X_scaled)
        
        feature_names_arr = np.array(self.feature_names)
        
        # 1. Global Bar Plot
        plt.figure(figsize=(10, 6), dpi=300)
        shap.summary_plot(shap_values, X_sub, feature_names=feature_names_arr, plot_type="bar", show=False, class_names=LABEL_NAMES)
        plt.title("TreeSHAP Global Feature Importance Across Attack Classes", fontsize=12, pad=15)
        plt.tight_layout()
        bar_path = FIGURES_DIR / "shap_global_bar_importance.png"
        plt.savefig(bar_path, bbox_inches="tight")
        plt.close()
        print(f"[xai] Saved global bar plot -> {bar_path}")

        # 2. Summary Beeswarm Plot for Class 1 (or primary attack)
        plt.figure(figsize=(10, 7), dpi=300)
        target_class_idx = 1 # e.g. DoS / primary attack
        target_shap = shap_values[target_class_idx] if isinstance(shap_values, list) else shap_values[:, :, target_class_idx]
        shap.summary_plot(target_shap, X_sub, feature_names=feature_names_arr, show=False)
        plt.title(f"TreeSHAP Beeswarm Distribution for Attack Vector ({LABEL_NAMES[target_class_idx]})", fontsize=12, pad=15)
        plt.tight_layout()
        beeswarm_path = FIGURES_DIR / "shap_summary_beeswarm.png"
        plt.savefig(beeswarm_path, bbox_inches="tight")
        plt.close()
        print(f"[xai] Saved beeswarm plot -> {beeswarm_path}")


if __name__ == "__main__":
    explainer = TreeSHAPExplainer()
    
    # Test on a synthetic DoS sample flow
    test_flow = {
        "Dst Port": 80,
        "Protocol": 6,
        "Flow Duration": 15000000,
        "Tot Fwd Pkts": 2500,
        "Tot Bwd Pkts": 10,
        "TotLen Fwd Pkts": 1250000,
        "TotLen Bwd Pkts": 500,
        "Flow Byts/s": 850000,
        "Flow Pkts/s": 6500,
        "SYN Flag Cnt": 15,
        "Fwd Pkt Len Max": 1460,
    }
    
    result = explainer.explain_instance(test_flow)
    print("\n--- TreeSHAP Single Instance Explanation ---")
    print(f"Predicted Class: {result['predicted_class']}")
    print("Top Feature Attributions (Shapley Values):")
    for item in result["top_shap_contributions"]:
        print(f"  • {item['feature']}: SHAP = {item['shap_value']:+.4f} (Input Value: {item['value']})")
