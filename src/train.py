# =============================================================
# train.py — CIC-IDS2018 training entry point
# Run: python src/train.py
# =============================================================

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import joblib
import numpy as np
from xgboost import XGBClassifier
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, f1_score

from config import (
    MODEL_PATH, IFOREST_MODEL_PATH, MODELS_DIR, XGB_PARAMS, IFOREST_PARAMS,
    LABEL_NAMES, NUM_CLASSES
)
from preprocess import load_all_data, preprocess_train


def train() -> float:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # ── Load ──
    print("[train] Loading all CIC-IDS2018 files...")
    df = load_all_data()

    # ── Preprocess ──
    print("[train] Preprocessing...")
    X_train, X_test, y_train, y_test = preprocess_train(df)

    print(f"[train] Train: {X_train.shape}")
    print(f"[train] Test:  {X_test.shape}")

    # ── XGBoost Model ──
    model = XGBClassifier(
        **XGB_PARAMS,
        num_class=NUM_CLASSES,
        tree_method="hist",   # fast on large data
        device="cpu",
    )

    # ── Fit XGBoost ──
    print("\n[train] Fitting XGBoost Classifier...")
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=50,
    )

    # ── Fit Isolation Forest (Zero-Day Anomaly Detector) ──
    print("\n[train] Fitting Isolation Forest for Zero-Day Anomaly Detection...")
    iforest = IsolationForest(**IFOREST_PARAMS)
    # Fit baseline on normal/benign traffic (class 0) for zero-day isolation
    X_benign = X_train[y_train == 0] if np.sum(y_train == 0) > 0 else X_train
    print(f"[train] Isolation Forest training on {X_benign.shape[0]:,} benign traffic samples...")
    iforest.fit(X_benign)

    # ── Evaluate ──
    y_pred = model.predict(X_test)
    macro_f1 = f1_score(y_test, y_pred, average="macro")
    target_names = [LABEL_NAMES[i] for i in range(NUM_CLASSES)]

    print("\n── XGBoost Classification Report ──")
    print(classification_report(
        y_test, y_pred, target_names=target_names
    ))
    print(f"Macro F1 Score: {macro_f1:.4f}")

    iforest_preds = iforest.predict(X_test)
    n_anomalies = np.sum(iforest_preds == -1)
    print(f"[train] Isolation Forest flagged {n_anomalies:,} / {len(X_test):,} test samples as anomalies.")

    # ── Save Models ──
    joblib.dump(model, MODEL_PATH)
    print(f"\n[train] XGBoost Model saved → {MODEL_PATH}")

    joblib.dump(iforest, IFOREST_MODEL_PATH)
    print(f"[train] Isolation Forest Model saved → {IFOREST_MODEL_PATH}")

    return macro_f1


if __name__ == "__main__":
    train()
