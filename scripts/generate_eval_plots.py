# ==============================================================================
# scripts/generate_eval_plots.py — NetGuard IDS Publication Plot Generator
# High-Resolution (300 DPI) Confusion Matrix Heatmap & Multi-Class ROC Curves
# ==============================================================================

import sys
from pathlib import Path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))
sys.path.insert(0, str(ROOT_DIR))

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, roc_curve, auc
from sklearn.preprocessing import label_binarize

from config import MODEL_PATH, SCALER_PATH, LABEL_NAMES, NUM_CLASSES
from scripts.evaluate_baselines import load_benchmark_sample
import joblib

FIGURES_DIR = ROOT_DIR / "static" / "figures"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)


def plot_confusion_matrix(y_true, y_pred, target_names, out_path: Path):
    """Generate high-resolution normalized confusion matrix heatmap."""
    cm = confusion_matrix(y_true, y_pred, normalize='true')
    
    fig, ax = plt.subplots(figsize=(8, 6.5), dpi=300)
    cax = ax.matshow(cm, cmap=plt.cm.Blues, alpha=0.85)

    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            val = cm[i, j]
            text_color = "white" if val > 0.5 else "black"
            ax.text(x=j, y=i, s=f"{val:.2f}", va='center', ha='center',
                    fontsize=11, fontweight='bold', color=text_color)

    fig.colorbar(cax, fraction=0.046, pad=0.04)
    ax.set_xticks(range(len(target_names)))
    ax.set_yticks(range(len(target_names)))
    ax.set_xticklabels([n.replace("_", "\n") for n in target_names], fontsize=9)
    ax.set_yticklabels(target_names, fontsize=9)
    
    ax.set_xlabel("Predicted Class Label", fontsize=11, fontweight='bold', labelpad=10)
    ax.set_ylabel("Ground Truth Class Label", fontsize=11, fontweight='bold', labelpad=10)
    ax.set_title("NetGuard IDS — Normalized Confusion Matrix (Test Set)", fontsize=12, pad=20, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[plots] Saved confusion matrix -> {out_path}")


def plot_multiclass_roc(y_true, y_prob, target_names, out_path: Path):
    """Generate multi-class One-vs-Rest ROC curves with AUC values."""
    y_bin = label_binarize(y_true, classes=range(len(target_names)))
    
    plt.figure(figsize=(8.5, 6.5), dpi=300)
    colors = ['#2563eb', '#16a34a', '#ea580c', '#9333ea', '#dc2626']
    
    for i, (name, color) in enumerate(zip(target_names, colors)):
        fpr, tpr, _ = roc_curve(y_bin[:, i], y_prob[:, i])
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, color=color, lw=2,
                 label=f"{name} (AUC = {roc_auc:.3f})")

    plt.plot([0, 1], [0, 1], 'k--', lw=1.2, alpha=0.6, label='Random Chance (AUC = 0.500)')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel("False Positive Rate (1 - Specificity)", fontsize=11, fontweight='bold')
    plt.ylabel("True Positive Rate (Sensitivity / Recall)", fontsize=11, fontweight='bold')
    plt.title("NetGuard Multi-Class Receiver Operating Characteristic (ROC)", fontsize=12, pad=15, fontweight='bold')
    plt.legend(loc="lower right", fontsize=9, frameon=True, framealpha=0.9)
    plt.grid(True, linestyle=":", alpha=0.6)
    
    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[plots] Saved multi-class ROC curve -> {out_path}")


def main():
    print("[plots] Loading trained XGBoost model and test sample...")
    model = joblib.load(MODEL_PATH)
    _, X_test, _, y_test = load_benchmark_sample(max_rows=100000)

    print("[plots] Computing inference predictions...")
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)

    class_names = [LABEL_NAMES[i] for i in range(NUM_CLASSES)]

    cm_path = FIGURES_DIR / "confusion_matrix_cascade.png"
    plot_confusion_matrix(y_test, y_pred, class_names, cm_path)

    roc_path = FIGURES_DIR / "roc_curves_multiclass.png"
    plot_multiclass_roc(y_test, y_prob, class_names, roc_path)

    print("[plots] Plot generation complete! Saved to static/figures/")


if __name__ == "__main__":
    main()
