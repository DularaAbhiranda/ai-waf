"""
evaluator.py
------------
Generates evaluation plots and SHAP feature importance.
Called from trainer.py or the training notebook.

Outputs saved to models/:
  - confusion_matrix.png
  - roc_curve.png
  - feature_importance.png
  - shap_summary.png  (if shap available)
"""

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import confusion_matrix, roc_curve, roc_auc_score

sns.set_theme(style="darkgrid", palette="muted")

OUT_DIR = Path(__file__).resolve().parent.parent / "models"


def plot_confusion_matrix(y_true, y_pred, save=True):
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=["Normal", "Attack"],
        yticklabels=["Normal", "Attack"],
        ax=ax,
    )
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("Confusion Matrix")
    plt.tight_layout()
    if save:
        path = OUT_DIR / "confusion_matrix.png"
        fig.savefig(path, dpi=150, bbox_inches="tight")
        print(f"Saved -> {path}")
    plt.close(fig)

    tn, fp, fn, tp = cm.ravel()
    print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"  False Positive Rate (normal blocked): {fp/(fp+tn)*100:.2f}%")
    print(f"  False Negative Rate (attack missed) : {fn/(fn+tp)*100:.2f}%")
    return cm


def plot_roc_curve(y_true, y_prob, save=True):
    fpr, tpr, thresholds = roc_curve(y_true, y_prob)
    auc = roc_auc_score(y_true, y_prob)

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot(fpr, tpr, color="tomato", lw=2, label=f"ROC (AUC = {auc:.4f})")
    ax.plot([0, 1], [0, 1], "k--", lw=1, label="Random baseline")
    ax.fill_between(fpr, tpr, alpha=0.1, color="tomato")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve")
    ax.legend(loc="lower right")
    plt.tight_layout()
    if save:
        path = OUT_DIR / "roc_curve.png"
        fig.savefig(path, dpi=150, bbox_inches="tight")
        print(f"Saved -> {path}")
    plt.close(fig)
    return auc


def plot_feature_importance(model, feature_names, top_n=15, save=True):
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:top_n]

    fig, ax = plt.subplots(figsize=(9, 6))
    colors = ["tomato" if importances[i] > np.median(importances) else "steelblue"
              for i in indices]
    ax.barh(
        [feature_names[i] for i in reversed(indices)],
        [importances[i] for i in reversed(indices)],
        color=list(reversed(colors)),
        edgecolor="black",
    )
    ax.set_xlabel("Feature Importance (Gini)")
    ax.set_title(f"Top {top_n} Feature Importances")
    plt.tight_layout()
    if save:
        path = OUT_DIR / "feature_importance.png"
        fig.savefig(path, dpi=150, bbox_inches="tight")
        print(f"Saved -> {path}")
    plt.close(fig)

    print("\nFeature importances:")
    for i in indices:
        print(f"  {feature_names[i]:<25} {importances[i]:.4f}")


def plot_threshold_analysis(y_true, y_prob, save=True):
    """Sweep thresholds 0.1-0.9 and show precision/recall/F1 trade-off."""
    from sklearn.metrics import precision_score, recall_score, f1_score

    thresholds = np.arange(0.1, 0.95, 0.05)
    precisions, recalls, f1s = [], [], []

    for t in thresholds:
        y_pred = (y_prob >= t).astype(int)
        precisions.append(precision_score(y_true, y_pred, zero_division=0))
        recalls.append(recall_score(y_true, y_pred, zero_division=0))
        f1s.append(f1_score(y_true, y_pred, zero_division=0))

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot(thresholds, precisions, "o-", label="Precision", color="steelblue")
    ax.plot(thresholds, recalls,    "s-", label="Recall",    color="tomato")
    ax.plot(thresholds, f1s,        "^-", label="F1",        color="green")
    ax.axvline(0.5, color="gray", linestyle="--", label="Default threshold (0.5)")
    ax.set_xlabel("Decision Threshold")
    ax.set_ylabel("Score")
    ax.set_title("Precision / Recall / F1 vs Decision Threshold")
    ax.legend()
    ax.set_ylim(0, 1.05)
    plt.tight_layout()
    if save:
        path = OUT_DIR / "threshold_analysis.png"
        fig.savefig(path, dpi=150, bbox_inches="tight")
        print(f"Saved -> {path}")
    plt.close(fig)

    best_idx = int(np.argmax(f1s))
    print(f"\nBest threshold by F1: {thresholds[best_idx]:.2f}  "
          f"(F1={f1s[best_idx]:.4f}  "
          f"P={precisions[best_idx]:.4f}  "
          f"R={recalls[best_idx]:.4f})")
    return thresholds[best_idx]


def plot_shap(model, X_test_scaled, feature_names, max_display=15, save=True):
    try:
        import shap
    except ImportError:
        print("shap not installed, skipping SHAP plot.")
        return

    print("\nCalculating SHAP values (this may take ~30s) ...")
    explainer   = shap.TreeExplainer(model)
    # Use a sample to keep it fast
    sample_size = min(500, len(X_test_scaled))
    X_sample    = X_test_scaled[:sample_size]
    shap_values = explainer.shap_values(X_sample)

    # shap_values is list [class0, class1] for RF
    sv = shap_values[1] if isinstance(shap_values, list) else shap_values

    fig, ax = plt.subplots(figsize=(10, 7))
    shap.summary_plot(
        sv, X_sample,
        feature_names=feature_names,
        max_display=max_display,
        show=False,
        plot_type="bar",
    )
    plt.tight_layout()
    if save:
        path = OUT_DIR / "shap_summary.png"
        fig.savefig(path, dpi=150, bbox_inches="tight")
        print(f"Saved -> {path}")
    plt.close(fig)


def run_all(model, scaler, X_test, y_test, y_prob):
    """Run all evaluation plots."""
    feature_names = list(X_test.columns)
    X_test_scaled = scaler.transform(X_test)

    print("\n=== Confusion Matrix ===")
    y_pred = (y_prob >= 0.5).astype(int)
    plot_confusion_matrix(y_test, y_pred)

    print("\n=== ROC Curve ===")
    plot_roc_curve(y_test, y_prob)

    print("\n=== Feature Importance ===")
    plot_feature_importance(model, feature_names)

    print("\n=== Threshold Analysis ===")
    best_t = plot_threshold_analysis(y_test, y_prob)

    print("\n=== SHAP Summary ===")
    plot_shap(model, X_test_scaled, feature_names)

    return best_t
