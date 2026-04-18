"""
trainer.py
----------
Loads data/processed.csv, trains a Random Forest classifier,
evaluates it, and saves the model + scaler to models/.

Usage:
    python -m src.trainer
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report,
    confusion_matrix, roc_curve,
)

# ── paths ─────────────────────────────────────────────────────────────────────
ROOT       = Path(__file__).resolve().parent.parent
DATA_PATH  = ROOT / "data" / "processed.csv"
MODEL_PATH = ROOT / "models" / "model_final.pkl"
SCALER_PATH= ROOT / "models" / "scaler.pkl"
RESULTS_PATH = ROOT / "models" / "eval_results.csv"


def load_data():
    df = pd.read_csv(DATA_PATH)
    X = df.drop(columns=["label"])
    y = df["label"]
    print(f"Loaded {len(df):,} samples | {X.shape[1]} features")
    print(f"  Normal : {(y==0).sum():,}  |  Attack: {(y==1).sum():,}")
    return X, y


def build_model():
    return RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",   # handles the 60/40 imbalance
        random_state=42,
        n_jobs=-1,
    )


def train(threshold: float = 0.5):
    X, y = load_data()

    # ── train / test split (80/20, stratified) ────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(X_train):,}  |  Test: {len(X_test):,}")

    # ── scale ─────────────────────────────────────────────────────────────────
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # ── train ─────────────────────────────────────────────────────────────────
    print("\nTraining Random Forest (200 trees) ...")
    model = build_model()
    model.fit(X_train_s, y_train)
    print("Training complete.")

    # ── 5-fold cross-val on training set ──────────────────────────────────────
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X_train_s, y_train, cv=cv, scoring="f1")
    print(f"\n5-Fold CV F1: {cv_scores.mean():.4f} +/- {cv_scores.std():.4f}")

    # ── evaluate on test set ──────────────────────────────────────────────────
    y_prob  = model.predict_proba(X_test_s)[:, 1]
    y_pred  = (y_prob >= threshold).astype(int)

    metrics = {
        "threshold": threshold,
        "accuracy":  accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall":    recall_score(y_test, y_pred),
        "f1":        f1_score(y_test, y_pred),
        "roc_auc":   roc_auc_score(y_test, y_prob),
        "cv_f1_mean": cv_scores.mean(),
        "cv_f1_std":  cv_scores.std(),
    }

    print("\n--- Test Set Metrics ---")
    for k, v in metrics.items():
        print(f"  {k:<15}: {v:.4f}" if isinstance(v, float) else f"  {k:<15}: {v}")

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

    # ── save artefacts ────────────────────────────────────────────────────────
    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(model,  MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"\nModel  saved -> {MODEL_PATH}")
    print(f"Scaler saved -> {SCALER_PATH}")

    # save metrics to CSV for dashboard
    pd.DataFrame([metrics]).to_csv(RESULTS_PATH, index=False)
    print(f"Metrics saved -> {RESULTS_PATH}")

    return model, scaler, X_test, y_test, y_prob, metrics


if __name__ == "__main__":
    from src.config import THRESHOLD
    train(threshold=THRESHOLD)
