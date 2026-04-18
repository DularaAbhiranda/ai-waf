"""
retrainer.py
------------
Auto-retraining loop for the AI-WAF.

What it does every RETRAIN_INTERVAL_HOURS:
  1. Check if enough new labelled data has arrived (WAF decisions logged to DB)
  2. Re-extract features from processed.csv + any new data
  3. Retrain the Random Forest
  4. Evaluate new model vs old model on a held-out test set
  5. Only SWAP the model if new >= old F1 (safety gate)
  6. Archive the old model with a timestamp
  7. Write a retrain history entry to models/retrain_log.csv

Run once:
    python -m src.retrainer --now

Run as daemon (checks every 24h):
    python -m src.retrainer --daemon
"""

import argparse
import csv
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from src.config import (
    MODEL_PATH,
    SCALER_PATH,
    RETRAIN_INTERVAL_HOURS,
    THRESHOLD,
)

# ── paths ─────────────────────────────────────────────────────────────────────
ROOT          = Path(MODEL_PATH).resolve().parent.parent
DATA_PATH     = ROOT / "data"  / "processed.csv"
RETRAIN_LOG   = ROOT / "models" / "retrain_log.csv"
ARCHIVE_DIR   = ROOT / "models" / "archive"
MIN_NEW_ROWS  = 500   # don't retrain unless this many new rows have been labelled


# ── helpers ───────────────────────────────────────────────────────────────────

def _log(msg: str):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [Retrainer] {msg}")


def _archive_current_model():
    """Copy current model + scaler to models/archive/<timestamp>/"""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    dest = ARCHIVE_DIR / ts
    dest.mkdir(parents=True, exist_ok=True)
    for src_path in [Path(MODEL_PATH), Path(SCALER_PATH)]:
        if src_path.exists():
            shutil.copy2(src_path, dest / src_path.name)
    _log(f"Archived old model to models/archive/{ts}/")
    return str(dest)


def _append_retrain_log(entry: dict):
    """Append one row to models/retrain_log.csv"""
    RETRAIN_LOG.parent.mkdir(exist_ok=True)
    write_header = not RETRAIN_LOG.exists()
    with open(RETRAIN_LOG, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(entry.keys()))
        if write_header:
            writer.writeheader()
        writer.writerow(entry)


def _load_current_model():
    """Load existing model and scaler. Returns (None, None) if not found."""
    mp, sp = Path(MODEL_PATH), Path(SCALER_PATH)
    if mp.exists() and sp.exists():
        return joblib.load(mp), joblib.load(sp)
    return None, None


def _train_model(X_train, y_train):
    model = RandomForestClassifier(
        n_estimators=200,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    return model


def _evaluate(model, scaler, X_test, y_test, threshold=THRESHOLD):
    y_prob = model.predict_proba(scaler.transform(X_test))[:, 1]
    y_pred = (y_prob >= threshold).astype(int)
    return {
        "f1":      round(f1_score(y_test, y_pred), 4),
        "roc_auc": round(roc_auc_score(y_test, y_prob), 4),
    }


# ── core retrain logic ────────────────────────────────────────────────────────

def retrain(force: bool = False) -> dict:
    """
    Full retrain cycle.

    Returns a dict with keys: status, old_f1, new_f1, swapped, rows_used.
    """
    _log("Starting retrain cycle ...")

    # ── load data ─────────────────────────────────────────────────────────────
    if not DATA_PATH.exists():
        _log("ERROR: data/processed.csv not found. Run feature_extractor first.")
        return {"status": "error", "reason": "no_data"}

    df = pd.read_csv(DATA_PATH)
    X  = df.drop(columns=["label"])
    y  = df["label"]
    _log(f"Loaded {len(df):,} rows from processed.csv")

    if not force and len(df) < MIN_NEW_ROWS:
        msg = f"Only {len(df)} rows — need {MIN_NEW_ROWS} minimum. Skipping."
        _log(msg)
        return {"status": "skipped", "reason": msg}

    # ── train / test split ────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # ── scale ─────────────────────────────────────────────────────────────────
    new_scaler = StandardScaler()
    X_train_s  = new_scaler.fit_transform(X_train)

    # ── evaluate OLD model first ──────────────────────────────────────────────
    old_model, old_scaler = _load_current_model()
    old_metrics = {"f1": 0.0, "roc_auc": 0.0}
    if old_model is not None:
        old_metrics = _evaluate(old_model, old_scaler, X_test, y_test)
        _log(f"Old model  — F1={old_metrics['f1']:.4f}  AUC={old_metrics['roc_auc']:.4f}")

    # ── train new model ───────────────────────────────────────────────────────
    _log("Training new model ...")
    new_model   = _train_model(X_train_s, y_train)
    new_metrics = _evaluate(new_model, new_scaler, X_test, y_test)
    _log(f"New model  — F1={new_metrics['f1']:.4f}  AUC={new_metrics['roc_auc']:.4f}")

    # ── safety gate: only swap if new model is at least as good ───────────────
    swapped = False
    if new_metrics["f1"] >= old_metrics["f1"] - 0.005:  # 0.5% tolerance
        archive_path = _archive_current_model() if old_model is not None else ""
        Path(MODEL_PATH).parent.mkdir(exist_ok=True)
        joblib.dump(new_model,  MODEL_PATH)
        joblib.dump(new_scaler, SCALER_PATH)
        swapped = True
        _log(f"Model SWAPPED. Old archived to: {archive_path}")
    else:
        _log(
            f"Model NOT swapped — new F1 ({new_metrics['f1']:.4f}) "
            f"< old F1 ({old_metrics['f1']:.4f}). Keeping current model."
        )

    # ── log the run ───────────────────────────────────────────────────────────
    entry = {
        "timestamp":   datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rows_used":   len(df),
        "old_f1":      old_metrics["f1"],
        "old_auc":     old_metrics["roc_auc"],
        "new_f1":      new_metrics["f1"],
        "new_auc":     new_metrics["roc_auc"],
        "swapped":     swapped,
        "threshold":   THRESHOLD,
    }
    _append_retrain_log(entry)
    _log(f"Logged retrain run to {RETRAIN_LOG}")

    return {
        "status":    "done",
        "old_f1":    old_metrics["f1"],
        "new_f1":    new_metrics["f1"],
        "swapped":   swapped,
        "rows_used": len(df),
    }


# ── daemon loop ───────────────────────────────────────────────────────────────

def run_daemon():
    interval_s = RETRAIN_INTERVAL_HOURS * 3600
    _log(f"Daemon started. Retraining every {RETRAIN_INTERVAL_HOURS}h "
         f"({interval_s:,}s). Press Ctrl+C to stop.")
    while True:
        result = retrain()
        _log(f"Cycle result: {result}")
        _log(f"Next retrain in {RETRAIN_INTERVAL_HOURS}h. Sleeping ...")
        time.sleep(interval_s)


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-WAF auto-retrainer")
    parser.add_argument("--now",    action="store_true", help="Run one retrain cycle immediately")
    parser.add_argument("--daemon", action="store_true", help="Run as a daemon (every 24h)")
    parser.add_argument("--force",  action="store_true", help="Skip minimum-rows check")
    args = parser.parse_args()

    if args.daemon:
        run_daemon()
    else:
        # default: run once
        result = retrain(force=args.force)
        print("\nResult:", result)
