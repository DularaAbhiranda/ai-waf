"""
drift_detector.py
-----------------
Detects two kinds of drift that signal the model needs retraining:

1. SCORE DRIFT   — the average attack-probability score for recent traffic
                   shifts significantly from the historical baseline.
                   High scores drifting down = attacks being missed.
                   Low scores drifting up = false-positive spike.

2. BLOCK RATE DRIFT — the rolling block rate deviates from the long-run
                      average by more than a threshold.

Both checks use the SQLite event log (src/logger.py).

Usage:
    python -m src.drift_detector          # print current drift status
    from src.drift_detector import check  # returns DriftReport
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

from src.config import LOG_DB_PATH

# ── tuneable parameters ───────────────────────────────────────────────────────
WINDOW_MINUTES      = 30      # "recent" window to compare against baseline
BASELINE_MULTIPLIER = 10      # baseline = last WINDOW*MULTIPLIER minutes
MIN_EVENTS          = 20      # need at least this many events to run a check
SCORE_Z_THRESHOLD   = 2.5     # z-score beyond which we flag score drift
BLOCK_RATE_ABS_DIFF = 0.15    # absolute block-rate change that triggers alert


@dataclass
class DriftReport:
    checked_at:        str
    recent_events:     int
    baseline_events:   int

    # score drift
    recent_avg_score:   float
    baseline_avg_score: float
    score_z:            float
    score_drift:        bool

    # block rate drift
    recent_block_rate:   float
    baseline_block_rate: float
    block_rate_diff:     float
    block_rate_drift:    bool

    # summary
    drift_detected: bool
    alerts:         list[str] = field(default_factory=list)

    def __str__(self):
        lines = [
            f"Drift report @ {self.checked_at}",
            f"  Recent window  : {self.recent_events} events",
            f"  Baseline window: {self.baseline_events} events",
            f"  Score  — recent={self.recent_avg_score:.3f}  "
            f"baseline={self.baseline_avg_score:.3f}  z={self.score_z:.2f}  "
            f"DRIFT={'YES' if self.score_drift else 'no'}",
            f"  Block  — recent={self.recent_block_rate:.1%}  "
            f"baseline={self.baseline_block_rate:.1%}  "
            f"diff={self.block_rate_diff:+.1%}  "
            f"DRIFT={'YES' if self.block_rate_drift else 'no'}",
        ]
        if self.alerts:
            lines.append("  ALERTS:")
            for a in self.alerts:
                lines.append(f"    * {a}")
        return "\n".join(lines)


def _query_events(since: datetime, until: Optional[datetime] = None) -> pd.DataFrame:
    """Pull events from SQLite between since and until."""
    db_path = Path(LOG_DB_PATH)
    if not db_path.exists():
        return pd.DataFrame(columns=["timestamp", "score", "action"])

    conn  = sqlite3.connect(str(db_path))
    since_str = since.isoformat(timespec="seconds")
    if until:
        until_str = until.isoformat(timespec="seconds")
        query = (
            "SELECT timestamp, score, action FROM events "
            "WHERE timestamp >= ? AND timestamp < ?"
        )
        df = pd.read_sql_query(query, conn, params=(since_str, until_str))
    else:
        query = "SELECT timestamp, score, action FROM events WHERE timestamp >= ?"
        df = pd.read_sql_query(query, conn, params=(since_str,))
    conn.close()
    return df


def check(
    window_minutes:    int   = WINDOW_MINUTES,
    baseline_mult:     int   = BASELINE_MULTIPLIER,
    score_z_thresh:    float = SCORE_Z_THRESHOLD,
    block_rate_thresh: float = BLOCK_RATE_ABS_DIFF,
) -> DriftReport:
    """
    Run all drift checks and return a DriftReport.
    """
    now      = datetime.now(timezone.utc)
    recent_start   = now - timedelta(minutes=window_minutes)
    baseline_start = now - timedelta(minutes=window_minutes * (baseline_mult + 1))
    baseline_end   = now - timedelta(minutes=window_minutes)

    df_recent   = _query_events(recent_start)
    df_baseline = _query_events(baseline_start, baseline_end)

    alerts = []

    # ── score drift ───────────────────────────────────────────────────────────
    recent_avg   = float(df_recent["score"].mean())   if len(df_recent)   > 0 else 0.0
    baseline_avg = float(df_baseline["score"].mean()) if len(df_baseline) > 0 else 0.0
    baseline_std = float(df_baseline["score"].std())  if len(df_baseline) > 1 else 1.0
    if baseline_std < 1e-6:
        baseline_std = 1e-6

    score_z     = abs(recent_avg - baseline_avg) / baseline_std
    score_drift = (
        len(df_recent) >= MIN_EVENTS
        and len(df_baseline) >= MIN_EVENTS
        and score_z >= score_z_thresh
    )

    if score_drift:
        direction = "higher" if recent_avg > baseline_avg else "lower"
        alerts.append(
            f"Score drift detected: recent avg={recent_avg:.3f} is {direction} "
            f"than baseline={baseline_avg:.3f} (z={score_z:.2f})"
        )

    # ── block rate drift ──────────────────────────────────────────────────────
    recent_block_rate   = 0.0
    baseline_block_rate = 0.0
    block_rate_diff     = 0.0
    block_rate_drift    = False

    if len(df_recent) >= MIN_EVENTS:
        recent_block_rate = (df_recent["action"] == "BLOCK").mean()

    if len(df_baseline) >= MIN_EVENTS:
        baseline_block_rate = (df_baseline["action"] == "BLOCK").mean()
        block_rate_diff  = recent_block_rate - baseline_block_rate
        block_rate_drift = abs(block_rate_diff) >= block_rate_thresh

    if block_rate_drift:
        direction = "spiked up" if block_rate_diff > 0 else "dropped"
        alerts.append(
            f"Block rate drift: {direction} from {baseline_block_rate:.1%} "
            f"to {recent_block_rate:.1%} (diff={block_rate_diff:+.1%})"
        )

    # ── low-event warning ─────────────────────────────────────────────────────
    if len(df_recent) < MIN_EVENTS:
        alerts.append(
            f"Not enough recent events ({len(df_recent)}) "
            f"to run reliable drift check (need {MIN_EVENTS})"
        )

    return DriftReport(
        checked_at=now.isoformat(timespec="seconds"),
        recent_events=len(df_recent),
        baseline_events=len(df_baseline),
        recent_avg_score=round(recent_avg, 4),
        baseline_avg_score=round(baseline_avg, 4),
        score_z=round(score_z, 3),
        score_drift=score_drift,
        recent_block_rate=round(recent_block_rate, 4),
        baseline_block_rate=round(baseline_block_rate, 4),
        block_rate_diff=round(block_rate_diff, 4),
        block_rate_drift=block_rate_drift,
        drift_detected=score_drift or block_rate_drift,
        alerts=alerts,
    )


if __name__ == "__main__":
    report = check()
    print(report)
    if report.drift_detected:
        print("\nRecommendation: trigger a retrain cycle.")
        print("  python -m src.retrainer --now --force")
    else:
        print("\nNo significant drift detected.")
