"""
dashboard/app.py
----------------
Streamlit dashboard for the AI-powered WAF.

Run with:
    cd ai-waf/
    venv/Scripts/activate
    streamlit run dashboard/app.py

Shows:
  - Live KPI cards: total, blocked, allowed, block rate
  - Recent events table with colour-coded actions
  - Requests over time (line chart)
  - Attack vs Normal distribution (pie)
  - Score distribution histogram
  - Model performance metrics
  - Auto-refresh every 5 seconds
"""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import time
from pathlib import Path
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import streamlit as st
from src.config import RETRAIN_INTERVAL_HOURS

# ── page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI-WAF Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .metric-card {
        background: #1e1e2e;
        border-radius: 10px;
        padding: 16px 20px;
        border-left: 4px solid #7c3aed;
    }
    .block-card  { border-left-color: #ef4444; }
    .allow-card  { border-left-color: #22c55e; }
    .rate-card   { border-left-color: #f59e0b; }
    .stDataFrame td { font-size: 13px; }
    div[data-testid="metric-container"] {
        background: #1e1e2e;
        border: 1px solid #374151;
        border-radius: 8px;
        padding: 10px 16px;
    }
</style>
""", unsafe_allow_html=True)


# ── helpers ───────────────────────────────────────────────────────────────────

@st.cache_data(ttl=5)
def load_events(limit: int = 500) -> pd.DataFrame:
    """Load recent events from SQLite. Cached for 5 seconds."""
    try:
        from src.logger import get_recent
        rows = get_recent(limit)
        if not rows:
            return pd.DataFrame(columns=["id","timestamp","method","url","path",
                                          "score","label","action","client_ip"])
        df = pd.DataFrame(rows)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df
    except Exception as e:
        st.error(f"Could not load events: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=5)
def load_stats() -> dict:
    try:
        from src.logger import get_stats
        return get_stats()
    except Exception:
        return {"total": 0, "blocked": 0, "allowed": 0,
                "block_rate_pct": 0.0, "recent_total": 0, "recent_blocked": 0}


@st.cache_data(ttl=3600)
def load_model_metrics() -> dict:
    try:
        df = pd.read_csv("models/eval_results.csv")
        return df.iloc[0].to_dict()
    except Exception:
        return {}


@st.cache_data(ttl=30)
def load_retrain_log() -> pd.DataFrame:
    try:
        df = pd.read_csv("models/retrain_log.csv")
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=30)
def load_drift_report() -> dict:
    try:
        from src.drift_detector import check
        r = check()
        return {
            "drift_detected":     r.drift_detected,
            "score_drift":        r.score_drift,
            "block_rate_drift":   r.block_rate_drift,
            "recent_avg_score":   r.recent_avg_score,
            "baseline_avg_score": r.baseline_avg_score,
            "recent_block_rate":  r.recent_block_rate,
            "baseline_block_rate":r.baseline_block_rate,
            "recent_events":      r.recent_events,
            "alerts":             r.alerts,
        }
    except Exception as e:
        return {"drift_detected": False, "alerts": [str(e)], "recent_events": 0}


# ── sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=60)
    st.title("AI-WAF")
    st.caption("Web Application Firewall")
    st.divider()

    st.subheader("Settings")
    auto_refresh = st.toggle("Auto-refresh (5s)", value=True)
    n_events     = st.slider("Events to display", 50, 500, 200, 50)
    show_allowed = st.toggle("Show ALLOW events", value=True)
    show_blocked = st.toggle("Show BLOCK events", value=True)

    st.divider()
    st.subheader("Model")
    metrics = load_model_metrics()
    if metrics:
        st.metric("ROC-AUC",   f"{metrics.get('ROC-AUC',   0):.4f}")
        st.metric("Recall",    f"{metrics.get('Recall',    0):.4f}")
        st.metric("Precision", f"{metrics.get('Precision', 0):.4f}")
        st.metric("F1",        f"{metrics.get('F1',        0):.4f}")
    else:
        st.info("Train model first: `python -m src.trainer`")

    st.divider()
    st.caption("Threshold: 0.5  |  Model: Random Forest 200 trees")

    if st.button("Clear all events", type="secondary"):
        from src.logger import clear_all
        clear_all()
        st.cache_data.clear()
        st.success("Events cleared.")

    if st.button("Simulate traffic"):
        import subprocess
        subprocess.Popen(
            ["venv/Scripts/python", "dashboard/simulate_traffic.py"],
            cwd=os.path.abspath("..") if os.getcwd().endswith("dashboard") else "."
        )
        st.info("Simulation started — refresh in a moment.")


# ── main area ─────────────────────────────────────────────────────────────────

st.title("🛡️ AI-Powered WAF  —  Live Dashboard")
st.caption("Real-time monitoring of HTTP traffic classifications")

tab_live, tab_retrain = st.tabs(["Live Traffic", "Auto-Retraining"])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — LIVE TRAFFIC
# ══════════════════════════════════════════════════════════════════════════════
with tab_live:

# load data
 stats  = load_stats()
 df_all = load_events(n_events)

# filter based on sidebar toggles
if not df_all.empty:
    actions = []
    if show_allowed: actions.append("ALLOW")
    if show_blocked: actions.append("BLOCK")
    df = df_all[df_all["action"].isin(actions)] if actions else df_all.iloc[0:0]
else:
    df = df_all

st.divider()

# ── KPI row ───────────────────────────────────────────────────────────────────
c1, c2, c3, c4, c5 = st.columns(5)

c1.metric("Total Requests",  f"{stats['total']:,}")
c2.metric("Blocked",         f"{stats['blocked']:,}",
          delta=f"+{stats['recent_blocked']} last 10 min",
          delta_color="inverse")
c3.metric("Allowed",         f"{stats['allowed']:,}")
c4.metric("Block Rate",      f"{stats['block_rate_pct']:.1f}%")
c5.metric("Recent (10 min)", f"{stats['recent_total']:,}")

st.divider()

# ── charts row ────────────────────────────────────────────────────────────────
if df.empty:
    st.info("No events yet. Start the proxy or run: `python dashboard/simulate_traffic.py`")
else:
    col_left, col_right = st.columns([2, 1])

    # ── timeline chart ────────────────────────────────────────────────────────
    with col_left:
        st.subheader("Requests Over Time")
        df_time = df.copy()
        df_time["minute"] = df_time["timestamp"].dt.floor("1min")
        timeline = (
            df_time.groupby(["minute", "action"])
            .size()
            .reset_index(name="count")
        )
        if not timeline.empty:
            fig_time = px.line(
                timeline, x="minute", y="count", color="action",
                color_discrete_map={"ALLOW": "#22c55e", "BLOCK": "#ef4444"},
                markers=True,
                labels={"minute": "Time", "count": "Requests", "action": "Action"},
            )
            fig_time.update_layout(
                plot_bgcolor="#0f172a", paper_bgcolor="#0f172a",
                font_color="#e2e8f0", legend_title_text="",
                margin=dict(l=0, r=0, t=10, b=0), height=280,
            )
            st.plotly_chart(fig_time, width='stretch')

    # ── pie chart ─────────────────────────────────────────────────────────────
    with col_right:
        st.subheader("Traffic Split")
        pie_data = df["action"].value_counts().reset_index()
        pie_data.columns = ["Action", "Count"]
        if not pie_data.empty:
            fig_pie = px.pie(
                pie_data, names="Action", values="Count",
                color="Action",
                color_discrete_map={"ALLOW": "#22c55e", "BLOCK": "#ef4444"},
                hole=0.45,
            )
            fig_pie.update_layout(
                plot_bgcolor="#0f172a", paper_bgcolor="#0f172a",
                font_color="#e2e8f0", showlegend=True,
                margin=dict(l=0, r=0, t=10, b=0), height=280,
            )
            fig_pie.update_traces(textinfo="percent+label")
            st.plotly_chart(fig_pie, width='stretch')

    st.divider()

    # ── score distribution + method breakdown ─────────────────────────────────
    col_hist, col_method = st.columns(2)

    with col_hist:
        st.subheader("Attack Score Distribution")
        fig_hist = go.Figure()
        for action, color in [("ALLOW", "#22c55e"), ("BLOCK", "#ef4444")]:
            subset = df[df["action"] == action]["score"]
            if not subset.empty:
                fig_hist.add_trace(go.Histogram(
                    x=subset, name=action, opacity=0.7,
                    marker_color=color, nbinsx=30,
                ))
        fig_hist.add_vline(x=0.5, line_dash="dash", line_color="white",
                           annotation_text="Threshold 0.5")
        fig_hist.update_layout(
            barmode="overlay",
            plot_bgcolor="#0f172a", paper_bgcolor="#0f172a",
            font_color="#e2e8f0", legend_title_text="",
            xaxis_title="Score", yaxis_title="Count",
            margin=dict(l=0, r=0, t=10, b=0), height=260,
        )
        st.plotly_chart(fig_hist, width='stretch')

    with col_method:
        st.subheader("HTTP Method Breakdown")
        method_counts = (
            df.groupby(["method", "action"])
            .size()
            .reset_index(name="count")
        )
        if not method_counts.empty:
            fig_method = px.bar(
                method_counts, x="method", y="count", color="action",
                color_discrete_map={"ALLOW": "#22c55e", "BLOCK": "#ef4444"},
                labels={"method": "HTTP Method", "count": "Count", "action": "Action"},
                barmode="group",
            )
            fig_method.update_layout(
                plot_bgcolor="#0f172a", paper_bgcolor="#0f172a",
                font_color="#e2e8f0", legend_title_text="",
                margin=dict(l=0, r=0, t=10, b=0), height=260,
            )
            st.plotly_chart(fig_method, width='stretch')

    st.divider()

    # ── recent events table ───────────────────────────────────────────────────
    st.subheader("Recent Events")

    display_df = df[["timestamp", "method", "url", "score", "action", "client_ip"]].copy()
    display_df["timestamp"] = display_df["timestamp"].dt.strftime("%H:%M:%S")
    display_df["score"]     = display_df["score"].round(3)
    display_df["url"]       = display_df["url"].str[:80]

    # Colour code: blocked rows red, allowed green
    def row_style(row):
        color = "#3f1f1f" if row["action"] == "BLOCK" else "#1a2f1a"
        return [f"background-color: {color}"] * len(row)

    st.dataframe(
        display_df.style.apply(row_style, axis=1),
        width='stretch',
        height=400,
        hide_index=True,
    )

    # ── top blocked IPs ───────────────────────────────────────────────────────
    blocked_ips = (
        df[df["action"] == "BLOCK"]["client_ip"]
        .value_counts()
        .reset_index()
    )
    blocked_ips.columns = ["IP Address", "Block Count"]

    if not blocked_ips.empty and blocked_ips["IP Address"].iloc[0] != "":
        st.divider()
        st.subheader("Top Blocked IPs")
        st.dataframe(blocked_ips.head(10), width='stretch', hide_index=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — AUTO-RETRAINING
# ══════════════════════════════════════════════════════════════════════════════
with tab_retrain:
    st.subheader("Drift Detection")
    drift = load_drift_report()

    d1, d2, d3 = st.columns(3)
    d1.metric("Drift Detected",   "YES" if drift.get("drift_detected") else "No",
              delta=None)
    d2.metric("Recent Avg Score",
              f"{drift.get('recent_avg_score', 0):.3f}",
              delta=f"{drift.get('recent_avg_score',0) - drift.get('baseline_avg_score',0):+.3f} vs baseline")
    d3.metric("Recent Block Rate",
              f"{drift.get('recent_block_rate', 0):.1%}",
              delta=f"{drift.get('recent_block_rate',0) - drift.get('baseline_block_rate',0):+.1%} vs baseline",
              delta_color="inverse")

    if drift.get("alerts"):
        for alert in drift["alerts"]:
            if "drift" in alert.lower():
                st.warning(f"Drift alert: {alert}")
            else:
                st.info(alert)
    else:
        st.success("No significant drift detected in recent traffic.")

    st.divider()

    # ── manual retrain trigger ────────────────────────────────────────────────
    st.subheader("Manual Retrain")
    col_btn, col_info = st.columns([1, 3])
    with col_btn:
        if st.button("Retrain Now", type="primary"):
            with st.spinner("Retraining model ..."):
                import subprocess, sys
                result = subprocess.run(
                    [sys.executable, "-m", "src.retrainer", "--now", "--force"],
                    capture_output=True, text=True
                )
                st.code(result.stdout or result.stderr)
                st.cache_data.clear()
    with col_info:
        st.info(
            f"Auto-retraining runs every **{RETRAIN_INTERVAL_HOURS}h** as a daemon.  \n"
            f"Start it with: `python -m src.retrainer --daemon`  \n"
            f"The model is only swapped if the new F1 >= old F1 − 0.5%."
        )

    st.divider()

    # ── retrain history ───────────────────────────────────────────────────────
    st.subheader("Retrain History")
    retrain_df = load_retrain_log()

    if retrain_df.empty:
        st.info("No retrain history yet. Click 'Retrain Now' to create the first entry.")
    else:
        # F1 over time chart
        fig_f1 = go.Figure()
        fig_f1.add_trace(go.Scatter(
            x=retrain_df["timestamp"], y=retrain_df["old_f1"],
            name="Old model F1", line=dict(color="#94a3b8", dash="dot"),
        ))
        fig_f1.add_trace(go.Scatter(
            x=retrain_df["timestamp"], y=retrain_df["new_f1"],
            name="New model F1", line=dict(color="#22c55e"),
            mode="lines+markers",
        ))
        fig_f1.update_layout(
            plot_bgcolor="#0f172a", paper_bgcolor="#0f172a",
            font_color="#e2e8f0", legend_title_text="",
            xaxis_title="Run Time", yaxis_title="F1 Score",
            margin=dict(l=0, r=0, t=10, b=0), height=260,
            yaxis=dict(range=[0.5, 1.0]),
        )
        st.plotly_chart(fig_f1, width='stretch')

        # history table
        display = retrain_df[[
            "timestamp", "rows_used", "old_f1", "new_f1", "old_auc", "new_auc", "swapped"
        ]].copy()
        display["timestamp"] = display["timestamp"].dt.strftime("%Y-%m-%d %H:%M")
        display["swapped"]   = display["swapped"].map({True: "YES", False: "no", 1: "YES", 0: "no"})
        st.dataframe(display, width='stretch', hide_index=True)

    st.divider()

    # ── archived models ───────────────────────────────────────────────────────
    st.subheader("Archived Models")
    archive_dir = Path("models/archive")
    if archive_dir.exists():
        archives = sorted(archive_dir.iterdir(), reverse=True)
        if archives:
            st.write(f"**{len(archives)}** archived version(s):")
            for a in archives[:10]:
                files = list(a.iterdir())
                file_names = ", ".join(f.name for f in files)
                st.text(f"  {a.name}  —  {file_names}")
        else:
            st.info("No archived models yet.")
    else:
        st.info("Archive directory will be created on first retrain.")


# ── auto-refresh ──────────────────────────────────────────────────────────────
if auto_refresh:
    time.sleep(5)
    st.cache_data.clear()
    st.rerun()
