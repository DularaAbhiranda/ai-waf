"""
dashboard/app.py  —  AI-WAF Live Dashboard (Redesigned)
Run:  streamlit run dashboard/app.py
"""

import sys, os, time, subprocess
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pathlib import Path
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from src.config import RETRAIN_INTERVAL_HOURS

# ── page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI-WAF Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── global CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── base ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* hide default streamlit chrome */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 1rem 1.5rem 2rem 1.5rem !important; }

/* ── top nav bar ── */
.nav-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
    border-radius: 14px;
    padding: 14px 24px;
    margin-bottom: 20px;
    border: 1px solid #334155;
}
.nav-brand {
    display: flex;
    align-items: center;
    gap: 12px;
}
.nav-brand h1 {
    font-size: 1.4rem;
    font-weight: 700;
    color: #f8fafc;
    margin: 0;
    letter-spacing: -0.3px;
}
.nav-brand p {
    font-size: 0.75rem;
    color: #94a3b8;
    margin: 0;
}
.nav-badge {
    display: flex;
    align-items: center;
    gap: 8px;
    background: #0f2c1a;
    border: 1px solid #166534;
    border-radius: 20px;
    padding: 6px 14px;
    font-size: 0.8rem;
    color: #4ade80;
    font-weight: 600;
}
.nav-badge .dot {
    width: 8px; height: 8px;
    background: #4ade80;
    border-radius: 50%;
    animation: pulse 2s infinite;
}
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.4; }
}

/* ── KPI cards ── */
.kpi-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 14px;
    margin-bottom: 20px;
}
.kpi-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 14px;
    padding: 18px 20px;
    position: relative;
    overflow: hidden;
    transition: transform 0.2s;
}
.kpi-card:hover { transform: translateY(-2px); }
.kpi-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 3px;
    border-radius: 14px 14px 0 0;
}
.kpi-total::before   { background: #818cf8; }
.kpi-blocked::before { background: #f87171; }
.kpi-allowed::before { background: #4ade80; }
.kpi-rate::before    { background: #fb923c; }
.kpi-recent::before  { background: #38bdf8; }

.kpi-icon {
    font-size: 1.6rem;
    margin-bottom: 8px;
    display: block;
}
.kpi-label {
    font-size: 0.72rem;
    font-weight: 600;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-bottom: 4px;
}
.kpi-value {
    font-size: 1.9rem;
    font-weight: 700;
    color: #f8fafc;
    line-height: 1;
}
.kpi-sub {
    font-size: 0.72rem;
    color: #64748b;
    margin-top: 6px;
}
.kpi-sub.up   { color: #f87171; }
.kpi-sub.down { color: #4ade80; }

/* ── section card ── */
.section-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 14px;
    padding: 20px 22px;
    margin-bottom: 16px;
}
.section-title {
    font-size: 0.9rem;
    font-weight: 600;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
}

/* ── event table badges ── */
.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.5px;
}
.badge-block { background: #3f1010; color: #f87171; border: 1px solid #7f1d1d; }
.badge-allow { background: #0f2e1a; color: #4ade80; border: 1px solid #166534; }

/* ── alert boxes ── */
.alert-drift {
    background: #3f1f0a;
    border: 1px solid #92400e;
    border-radius: 10px;
    padding: 12px 16px;
    color: #fb923c;
    font-size: 0.85rem;
    margin-bottom: 10px;
}
.alert-ok {
    background: #0f2e1a;
    border: 1px solid #166534;
    border-radius: 10px;
    padding: 12px 16px;
    color: #4ade80;
    font-size: 0.85rem;
}

/* ── model metric pill ── */
.metric-pill {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 10px 14px;
    margin-bottom: 8px;
}
.metric-pill .mp-label { font-size: 0.72rem; color: #64748b; font-weight: 600; }
.metric-pill .mp-value { font-size: 1.3rem; font-weight: 700; color: #f8fafc; }
.metric-pill .mp-bar-bg {
    background: #1e293b; border-radius: 4px;
    height: 5px; margin-top: 6px;
}
.metric-pill .mp-bar-fill {
    height: 5px; border-radius: 4px;
    background: linear-gradient(90deg, #818cf8, #38bdf8);
}

/* ── tab styling ── */
.stTabs [data-baseweb="tab-list"] {
    gap: 4px;
    background: #0f172a;
    border-radius: 10px;
    padding: 4px;
    border: 1px solid #334155;
}
.stTabs [data-baseweb="tab"] {
    border-radius: 8px;
    color: #94a3b8;
    font-weight: 600;
    font-size: 0.85rem;
    padding: 8px 20px;
}
.stTabs [aria-selected="true"] {
    background: #1e293b !important;
    color: #f8fafc !important;
}

/* ── mobile responsive ── */
@media (max-width: 768px) {
    .kpi-grid {
        grid-template-columns: repeat(2, 1fr) !important;
    }
    .nav-bar {
        flex-direction: column;
        align-items: flex-start;
        gap: 10px;
    }
    .block-container { padding: 0.5rem !important; }
    .kpi-value { font-size: 1.5rem; }
}
@media (max-width: 480px) {
    .kpi-grid { grid-template-columns: 1fr 1fr !important; }
}

/* ── sidebar ── */
[data-testid="stSidebar"] {
    background: #0f172a;
    border-right: 1px solid #334155;
}
[data-testid="stSidebar"] .stButton button {
    width: 100%;
    border-radius: 8px;
}

/* ── scrollbar ── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #1e293b; }
::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
</style>
""", unsafe_allow_html=True)


# ── data loaders ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=5)
def load_events(limit=500):
    try:
        from src.logger import get_recent
        rows = get_recent(limit)
        if not rows:
            return pd.DataFrame(columns=["id","timestamp","method","url",
                                          "path","score","label","action","client_ip"])
        df = pd.DataFrame(rows)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df
    except Exception as e:
        return pd.DataFrame()

@st.cache_data(ttl=5)
def load_stats():
    try:
        from src.logger import get_stats
        return get_stats()
    except Exception:
        return {"total":0,"blocked":0,"allowed":0,
                "block_rate_pct":0.0,"recent_total":0,"recent_blocked":0}

@st.cache_data(ttl=3600)
def load_model_metrics():
    try:
        df = pd.read_csv("models/eval_results.csv")
        row = df.iloc[0].to_dict()
        # Normalise column names so the rest of the app always sees the same keys
        row.setdefault("CV_F1_Mean", row.pop("cv_f1_mean", 0))
        row.setdefault("CV_F1_Std",  row.pop("cv_f1_std",  0))
        return row
    except Exception:
        return {}

@st.cache_data(ttl=30)
def load_retrain_log():
    try:
        df = pd.read_csv("models/retrain_log.csv")
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df
    except Exception:
        return pd.DataFrame()

@st.cache_data(ttl=30)
def load_drift_report():
    try:
        from src.drift_detector import check
        r = check()
        return {
            "drift_detected":      r.drift_detected,
            "score_drift":         r.score_drift,
            "block_rate_drift":    r.block_rate_drift,
            "recent_avg_score":    r.recent_avg_score,
            "baseline_avg_score":  r.baseline_avg_score,
            "recent_block_rate":   r.recent_block_rate,
            "baseline_block_rate": r.baseline_block_rate,
            "recent_events":       r.recent_events,
            "alerts":              r.alerts,
        }
    except Exception as e:
        return {"drift_detected":False,"alerts":[str(e)],"recent_events":0,
                "recent_avg_score":0,"baseline_avg_score":0,
                "recent_block_rate":0,"baseline_block_rate":0}

CHART_LAYOUT = dict(
    plot_bgcolor="#0f172a", paper_bgcolor="rgba(0,0,0,0)",
    font_color="#94a3b8", font_family="Inter",
    margin=dict(l=10, r=10, t=10, b=10),
    xaxis=dict(gridcolor="#1e293b", linecolor="#334155"),
    yaxis=dict(gridcolor="#1e293b", linecolor="#334155"),
)
# Shared legend style — apply separately to avoid conflicts with per-chart legend overrides
_LEGEND = dict(bgcolor="rgba(0,0,0,0)", bordercolor="#334155", borderwidth=1)

def chart_layout(**overrides):
    """Return CHART_LAYOUT merged with per-chart overrides (handles legend safely)."""
    layout = dict(CHART_LAYOUT)
    layout.pop("xaxis", None) if "xaxis" not in overrides else None
    layout.pop("yaxis", None) if "yaxis" not in overrides else None
    layout["legend"] = {**_LEGEND, **overrides.pop("legend", {})}
    layout.update(overrides)
    return layout


# ── sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ Controls")
    st.divider()

    auto_refresh  = st.toggle("Auto-refresh every 5s", value=True)
    n_events      = st.slider("Max events to load", 50, 500, 200, 50)
    show_allowed  = st.toggle("Show ALLOW events", value=True)
    show_blocked  = st.toggle("Show BLOCK events", value=True)

    st.divider()
    st.markdown("### 🤖 Model Performance")
    metrics = load_model_metrics()
    if metrics:
        for label, key, color in [
            ("ROC-AUC",   "ROC-AUC",   "#818cf8"),
            ("F1 Score",  "F1",        "#38bdf8"),
            ("Recall",    "Recall",    "#4ade80"),
            ("Precision", "Precision", "#fb923c"),
        ]:
            val = metrics.get(key, 0)
            pct = int(val * 100)
            st.markdown(f"""
            <div class="metric-pill">
                <div class="mp-label">{label}</div>
                <div class="mp-value">{val:.4f}</div>
                <div class="mp-bar-bg">
                    <div class="mp-bar-fill" style="width:{pct}%; background: linear-gradient(90deg,{color}88,{color});"></div>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("Train model first")

    st.divider()
    st.markdown("### 🛠️ Actions")

    if st.button("🗑️ Clear all events", use_container_width=True):
        try:
            from src.logger import clear_all
            clear_all()
            st.cache_data.clear()
            st.success("Events cleared.")
        except Exception as e:
            st.error(str(e))

    if st.button("⚡ Simulate traffic", use_container_width=True):
        try:
            cwd = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            subprocess.Popen(
                [sys.executable, "dashboard/simulate_traffic.py", "--n", "300"],
                cwd=cwd
            )
            st.info("Simulation started — refresh in ~5s")
        except Exception as e:
            st.error(str(e))

    st.divider()
    st.caption("Threshold: 0.5  ·  RF 200 trees  ·  CSIC 2010")


# ── top nav bar ───────────────────────────────────────────────────────────────
stats = load_stats()
proxy_active = stats["total"] > 0

st.markdown(f"""
<div class="nav-bar">
    <div class="nav-brand">
        <span style="font-size:2rem;">🛡️</span>
        <div>
            <h1>AI-WAF Dashboard</h1>
            <p>AI-Powered Web Application Firewall  ·  Real-time monitoring</p>
        </div>
    </div>
    <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
        <div class="nav-badge">
            <span class="dot"></span>
            {"Proxy Active" if proxy_active else "Awaiting traffic"}
        </div>
        <div style="color:#64748b; font-size:0.75rem;">
            Last update: {pd.Timestamp.now().strftime("%H:%M:%S")}
        </div>
    </div>
</div>
""", unsafe_allow_html=True)


# ── KPI cards ─────────────────────────────────────────────────────────────────
block_rate = stats.get("block_rate_pct", 0)
recent_blocked = stats.get("recent_blocked", 0)

st.markdown(f"""
<div class="kpi-grid">
    <div class="kpi-card kpi-total">
        <span class="kpi-icon">📊</span>
        <div class="kpi-label">Total Requests</div>
        <div class="kpi-value">{stats['total']:,}</div>
        <div class="kpi-sub">All time</div>
    </div>
    <div class="kpi-card kpi-blocked">
        <span class="kpi-icon">🚫</span>
        <div class="kpi-label">Blocked</div>
        <div class="kpi-value">{stats['blocked']:,}</div>
        <div class="kpi-sub up">+{recent_blocked} last 10 min</div>
    </div>
    <div class="kpi-card kpi-allowed">
        <span class="kpi-icon">✅</span>
        <div class="kpi-label">Allowed</div>
        <div class="kpi-value">{stats['allowed']:,}</div>
        <div class="kpi-sub down">Clean traffic</div>
    </div>
    <div class="kpi-card kpi-rate">
        <span class="kpi-icon">📈</span>
        <div class="kpi-label">Block Rate</div>
        <div class="kpi-value">{block_rate:.1f}%</div>
        <div class="kpi-sub">of all requests</div>
    </div>
    <div class="kpi-card kpi-recent">
        <span class="kpi-icon">⏱️</span>
        <div class="kpi-label">Recent (10 min)</div>
        <div class="kpi-value">{stats['recent_total']:,}</div>
        <div class="kpi-sub">Live activity</div>
    </div>
</div>
""", unsafe_allow_html=True)


# ── tabs ──────────────────────────────────────────────────────────────────────
tab_live, tab_attacks, tab_retrain, tab_model = st.tabs([
    "📡  Live Traffic",
    "⚔️  Attack Analysis",
    "🔄  Auto-Retraining",
    "🤖  Model Info",
])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — LIVE TRAFFIC
# ══════════════════════════════════════════════════════════════════════════════
with tab_live:
    df_all = load_events(n_events)

    if df_all.empty:
        st.markdown("""
        <div style="text-align:center; padding:60px 20px; color:#64748b;">
            <div style="font-size:3rem;">📭</div>
            <div style="font-size:1.1rem; margin-top:12px; color:#94a3b8;">No events yet</div>
            <div style="font-size:0.85rem; margin-top:6px;">
                Start the proxy with <code>mitmdump -s src/proxy_interceptor.py --listen-port 8080</code><br>
                or click <b>Simulate traffic</b> in the sidebar.
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        actions = []
        if show_allowed: actions.append("ALLOW")
        if show_blocked: actions.append("BLOCK")
        df = df_all[df_all["action"].isin(actions)] if actions else df_all.iloc[0:0]

        # ── row 1: timeline + pie ─────────────────────────────────────────────
        col_left, col_right = st.columns([3, 1], gap="medium")

        with col_left:
            st.markdown('<div class="section-card">', unsafe_allow_html=True)
            st.markdown('<div class="section-title">📡 Requests Over Time</div>', unsafe_allow_html=True)
            df_time = df.copy()
            df_time["minute"] = df_time["timestamp"].dt.floor("1min")
            timeline = df_time.groupby(["minute","action"]).size().reset_index(name="count")

            if not timeline.empty:
                fig = px.area(
                    timeline, x="minute", y="count", color="action",
                    color_discrete_map={"ALLOW":"#4ade80","BLOCK":"#f87171"},
                    labels={"minute":"Time","count":"Requests","action":""},
                    line_shape="spline",
                )
                fig.update_traces(opacity=0.7)
                fig.update_layout(**chart_layout(height=240, showlegend=True))
                st.plotly_chart(fig, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with col_right:
            st.markdown('<div class="section-card">', unsafe_allow_html=True)
            st.markdown('<div class="section-title">🥧 Traffic Split</div>', unsafe_allow_html=True)
            pie_data = df["action"].value_counts().reset_index()
            pie_data.columns = ["Action","Count"]
            if not pie_data.empty:
                fig_pie = px.pie(
                    pie_data, names="Action", values="Count",
                    color="Action",
                    color_discrete_map={"ALLOW":"#4ade80","BLOCK":"#f87171"},
                    hole=0.55,
                )
                fig_pie.update_traces(textinfo="percent", textfont_size=13)
                fig_pie.update_layout(**chart_layout(
                    height=240, showlegend=True,
                    legend=dict(orientation="h", yanchor="bottom", y=-0.2),
                ))
                st.plotly_chart(fig_pie, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

        # ── row 2: score histogram + method bar ───────────────────────────────
        col_hist, col_method = st.columns(2, gap="medium")

        with col_hist:
            st.markdown('<div class="section-card">', unsafe_allow_html=True)
            st.markdown('<div class="section-title">🎯 ML Score Distribution</div>', unsafe_allow_html=True)
            fig_hist = go.Figure()
            for action, color in [("ALLOW","#4ade80"),("BLOCK","#f87171")]:
                subset = df[df["action"]==action]["score"]
                if not subset.empty:
                    fig_hist.add_trace(go.Histogram(
                        x=subset, name=action, opacity=0.75,
                        marker_color=color, nbinsx=25,
                    ))
            fig_hist.add_vline(x=0.5, line_dash="dash", line_color="#f8fafc",
                               line_width=1.5,
                               annotation_text="  Threshold 0.5",
                               annotation_font_color="#f8fafc",
                               annotation_font_size=11)
            fig_hist.update_layout(**chart_layout(
                barmode="overlay", height=240,
                xaxis_title="Score", yaxis_title="Count",
            ))
            st.plotly_chart(fig_hist, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with col_method:
            st.markdown('<div class="section-card">', unsafe_allow_html=True)
            st.markdown('<div class="section-title">🔀 HTTP Method Breakdown</div>', unsafe_allow_html=True)
            method_counts = df.groupby(["method","action"]).size().reset_index(name="count")
            if not method_counts.empty:
                fig_method = px.bar(
                    method_counts, x="method", y="count", color="action",
                    color_discrete_map={"ALLOW":"#4ade80","BLOCK":"#f87171"},
                    labels={"method":"Method","count":"Count","action":""},
                    barmode="group", text_auto=True,
                )
                fig_method.update_traces(textfont_size=11, textposition="outside")
                fig_method.update_layout(**chart_layout(height=240, showlegend=True))
                st.plotly_chart(fig_method, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

        # ── recent events table ───────────────────────────────────────────────
        st.markdown('<div class="section-card">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">📋 Recent Events</div>', unsafe_allow_html=True)

        display_df = df[["timestamp","method","url","score","action","client_ip"]].copy()
        display_df["timestamp"] = display_df["timestamp"].dt.strftime("%H:%M:%S")
        display_df["score"]     = display_df["score"].round(3)
        display_df["url"]       = display_df["url"].str[:90]

        def style_row(row):
            bg = "#2d0f0f" if row["action"] == "BLOCK" else "#0f2d1a"
            return [f"background-color:{bg}; color:#f1f5f9"] * len(row)

        styled = display_df.style.apply(style_row, axis=1).format({"score": "{:.3f}"})
        st.dataframe(styled, use_container_width=True, height=380, hide_index=True)
        st.markdown('</div>', unsafe_allow_html=True)

        # ── top blocked IPs ───────────────────────────────────────────────────
        blocked_ips = (
            df[df["action"]=="BLOCK"]["client_ip"]
            .value_counts().reset_index()
        )
        blocked_ips.columns = ["IP Address","Block Count"]
        if not blocked_ips.empty and blocked_ips["IP Address"].iloc[0]:
            st.markdown('<div class="section-card">', unsafe_allow_html=True)
            st.markdown('<div class="section-title">🔴 Top Blocked IPs</div>', unsafe_allow_html=True)
            fig_ip = px.bar(
                blocked_ips.head(10), x="Block Count", y="IP Address",
                orientation="h", color_discrete_sequence=["#f87171"],
                text_auto=True,
            )
            fig_ip.update_layout(**chart_layout(height=max(200, len(blocked_ips.head(10))*40)))
            st.plotly_chart(fig_ip, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — ATTACK ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
with tab_attacks:
    df_all = load_events(n_events)

    if df_all.empty:
        st.info("No events to analyse yet.")
    else:
        attacks = df_all[df_all["action"] == "BLOCK"].copy()
        normal  = df_all[df_all["action"] == "ALLOW"].copy()

        # ── attack type detector ──────────────────────────────────────────────
        def classify_attack(url):
            url_l = str(url).lower()
            if any(k in url_l for k in ["select","union","drop","insert","sleep(","or 1=1","'or'","1=1--"]):
                return "SQL Injection"
            if any(k in url_l for k in ["<script","onerror=","javascript:","alert(","document.cookie"]):
                return "XSS"
            if any(k in url_l for k in ["../","..%2f","%2e%2e","..%5c"]):
                return "Path Traversal"
            if any(k in url_l for k in [";cat","| cat","&&","||","; ls","| ls","%3bcat","%7ccat"]):
                return "Command Injection"
            if "%00" in url_l or "\x00" in url_l:
                return "Null Byte"
            return "Other"

        if not attacks.empty:
            attacks["attack_type"] = attacks["url"].apply(classify_attack)

        col1, col2 = st.columns(2, gap="medium")

        with col1:
            st.markdown('<div class="section-card">', unsafe_allow_html=True)
            st.markdown('<div class="section-title">⚔️ Attack Type Breakdown</div>', unsafe_allow_html=True)
            if not attacks.empty:
                type_counts = attacks["attack_type"].value_counts().reset_index()
                type_counts.columns = ["Attack Type","Count"]
                ATTACK_COLORS = {
                    "SQL Injection":    "#f87171",
                    "XSS":             "#fb923c",
                    "Path Traversal":  "#fbbf24",
                    "Command Injection":"#a78bfa",
                    "Null Byte":       "#38bdf8",
                    "Other":           "#94a3b8",
                }
                fig_types = px.bar(
                    type_counts, x="Count", y="Attack Type", orientation="h",
                    color="Attack Type", color_discrete_map=ATTACK_COLORS,
                    text_auto=True,
                )
                fig_types.update_layout(**chart_layout(height=260, showlegend=False))
                st.plotly_chart(fig_types, use_container_width=True)
            else:
                st.success("No attacks detected in current window.")
            st.markdown('</div>', unsafe_allow_html=True)

        with col2:
            st.markdown('<div class="section-card">', unsafe_allow_html=True)
            st.markdown('<div class="section-title">📊 Score: Attack vs Normal</div>', unsafe_allow_html=True)
            fig_box = go.Figure()
            if not attacks.empty:
                fig_box.add_trace(go.Box(
                    y=attacks["score"], name="Attacks",
                    marker_color="#f87171", boxmean=True,
                    line_color="#f87171",
                ))
            if not normal.empty:
                fig_box.add_trace(go.Box(
                    y=normal["score"], name="Normal",
                    marker_color="#4ade80", boxmean=True,
                    line_color="#4ade80",
                ))
            fig_box.update_layout(**chart_layout(height=260, yaxis_title="Score"))
            st.plotly_chart(fig_box, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

        # ── recent blocked requests detail ────────────────────────────────────
        st.markdown('<div class="section-card">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">🚫 Recent Blocked Requests</div>', unsafe_allow_html=True)
        if not attacks.empty:
            att_display = attacks[["timestamp","method","url","score","attack_type","client_ip"]].copy()
            att_display["timestamp"] = att_display["timestamp"].dt.strftime("%H:%M:%S")
            att_display["score"] = att_display["score"].round(3)
            att_display["url"]   = att_display["url"].str[:85]
            att_display = att_display.rename(columns={"attack_type":"Type"})

            def style_attacks(row):
                color_map = {
                    "SQL Injection":"#3f1510","XSS":"#3f2010",
                    "Path Traversal":"#3f3010","Command Injection":"#2a1040",
                    "Null Byte":"#0f2a3f","Other":"#1e293b"
                }
                bg = color_map.get(row["Type"], "#1e293b")
                return [f"background-color:{bg}; color:#f1f5f9"] * len(row)

            st.dataframe(
                att_display.style.apply(style_attacks, axis=1),
                use_container_width=True, height=360, hide_index=True,
            )
        else:
            st.success("No blocked requests in current view.")
        st.markdown('</div>', unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — AUTO-RETRAINING
# ══════════════════════════════════════════════════════════════════════════════
with tab_retrain:
    drift = load_drift_report()

    # drift KPI row
    d1, d2, d3, d4 = st.columns(4, gap="medium")
    drift_color = "#f87171" if drift.get("drift_detected") else "#4ade80"
    drift_icon  = "🔴" if drift.get("drift_detected") else "🟢"

    d1.markdown(f"""
    <div class="section-card" style="text-align:center;">
        <div style="font-size:2rem;">{drift_icon}</div>
        <div class="kpi-label" style="margin-top:6px;">Drift Status</div>
        <div style="font-size:1.2rem; font-weight:700; color:{drift_color};">
            {"DRIFT DETECTED" if drift.get("drift_detected") else "Stable"}
        </div>
    </div>""", unsafe_allow_html=True)

    d2.markdown(f"""
    <div class="section-card" style="text-align:center;">
        <div style="font-size:2rem;">🎯</div>
        <div class="kpi-label" style="margin-top:6px;">Recent Avg Score</div>
        <div style="font-size:1.4rem; font-weight:700; color:#f8fafc;">
            {drift.get('recent_avg_score', 0):.3f}
        </div>
        <div class="kpi-sub">baseline: {drift.get('baseline_avg_score',0):.3f}</div>
    </div>""", unsafe_allow_html=True)

    d3.markdown(f"""
    <div class="section-card" style="text-align:center;">
        <div style="font-size:2rem;">🚫</div>
        <div class="kpi-label" style="margin-top:6px;">Recent Block Rate</div>
        <div style="font-size:1.4rem; font-weight:700; color:#f8fafc;">
            {drift.get('recent_block_rate', 0):.1%}
        </div>
        <div class="kpi-sub">baseline: {drift.get('baseline_block_rate',0):.1%}</div>
    </div>""", unsafe_allow_html=True)

    d4.markdown(f"""
    <div class="section-card" style="text-align:center;">
        <div style="font-size:2rem;">📦</div>
        <div class="kpi-label" style="margin-top:6px;">Recent Events</div>
        <div style="font-size:1.4rem; font-weight:700; color:#f8fafc;">
            {drift.get('recent_events', 0):,}
        </div>
        <div class="kpi-sub">30-min window</div>
    </div>""", unsafe_allow_html=True)

    # alerts
    st.markdown("<br>", unsafe_allow_html=True)
    alerts = drift.get("alerts", [])
    if alerts and drift.get("drift_detected"):
        for a in alerts:
            st.markdown(f'<div class="alert-drift">⚠️ {a}</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="alert-ok">✅ No significant drift detected. Model is performing as expected.</div>',
                    unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # manual retrain
    col_btn, col_info = st.columns([1, 2], gap="medium")
    with col_btn:
        st.markdown('<div class="section-card">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">🔄 Manual Retrain</div>', unsafe_allow_html=True)
        if st.button("🚀 Retrain Now", type="primary", use_container_width=True):
            with st.spinner("Retraining model — this may take a minute..."):
                result = subprocess.run(
                    [sys.executable, "-m", "src.retrainer", "--now", "--force"],
                    capture_output=True, text=True
                )
                st.code(result.stdout[-2000:] if result.stdout else result.stderr[-2000:],
                        language="text")
                st.cache_data.clear()
        st.markdown('</div>', unsafe_allow_html=True)

    with col_info:
        st.markdown(f"""
        <div class="section-card">
            <div class="section-title">ℹ️ How Auto-Retraining Works</div>
            <div style="color:#94a3b8; font-size:0.85rem; line-height:1.7;">
                <b style="color:#f8fafc;">Every {RETRAIN_INTERVAL_HOURS}h</b> the daemon checks for model drift using:
                <ul style="margin:8px 0; padding-left:18px;">
                    <li>Score Z-score &gt; 2.5 vs 5h baseline</li>
                    <li>Block rate absolute diff &gt; 15%</li>
                </ul>
                If drift is detected, the model is retrained on the latest data.
                The new model is <b style="color:#4ade80;">only deployed if F1 ≥ old F1 − 0.5%</b>.<br><br>
                Old models are automatically archived to <code>models/archive/</code>.<br><br>
                Start daemon: <code>python -m src.retrainer --daemon</code>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # F1 over time chart
    retrain_df = load_retrain_log()
    if not retrain_df.empty:
        st.markdown('<div class="section-card">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">📈 F1 Score Over Retrain History</div>', unsafe_allow_html=True)
        fig_f1 = go.Figure()
        fig_f1.add_trace(go.Scatter(
            x=retrain_df["timestamp"], y=retrain_df["old_f1"],
            name="Previous Model", line=dict(color="#64748b", dash="dot", width=2),
            mode="lines+markers", marker=dict(size=6),
        ))
        fig_f1.add_trace(go.Scatter(
            x=retrain_df["timestamp"], y=retrain_df["new_f1"],
            name="New Model", line=dict(color="#4ade80", width=2),
            mode="lines+markers", marker=dict(size=8, symbol="circle"),
            fill="tonexty", fillcolor="rgba(74,222,128,0.05)",
        ))
        fig_f1.update_layout(**chart_layout(
            height=260,
            xaxis_title="Run Time", yaxis_title="F1 Score",
            yaxis=dict(range=[0.5, 1.0], gridcolor="#1e293b"),
        ))
        st.plotly_chart(fig_f1, use_container_width=True)

        display = retrain_df[["timestamp","rows_used","old_f1","new_f1","old_auc","new_auc","swapped"]].copy()
        display["timestamp"] = display["timestamp"].dt.strftime("%Y-%m-%d %H:%M")
        display["swapped"]   = display["swapped"].map({True:"✅ YES", False:"❌ No", 1:"✅ YES", 0:"❌ No"})
        st.dataframe(display, use_container_width=True, hide_index=True)
        st.markdown('</div>', unsafe_allow_html=True)

    # archived models
    archive_dir = Path("models/archive")
    if archive_dir.exists() and any(archive_dir.iterdir()):
        st.markdown('<div class="section-card">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">🗄️ Archived Models</div>', unsafe_allow_html=True)
        archives = sorted(archive_dir.iterdir(), reverse=True)
        for a in archives[:10]:
            files = [f.name for f in a.iterdir()]
            sizes = [f"{f.stat().st_size/1024:.0f} KB" for f in a.iterdir()]
            st.markdown(f"""
            <div style="background:#0f172a; border:1px solid #334155; border-radius:8px;
                        padding:10px 14px; margin-bottom:8px; font-size:0.82rem; color:#94a3b8;">
                📦 <b style="color:#f8fafc;">{a.name}</b> &nbsp;·&nbsp;
                {", ".join(files)}
            </div>""", unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — MODEL INFO
# ══════════════════════════════════════════════════════════════════════════════
with tab_model:
    metrics = load_model_metrics()

    col_m1, col_m2 = st.columns(2, gap="medium")

    with col_m1:
        st.markdown('<div class="section-card">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">📊 Performance Metrics</div>', unsafe_allow_html=True)
        if metrics:
            metric_items = [
                ("Accuracy",  "Accuracy",  "#818cf8"),
                ("Precision", "Precision", "#fb923c"),
                ("Recall",    "Recall",    "#4ade80"),
                ("F1 Score",  "F1",        "#38bdf8"),
                ("ROC-AUC",   "ROC-AUC",   "#a78bfa"),
            ]
            for label, key, color in metric_items:
                val = metrics.get(key, 0)
                pct = int(val * 100)
                st.markdown(f"""
                <div style="margin-bottom:12px;">
                    <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                        <span style="color:#94a3b8; font-size:0.8rem; font-weight:600;">{label}</span>
                        <span style="color:#f8fafc; font-weight:700;">{val:.4f}</span>
                    </div>
                    <div style="background:#0f172a; border-radius:4px; height:8px;">
                        <div style="width:{pct}%; height:8px; border-radius:4px;
                                    background:linear-gradient(90deg,{color}88,{color});"></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            cv_f1 = metrics.get("CV_F1_Mean", metrics.get("CV F1 Mean", 0))
            cv_std = metrics.get("CV_F1_Std",  metrics.get("CV F1 Std",  0))
            if cv_f1:
                st.markdown(f"""
                <div style="background:#0f172a; border-radius:8px; padding:10px 14px; margin-top:8px;
                            font-size:0.82rem; color:#94a3b8;">
                    5-fold CV F1: <b style="color:#f8fafc;">{cv_f1:.4f}</b> ± {cv_std:.4f}
                </div>""", unsafe_allow_html=True)
        else:
            st.info("No model metrics found. Train the model first.")
        st.markdown('</div>', unsafe_allow_html=True)

    with col_m2:
        st.markdown("""
        <div class="section-card">
            <div class="section-title">⚙️ Model Configuration</div>
            <div style="display:grid; gap:8px; font-size:0.83rem;">
                <div style="background:#0f172a; border-radius:8px; padding:10px 14px;
                            display:flex; justify-content:space-between;">
                    <span style="color:#64748b;">Algorithm</span>
                    <span style="color:#f8fafc; font-weight:600;">Random Forest</span>
                </div>
                <div style="background:#0f172a; border-radius:8px; padding:10px 14px;
                            display:flex; justify-content:space-between;">
                    <span style="color:#64748b;">Trees</span>
                    <span style="color:#f8fafc; font-weight:600;">200 estimators</span>
                </div>
                <div style="background:#0f172a; border-radius:8px; padding:10px 14px;
                            display:flex; justify-content:space-between;">
                    <span style="color:#64748b;">Class weight</span>
                    <span style="color:#f8fafc; font-weight:600;">balanced</span>
                </div>
                <div style="background:#0f172a; border-radius:8px; padding:10px 14px;
                            display:flex; justify-content:space-between;">
                    <span style="color:#64748b;">Decision threshold</span>
                    <span style="color:#f8fafc; font-weight:600;">0.5</span>
                </div>
                <div style="background:#0f172a; border-radius:8px; padding:10px 14px;
                            display:flex; justify-content:space-between;">
                    <span style="color:#64748b;">Features</span>
                    <span style="color:#f8fafc; font-weight:600;">15 engineered</span>
                </div>
                <div style="background:#0f172a; border-radius:8px; padding:10px 14px;
                            display:flex; justify-content:space-between;">
                    <span style="color:#64748b;">Training samples</span>
                    <span style="color:#f8fafc; font-weight:600;">61,065</span>
                </div>
                <div style="background:#0f172a; border-radius:8px; padding:10px 14px;
                            display:flex; justify-content:space-between;">
                    <span style="color:#64748b;">Dataset</span>
                    <span style="color:#f8fafc; font-weight:600;">CSIC 2010</span>
                </div>
                <div style="background:#0f172a; border-radius:8px; padding:10px 14px;
                            display:flex; justify-content:space-between;">
                    <span style="color:#64748b;">Scaler</span>
                    <span style="color:#f8fafc; font-weight:600;">StandardScaler</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # feature table
    st.markdown('<div class="section-card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">🔬 Feature Engineering (15 Features)</div>', unsafe_allow_html=True)
    features = pd.DataFrame([
        ("#1",  "method_is_post",      "Structural", "1 if POST request, 0 otherwise"),
        ("#2",  "url_length",          "Structural", "Total character length of the full URL"),
        ("#3",  "path_depth",          "Structural", "Number of / separators in the URL path"),
        ("#4",  "query_length",        "Structural", "Length of the query string"),
        ("#5",  "num_query_params",    "Structural", "Number of & separated query parameters"),
        ("#6",  "body_length",         "Structural", "Length of HTTP request body"),
        ("#7",  "num_body_params",     "Structural", "Number of key=value pairs in body"),
        ("#8",  "content_length",      "Structural", "Value of Content-Length header"),
        ("#9",  "has_cookie",          "Structural", "1 if Cookie header is present"),
        ("#10", "has_sql",             "Pattern",    "SQL keywords detected (regex)"),
        ("#11", "has_xss",             "Pattern",    "XSS patterns detected (regex)"),
        ("#12", "has_path_traversal",  "Pattern",    "../ or encoded equivalents detected"),
        ("#13", "has_cmd_injection",   "Pattern",    "Shell injection patterns ; | && detected"),
        ("#14", "has_null_byte",       "Pattern",    "%00 null byte detected"),
        ("#15", "special_char_count",  "Pattern",    "Count of < > ' \" ; ( ) = | characters"),
    ], columns=["#","Feature","Type","Description"])

    def style_features(row):
        bg = "#1a0f2e" if row["Type"] == "Pattern" else "#0f1a2e"
        return [f"background-color:{bg}; color:#f1f5f9"] * len(row)

    st.dataframe(
        features.style.apply(style_features, axis=1),
        use_container_width=True, hide_index=True,
    )
    st.markdown('</div>', unsafe_allow_html=True)


# ── auto-refresh ──────────────────────────────────────────────────────────────
if auto_refresh:
    time.sleep(5)
    st.cache_data.clear()
    st.rerun()
