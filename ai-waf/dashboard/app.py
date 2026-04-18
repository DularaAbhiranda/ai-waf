"""
dashboard/app.py  —  AI-WAF Live Dashboard
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

# ── minimal CSS (only overrides, no custom classes) ───────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 1rem 1.5rem 2rem 1.5rem !important; }
div[data-testid="metric-container"] {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 14px 18px;
}
div[data-testid="metric-container"] label { color: #94a3b8 !important; font-size: 0.75rem !important; }
div[data-testid="metric-container"] [data-testid="stMetricValue"] { color: #f8fafc !important; }
.stTabs [data-baseweb="tab-list"] {
    gap: 4px; background: #0f172a;
    border-radius: 10px; padding: 4px;
    border: 1px solid #334155;
}
.stTabs [data-baseweb="tab"] {
    border-radius: 8px; color: #94a3b8;
    font-weight: 600; font-size: 0.85rem; padding: 8px 20px;
}
.stTabs [aria-selected="true"] { background: #1e293b !important; color: #f8fafc !important; }
[data-testid="stSidebar"] { background: #0f172a; border-right: 1px solid #334155; }
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #1e293b; }
::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
</style>
""", unsafe_allow_html=True)

# ── chart theme ───────────────────────────────────────────────────────────────
DARK = dict(
    plot_bgcolor="#0f172a",
    paper_bgcolor="rgba(0,0,0,0)",
    font_color="#94a3b8",
    font_family="Inter",
    margin=dict(l=10, r=10, t=10, b=10),
    legend=dict(bgcolor="rgba(0,0,0,0)", bordercolor="#334155", borderwidth=1),
    xaxis=dict(gridcolor="#1e293b", linecolor="#334155"),
    yaxis=dict(gridcolor="#1e293b", linecolor="#334155"),
)

def dark(**kw):
    """Merge per-chart overrides into DARK theme safely."""
    d = {k: v for k, v in DARK.items()}
    if "legend" in kw:
        d["legend"] = {**DARK["legend"], **kw.pop("legend")}
    d.update(kw)
    return d

# ── card helper (inline style only — no custom CSS classes) ───────────────────
def card(content_fn, title=None):
    with st.container():
        st.markdown(
            '<div style="background:#1e293b;border:1px solid #334155;'
            'border-radius:14px;padding:18px 20px;margin-bottom:14px;">',
            unsafe_allow_html=True,
        )
        if title:
            st.markdown(
                f'<p style="font-size:0.78rem;font-weight:700;color:#64748b;'
                f'text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;">'
                f'{title}</p>',
                unsafe_allow_html=True,
            )
        content_fn()
        st.markdown("</div>", unsafe_allow_html=True)

# ── data loaders ──────────────────────────────────────────────────────────────
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
    except Exception:
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
        row["CV_F1_Mean"] = row.pop("cv_f1_mean", row.pop("CV_F1_Mean", 0))
        row["CV_F1_Std"]  = row.pop("cv_f1_std",  row.pop("CV_F1_Std",  0))
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

def classify_attack(url):
    u = str(url).lower()
    if any(k in u for k in ["select","union","drop","sleep(","or 1=1","'or'","1=1--","insert into"]):
        return "SQL Injection"
    if any(k in u for k in ["<script","onerror=","javascript:","alert(","document.cookie","onload="]):
        return "XSS"
    if any(k in u for k in ["../","..%2f","%2e%2e","..%5c","%252e"]):
        return "Path Traversal"
    if any(k in u for k in [";cat","|cat","&&","||","; ls","| ls","%3bcat","%7ccat","; whoami","| whoami"]):
        return "Command Injection"
    if "%00" in u or "\x00" in u:
        return "Null Byte"
    return "Other"


# ── sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ Controls")
    st.divider()
    auto_refresh = st.toggle("Auto-refresh every 5s", value=True)
    n_events     = st.slider("Max events to load", 50, 500, 200, 50)
    show_allowed = st.toggle("Show ALLOW events", value=True)
    show_blocked = st.toggle("Show BLOCK events", value=True)

    st.divider()
    st.markdown("### 🤖 Model Metrics")
    metrics = load_model_metrics()
    if metrics:
        st.metric("ROC-AUC",   f"{metrics.get('ROC-AUC',0):.4f}")
        st.metric("F1 Score",  f"{metrics.get('F1',0):.4f}")
        st.metric("Recall",    f"{metrics.get('Recall',0):.4f}")
        st.metric("Precision", f"{metrics.get('Precision',0):.4f}")
    else:
        st.info("Train model first.")

    st.divider()
    st.markdown("### 🛠️ Actions")
    if st.button("🗑️ Clear all events", use_container_width=True):
        try:
            from src.logger import clear_all
            clear_all(); st.cache_data.clear()
            st.success("Cleared.")
        except Exception as e:
            st.error(str(e))

    if st.button("⚡ Simulate 300 events", use_container_width=True):
        try:
            cwd = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            subprocess.Popen([sys.executable, "dashboard/simulate_traffic.py", "--n", "300"], cwd=cwd)
            st.info("Simulation started — refresh in ~5s")
        except Exception as e:
            st.error(str(e))

    st.divider()
    st.caption("Threshold 0.5 · RF 200 trees · CSIC 2010")


# ── header ────────────────────────────────────────────────────────────────────
stats = load_stats()
proxy_up = stats["total"] > 0

col_title, col_badge = st.columns([4, 1])
with col_title:
    st.markdown("## 🛡️ AI-WAF  —  Live Dashboard")
    st.caption("AI-Powered Web Application Firewall · Real-time HTTP traffic monitoring")
with col_badge:
    st.markdown("<br>", unsafe_allow_html=True)
    if proxy_up:
        st.success("🟢  Proxy Active")
    else:
        st.warning("🟡  Awaiting traffic")

st.divider()

# ── KPI row (native st.metric — no custom HTML) ───────────────────────────────
k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("📊 Total Requests",  f"{stats['total']:,}")
k2.metric("🚫 Blocked",         f"{stats['blocked']:,}",
          delta=f"+{stats['recent_blocked']} last 10 min", delta_color="inverse")
k3.metric("✅ Allowed",          f"{stats['allowed']:,}")
k4.metric("📈 Block Rate",       f"{stats.get('block_rate_pct',0):.1f}%")
k5.metric("⏱️ Recent (10 min)", f"{stats['recent_total']:,}")

st.divider()

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
        st.info("No events yet. Start the proxy or click **Simulate 300 events** in the sidebar.")
    else:
        acts = []
        if show_allowed: acts.append("ALLOW")
        if show_blocked: acts.append("BLOCK")
        df = df_all[df_all["action"].isin(acts)] if acts else df_all.iloc[0:0]

        # row 1 — timeline + pie
        col_a, col_b = st.columns([3, 1], gap="medium")
        with col_a:
            st.markdown("**📡 Requests Over Time**")
            df_t = df.copy()
            df_t["minute"] = df_t["timestamp"].dt.floor("1min")
            tl = df_t.groupby(["minute","action"]).size().reset_index(name="count")
            if not tl.empty:
                fig = px.area(tl, x="minute", y="count", color="action",
                              color_discrete_map={"ALLOW":"#4ade80","BLOCK":"#f87171"},
                              labels={"minute":"Time","count":"Requests","action":""},
                              line_shape="spline")
                fig.update_traces(opacity=0.75)
                fig.update_layout(**dark(height=250, showlegend=True))
                st.plotly_chart(fig, use_container_width=True)

        with col_b:
            st.markdown("**🥧 Traffic Split**")
            pie = df["action"].value_counts().reset_index()
            pie.columns = ["Action","Count"]
            if not pie.empty:
                fig_pie = px.pie(pie, names="Action", values="Count", hole=0.55,
                                 color="Action",
                                 color_discrete_map={"ALLOW":"#4ade80","BLOCK":"#f87171"})
                fig_pie.update_traces(textinfo="percent+label", textfont_size=12)
                fig_pie.update_layout(**dark(
                    height=250, showlegend=False,
                    xaxis=None, yaxis=None,
                ))
                st.plotly_chart(fig_pie, use_container_width=True)

        # row 2 — score histogram + method bar
        col_c, col_d = st.columns(2, gap="medium")
        with col_c:
            st.markdown("**🎯 ML Score Distribution**")
            fig_h = go.Figure()
            for action, color in [("ALLOW","#4ade80"),("BLOCK","#f87171")]:
                sub = df[df["action"]==action]["score"]
                if not sub.empty:
                    fig_h.add_trace(go.Histogram(x=sub, name=action, opacity=0.75,
                                                 marker_color=color, nbinsx=25))
            fig_h.add_vline(x=0.5, line_dash="dash", line_color="#cbd5e1", line_width=1.5,
                            annotation_text="Threshold 0.5", annotation_font_color="#cbd5e1",
                            annotation_font_size=11)
            fig_h.update_layout(**dark(barmode="overlay", height=250,
                                       xaxis_title="Score", yaxis_title="Count"))
            st.plotly_chart(fig_h, use_container_width=True)

        with col_d:
            st.markdown("**🔀 HTTP Method Breakdown**")
            mc = df.groupby(["method","action"]).size().reset_index(name="count")
            if not mc.empty:
                fig_m = px.bar(mc, x="method", y="count", color="action",
                               color_discrete_map={"ALLOW":"#4ade80","BLOCK":"#f87171"},
                               labels={"method":"Method","count":"Count","action":""},
                               barmode="group", text_auto=True)
                fig_m.update_traces(textfont_size=11, textposition="outside")
                fig_m.update_layout(**dark(height=250, showlegend=True))
                st.plotly_chart(fig_m, use_container_width=True)

        # events table
        st.markdown("**📋 Recent Events**")
        disp = df[["timestamp","method","url","score","action","client_ip"]].copy()
        disp["timestamp"] = disp["timestamp"].dt.strftime("%H:%M:%S")
        disp["score"]     = disp["score"].round(3)
        disp["url"]       = disp["url"].str[:90]
        disp["action"]    = disp["action"].apply(
            lambda x: "🚫 BLOCK" if x == "BLOCK" else "✅ ALLOW"
        )
        st.dataframe(disp, use_container_width=True, height=380, hide_index=True,
                     column_config={
                         "timestamp":  st.column_config.TextColumn("Time",      width="small"),
                         "method":     st.column_config.TextColumn("Method",    width="small"),
                         "url":        st.column_config.TextColumn("URL",       width="large"),
                         "score":      st.column_config.NumberColumn("Score",   width="small", format="%.3f"),
                         "action":     st.column_config.TextColumn("Decision",  width="small"),
                         "client_ip":  st.column_config.TextColumn("Client IP", width="small"),
                     })

        # top blocked IPs
        bips = (df[df["action"].str.contains("BLOCK")]["client_ip"]
                .value_counts().reset_index())
        bips.columns = ["IP Address","Block Count"]
        if not bips.empty and bips["IP Address"].iloc[0]:
            st.markdown("**🔴 Top Blocked IPs**")
            fig_ip = px.bar(bips.head(10), x="Block Count", y="IP Address",
                            orientation="h", color_discrete_sequence=["#f87171"],
                            text_auto=True)
            fig_ip.update_layout(**dark(height=max(180, len(bips.head(10)) * 36)))
            st.plotly_chart(fig_ip, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — ATTACK ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
with tab_attacks:
    df_all = load_events(n_events)

    if df_all.empty:
        st.info("No events to analyse yet. Click **Simulate 300 events** in the sidebar.")
    else:
        attacks = df_all[df_all["action"] == "BLOCK"].copy()
        normal  = df_all[df_all["action"] == "ALLOW"].copy()

        if not attacks.empty:
            attacks["attack_type"] = attacks["url"].apply(classify_attack)

        ACOLORS = {
            "SQL Injection":    "#f87171",
            "XSS":             "#fb923c",
            "Path Traversal":  "#fbbf24",
            "Command Injection":"#a78bfa",
            "Null Byte":       "#38bdf8",
            "Other":           "#94a3b8",
        }

        col1, col2 = st.columns(2, gap="medium")
        with col1:
            st.markdown("**⚔️ Attack Type Breakdown**")
            if not attacks.empty:
                tc = attacks["attack_type"].value_counts().reset_index()
                tc.columns = ["Attack Type","Count"]
                fig_t = px.bar(tc, x="Count", y="Attack Type", orientation="h",
                               color="Attack Type", color_discrete_map=ACOLORS,
                               text_auto=True)
                fig_t.update_layout(**dark(height=280, showlegend=False))
                st.plotly_chart(fig_t, use_container_width=True)
            else:
                st.success("No attacks in current window.")

        with col2:
            st.markdown("**📊 Score Distribution: Attack vs Normal**")
            fig_box = go.Figure()
            if not attacks.empty:
                fig_box.add_trace(go.Box(y=attacks["score"], name="Attacks",
                                         marker_color="#f87171", boxmean=True,
                                         line_color="#f87171"))
            if not normal.empty:
                fig_box.add_trace(go.Box(y=normal["score"], name="Normal",
                                         marker_color="#4ade80", boxmean=True,
                                         line_color="#4ade80"))
            fig_box.update_layout(**dark(height=280, yaxis_title="ML Score"))
            st.plotly_chart(fig_box, use_container_width=True)

        # Attack summary metrics
        if not attacks.empty:
            type_counts = attacks["attack_type"].value_counts()
            a1, a2, a3, a4 = st.columns(4)
            a1.metric("Total Attacks",      f"{len(attacks):,}")
            a2.metric("Avg Attack Score",   f"{attacks['score'].mean():.3f}")
            a3.metric("Max Score",          f"{attacks['score'].max():.3f}")
            a4.metric("Attack Types Found", f"{len(type_counts)}")

        st.divider()
        st.markdown("**🚫 Blocked Requests Detail**")
        if not attacks.empty:
            att_disp = attacks[["timestamp","method","url","score","attack_type","client_ip"]].copy()
            att_disp["timestamp"]   = att_disp["timestamp"].dt.strftime("%H:%M:%S")
            att_disp["score"]       = att_disp["score"].round(3)
            att_disp["url"]         = att_disp["url"].str[:85]
            att_disp["attack_type"] = att_disp["attack_type"].apply(
                lambda x: {"SQL Injection":"💉 SQL Injection","XSS":"🖥️ XSS",
                           "Path Traversal":"📂 Path Traversal",
                           "Command Injection":"⚡ Cmd Injection",
                           "Null Byte":"🔴 Null Byte","Other":"❓ Other"}.get(x, x)
            )
            st.dataframe(att_disp, use_container_width=True, height=380, hide_index=True,
                         column_config={
                             "timestamp":   st.column_config.TextColumn("Time",    width="small"),
                             "method":      st.column_config.TextColumn("Method",  width="small"),
                             "url":         st.column_config.TextColumn("URL",     width="large"),
                             "score":       st.column_config.NumberColumn("Score", width="small", format="%.3f"),
                             "attack_type": st.column_config.TextColumn("Type",   width="medium"),
                             "client_ip":   st.column_config.TextColumn("IP",     width="small"),
                         })
        else:
            st.success("No blocked requests in current view.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — AUTO-RETRAINING
# ══════════════════════════════════════════════════════════════════════════════
with tab_retrain:
    drift = load_drift_report()

    # Drift KPI row
    d1, d2, d3, d4 = st.columns(4)
    d1.metric("Drift Status",
              "⚠️ DRIFT" if drift.get("drift_detected") else "✅ Stable")
    d2.metric("Recent Avg Score",
              f"{drift.get('recent_avg_score',0):.3f}",
              delta=f"{drift.get('recent_avg_score',0)-drift.get('baseline_avg_score',0):+.3f} vs baseline")
    d3.metric("Recent Block Rate",
              f"{drift.get('recent_block_rate',0):.1%}",
              delta=f"{drift.get('recent_block_rate',0)-drift.get('baseline_block_rate',0):+.1%} vs baseline",
              delta_color="inverse")
    d4.metric("Recent Events (30 min)", f"{drift.get('recent_events',0):,}")

    st.divider()

    # Alerts
    alerts = drift.get("alerts", [])
    if alerts and drift.get("drift_detected"):
        for a in alerts:
            st.warning(f"⚠️ Drift alert: {a}")
    else:
        st.success("✅ No significant drift detected. Model is performing as expected.")

    st.divider()

    # Manual retrain + info
    col_btn, col_info = st.columns([1, 2], gap="medium")
    with col_btn:
        st.markdown("**🔄 Manual Retrain**")
        if st.button("🚀 Retrain Now", type="primary", use_container_width=True):
            with st.spinner("Retraining — this may take a minute..."):
                result = subprocess.run(
                    [sys.executable, "-m", "src.retrainer", "--now", "--force"],
                    capture_output=True, text=True
                )
                st.code(result.stdout[-2000:] if result.stdout else result.stderr[-2000:],
                        language="text")
                st.cache_data.clear()

    with col_info:
        st.info(
            f"**Every {RETRAIN_INTERVAL_HOURS}h** the daemon checks for model drift using:\n"
            f"- Score Z-score > 2.5 vs 5h baseline\n"
            f"- Block rate absolute diff > 15%\n\n"
            f"The new model is **only deployed if F1 ≥ old F1 − 0.5%**. "
            f"Old models are archived to `models/archive/`.\n\n"
            f"Start daemon: `python -m src.retrainer --daemon`"
        )

    st.divider()

    # F1 history chart + table
    retrain_df = load_retrain_log()
    if retrain_df.empty:
        st.info("No retrain history yet. Click **Retrain Now** above to create the first entry.")
    else:
        st.markdown("**📈 F1 Score Over Retrain History**")
        fig_f1 = go.Figure()
        fig_f1.add_trace(go.Scatter(
            x=retrain_df["timestamp"], y=retrain_df["old_f1"],
            name="Previous Model", line=dict(color="#64748b", dash="dot", width=2),
            mode="lines+markers", marker=dict(size=6),
        ))
        fig_f1.add_trace(go.Scatter(
            x=retrain_df["timestamp"], y=retrain_df["new_f1"],
            name="New Model", line=dict(color="#4ade80", width=2),
            mode="lines+markers", marker=dict(size=8),
            fill="tonexty", fillcolor="rgba(74,222,128,0.05)",
        ))
        fig_f1.update_layout(**dark(height=260,
                                    xaxis_title="Run Time", yaxis_title="F1 Score",
                                    yaxis=dict(range=[0.5,1.0], gridcolor="#1e293b")))
        st.plotly_chart(fig_f1, use_container_width=True)

        disp = retrain_df[["timestamp","rows_used","old_f1","new_f1",
                            "old_auc","new_auc","swapped"]].copy()
        disp["timestamp"] = disp["timestamp"].dt.strftime("%Y-%m-%d %H:%M")
        disp["swapped"]   = disp["swapped"].map({True:"✅ YES",False:"❌ No",1:"✅ YES",0:"❌ No"})
        st.dataframe(disp, use_container_width=True, hide_index=True)

    st.divider()

    # Archived models
    archive_dir = Path("models/archive")
    st.markdown("**🗄️ Archived Models**")
    if archive_dir.exists() and any(archive_dir.iterdir()):
        archives = sorted(archive_dir.iterdir(), reverse=True)
        for a in archives[:10]:
            files = ", ".join(f.name for f in a.iterdir())
            st.text(f"📦  {a.name}  —  {files}")
    else:
        st.info("No archived models yet. Archive is created on first retrain.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — MODEL INFO
# ══════════════════════════════════════════════════════════════════════════════
with tab_model:
    metrics = load_model_metrics()
    col_m1, col_m2 = st.columns(2, gap="medium")

    with col_m1:
        st.markdown("**📊 Performance Metrics**")
        if metrics:
            perf_items = [
                ("Accuracy",  "Accuracy",  "#818cf8"),
                ("Precision", "Precision", "#fb923c"),
                ("Recall",    "Recall",    "#4ade80"),
                ("F1 Score",  "F1",        "#38bdf8"),
                ("ROC-AUC",   "ROC-AUC",   "#a78bfa"),
            ]
            for label, key, color in perf_items:
                val = metrics.get(key, 0)
                pct = int(val * 100)
                st.markdown(
                    f'<div style="margin-bottom:10px;">'
                    f'<div style="display:flex;justify-content:space-between;'
                    f'margin-bottom:4px;">'
                    f'<span style="color:#94a3b8;font-size:0.82rem;">{label}</span>'
                    f'<span style="color:#f8fafc;font-weight:700;">{val:.4f}</span>'
                    f'</div>'
                    f'<div style="background:#0f172a;border-radius:4px;height:7px;">'
                    f'<div style="width:{pct}%;height:7px;border-radius:4px;'
                    f'background:{color};"></div></div></div>',
                    unsafe_allow_html=True,
                )
            cv = metrics.get("CV_F1_Mean", 0)
            cs = metrics.get("CV_F1_Std", 0)
            if cv:
                st.caption(f"5-fold CV F1: {cv:.4f} ± {cs:.4f}")
        else:
            st.info("Train model first: `python -m src.trainer`")

    with col_m2:
        st.markdown("**⚙️ Model Configuration**")
        cfg = pd.DataFrame([
            ("Algorithm",        "Random Forest"),
            ("Trees",            "200 estimators"),
            ("Class weight",     "balanced"),
            ("Threshold",        "0.5"),
            ("Features",         "15 engineered"),
            ("Training samples", "61,065"),
            ("Dataset",          "CSIC 2010"),
            ("Scaler",           "StandardScaler"),
            ("Cross-validation", "5-fold stratified"),
        ], columns=["Setting","Value"])
        st.dataframe(cfg, use_container_width=True, hide_index=True,
                     column_config={
                         "Setting": st.column_config.TextColumn(width="medium"),
                         "Value":   st.column_config.TextColumn(width="medium"),
                     })

    st.divider()
    st.markdown("**🔬 Feature Engineering — All 15 Features**")
    features = pd.DataFrame([
        ("#1",  "method_is_post",      "Structural", "1 if POST, 0 otherwise"),
        ("#2",  "url_length",          "Structural", "Total character length of URL"),
        ("#3",  "path_depth",          "Structural", "Count of / in URL path"),
        ("#4",  "query_length",        "Structural", "Length of query string"),
        ("#5",  "num_query_params",    "Structural", "Number of & separated params"),
        ("#6",  "body_length",         "Structural", "Length of request body"),
        ("#7",  "num_body_params",     "Structural", "Key=value pairs in body"),
        ("#8",  "content_length",      "Structural", "Content-Length header value"),
        ("#9",  "has_cookie",          "Structural", "1 if Cookie header present"),
        ("#10", "has_sql",             "🚨 Pattern",  "SQL keywords detected (regex)"),
        ("#11", "has_xss",             "🚨 Pattern",  "XSS patterns detected (regex)"),
        ("#12", "has_path_traversal",  "🚨 Pattern",  "../ or encoded equivalents"),
        ("#13", "has_cmd_injection",   "🚨 Pattern",  "; | && shell injection patterns"),
        ("#14", "has_null_byte",       "🚨 Pattern",  "%00 null byte detected"),
        ("#15", "special_char_count",  "🚨 Pattern",  "Count of < > ' \" ; ( ) = | chars"),
    ], columns=["#","Feature","Type","Description"])
    st.dataframe(features, use_container_width=True, hide_index=True,
                 column_config={
                     "#":           st.column_config.TextColumn(width="small"),
                     "Feature":     st.column_config.TextColumn(width="medium"),
                     "Type":        st.column_config.TextColumn(width="small"),
                     "Description": st.column_config.TextColumn(width="large"),
                 })


# ── auto-refresh ──────────────────────────────────────────────────────────────
if auto_refresh:
    time.sleep(5)
    st.cache_data.clear()
    st.rerun()
