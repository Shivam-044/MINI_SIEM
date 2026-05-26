"""
app.py  ─  Enterprise SOC Dashboard  (Streamlit · Phase 5)
══════════════════════════════════════════════════════════════════════════════
Professional Security Operations Center dashboard.

Design language
───────────────
  Aesthetic     Slate & Charcoal Glassmorphism — refined, muted, enterprise
  Background    #0E1117
  Cards         #161B22  with 1px #30363D border, 8px radius
  Text          #C9D1D9 (primary)  ·  #8B949E (muted)
  Accent Blue   #58A6FF  (info, metrics, charts)
  Alert Red     #F85149  (failures, critical)
  Success       #3FB950  (successes)
  Warning       #D29922  (medium severity)
  Font          DM Sans (UI) + DM Mono (log data)

Features
────────
  · st.tabs – Live Monitor / Security Analytics / System Logs
  · Sidebar filtering by username and event type
  · CSV export of filtered log data
  · System Health widget (CPU / Memory / Disk – simulated)
  · Plotly charts with muted professional palette
  · Auto-refresh every 5 seconds (streamlit-autorefresh or manual button)

Install:
    pip install streamlit pandas plotly
    pip install streamlit-autorefresh      # optional

Run:
    streamlit run app.py
    streamlit run app.py -- --db data/siem_logs.db
══════════════════════════════════════════════════════════════════════════════
"""

# ─────────────────────────────────────────────────────────────────────────────
# stdlib
# ─────────────────────────────────────────────────────────────────────────────
import argparse
import io
import math
import os
import random
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib  import Path
from typing   import Optional, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# third-party
# ─────────────────────────────────────────────────────────────────────────────
import pandas as pd
import streamlit as st

try:
    import plotly.graph_objects as go
    import plotly.express as px
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

try:
    from streamlit_autorefresh import st_autorefresh
    HAS_AUTOREFRESH = True
except ImportError:
    HAS_AUTOREFRESH = False


# ═════════════════════════════════════════════════════════════════════════════
# CONFIG
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_DB    = os.path.join("data", "siem_logs.db")
REFRESH_MS    = 5_000
CHART_HOURS   = 6
CHART_BIN     = "5min"
EVENTS_LIMIT  = 500    # max rows loaded for filtering
LOG_DISPLAY   = 50     # rows shown in System Logs tab

# ── Colour palette ────────────────────────────────────────────────────────────
P = {
    "bg"      : "#0E1117",
    "card"    : "#161B22",
    "card2"   : "#1C2128",
    "border"  : "#30363D",
    "border2" : "#21262D",
    "blue"    : "#58A6FF",
    "red"     : "#F85149",
    "green"   : "#3FB950",
    "amber"   : "#D29922",
    "violet"  : "#A371F7",
    "text"    : "#C9D1D9",
    "muted"   : "#8B949E",
    "dim"     : "#484F58",
}

SEVERITY_COLOR = {
    "CRITICAL": P["violet"],
    "HIGH"    : P["red"],
    "MEDIUM"  : P["amber"],
    "LOW"     : P["blue"],
}

STATUS_COLOR = {
    "SUCCESS": P["green"],
    "FAILURE": P["red"],
}


# ═════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ═════════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title            = "SOC Dashboard",
    page_icon             = "🔒",
    layout                = "wide",
    initial_sidebar_state = "expanded",
)


# ═════════════════════════════════════════════════════════════════════════════
# CSS  ─  Enterprise Glassmorphism
# ═════════════════════════════════════════════════════════════════════════════

st.markdown("""
<style>
/* ── Fonts ── */
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&family=DM+Mono:wght@300;400;500&display=swap');

/* ── Root ── */
:root {
    --bg:      #0E1117; --card:    #161B22; --card2:   #1C2128;
    --border:  #30363D; --border2: #21262D;
    --blue:    #58A6FF; --red:     #F85149; --green:   #3FB950;
    --amber:   #D29922; --violet:  #A371F7;
    --text:    #C9D1D9; --muted:   #8B949E; --dim:     #484F58;
    --radius:  8px;
    --glass:   rgba(255,255,255,0.03);
}

html, body, [class*="css"] {
    background-color: var(--bg) !important;
    color: var(--text) !important;
    font-family: 'DM Sans', 'Segoe UI', system-ui, sans-serif !important;
    -webkit-font-smoothing: antialiased !important;
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--dim); }

/* ── Main container ── */
.main .block-container {
    padding: 1.5rem 2rem 4rem !important;
    max-width: 1700px !important;
    background: var(--bg) !important;
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: var(--card) !important;
    border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] section { padding-top: 1rem !important; }

/* ── Metric cards ── */
[data-testid="stMetric"] {
    background: var(--card) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius) !important;
    padding: 1.25rem 1.5rem !important;
    backdrop-filter: blur(12px) !important;
    -webkit-backdrop-filter: blur(12px) !important;
    background-image: linear-gradient(135deg, var(--glass) 0%, transparent 100%) !important;
    transition: border-color 0.2s ease, box-shadow 0.2s ease !important;
}
[data-testid="stMetric"]:hover {
    border-color: var(--dim) !important;
    box-shadow: 0 4px 24px rgba(0,0,0,0.3) !important;
}
[data-testid="stMetricLabel"] p {
    color: var(--muted) !important;
    font-size: 0.7rem !important;
    font-weight: 500 !important;
    letter-spacing: 0.06em !important;
    text-transform: uppercase !important;
}
[data-testid="stMetricValue"] {
    font-family: 'DM Sans', sans-serif !important;
    font-size: 1.85rem !important;
    font-weight: 600 !important;
    color: var(--text) !important;
    letter-spacing: -0.02em !important;
}
[data-testid="stMetricDelta"] {
    font-size: 0.72rem !important;
}

/* ── Tabs ── */
[data-testid="stTabs"] [data-baseweb="tab-list"] {
    background: transparent !important;
    border-bottom: 1px solid var(--border) !important;
    gap: 0.25rem !important;
    padding-bottom: 0 !important;
}
[data-testid="stTabs"] [data-baseweb="tab"] {
    background: transparent !important;
    border: none !important;
    border-bottom: 2px solid transparent !important;
    color: var(--muted) !important;
    font-family: 'DM Sans', sans-serif !important;
    font-size: 0.82rem !important;
    font-weight: 500 !important;
    padding: 0.6rem 1.1rem !important;
    border-radius: 0 !important;
    transition: color 0.15s ease !important;
}
[data-testid="stTabs"] [data-baseweb="tab"]:hover {
    color: var(--text) !important;
    background: rgba(255,255,255,0.03) !important;
}
[data-testid="stTabs"] [aria-selected="true"] {
    color: var(--blue) !important;
    border-bottom-color: var(--blue) !important;
    background: transparent !important;
}
[data-testid="stTabs"] [data-baseweb="tab-panel"] {
    padding-top: 1.5rem !important;
}
/* Hide the underline indicator bar Streamlit adds */
[data-testid="stTabs"] [data-baseweb="tab-highlight"] { display: none !important; }

/* ── Buttons ── */
.stButton > button {
    background: var(--card) !important;
    border: 1px solid var(--border) !important;
    color: var(--text) !important;
    font-family: 'DM Sans', sans-serif !important;
    font-size: 0.8rem !important;
    font-weight: 500 !important;
    border-radius: 6px !important;
    padding: 0.4rem 1rem !important;
    transition: all 0.15s ease !important;
}
.stButton > button:hover {
    background: var(--card2) !important;
    border-color: var(--dim) !important;
    box-shadow: 0 2px 8px rgba(0,0,0,0.2) !important;
}
.stButton > button[kind="primary"] {
    background: var(--blue) !important;
    border-color: var(--blue) !important;
    color: #0E1117 !important;
}
.stButton > button[kind="primary"]:hover {
    opacity: 0.9 !important;
}

/* ── Download button ── */
[data-testid="stDownloadButton"] button {
    background: var(--card) !important;
    border: 1px solid var(--border) !important;
    color: var(--blue) !important;
    font-family: 'DM Sans', sans-serif !important;
    font-size: 0.8rem !important;
    font-weight: 500 !important;
    border-radius: 6px !important;
    padding: 0.4rem 1rem !important;
    transition: all 0.15s ease !important;
}
[data-testid="stDownloadButton"] button:hover {
    background: rgba(88,166,255,0.08) !important;
    border-color: var(--blue) !important;
}

/* ── Selectbox / multiselect ── */
[data-testid="stSelectbox"] > div > div,
[data-testid="stMultiSelect"] > div > div {
    background: var(--card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    color: var(--text) !important;
    font-family: 'DM Sans', sans-serif !important;
    font-size: 0.82rem !important;
}

/* ── Text input ── */
[data-testid="stTextInput"] > div > div > input {
    background: var(--card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    color: var(--text) !important;
    font-family: 'DM Sans', sans-serif !important;
    font-size: 0.82rem !important;
}
[data-testid="stTextInput"] > div > div > input:focus {
    border-color: var(--blue) !important;
    box-shadow: 0 0 0 3px rgba(88,166,255,0.1) !important;
}

/* ── Dataframe ── */
[data-testid="stDataFrame"] {
    border: 1px solid var(--border) !important;
    border-radius: var(--radius) !important;
}
.stDataFrame iframe { border-radius: var(--radius) !important; }

/* ── Horizontal rule ── */
hr { border-color: var(--border) !important; margin: 1rem 0 !important; }

/* ── Section header ── */
.sec-hdr {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin: 1.5rem 0 0.75rem;
}
.sec-title {
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--muted);
}

/* ── Glass card ── */
.glass-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1.25rem 1.5rem;
    backdrop-filter: blur(12px);
    background-image: linear-gradient(135deg, var(--glass) 0%, transparent 100%);
}
.glass-card + .glass-card { margin-top: 0.75rem; }

/* ── Stat pill ── */
.stat-pill {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    background: var(--card2);
    border: 1px solid var(--border2);
    border-radius: 20px;
    padding: 0.2rem 0.65rem;
    font-size: 0.7rem;
    font-weight: 500;
    color: var(--muted);
}
.stat-dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
}

/* ── Status badge ── */
.badge {
    display: inline-block;
    font-size: 0.65rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    padding: 0.15rem 0.55rem;
    border-radius: 4px;
}
.badge-success { background: rgba(63,185,80,0.12);  color: #3FB950; border: 1px solid rgba(63,185,80,0.25);  }
.badge-failure { background: rgba(248,81,73,0.12);  color: #F85149; border: 1px solid rgba(248,81,73,0.25);  }
.badge-high    { background: rgba(248,81,73,0.12);  color: #F85149; border: 1px solid rgba(248,81,73,0.25);  }
.badge-critical{ background: rgba(163,113,247,0.12);color: #A371F7; border: 1px solid rgba(163,113,247,0.25);}
.badge-medium  { background: rgba(210,153,34,0.12); color: #D29922; border: 1px solid rgba(210,153,34,0.25); }
.badge-low     { background: rgba(88,166,255,0.12); color: #58A6FF; border: 1px solid rgba(88,166,255,0.25); }

/* ── Alert card in sidebar ── */
.al-card {
    background: var(--card2);
    border: 1px solid var(--border2);
    border-left: 3px solid var(--red);
    border-radius: 6px;
    padding: 0.65rem 0.85rem;
    margin-bottom: 0.5rem;
    font-size: 0.72rem;
    line-height: 1.55;
}
.al-card.critical { border-left-color: var(--violet); }
.al-card.medium   { border-left-color: var(--amber);  }
.al-card.low      { border-left-color: var(--blue);   }
.al-meta  { color: var(--muted); font-size: 0.62rem; margin-bottom: 0.15rem; }
.al-type  { font-weight: 600; color: var(--blue); }
.al-desc  { color: var(--text); }

/* ── System health bar ── */
.health-bar-wrap { margin-bottom: 0.85rem; }
.health-label {
    display: flex;
    justify-content: space-between;
    font-size: 0.72rem;
    color: var(--muted);
    margin-bottom: 0.3rem;
}
.health-bar-bg {
    background: var(--border2);
    border-radius: 3px;
    height: 4px;
    overflow: hidden;
}
.health-bar-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.4s ease;
}

/* ── Log table (monospace) ── */
.log-table {
    font-family: 'DM Mono', 'Fira Code', monospace;
    font-size: 0.7rem;
    background: var(--card2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
}
.log-row {
    display: grid;
    grid-template-columns: 155px 50px 80px 130px 130px 1fr;
    gap: 0;
    padding: 0.45rem 0.85rem;
    border-bottom: 1px solid var(--border2);
    align-items: center;
    transition: background 0.1s ease;
}
.log-row:hover { background: var(--card); }
.log-row:last-child { border-bottom: none; }
.log-row.hdr {
    font-size: 0.62rem;
    font-weight: 600;
    color: var(--muted);
    letter-spacing: 0.06em;
    text-transform: uppercase;
    background: var(--card);
    border-bottom: 1px solid var(--border);
}
.log-row.fail { background: rgba(248,81,73,0.04); }
.log-ts   { color: var(--muted); font-size: 0.68rem; }
.log-eid  { color: var(--dim); }
.log-ip   { color: var(--blue); }
.log-user { color: var(--text); }

/* ── Dashboard header ── */
.dash-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 0 1rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 1.25rem;
}
.dash-title {
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--text);
    letter-spacing: -0.01em;
    display: flex;
    align-items: center;
    gap: 0.6rem;
}
.dash-subtitle {
    font-size: 0.72rem;
    color: var(--muted);
    margin-top: 0.2rem;
}
.live-chip {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    background: rgba(63,185,80,0.1);
    border: 1px solid rgba(63,185,80,0.25);
    border-radius: 20px;
    padding: 0.2rem 0.65rem;
    font-size: 0.65rem;
    font-weight: 600;
    color: #3FB950;
    letter-spacing: 0.04em;
}
@keyframes livepulse {
    0%,100% { opacity: 1; }
    50%      { opacity: 0.3; }
}
.live-chip-dot {
    width: 5px; height: 5px;
    background: #3FB950;
    border-radius: 50%;
    animation: livepulse 2s ease-in-out infinite;
}

/* ── Empty state ── */
.empty {
    text-align: center;
    padding: 3rem 1rem;
    color: var(--dim);
    font-size: 0.82rem;
}

/* ── Sidebar label ── */
.sb-section {
    font-size: 0.65rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 1rem 0 0.5rem;
}

/* ── Gauge ring (SVG-based health indicators) ── */
.gauge-row {
    display: flex;
    gap: 0.75rem;
    justify-content: space-around;
    margin-bottom: 0.5rem;
}
</style>
""", unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
# DATABASE
# ═════════════════════════════════════════════════════════════════════════════

def _db_path() -> str:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--db", default=DEFAULT_DB)
    args, _ = parser.parse_known_args()
    return args.db


@st.cache_resource
def get_conn(db_path: str) -> Optional[sqlite3.Connection]:
    if not Path(db_path).exists():
        return None
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def qdf(conn, sql: str, params: tuple = ()) -> pd.DataFrame:
    try:
        return pd.read_sql_query(sql, conn, params=params)
    except Exception:
        return pd.DataFrame()


# ── Data fetchers ─────────────────────────────────────────────────────────────

def fetch_metrics(conn) -> dict:
    df = qdf(conn, "SELECT status, COUNT(*) n FROM security_events GROUP BY status")
    failed  = int(df.loc[df.status == "FAILURE", "n"].sum()) if not df.empty else 0
    success = int(df.loc[df.status == "SUCCESS", "n"].sum()) if not df.empty else 0

    since60 = (datetime.now() - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%S")
    c60 = qdf(conn, "SELECT COUNT(*) n FROM security_events WHERE timestamp>=?", (since60,))
    eps = round(int(c60["n"].iloc[0]) / 60, 2) if not c60.empty else 0.0

    since24h = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
    new24 = qdf(conn, "SELECT COUNT(*) n FROM security_events WHERE timestamp>=?", (since24h,))
    today = int(new24["n"].iloc[0]) if not new24.empty else 0

    try:
        alerts  = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
        hi_alts = int(conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity IN ('HIGH','CRITICAL')"
        ).fetchone()[0])
    except Exception:
        alerts = hi_alts = 0

    return {
        "total": failed + success, "failed": failed, "success": success,
        "eps": eps, "today": today, "alerts": alerts, "hi_alts": hi_alts,
    }


def fetch_all_events(conn, limit: int = EVENTS_LIMIT) -> pd.DataFrame:
    return qdf(conn, f"""
        SELECT id, timestamp, event_id, status, username,
               source_ip, workstation_name, logon_type, failure_reason, domain
        FROM   security_events
        ORDER  BY id DESC LIMIT {limit}
    """)


def fetch_timeseries(conn, hours: int = CHART_HOURS) -> pd.DataFrame:
    since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    return qdf(conn,
        "SELECT timestamp, status FROM security_events WHERE timestamp>=? ORDER BY timestamp ASC",
        (since,))


def fetch_top_ips(conn, n: int = 8) -> pd.DataFrame:
    return qdf(conn, f"""
        SELECT source_ip, COUNT(*) n
        FROM   security_events
        WHERE  status='FAILURE' AND source_ip NOT IN ('-','localhost','unknown','')
        GROUP  BY source_ip ORDER BY n DESC LIMIT {n}
    """)


def fetch_top_users(conn, n: int = 8) -> pd.DataFrame:
    return qdf(conn, f"""
        SELECT username, COUNT(*) n
        FROM   security_events
        WHERE  status='FAILURE' AND username NOT IN ('-','')
        GROUP  BY username ORDER BY n DESC LIMIT {n}
    """)


def fetch_logon_type_dist(conn) -> pd.DataFrame:
    return qdf(conn, """
        SELECT logon_type, COUNT(*) n
        FROM   security_events
        WHERE  logon_type IS NOT NULL AND logon_type != ''
        GROUP  BY logon_type ORDER BY n DESC
    """)


def fetch_hourly_heatmap(conn) -> pd.DataFrame:
    """Events by hour-of-day × weekday (for heatmap)."""
    return qdf(conn, """
        SELECT
            CAST(strftime('%H', timestamp) AS INTEGER) AS hour,
            CAST(strftime('%w', timestamp) AS INTEGER) AS dow,
            COUNT(*) AS n
        FROM security_events
        WHERE status = 'FAILURE'
        GROUP BY hour, dow
    """)


def fetch_alerts(conn, n: int = 20) -> pd.DataFrame:
    try:
        return qdf(conn, f"SELECT * FROM alerts ORDER BY id DESC LIMIT {n}")
    except Exception:
        return pd.DataFrame()


def fetch_usernames(conn) -> list:
    df = qdf(conn, "SELECT DISTINCT username FROM security_events WHERE username != '-' ORDER BY username")
    return ["All"] + df["username"].tolist() if not df.empty else ["All"]


# ═════════════════════════════════════════════════════════════════════════════
# SYSTEM HEALTH  (mock / simulated)
# ═════════════════════════════════════════════════════════════════════════════

def get_system_health() -> dict:
    """
    Simulated system health metrics.
    In production, replace with psutil calls:
        import psutil
        return {
            "cpu":  psutil.cpu_percent(interval=0.1),
            "mem":  psutil.virtual_memory().percent,
            "disk": psutil.disk_usage('/').percent,
            "net_in":  psutil.net_io_counters().bytes_recv // (1024*1024),
            "net_out": psutil.net_io_counters().bytes_sent // (1024*1024),
        }
    """
    t = time.time()
    return {
        "cpu"     : 18 + 12 * abs(math.sin(t / 30)),
        "mem"     : 42 + 8  * abs(math.sin(t / 45 + 1)),
        "disk"    : 67 + 2  * abs(math.sin(t / 120 + 2)),
        "net_in"  : round(1.2 + 0.8 * abs(math.sin(t / 20)), 1),
        "net_out" : round(0.4 + 0.3 * abs(math.sin(t / 25 + 0.5)), 1),
        "collector": True,
        "engine"   : True,
        "db_ok"    : True,
    }


# ═════════════════════════════════════════════════════════════════════════════
# PLOTLY HELPERS
# ═════════════════════════════════════════════════════════════════════════════

_PLOTLY_BASE = dict(
    template      = "plotly_dark",
    paper_bgcolor = "rgba(0,0,0,0)",
    plot_bgcolor  = "rgba(28,33,40,0.6)",
    font          = dict(family="DM Sans", size=11, color=P["muted"]),
    margin        = dict(l=40, r=16, t=16, b=36),
    xaxis = dict(gridcolor=P["border2"], linecolor=P["border"], showgrid=True,
                 tickfont=dict(color=P["muted"], size=10), zeroline=False),
    yaxis = dict(gridcolor=P["border2"], linecolor=P["border"], showgrid=True,
                 tickfont=dict(color=P["muted"], size=10), zeroline=False),
    legend = dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1,
                  font=dict(size=10, color=P["muted"]), bgcolor="rgba(0,0,0,0)"),
    hoverlabel = dict(bgcolor=P["card"], font_color=P["text"],
                      bordercolor=P["border"], font_family="DM Sans"),
    hovermode = "x unified",
)


def plot_cfg():
    return {"displayModeBar": False, "responsive": True}


def render_event_timeseries(conn, h: int):
    df = fetch_timeseries(conn, h)
    if df.empty:
        st.markdown('<div class="empty">No events in selected time range</div>',
                    unsafe_allow_html=True)
        return

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"]).set_index("timestamp")

    bin_map = {1: "1min", 3: "5min", 6: "10min", 12: "30min", 24: "1h"}
    binn = bin_map.get(h, "30min")

    s = df[df.status == "SUCCESS"].resample(binn).size().rename("Successes")
    f = df[df.status == "FAILURE"].resample(binn).size().rename("Failures")
    c = pd.concat([s, f], axis=1).fillna(0).reset_index()

    if not HAS_PLOTLY:
        st.line_chart(c.set_index("timestamp")[["Successes", "Failures"]],
                      color=[P["green"], P["red"]])
        return

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=c["timestamp"], y=c["Successes"], name="Successes",
        mode="lines", line=dict(color=P["green"], width=1.5),
        fill="tozeroy", fillcolor="rgba(63,185,80,0.06)",
        hovertemplate="<b>Successes</b>: %{y}<extra></extra>",
    ))
    fig.add_trace(go.Scatter(
        x=c["timestamp"], y=c["Failures"], name="Failures",
        mode="lines", line=dict(color=P["red"], width=1.5),
        fill="tozeroy", fillcolor="rgba(248,81,73,0.06)",
        hovertemplate="<b>Failures</b>: %{y}<extra></extra>",
    ))
    fig.update_layout(**{**_PLOTLY_BASE, "height": 260})
    st.plotly_chart(fig, use_container_width=True, config=plot_cfg())


def render_top_ips_chart(conn):
    df = fetch_top_ips(conn)
    if df.empty:
        st.markdown('<div class="empty">No failure data yet</div>', unsafe_allow_html=True)
        return
    if not HAS_PLOTLY:
        st.bar_chart(df.set_index("source_ip")["n"]); return

    colours = [P["red"] if i == 0 else P["amber"] if i < 3 else P["blue"]
               for i in range(len(df))]
    fig = go.Figure(go.Bar(
        x=df["n"], y=df["source_ip"], orientation="h",
        marker_color=colours, marker_line_width=0,
        text=df["n"], textposition="outside",
        textfont=dict(color=P["muted"], size=10),
        hovertemplate="<b>%{y}</b>: %{x} failures<extra></extra>",
    ))
    fig.update_layout(**{
        **_PLOTLY_BASE, "height": 280,
        "yaxis": dict(gridcolor="rgba(0,0,0,0)", linecolor=P["border"],
                      tickfont=dict(color=P["text"], size=10)),
        "xaxis_title": "Failed Logon Count",
    })
    st.plotly_chart(fig, use_container_width=True, config=plot_cfg())


def render_logon_type_pie(conn):
    df = fetch_logon_type_dist(conn)
    if df.empty:
        st.markdown('<div class="empty">No data</div>', unsafe_allow_html=True)
        return
    if not HAS_PLOTLY:
        st.bar_chart(df.set_index("logon_type")["n"]); return

    palette = [P["blue"], P["green"], P["amber"], P["red"], P["violet"], P["muted"]]
    fig = go.Figure(go.Pie(
        labels=df["logon_type"], values=df["n"],
        marker=dict(colors=palette[:len(df)],
                    line=dict(color=P["border"], width=1)),
        textfont=dict(size=10, color=P["text"]),
        hovertemplate="<b>%{label}</b><br>%{value} events (%{percent})<extra></extra>",
        hole=0.45,
    ))
    fig.update_layout(**{
        **_PLOTLY_BASE, "height": 280,
        "showlegend": True,
        "legend": dict(font=dict(size=9, color=P["muted"]), bgcolor="rgba(0,0,0,0)",
                       orientation="v", x=1.05, y=0.5),
    })
    st.plotly_chart(fig, use_container_width=True, config=plot_cfg())


def render_top_users_chart(conn):
    df = fetch_top_users(conn)
    if df.empty:
        st.markdown('<div class="empty">No targeted accounts yet</div>', unsafe_allow_html=True)
        return
    if not HAS_PLOTLY:
        st.bar_chart(df.set_index("username")["n"]); return

    fig = go.Figure(go.Bar(
        x=df["username"], y=df["n"],
        marker_color=P["amber"], marker_line_width=0,
        text=df["n"], textposition="outside",
        textfont=dict(color=P["muted"], size=10),
        hovertemplate="<b>%{x}</b>: %{y} failures<extra></extra>",
    ))
    fig.update_layout(**{**_PLOTLY_BASE, "height": 260, "yaxis_title": "Failures"})
    st.plotly_chart(fig, use_container_width=True, config=plot_cfg())


def render_heatmap(conn):
    df = fetch_hourly_heatmap(conn)
    if df.empty or not HAS_PLOTLY:
        st.markdown('<div class="empty">Insufficient data for heatmap</div>',
                    unsafe_allow_html=True)
        return

    days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    pivot = df.pivot_table(index="hour", columns="dow", values="n", fill_value=0)
    pivot = pivot.reindex(columns=range(7), fill_value=0)

    fig = go.Figure(go.Heatmap(
        z=pivot.values,
        x=[days[d] for d in pivot.columns],
        y=[f"{h:02d}:00" for h in pivot.index],
        colorscale=[[0, P["card2"]], [0.5, P["amber"]], [1, P["red"]]],
        showscale=True,
        hovertemplate="Day: <b>%{x}</b><br>Hour: <b>%{y}</b><br>Failures: <b>%{z}</b><extra></extra>",
    ))
    fig.update_layout(**{
        **_PLOTLY_BASE, "height": 340,
        "yaxis": dict(autorange="reversed", tickfont=dict(color=P["muted"], size=9),
                      gridcolor=P["border2"]),
        "xaxis": dict(tickfont=dict(color=P["muted"], size=10), gridcolor=P["border2"]),
    })
    st.plotly_chart(fig, use_container_width=True, config=plot_cfg())


# ═════════════════════════════════════════════════════════════════════════════
# FILTERING
# ═════════════════════════════════════════════════════════════════════════════

def apply_filters(df: pd.DataFrame, username_filter: str,
                  status_filter: str) -> pd.DataFrame:
    if df.empty:
        return df
    if username_filter and username_filter != "All":
        df = df[df["username"] == username_filter]
    if status_filter and status_filter != "All":
        df = df[df["status"] == status_filter]
    return df


# ═════════════════════════════════════════════════════════════════════════════
# SYSTEM HEALTH WIDGET
# ═════════════════════════════════════════════════════════════════════════════

def _health_bar(label: str, pct: float, colour: str):
    bar_colour = colour
    pct_str = f"{pct:.0f}%"
    st.markdown(f"""
    <div class="health-bar-wrap">
        <div class="health-label">
            <span>{label}</span>
            <span style="color:{colour};font-weight:500;">{pct_str}</span>
        </div>
        <div class="health-bar-bg">
            <div class="health-bar-fill"
                 style="width:{min(pct,100):.0f}%;background:{bar_colour};"></div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_system_health():
    h = get_system_health()

    st.markdown('<div class="sb-section">System Health</div>', unsafe_allow_html=True)

    cpu_col  = P["green"] if h["cpu"]  < 60 else P["amber"] if h["cpu"]  < 85 else P["red"]
    mem_col  = P["green"] if h["mem"]  < 70 else P["amber"] if h["mem"]  < 90 else P["red"]
    disk_col = P["green"] if h["disk"] < 75 else P["amber"] if h["disk"] < 90 else P["red"]

    _health_bar("CPU",    h["cpu"],  cpu_col)
    _health_bar("Memory", h["mem"],  mem_col)
    _health_bar("Disk",   h["disk"], disk_col)

    # Service status pills
    services = [
        ("Collector", h["collector"], "ACTIVE"),
        ("Engine",    h["engine"],    "ACTIVE"),
        ("Database",  h["db_ok"],     "OK"),
    ]
    for name, ok, label in services:
        col  = P["green"] if ok else P["red"]
        status_txt = label if ok else "DOWN"
        st.markdown(f"""
        <div style="display:flex;justify-content:space-between;align-items:center;
                    margin-bottom:0.4rem;font-size:0.72rem;">
            <span style="color:var(--muted);">{name}</span>
            <span style="color:{col};font-weight:500;">● {status_txt}</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown(f"""
    <div style="display:flex;justify-content:space-between;margin-top:0.75rem;
                font-size:0.68rem;color:var(--muted);">
        <span>↓ {h['net_in']} MB/s</span>
        <span>↑ {h['net_out']} MB/s</span>
    </div>
    """, unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═════════════════════════════════════════════════════════════════════════════

def render_sidebar(conn, usernames: list) -> Tuple[str, str]:
    with st.sidebar:
        # Logo / title
        st.markdown("""
        <div style="display:flex;align-items:center;gap:0.6rem;
                    padding:0.25rem 0 1rem;border-bottom:1px solid #30363D;">
            <span style="font-size:1.2rem;">🔒</span>
            <div>
                <div style="font-size:0.9rem;font-weight:600;color:#C9D1D9;">SOC Dashboard</div>
                <div style="font-size:0.62rem;color:#8B949E;">Security Operations</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # ── Filters ──────────────────────────────────────────────────────────
        st.markdown('<div class="sb-section">Log Filters</div>', unsafe_allow_html=True)

        username_filter = st.selectbox(
            "Username",
            options=usernames,
            index=0,
            label_visibility="visible",
        )
        status_filter = st.selectbox(
            "Event Type",
            options=["All", "SUCCESS", "FAILURE"],
            index=0,
        )

        st.markdown("<hr>", unsafe_allow_html=True)

        # ── System health ─────────────────────────────────────────────────────
        render_system_health()

        st.markdown("<hr>", unsafe_allow_html=True)

        # ── Recent alerts ─────────────────────────────────────────────────────
        st.markdown('<div class="sb-section">Recent Alerts</div>', unsafe_allow_html=True)

        df_al = fetch_alerts(conn, 10) if conn else pd.DataFrame()
        if df_al.empty:
            st.markdown('<div style="color:#484F58;font-size:0.72rem;'
                        'text-align:center;padding:0.75rem;">No alerts stored</div>',
                        unsafe_allow_html=True)
        else:
            hi = df_al[df_al["severity"].isin(["HIGH", "CRITICAL"])]
            show = hi if not hi.empty else df_al.head(6)
            for _, row in show.iterrows():
                sev   = str(row.get("severity", "LOW")).lower()
                cls   = sev if sev in ("critical","high","medium","low") else "low"
                ts    = str(row.get("timestamp", ""))[:16]
                atype = str(row.get("alert_type", "-"))
                desc  = str(row.get("description", ""))
                short = desc[:72] + ("…" if len(desc) > 72 else "")
                st.markdown(f"""
                <div class="al-card {cls}">
                    <div class="al-meta">{ts} · <span class="al-type">{atype}</span>
                         · {sev.upper()}</div>
                    <div class="al-desc">{short}</div>
                </div>""", unsafe_allow_html=True)

        st.markdown("<hr>", unsafe_allow_html=True)
        st.markdown(
            f'<div style="font-size:0.6rem;color:#484F58;text-align:center;">'
            f'SOC Dashboard · Phase 5<br>Updated {datetime.now().strftime("%H:%M:%S")}</div>',
            unsafe_allow_html=True,
        )

    return username_filter, status_filter


# ═════════════════════════════════════════════════════════════════════════════
# HEADER
# ═════════════════════════════════════════════════════════════════════════════

def render_header(db_path: str, metrics: dict):
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    threat = "Normal"
    threat_col = P["green"]
    if metrics["hi_alts"] >= 8:
        threat, threat_col = "Critical", P["red"]
    elif metrics["hi_alts"] >= 3:
        threat, threat_col = "Elevated", P["amber"]
    elif metrics["hi_alts"] >= 1:
        threat, threat_col = "Guarded", P["blue"]

    st.markdown(f"""
    <div class="dash-header">
        <div>
            <div class="dash-title">
                Security Operations Center
                <span class="live-chip">
                    <span class="live-chip-dot"></span> LIVE
                </span>
            </div>
            <div class="dash-subtitle">{db_path} · {now}</div>
        </div>
        <div style="text-align:right;">
            <div style="font-size:0.7rem;color:var(--muted);margin-bottom:0.2rem;">
                Threat Posture
            </div>
            <div style="font-size:1rem;font-weight:600;color:{threat_col};">
                {threat}
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
# METRICS ROW
# ═════════════════════════════════════════════════════════════════════════════

def render_metrics(m: dict):
    c1, c2, c3, c4, c5, c6 = st.columns(6, gap="small")
    with c1: st.metric("Total Events",    f"{m['total']:,}")
    with c2: st.metric("Today's Events",  f"{m['today']:,}")
    with c3: st.metric("Successful",      f"{m['success']:,}",
                        delta=None, help="EID 4624")
    with c4: st.metric("Failed Logins",   f"{m['failed']:,}",
                        delta=f"{m['failed']} failures" if m['failed'] > 0 else None,
                        delta_color="inverse", help="EID 4625")
    with c5: st.metric("Events / Sec",    f"{m['eps']:.2f}")
    with c6: st.metric("Active Alerts",   f"{m['hi_alts']:,}",
                        help="HIGH + CRITICAL severity")


# ═════════════════════════════════════════════════════════════════════════════
# TABS
# ═════════════════════════════════════════════════════════════════════════════

def render_tab_live(conn, username_filter: str, status_filter: str):
    """Tab 1: Live Monitor — real-time event stream + quick chart."""
    # Time range selector
    col_range, col_spacer = st.columns([2, 5])
    with col_range:
        hours = st.selectbox(
            "Time window",
            options=[1, 3, 6, 12, 24],
            format_func=lambda x: f"Last {x}h",
            index=2,
            label_visibility="visible",
        )

    st.markdown('<div class="sec-title">Event Frequency</div>', unsafe_allow_html=True)
    render_event_timeseries(conn, hours)

    st.markdown('<div class="sec-title" style="margin-top:1.5rem;">Live Event Stream</div>',
                unsafe_allow_html=True)

    df = fetch_all_events(conn, EVENTS_LIMIT)
    df_filtered = apply_filters(df, username_filter, status_filter)

    if df_filtered.empty:
        st.markdown('<div class="empty">No events match the current filters</div>',
                    unsafe_allow_html=True)
        return

    # CSV export
    col_info, col_dl = st.columns([5, 1])
    with col_info:
        st.markdown(
            f'<div style="font-size:0.72rem;color:{P["muted"]};padding:0.4rem 0;">'
            f'Showing {len(df_filtered):,} events'
            + (f' · filtered from {len(df):,}' if len(df_filtered) < len(df) else '')
            + '</div>', unsafe_allow_html=True)
    with col_dl:
        csv_bytes = df_filtered.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="⬇ Export CSV",
            data=csv_bytes,
            file_name=f"siem_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    # Styled dataframe
    display = df_filtered[["timestamp", "event_id", "status", "username",
                            "source_ip", "workstation_name", "logon_type"]].copy()
    display.columns = ["Timestamp", "EID", "Status", "Username",
                        "Source IP", "Workstation", "Logon Type"]

    def _colour(row):
        base = [""] * len(display.columns)
        if row.get("Status") == "FAILURE":
            base[2] = f"color: {P['red']}; font-weight: 500"
        else:
            base[2] = f"color: {P['green']}; font-weight: 500"
        return base

    styled = display.style.apply(_colour, axis=1)
    st.dataframe(styled, use_container_width=True, hide_index=True, height=440,
                 column_config={
                     "EID": st.column_config.NumberColumn("EID", width="small"),
                     "Status": st.column_config.TextColumn("Status", width="small"),
                     "Timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                 })


def render_tab_analytics(conn):
    """Tab 2: Security Analytics — deeper charts."""
    st.markdown('<div class="sec-title">Attack Landscape</div>', unsafe_allow_html=True)

    col_a, col_b = st.columns(2, gap="medium")
    with col_a:
        st.markdown('<div style="font-size:0.7rem;color:#8B949E;margin-bottom:0.5rem;">'
                    'Top Attacker IPs</div>', unsafe_allow_html=True)
        render_top_ips_chart(conn)

    with col_b:
        st.markdown('<div style="font-size:0.7rem;color:#8B949E;margin-bottom:0.5rem;">'
                    'Most Targeted Accounts</div>', unsafe_allow_html=True)
        render_top_users_chart(conn)

    st.markdown('<div class="sec-title" style="margin-top:1rem;">Logon Patterns</div>',
                unsafe_allow_html=True)

    col_c, col_d = st.columns([1, 2], gap="medium")
    with col_c:
        st.markdown('<div style="font-size:0.7rem;color:#8B949E;margin-bottom:0.5rem;">'
                    'Logon Type Distribution</div>', unsafe_allow_html=True)
        render_logon_type_pie(conn)

    with col_d:
        st.markdown('<div style="font-size:0.7rem;color:#8B949E;margin-bottom:0.5rem;">'
                    'Failure Heatmap — Hour × Weekday</div>', unsafe_allow_html=True)
        render_heatmap(conn)

    # Alerts table
    st.markdown('<div class="sec-title" style="margin-top:1rem;">Alert History</div>',
                unsafe_allow_html=True)
    df_al = fetch_alerts(conn, 50)
    if df_al.empty:
        st.markdown('<div class="empty">No alerts in database</div>', unsafe_allow_html=True)
    else:
        display_cols = ["id", "timestamp", "alert_type", "severity", "description"]
        display_cols = [c for c in display_cols if c in df_al.columns]
        df_show = df_al[display_cols].copy()
        df_show.columns = [c.replace("_", " ").title() for c in display_cols]

        def _al_colour(row):
            base = [""] * len(df_show.columns)
            sev_col = SEVERITY_COLOR.get(str(row.get("Severity", "")).upper(), P["muted"])
            sev_idx = df_show.columns.tolist().index("Severity") if "Severity" in df_show.columns else -1
            if sev_idx >= 0:
                base[sev_idx] = f"color: {sev_col}; font-weight: 500"
            return base

        styled_al = df_show.style.apply(_al_colour, axis=1)
        st.dataframe(styled_al, use_container_width=True, hide_index=True, height=360)

        csv_al = df_al.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇ Export Alerts CSV", data=csv_al,
            file_name=f"siem_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )


def render_tab_logs(conn, username_filter: str, status_filter: str):
    """Tab 3: System Logs — raw monospace log view with export."""
    st.markdown('<div class="sec-title">Raw System Log</div>', unsafe_allow_html=True)

    df = fetch_all_events(conn, LOG_DISPLAY * 4)
    df_filtered = apply_filters(df, username_filter, status_filter)

    col_cnt, col_export = st.columns([4, 1])
    with col_cnt:
        st.markdown(
            f'<div style="font-size:0.72rem;color:{P["muted"]};padding:0.4rem 0;">'
            f'{len(df_filtered):,} records · monospace view</div>',
            unsafe_allow_html=True)
    with col_export:
        csv_bytes = df_filtered.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇ Download Logs",
            data=csv_bytes,
            file_name=f"siem_raw_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    if df_filtered.empty:
        st.markdown('<div class="empty">No logs match filters</div>', unsafe_allow_html=True)
        return

    # Render custom monospace log table
    rows_html = ["""
    <div class="log-table">
    <div class="log-row hdr">
        <span>Timestamp</span><span>EID</span><span>Status</span>
        <span>Username</span><span>Source IP</span><span>Logon Type / Reason</span>
    </div>"""]

    for _, r in df_filtered.head(LOG_DISPLAY).iterrows():
        ts   = str(r.get("timestamp", ""))[:19]
        eid  = str(r.get("event_id", ""))
        st_  = str(r.get("status", ""))
        usr  = str(r.get("username", "-"))
        ip   = str(r.get("source_ip", "-"))
        lt   = str(r.get("logon_type", "") or "")
        re   = str(r.get("failure_reason", "") or "")
        note = re[:38] if re not in ("-","","None") else lt

        st_col  = P["red"] if st_ == "FAILURE" else P["green"]
        row_cls = "fail" if st_ == "FAILURE" else ""
        ip_col  = P["blue"]

        rows_html.append(f"""
        <div class="log-row {row_cls}">
            <span class="log-ts">{ts}</span>
            <span class="log-eid">{eid}</span>
            <span style="color:{st_col};font-weight:500;">{st_}</span>
            <span class="log-user">{usr}</span>
            <span class="log-ip" style="color:{ip_col};">{ip}</span>
            <span style="color:var(--muted);">{note}</span>
        </div>""")

    rows_html.append("</div>")
    st.markdown("".join(rows_html), unsafe_allow_html=True)

    if len(df_filtered) > LOG_DISPLAY:
        st.markdown(
            f'<div style="font-size:0.68rem;color:{P["dim"]};'
            f'text-align:center;margin-top:0.5rem;">'
            f'Showing {LOG_DISPLAY} of {len(df_filtered)} records. '
            f'Export CSV to see all.</div>', unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main():
    db_path = _db_path()

    # ── Auto-refresh ──────────────────────────────────────────────────────────
    if HAS_AUTOREFRESH:
        st_autorefresh(interval=REFRESH_MS, key="soc_refresh")

    # ── Connection ────────────────────────────────────────────────────────────
    conn    = get_conn(db_path)
    metrics = fetch_metrics(conn) if conn else {
        "total":0,"failed":0,"success":0,"eps":0.0,
        "today":0,"alerts":0,"hi_alts":0,
    }
    usernames = fetch_usernames(conn) if conn else ["All"]

    # ── Sidebar ───────────────────────────────────────────────────────────────
    username_filter, status_filter = render_sidebar(conn, usernames)

    # ── Header ────────────────────────────────────────────────────────────────
    render_header(db_path, metrics)

    # ── DB missing ────────────────────────────────────────────────────────────
    if conn is None:
        st.error(
            f"**Database not found:** `{os.path.abspath(db_path)}`\n\n"
            "Run `python collector.py` first to create it."
        )
        return

    # ── Metric row ────────────────────────────────────────────────────────────
    render_metrics(metrics)

    st.markdown("<div style='height:1.25rem'></div>", unsafe_allow_html=True)

    # ── Tabs ──────────────────────────────────────────────────────────────────
    tab_live, tab_analytics, tab_logs = st.tabs([
        "📡  Live Monitor",
        "📊  Security Analytics",
        "📄  System Logs",
    ])

    with tab_live:
        render_tab_live(conn, username_filter, status_filter)

    with tab_analytics:
        render_tab_analytics(conn)

    with tab_logs:
        render_tab_logs(conn, username_filter, status_filter)

    # ── Manual refresh fallback ───────────────────────────────────────────────
    if not HAS_AUTOREFRESH:
        st.markdown("---")
        col_btn, col_hint = st.columns([1, 5])
        with col_btn:
            if st.button("↺  Refresh"):
                st.rerun()
        with col_hint:
            st.markdown(
                f'<span style="font-size:0.7rem;color:{P["muted"]};">'
                'Install <code>streamlit-autorefresh</code> for silent 5s live updates.</span>',
                unsafe_allow_html=True)

    # ── Footer ────────────────────────────────────────────────────────────────
    st.markdown(
        f'<div style="text-align:center;color:{P["dim"]};font-size:0.62rem;'
        f'margin-top:2.5rem;letter-spacing:0.06em;">'
        f'SOC Dashboard · {db_path} · Auto-refresh {REFRESH_MS//1000}s</div>',
        unsafe_allow_html=True)


if __name__ == "__main__":
    main()