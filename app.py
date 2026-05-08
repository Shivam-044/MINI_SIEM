"""
app.py  ─  SIEM WAR ROOM  (Streamlit  ·  Phase 4)
══════════════════════════════════════════════════════════════════════════════
High-tech "War Room" security dashboard.

Design language
───────────────
  Background  #0E1117  (near-black)
  Neon green  #39FF14  (phosphor CRT – success / live)
  Cyber red   #FF3131  (threat / failure)
  Amber       #FFB800  (warning)
  Cyan        #00FFFF  (info)
  Font        Share Tech Mono (body) + Orbitron (numbers / headers)

Install:
    pip install streamlit pandas plotly
    pip install streamlit-autorefresh      # optional – silent 5 s refresh

Run:
    streamlit run app.py
    streamlit run app.py -- --db data/siem_logs.db
══════════════════════════════════════════════════════════════════════════════
"""

import argparse
import os
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib  import Path
from typing   import Optional, Tuple

import pandas as pd
import streamlit as st

try:
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

try:
    from streamlit_autorefresh import st_autorefresh
    HAS_AUTOREFRESH = True
except ImportError:
    HAS_AUTOREFRESH = False


# ═════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_DB   = os.path.join("data", "siem_logs.db")
REFRESH_MS   = 5_000
TICKER_ROWS  = 20
CHART_HOURS  = 1
CHART_BIN    = "1min"
TOP_IP_LIMIT = 6

P = {
    "bg"    : "#0E1117",
    "bg2"   : "#0A0F0A",
    "panel" : "#0D1117",
    "card"  : "#0B150B",
    "border": "#1A2E1A",
    "green" : "#39FF14",
    "red"   : "#FF3131",
    "amber" : "#FFB800",
    "cyan"  : "#00FFFF",
    "violet": "#BF5FFF",
    "muted" : "#3D5C3D",
    "text"  : "#C8E6C8",
    "dim"   : "#1E3A1E",
}

SEVERITY_COLOR = {
    "CRITICAL": P["violet"],
    "HIGH"    : P["red"],
    "MEDIUM"  : P["amber"],
    "LOW"     : P["cyan"],
}

# ═════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ═════════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="SIEM WAR ROOM",
    page_icon="☢",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═════════════════════════════════════════════════════════════════════════════
# CSS
# ═════════════════════════════════════════════════════════════════════════════

st.markdown(r"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');

:root {
    --bg:       #0E1117; --bg2:    #0A0F0A; --card:   #0B150B;
    --border:   #1A2E1A; --dim:    #1E3A1E;
    --green:    #39FF14; --red:    #FF3131; --amber:  #FFB800;
    --cyan:     #00FFFF; --violet: #BF5FFF;
    --muted:    #3D5C3D; --text:   #C8E6C8;
    --glow-g:   0 0 8px #39FF14, 0 0 24px rgba(57,255,20,.25);
    --glow-r:   0 0 8px #FF3131, 0 0 24px rgba(255,49,49,.25);
    --glow-a:   0 0 8px #FFB800, 0 0 20px rgba(255,184,0,.2);
    --glow-c:   0 0 8px #00FFFF, 0 0 20px rgba(0,255,255,.15);
}

html, body, [class*="css"] {
    background-color: var(--bg) !important;
    color: var(--text) !important;
    font-family: 'Share Tech Mono','Courier New',monospace !important;
}
::-webkit-scrollbar { width:5px; height:5px; }
::-webkit-scrollbar-track { background:var(--bg2); }
::-webkit-scrollbar-thumb { background:var(--dim); border-radius:3px; }

.main .block-container {
    padding:1rem 1.5rem 3rem !important;
    max-width:1800px !important;
    background:var(--bg) !important;
}

/* grid overlay */
.main::after {
    content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
    background-image:
        linear-gradient(rgba(57,255,20,.025) 1px,transparent 1px),
        linear-gradient(90deg,rgba(57,255,20,.025) 1px,transparent 1px);
    background-size:44px 44px;
}

[data-testid="stSidebar"] {
    background:var(--bg2) !important;
    border-right:1px solid var(--border) !important;
}
[data-testid="stSidebar"] * { font-family:'Share Tech Mono',monospace !important; }

/* Metric card */
[data-testid="stMetric"] {
    background:var(--card) !important;
    border:1px solid var(--border) !important;
    border-top:2px solid var(--green) !important;
    border-radius:4px !important;
    padding:1.1rem 1.3rem !important;
    box-shadow:var(--glow-g),inset 0 0 30px rgba(57,255,20,.02) !important;
    position:relative; overflow:hidden;
}
[data-testid="stMetric"]::before {
    content:'';position:absolute;top:0;left:-100%;
    width:60%;height:1px;
    background:linear-gradient(90deg,transparent,var(--green),transparent);
    animation:scan 4s linear infinite;
}
@keyframes scan { 0%{left:-60%} 100%{left:160%} }
[data-testid="stMetricLabel"] {
    color:var(--muted) !important;
    font-size:.62rem !important;
    letter-spacing:.2em !important;
    text-transform:uppercase !important;
}
[data-testid="stMetricValue"] {
    font-family:'Orbitron',monospace !important;
    font-size:1.85rem !important; font-weight:900 !important;
    color:var(--green) !important;
    text-shadow:var(--glow-g) !important;
}

/* Section label */
.ws { font-size:.58rem; letter-spacing:.25em; text-transform:uppercase;
      color:var(--muted); border-bottom:1px solid var(--dim);
      padding-bottom:.25rem; margin:1.3rem 0 .6rem; }

/* Buttons */
.stButton>button {
    background:transparent !important;
    border:1px solid var(--green) !important;
    color:var(--green) !important;
    font-family:'Share Tech Mono',monospace !important;
    font-size:.72rem !important; letter-spacing:.12em !important;
    border-radius:2px !important; padding:.3rem 1rem !important;
    text-shadow:var(--glow-g) !important; transition:all .15s ease !important;
}
.stButton>button:hover {
    background:rgba(57,255,20,.08) !important;
    box-shadow:var(--glow-g) !important;
}

/* Terminal ticker */
.ticker {
    background:var(--bg2);
    border:1px solid var(--border); border-left:3px solid var(--green);
    border-radius:4px; padding:.75rem 1rem;
    font-family:'Share Tech Mono',monospace; font-size:.7rem; line-height:1.75;
    overflow-y:auto; max-height:300px;
    box-shadow:inset 0 0 40px rgba(0,0,0,.5), var(--glow-g);
}
.tl  { margin:0; white-space:pre; }
.tf  { color:var(--red);   text-shadow:0 0 5px rgba(255,49,49,.5); }
.tok { color:var(--green); text-shadow:0 0 5px rgba(57,255,20,.4); }
.tts { color:var(--muted); }
.ti  { color:var(--cyan);  }
.tc::after { content:'▮'; animation:blink 1s step-end infinite;
             color:var(--green); text-shadow:var(--glow-g); }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }

/* Alert cards */
.ac {
    background:var(--card); border:1px solid var(--dim);
    border-left:3px solid var(--red); border-radius:3px;
    padding:.5rem .75rem; margin-bottom:.45rem; font-size:.66rem; line-height:1.55;
}
.ac.critical { border-left-color:var(--violet); }
.ac.medium   { border-left-color:var(--amber);  }
.ac.low      { border-left-color:var(--cyan);   }
.at  { color:var(--muted); font-size:.58rem; }
.atp { color:var(--cyan); font-weight:700; letter-spacing:.08em; }
.ad  { color:var(--text); margin-top:.1rem; }

/* Pulse dot */
@keyframes pg { 0%,100%{opacity:1;box-shadow:0 0 4px var(--green),0 0 10px var(--green);} 50%{opacity:.35;box-shadow:none;} }
@keyframes pr { 0%,100%{opacity:1;box-shadow:0 0 4px var(--red),  0 0 10px var(--red);}   50%{opacity:.35;box-shadow:none;} }
.pd  { display:inline-block;width:8px;height:8px;background:var(--green);
       border-radius:50%;animation:pg 1.4s ease-in-out infinite;vertical-align:middle;margin-right:.4rem; }
.pd.r { background:var(--red); animation-name:pr; }

/* Header */
.wh { display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:.2rem; }
.wt { font-family:'Orbitron',monospace; font-size:1.55rem; font-weight:900;
      color:var(--green); letter-spacing:.12em; line-height:1;
      text-shadow:0 0 20px rgba(57,255,20,.6),0 0 50px rgba(57,255,20,.2); }
.ws2{ font-size:.6rem; color:var(--muted); letter-spacing:.18em; text-transform:uppercase; margin-top:.2rem; }
.wc { font-family:'Orbitron',monospace; font-size:.88rem; color:var(--green);
      text-shadow:var(--glow-g); letter-spacing:.1em; text-align:right; }
.wcs{ font-size:.53rem; color:var(--muted); letter-spacing:.12em; text-transform:uppercase;
      text-align:right; margin-top:.1rem; }

/* Pulse card (custom metric) */
.pc {
    background:var(--card); border:1px solid var(--border);
    border-radius:4px; padding:1.1rem 1.3rem;
    position:relative; overflow:hidden;
}
.pc-label { font-size:.62rem; letter-spacing:.2em; color:var(--muted); text-transform:uppercase; }
.pc-value { font-family:'Orbitron',monospace; font-size:1.65rem; font-weight:900; margin-top:.25rem; }
.pc-green { border-top:2px solid var(--green); box-shadow:var(--glow-g); }
.pc-green .pc-value { color:var(--green); text-shadow:var(--glow-g); }
.pc-red   { border-top:2px solid var(--red);   box-shadow:var(--glow-r); }
.pc-red   .pc-value { color:var(--red);   text-shadow:var(--glow-r); }
.pc-amber { border-top:2px solid var(--amber); box-shadow:var(--glow-a); }
.pc-amber .pc-value { color:var(--amber); text-shadow:var(--glow-a); }

/* Threat badge */
.tb { display:inline-block; font-family:'Orbitron',monospace; font-size:.68rem;
      font-weight:700; letter-spacing:.15em; padding:.2rem .65rem; border-radius:2px; margin-left:.4rem; }
.tb-low  { background:rgba(57,255,20,.1); color:var(--green); border:1px solid var(--green); box-shadow:var(--glow-g); }
.tb-mod  { background:rgba(255,184,0,.1); color:var(--amber); border:1px solid var(--amber); box-shadow:var(--glow-a); }
.tb-hi   { background:rgba(255,49,49,.1); color:var(--red);   border:1px solid var(--red);   box-shadow:var(--glow-r); }
.tb-crit { background:rgba(191,95,255,.1);color:var(--violet);border:1px solid var(--violet);}

[data-testid="stDataFrame"] {
    border:1px solid var(--border) !important; border-radius:4px !important;
    box-shadow:0 0 20px rgba(57,255,20,.03) !important;
}
hr { border-color:var(--dim) !important; margin:.5rem 0 .7rem !important; }

.stSelectbox>div>div { background:var(--card) !important; border:1px solid var(--border) !important; color:var(--text) !important; }
</style>
""", unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
# DATABASE
# ═════════════════════════════════════════════════════════════════════════════

def _db_path() -> str:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--db", default=DEFAULT_DB)
    args, _ = p.parse_known_args()
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

def get_metrics(conn) -> dict:
    df = qdf(conn, "SELECT status,COUNT(*) n FROM security_events GROUP BY status")
    f = int(df.loc[df.status=="FAILURE","n"].sum()) if not df.empty else 0
    s = int(df.loc[df.status=="SUCCESS","n"].sum()) if not df.empty else 0
    since60 = (datetime.now()-timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%S")
    c60 = qdf(conn,"SELECT COUNT(*) n FROM security_events WHERE timestamp>=?",(since60,))
    eps = round(int(c60["n"].iloc[0])/60,2) if not c60.empty else 0.0
    try:
        al  = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
        hi  = int(conn.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('HIGH','CRITICAL')").fetchone()[0])
    except Exception:
        al = hi = 0
    return {"total":f+s,"failed":f,"success":s,"eps":eps,"alerts":al,"hi_alts":hi}

def get_timeseries(conn) -> pd.DataFrame:
    since = (datetime.now()-timedelta(hours=CHART_HOURS)).strftime("%Y-%m-%dT%H:%M:%S")
    return qdf(conn,"SELECT timestamp,status FROM security_events WHERE timestamp>=? ORDER BY timestamp ASC",(since,))

def get_recent_events(conn, n: int = TICKER_ROWS) -> pd.DataFrame:
    return qdf(conn,f"SELECT timestamp,event_id,status,username,source_ip,workstation_name,logon_type,failure_reason FROM security_events ORDER BY id DESC LIMIT {n}")

def get_top_ips(conn) -> pd.DataFrame:
    return qdf(conn,f"SELECT source_ip,COUNT(*) n FROM security_events WHERE status='FAILURE' AND source_ip NOT IN ('-','localhost','unknown','') GROUP BY source_ip ORDER BY n DESC LIMIT {TOP_IP_LIMIT}")

def get_top_users(conn) -> pd.DataFrame:
    return qdf(conn,"SELECT username,COUNT(*) n FROM security_events WHERE status='FAILURE' AND username NOT IN ('-','') GROUP BY username ORDER BY n DESC LIMIT 6")

def get_recent_alerts(conn, n: int = 20) -> pd.DataFrame:
    try:
        return qdf(conn,f"SELECT * FROM alerts ORDER BY id DESC LIMIT {n}")
    except Exception:
        return pd.DataFrame()


# ═════════════════════════════════════════════════════════════════════════════
# THREAT LEVEL
# ═════════════════════════════════════════════════════════════════════════════

def threat_level(metrics: dict) -> Tuple[str,str,str]:
    hi = metrics["hi_alts"]
    if hi == 0: return "LOW",      "tb-low",  P["green"]
    if hi <  3: return "MODERATE", "tb-mod",  P["amber"]
    if hi <  8: return "HIGH",     "tb-hi",   P["red"]
    return             "CRITICAL", "tb-crit", P["violet"]


# ═════════════════════════════════════════════════════════════════════════════
# PLOTLY  ─  neon glow
# ═════════════════════════════════════════════════════════════════════════════

def _layout(h: int = 240) -> dict:
    return dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor ="rgba(10,15,10,.85)",
        font=dict(family="Share Tech Mono",size=10,color=P["muted"]),
        xaxis=dict(gridcolor=P["dim"],linecolor=P["border"],tickfont=dict(color=P["muted"],size=9),zeroline=False),
        yaxis=dict(gridcolor=P["dim"],linecolor=P["border"],tickfont=dict(color=P["muted"],size=9),zeroline=False),
        legend=dict(orientation="h",yanchor="bottom",y=1.02,xanchor="right",x=1,
                    font=dict(size=9,color=P["muted"]),bgcolor="rgba(0,0,0,0)"),
        margin=dict(l=38,r=12,t=12,b=32),
        height=h,hovermode="x unified",
        hoverlabel=dict(bgcolor="#0B150B",font_color=P["text"],
                        bordercolor=P["border"],font_family="Share Tech Mono"),
    )

def glow_traces(x, y, name: str, colour: str, fill: bool=True):
    out = []
    if fill:
        out.append(go.Scatter(x=x,y=y,name=name,mode="lines",
            line=dict(color="rgba(0,0,0,0)",width=0),
            fill="tozeroy",fillcolor=colour+"0C",showlegend=False,hoverinfo="skip"))
    out.append(go.Scatter(x=x,y=y,name=f"{name}_b2",mode="lines",
        line=dict(color=colour+"18",width=9),showlegend=False,hoverinfo="skip"))
    out.append(go.Scatter(x=x,y=y,name=f"{name}_b1",mode="lines",
        line=dict(color=colour+"45",width=4),showlegend=False,hoverinfo="skip"))
    out.append(go.Scatter(x=x,y=y,name=name,mode="lines+markers",
        line=dict(color=colour,width=1.5),
        marker=dict(size=3,color=colour),
        hovertemplate=f"<b>{name}</b>: %{{y}}<extra></extra>"))
    return out

def render_event_chart(conn):
    st.markdown('<div class="ws">⬡ Event Frequency · Last Hour</div>', unsafe_allow_html=True)
    df = get_timeseries(conn)
    if df.empty:
        st.markdown('<div style="color:#1E3A1E;text-align:center;padding:1.5rem;font-size:.72rem;letter-spacing:.1em;">NO DATA IN RANGE</div>', unsafe_allow_html=True)
        return
    df["timestamp"] = pd.to_datetime(df["timestamp"],errors="coerce")
    df = df.dropna(subset=["timestamp"]).set_index("timestamp")
    s = df[df.status=="SUCCESS"].resample(CHART_BIN).size().rename("SUCCESS")
    f = df[df.status=="FAILURE"].resample(CHART_BIN).size().rename("FAILURE")
    c = pd.concat([s,f],axis=1).fillna(0).reset_index()
    if not HAS_PLOTLY:
        st.line_chart(c.set_index("timestamp")[["SUCCESS","FAILURE"]],color=[P["green"],P["red"]])
        return
    fig = go.Figure()
    for t in glow_traces(c["timestamp"],c["SUCCESS"],"SUCCESS",P["green"]): fig.add_trace(t)
    for t in glow_traces(c["timestamp"],c["FAILURE"],"FAILURE",P["red"]):   fig.add_trace(t)
    fig.update_layout(**_layout(235))
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})

def render_ip_chart(conn):
    st.markdown('<div class="ws">⬡ Top Attacker IPs</div>', unsafe_allow_html=True)
    df = get_top_ips(conn)
    if df.empty:
        st.markdown('<div style="color:#1E3A1E;text-align:center;padding:1rem;font-size:.7rem;">NO FAILURE DATA</div>', unsafe_allow_html=True)
        return
    if not HAS_PLOTLY:
        st.bar_chart(df.set_index("source_ip")["n"]); return
    colours = [P["red"] if i==0 else P["amber"] if i==1 else P["muted"] for i in range(len(df))]
    fig = go.Figure(go.Bar(x=df["n"],y=df["source_ip"],orientation="h",
        marker_color=colours,marker_line_width=0,
        text=df["n"].astype(str),textposition="outside",
        textfont=dict(color=P["text"],family="Share Tech Mono",size=9)))
    fig.update_layout(**_layout(215),
        yaxis=dict(gridcolor="rgba(0,0,0,0)",linecolor=P["border"],tickfont=dict(color=P["text"],size=9)))
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})

def render_user_chart(conn):
    st.markdown('<div class="ws">⬡ Most Targeted Accounts</div>', unsafe_allow_html=True)
    df = get_top_users(conn)
    if df.empty: return
    if not HAS_PLOTLY:
        st.bar_chart(df.set_index("username")["n"]); return
    fig = go.Figure(go.Bar(x=df["username"],y=df["n"],marker_color=P["amber"],
        marker_line_width=0,text=df["n"].astype(str),textposition="outside",
        textfont=dict(color=P["text"],family="Share Tech Mono",size=9)))
    fig.update_layout(**_layout(195),yaxis_title="Failures")
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})


# ═════════════════════════════════════════════════════════════════════════════
# TERMINAL TICKER
# ═════════════════════════════════════════════════════════════════════════════

def render_ticker(conn):
    st.markdown('<div class="ws">⬡ Terminal Log Feed</div>', unsafe_allow_html=True)
    df = get_recent_events(conn, TICKER_ROWS)
    if df.empty:
        st.markdown('<div class="ticker"><p class="tl ti">&gt; AWAITING EVENTS...<span class="tc"></span></p></div>', unsafe_allow_html=True)
        return
    lines = []
    for _, r in df.iterrows():
        ts  = str(r.get("timestamp",""))[:19]
        eid = r.get("event_id","?")
        st_ = str(r.get("status",""))
        usr = str(r.get("username","-"))
        ip  = str(r.get("source_ip","-"))
        ws  = str(r.get("workstation_name","") or "")
        lt  = str(r.get("logon_type","") or "")
        re  = str(r.get("failure_reason","") or "")
        cls = "tf" if st_=="FAILURE" else "tok"
        icon= "✗" if st_=="FAILURE" else "✓"
        ws_ = f" WS={ws}" if ws not in ("-","","local") else ""
        re_ = f" REASON={re[:28]}" if re not in ("-","","None") else ""
        lines.append(
            f'<p class="tl"><span class="tts">[{ts}] EID:{eid} </span>'
            f'<span class="{cls}">[{icon} {st_}]</span>'
            f' USER={usr} IP={ip}{ws_} LOGON={lt}{re_}</p>'
        )
    lines.append('<p class="tl ti">&gt; MONITORING... <span class="tc"></span></p>')
    st.markdown(f'<div class="ticker">{"".join(lines)}</div>', unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
# PULSE METRICS
# ═════════════════════════════════════════════════════════════════════════════

def render_pulse_metrics(m: dict, tlabel: str, tcls: str, tcol: str):
    st.markdown('<div class="ws">⬡ Pulse Metrics</div>', unsafe_allow_html=True)
    c1,c2,c3,c4,c5 = st.columns(5, gap="small")

    with c1:
        st.markdown(f'<div class="pc pc-green"><div class="pc-label">Live Status</div>'
                    f'<div class="pc-value"><span class="pd"></span>ONLINE</div></div>',
                    unsafe_allow_html=True)
    with c2:
        st.metric("Total Events", f"{m['total']:,}")
    with c3:
        st.metric("Events / Sec", f"{m['eps']:.2f}")
    with c4:
        st.markdown(f'<div class="pc pc-red"><div class="pc-label">Failed Logins</div>'
                    f'<div class="pc-value">{m["failed"]:,}</div></div>',
                    unsafe_allow_html=True)
    with c5:
        dotcls = "r" if tlabel in ("HIGH","CRITICAL") else ""
        st.markdown(
            f'<div class="pc" style="border-top:2px solid {tcol};box-shadow:0 0 8px rgba(0,0,0,.4);">'
            f'<div class="pc-label">Threat Level</div>'
            f'<div class="pc-value" style="color:{tcol};text-shadow:0 0 8px {tcol};">'
            f'<span class="pd {dotcls}"></span>{tlabel}</div></div>',
            unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═════════════════════════════════════════════════════════════════════════════

def render_sidebar(conn, tlabel: str, tcls: str, m: dict):
    with st.sidebar:
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.78rem;'
                    'font-weight:700;color:#FF3131;text-shadow:0 0 8px #FF3131,'
                    '0 0 24px rgba(255,49,49,.25);letter-spacing:.12em;margin-bottom:.8rem;">'
                    '☢ ALERT FEED</div>', unsafe_allow_html=True)
        st.markdown(f'Threat: <span class="tb {tcls}">{tlabel}</span>', unsafe_allow_html=True)
        st.markdown("<hr>", unsafe_allow_html=True)

        df = get_recent_alerts(conn, 20)
        if df.empty:
            st.markdown('<div style="color:#1E3A1E;font-size:.68rem;text-align:center;'
                        'padding:.8rem;letter-spacing:.1em;">NO ALERTS STORED</div>',
                        unsafe_allow_html=True)
        else:
            hi = df[df["severity"].isin(["HIGH","CRITICAL"])]
            show = hi if not hi.empty else df.head(10)
            for _, r in show.iterrows():
                sev  = str(r.get("severity","LOW")).lower()
                cls  = sev if sev in ("critical","high","medium","low") else "low"
                ts   = str(r.get("timestamp",""))[:19]
                atp  = str(r.get("alert_type","-"))
                desc = str(r.get("description",""))
                short= desc[:88]+ ("…" if len(desc)>88 else "")
                st.markdown(f'<div class="ac {cls}"><div class="at">{ts}</div>'
                             f'<div class="atp">{atp} · {sev.upper()}</div>'
                             f'<div class="ad">{short}</div></div>',
                             unsafe_allow_html=True)

        st.markdown("<hr>", unsafe_allow_html=True)
        ca, cb = st.columns(2)
        with ca: st.metric("Alerts",     m["alerts"])
        with cb: st.metric("HIGH+CRIT",  m["hi_alts"])
        st.markdown("<hr>", unsafe_allow_html=True)
        st.markdown('<div style="font-size:.56rem;color:#1A2E1A;text-align:center;'
                    'letter-spacing:.1em;">SIEM WAR ROOM · PHASE 4<br>'
                    'ENGINE + COLLECTOR ACTIVE</div>', unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
# HEADER
# ═════════════════════════════════════════════════════════════════════════════

def render_header(db_path: str):
    now = datetime.now()
    st.markdown(f"""
    <div class="wh">
        <div>
            <div class="wt">☢ WAR ROOM</div>
            <div class="ws2"><span class="pd"></span>Security Information &amp; Event Management
            &nbsp;·&nbsp; {db_path}</div>
        </div>
        <div>
            <div class="wc">{now.strftime("%H:%M:%S")}</div>
            <div class="wcs">{now.strftime("%Y-%m-%d")} · LOCAL</div>
        </div>
    </div><hr>""", unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main():
    db_path = _db_path()

    if HAS_AUTOREFRESH:
        st_autorefresh(interval=REFRESH_MS, key="warroom_tick")

    conn = get_conn(db_path)
    m    = get_metrics(conn) if conn else {"total":0,"failed":0,"success":0,"eps":0.0,"alerts":0,"hi_alts":0}
    tlabel, tcls, tcol = threat_level(m)

    if conn:
        render_sidebar(conn, tlabel, tcls, m)
    else:
        with st.sidebar:
            st.error(f"DB not found:\n`{db_path}`")

    render_header(db_path)

    if conn is None:
        st.error(f"**Database not found:** `{os.path.abspath(db_path)}`\n\nRun `python collector.py` first.")
        return

    render_pulse_metrics(m, tlabel, tcls, tcol)

    col_chart, col_ip = st.columns([3,1], gap="medium")
    with col_chart: render_event_chart(conn)
    with col_ip:    render_ip_chart(conn)

    col_users, col_ticker = st.columns([1,2], gap="medium")
    with col_users:  render_user_chart(conn)
    with col_ticker: render_ticker(conn)

    if not HAS_AUTOREFRESH:
        st.markdown("---")
        c1,c2 = st.columns([1,5])
        with c1:
            if st.button("⟳  REFRESH"): st.rerun()
        with c2:
            st.markdown('<span style="font-size:.65rem;color:#1E3A1E;">'
                        'Install <code>streamlit-autorefresh</code> for silent 5s updates.</span>',
                        unsafe_allow_html=True)

    st.markdown(f'<div style="text-align:center;color:#1A2E1A;font-size:.55rem;'
                f'letter-spacing:.15em;margin-top:1.5rem;font-family:Share Tech Mono,monospace;">'
                f'SIEM WAR ROOM · PHASE 4 · {db_path} · REFRESH {REFRESH_MS//1000}s</div>',
                unsafe_allow_html=True)


if __name__ == "__main__":
    main()