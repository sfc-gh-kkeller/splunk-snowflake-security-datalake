#!/usr/bin/env python3
"""
Splunk + Snowflake Federated Search Demo
=========================================
Simulates the Splunk DB Connect federated search experience.
Runs live queries against CTF.PUBLIC.* tables in Snowflake.
"""

import re
import time
import random
import hashlib
import streamlit as st
import pandas as pd
import altair as alt

st.set_page_config(page_title="DataVault + Snowflake | Search & Reporting", layout="wide")

# ---------------------------------------------------------------------------
# Snowflake session
# ---------------------------------------------------------------------------
try:
    _conn = st.connection("snowflake")
    def run_query(sql):
        t0 = time.time()
        return _conn.query(sql), time.time() - t0
except Exception:
    from snowflake.snowpark.context import get_active_session
    _session = get_active_session()
    def run_query(sql):
        t0 = time.time()
        return _session.sql(sql).to_pandas(), time.time() - t0

# ---------------------------------------------------------------------------
# Splunk-authentic CSS
# ---------------------------------------------------------------------------
st.markdown("""
<style>
/* --- Splunk color tokens --- */
:root {
    --splunk-bg: #111215;
    --splunk-panel: #171D21;
    --splunk-border: #2B2F35;
    --splunk-text: #C3CBD4;
    --splunk-green: #65A637;
    --splunk-cyan: #5CC0DE;
    --splunk-red: #D94E17;
    --splunk-yellow: #F8BE34;
    --splunk-nav: #000000;
}

/* --- Top Nav Bar --- */
.splunk-nav {
    background: var(--splunk-nav);
    padding: 8px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 2px solid var(--splunk-border);
    margin: -1rem -1rem 1rem -1rem;
    font-family: 'Splunk Platform Sans', 'Helvetica Neue', Arial, sans-serif;
}
.splunk-logo {
    font-size: 26px;
    font-weight: 700;
    color: #FFFFFF;
    letter-spacing: -0.5px;
}
.splunk-logo span { color: var(--splunk-green); font-size: 30px; }
.splunk-nav-app {
    font-size: 13px;
    color: #9DA8B5;
    margin-left: 24px;
    padding: 4px 12px;
    border-left: 1px solid var(--splunk-border);
}
.splunk-nav-right {
    display: flex;
    align-items: center;
    gap: 16px;
    font-size: 12px;
    color: #9DA8B5;
}
.splunk-conn-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--splunk-green);
    margin-right: 6px;
}

/* --- Metric Cards --- */
[data-testid="stMetric"] {
    background: var(--splunk-panel);
    border: 1px solid var(--splunk-border);
    border-radius: 4px;
    padding: 16px;
}

/* --- Search bar (green SPL bar) --- */
.search-bar {
    background: var(--splunk-green);
    padding: 10px 16px;
    border-radius: 4px 4px 0 0;
    margin-bottom: 0;
    font-family: 'Courier New', monospace;
    font-size: 13px;
    color: #000;
    word-break: break-all;
    line-height: 1.4;
}
.search-bar .spl-pipe { color: #553F00; font-weight: 700; }
.search-bar .spl-cmd { color: #1A237E; font-weight: 700; }
.search-bar .spl-str { color: #1B5E20; }

/* --- Result tabs bar --- */
.result-tabs {
    display: flex;
    background: #1E2328;
    border-bottom: 2px solid var(--splunk-border);
    margin-bottom: 12px;
}
.result-tab {
    padding: 8px 20px;
    font-size: 13px;
    color: #9DA8B5;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    margin-bottom: -2px;
}
.result-tab.active {
    color: #FFFFFF;
    border-bottom: 2px solid var(--splunk-green);
    background: var(--splunk-panel);
}

/* --- Job Inspector --- */
.ji {
    background: var(--splunk-panel);
    border: 1px solid var(--splunk-border);
    border-radius: 4px;
    padding: 16px;
    font-family: 'Courier New', monospace;
    font-size: 13px;
}
.ji .hl { color: var(--splunk-green); font-weight: bold; }
.ji .cy { color: var(--splunk-cyan); }
.ji .warn { color: var(--splunk-yellow); }
.ji-header {
    font-size: 14px;
    font-weight: 600;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--splunk-border);
    margin-bottom: 12px;
}
.ji-sid {
    color: #6C7A89;
    font-size: 11px;
    float: right;
}

/* --- Info banner --- */
.ib {
    background: linear-gradient(135deg, #1A2E1A 0%, var(--splunk-panel) 100%);
    border: 1px solid var(--splunk-green);
    border-radius: 4px;
    padding: 12px 20px;
    margin-bottom: 16px;
}
.ib strong { color: var(--splunk-green); }

/* --- Panel header --- */
.ph {
    background: var(--splunk-panel);
    border: 1px solid var(--splunk-border);
    border-radius: 4px 4px 0 0;
    padding: 10px 16px;
    font-weight: 600;
    font-size: 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.ph-badge {
    font-size: 10px;
    background: var(--splunk-green);
    color: #000;
    padding: 2px 8px;
    border-radius: 3px;
    font-weight: 600;
}

/* --- Step boxes (flow tab) --- */
.sb {
    background: var(--splunk-panel);
    border: 1px solid var(--splunk-border);
    border-radius: 4px;
    padding: 20px;
    margin-bottom: 16px;
}
.sn {
    display: inline-block;
    background: var(--splunk-green);
    color: #000;
    border-radius: 50%;
    width: 28px;
    height: 28px;
    text-align: center;
    line-height: 28px;
    font-weight: bold;
    margin-right: 10px;
}

/* --- Timeline bar --- */
.timeline-bar {
    background: var(--splunk-panel);
    border: 1px solid var(--splunk-border);
    border-radius: 0;
    padding: 8px 16px;
    margin-bottom: 0;
    display: flex;
    align-items: flex-end;
    gap: 1px;
    height: 60px;
}
.timeline-bar-segment {
    background: var(--splunk-green);
    opacity: 0.7;
    flex: 1;
    min-width: 2px;
    border-radius: 1px 1px 0 0;
}

/* --- Status bar under search --- */
.status-bar {
    background: #1E2328;
    padding: 6px 16px;
    font-size: 12px;
    color: #9DA8B5;
    display: flex;
    justify-content: space-between;
    border: 1px solid var(--splunk-border);
    border-top: none;
}
.status-bar .count { color: #FFFFFF; font-weight: 600; }

/* --- Compare table --- */
.compare-tbl td, .compare-tbl th {
    padding: 8px 12px;
    font-size: 13px;
}
.compare-tbl th {
    border-bottom: 2px solid var(--splunk-border);
    text-align: left;
}
.compare-tbl tr:nth-child(even) { background: rgba(255,255,255,0.02); }

/* --- Alert & Actions --- */
.alert-card {
    background: var(--splunk-panel);
    border: 1px solid var(--splunk-border);
    border-left: 4px solid var(--splunk-red);
    border-radius: 4px;
    padding: 16px;
    margin-bottom: 12px;
}
.alert-card.severity-high { border-left-color: var(--splunk-red); }
.alert-card.severity-medium { border-left-color: var(--splunk-yellow); }
.alert-card.severity-info { border-left-color: var(--splunk-cyan); }
.alert-badge {
    display: inline-block;
    font-size: 10px;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 3px;
    margin-right: 8px;
}
.alert-badge.triggered { background: var(--splunk-red); color: #fff; }
.alert-badge.resolved { background: var(--splunk-green); color: #000; }
.alert-badge.pending { background: var(--splunk-yellow); color: #000; }
.action-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 6px 0;
    font-size: 13px;
    border-bottom: 1px solid rgba(43,47,53,0.5);
}
.action-icon {
    font-size: 16px;
    width: 24px;
    text-align: center;
}
.action-status {
    font-size: 11px;
    padding: 2px 6px;
    border-radius: 3px;
    margin-left: auto;
}
.action-status.sent { background: rgba(101,166,55,0.2); color: var(--splunk-green); }
.action-status.queued { background: rgba(248,190,52,0.2); color: var(--splunk-yellow); }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def show_df(df):
    try:
        st.dataframe(df, use_container_width=True, hide_index=True)
    except TypeError:
        st.dataframe(df)

def gen_sid():
    ts = str(time.time())
    return f"1{hashlib.md5(ts.encode()).hexdigest()[:9]}.{random.randint(100,999)}"

def job_inspector(n, dur, scanned, sql=""):
    sid = gen_sid()
    eval_time = round(dur * 0.05, 3)
    fetch_time = round(dur * 0.08, 3)
    dbx_time = round(dur * 0.82, 3)
    stream_time = round(dur * 0.05, 3)
    scan_rate = int(scanned / dur) if dur > 0 else 0
    st.markdown(f"""
<div class="ji">
<div class="ji-header">
    Search Job Inspector
    <span class="ji-sid">SID: {sid}</span>
</div>

<table style="width:100%;font-size:13px;margin-bottom:12px">
<tr><td style="padding:4px 8px;width:50%">Result count: <strong>{n:,}</strong></td>
    <td style="padding:4px 8px">Scan count: <span class="hl" style="font-size:15px">0 events</span></td></tr>
<tr><td style="padding:4px 8px">Run duration: <strong>{dur:.2f}s</strong></td>
    <td style="padding:4px 8px">Snowflake rows scanned: <span class="cy">{scanned:,}</span></td></tr>
<tr><td style="padding:4px 8px">Scan rate: <span class="cy">{scan_rate:,} rows/sec</span> (Snowflake)</td>
    <td style="padding:4px 8px">Result is <span class="hl">not</span> from cache</td></tr>
</table>

<strong>Execution Cost (seconds)</strong>
<hr style="border-color:#2B2F35;margin:6px 0">
<table style="width:100%;font-size:13px">
<tr style="border-bottom:1px solid #2B2F35">
    <td style="padding:4px 8px"><strong>Component</strong></td>
    <td style="padding:4px 8px"><strong>Invocations</strong></td>
    <td style="padding:4px 8px"><strong>Input (count)</strong></td>
    <td style="padding:4px 8px"><strong>Output (count)</strong></td>
    <td style="padding:4px 8px"><strong>Duration</strong></td>
</tr>
<tr><td style="padding:4px 8px">dispatch.createProviderContext</td><td style="padding:4px 8px">1</td><td style="padding:4px 8px">-</td><td style="padding:4px 8px">-</td><td style="padding:4px 8px">0.001s</td></tr>
<tr><td style="padding:4px 8px">dispatch.evaluate</td><td style="padding:4px 8px">1</td><td style="padding:4px 8px">-</td><td style="padding:4px 8px">-</td><td style="padding:4px 8px">{eval_time:.3f}s</td></tr>
<tr><td style="padding:4px 8px">dispatch.fetch</td><td style="padding:4px 8px">1</td><td style="padding:4px 8px">0</td><td style="padding:4px 8px">{n:,}</td><td style="padding:4px 8px">{fetch_time:.3f}s</td></tr>
<tr style="background:rgba(101,166,55,0.08)"><td style="padding:4px 8px"><strong>command.dbxquery</strong></td><td style="padding:4px 8px">1</td><td style="padding:4px 8px">0</td><td style="padding:4px 8px"><span class="hl">{n:,}</span></td><td style="padding:4px 8px"><span class="hl">{dbx_time:.3f}s</span></td></tr>
<tr><td style="padding:4px 8px">dispatch.stream.local</td><td style="padding:4px 8px">1</td><td style="padding:4px 8px">{n:,}</td><td style="padding:4px 8px">{n:,}</td><td style="padding:4px 8px">{stream_time:.3f}s</td></tr>
</table>
<br>
<span class="hl">KEY INSIGHT:</span> Splunk scanned <span class="hl" style="font-size:15px">0 local events</span>.
All compute pushed to Snowflake ({scanned:,} rows). Only <span class="cy">{n}</span> aggregated result{"s" if n!=1 else ""} returned to Splunk.
</div>""", unsafe_allow_html=True)

def extract_sql(spl):
    spl = spl.strip()
    m = re.search(r'query\s*=\s*"(.*)"', spl, re.DOTALL | re.IGNORECASE)
    if m: return m.group(1)
    m = re.search(r"query\s*=\s*'(.*)'", spl, re.DOTALL | re.IGNORECASE)
    if m: return m.group(1)
    if spl.upper().lstrip().startswith(("SELECT","WITH","SHOW","DESCRIBE")):
        return spl
    return None

def estimate_rows(sql):
    u = sql.upper()
    r = 0
    if "ACCESS_LOGS" in u: r += 100000
    if "VULNERABILITIES" in u: r += 15000
    if "ASSET_INVENTORY" in u: r += 844
    if "SECURITY_FINDINGS" in u: r += 106
    return r or 1

def highlight_spl(spl):
    """Highlight SPL syntax for display in the green search bar."""
    esc = spl.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    esc = re.sub(r'(\|)', r'<span class="spl-pipe">\1</span>', esc)
    for cmd in ["dbxquery","stats","table","chart","eval","where","search","fields","head","tail","sort","top","rare","timechart","transaction","lookup","collect"]:
        esc = re.sub(rf'\b({cmd})\b', rf'<span class="spl-cmd">\1</span>', esc, flags=re.IGNORECASE)
    esc = re.sub(r'(".*?")', r'<span class="spl-str">\1</span>', esc)
    return esc

def render_search_bar(spl_text):
    """Render SPL in a Splunk-style green search bar."""
    st.markdown(f'<div class="search-bar">{highlight_spl(spl_text)}</div>', unsafe_allow_html=True)

def render_timeline(n_results, dur):
    """Render a fake Splunk-style event timeline bar chart."""
    n_bars = 30
    heights = []
    for i in range(n_bars):
        base = max(10, int(100 * (0.5 + 0.5 * (1 - abs(i - n_bars//2) / (n_bars//2)))))
        heights.append(base + random.randint(-15, 15))
    max_h = max(heights)
    bars = "".join(
        f'<div class="timeline-bar-segment" style="height:{int(40*h/max_h)}px" '
        f'title="{int(n_results*h/sum(heights))} events"></div>'
        for h in heights
    )
    st.markdown(
        f'<div class="timeline-bar">{bars}</div>'
        f'<div class="status-bar">'
        f'<span><span class="count">{n_results:,}</span> results &nbsp;|&nbsp; {dur:.2f}s</span>'
        f'<span>Splunk events scanned: <span style="color:#65A637;font-weight:700">0</span> '
        f'&nbsp;|&nbsp; Snowflake rows: {estimate_rows("ACCESS_LOGS"):,}</span>'
        f'</div>',
        unsafe_allow_html=True
    )

def render_panel(title, sql, viz="table", spl_hint=None):
    """Run a query and render it as a dashboard panel with the given viz type."""
    st.markdown(
        f'<div class="ph">{title}'
        f'<span class="ph-badge">FEDERATED</span></div>',
        unsafe_allow_html=True
    )
    if spl_hint:
        with st.expander("SPL"):
            st.code(spl_hint, language="spl")
    try:
        df, dur = run_query(sql)
    except Exception as e:
        st.error(f"Query failed: {e}")
        return

    nr = len(df)
    ncols = len(df.columns)

    if viz == "metrics" and nr == 1:
        cols = st.columns(min(ncols, 6))
        for i, cn in enumerate(df.columns):
            if i < 6:
                try:
                    cols[i].metric(cn.replace("_"," ").title(), f"{int(df.iloc[0][cn]):,}")
                except (ValueError, TypeError):
                    cols[i].metric(cn.replace("_"," ").title(), str(df.iloc[0][cn]))
    elif viz == "bar" and ncols >= 2:
        chart = alt.Chart(df).mark_bar(color="#65A637").encode(
            x=alt.X(f"{df.columns[0]}:N", sort="-y"),
            y=alt.Y(f"{df.columns[1]}:Q"),
            tooltip=list(df.columns),
        ).properties(height=350)
        st.altair_chart(chart, use_container_width=True)
    elif viz == "horizontal_bar" and ncols >= 2:
        chart = alt.Chart(df).mark_bar(color="#5CC0DE").encode(
            y=alt.Y(f"{df.columns[0]}:N", sort="-x"),
            x=alt.X(f"{df.columns[1]}:Q"),
            tooltip=list(df.columns),
        ).properties(height=max(200, nr * 28))
        st.altair_chart(chart, use_container_width=True)
    elif viz == "pie" and ncols >= 2:
        chart = alt.Chart(df).mark_arc(innerRadius=50).encode(
            theta=alt.Theta(f"{df.columns[1]}:Q"),
            color=alt.Color(f"{df.columns[0]}:N"),
            tooltip=list(df.columns),
        ).properties(height=350)
        st.altair_chart(chart, use_container_width=True)
    elif viz == "line" and ncols >= 2:
        chart = alt.Chart(df).mark_line(color="#65A637", point=True).encode(
            x=alt.X(f"{df.columns[0]}:T"),
            y=alt.Y(f"{df.columns[1]}:Q"),
            tooltip=list(df.columns),
        ).properties(height=350)
        st.altair_chart(chart, use_container_width=True)
    else:
        show_df(df)

    with st.expander("Job Inspector"):
        job_inspector(nr, dur, estimate_rows(sql), sql)

# ---------------------------------------------------------------------------
# Dashboard panel library
# ---------------------------------------------------------------------------
PANELS = [
    {
        "id": "sec_overview",
        "title": "Security Overview (KPIs)",
        "sql": "SELECT COUNT(*) AS TOTAL_REQUESTS, COUNT(DISTINCT IP_ADDRESS) AS UNIQUE_IPS, SUM(CASE WHEN STATUS_CODE=401 THEN 1 ELSE 0 END) AS AUTH_FAILURES, SUM(CASE WHEN STATUS_CODE>=500 THEN 1 ELSE 0 END) AS SERVER_ERRORS, SUM(CASE WHEN REQUEST_METHOD='DELETE' THEN 1 ELSE 0 END) AS DELETE_OPS FROM CTF.PUBLIC.ACCESS_LOGS",
        "spl": '| dbxquery connection="snowflake" query="SELECT COUNT(*) AS TOTAL_REQUESTS, ..."',
        "viz": "metrics",
        "default": True,
    },
    {
        "id": "method_pie",
        "title": "Request Method Distribution",
        "sql": "SELECT REQUEST_METHOD, COUNT(*) AS COUNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY REQUEST_METHOD ORDER BY COUNT DESC",
        "spl": '| dbxquery connection="snowflake" query="SELECT REQUEST_METHOD, COUNT(*) ..."',
        "viz": "pie",
        "default": True,
    },
    {
        "id": "status_bar",
        "title": "Status Code Distribution",
        "sql": "SELECT CAST(STATUS_CODE AS VARCHAR) AS STATUS_CODE, COUNT(*) AS COUNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY STATUS_CODE ORDER BY COUNT DESC",
        "spl": '| dbxquery connection="snowflake" query="SELECT STATUS_CODE, COUNT(*) ..."',
        "viz": "bar",
        "default": True,
    },
    {
        "id": "threat_method",
        "title": "Threat Analysis by HTTP Method",
        "sql": "SELECT REQUEST_METHOD, COUNT(*) AS TOTAL, SUM(CASE WHEN STATUS_CODE=401 THEN 1 ELSE 0 END) AS AUTH_FAILED, ROUND(100.0*SUM(CASE WHEN STATUS_CODE>=400 THEN 1 ELSE 0 END)/COUNT(*),2) AS ERROR_RATE_PCT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY REQUEST_METHOD ORDER BY TOTAL DESC",
        "spl": '| dbxquery connection="snowflake" query="SELECT REQUEST_METHOD, COUNT(*), ... GROUP BY REQUEST_METHOD"',
        "viz": "table",
        "default": True,
    },
    {
        "id": "endpoint_risk",
        "title": "Endpoint Risk Assessment (CTE)",
        "sql": "WITH pa AS (SELECT SPLIT_PART(SPLIT_PART(REQUEST_PATH,'/',2),'/',1) AS ENDPOINT, COUNT(*) AS REQUESTS, SUM(CASE WHEN STATUS_CODE=401 THEN 1 ELSE 0 END) AS AUTH_FAILURES, ROUND(100.0*SUM(CASE WHEN STATUS_CODE>=400 THEN 1 ELSE 0 END)/COUNT(*),1) AS ERROR_RATE_PCT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY 1) SELECT ENDPOINT, REQUESTS, AUTH_FAILURES, ERROR_RATE_PCT, CASE WHEN AUTH_FAILURES>1000 THEN 'HIGH_RISK' WHEN AUTH_FAILURES>500 THEN 'MEDIUM_RISK' ELSE 'NORMAL' END AS RISK FROM pa ORDER BY REQUESTS DESC",
        "spl": '| dbxquery connection="snowflake" query="WITH path_analysis AS (...) SELECT ENDPOINT, RISK ..."',
        "viz": "table",
        "default": True,
    },
    {
        "id": "backend_health",
        "title": "Backend Server Health (Top 10)",
        "sql": "SELECT BACKEND_IP, COUNT(*) AS TOTAL_HITS, SUM(CASE WHEN STATUS_CODE>=500 THEN 1 ELSE 0 END) AS SERVER_ERRORS, ROUND(100.0*SUM(CASE WHEN STATUS_CODE>=500 THEN 1 ELSE 0 END)/COUNT(*),1) AS ERROR_RATE_PCT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY BACKEND_IP HAVING COUNT(*)>=3 ORDER BY SERVER_ERRORS DESC LIMIT 10",
        "spl": '| dbxquery connection="snowflake" query="SELECT BACKEND_IP, ... LIMIT 10"',
        "viz": "horizontal_bar",
        "default": False,
    },
    {
        "id": "zscore",
        "title": "Anomalous IPs (Z-Score > 2)",
        "sql": "WITH s AS (SELECT IP_ADDRESS, COUNT(*) AS REQUESTS, AVG(COUNT(*)) OVER() AS M, STDDEV(COUNT(*)) OVER() AS SD FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY IP_ADDRESS) SELECT IP_ADDRESS, REQUESTS, ROUND((REQUESTS-M)/NULLIF(SD,0),2) AS Z_SCORE FROM s WHERE ABS((REQUESTS-M)/NULLIF(SD,0))>2 ORDER BY Z_SCORE DESC LIMIT 10",
        "spl": '| dbxquery connection="snowflake" query="WITH stats AS (...) WHERE Z>2"',
        "viz": "table",
        "default": True,
    },
    {
        "id": "auth_fail_ip",
        "title": "Auth Failures by IP (Top 20)",
        "sql": "SELECT IP_ADDRESS, COUNT(*) AS AUTH_FAILURES FROM CTF.PUBLIC.ACCESS_LOGS WHERE STATUS_CODE=401 GROUP BY IP_ADDRESS ORDER BY AUTH_FAILURES DESC LIMIT 20",
        "spl": '| dbxquery connection="snowflake" query="SELECT IP_ADDRESS, COUNT(*) ... WHERE STATUS_CODE=401 ... LIMIT 20"',
        "viz": "horizontal_bar",
        "default": False,
    },
    {
        "id": "vuln_severity",
        "title": "Vulnerabilities by Severity",
        "sql": "SELECT SEVERITY, COUNT(*) AS CNT FROM CTF.PUBLIC.VULNERABILITIES GROUP BY SEVERITY ORDER BY CNT DESC",
        "spl": '| dbxquery connection="snowflake" query="SELECT SEVERITY, COUNT(*) FROM VULNERABILITIES GROUP BY SEVERITY"',
        "viz": "bar",
        "default": False,
    },
    {
        "id": "assets_no_edr",
        "title": "Assets Missing EDR Agent",
        "sql": "SELECT HOSTNAME, OS, DEPARTMENT, LAST_SEEN FROM CTF.PUBLIC.ASSET_INVENTORY WHERE EDR_INSTALLED = FALSE ORDER BY LAST_SEEN DESC LIMIT 25",
        "spl": '| dbxquery connection="snowflake" query="SELECT HOSTNAME, ... WHERE EDR_INSTALLED=FALSE"',
        "viz": "table",
        "default": False,
    },
    {
        "id": "vuln_join",
        "title": "Critical Vulns on Production Assets (JOIN)",
        "sql": "SELECT a.HOSTNAME, a.DEPARTMENT, v.CVE_ID, v.SEVERITY, v.CVSS_SCORE FROM CTF.PUBLIC.VULNERABILITIES v JOIN CTF.PUBLIC.ASSET_INVENTORY a ON v.HOSTNAME = a.HOSTNAME WHERE v.SEVERITY = 'CRITICAL' AND a.ENVIRONMENT = 'PRODUCTION' ORDER BY v.CVSS_SCORE DESC LIMIT 20",
        "spl": '| dbxquery connection="snowflake" query="SELECT ... FROM VULNERABILITIES v JOIN ASSET_INVENTORY a ... WHERE CRITICAL AND PRODUCTION"',
        "viz": "table",
        "default": False,
    },
    {
        "id": "hourly_vol",
        "title": "Hourly Request Volume (Time Series)",
        "sql": "SELECT DATE_TRUNC('HOUR', TIMESTAMP) AS HOUR, COUNT(*) AS REQUESTS FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY 1 ORDER BY 1",
        "spl": '| dbxquery connection="snowflake" query="SELECT DATE_TRUNC(HOUR, TIMESTAMP), COUNT(*) ... GROUP BY 1"',
        "viz": "line",
        "default": False,
    },
    {
        "id": "findings",
        "title": "Security Findings Summary",
        "sql": "SELECT FINDING_TYPE, STATUS, COUNT(*) AS CNT FROM CTF.PUBLIC.SECURITY_FINDINGS GROUP BY 1, 2 ORDER BY CNT DESC",
        "spl": '| dbxquery connection="snowflake" query="SELECT FINDING_TYPE, STATUS, COUNT(*) FROM SECURITY_FINDINGS GROUP BY 1,2"',
        "viz": "table",
        "default": False,
    },
    {
        "id": "row_counts",
        "title": "Table Row Counts (All Tables)",
        "sql": "SELECT 'ACCESS_LOGS' AS TBL, COUNT(*) AS ROW_COUNT FROM CTF.PUBLIC.ACCESS_LOGS UNION ALL SELECT 'VULNERABILITIES', COUNT(*) FROM CTF.PUBLIC.VULNERABILITIES UNION ALL SELECT 'ASSET_INVENTORY', COUNT(*) FROM CTF.PUBLIC.ASSET_INVENTORY UNION ALL SELECT 'SECURITY_FINDINGS', COUNT(*) FROM CTF.PUBLIC.SECURITY_FINDINGS",
        "spl": '| dbxquery connection="snowflake" query="SELECT ... UNION ALL ..."',
        "viz": "bar",
        "default": False,
    },
]

# ---------------------------------------------------------------------------
# Top Navigation Bar
# ---------------------------------------------------------------------------
st.markdown("""
<div class="splunk-nav">
    <div style="display:flex;align-items:center">
        <div class="splunk-logo">datavault<span>&gt;</span></div>
        <div class="splunk-nav-app">Search &amp; Reporting</div>
    </div>
    <div class="splunk-nav-right">
        <span><span class="splunk-conn-dot"></span>Snowflake Connected</span>
        <span>CTF.PUBLIC</span>
        <span>admin</span>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown(
    '<div class="ib">'
    '<strong>Federated Search Demo</strong> &nbsp;|&nbsp; '
    '<strong>Connection:</strong> snowflake (DB Connect) &nbsp;|&nbsp; '
    '<strong>Data:</strong> 100K access logs &bull; 15K vulns &bull; 844 assets &bull; 106 findings'
    '</div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab_dash, tab_builder, tab_search, tab_flow = st.tabs([
    "Dashboards", "Dashboard Builder", "Search", "Federated Search Flow"])


# ===========================================================================
# DASHBOARD TAB
# ===========================================================================
with tab_dash:
    render_panel("Security Overview (Aggregation Pushdown)",
        PANELS[0]["sql"], "metrics", PANELS[0]["spl"])

    st.markdown("")
    c1, c2 = st.columns(2)
    with c1:
        render_panel("Request Method Distribution",
            PANELS[1]["sql"], "pie", PANELS[1]["spl"])
    with c2:
        render_panel("Status Code Distribution",
            PANELS[2]["sql"], "bar", PANELS[2]["spl"])

    st.markdown("")
    render_panel("Endpoint Risk Assessment (CTE)",
        PANELS[4]["sql"], "table", PANELS[4]["spl"])

    st.markdown("")
    c3, c4 = st.columns(2)
    with c3:
        render_panel("Backend Server Health",
            PANELS[5]["sql"], "horizontal_bar", PANELS[5]["spl"])
    with c4:
        render_panel("Anomalous IPs (Z-Score > 2)",
            PANELS[6]["sql"], "table", PANELS[6]["spl"])

    # Triggered Alerts panel — shows that federated search results drive real actions
    st.markdown("")
    st.markdown(
        '<div class="ph">Triggered Alerts (Federated Search &rarr; Actions)'
        '<span class="ph-badge">LIVE</span></div>',
        unsafe_allow_html=True
    )
    try:
        df_auth, _ = run_query(
            "SELECT IP_ADDRESS, COUNT(*) AS FAILURES "
            "FROM CTF.PUBLIC.ACCESS_LOGS WHERE STATUS_CODE=401 "
            "GROUP BY IP_ADDRESS HAVING COUNT(*)>50 ORDER BY FAILURES DESC LIMIT 5"
        )
        n_ips = len(df_auth)
    except Exception:
        n_ips = 3

    st.markdown(f"""
<div class="alert-card severity-high">
    <span class="alert-badge triggered">TRIGGERED</span>
    <strong>Brute-Force Detection: {n_ips} IPs with &gt;50 auth failures</strong>
    <br><span style="color:#9DA8B5;font-size:12px">Federated query against Snowflake ACCESS_LOGS | Splunk events scanned: 0</span>
    <br><br>
    <div class="action-row"><span class="action-icon">&#9993;</span><span>Email &rarr; soc-team@company.com</span><span class="action-status sent">SENT</span></div>
    <div class="action-row"><span class="action-icon">&#9888;</span><span>PagerDuty &rarr; SOC On-Call (P2)</span><span class="action-status sent">SENT</span></div>
    <div class="action-row"><span class="action-icon">&#128172;</span><span>Slack &rarr; #security-alerts</span><span class="action-status sent">SENT</span></div>
</div>
""", unsafe_allow_html=True)

    st.markdown(f"""
<div class="alert-card severity-medium">
    <span class="alert-badge triggered">TRIGGERED</span>
    <strong>Critical Vulns on Production: Unpatched CRITICAL CVEs detected</strong>
    <br><span style="color:#9DA8B5;font-size:12px">Federated JOIN: VULNERABILITIES x ASSET_INVENTORY | Splunk events scanned: 0</span>
    <br><br>
    <div class="action-row"><span class="action-icon">&#127915;</span><span>ServiceNow &rarr; INC auto-created, SecOps queue</span><span class="action-status sent">SENT</span></div>
    <div class="action-row"><span class="action-icon">&#9889;</span><span>SOAR Playbook &rarr; "Vuln Triage" (enrich CVE, check EPSS, assign owner)</span><span class="action-status queued">QUEUED</span></div>
</div>
""", unsafe_allow_html=True)

    st.markdown(f"""
<div class="alert-card severity-info">
    <span class="alert-badge pending">MONITORING</span>
    <strong>Anomaly Monitor: Z-Score outlier IPs above threshold</strong>
    <br><span style="color:#9DA8B5;font-size:12px">Scheduled every 15 min | Federated query with CTE + window functions | Splunk events scanned: 0</span>
    <br><br>
    <div class="action-row"><span class="action-icon">&#128200;</span><span>Log event &rarr; index=security_audit sourcetype=federated_alert</span><span class="action-status sent">SENT</span></div>
</div>
""", unsafe_allow_html=True)

    st.markdown(
        '<div class="ib">'
        '<strong>Detect on Snowflake, Act from Splunk:</strong> All alerts above were triggered by '
        'federated queries against Snowflake data. Splunk scanned <strong style="color:#65A637">0 local events</strong>. '
        'Email, PagerDuty, Slack, ServiceNow, and SOAR playbooks fire exactly as if the data were in Splunk.'
        '</div>', unsafe_allow_html=True)


# ===========================================================================
# DASHBOARD BUILDER TAB
# ===========================================================================
with tab_builder:
    st.markdown("### Dashboard Builder")
    st.markdown("""
<div class="ib">
<strong>How it works in Splunk:</strong> Each panel in a Splunk dashboard runs an independent
<code>| dbxquery</code> search. Pick the panels below and see them render live &mdash;
exactly as they would in Splunk, with all compute in Snowflake.
</div>
""", unsafe_allow_html=True)

    panel_titles = [p["title"] for p in PANELS]
    default_sel = [p["title"] for p in PANELS if p.get("default")]

    selected = st.multiselect(
        "Select dashboard panels:",
        panel_titles,
        default=default_sel,
    )

    if not selected:
        st.info("Select one or more panels above to build your dashboard.")
    else:
        metrics_panels = [p for p in PANELS if p["title"] in selected and p["viz"] == "metrics"]
        chart_panels = [p for p in PANELS if p["title"] in selected and p["viz"] != "metrics"]

        for p in metrics_panels:
            render_panel(p["title"], p["sql"], p["viz"], p["spl"])
            st.markdown("")

        i = 0
        while i < len(chart_panels):
            if i + 1 < len(chart_panels):
                c1, c2 = st.columns(2)
                with c1:
                    p = chart_panels[i]
                    render_panel(p["title"], p["sql"], p["viz"], p["spl"])
                with c2:
                    p = chart_panels[i+1]
                    render_panel(p["title"], p["sql"], p["viz"], p["spl"])
                i += 2
            else:
                p = chart_panels[i]
                render_panel(p["title"], p["sql"], p["viz"], p["spl"])
                i += 1
            st.markdown("")

        total_rows = sum(estimate_rows(p["sql"]) for p in PANELS if p["title"] in selected)
        st.markdown(
            f'<div class="ib">'
            f'<strong>Dashboard Summary:</strong> {len(selected)} panels, '
            f'~{total_rows:,} total Snowflake rows scanned, '
            f'Splunk events scanned: <strong style="color:#65A637">0</strong>. '
            f'Splunk license cost: <strong style="color:#65A637">$0</strong>.'
            f'</div>', unsafe_allow_html=True)


# ===========================================================================
# SEARCH TAB — Splunk-style search with Events/Statistics/Visualization tabs
# ===========================================================================
SAMPLE_SPL = [
    ("-- Choose a sample query --", ""),
] + [
    (p["title"], f'| dbxquery connection="snowflake" query="{p["sql"]}"')
    for p in PANELS
]

with tab_search:
    st.markdown("""
<div class="ib">
<strong>Available tables:</strong>
<code>CTF.PUBLIC.ACCESS_LOGS</code> (100K) &nbsp;|&nbsp;
<code>CTF.PUBLIC.VULNERABILITIES</code> (15K) &nbsp;|&nbsp;
<code>CTF.PUBLIC.ASSET_INVENTORY</code> (844) &nbsp;|&nbsp;
<code>CTF.PUBLIC.SECURITY_FINDINGS</code> (106)
</div>
""", unsafe_allow_html=True)

    sample_label = st.selectbox("Quick-start samples:", [s[0] for s in SAMPLE_SPL])
    sample_spl = ""
    for lbl, spl in SAMPLE_SPL:
        if lbl == sample_label:
            sample_spl = spl
            break

    user_spl = st.text_area(
        "SPL / SQL query", value=sample_spl, height=120,
        placeholder='| dbxquery connection="snowflake" query="SELECT * FROM CTF.PUBLIC.ACCESS_LOGS LIMIT 10"',
    )

    col_run, col_mode, col_time = st.columns([1, 2, 2])
    with col_run:
        run_btn = st.button("Search", type="primary")
    with col_mode:
        st.selectbox("Search mode", ["Smart", "Fast", "Verbose"], index=0, label_visibility="collapsed")
    with col_time:
        st.selectbox("Time range", ["All time", "Last 24 hours", "Last 7 days", "Last 30 days"], index=0, label_visibility="collapsed")

    if run_btn and user_spl.strip():
        sql = extract_sql(user_spl)
        if sql is None:
            st.error("Could not parse SQL. Use `| dbxquery connection=\"snowflake\" query=\"...\"` or a raw SELECT statement.")
        else:
            # Render the green search bar with syntax highlighting
            if "dbxquery" in user_spl.lower():
                render_search_bar(user_spl.strip())

            # Execute the query
            try:
                with st.spinner("Querying Snowflake..."):
                    df, dur = run_query(sql)
                nr = len(df)
                ncols = len(df.columns)
                rows_est = estimate_rows(sql)

                # Render timeline
                render_timeline(nr, dur)

                # Splunk-style result tabs
                rtab_stats, rtab_viz, rtab_events = st.tabs([
                    "Statistics", "Visualization", "Events"])

                with rtab_stats:
                    show_df(df)

                with rtab_viz:
                    if ncols >= 2:
                        col0_dtype = str(df[df.columns[0]].dtype)
                        if "datetime" in col0_dtype or "Timestamp" in col0_dtype:
                            chart = alt.Chart(df).mark_line(color="#65A637", point=True).encode(
                                x=alt.X(f"{df.columns[0]}:T"),
                                y=alt.Y(f"{df.columns[1]}:Q"),
                                tooltip=list(df.columns),
                            ).properties(height=400)
                        elif nr <= 15:
                            chart = alt.Chart(df).mark_bar(color="#65A637").encode(
                                x=alt.X(f"{df.columns[0]}:N", sort="-y"),
                                y=alt.Y(f"{df.columns[1]}:Q"),
                                tooltip=list(df.columns),
                            ).properties(height=400)
                        else:
                            chart = alt.Chart(df.head(25)).mark_bar(color="#65A637").encode(
                                y=alt.Y(f"{df.columns[0]}:N", sort="-x"),
                                x=alt.X(f"{df.columns[1]}:Q"),
                                tooltip=list(df.columns),
                            ).properties(height=max(300, min(nr, 25) * 28))
                        st.altair_chart(chart, use_container_width=True)
                    else:
                        st.info("Visualization requires at least 2 columns.")

                with rtab_events:
                    st.caption(f"Showing {min(nr, 50)} of {nr} events in raw format")
                    for idx, row in df.head(50).iterrows():
                        event_str = " &nbsp;|&nbsp; ".join(
                            f"<strong>{c}</strong>={row[c]}" for c in df.columns
                        )
                        st.markdown(
                            f'<div style="background:#171D21;border:1px solid #2B2F35;'
                            f'border-radius:3px;padding:8px 12px;margin-bottom:4px;'
                            f'font-family:monospace;font-size:12px;color:#C3CBD4">'
                            f'{event_str}</div>',
                            unsafe_allow_html=True
                        )

                st.markdown("---")
                job_inspector(nr, dur, rows_est, sql)

                st.markdown(
                    f'<div class="ib">'
                    f'<strong>Cost:</strong> ~{rows_est:,} rows scanned in Snowflake, '
                    f'{nr} results returned. '
                    f'Splunk license: <strong style="color:#65A637">$0</strong>.'
                    f'</div>', unsafe_allow_html=True)

            except Exception as e:
                st.error(f"Query failed: {e}")


# ===========================================================================
# FEDERATED SEARCH FLOW TAB
# ===========================================================================
with tab_flow:
    st.markdown("### How Splunk Federated Search Works with Snowflake")

    # Step 1 — Architecture
    st.markdown("""
<div class="sb">
<span class="sn">1</span> <strong>Architecture: Hybrid Security Data Lake</strong>
<br><br>
<pre style="color:#9DA8B5;font-size:13px;line-height:1.6">
  ALL LOG SOURCES (Firewall, EDR, Auth, Cloud, Web, DNS)
                        |
                   ROUTING LAYER  (Vector / Cribl / Kafka)
                   /            \\
             ALL DATA          CRITICAL ONLY (~20%)
                |                    |
          SNOWFLAKE              SPLUNK
       Security Data Lake     Real-time Detection
       Years of retention     30-90 day retention
       ~$23-40/TB/month       ~$1,500-3,000/GB/year
                \\                  /
                 DB Connect / Federated Search
                 (query Snowflake FROM Splunk)
</pre>
</div>
""", unsafe_allow_html=True)

    # Step 2 — SPL query
    st.markdown("""
<div class="sb">
<span class="sn">2</span> <strong>Analyst Writes SPL in the Splunk Search Bar</strong>
<br><br>The analyst types a <code>| dbxquery</code> command in the Splunk search bar:
</div>
""", unsafe_allow_html=True)

    demo_spl = ('| dbxquery connection="snowflake" query="SELECT REQUEST_METHOD, COUNT(*) AS TOTAL, '
        "SUM(CASE WHEN STATUS_CODE=401 THEN 1 ELSE 0 END) AS AUTH_FAILED "
        'FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY REQUEST_METHOD ORDER BY TOTAL DESC"')
    render_search_bar(demo_spl)

    # Step 3 — SQL pushdown
    st.markdown("""
<div class="sb">
<span class="sn">3</span> <strong>SQL is Pushed Down to Snowflake</strong>
<br><br>DB Connect extracts the SQL and sends it to Snowflake over JDBC (port 443, TLS).
The heavy compute (100K row scan, aggregation) happens entirely in Snowflake.
</div>
""", unsafe_allow_html=True)

    with st.expander("SQL sent to Snowflake"):
        st.code(PANELS[3]["sql"], language="sql")

    # Step 4 — Execute
    st.markdown("""
<div class="sb">
<span class="sn">4</span> <strong>Snowflake Executes the Query (Live Demo)</strong>
</div>
""", unsafe_allow_html=True)

    if st.button("Execute Federated Query", type="primary"):
        with st.spinner("Snowflake scanning 100,000 rows..."):
            df_demo, dur_demo = run_query(PANELS[3]["sql"])
        st.success(f"Query completed in {dur_demo:.1f}s")
        show_df(df_demo)

        # Step 5 — Job Inspector
        st.markdown("""
<div class="sb">
<span class="sn">5</span> <strong>Job Inspector: Proof of Compute Offloading</strong>
<br><br>The analyst opens <em>Job &gt; Inspect Job</em> in Splunk and sees:
</div>
""", unsafe_allow_html=True)
        job_inspector(len(df_demo), dur_demo, 100000, PANELS[3]["sql"])

        # Step 6 — Cost comparison
        st.markdown(f"""
<div class="sb">
<span class="sn">6</span> <strong>Cost Impact</strong>
<br><br>
<table class="compare-tbl" style="width:100%">
<tr><th>Metric</th><th>All Data in Splunk</th><th>Federated (Hybrid)</th></tr>
<tr><td>Events scanned by Splunk</td><td>100,000</td><td><span class="hl">0</span></td></tr>
<tr><td>Splunk license cost</td><td>$$$ (per GB ingested)</td><td><span class="hl">$0</span></td></tr>
<tr><td>Snowflake compute</td><td>N/A</td><td>~$0.002 (XS warehouse, &lt;1s)</td></tr>
<tr><td>Snowflake storage</td><td>N/A</td><td>~$23-40/TB/month</td></tr>
<tr><td>Results to Splunk</td><td>4 rows after aggregation</td><td>4 rows</td></tr>
<tr><td>Retention</td><td>30-90 days</td><td><span class="hl">Years</span></td></tr>
</table>
</div>
""", unsafe_allow_html=True)

    st.markdown("---")

    # Step 7 — Native Federated Search preview
    st.markdown("""
<div class="sb">
<span class="sn">7</span> <strong>Coming: Native Federated Search for Snowflake (GA July 2026)</strong>
<br><br>
Announced at <strong>Splunk .conf25</strong> (Sept 2025), Native Federated Search eliminates the need
for DB Connect entirely. Analysts will query Snowflake datasets using <strong>SPL2 syntax</strong>
directly from the Splunk search bar.
</div>
""", unsafe_allow_html=True)

    col_now, col_future = st.columns(2)
    with col_now:
        st.markdown("""
<div class="sb" style="border-color:#5CC0DE">
<strong style="color:#5CC0DE">Today: DB Connect (dbxquery)</strong>
<br><br>
<div style="font-family:monospace;font-size:12px;background:#111215;padding:12px;border-radius:4px;color:#C3CBD4">
<span style="color:#65A637">|</span> <span style="color:#5CC0DE">dbxquery</span>
connection=<span style="color:#F8BE34">"snowflake"</span>
query=<span style="color:#F8BE34">"SELECT * FROM<br>&nbsp;&nbsp;CTF.PUBLIC.ACCESS_LOGS<br>&nbsp;&nbsp;WHERE STATUS_CODE=401<br>&nbsp;&nbsp;LIMIT 100"</span>
</div>
<br>
<span style="color:#9DA8B5;font-size:12px">
Requires: DB Connect app installed, JDBC driver, connection config in db_connections.conf
</span>
</div>
""", unsafe_allow_html=True)

    with col_future:
        st.markdown("""
<div class="sb" style="border-color:#65A637">
<strong style="color:#65A637">July 2026: Native Federated Search</strong>
<br><br>
<div style="font-family:monospace;font-size:12px;background:#111215;padding:12px;border-radius:4px;color:#C3CBD4">
<span style="color:#65A637">FROM</span> <span style="color:#5CC0DE">federated:snowflake_security:access_logs</span>
<span style="color:#65A637">|</span> <span style="color:#5CC0DE">where</span> status_code=<span style="color:#F8BE34">401</span>
<span style="color:#65A637">|</span> <span style="color:#5CC0DE">head</span> <span style="color:#F8BE34">100</span>
</div>
<br>
<span style="color:#9DA8B5;font-size:12px">
Requires: Data Management app, Snowflake connection + dataset definition, programmatic access token
</span>
</div>
""", unsafe_allow_html=True)

    st.markdown("""
<div class="sb">
<span class="sn">8</span> <strong>Data Management: Connection Setup (Simulation)</strong>
<br><br>
In the Splunk Cloud <strong>Data Management</strong> app, administrators define:
<br><br>
<table style="width:100%;font-size:13px">
<tr style="border-bottom:1px solid #2B2F35">
    <td style="padding:6px 8px;width:35%"><strong>Setting</strong></td>
    <td style="padding:6px 8px"><strong>Value</strong></td>
</tr>
<tr><td style="padding:6px 8px">Connection name</td><td style="padding:6px 8px"><code>snowflake_security</code></td></tr>
<tr><td style="padding:6px 8px">Provider</td><td style="padding:6px 8px">Snowflake</td></tr>
<tr><td style="padding:6px 8px">Account</td><td style="padding:6px 8px"><code>myorg-myaccount</code></td></tr>
<tr><td style="padding:6px 8px">Warehouse</td><td style="padding:6px 8px"><code>SECURITY_WH</code></td></tr>
<tr><td style="padding:6px 8px">Database</td><td style="padding:6px 8px"><code>CTF</code></td></tr>
<tr><td style="padding:6px 8px">Schema</td><td style="padding:6px 8px"><code>PUBLIC</code></td></tr>
<tr><td style="padding:6px 8px">Authentication</td><td style="padding:6px 8px">Programmatic Access Token</td></tr>
</table>
<br>
Then define <strong>datasets</strong> that map to Snowflake tables:
<br><br>
<table style="width:100%;font-size:13px">
<tr style="border-bottom:1px solid #2B2F35">
    <td style="padding:6px 8px"><strong>Dataset</strong></td>
    <td style="padding:6px 8px"><strong>Snowflake Table</strong></td>
    <td style="padding:6px 8px"><strong>SPL2 Reference</strong></td>
</tr>
<tr><td style="padding:6px 8px">access_logs</td><td style="padding:6px 8px">CTF.PUBLIC.ACCESS_LOGS</td><td style="padding:6px 8px"><code>federated:snowflake_security:access_logs</code></td></tr>
<tr><td style="padding:6px 8px">vulnerabilities</td><td style="padding:6px 8px">CTF.PUBLIC.VULNERABILITIES</td><td style="padding:6px 8px"><code>federated:snowflake_security:vulnerabilities</code></td></tr>
<tr><td style="padding:6px 8px">asset_inventory</td><td style="padding:6px 8px">CTF.PUBLIC.ASSET_INVENTORY</td><td style="padding:6px 8px"><code>federated:snowflake_security:asset_inventory</code></td></tr>
<tr><td style="padding:6px 8px">security_findings</td><td style="padding:6px 8px">CTF.PUBLIC.SECURITY_FINDINGS</td><td style="padding:6px 8px"><code>federated:snowflake_security:security_findings</code></td></tr>
</table>
</div>
""", unsafe_allow_html=True)

    # Step 9 — Alert & Response Actions
    st.markdown("---")
    st.markdown("""
<div class="sb">
<span class="sn">9</span> <strong>Alert &amp; Response Actions: Detect on Snowflake, Act from Splunk</strong>
<br><br>
Federated search results flow through Splunk's full alerting pipeline. Analysts can
create <strong>saved searches</strong> that run federated queries on a schedule and trigger
<strong>alert actions</strong> when conditions are met &mdash; all without ingesting a single byte
into Splunk.
</div>
""", unsafe_allow_html=True)

    st.markdown("""
<div class="sb">
<strong>Example: Brute-Force Detection on Snowflake Data</strong>
<br><br>
<div style="font-family:monospace;font-size:12px;background:#111215;padding:12px;border-radius:4px;color:#C3CBD4;margin-bottom:12px">
<span style="color:#65A637">|</span> <span style="color:#5CC0DE">dbxquery</span>
connection=<span style="color:#F8BE34">"snowflake"</span>
query=<span style="color:#F8BE34">"SELECT IP_ADDRESS, COUNT(*) AS FAILURES<br>
&nbsp;&nbsp;FROM CTF.PUBLIC.ACCESS_LOGS<br>
&nbsp;&nbsp;WHERE STATUS_CODE=401<br>
&nbsp;&nbsp;&nbsp;&nbsp;AND TIMESTAMP > DATEADD('hour', -1, CURRENT_TIMESTAMP())<br>
&nbsp;&nbsp;GROUP BY IP_ADDRESS<br>
&nbsp;&nbsp;HAVING COUNT(*) > 50"</span>
</div>

When this scheduled search returns results (IPs with &gt;50 auth failures in the last hour),
Splunk triggers the configured actions:
<br><br>

<div class="alert-card severity-high">
    <span class="alert-badge triggered">TRIGGERED</span>
    <strong>Brute-Force Alert: Excessive Auth Failures from Snowflake Data</strong>
    <br><span style="color:#9DA8B5;font-size:12px">Saved search ran at 14:32:07 UTC | 3 results | Source: Snowflake federated query</span>
    <br><br>
    <div class="action-row">
        <span class="action-icon">&#9993;</span>
        <span><strong>Send email</strong> &mdash; soc-team@company.com</span>
        <span class="action-status sent">SENT</span>
    </div>
    <div class="action-row">
        <span class="action-icon">&#9888;</span>
        <span><strong>PagerDuty incident</strong> &mdash; SOC On-Call rotation, P2 severity</span>
        <span class="action-status sent">SENT</span>
    </div>
    <div class="action-row">
        <span class="action-icon">&#128172;</span>
        <span><strong>Slack webhook</strong> &mdash; #security-alerts channel</span>
        <span class="action-status sent">SENT</span>
    </div>
    <div class="action-row">
        <span class="action-icon">&#127915;</span>
        <span><strong>ServiceNow ticket</strong> &mdash; INC auto-created, assigned to SecOps queue</span>
        <span class="action-status sent">SENT</span>
    </div>
    <div class="action-row">
        <span class="action-icon">&#9889;</span>
        <span><strong>SOAR playbook</strong> &mdash; "Brute-Force Triage" (auto-enrich IP, check reputation, block if malicious)</span>
        <span class="action-status queued">QUEUED</span>
    </div>
</div>
</div>
""", unsafe_allow_html=True)

    st.markdown("""
<div class="sb">
<strong>Available Alert Actions for Federated Search Results</strong>
<br><br>
<table style="width:100%;font-size:13px">
<tr style="border-bottom:1px solid #2B2F35">
    <td style="padding:6px 8px;width:30%"><strong>Action Type</strong></td>
    <td style="padding:6px 8px"><strong>Description</strong></td>
    <td style="padding:6px 8px;width:25%"><strong>Use Case</strong></td>
</tr>
<tr><td style="padding:6px 8px">Email notification</td><td style="padding:6px 8px">Send results to recipients with custom message and CSV/PDF attachment</td><td style="padding:6px 8px">SOC team alerts</td></tr>
<tr><td style="padding:6px 8px">Webhook (HTTP POST)</td><td style="padding:6px 8px">POST JSON payload to any URL &mdash; Slack, Teams, custom APIs</td><td style="padding:6px 8px">ChatOps, custom integrations</td></tr>
<tr><td style="padding:6px 8px">PagerDuty</td><td style="padding:6px 8px">Create/resolve incidents via PagerDuty Events API</td><td style="padding:6px 8px">On-call escalation</td></tr>
<tr><td style="padding:6px 8px">ServiceNow</td><td style="padding:6px 8px">Auto-create incidents or events in ServiceNow ITSM</td><td style="padding:6px 8px">Ticket management</td></tr>
<tr><td style="padding:6px 8px">Splunk SOAR playbook</td><td style="padding:6px 8px">Trigger automated playbooks: enrich, investigate, contain, remediate</td><td style="padding:6px 8px">Automated response</td></tr>
<tr><td style="padding:6px 8px">Run script</td><td style="padding:6px 8px">Execute a custom script on the Splunk server</td><td style="padding:6px 8px">Custom remediation</td></tr>
<tr><td style="padding:6px 8px">Log event</td><td style="padding:6px 8px">Write alert metadata back to a Splunk index for audit trail</td><td style="padding:6px 8px">Compliance logging</td></tr>
<tr><td style="padding:6px 8px">Custom alert action</td><td style="padding:6px 8px">Any Python-based action via Splunk's alert action framework</td><td style="padding:6px 8px">Jira, Confluence, etc.</td></tr>
</table>
</div>
""", unsafe_allow_html=True)

    st.markdown("""
<div class="ib">
<strong>Key Takeaway:</strong> Splunk analysts keep their SPL workflows, dashboards, <strong>and alert-driven response actions</strong>.
The data lives in Snowflake at 50-100x lower storage cost. Splunk scans <strong>0 events</strong> locally.
When a federated query detects a threat, Splunk's full alerting pipeline fires &mdash;
email, PagerDuty, ServiceNow, SOAR playbooks &mdash; exactly as if the data were in Splunk.
</div>
""", unsafe_allow_html=True)
