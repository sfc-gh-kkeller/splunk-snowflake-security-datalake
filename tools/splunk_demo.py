#!/usr/bin/env python3
"""
Mock Splunk Federated Search Experience
========================================
Simulates the Splunk Web interface showing federated search queries
hitting Snowflake via DB Connect. Designed for demos where the prospect
doesn't have a Splunk instance available.

Two modes:
  - Mock Data (default): Works offline, zero config, pre-baked results
  - Live Snowflake: Toggle in sidebar, runs real queries against CTF.PUBLIC.*

Usage:
    streamlit run tools/splunk_demo.py
    pixi run splunk-demo
    make splunk-demo
"""

import time
import random
import streamlit as st
import pandas as pd

# ---------------------------------------------------------------------------
# Page config (must be first Streamlit call)
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Splunk + Snowflake Federated Search",
    page_icon="=",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Splunk-like dark theme CSS
# ---------------------------------------------------------------------------
SPLUNK_CSS = """
<style>
    /* Main background */
    .stApp { background-color: #171D21; }
    header[data-testid="stHeader"] { background-color: #111418; }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #1A1C20;
    }
    section[data-testid="stSidebar"] .stMarkdown p,
    section[data-testid="stSidebar"] label {
        color: #C3CBD4 !important;
    }

    /* Text */
    .stApp, .stApp p, .stApp li, .stApp span { color: #C3CBD4; }
    .stApp h1, .stApp h2, .stApp h3 { color: #FFFFFF; }

    /* Metric cards */
    [data-testid="stMetric"] {
        background-color: #1A1C20;
        border: 1px solid #2B2F35;
        border-radius: 6px;
        padding: 16px;
    }
    [data-testid="stMetricValue"] { color: #FFFFFF !important; font-size: 2rem !important; }
    [data-testid="stMetricLabel"] { color: #9DA8B5 !important; }

    /* Tables */
    .stDataFrame { border: 1px solid #2B2F35; border-radius: 6px; }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] { gap: 0; }
    .stTabs [data-baseweb="tab"] {
        background-color: #1A1C20;
        color: #9DA8B5;
        border: 1px solid #2B2F35;
        padding: 10px 24px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #2B2F35;
        color: #FFFFFF;
        border-bottom: 2px solid #00C853;
    }

    /* Search bar area */
    .search-bar {
        background-color: #00C853;
        padding: 8px 16px;
        border-radius: 6px;
        margin-bottom: 16px;
    }
    .search-bar-text {
        color: #000000;
        font-family: 'Courier New', monospace;
        font-size: 14px;
        word-break: break-all;
    }

    /* Job inspector */
    .job-inspector {
        background-color: #1A1C20;
        border: 1px solid #2B2F35;
        border-radius: 6px;
        padding: 16px;
        font-family: 'Courier New', monospace;
        font-size: 13px;
        color: #9DA8B5;
    }
    .job-inspector .highlight { color: #00C853; font-weight: bold; }
    .job-inspector .zero { color: #00C853; font-weight: bold; font-size: 16px; }

    /* Panel headers */
    .panel-header {
        background-color: #1A1C20;
        border: 1px solid #2B2F35;
        border-radius: 6px 6px 0 0;
        padding: 10px 16px;
        color: #C3CBD4;
        font-weight: 600;
        font-size: 14px;
        margin-bottom: 0;
    }

    /* Risk badges */
    .risk-high { color: #FF5252; font-weight: bold; }
    .risk-medium { color: #FFD740; font-weight: bold; }
    .risk-normal { color: #69F0AE; }

    /* Info banner */
    .info-banner {
        background: linear-gradient(135deg, #1A3A1A 0%, #1A1C20 100%);
        border: 1px solid #00C853;
        border-radius: 6px;
        padding: 12px 20px;
        margin-bottom: 20px;
        color: #C3CBD4;
        font-size: 13px;
    }
    .info-banner strong { color: #00C853; }
</style>
"""
st.markdown(SPLUNK_CSS, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Demo query library with mock data
# ---------------------------------------------------------------------------
DEMO_QUERIES = {
    "Security Overview (Aggregation Pushdown)": {
        "spl": '| dbxquery connection="snowflake" query="SELECT COUNT(*) AS TOTAL_REQUESTS, COUNT(DISTINCT IP_ADDRESS) AS UNIQUE_IPS, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) AS AUTH_FAILURES, SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) AS SERVER_ERRORS, SUM(CASE WHEN REQUEST_METHOD = \'DELETE\' THEN 1 ELSE 0 END) AS DELETE_OPS FROM CTF.PUBLIC.ACCESS_LOGS"',
        "sql": "SELECT COUNT(*) AS TOTAL_REQUESTS, COUNT(DISTINCT IP_ADDRESS) AS UNIQUE_IPS, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) AS AUTH_FAILURES, SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) AS SERVER_ERRORS, SUM(CASE WHEN REQUEST_METHOD = 'DELETE' THEN 1 ELSE 0 END) AS DELETE_OPS FROM CTF.PUBLIC.ACCESS_LOGS",
        "description": "Snowflake scans 100,000 rows but returns only 1 row with 5 metrics to Splunk.",
        "mock_result": [{"TOTAL_REQUESTS": 100000, "UNIQUE_IPS": 99998, "AUTH_FAILURES": 9362, "SERVER_ERRORS": 18054, "DELETE_OPS": 25205}],
        "display": "metrics",
        "rows_scanned": 100000,
    },
    "Threat Analysis by HTTP Method": {
        "spl": '| dbxquery connection="snowflake" query="SELECT REQUEST_METHOD, COUNT(*) AS TOTAL, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) AS AUTH_FAILED, SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) AS SERVER_ERROR, ROUND(100.0 * SUM(CASE WHEN STATUS_CODE >= 400 THEN 1 ELSE 0 END) / COUNT(*), 2) AS ERROR_RATE_PCT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY REQUEST_METHOD ORDER BY TOTAL DESC"',
        "sql": "SELECT REQUEST_METHOD, COUNT(*) AS TOTAL, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) AS AUTH_FAILED, SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) AS SERVER_ERROR, ROUND(100.0 * SUM(CASE WHEN STATUS_CODE >= 400 THEN 1 ELSE 0 END) / COUNT(*), 2) AS ERROR_RATE_PCT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY REQUEST_METHOD ORDER BY TOTAL DESC",
        "description": "Security analytics by HTTP method. ~25% DELETE with ~55% error rate.",
        "mock_result": [
            {"REQUEST_METHOD": "DELETE", "TOTAL": 25205, "AUTH_FAILED": 2329, "SERVER_ERROR": 4620, "ERROR_RATE_PCT": 54.68},
            {"REQUEST_METHOD": "PUT", "TOTAL": 25188, "AUTH_FAILED": 2359, "SERVER_ERROR": 4578, "ERROR_RATE_PCT": 54.97},
            {"REQUEST_METHOD": "POST", "TOTAL": 24851, "AUTH_FAILED": 2378, "SERVER_ERROR": 4442, "ERROR_RATE_PCT": 54.37},
            {"REQUEST_METHOD": "GET", "TOTAL": 24756, "AUTH_FAILED": 2296, "SERVER_ERROR": 4414, "ERROR_RATE_PCT": 54.63},
        ],
        "display": "table",
        "rows_scanned": 100000,
    },
    "Status Code Distribution": {
        "spl": '| dbxquery connection="snowflake" query="SELECT CAST(STATUS_CODE AS VARCHAR) AS STATUS_CODE, COUNT(*) AS COUNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY STATUS_CODE ORDER BY COUNT DESC"',
        "sql": "SELECT CAST(STATUS_CODE AS VARCHAR) AS STATUS_CODE, COUNT(*) AS COUNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY STATUS_CODE ORDER BY COUNT DESC",
        "description": "Simple GROUP BY pushdown. 100K rows scanned, 11 rows returned.",
        "mock_result": [
            {"STATUS_CODE": "401", "COUNT": 9362}, {"STATUS_CODE": "503", "COUNT": 9209},
            {"STATUS_CODE": "500", "COUNT": 8845}, {"STATUS_CODE": "200", "COUNT": 9100},
            {"STATUS_CODE": "201", "COUNT": 9065}, {"STATUS_CODE": "301", "COUNT": 9098},
            {"STATUS_CODE": "302", "COUNT": 9040}, {"STATUS_CODE": "403", "COUNT": 9078},
            {"STATUS_CODE": "404", "COUNT": 9120}, {"STATUS_CODE": "204", "COUNT": 9042},
            {"STATUS_CODE": "502", "COUNT": 9041},
        ],
        "display": "bar",
        "rows_scanned": 100000,
    },
    "Request Method Distribution": {
        "spl": '| dbxquery connection="snowflake" query="SELECT REQUEST_METHOD, COUNT(*) AS COUNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY REQUEST_METHOD ORDER BY COUNT DESC"',
        "sql": "SELECT REQUEST_METHOD, COUNT(*) AS COUNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY REQUEST_METHOD ORDER BY COUNT DESC",
        "description": "HTTP method breakdown as pie chart.",
        "mock_result": [
            {"REQUEST_METHOD": "DELETE", "COUNT": 25205},
            {"REQUEST_METHOD": "PUT", "COUNT": 25188},
            {"REQUEST_METHOD": "POST", "COUNT": 24851},
            {"REQUEST_METHOD": "GET", "COUNT": 24756},
        ],
        "display": "pie",
        "rows_scanned": 100000,
    },
    "Endpoint Risk Assessment (CTE)": {
        "spl": '| dbxquery connection="snowflake" query="WITH path_analysis AS (SELECT SPLIT_PART(SPLIT_PART(REQUEST_PATH, \'/\', 2), \'/\', 1) AS ENDPOINT, COUNT(*) AS REQUESTS, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) AS AUTH_FAILURES, ROUND(100.0 * SUM(CASE WHEN STATUS_CODE >= 400 THEN 1 ELSE 0 END) / COUNT(*), 1) AS ERROR_RATE_PCT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY 1) SELECT ENDPOINT, REQUESTS, AUTH_FAILURES, ERROR_RATE_PCT, CASE WHEN AUTH_FAILURES > 1000 THEN \'HIGH_RISK\' WHEN AUTH_FAILURES > 500 THEN \'MEDIUM_RISK\' ELSE \'NORMAL\' END AS RISK FROM path_analysis ORDER BY REQUESTS DESC"',
        "sql": "WITH path_analysis AS (SELECT SPLIT_PART(SPLIT_PART(REQUEST_PATH, '/', 2), '/', 1) AS ENDPOINT, COUNT(*) AS REQUESTS, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) AS AUTH_FAILURES, ROUND(100.0 * SUM(CASE WHEN STATUS_CODE >= 400 THEN 1 ELSE 0 END) / COUNT(*), 1) AS ERROR_RATE_PCT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY 1) SELECT ENDPOINT, REQUESTS, AUTH_FAILURES, ERROR_RATE_PCT, CASE WHEN AUTH_FAILURES > 1000 THEN 'HIGH_RISK' WHEN AUTH_FAILURES > 500 THEN 'MEDIUM_RISK' ELSE 'NORMAL' END AS RISK FROM path_analysis ORDER BY REQUESTS DESC",
        "description": "CTE with CASE statements for threat classification — runs entirely on Snowflake compute.",
        "mock_result": [
            {"ENDPOINT": "logout", "REQUESTS": 12725, "AUTH_FAILURES": 1216, "ERROR_RATE_PCT": 54.8, "RISK": "HIGH_RISK"},
            {"ENDPOINT": "dashboard", "REQUESTS": 12594, "AUTH_FAILURES": 1172, "ERROR_RATE_PCT": 54.5, "RISK": "HIGH_RISK"},
            {"ENDPOINT": "login", "REQUESTS": 12525, "AUTH_FAILURES": 1165, "ERROR_RATE_PCT": 54.2, "RISK": "HIGH_RISK"},
            {"ENDPOINT": "home", "REQUESTS": 12509, "AUTH_FAILURES": 1116, "ERROR_RATE_PCT": 54.6, "RISK": "HIGH_RISK"},
            {"ENDPOINT": "api", "REQUESTS": 12480, "AUTH_FAILURES": 1098, "ERROR_RATE_PCT": 53.9, "RISK": "HIGH_RISK"},
            {"ENDPOINT": "search", "REQUESTS": 12430, "AUTH_FAILURES": 1080, "ERROR_RATE_PCT": 54.1, "RISK": "HIGH_RISK"},
            {"ENDPOINT": "profile", "REQUESTS": 12390, "AUTH_FAILURES": 1060, "ERROR_RATE_PCT": 53.7, "RISK": "HIGH_RISK"},
            {"ENDPOINT": "settings", "REQUESTS": 12347, "AUTH_FAILURES": 1055, "ERROR_RATE_PCT": 54.3, "RISK": "HIGH_RISK"},
        ],
        "display": "table",
        "rows_scanned": 100000,
    },
    "Backend Server Health (Top 10 Errors)": {
        "spl": '| dbxquery connection="snowflake" query="SELECT BACKEND_IP, COUNT(*) AS TOTAL_HITS, SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) AS SERVER_ERRORS, ROUND(100.0 * SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) / COUNT(*), 1) AS ERROR_RATE_PCT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY BACKEND_IP HAVING COUNT(*) >= 3 ORDER BY SERVER_ERRORS DESC LIMIT 10"',
        "sql": "SELECT BACKEND_IP, COUNT(*) AS TOTAL_HITS, SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) AS SERVER_ERRORS, ROUND(100.0 * SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) / COUNT(*), 1) AS ERROR_RATE_PCT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY BACKEND_IP HAVING COUNT(*) >= 3 ORDER BY SERVER_ERRORS DESC LIMIT 10",
        "description": "Find unhealthy backend servers by error rate.",
        "mock_result": [
            {"BACKEND_IP": "10.0.148.72", "TOTAL_HITS": 5, "SERVER_ERRORS": 4, "ERROR_RATE_PCT": 80.0},
            {"BACKEND_IP": "10.0.31.205", "TOTAL_HITS": 4, "SERVER_ERRORS": 3, "ERROR_RATE_PCT": 75.0},
            {"BACKEND_IP": "10.0.92.118", "TOTAL_HITS": 5, "SERVER_ERRORS": 3, "ERROR_RATE_PCT": 60.0},
            {"BACKEND_IP": "10.0.7.44", "TOTAL_HITS": 4, "SERVER_ERRORS": 3, "ERROR_RATE_PCT": 75.0},
            {"BACKEND_IP": "10.0.201.55", "TOTAL_HITS": 6, "SERVER_ERRORS": 3, "ERROR_RATE_PCT": 50.0},
            {"BACKEND_IP": "10.0.165.90", "TOTAL_HITS": 3, "SERVER_ERRORS": 3, "ERROR_RATE_PCT": 100.0},
            {"BACKEND_IP": "10.0.88.133", "TOTAL_HITS": 4, "SERVER_ERRORS": 2, "ERROR_RATE_PCT": 50.0},
            {"BACKEND_IP": "10.0.53.201", "TOTAL_HITS": 3, "SERVER_ERRORS": 2, "ERROR_RATE_PCT": 66.7},
            {"BACKEND_IP": "10.0.112.77", "TOTAL_HITS": 5, "SERVER_ERRORS": 2, "ERROR_RATE_PCT": 40.0},
            {"BACKEND_IP": "10.0.9.160", "TOTAL_HITS": 3, "SERVER_ERRORS": 2, "ERROR_RATE_PCT": 66.7},
        ],
        "display": "table",
        "rows_scanned": 100000,
    },
    "Data Exfiltration Detection (High Bytes)": {
        "spl": '| dbxquery connection="snowflake" query="SELECT IP_ADDRESS, REQUEST_METHOD, STATUS_CODE, BYTES_SENT FROM CTF.PUBLIC.ACCESS_LOGS WHERE BYTES_SENT > 9000 ORDER BY BYTES_SENT DESC LIMIT 10"',
        "sql": "SELECT IP_ADDRESS, REQUEST_METHOD, STATUS_CODE, BYTES_SENT FROM CTF.PUBLIC.ACCESS_LOGS WHERE BYTES_SENT > 9000 ORDER BY BYTES_SENT DESC LIMIT 10",
        "description": "WHERE clause filter pushdown. Find large data transfers.",
        "mock_result": [
            {"IP_ADDRESS": "203.0.113.42", "REQUEST_METHOD": "GET", "STATUS_CODE": 200, "BYTES_SENT": 9987},
            {"IP_ADDRESS": "198.51.100.88", "REQUEST_METHOD": "GET", "STATUS_CODE": 200, "BYTES_SENT": 9945},
            {"IP_ADDRESS": "192.0.2.155", "REQUEST_METHOD": "POST", "STATUS_CODE": 200, "BYTES_SENT": 9901},
            {"IP_ADDRESS": "10.45.12.33", "REQUEST_METHOD": "GET", "STATUS_CODE": 301, "BYTES_SENT": 9876},
            {"IP_ADDRESS": "172.16.0.44", "REQUEST_METHOD": "GET", "STATUS_CODE": 200, "BYTES_SENT": 9834},
            {"IP_ADDRESS": "203.0.113.99", "REQUEST_METHOD": "PUT", "STATUS_CODE": 201, "BYTES_SENT": 9798},
            {"IP_ADDRESS": "198.51.100.12", "REQUEST_METHOD": "GET", "STATUS_CODE": 200, "BYTES_SENT": 9756},
            {"IP_ADDRESS": "192.0.2.78", "REQUEST_METHOD": "DELETE", "STATUS_CODE": 200, "BYTES_SENT": 9712},
            {"IP_ADDRESS": "10.99.0.5", "REQUEST_METHOD": "GET", "STATUS_CODE": 200, "BYTES_SENT": 9688},
            {"IP_ADDRESS": "172.16.5.201", "REQUEST_METHOD": "POST", "STATUS_CODE": 200, "BYTES_SENT": 9654},
        ],
        "display": "table",
        "rows_scanned": 100000,
    },
    "Z-Score Anomaly Detection": {
        "spl": '| dbxquery connection="snowflake" query="WITH stats AS (SELECT IP_ADDRESS, COUNT(*) AS REQUESTS, AVG(COUNT(*)) OVER() AS AVG_REQUESTS, STDDEV(COUNT(*)) OVER() AS STDDEV_REQUESTS FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY IP_ADDRESS) SELECT IP_ADDRESS, REQUESTS, ROUND((REQUESTS - AVG_REQUESTS) / NULLIF(STDDEV_REQUESTS, 0), 2) AS Z_SCORE FROM stats WHERE ABS((REQUESTS - AVG_REQUESTS) / NULLIF(STDDEV_REQUESTS, 0)) > 2 ORDER BY Z_SCORE DESC LIMIT 10"',
        "sql": "WITH stats AS (SELECT IP_ADDRESS, COUNT(*) AS REQUESTS, AVG(COUNT(*)) OVER() AS AVG_REQUESTS, STDDEV(COUNT(*)) OVER() AS STDDEV_REQUESTS FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY IP_ADDRESS) SELECT IP_ADDRESS, REQUESTS, ROUND((REQUESTS - AVG_REQUESTS) / NULLIF(STDDEV_REQUESTS, 0), 2) AS Z_SCORE FROM stats WHERE ABS((REQUESTS - AVG_REQUESTS) / NULLIF(STDDEV_REQUESTS, 0)) > 2 ORDER BY Z_SCORE DESC LIMIT 10",
        "description": "Statistical anomaly detection via window functions. Finds IPs with request volumes > 2 standard deviations from the mean.",
        "mock_result": [
            {"IP_ADDRESS": "45.33.32.156", "REQUESTS": 8, "Z_SCORE": 6.72},
            {"IP_ADDRESS": "91.189.92.10", "REQUESTS": 7, "Z_SCORE": 5.68},
            {"IP_ADDRESS": "104.16.249.5", "REQUESTS": 6, "Z_SCORE": 4.65},
            {"IP_ADDRESS": "185.199.108.1", "REQUESTS": 5, "Z_SCORE": 3.61},
            {"IP_ADDRESS": "151.101.1.140", "REQUESTS": 5, "Z_SCORE": 3.61},
            {"IP_ADDRESS": "13.107.42.14", "REQUESTS": 4, "Z_SCORE": 2.58},
            {"IP_ADDRESS": "52.85.132.99", "REQUESTS": 4, "Z_SCORE": 2.58},
            {"IP_ADDRESS": "99.84.191.44", "REQUESTS": 4, "Z_SCORE": 2.58},
        ],
        "display": "table",
        "rows_scanned": 100000,
    },
}

# ---------------------------------------------------------------------------
# Snowflake connection helpers
# ---------------------------------------------------------------------------

def get_snowflake_connection(account, user, password):
    """Establish a Snowflake connection. Returns (conn, error_msg)."""
    try:
        import snowflake.connector
        conn = snowflake.connector.connect(
            account=account, user=user, password=password,
            warehouse="COMPUTE_WH", database="CTF", schema="PUBLIC",
        )
        return conn, None
    except ImportError:
        return None, "snowflake-connector-python not installed. Run: pip install snowflake-connector-python"
    except Exception as e:
        return None, str(e)


def run_live_query(conn, sql):
    """Execute SQL against Snowflake. Returns (df, duration_sec, error)."""
    try:
        start = time.time()
        cursor = conn.cursor()
        cursor.execute(sql)
        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()
        duration = time.time() - start
        df = pd.DataFrame(rows, columns=columns)
        cursor.close()
        return df, duration, None
    except Exception as e:
        return None, 0, str(e)


def run_mock_query(mock_result):
    """Simulate a query with realistic latency. Returns (df, duration_sec)."""
    duration = random.uniform(1.2, 2.8)
    time.sleep(min(duration, 1.5))  # cap actual wait for UX
    df = pd.DataFrame(mock_result)
    return df, duration


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def render_search_bar(spl_text):
    """Render a Splunk-like green search bar."""
    st.markdown(
        f'<div class="search-bar"><div class="search-bar-text">{spl_text}</div></div>',
        unsafe_allow_html=True,
    )


def render_job_inspector(num_results, duration, rows_scanned):
    """Render a simulated Splunk Job Inspector panel."""
    st.markdown(f"""
<div class="job-inspector">
<strong>Job Inspector</strong>
<hr style="border-color:#2B2F35; margin:8px 0">
This search has completed and returned <strong>{num_results} results</strong>
by scanning <span class="zero">0 events</span> in <strong>{duration:.1f} seconds</strong>
<br><br>
<table style="width:100%; color:#9DA8B5; font-size:13px">
<tr style="border-bottom:1px solid #2B2F35">
    <td style="padding:4px 8px"><strong>Component</strong></td>
    <td style="padding:4px 8px"><strong>Duration</strong></td>
    <td style="padding:4px 8px"><strong>Input</strong></td>
    <td style="padding:4px 8px"><strong>Output</strong></td>
</tr>
<tr>
    <td style="padding:4px 8px">command.dbxquery</td>
    <td style="padding:4px 8px">{duration:.2f}s</td>
    <td style="padding:4px 8px">-</td>
    <td style="padding:4px 8px"><span class="highlight">{num_results}</span></td>
</tr>
<tr>
    <td style="padding:4px 8px">dispatch.evaluate</td>
    <td style="padding:4px 8px">0.00s</td>
    <td style="padding:4px 8px">-</td>
    <td style="padding:4px 8px">-</td>
</tr>
</table>
<br>
<span class="highlight">KEY INSIGHT:</span> Splunk scanned <span class="zero">0 events</span>.
All compute happened in Snowflake ({rows_scanned:,} rows scanned there).
Splunk only received {num_results} aggregated result{"s" if num_results != 1 else ""}.
</div>
""", unsafe_allow_html=True)


def render_result(df, display_type, query_name=""):
    """Render query results based on display type."""
    if display_type == "metrics" and len(df) == 1:
        cols = st.columns(len(df.columns))
        for i, col_name in enumerate(df.columns):
            val = df.iloc[0][col_name]
            label = col_name.replace("_", " ").title()
            cols[i].metric(label, f"{int(val):,}")

    elif display_type == "bar":
        x_col = df.columns[0]
        y_col = df.columns[1]
        st.bar_chart(df.set_index(x_col)[y_col])

    elif display_type == "pie":
        import plotly.express as px
        label_col = df.columns[0]
        value_col = df.columns[1]
        fig = px.pie(df, names=label_col, values=value_col, hole=0.3)
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#C3CBD4", showlegend=True,
            margin=dict(t=20, b=20, l=20, r=20),
            height=350,
        )
        fig.update_traces(
            marker=dict(colors=["#00C853", "#2196F3", "#FF9800", "#E91E63", "#9C27B0"]),
            textinfo="label+percent",
        )
        st.plotly_chart(fig, use_container_width=True)

    else:  # table
        st.dataframe(df, width="stretch", hide_index=True)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("### Data Source")
    live_mode = st.toggle("Live Snowflake", value=False, help="Connect to real Snowflake instance")

    sf_conn = None
    if live_mode:
        st.markdown("---")
        st.markdown("### Snowflake Connection")
        sf_account = st.text_input("Account", placeholder="your_account_id")
        sf_user = st.text_input("User", placeholder="your_username")
        sf_password = st.text_input("Password", type="password")

        if sf_account and sf_user and sf_password:
            sf_conn, sf_err = get_snowflake_connection(sf_account, sf_user, sf_password)
            if sf_err:
                st.error(f"Connection failed: {sf_err}")
            else:
                st.success("Connected")
        else:
            st.info("Enter credentials to connect")
    else:
        st.caption("Using embedded mock data. Toggle 'Live Snowflake' to connect to real data.")

    st.markdown("---")
    st.markdown("### About")
    st.caption(
        "This app simulates the Splunk Web interface showing federated search queries "
        "hitting Snowflake via DB Connect. It demonstrates how Splunk offloads compute "
        "to Snowflake while scanning 0 events locally."
    )
    st.caption("Source: [splunk-snowflake-security-datalake](https://github.com/sfc-gh-kkeller/splunk-snowflake-security-datalake)")


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.markdown("# Splunk + Snowflake Federated Search")

mode_label = "LIVE SNOWFLAKE" if live_mode else "MOCK DATA"
mode_color = "#00C853" if not live_mode else "#2196F3"
st.markdown(
    f'<div class="info-banner">'
    f'<strong>Mode:</strong> <span style="color:{mode_color}">{mode_label}</span> &nbsp;|&nbsp; '
    f'<strong>Database:</strong> CTF.PUBLIC &nbsp;|&nbsp; '
    f'<strong>Connection:</strong> snowflake (DB Connect) &nbsp;|&nbsp; '
    f'<strong>Rows:</strong> 100,000 access logs + 15K vulns + 844 assets + 106 findings'
    f'</div>',
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Main tabs
# ---------------------------------------------------------------------------

tab_dashboard, tab_search = st.tabs(["Dashboard", "Search"])


# ===========================================================================
# DASHBOARD TAB
# ===========================================================================

with tab_dashboard:

    def execute_query(query_key):
        """Run a query in the current mode. Returns (df, duration, num_results, rows_scanned)."""
        q = DEMO_QUERIES[query_key]
        if live_mode and sf_conn:
            df, dur, err = run_live_query(sf_conn, q["sql"])
            if err:
                st.error(f"Query failed: {err}")
                return None, 0, 0, q["rows_scanned"]
            return df, dur, len(df), q["rows_scanned"]
        else:
            df, dur = run_mock_query(q["mock_result"])
            return df, dur, len(df), q["rows_scanned"]

    # Row 1: KPI Metrics
    st.markdown('<div class="panel-header">Security Overview (Aggregation Pushdown)</div>', unsafe_allow_html=True)
    df_kpi, dur_kpi, _, _ = execute_query("Security Overview (Aggregation Pushdown)")
    if df_kpi is not None:
        kpi_cols = st.columns(5)
        labels = {
            "TOTAL_REQUESTS": "Total Requests",
            "UNIQUE_IPS": "Unique IPs",
            "AUTH_FAILURES": "Auth Failures (401)",
            "SERVER_ERRORS": "Server Errors (5xx)",
            "DELETE_OPS": "DELETE Operations",
        }
        for i, (col_name, label) in enumerate(labels.items()):
            val = int(df_kpi.iloc[0][col_name])
            kpi_cols[i].metric(label, f"{val:,}")

        with st.expander("Job Inspector", expanded=False):
            render_job_inspector(1, dur_kpi, 100000)

    st.markdown("")

    # Row 2: Charts
    col_pie, col_bar = st.columns(2)

    with col_pie:
        st.markdown('<div class="panel-header">Request Method Distribution</div>', unsafe_allow_html=True)
        df_pie, _, _, _ = execute_query("Request Method Distribution")
        if df_pie is not None:
            render_result(df_pie, "pie")

    with col_bar:
        st.markdown('<div class="panel-header">Status Code Distribution</div>', unsafe_allow_html=True)
        df_bar, _, _, _ = execute_query("Status Code Distribution")
        if df_bar is not None:
            render_result(df_bar, "bar")

    st.markdown("")

    # Row 3: Risk Assessment
    st.markdown('<div class="panel-header">Endpoint Risk Assessment (CTE - runs entirely on Snowflake)</div>', unsafe_allow_html=True)
    df_risk, dur_risk, n_risk, _ = execute_query("Endpoint Risk Assessment (CTE)")
    if df_risk is not None:
        st.dataframe(df_risk, width="stretch", hide_index=True)
        with st.expander("Job Inspector", expanded=False):
            render_job_inspector(n_risk, dur_risk, 100000)

    st.markdown("")

    # Row 4: Backend Health + Anomalies
    col_backend, col_anomaly = st.columns(2)

    with col_backend:
        st.markdown('<div class="panel-header">Backend Server Health (Top 10)</div>', unsafe_allow_html=True)
        df_be, _, _, _ = execute_query("Backend Server Health (Top 10 Errors)")
        if df_be is not None:
            st.dataframe(df_be, width="stretch", hide_index=True)

    with col_anomaly:
        st.markdown('<div class="panel-header">Anomalous IPs (Z-Score > 2)</div>', unsafe_allow_html=True)
        df_zs, _, _, _ = execute_query("Z-Score Anomaly Detection")
        if df_zs is not None:
            st.dataframe(df_zs, width="stretch", hide_index=True)


# ===========================================================================
# SEARCH TAB
# ===========================================================================

with tab_search:
    st.markdown("### Splunk Search")

    query_name = st.selectbox(
        "Select a pre-built query:",
        list(DEMO_QUERIES.keys()),
        index=0,
    )

    q = DEMO_QUERIES[query_name]

    # Show the SPL and description
    render_search_bar(q["spl"])
    st.caption(q["description"])

    # SQL being pushed to Snowflake
    with st.expander("SQL pushed to Snowflake", expanded=False):
        st.code(q["sql"], language="sql")

    # Search button
    if st.button("Search", type="primary", width="stretch"):
        with st.spinner("Querying Snowflake... (0 Splunk events scanned)"):
            if live_mode and sf_conn:
                df, duration, err = run_live_query(sf_conn, q["sql"])
                if err:
                    st.error(f"Query failed: {err}")
                    df = None
            else:
                df, duration = run_mock_query(q["mock_result"])

        if df is not None:
            num_results = len(df)
            rows_scanned = q["rows_scanned"]

            # Results header
            st.markdown(
                f"**{num_results} results** &nbsp; | &nbsp; "
                f"Snowflake rows scanned: {rows_scanned:,} &nbsp; | &nbsp; "
                f"Splunk events scanned: **0** &nbsp; | &nbsp; "
                f"Duration: {duration:.1f}s"
            )

            st.markdown("---")

            # Render the results
            render_result(df, q["display"], query_name)

            st.markdown("---")

            # Job Inspector
            render_job_inspector(num_results, duration, rows_scanned)

            # Cost callout
            st.markdown("")
            st.markdown(
                f'<div class="info-banner">'
                f'<strong>Cost Impact:</strong> This query scanned {rows_scanned:,} rows in Snowflake '
                f'but returned only {num_results} aggregated results to Splunk. '
                f'Splunk license cost for this query: <strong style="color:#00C853">$0</strong> '
                f'(0 events scanned = no ingestion cost). '
                f'Storing this data in Snowflake costs ~$0.02/GB/month vs ~$150/GB/month in Splunk.'
                f'</div>',
                unsafe_allow_html=True,
            )
