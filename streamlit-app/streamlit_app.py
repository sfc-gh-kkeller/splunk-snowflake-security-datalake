#!/usr/bin/env python3
"""
Splunk + Snowflake Federated Search Demo — Streamlit in Snowflake
=================================================================
Runs live queries against CTF.PUBLIC.* tables in your Snowflake account.
Simulates the Splunk DB Connect federated search experience.
"""

import time
import streamlit as st
import pandas as pd
import altair as alt

st.set_page_config(page_title="Splunk + Snowflake Federated Search", layout="wide")

# ---------------------------------------------------------------------------
# Snowflake session — works in both legacy warehouse SiS and container runtime
# ---------------------------------------------------------------------------
try:
    conn = st.connection("snowflake")
    def run_query(sql):
        start = time.time()
        df = conn.query(sql)
        return df, time.time() - start
except AttributeError:
    from snowflake.snowpark.context import get_active_session
    _session = get_active_session()
    def run_query(sql):
        start = time.time()
        df = _session.sql(sql).to_pandas()
        return df, time.time() - start

# ---------------------------------------------------------------------------
# Dark theme CSS
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    [data-testid="stMetric"] {
        background-color: #1A1C20; border: 1px solid #2B2F35;
        border-radius: 6px; padding: 16px;
    }
    .search-bar { background-color: #00C853; padding: 8px 16px; border-radius: 6px; margin-bottom: 16px; }
    .search-bar-text { color: #000; font-family: 'Courier New', monospace; font-size: 13px; word-break: break-all; }
    .job-inspector {
        background-color: #1A1C20; border: 1px solid #2B2F35; border-radius: 6px;
        padding: 16px; font-family: 'Courier New', monospace; font-size: 13px;
    }
    .job-inspector .highlight { color: #00C853; font-weight: bold; }
    .info-banner {
        background: linear-gradient(135deg, #1A3A1A 0%, #1A1C20 100%);
        border: 1px solid #00C853; border-radius: 6px; padding: 12px 20px; margin-bottom: 20px;
    }
    .info-banner strong { color: #00C853; }
    .panel-header {
        background-color: #1A1C20; border: 1px solid #2B2F35;
        border-radius: 6px 6px 0 0; padding: 10px 16px; font-weight: 600; font-size: 14px;
    }
</style>
""", unsafe_allow_html=True)



DEMO_QUERIES = {
    "Security Overview (Aggregation Pushdown)": {
        "spl": '| dbxquery connection="snowflake" query="SELECT COUNT(*) AS TOTAL_REQUESTS, COUNT(DISTINCT IP_ADDRESS) AS UNIQUE_IPS, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) AS AUTH_FAILURES, SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) AS SERVER_ERRORS, SUM(CASE WHEN REQUEST_METHOD = \'DELETE\' THEN 1 ELSE 0 END) AS DELETE_OPS FROM CTF.PUBLIC.ACCESS_LOGS"',
        "sql": "SELECT COUNT(*) AS TOTAL_REQUESTS, COUNT(DISTINCT IP_ADDRESS) AS UNIQUE_IPS, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) AS AUTH_FAILURES, SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) AS SERVER_ERRORS, SUM(CASE WHEN REQUEST_METHOD = 'DELETE' THEN 1 ELSE 0 END) AS DELETE_OPS FROM CTF.PUBLIC.ACCESS_LOGS",
        "description": "Snowflake scans 100,000 rows but returns only 1 row with 5 metrics to Splunk.",
        "display": "metrics",
        "rows_scanned": 100000,
    },
    "Threat Analysis by HTTP Method": {
        "spl": '| dbxquery connection="snowflake" query="SELECT REQUEST_METHOD, COUNT(*) AS TOTAL, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) AS AUTH_FAILED, ROUND(100.0 * SUM(CASE WHEN STATUS_CODE >= 400 THEN 1 ELSE 0 END) / COUNT(*), 2) AS ERROR_RATE_PCT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY REQUEST_METHOD ORDER BY TOTAL DESC"',
        "sql": "SELECT REQUEST_METHOD, COUNT(*) AS TOTAL, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) AS AUTH_FAILED, ROUND(100.0 * SUM(CASE WHEN STATUS_CODE >= 400 THEN 1 ELSE 0 END) / COUNT(*), 2) AS ERROR_RATE_PCT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY REQUEST_METHOD ORDER BY TOTAL DESC",
        "description": "Security analytics by HTTP method. ~25% DELETE with ~55% error rate.",
        "display": "table",
        "rows_scanned": 100000,
    },
    "Status Code Distribution": {
        "spl": '| dbxquery connection="snowflake" query="SELECT CAST(STATUS_CODE AS VARCHAR) AS STATUS_CODE, COUNT(*) AS COUNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY STATUS_CODE ORDER BY COUNT DESC"',
        "sql": "SELECT CAST(STATUS_CODE AS VARCHAR) AS STATUS_CODE, COUNT(*) AS COUNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY STATUS_CODE ORDER BY COUNT DESC",
        "description": "Simple GROUP BY pushdown. 100K rows scanned, 11 rows returned.",
        "display": "bar",
        "rows_scanned": 100000,
    },
    "Request Method Distribution": {
        "spl": '| dbxquery connection="snowflake" query="SELECT REQUEST_METHOD, COUNT(*) AS COUNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY REQUEST_METHOD ORDER BY COUNT DESC"',
        "sql": "SELECT REQUEST_METHOD, COUNT(*) AS COUNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY REQUEST_METHOD ORDER BY COUNT DESC",
        "description": "HTTP method breakdown as pie chart.",
        "display": "pie",
        "rows_scanned": 100000,
    },
    "Endpoint Risk Assessment (CTE)": {
        "spl": '| dbxquery connection="snowflake" query="WITH path_analysis AS (...) SELECT ENDPOINT, REQUESTS, AUTH_FAILURES, ERROR_RATE_PCT, RISK FROM path_analysis ORDER BY REQUESTS DESC"',
        "sql": "WITH path_analysis AS (SELECT SPLIT_PART(SPLIT_PART(REQUEST_PATH, '/', 2), '/', 1) AS ENDPOINT, COUNT(*) AS REQUESTS, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) AS AUTH_FAILURES, ROUND(100.0 * SUM(CASE WHEN STATUS_CODE >= 400 THEN 1 ELSE 0 END) / COUNT(*), 1) AS ERROR_RATE_PCT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY 1) SELECT ENDPOINT, REQUESTS, AUTH_FAILURES, ERROR_RATE_PCT, CASE WHEN AUTH_FAILURES > 1000 THEN 'HIGH_RISK' WHEN AUTH_FAILURES > 500 THEN 'MEDIUM_RISK' ELSE 'NORMAL' END AS RISK FROM path_analysis ORDER BY REQUESTS DESC",
        "description": "CTE with CASE statements for threat classification -- runs entirely on Snowflake.",
        "display": "table",
        "rows_scanned": 100000,
    },
    "Backend Server Health (Top 10)": {
        "spl": '| dbxquery connection="snowflake" query="SELECT BACKEND_IP, COUNT(*) AS TOTAL_HITS, ... ORDER BY SERVER_ERRORS DESC LIMIT 10"',
        "sql": "SELECT BACKEND_IP, COUNT(*) AS TOTAL_HITS, SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) AS SERVER_ERRORS, ROUND(100.0 * SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) / COUNT(*), 1) AS ERROR_RATE_PCT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY BACKEND_IP HAVING COUNT(*) >= 3 ORDER BY SERVER_ERRORS DESC LIMIT 10",
        "description": "Find unhealthy backend servers by error rate.",
        "display": "table",
        "rows_scanned": 100000,
    },
    "Z-Score Anomaly Detection": {
        "spl": '| dbxquery connection="snowflake" query="WITH stats AS (...) SELECT IP_ADDRESS, REQUESTS, Z_SCORE ... WHERE Z_SCORE > 2"',
        "sql": "WITH stats AS (SELECT IP_ADDRESS, COUNT(*) AS REQUESTS, AVG(COUNT(*)) OVER() AS AVG_REQUESTS, STDDEV(COUNT(*)) OVER() AS STDDEV_REQUESTS FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY IP_ADDRESS) SELECT IP_ADDRESS, REQUESTS, ROUND((REQUESTS - AVG_REQUESTS) / NULLIF(STDDEV_REQUESTS, 0), 2) AS Z_SCORE FROM stats WHERE ABS((REQUESTS - AVG_REQUESTS) / NULLIF(STDDEV_REQUESTS, 0)) > 2 ORDER BY Z_SCORE DESC LIMIT 10",
        "description": "Statistical anomaly detection via window functions.",
        "display": "table",
        "rows_scanned": 100000,
    },
}



def render_job_inspector(num_results, duration, rows_scanned):
    st.markdown(f"""
<div class="job-inspector">
<strong>Job Inspector</strong>
<hr style="border-color:#2B2F35; margin:8px 0">
This search has completed and returned <strong>{num_results} results</strong>
by scanning <span class="highlight" style="font-size:16px">0 events</span> in <strong>{duration:.1f} seconds</strong>
<br><br>
<table style="width:100%; font-size:13px">
<tr style="border-bottom:1px solid #2B2F35">
    <td style="padding:4px 8px"><strong>Component</strong></td>
    <td style="padding:4px 8px"><strong>Duration</strong></td>
    <td style="padding:4px 8px"><strong>Output</strong></td>
</tr>
<tr>
    <td style="padding:4px 8px">command.dbxquery</td>
    <td style="padding:4px 8px">{duration:.2f}s</td>
    <td style="padding:4px 8px"><span class="highlight">{num_results}</span></td>
</tr>
<tr>
    <td style="padding:4px 8px">dispatch.evaluate</td>
    <td style="padding:4px 8px">0.00s</td>
    <td style="padding:4px 8px">-</td>
</tr>
</table>
<br>
<span class="highlight">KEY INSIGHT:</span> Splunk scanned <span class="highlight" style="font-size:16px">0 events</span>.
All compute happened in Snowflake ({rows_scanned:,} rows scanned).
Splunk received {num_results} aggregated result{"s" if num_results != 1 else ""}.
</div>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.markdown("# Splunk + Snowflake Federated Search")
st.markdown(
    '<div class="info-banner">'
    '<strong>Live Snowflake</strong> | '
    '<strong>Database:</strong> CTF.PUBLIC | '
    '<strong>Connection:</strong> snowflake (DB Connect) | '
    '<strong>Data:</strong> 100K access logs + 15K vulns + 844 assets + 106 findings'
    '</div>',
    unsafe_allow_html=True,
)

tab_dashboard, tab_search = st.tabs(["Dashboard", "Search"])

# ===========================================================================
# DASHBOARD TAB
# ===========================================================================
with tab_dashboard:

    # KPIs
    st.markdown('<div class="panel-header">Security Overview (Aggregation Pushdown)</div>', unsafe_allow_html=True)
    df_kpi, dur_kpi = run_query(DEMO_QUERIES["Security Overview (Aggregation Pushdown)"]["sql"])
    kpi_cols = st.columns(5)
    labels = ["Total Requests", "Unique IPs", "Auth Failures (401)", "Server Errors (5xx)", "DELETE Ops"]
    for i, label in enumerate(labels):
        kpi_cols[i].metric(label, f"{int(df_kpi.iloc[0, i]):,}")
    with st.expander("Job Inspector"):
        render_job_inspector(1, dur_kpi, 100000)

    st.markdown("")
    col_pie, col_bar = st.columns(2)

    with col_pie:
        st.markdown('<div class="panel-header">Request Method Distribution</div>', unsafe_allow_html=True)
        df_pie, _ = run_query(DEMO_QUERIES["Request Method Distribution"]["sql"])
        pie_chart = alt.Chart(df_pie).mark_arc(innerRadius=50).encode(
            theta=alt.Theta("COUNT:Q"),
            color=alt.Color("REQUEST_METHOD:N", scale=alt.Scale(
                domain=["DELETE", "PUT", "POST", "GET"],
                range=["#00C853", "#2196F3", "#FF9800", "#E91E63"]
            )),
            tooltip=["REQUEST_METHOD", "COUNT"],
        ).properties(height=350)
        st.altair_chart(pie_chart, use_container_width=True)

    with col_bar:
        st.markdown('<div class="panel-header">Status Code Distribution</div>', unsafe_allow_html=True)
        df_bar, _ = run_query(DEMO_QUERIES["Status Code Distribution"]["sql"])
        st.bar_chart(df_bar.set_index("STATUS_CODE")["COUNT"])

    st.markdown("")
    st.markdown('<div class="panel-header">Endpoint Risk Assessment (CTE)</div>', unsafe_allow_html=True)
    df_risk, dur_risk = run_query(DEMO_QUERIES["Endpoint Risk Assessment (CTE)"]["sql"])
    st.dataframe(df_risk, width="stretch", hide_index=True)
    with st.expander("Job Inspector"):
        render_job_inspector(len(df_risk), dur_risk, 100000)

    st.markdown("")
    col_be, col_zs = st.columns(2)
    with col_be:
        st.markdown('<div class="panel-header">Backend Server Health (Top 10)</div>', unsafe_allow_html=True)
        df_be, _ = run_query(DEMO_QUERIES["Backend Server Health (Top 10)"]["sql"])
        st.dataframe(df_be, width="stretch", hide_index=True)
    with col_zs:
        st.markdown('<div class="panel-header">Anomalous IPs (Z-Score > 2)</div>', unsafe_allow_html=True)
        df_zs, _ = run_query(DEMO_QUERIES["Z-Score Anomaly Detection"]["sql"])
        st.dataframe(df_zs, width="stretch", hide_index=True)


# ===========================================================================
# SEARCH TAB
# ===========================================================================
with tab_search:
    st.markdown("### Splunk Search")
    query_name = st.selectbox("Select a pre-built query:", list(DEMO_QUERIES.keys()))
    q = DEMO_QUERIES[query_name]

    st.markdown(f'<div class="search-bar"><div class="search-bar-text">{q["spl"]}</div></div>', unsafe_allow_html=True)
    st.caption(q["description"])
    with st.expander("SQL pushed to Snowflake"):
        st.code(q["sql"], language="sql")

    if st.button("Search", type="primary", use_container_width=True):
        with st.spinner("Querying Snowflake... (0 Splunk events scanned)"):
            df, duration = run_query(q["sql"])

        num_results = len(df)
        st.markdown(
            f"**{num_results} results** | Snowflake rows scanned: {q['rows_scanned']:,} | "
            f"Splunk events scanned: **0** | Duration: {duration:.1f}s"
        )
        st.markdown("---")

        if q["display"] == "metrics" and len(df) == 1:
            cols = st.columns(len(df.columns))
            for i, col_name in enumerate(df.columns):
                cols[i].metric(col_name.replace("_", " ").title(), f"{int(df.iloc[0][col_name]):,}")
        elif q["display"] == "pie":
            pie_chart = alt.Chart(df).mark_arc(innerRadius=50).encode(
                theta=alt.Theta(f"{df.columns[1]}:Q"),
                color=alt.Color(f"{df.columns[0]}:N"),
                tooltip=[df.columns[0], df.columns[1]],
            ).properties(height=350)
            st.altair_chart(pie_chart, use_container_width=True)
        elif q["display"] == "bar":
            st.bar_chart(df.set_index(df.columns[0])[df.columns[1]])
        else:
            st.dataframe(df, width="stretch", hide_index=True)

        st.markdown("---")
        render_job_inspector(num_results, duration, q["rows_scanned"])

        st.markdown(
            f'<div class="info-banner">'
            f'<strong>Cost Impact:</strong> {q["rows_scanned"]:,} rows scanned in Snowflake, '
            f'{num_results} results returned. Splunk license cost: '
            f'<strong style="color:#00C853">$0</strong> (0 events scanned).'
            f'</div>', unsafe_allow_html=True,
        )
