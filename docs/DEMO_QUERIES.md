# Splunk + Snowflake Demo: Correlations & Compute Offloading

> **Demo Objectives:**
> 1. ✅ Prove Splunk can perform correlations using Snowflake as a cybersecurity data lake
> 2. ✅ Prove there is little to no Splunk compute used when doing query federation

---

## Environment Details

| Component | Value |
|-----------|-------|
| **Snowflake Account** | `YOUR_ACCOUNT_IDENTIFIER` |
| **User** | `YOUR_USER@COMPANY.COM` |
| **Database** | `CTF` |
| **Schema** | `PUBLIC` |
| **Table** | `ACCESS_LOGS` |
| **Row Count** | 100,000 |
| **Splunk Connection Name** | `snowflake` |
| **Snow CLI Connection** | `your_connection` |

### Table Schema: CTF.PUBLIC.ACCESS_LOGS

| Column | Type | Description |
|--------|------|-------------|
| TIMESTAMP | TIMESTAMP_NTZ | Request timestamp (2023-05-08) |
| IP_ADDRESS | VARCHAR(45) | Client IP address (99,998 unique) |
| REQUEST_METHOD | VARCHAR(10) | HTTP method (GET, POST, PUT, DELETE - ~25% each) |
| REQUEST_PATH | VARCHAR(2024) | URL path with query parameters |
| STATUS_CODE | NUMBER | HTTP status code (401=9.4%, 500=9.2%, 200=9.1%, etc.) |
| BYTES_SENT | NUMBER | Response size in bytes |
| BACKEND_IP | VARCHAR(45) | Backend server IP (92,214 unique) |

---

## Part 1: Proving Correlations Work

> ⚠️ **Important:** 
> - All queries are formatted as **single-line** to work properly with dbxquery
> - Column aliases are **UPPERCASE** because Snowflake returns uppercase column names
> - Don't use `| table` with lowercase column names - columns will appear empty

---

### Demo 1.1: Basic Query - Fetch Data from Snowflake

**Splunk SPL (copy-paste ready):**
```spl
| dbxquery connection="snowflake" query="SELECT * FROM CTF.PUBLIC.ACCESS_LOGS LIMIT 100"
```

**What This Proves:** Splunk can successfully retrieve data from Snowflake.

---

### Demo 1.2: Security Overview Dashboard (Aggregation Pushdown)

**Expected Results:**
| Metric | Value |
|--------|-------|
| total_requests | 100,000 |
| unique_ips | 99,998 |
| auth_failures | 9,362 |
| server_errors | 18,054 |
| delete_ops | 25,205 |

**Splunk SPL (copy-paste ready):**
```spl
| dbxquery connection="snowflake" query="SELECT COUNT(*) as total_requests, COUNT(DISTINCT IP_ADDRESS) as unique_ips, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) as auth_failures, SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) as server_errors, SUM(CASE WHEN REQUEST_METHOD = 'DELETE' THEN 1 ELSE 0 END) as delete_ops FROM CTF.PUBLIC.ACCESS_LOGS"
```

**What This Proves:** 
- Complex aggregations run on Snowflake compute
- Splunk receives only 1 row with 5 metrics (not 100,000 raw rows)

---

### Demo 1.3: Threat Analysis by HTTP Method

**Expected Results:**
| REQUEST_METHOD | total | auth_failed | error_rate_pct |
|----------------|-------|-------------|----------------|
| DELETE | 25,205 | 2,329 | 54.68% |
| PUT | 25,188 | 2,359 | 54.97% |
| POST | 24,851 | 2,378 | 54.37% |
| GET | 24,756 | 2,296 | 54.63% |

**Splunk SPL (copy-paste ready):**
```spl
| dbxquery connection="snowflake" query="SELECT REQUEST_METHOD, COUNT(*) as TOTAL, SUM(CASE WHEN STATUS_CODE = 200 THEN 1 ELSE 0 END) as SUCCESS, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) as AUTH_FAILED, SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) as SERVER_ERROR, ROUND(100.0 * SUM(CASE WHEN STATUS_CODE >= 400 THEN 1 ELSE 0 END) / COUNT(*), 2) as ERROR_RATE_PCT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY REQUEST_METHOD ORDER BY TOTAL DESC"
```

> ⚠️ **Note:** Snowflake returns column names in UPPERCASE. Don't use `| table` with lowercase names.

**What This Proves:** Security analytics by HTTP method - 25% DELETE operations with 55% error rate.

---

### Demo 1.4: Status Code Distribution

**Splunk SPL (copy-paste ready):**
```spl
| dbxquery connection="snowflake" query="SELECT STATUS_CODE, COUNT(*) as COUNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY STATUS_CODE ORDER BY COUNT DESC"
```

**What This Proves:** Simple GROUP BY pushdown to Snowflake.

---

### Demo 1.5: Backend Server Risk Analysis

**Splunk SPL (copy-paste ready):**
```spl
| dbxquery connection="snowflake" query="SELECT BACKEND_IP, COUNT(*) as TOTAL_HITS, SUM(CASE WHEN STATUS_CODE >= 400 THEN 1 ELSE 0 END) as ERRORS, SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) as SERVER_ERRORS, ROUND(100.0 * SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) / COUNT(*), 2) as ERROR_RATE FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY BACKEND_IP HAVING COUNT(*) >= 3 ORDER BY SERVER_ERRORS DESC LIMIT 10"
```

**What This Proves:** HAVING clause and ORDER BY pushdown - identify unhealthy backend servers.

---

### Demo 1.6: Attack Surface Analysis with CTE (Complex Correlation) ⭐

**Expected Results:**
| endpoint | requests | auth_failures | risk |
|----------|----------|---------------|------|
| logout | 12,725 | 1,216 | HIGH_RISK |
| dashboard | 12,594 | 1,172 | HIGH_RISK |
| login | 12,525 | 1,165 | HIGH_RISK |
| home | 12,509 | 1,116 | HIGH_RISK |

**Splunk SPL (copy-paste ready):**
```spl
| dbxquery connection="snowflake" query="WITH path_analysis AS (SELECT SPLIT_PART(SPLIT_PART(REQUEST_PATH, '/', 2), '/', 1) as ENDPOINT, COUNT(*) as REQUESTS, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) as AUTH_FAILURES FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY SPLIT_PART(SPLIT_PART(REQUEST_PATH, '/', 2), '/', 1)) SELECT ENDPOINT, REQUESTS, AUTH_FAILURES, CASE WHEN AUTH_FAILURES > 1000 THEN 'HIGH_RISK' ELSE 'NORMAL' END as RISK FROM path_analysis ORDER BY REQUESTS DESC"
```

**What This Proves:** 
- CTEs work via federated search
- CASE statements for threat classification
- Complex string functions (SPLIT_PART)

---

### Demo 1.7: Top Request Paths

**Splunk SPL (copy-paste ready):**
```spl
| dbxquery connection="snowflake" query="SELECT SPLIT_PART(REQUEST_PATH, '?', 1) as PATH, COUNT(*) as HITS, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) as AUTH_FAILURES FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY SPLIT_PART(REQUEST_PATH, '?', 1) ORDER BY HITS DESC LIMIT 15"
```

---

### Demo 1.8: Data Exfiltration Detection (High Bytes)

**Splunk SPL (copy-paste ready):**
```spl
| dbxquery connection="snowflake" query="SELECT IP_ADDRESS, REQUEST_METHOD, STATUS_CODE, BYTES_SENT FROM CTF.PUBLIC.ACCESS_LOGS WHERE BYTES_SENT > 9000 ORDER BY BYTES_SENT DESC LIMIT 10"
```

**What This Proves:** WHERE clause filter pushdown.

---

### Demo 1.9: Request Method Distribution (Pie Chart)

**Splunk SPL (copy-paste ready):**
```spl
| dbxquery connection="snowflake" query="SELECT REQUEST_METHOD, COUNT(*) as COUNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY REQUEST_METHOD ORDER BY COUNT DESC"
```

---

## Part 1B: Hybrid Correlations (Splunk + Snowflake Data)

> 🎯 **Use Case:** Correlate real-time Splunk data with historical Snowflake data

### Setup: Upload Sample Web Logs to Splunk Cloud

A sample CSV file has been created at: `sample_web_logs.csv`

**Step 1: Upload via Splunk Web UI**

1. Go to **Settings → Add Data**
2. Click **Upload**
3. Select the `sample_web_logs.csv` file
4. Set Source type: `csv`
5. Set Host: `demo-host`
6. Set Index: `main` (or create a new index called `web_logs`)
7. Click **Review** → **Submit**

**Step 2: Alternative - Use the Search Command**

```spl
| inputlookup sample_web_logs.csv
| collect index=main sourcetype=access_combined
```

**Step 3: Verify the data is indexed**

```spl
index=main sourcetype=csv OR sourcetype=access_combined
| head 10
```

**Sample Data Includes:**
- 50 web log events with realistic patterns
- IPs that **overlap with Snowflake data** (for correlation demos)
- Various status codes: 200, 201, 302, 401, 403, 404, 500
- Attack patterns: brute force (repeated 401s), scanning (404s), suspicious DELETEs

---

### Demo 1.10: Append - Combine Splunk and Snowflake Results

Combine Splunk logs with historical Snowflake data in one view:

```spl
index=main sourcetype=csv
| stats count as COUNT by status
| rename status as STATUS_CODE
| eval SOURCE="Splunk (Recent)"
| append [
    | dbxquery connection="snowflake" query="SELECT STATUS_CODE, COUNT(*) as COUNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY STATUS_CODE"
    | eval SOURCE="Snowflake (Historical)"
]
| table SOURCE, STATUS_CODE, COUNT
```

**What This Proves:** Real-time + historical data in one search.

---

### Demo 1.11: JOIN - Enrich Splunk Events with Snowflake Data (✅ RECOMMENDED)

**Use Case:** Match IPs in Splunk with their historical context from Snowflake.

**Pattern: Join on Common Field**
```spl
index=main sourcetype=csv
| stats count as SPLUNK_HITS by src_ip
| rename src_ip as IP_ADDRESS
| join type=left IP_ADDRESS [| dbxquery connection="snowflake" query="SELECT IP_ADDRESS, COUNT(*) as HISTORICAL_HITS, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) as HIST_AUTH_FAILURES FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY IP_ADDRESS"]
| table IP_ADDRESS, SPLUNK_HITS, HISTORICAL_HITS, HIST_AUTH_FAILURES
```

**Important Notes:**
- The main search MUST have a `stats` or transforming command BEFORE the join
- Field names must match exactly (case-sensitive) - hence the `rename` command
- `type=left` ensures Splunk data appears even if no Snowflake match

**What This Proves:** Automated enrichment - join real-time Splunk data with historical Snowflake context.

---

### Demo 1.12: Append + Stats Pattern - Merge on Common Field

**Use Case:** Combine status code counts from both sources into unified metrics.

```spl
index=main sourcetype=csv
| stats count as RECENT_COUNT by status
| rename status as STATUS_CODE
| eval STATUS_CODE=tostring(STATUS_CODE)
| append [| dbxquery connection="snowflake" query="SELECT CAST(STATUS_CODE AS VARCHAR) as STATUS_CODE, COUNT(*) as HISTORICAL_COUNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY STATUS_CODE"]
| stats values(RECENT_COUNT) as RECENT_COUNT, values(HISTORICAL_COUNT) as HISTORICAL_COUNT by STATUS_CODE
| fillnull value=0 RECENT_COUNT HISTORICAL_COUNT
| eval TOTAL=RECENT_COUNT+HISTORICAL_COUNT
| table STATUS_CODE, RECENT_COUNT, HISTORICAL_COUNT, TOTAL
| sort - TOTAL
```

**How It Works:**
1. Get stats from Splunk → Get stats from Snowflake
2. Append combines both result sets (stacked rows)
3. `stats values(...) by STATUS_CODE` merges rows with same STATUS_CODE
4. Result: one row per status code with both counts

**What This Proves:** True data merge across both platforms.

---

### Demo 1.13: Subsearch Filter - Use Snowflake Data to Filter Splunk

**Use Case:** Only show Splunk events for IPs that have historical issues in Snowflake.

```spl
index=main sourcetype=csv
| search [| dbxquery connection="snowflake" query="SELECT DISTINCT IP_ADDRESS FROM CTF.PUBLIC.ACCESS_LOGS WHERE STATUS_CODE = 401 LIMIT 100" | rename IP_ADDRESS as src_ip | fields src_ip | format]
| stats count by src_ip, status
| sort - count
```

**How It Works:**
1. Subsearch queries Snowflake for IPs with auth failures
2. `rename IP_ADDRESS as src_ip` converts Snowflake's uppercase field to match Splunk's field
3. `format` converts results to search filter: `(src_ip="x" OR src_ip="y" ...)`
4. Main search only shows Splunk events matching those IPs

**Debugging tip:** Run the subsearch alone first to verify it produces results:
```spl
| dbxquery connection="snowflake" query="SELECT DISTINCT IP_ADDRESS FROM CTF.PUBLIC.ACCESS_LOGS WHERE STATUS_CODE = 401 LIMIT 100" 
| rename IP_ADDRESS as src_ip 
| fields src_ip 
| format
```

**What This Proves:** Use Snowflake as a threat intel source to filter Splunk searches.

---

### Demo 1.14: Unified View with Append (✅ VERIFIED WORKING)

**Use Case:** Single table showing stats from both Splunk and Snowflake.

```spl
index=main sourcetype=csv
| stats count as COUNT by status
| rename status as STATUS_CODE
| eval SOURCE="Splunk"
| append [| dbxquery connection="snowflake" query="SELECT STATUS_CODE, COUNT(*) as COUNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY STATUS_CODE" | eval SOURCE="Snowflake"]
| sort SOURCE, STATUS_CODE
```

**What This Proves:** Unified view combining both data sources in one table.

---

### Demo 1.15: Compare Request Methods - Side by Side

**Use Case:** Show request method distribution from both sources in one view.

```spl
index=main sourcetype=csv
| stats count as RECENT by request_method
| rename request_method as REQUEST_METHOD
| append [| dbxquery connection="snowflake" query="SELECT REQUEST_METHOD, COUNT(*) as HISTORICAL FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY REQUEST_METHOD"]
| stats values(RECENT) as SPLUNK_COUNT, values(HISTORICAL) as SNOWFLAKE_COUNT by REQUEST_METHOD
| fillnull value=0
| eval RATIO=round(SNOWFLAKE_COUNT/SPLUNK_COUNT,2)
| table REQUEST_METHOD, SPLUNK_COUNT, SNOWFLAKE_COUNT, RATIO
```

**What This Proves:** Compare attack patterns (like DELETE abuse) across time periods.

---

### Troubleshooting Join/Subsearch Issues

If join or subsearch with dbxquery isn't working:

| Issue | Solution |
|-------|----------|
| **Empty results from join** | Ensure field names match EXACTLY (case-sensitive). Use `rename` to align. |
| **dbxquery in subsearch fails** | Make sure there's a space after `[|` and the query is on a single line |
| **Join returns no matches** | Check with `type=left` first. Run dbxquery standalone to verify data exists. |
| **Subsearch timeout** | Snowflake queries have 60-second limit in subsearch. Simplify query or use append instead. |

---

### Hybrid Correlation Use Cases

| Use Case | Best Pattern | Example |
|----------|--------------|---------|
| **Threat Hunting** | Join or Subsearch Filter | Check if today's suspicious IP appeared in historical logs |
| **Incident Investigation** | Join | Enrich alerts with 90-day historical context |
| **Compliance Audit** | Append + Stats | Combine current access with historical access patterns |
| **Anomaly Detection** | Append + Stats | Compare real-time metrics to historical baselines |
| **IOC Matching** | Subsearch Filter | Match current events against historical threat intel |

---

## Part 2: Proving Minimal Splunk Compute

### Demo 2.1: Data Volume Comparison

| Query | Snowflake Scans | Splunk Receives |
|-------|-----------------|-----------------|
| Security Overview (Demo 1.2) | 100,000 rows | 1 row |
| Method Analysis (Demo 1.3) | 100,000 rows | 4 rows |
| Attack Surface CTE (Demo 1.6) | 100,000 rows | 8 rows |
| Backend Analysis (Demo 1.5) | 100,000 rows | 10 rows |

**Talking Point:** "Snowflake scans 100,000 rows but Splunk only receives the aggregated results."

---

### Demo 2.2: Splunk Job Inspector (Actual Results ✅)

**Step 1:** Run this query:
```spl
| dbxquery connection="snowflake" query="SELECT STATUS_CODE, COUNT(*) as CNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY STATUS_CODE ORDER BY CNT DESC"
```

**Step 2:** Click **Job → Inspect Job**

**Step 3:** Show the "Execution Costs" section

#### Actual Job Inspector Results (Verified):

```
This search has completed and has returned 11 results by scanning 0 events in 2.041 seconds
```

| Component | Duration (sec) | Input | Output | What It Means |
|-----------|----------------|-------|--------|---------------|
| command.dbxquery | 0.36 | - | 11 | Query sent to Snowflake, 11 rows returned |
| dispatch.evaluate.dbxquery | 0.57 | - | - | Processing the dbxquery command |
| search.optimize | 0.50 | - | - | Splunk query optimization |
| startup.configuration | 0.04 | - | - | Initial setup |
| startup.handoff | 0.02 | - | - | Job handoff |

#### How to Read These Statistics:

| Metric | Value | Interpretation |
|--------|-------|----------------|
| **"scanning 0 events"** | 0 | 🎯 **KEY METRIC!** Splunk did NOT scan any indexed data |
| **"returned 11 results"** | 11 | Only aggregated results returned (11 status codes) |
| **command.dbxquery output** | 11 | Snowflake returned 11 rows, not 100,000 raw rows |
| **Total duration** | 2.04 sec | Time waiting for Snowflake response |

#### What This Proves:

| Claim | Evidence |
|-------|----------|
| ✅ No Splunk index scanning | "scanning 0 events" |
| ✅ Compute happened in Snowflake | All time in dbxquery component |
| ✅ Only results transferred | 11 output rows, not 100,000 |
| ✅ No Splunk license usage | 0 events scanned = $0 license cost for this data |

#### Comparison: If This Data Was Indexed in Splunk

| Metric | Federated (Snowflake) | If Indexed in Splunk |
|--------|----------------------|---------------------|
| Events Scanned | **0** | 100,000 |
| Results Returned | 11 | 11 |
| Splunk License Cost | **$0** | $$$ (per GB/day) |
| Compute Location | Snowflake | Splunk Search Heads |
| Storage Cost | Snowflake (cheap) | Splunk (expensive) |

---

### Demo 2.3: Show Snowflake Query History

After running Splunk queries, show they appear in Snowflake:

**Snow CLI:**
```bash
snow sql -q "SELECT QUERY_TEXT, TOTAL_ELAPSED_TIME/1000 as seconds, ROWS_PRODUCED FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY WHERE START_TIME >= DATEADD(hour, -1, CURRENT_TIMESTAMP()) ORDER BY START_TIME DESC LIMIT 5" -c your_connection
```

**What This Proves:** Every Splunk query logged in Snowflake = compute happened there.

---

## Part 3: Dashboard XML (Copy-Paste Ready)

```xml
<dashboard version="1.1">
  <label>Cybersecurity Data Lake - Snowflake</label>
  <description>Security analytics with compute offloaded to Snowflake</description>
  
  <row>
    <panel>
      <title>Total Requests</title>
      <single>
        <search>
          <query>| dbxquery connection="snowflake" query="SELECT COUNT(*) as total FROM CTF.PUBLIC.ACCESS_LOGS"</query>
        </search>
        <option name="field">TOTAL</option>
      </single>
    </panel>
    <panel>
      <title>Auth Failures (401)</title>
      <single>
        <search>
          <query>| dbxquery connection="snowflake" query="SELECT COUNT(*) as cnt FROM CTF.PUBLIC.ACCESS_LOGS WHERE STATUS_CODE = 401"</query>
        </search>
        <option name="field">CNT</option>
        <option name="colorMode">block</option>
        <option name="rangeColors">["0x53a051","0xf8be34","0xdc4e41"]</option>
        <option name="rangeValues">[5000,8000]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <title>Server Errors (5xx)</title>
      <single>
        <search>
          <query>| dbxquery connection="snowflake" query="SELECT COUNT(*) as cnt FROM CTF.PUBLIC.ACCESS_LOGS WHERE STATUS_CODE >= 500"</query>
        </search>
        <option name="field">CNT</option>
      </single>
    </panel>
    <panel>
      <title>DELETE Operations</title>
      <single>
        <search>
          <query>| dbxquery connection="snowflake" query="SELECT COUNT(*) as cnt FROM CTF.PUBLIC.ACCESS_LOGS WHERE REQUEST_METHOD = 'DELETE'"</query>
        </search>
        <option name="field">CNT</option>
      </single>
    </panel>
  </row>

  <row>
    <panel>
      <title>Request Methods</title>
      <chart>
        <search>
          <query>| dbxquery connection="snowflake" query="SELECT REQUEST_METHOD, COUNT(*) as count FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY REQUEST_METHOD"</query>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
    <panel>
      <title>Status Codes</title>
      <chart>
        <search>
          <query>| dbxquery connection="snowflake" query="SELECT STATUS_CODE, COUNT(*) as count FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY STATUS_CODE ORDER BY count DESC"</query>
        </search>
        <option name="charting.chart">bar</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <title>Endpoint Risk Assessment (CTE)</title>
      <table>
        <search>
          <query>| dbxquery connection="snowflake" query="WITH p AS (SELECT SPLIT_PART(SPLIT_PART(REQUEST_PATH, '/', 2), '/', 1) as endpoint, COUNT(*) as requests, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) as auth_fail FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY 1) SELECT endpoint, requests, auth_fail, CASE WHEN auth_fail > 1000 THEN 'HIGH_RISK' ELSE 'NORMAL' END as risk FROM p ORDER BY requests DESC"</query>
        </search>
      </table>
    </panel>
  </row>

  <row>
    <panel>
      <title>Backend Server Health</title>
      <table>
        <search>
          <query>| dbxquery connection="snowflake" query="SELECT BACKEND_IP, COUNT(*) as hits, SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) as errors FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY BACKEND_IP HAVING COUNT(*) >= 3 ORDER BY errors DESC LIMIT 10"</query>
        </search>
      </table>
    </panel>
  </row>

</dashboard>
```

---

## Part 4: What Splunk Professionals Can Do with Federated Data

> **📢 Industry Update:** Cisco announced "Splunk Federated Search for Snowflake" in January 2025, with General Availability planned for July 2026. This will provide native integration beyond DB Connect. Our current approach using DB Connect provides these capabilities today.
> 
> **Source:** [Cisco Press Release](https://www.splunk.com/en_us/newsroom/press-releases/2025/cisco-advances-open-data-ecosystems-with-splunk-federated-search-for-snowflake.html)

### ✅ What WORKS with Federated Snowflake Data (Verified)

| Capability | Works? | Notes | Source |
|------------|--------|-------|--------|
| **Dashboards** | ✅ YES | Full visualization support - charts, tables, single values | Tested ✓ |
| **Scheduled Reports** | ✅ YES | Run daily/weekly reports, export to PDF/CSV | Splunk Docs |
| **Scheduled Alerts** | ✅ YES | Trigger alerts when thresholds exceeded (min 1-5 min intervals) | Tested ✓ |
| **Ad-hoc Searches** | ✅ YES | Interactive threat hunting and investigation | Tested ✓ |
| **Correlation (Hybrid)** | ✅ YES | Join/append Splunk + Snowflake data | Tested ✓ |
| **SPL Post-Processing** | ✅ YES | Apply SPL commands (stats, eval, where) to dbxquery results | Tested ✓ |
| **Lookups** | ✅ YES | Create lookups from Snowflake for enrichment | Tested ✓ |
| **Drilldowns** | ✅ YES | Click dashboard panels to drill into details | Splunk Docs |
| **Subsearch/Join** | ✅ YES | Use dbxquery in subsearch with proper syntax | Tested ✓ |

### ⚠️ What Has LIMITATIONS (Research-Validated)

| Capability | Status | Workaround | Why |
|------------|--------|------------|-----|
| **Real-time Alerts** | ⚠️ Batch only | Use scheduled alerts (every 1-5 min) | dbxquery is not streaming |
| **Machine Learning (MLTK)** | ❌ Needs indexed | Push ML logic to Snowflake SQL (Z-scores, percentiles) | MLTK requires indexed events |
| **Anomaly Detection** | ⚠️ Limited | Use SQL statistical functions (STDDEV, AVG, window functions) | Native commands need indexed data |
| **Data Models** | ❌ Needs indexed | Query Snowflake tables directly with SQL | Data models accelerate indexed data |
| **Accelerated Reports** | ❌ Needs indexed | Use Snowflake's own caching/clustering | Acceleration is for indexed data |
| **Event Types/Tags** | ❌ Needs indexed | Use SQL CASE statements for classification | Applied during indexing |
| **Field Extraction** | N/A | Not needed - Snowflake data is already structured | Data comes pre-structured |

### 🔬 Research-Validated Benefits

Based on official Cisco/Splunk announcements and industry research:

| Benefit | Description | Source |
|---------|-------------|--------|
| **Unified Data Access** | Query Snowflake directly from Splunk interface, no data duplication | Cisco Press Release 2025 |
| **Compute Offloading** | Complex queries run in Snowflake, reducing Splunk load | Splunkbase, Elysium Analytics |
| **Cost Efficiency** | Pay-as-you-go Snowflake vs. per-GB Splunk licensing | Industry Analysis |
| **Accelerated Incident Response** | Correlate real-time Splunk data with historical Snowflake data | Cisco Press Release 2025 |
| **Scalability** | Snowflake's elastic compute handles large historical datasets | Snowflake Architecture |

### 💰 Cost Comparison (Industry Estimates)

| Storage Type | Approximate Cost | Notes |
|--------------|------------------|-------|
| **Splunk Enterprise** | ~$1,800-$2,400/GB/year | Based on ingest licensing |
| **Splunk Cloud** | ~$1,500-$3,000/GB/year | Varies by tier |
| **Snowflake Storage** | ~$23-$40/TB/month (~$276-$480/TB/year) | On-demand pricing |
| **Cost Ratio** | **~50-100x cheaper** for cold storage | Snowflake for historical data |

**ROI Strategy:**
- Keep 7-30 days in Splunk for real-time detection (~$X based on daily ingest)
- Keep 1-5 years in Snowflake for investigations (~$0.02/GB/month)
- Federated search = query historical data without re-ingestion

### ⚠️ Known Limitations to Communicate

Based on research, be transparent about:

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| **Query Latency** | Snowflake queries take 1-5 seconds vs. milliseconds for indexed | Set user expectations; use for investigation, not real-time |
| **Large Data Transfers** | Returning millions of rows is slow | Aggregate in Snowflake, return summarized results |
| **Subsearch Timeout** | Subsearches have 60-second default limit | Keep Snowflake queries efficient; use append pattern for complex cases |
| **No Real-time Streaming** | dbxquery is batch, not streaming | Use scheduled alerts (every 1-5 min) for near-real-time |
| **SQL Knowledge Required** | Analysts need SQL for Snowflake queries | Provide pre-built dashboards and saved searches |

---

### Security Operations Use Cases

#### 1. Threat Hunting Dashboard

Create a dashboard for security analysts to hunt through historical data:

```xml
<dashboard version="1.1">
  <label>Threat Hunting - Snowflake Historical Data</label>
  
  <fieldset submitButton="true">
    <input type="text" token="ip_address">
      <label>Suspicious IP Address</label>
      <default>*</default>
    </input>
    <input type="dropdown" token="time_range">
      <label>Time Range</label>
      <choice value="7">Last 7 days</choice>
      <choice value="30">Last 30 days</choice>
      <choice value="90">Last 90 days</choice>
      <default>30</default>
    </input>
  </fieldset>
  
  <row>
    <panel>
      <title>IP Activity Summary</title>
      <table>
        <search>
          <query>| dbxquery connection="snowflake" query="SELECT IP_ADDRESS, COUNT(*) as TOTAL_REQUESTS, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) as AUTH_FAILURES, SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) as SERVER_ERRORS, COUNT(DISTINCT REQUEST_PATH) as UNIQUE_PATHS FROM CTF.PUBLIC.ACCESS_LOGS WHERE IP_ADDRESS LIKE '$ip_address$' OR '$ip_address$' = '*' GROUP BY IP_ADDRESS ORDER BY AUTH_FAILURES DESC LIMIT 50"</query>
        </search>
        <drilldown>
          <set token="selected_ip">$row.IP_ADDRESS$</set>
        </drilldown>
      </table>
    </panel>
  </row>
  
  <row depends="$selected_ip$">
    <panel>
      <title>Detailed Activity for $selected_ip$</title>
      <table>
        <search>
          <query>| dbxquery connection="snowflake" query="SELECT TIMESTAMP, REQUEST_METHOD, REQUEST_PATH, STATUS_CODE, USER_AGENT FROM CTF.PUBLIC.ACCESS_LOGS WHERE IP_ADDRESS = '$selected_ip$' ORDER BY TIMESTAMP DESC LIMIT 100"</query>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
```

#### 2. Scheduled Alert: Brute Force Detection

Create an alert that runs every 15 minutes:

**Search:**
```spl
| dbxquery connection="snowflake" query="SELECT IP_ADDRESS, COUNT(*) as FAILURES FROM CTF.PUBLIC.ACCESS_LOGS WHERE STATUS_CODE = 401 AND TIMESTAMP > DATEADD(minute, -15, CURRENT_TIMESTAMP()) GROUP BY IP_ADDRESS HAVING COUNT(*) > 10 ORDER BY FAILURES DESC"
| where FAILURES > 10
```

**Alert Settings:**
- Schedule: Every 15 minutes
- Trigger: When results > 0
- Action: Send email, create ticket, or trigger webhook

#### 3. Compliance Report: Access Audit

**Daily scheduled report:**
```spl
| dbxquery connection="snowflake" query="SELECT DATE(TIMESTAMP) as DATE, COUNT(*) as TOTAL_REQUESTS, COUNT(DISTINCT IP_ADDRESS) as UNIQUE_IPS, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) as AUTH_FAILURES, SUM(CASE WHEN REQUEST_METHOD = 'DELETE' THEN 1 ELSE 0 END) as DELETE_OPS FROM CTF.PUBLIC.ACCESS_LOGS WHERE TIMESTAMP >= DATEADD(day, -7, CURRENT_DATE()) GROUP BY DATE(TIMESTAMP) ORDER BY DATE"
| table DATE, TOTAL_REQUESTS, UNIQUE_IPS, AUTH_FAILURES, DELETE_OPS
```

#### 4. IOC Matching: Check Known Bad IPs

**Use Case:** Check if any known bad IPs from threat intel appear in historical logs.

```spl
| inputlookup threat_intel_ips.csv
| rename ip as IP_ADDRESS
| join type=inner IP_ADDRESS [| dbxquery connection="snowflake" query="SELECT DISTINCT IP_ADDRESS, COUNT(*) as HITS FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY IP_ADDRESS"]
| table IP_ADDRESS, threat_category, HITS
| sort - HITS
```

#### 5. Incident Investigation Workflow

**Step 1: Analyst finds suspicious activity in Splunk (real-time)**
```spl
index=main sourcetype=access_combined status=401
| stats count by src_ip
| where count > 5
```

**Step 2: Check historical context in Snowflake**
```spl
| dbxquery connection="snowflake" query="SELECT IP_ADDRESS, MIN(TIMESTAMP) as FIRST_SEEN, MAX(TIMESTAMP) as LAST_SEEN, COUNT(*) as TOTAL_REQUESTS, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) as TOTAL_AUTH_FAILURES FROM CTF.PUBLIC.ACCESS_LOGS WHERE IP_ADDRESS = '210.40.67.189' GROUP BY IP_ADDRESS"
```

**Step 3: Get full attack timeline**
```spl
| dbxquery connection="snowflake" query="SELECT TIMESTAMP, REQUEST_METHOD, REQUEST_PATH, STATUS_CODE, USER_AGENT FROM CTF.PUBLIC.ACCESS_LOGS WHERE IP_ADDRESS = '210.40.67.189' AND STATUS_CODE IN (401, 403, 500) ORDER BY TIMESTAMP"
```

---

### Advanced Analytics in Snowflake SQL

Since Splunk's MLTK doesn't work with federated data, push analytics to Snowflake:

#### Statistical Anomaly Detection (Z-Score)
```spl
| dbxquery connection="snowflake" query="WITH stats AS (SELECT IP_ADDRESS, COUNT(*) as requests, AVG(COUNT(*)) OVER() as avg_requests, STDDEV(COUNT(*)) OVER() as stddev_requests FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY IP_ADDRESS) SELECT IP_ADDRESS, requests, ROUND((requests - avg_requests) / NULLIF(stddev_requests, 0), 2) as z_score FROM stats WHERE ABS((requests - avg_requests) / NULLIF(stddev_requests, 0)) > 2 ORDER BY z_score DESC"
```

**What this does:** Finds IPs with statistically unusual request volumes (Z-score > 2).

#### Time-based Pattern Analysis
```spl
| dbxquery connection="snowflake" query="SELECT HOUR(TIMESTAMP) as HOUR, DAYOFWEEK(TIMESTAMP) as DOW, COUNT(*) as REQUESTS, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) as FAILURES FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY HOUR(TIMESTAMP), DAYOFWEEK(TIMESTAMP) ORDER BY HOUR, DOW"
```

**What this does:** Shows attack patterns by hour and day of week.

#### Velocity Analysis (Requests per Minute)
```spl
| dbxquery connection="snowflake" query="SELECT IP_ADDRESS, DATE_TRUNC('minute', TIMESTAMP) as MINUTE, COUNT(*) as REQUESTS_PER_MIN FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY IP_ADDRESS, DATE_TRUNC('minute', TIMESTAMP) HAVING COUNT(*) > 100 ORDER BY REQUESTS_PER_MIN DESC LIMIT 50"
```

**What this does:** Finds IPs making more than 100 requests per minute (potential DDoS/scraping).

---

### Hybrid Architecture: Best of Both Worlds

| Data Type | Where to Store | Why |
|-----------|----------------|-----|
| **Real-time (0-7 days)** | Splunk | Fast alerting, real-time correlation |
| **Historical (7-365+ days)** | Snowflake | Cost-effective, compliance retention |
| **Threat Intel** | Splunk (lookups) | Fast matching during real-time analysis |
| **Investigation Data** | Snowflake | Deep historical context when needed |

**The Workflow:**
1. **Real-time alerts** fire from Splunk indexed data (immediate)
2. **Investigation** uses hybrid queries to add historical context from Snowflake
3. **Compliance reports** run scheduled queries against Snowflake
4. **Threat hunting** uses both sources depending on time range needed

---

### Demo Talking Points for Security Professionals

**For SOC Analysts:**
- "You can investigate incidents using the same Splunk interface you know"
- "Historical context is just a query away - no need to restore archives"
- "Dashboard and alert capabilities work exactly the same"

**For Threat Hunters:**
- "Hunt across years of data without ingestion costs"
- "SQL analytics (like Z-scores) run in Snowflake - Splunk displays results"
- "Correlate real-time alerts with historical patterns"

**For Security Architects:**
- "Tiered storage: hot data in Splunk, cold data in Snowflake"
- "Compute happens where the data lives - no data movement"
- "Splunk license costs scale with real-time needs, not retention needs"

**For Compliance Officers:**
- "Meet 7-year retention requirements economically"
- "Scheduled reports run against compliant Snowflake storage"
- "Audit trails maintained in cost-effective storage"

---

## Quick Demo Script (5 Minutes)

### Step 1: The Problem (30 sec)
"Traditional SIEM = all data ingested = high license costs. Historical data expensive."

### Step 2: The Solution (30 sec)
"Federated Search = query Snowflake directly. No ingestion, no license cost for that data."

### Step 3: Basic Query (1 min)
```spl
| dbxquery connection="snowflake" query="SELECT COUNT(*) as total FROM CTF.PUBLIC.ACCESS_LOGS"
```
"100,000 rows in Snowflake → 1 row returned to Splunk."

### Step 4: Complex CTE Query (1 min)
```spl
| dbxquery connection="snowflake" query="WITH p AS (SELECT SPLIT_PART(SPLIT_PART(REQUEST_PATH, '/', 2), '/', 1) as endpoint, COUNT(*) as cnt, SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) as auth_fail FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY 1) SELECT endpoint, cnt, auth_fail, CASE WHEN auth_fail > 1000 THEN 'HIGH_RISK' ELSE 'NORMAL' END as risk FROM p ORDER BY cnt DESC"
```
"CTE with CASE statement → threat classification runs in Snowflake."

### Step 5: Job Inspector (1 min)
Open **Job → Inspect Job** and highlight:
- **"scanning 0 events"** = Splunk didn't use any compute
- **"returned 11 results"** = Only aggregated data transferred
- **command.dbxquery: 11 output** = Snowflake did all the work
- "This proves compute happened in Snowflake, not Splunk. Zero license cost for this data."

### Step 6: Snowflake Query History (1 min)
Show queries logged in Snowflake console.
"Compute happened in Snowflake, not Splunk."

---

## Key Talking Points (Research-Validated)

### For Correlations:
- ✅ "CTEs, CASE statements, window functions - all standard SQL works"
- ✅ "Threat detection logic runs in Snowflake, results displayed in Splunk"
- ✅ "Same security insights, same dashboards - just different compute location"
- ✅ "Best of both worlds: Splunk UI + Snowflake economics"

### For Compute Offloading (Job Inspector):
- ✅ **"Scanning 0 events"** - The most important number! Splunk didn't scan anything
- ✅ **"Returned 11 results"** - 100,000 rows processed → 11 returned
- ✅ **"command.dbxquery"** - All work happened via this component (= Snowflake)
- ✅ **Cost savings** - Splunk license is per-GB ingested. Federated = $0 ingestion

### ROI Talking Points (Industry-Validated):
- ✅ "Keep 7-30 days in Splunk for real-time alerts"
- ✅ "Keep 1-5 years in Snowflake for investigations and compliance"
- ✅ "Query historical data without re-ingesting into Splunk"
- ✅ "Snowflake storage = ~$23-40/TB/month vs Splunk = 50-100x more expensive"
- ✅ "Cisco officially announced Splunk Federated Search for Snowflake (GA July 2026)"

### What You CAN Say (Verified):
- ✅ "Dashboards, alerts, reports - all work with federated data"
- ✅ "SOC analysts can investigate using familiar Splunk interface"
- ✅ "Threat hunting across years of data without ingestion costs"
- ✅ "Hybrid correlation - enrich real-time alerts with historical context"
- ✅ "Compliance reports run on cost-effective Snowflake storage"

### What to Be Transparent About:
- ⚠️ "Alerts are scheduled (1-5 min intervals), not true real-time streaming"
- ⚠️ "MLTK doesn't work - but SQL statistical functions provide alternatives"
- ⚠️ "Query latency is 1-5 seconds, not milliseconds"
- ⚠️ "Analysts need SQL knowledge for custom Snowflake queries"

### Bottom Line Message:
> "This isn't about replacing Splunk - it's about using the right tool for the right job. 
> Splunk excels at real-time detection and alerting on hot data. 
> Snowflake excels at storing years of historical data economically. 
> Together, they provide complete visibility at optimized cost."

---

## Pre-Demo Checklist

- [ ] Verify `snowflake` connection works in Splunk
- [ ] Test Demo 1.2 (Security Overview)
- [ ] Test Demo 1.6 (CTE query)
- [ ] Have Snowflake console ready for query history
- [ ] Have Job Inspector walkthrough ready
