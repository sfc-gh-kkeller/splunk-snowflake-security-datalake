# Splunk Cloud + Snowflake Federated Search Demo Guide

> Splunk Cloud Query Pushdown to Snowflake Cybersecurity Data Lake

---

## 🚀 Quick Start - DB Connect Settings for Splunk Cloud

Copy these values directly into **Configuration → Settings → General**:

| Setting | Value to Enter |
|---------|----------------|
| **JRE Installation Path (JAVA_HOME)** | `/usr/lib/jvm/java-17-openjdk-amd64` |
| **Task Server Port** | `9998` |
| **Task Server JVM Options** | `-Ddw.server.applicationConnectors[0].port=9998 --add-opens java.base/java.nio=ALL-UNNAMED` |
| **Query Server JVM Options** | `-Dport=9999 --add-opens java.base/java.nio=ALL-UNNAMED` |

> ✅ **Verified Working**: These settings have been tested and confirmed working with Snowflake on Splunk Cloud.

### JVM Options Breakdown

| Option | Purpose |
|--------|---------|
| `-Ddw.server.applicationConnectors[0].port=9998` | Task Server port configuration |
| `-Dport=9999` | Query Server port configuration |
| `--add-opens java.base/java.nio=ALL-UNNAMED` | Fixes Arrow library error for Snowflake JDBC |


---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Integration Options](#integration-options)
4. [Prerequisites](#prerequisites)
5. [Option 1: Splunk DB Connect Setup](#option-1-splunk-db-connect-setup-recommended)
6. [Option 2: Elysium Analytics Add-on](#option-2-elysium-analytics-add-on)
7. [Option 3: Native Federated Search (Future)](#option-3-native-federated-search-future)
8. [DB Connect Configuration Reference](#db-connect-configuration-reference)
9. [Demo Scenarios & Queries](#demo-scenarios--queries)
10. [Troubleshooting](#troubleshooting)
11. [References](#references)

---

## Overview

This guide outlines how to demonstrate **Splunk Cloud pushing down queries to Snowflake** as a cybersecurity data lake. Instead of ingesting all data into Splunk (expensive storage/compute), we leverage Snowflake for:

- **Long-term storage** of security logs (12-36 months)
- **Heavy analytical queries** that scan billions of rows
- **Cost optimization** by keeping only hot data in Splunk

### Key Benefits

| Benefit | Description |
|---------|-------------|
| **Cost Reduction** | Snowflake storage is significantly cheaper than Splunk indexing |
| **Query Pushdown** | Complex aggregations run on Snowflake compute, not Splunk |
| **Data Tiering** | Hot data in Splunk (7-30 days), cold data in Snowflake |
| **Unified View** | Single pane of glass for security investigations |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           SPLUNK CLOUD                                  │
│  ┌───────────────────┐    ┌────────────────────────────────────────┐   │
│  │  HOT DATA         │    │         SPLUNK DB CONNECT              │   │
│  │  (7-30 days)      │    │  ┌──────────────────────────────────┐  │   │
│  │  • Real-time      │    │  │  Task Server (Java)              │  │   │
│  │    alerts         │◄───┤  │  • JDBC Connection Pool          │  │   │
│  │  • Live dashboards│    │  │  • Query Execution               │  │   │
│  │  • Incident       │    │  │  • Result Streaming              │  │   │
│  │    response       │    │  └──────────────┬───────────────────┘  │   │
│  └───────────────────┘    └─────────────────┼──────────────────────┘   │
└──────────────────────────────────────────────┼──────────────────────────┘
                                               │
                         SQL Queries Pushed    │  JDBC over TLS
                         Down to Snowflake     │  (Port 443)
                                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      SNOWFLAKE (Cybersecurity Data Lake)                │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  OCSF-Formatted Security Data                                    │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │   │
│  │  │ network_activity│  │ authentication  │  │ endpoint_events │  │   │
│  │  │ (12 months)     │  │ (24 months)     │  │ (18 months)     │  │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │   │
│  │  │ cloud_audit_logs│  │ threat_intel    │  │ vulnerability   │  │   │
│  │  │ (36 months)     │  │ (continuous)    │  │ (12 months)     │  │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                     💾 Cheap Storage + ❄️ Elastic Compute               │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Integration Options

| Approach | Best For | Status | Complexity |
|----------|----------|--------|------------|
| **Splunk DB Connect + JDBC** | Production, full control | ✅ Available Now | Medium |
| **Elysium Analytics Add-on** | Quick demos, POCs | ✅ Available Now | Low |
| **Splunk Federated Search for Snowflake** | Native integration | 🔜 GA July 2026 | Low |

---

## Prerequisites

### Snowflake Requirements

- [ ] Snowflake account (Enterprise or Business Critical tier recommended)
- [ ] Database with cybersecurity data (OCSF schema recommended)
- [ ] Service account with `SELECT` privileges on target tables
- [ ] Virtual warehouse configured (recommend `MEDIUM` or larger for demos)
- [ ] Network policy allowing Splunk Cloud IP ranges (if applicable)

### Splunk Cloud Requirements

- [ ] Splunk Cloud instance (Victoria Experience recommended)
- [ ] Admin access to install apps
- [ ] Splunk Cloud Stack with Java 17 or 21 pre-installed
  - DB Connect 3.x/4.x only supports **Java 17 and Java 21**
- [ ] Network connectivity to Snowflake (port 443)

### Credentials Needed

| Item | Example Value | Notes |
|------|---------------|-------|
| Snowflake Account Identifier | `YOUR_ACCOUNT_IDENTIFIER` | Without `.snowflakecomputing.com` |
| Service Account Username | `svc_splunk` | Or your Snowflake username |
| Service Account Password | `(stored securely)` | |
| Default Warehouse | `COMPUTE_WH` | Set in Snowflake user defaults |
| Default Database | `SECURITY_DATA` | Set in Snowflake user defaults |
| Default Schema | `OCSF` | Set in Snowflake user defaults |
| Default Role | `SPLUNK_READER` | Set in Snowflake user defaults |

---

## Option 1: Splunk DB Connect Setup (Recommended)

### Step 1: Install Splunk DB Connect

1. Navigate to **Apps → Find More Apps** in Splunk Web
2. Search for **"Splunk DB Connect"**
3. Click **Install** (version 3.x or 4.x)
4. Restart Splunk if prompted

### Step 2: Install Snowflake JDBC Driver

#### For Splunk Cloud:

1. Download the Snowflake JDBC driver:
   - URL: https://repo1.maven.org/maven2/net/snowflake/snowflake-jdbc/
   - Recommended version: `snowflake-jdbc-3.14.x.jar` (or latest stable)

2. In Splunk DB Connect, go to **Configuration → Settings → Drivers**

3. Click **Upload Driver** and select the JAR file

4. Click **Reload** to detect the driver

5. Verify the Snowflake driver shows a ✅ green checkmark

#### For Splunk Enterprise (on-prem):

```bash
# Copy driver to the correct location
cp snowflake-jdbc-3.14.x.jar $SPLUNK_HOME/etc/apps/splunk_app_db_connect/drivers/

# Restart Splunk
$SPLUNK_HOME/bin/splunk restart
```

### Step 3: Configure DB Connect Settings

Navigate to **Configuration → Settings → General** in DB Connect.

#### Splunk Cloud JRE Installation Path (JAVA_HOME)

Even though Java is pre-installed on Splunk Cloud, you still need to specify the path. DB Connect **only supports Java 17 and Java 21**.

| Java Version | JRE Installation Path |
|--------------|----------------------|
| **Java 17** (recommended) | `/usr/lib/jvm/java-17-openjdk-amd64` |


#### Task Server JVM Options

> ✅ **Verified Working**: Include both port configuration and Arrow fix.

| Environment | Task Server JVM Options |
|-------------|------------------------|
| **Snowflake (verified)** | `-Ddw.server.applicationConnectors[0].port=9998 --add-opens java.base/java.nio=ALL-UNNAMED` ✅ |
| **With extra memory** | `-Ddw.server.applicationConnectors[0].port=9998 --add-opens java.base/java.nio=ALL-UNNAMED -Xms512m -Xmx1024m` |

#### Query Server JVM Options

> ✅ **Verified Working**: Include both port configuration and Arrow fix.

| Environment | Query Server JVM Options |
|-------------|-------------------------|
| **Snowflake (verified)** | `-Dport=9999 --add-opens java.base/java.nio=ALL-UNNAMED` ✅ |
| **With extra memory** | `-Dport=9999 --add-opens java.base/java.nio=ALL-UNNAMED -Xms256m -Xmx512m` |

#### Complete Configuration Table (Verified Working for Snowflake)

| Setting | Splunk Cloud Value |
|---------|-------------------|
| **JRE Installation Path** | `/usr/lib/jvm/java-17-openjdk-amd64` ✅ |
| **Task Server Port** | `9998` |
| **Task Server JVM Options** | `-Ddw.server.applicationConnectors[0].port=9998 --add-opens java.base/java.nio=ALL-UNNAMED` ✅ |
| **Query Server JVM Options** | `-Dport=9999 --add-opens java.base/java.nio=ALL-UNNAMED` ✅ |

#### Why is `--add-opens` Required?

The Snowflake JDBC driver uses Apache Arrow for efficient result processing. Java 17+ restricts access to internal APIs by default, causing this error:

```
NoClassDefFoundError: Could not initialize class 
net.snowflake.client.jdbc.internal.apache.arrow.memory.RootAllocator
```

The `--add-opens=java.base/java.nio=ALL-UNNAMED` option allows the Arrow library to access the required Java internals.

#### JVM Options Format Reference

JVM options in Splunk DB Connect support multiple formats:

| Format | Example | Purpose |
|--------|---------|---------|
| `--add-opens` | `--add-opens=java.base/java.nio=ALL-UNNAMED` | Module access (Java 9+) |
| `-D` property | `-Dnet.snowflake.jdbc.enableArrowResultFormat=false` | System properties |
| `-X` memory | `-Xms512m -Xmx1024m` | Memory settings |

Multiple options can be combined with spaces:
```
--add-opens=java.base/java.nio=ALL-UNNAMED -Xms512m -Xmx1024m
```

#### Additional JVM Options (Advanced - Only If Needed)

Only add JVM options if you experience memory issues with large queries:

```
# For large result sets (if you get OutOfMemory errors)
-Xms512m -Xmx1024m

# Enable SSL debugging (for connection troubleshooting)
-Djavax.net.debug=ssl,handshake

# Enable verbose garbage collection logging
-verbose:gc
```

| JVM Option | Purpose |
|------------|---------|
| `-Xms<size>` | Initial heap size (memory allocated at startup) |
| `-Xmx<size>` | Maximum heap size (memory limit) |
| `-Djavax.net.debug=ssl` | Debug SSL/TLS connections |

### Step 4: Create Identity (Credentials)

1. Go to **Configuration → Databases → Identities**
2. Click **New Identity**
3. Configure:

| Field | Value |
|-------|-------|
| **Identity Name** | `snowflake_svc_account` |  
| **Username** | `svc_splunk` |
| **Password** | `(your service account password)` |

4. Click **Save**

### Step 5: Create Snowflake Connection

1. Go to **Configuration → Databases → Connections**
2. Click **New Connection**
3. Configure:

| Field | Value | Example |
|-------|-------|---------|
| **Connection Name** | Descriptive name | `snowflake` |
| **Identity** | Select from dropdown | `snowflake_svc_account` |
| **Connection Type** | Select | `Snowflake` |
| **Host** | Account identifier only | `YOUR_ACCOUNT_IDENTIFIER` |
| **Timezone** | Your timezone | `UTC` |
| **Readonly** | Check this | `✓` (recommended for security) |

#### Important: Host Format

> ⚠️ **Do NOT include `.snowflakecomputing.com`** - Splunk DB Connect adds this automatically!

| Enter This | NOT This |
|------------|----------|
| `YOUR_ACCOUNT_IDENTIFIER` ✅ | `YOUR_ACCOUNT_IDENTIFIER.snowflakecomputing.com` ❌ |
| `xy12345.us-east-1` ✅ | `xy12345.us-east-1.snowflakecomputing.com` ❌ |

#### Database, Warehouse, Schema Settings

> ⚠️ **These cannot be configured in the JDBC URL string.** DB Connect will use the **user's default settings** from Snowflake.

To set defaults for your Snowflake user, run this in Snowflake:

```sql
-- Set default warehouse, database, schema, and role for the service account
ALTER USER svc_splunk SET 
    DEFAULT_WAREHOUSE = 'COMPUTE_WH'
    DEFAULT_NAMESPACE = 'SECURITY_DATA.OCSF'
    DEFAULT_ROLE = 'SPLUNK_READER';
```

Or specify database/schema in your queries:

```sql
SELECT * FROM SECURITY_DATA.OCSF.network_activity LIMIT 10;
```

4. Click **Test Connection**
5. If successful, click **Save**

### Step 6: Test with a Query

Run a test query in Splunk Search:

```spl
| dbxquery 
    connection="snowflake" 
    query="SELECT CURRENT_TIMESTAMP() as test_time, CURRENT_USER() as user"
```

---

## Option 2: Elysium Analytics Add-on

Best for quick demos when you don't have your own Snowflake instance.

### Step 1: Install the Add-on

1. Go to Splunkbase: https://splunkbase.splunk.com/app/6391
2. Download **Elysium Analytics Add-on for Splunk on Snowflake**
3. Install on your Splunk Cloud instance

### Step 2: Request Demo Credentials (Optional)

If you don't have your own Snowflake:
1. Visit Elysium Analytics website
2. Fill out demo request form
3. Receive credentials via email:
   - Data Lake Instance
   - Client ID
   - Client Secret
   - Refresh Token

### Step 3: Configure the Add-on

1. Navigate to **Elysium Analytics Add-on** in Splunk
2. Go to **Configuration → Elysium Analytics Credentials**
3. Enter credentials:
   - **Account Type**: Demo or Production
   - **Data Lake Instance**: (from email)
   - **Client ID**: (from email)
   - **Client Secret**: (from email)
   - **Refresh Token**: (from email)
4. Click **Save**

### Step 4: Run Queries

```spl
| elysium_query query="SELECT * FROM security_events WHERE severity = 'HIGH' LIMIT 100"
```

---

## Option 3: Native Federated Search (GA July 2026)

**Splunk Federated Search for Snowflake** was announced by Cisco at Splunk .conf25 (September 2025). It provides a native, first-class integration that replaces the DB Connect/JDBC approach.

- **General Availability**: July 2026 (Splunk Cloud AWS commercial customers)
- **Announced at**: Splunk .conf25, Boston
- **Source**: [Cisco Press Release](https://www.splunk.com/en_us/newsroom/press-releases/2025/cisco-advances-open-data-ecosystems-with-splunk-federated-search-for-snowflake.html)

### Key Capabilities (vs. DB Connect)

| Capability | DB Connect (Today) | Native Federated Search (July 2026) |
|------------|-------------------|--------------------------------------|
| **Setup** | Install DB Connect + JDBC driver, configure JVM, upload JAR | Add Snowflake as a data source in Splunk UI |
| **Query Syntax** | `\| dbxquery connection="snowflake" query="SQL..."` | SPL-like queries to search Snowflake directly |
| **Data Joining** | Manual `\| join` / `\| append` with dbxquery | Native cross-platform joins in SPL |
| **Query Optimization** | Manual — you write the SQL | Automatic pushdown optimization |
| **Onboarding** | Medium complexity (JDBC, JVM options, Arrow fix) | Seamless — add Snowflake as a provider |
| **Dependencies** | DB Connect app + Snowflake JDBC driver JAR | No additional apps required |

### Migration Path: DB Connect to Native Federated Search

When the native integration becomes available, existing queries can be migrated. The data model and Snowflake tables remain unchanged — only the Splunk query syntax changes.

**DB Connect (current):**
```spl
| dbxquery connection="snowflake" query="SELECT STATUS_CODE, COUNT(*) AS CNT FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY STATUS_CODE ORDER BY CNT DESC"
```

**Native Federated Search (expected syntax — subject to change):**
```spl
| from snowflake:CTF.PUBLIC.ACCESS_LOGS
| stats count AS CNT by STATUS_CODE
| sort - CNT
```

**Hybrid join — DB Connect (current):**
```spl
index=main sourcetype=csv
| stats count as SPLUNK_HITS by src_ip
| rename src_ip as IP_ADDRESS
| join type=left IP_ADDRESS [| dbxquery connection="snowflake" query="SELECT IP_ADDRESS, COUNT(*) AS HIST_HITS FROM CTF.PUBLIC.ACCESS_LOGS GROUP BY IP_ADDRESS"]
```

**Hybrid join — Native Federated Search (expected):**
```spl
index=main sourcetype=csv
| stats count as SPLUNK_HITS by src_ip
| rename src_ip as IP_ADDRESS
| join type=left IP_ADDRESS [| from snowflake:CTF.PUBLIC.ACCESS_LOGS | stats count AS HIST_HITS by IP_ADDRESS]
```

### Recommendation

**Start with DB Connect today.** All the queries, dashboards, and workflows in this repo work now with DB Connect. When Native Federated Search reaches GA:

1. The Snowflake side (tables, data, stages) requires zero changes
2. Only the Splunk SPL queries need to be updated (SQL strings to SPL syntax)
3. The pre-built dashboard XML can be adapted by replacing `dbxquery` panels

This repo will be updated with native federated search examples once GA documentation is available.

---

## DB Connect Configuration Reference

### General Settings (`Configuration → Settings → General`)

#### Quick Reference for Splunk Cloud

Copy these values directly into DB Connect settings:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  SPLUNK CLOUD DB CONNECT - VERIFIED WORKING FOR SNOWFLAKE ✅                     │
├──────────────────────────────────────────────────────────────────────────────────┤
│  JRE Installation Path (JAVA_HOME):                                              │
│  /usr/lib/jvm/java-17-openjdk-amd64                                              │
│                                                                                  │
│  Task Server Port:                                                               │
│  9998                                                                            │
│                                                                                  │
│  Task Server JVM Options:                                                        │
│  -Ddw.server.applicationConnectors[0].port=9998 --add-opens java.base/java.nio=ALL-UNNAMED │
│                                                                                  │
│  Query Server JVM Options:                                                       │
│  -Dport=9999 --add-opens java.base/java.nio=ALL-UNNAMED                          │
└──────────────────────────────────────────────────────────────────────────────────┘
```

> **✅ Verified Working**: 
> - DB Connect only supports **Java 17** and **Java 21**
> - The `--add-opens` JVM option is **required** for Snowflake to fix Arrow library errors
> - Port configuration via `-D` properties is also required

#### All General Settings

| Setting | Default | Splunk Cloud + Snowflake | Description |
|---------|---------|--------------------------|-------------|
| **JRE Installation Path** | Auto-detected | `/usr/lib/jvm/java-17-openjdk-amd64` ✅ | Path to Java 17 or 21 |
| **Task Server Port** | `9998` | `9998` | Port for Task Server |
| **Task Server JVM Options** | (blank) | `-Ddw.server.applicationConnectors[0].port=9998 --add-opens java.base/java.nio=ALL-UNNAMED` ✅ | Port + Arrow fix |
| **Query Server JVM Options** | (blank) | `-Dport=9999 --add-opens java.base/java.nio=ALL-UNNAMED` ✅ | Port + Arrow fix |
| **Keystore Password** | (auto-generated) | Leave as-is | For SSL connections |

### Supported Java Versions

DB Connect **only supports Java 17 and Java 21**. Java 8 and 11 are NOT supported.

| Try This Path First | Alternative Path |
|--------------------|------------------|
| `/usr/lib/jvm/java-17-openjdk-amd64` | `/usr/lib/jvm/java-21-openjdk-amd64` |

| If You See This Error... | Solution |
|--------------------------|----------|
| "JAVA_HOME not found" | File a Splunk support ticket to get the exact path |
| "Unsupported Java version" | Make sure you're using Java 17 or 21 path |
| "Task Server failed to start" | Check the path exists and JVM options are valid |

### JVM Options for Snowflake (Verified Working)

> ✅ **Both port configuration AND `--add-opens` are required for Snowflake connections!**

| Scenario | Task Server JVM Options |
|----------|------------------------|
| **Standard** | `-Ddw.server.applicationConnectors[0].port=9998 --add-opens java.base/java.nio=ALL-UNNAMED` ✅ |
| **+ Extra Memory** | `-Ddw.server.applicationConnectors[0].port=9998 --add-opens java.base/java.nio=ALL-UNNAMED -Xms512m -Xmx1024m` |

| Scenario | Query Server JVM Options |
|----------|-------------------------|
| **Standard** | `-Dport=9999 --add-opens java.base/java.nio=ALL-UNNAMED` ✅ |
| **+ Extra Memory** | `-Dport=9999 --add-opens java.base/java.nio=ALL-UNNAMED -Xms256m -Xmx512m` |

### JVM Options Explained

```
-Xms512m -Xmx1024m -XX:+UseG1GC -XX:MaxGCPauseMillis=200
```

| Option | Description |
|--------|-------------|
| `-Xms512m` | Initial heap size (512 MB) - memory allocated at startup |
| `-Xmx1024m` | Maximum heap size (1 GB) - memory limit, increase for large result sets |
| `-XX:+UseG1GC` | Use G1 Garbage Collector (default in Java 17+, can be omitted) |
| `-XX:MaxGCPauseMillis=200` | Target max GC pause time (keeps UI responsive) |

### Connection Settings

| Setting | Default | Recommended for Snowflake |
|---------|---------|---------------------------|
| **Fetch Size** | `300` | `1000` - `10000` for large queries |
| **Max Rows** | `0` (unlimited) | Set based on use case |
| **Query Timeout** | `30` seconds | `300` seconds for complex queries |
| **Connection Timeout** | `30` seconds | `60` seconds |
| **Readonly** | `false` | `true` (security best practice) |

### Connection Pool Settings

Configure in **Configuration → Settings → Connection Pooling**:

| Setting | Default | Recommended | Description |
|---------|---------|-------------|-------------|
| **Default Fetch Size** | `300` | `1000` | Rows fetched per network round-trip |
| **Max Connections** | `20` | `10-20` | Max simultaneous connections |
| **Min Idle** | `0` | `2` | Minimum idle connections to maintain |
| **Max Idle** | `8` | `5` | Maximum idle connections |
| **Max Wait** | `-1` | `30000` | Max wait time for connection (ms) |
| **Max Connection Lifetime** | `0` | `1800000` | Connection lifetime (30 min in ms) |

### Snowflake Connection Notes

> ⚠️ **Important**: Splunk DB Connect manages the JDBC URL automatically. You cannot customize JDBC parameters directly.

**What you configure in DB Connect:**
- **Host**: Account identifier only (e.g., `YOUR_ACCOUNT_IDENTIFIER`)
- **Identity**: Username and password

**What uses Snowflake user defaults:**
- Database
- Schema  
- Warehouse
- Role

**To set defaults**, run this in Snowflake for your service account:

```sql
ALTER USER your_username SET 
    DEFAULT_WAREHOUSE = 'COMPUTE_WH'
    DEFAULT_NAMESPACE = 'SECURITY_DATA.OCSF'
    DEFAULT_ROLE = 'SPLUNK_READER';
```

**Or specify fully-qualified table names in queries:**

```sql
SELECT * FROM DATABASE.SCHEMA.TABLE_NAME;
```

### Configuration Files (Advanced)

For Splunk Enterprise, settings are stored in:

```
$SPLUNK_HOME/etc/apps/splunk_app_db_connect/local/db_connections.conf
$SPLUNK_HOME/etc/apps/splunk_app_db_connect/local/db_connection_types.conf
$SPLUNK_HOME/etc/apps/splunk_app_db_connect/local/dbx_settings.conf
```

#### Example `dbx_settings.conf`:

```ini
[dbx_settings]
# JVM settings
jvm_options = -Xms512m -Xmx2048m -XX:+UseG1GC

# Task server
port = 9998

# Logging
log_level = INFO

# Connection pool defaults
default_fetch_size = 1000
```

---

## Demo Scenarios & Queries

### Scenario 1: Historical Threat Investigation

**Use Case**: Investigate a compromised user account over the past 6 months.

```spl
| dbxquery 
    connection="snowflake" 
    query="
        SELECT 
            event_time,
            src_ip,
            dst_ip,
            user_name,
            action,
            status_code,
            user_agent
        FROM authentication_logs 
        WHERE user_name = 'john.doe@company.com'
          AND event_time >= DATEADD(month, -6, CURRENT_DATE())
        ORDER BY event_time DESC
        LIMIT 5000
    "
| eval event_time = strptime(event_time, "%Y-%m-%d %H:%M:%S")
| timechart span=1d count by status_code
```

### Scenario 2: Network Anomaly Detection (Aggregation Pushdown)

**Use Case**: Find top talkers with unusual traffic patterns. Query runs entirely on Snowflake.

```spl
| dbxquery 
    connection="snowflake" 
    query="
        WITH traffic_stats AS (
            SELECT 
                src_ip,
                dst_ip,
                COUNT(*) as connection_count,
                SUM(bytes_out) as total_bytes_out,
                SUM(bytes_in) as total_bytes_in,
                COUNT(DISTINCT dst_port) as unique_ports
            FROM network_activity
            WHERE event_time >= DATEADD(day, -30, CURRENT_DATE())
            GROUP BY src_ip, dst_ip
        )
        SELECT *
        FROM traffic_stats
        WHERE unique_ports > 100  -- Port scanning indicator
           OR total_bytes_out > 10000000000  -- 10GB+ exfiltration
        ORDER BY total_bytes_out DESC
        LIMIT 100
    "
| table src_ip, dst_ip, connection_count, total_bytes_out, unique_ports
| eval total_bytes_out_gb = round(total_bytes_out / 1073741824, 2)
| sort - total_bytes_out_gb
```

### Scenario 3: Compliance Audit (Long-term Data)

**Use Case**: Generate PCI-DSS audit report for the past 12 months.

```spl
| dbxquery 
    connection="snowflake" 
    query="
        SELECT 
            DATE_TRUNC('month', event_time) as month,
            user_name,
            action_type,
            resource_accessed,
            COUNT(*) as access_count
        FROM cloud_audit_logs
        WHERE event_time >= DATEADD(month, -12, CURRENT_DATE())
          AND resource_type = 'CARDHOLDER_DATA'
        GROUP BY 1, 2, 3, 4
        ORDER BY 1, 2
    "
| xyseries month user_name access_count
```

### Scenario 4: Real-time + Historical Correlation

**Use Case**: Correlate real-time Splunk alerts with historical Snowflake data.

```spl
| inputlookup recent_alerts.csv 
| map search="
    | dbxquery 
        connection=\"snowflake\" 
        query=\"
            SELECT event_time, action, details
            FROM endpoint_events
            WHERE src_ip = '$src_ip$'
              AND event_time >= DATEADD(day, -90, CURRENT_DATE())
            LIMIT 1000
        \"
    | eval alert_id = \"$alert_id$\"
    "
| stats count by alert_id, action
```

### Scenario 5: Threat Intelligence Matching

**Use Case**: Match indicators against historical network logs.

```spl
| dbxquery 
    connection="snowflake" 
    query="
        SELECT 
            n.event_time,
            n.src_ip,
            n.dst_ip,
            n.dst_port,
            t.indicator_type,
            t.threat_name,
            t.severity
        FROM network_activity n
        INNER JOIN threat_intel t 
            ON n.dst_ip = t.indicator_value
        WHERE n.event_time >= DATEADD(day, -7, CURRENT_DATE())
          AND t.indicator_type = 'ip'
        ORDER BY t.severity DESC, n.event_time DESC
        LIMIT 500
    "
| table event_time, src_ip, dst_ip, threat_name, severity
```

---

## Troubleshooting

### Common Issues

#### 1. Arrow Library Error (NoClassDefFoundError: RootAllocator)

**Symptom**: 
```
JDBC driver internal error: exception creating result 
java.lang.NoClassDefFoundError: Could not initialize class 
net.snowflake.client.jdbc.internal.apache.arrow.memory.RootAllocator
```

**Cause**: Java 17+ restricts access to internal APIs that the Snowflake JDBC Arrow library needs.

**Solution** (Verified Working): Add these JVM options in **Configuration → Settings → General**:

**Task Server JVM Options:**
```
-Ddw.server.applicationConnectors[0].port=9998 --add-opens java.base/java.nio=ALL-UNNAMED
```

**Query Server JVM Options:**
```
-Dport=9999 --add-opens java.base/java.nio=ALL-UNNAMED
```

#### 2. Connection Failed - JDBC Driver Not Found

**Symptom**: Error "No suitable driver found"

**Solution**:
- Verify JDBC driver is in correct location
- Click **Reload** in Drivers settings
- Check driver file permissions

#### 3. Java Heap Space Error

**Symptom**: `java.lang.OutOfMemoryError: Java heap space`

**Solution**: Add memory settings after the `--add-opens` option:
```
--add-opens=java.base/java.nio=ALL-UNNAMED -Xms512m -Xmx2048m
```

#### 4. Connection Timeout

**Symptom**: Connection times out during query execution

**Solution**:
- Check Snowflake warehouse is not suspended
- Verify network connectivity to Snowflake (port 443)
- Try a simpler query first: `SELECT 1`

#### 5. SSL Certificate Error

**Symptom**: SSL handshake failure

**Solution**:
- Ensure Snowflake account identifier is correct (without `.snowflakecomputing.com`)
- Check network allows outbound 443
- Verify your Snowflake account is accessible

#### 6. No Results Returned

**Symptom**: Query runs but returns empty results

**Solution**:
- Test query directly in Snowflake first
- Check role has SELECT permission
- Verify database/schema/table names are correct (case-sensitive!)

### Logging

Enable debug logging for troubleshooting:

1. Go to **Configuration → Settings → Logging**
2. Set log level to **DEBUG**
3. View logs at: `$SPLUNK_HOME/var/log/splunk/splunk_app_db_connect.log`

---

## References

### Official Documentation

- [Splunk DB Connect Documentation](https://help.splunk.com/en/splunk-cloud-platform/connect-relational-databases/deploy-and-use-splunk-db-connect)
- [Snowflake JDBC Driver for Splunk](https://help.splunk.com/en/splunk-cloud-platform/connect-relational-databases/jdbc-driver-for-the-snowflake-database)
- [Splunk DB Connect Prerequisites](https://docs.splunk.com/Documentation/DBX/latest/DeployDBX/Prerequisites)
- [Snowflake JDBC Driver Parameters](https://docs.snowflake.com/en/user-guide/jdbc-parameters)

### Splunkbase Apps

- [Splunk DB Connect](https://splunkbase.splunk.com/app/2686)
- [JDBC Driver for Snowflake](https://splunkbase.splunk.com/app/6826)
- [Elysium Analytics Add-on](https://splunkbase.splunk.com/app/6391)
- [Snowflake App for Splunk SOAR](https://splunkbase.splunk.com/app/6763)

### Webinars & Resources

- [Snowflake Webinar: Unlock Splunk with Snowflake Federated Queries](https://www.snowflake.com/webinar/thought-leadership/unlock-your-splunk-capabilities-with-snowflake-federated-queries-2024-01-25/)
- [Elysium Analytics Setup Guide (PDF)](https://elysiumanalytics.ai/splunk-add-on/docs/DA-SETUPGUIDE.pdf)

### Announcements

- [Cisco Announces Splunk Federated Search for Snowflake (Sept 2025)](https://www.splunk.com/en_us/newsroom/press-releases/2025/cisco-advances-open-data-ecosystems-with-splunk-federated-search-for-snowflake.html)

---

## Changelog

| Date | Author | Changes |
|------|--------|---------|
| 2026-01-07 | | Initial document creation |

---

## Next Steps

- [ ] Set up Snowflake trial account with sample cybersecurity data
- [ ] Install DB Connect on Splunk Cloud
- [ ] Configure Snowflake connection
- [ ] Test basic queries
- [ ] Build demo dashboard
- [ ] Prepare talking points for demo
- [ ] Run end-to-end demo rehearsal

