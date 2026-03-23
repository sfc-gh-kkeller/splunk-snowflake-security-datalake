# Splunk + Snowflake: Optimal Security Data Architecture

> A comprehensive guide to combining Splunk and Snowflake for cost-effective security operations

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [The Cost Problem](#the-cost-problem)
3. [Feature Comparison](#feature-comparison)
4. [Optimal Architecture](#optimal-architecture)
5. [Data Routing Strategies](#data-routing-strategies)
6. [Tool Options](#tool-options)
7. [Implementation Guide](#implementation-guide)
8. [What Works & What Doesn't](#what-works--what-doesnt)
9. [Cost Savings Analysis](#cost-savings-analysis)
10. [Decision Framework](#decision-framework)

---

## Executive Summary

### The Key Insight

**Splunk excels at real-time detection and response. Snowflake excels at cost-effective storage and analytics.**

The optimal architecture uses both:
- **Snowflake** as the primary security data lake (ALL data)
- **Splunk** for real-time detection on critical data subset (20-30% of data)
- **Federated Search** (DB Connect) to query Snowflake from Splunk

### Bottom Line

| Metric | All-Splunk | Hybrid (Splunk + Snowflake) |
|--------|------------|----------------------------|
| **Ingestion Cost** | $$$$$$ | $$ (70-80% savings) |
| **Real-time Detection** | ✅ Full | ✅ Critical data |
| **Historical Investigation** | Limited by cost | ✅ Years of data |
| **Threat Hunting** | Expensive | ✅ Cost-effective |
| **Compliance/Retention** | Very expensive | ✅ Cheap (years) |

---

## The Cost Problem

### Splunk Pricing Reality

| Component | Splunk Cloud | Notes |
|-----------|--------------|-------|
| **Base Platform** | ~$150-200/GB/day ingested | The big cost |
| **Enterprise Security (ES)** | Additional ~$50-100/GB/day | Required for SIEM features |
| **SOAR** | Additional licensing | Automation/response |
| **Storage** | Included (limited) | Retention drives cost |

**Key insight:** Splunk charges primarily on **ingestion**, not storage. Once ingested, you've paid.

### Snowflake Pricing Reality

| Component | Cost | Notes |
|-----------|------|-------|
| **Storage** | ~$23-40/TB/month | 50-100x cheaper than Splunk |
| **Compute** | Per-second billing | Only pay when querying |
| **Ingestion** | Free (via Snowpipe) | No per-GB ingestion cost |

### Cost Comparison Example

| Scenario | Daily Volume | Splunk Cost/Month | Snowflake Cost/Month |
|----------|--------------|-------------------|---------------------|
| **All to Splunk** | 100 GB/day | ~$15,000-20,000 | $0 |
| **Hybrid (20% to Splunk)** | 100 GB total | ~$3,000-4,000 | ~$100 |
| **Savings** | - | - | **~80%** |

---

## Feature Comparison

### What Splunk Provides

| Feature | Base Splunk Cloud | Splunk ES (Premium) | Notes |
|---------|-------------------|---------------------|-------|
| **Search & Analytics** | ✅ | ✅ | SPL query language |
| **Dashboards** | ✅ | ✅ | Full visualization |
| **Scheduled Alerts** | ✅ | ✅ | Email, webhook |
| **Real-time Alerts** | ✅ | ✅ | Sub-second |
| **Pre-built Detections** | ❌ | ✅ 1400+ | MITRE ATT&CK mapped |
| **Threat Intelligence** | ❌ | ✅ | Feeds included |
| **SOAR/Automation** | ❌ | Separate license | Playbooks, response |
| **Risk-based Alerting** | ❌ | ✅ | Correlation |
| **MLTK (ML)** | ✅ | ✅ | Requires indexed data |

**Important:** Many "Splunk features" people assume are included actually require **Enterprise Security (ES)** - an expensive add-on.

### What Snowflake Provides

| Feature | Status | Notes |
|---------|--------|-------|
| **SQL Analytics** | ✅ | Full SQL support |
| **Storage** | ✅ | Cheap, scalable |
| **Dashboards** | ✅ Streamlit | Native integration |
| **Scheduled Queries** | ✅ Tasks | Cron-like scheduling |
| **Alerts/Notifications** | ✅ | Email, webhook via External Functions |
| **AI/ML** | ✅ Cortex | LLMs, ML functions |
| **Real-time Ingestion** | ✅ Snowpipe Streaming | Seconds latency |
| **Near-real-time Processing** | ✅ Dynamic Tables | Minutes latency |
| **Pre-built Detections** | ❌ | Must build or buy |
| **Threat Intelligence** | ❌ | Must source separately |
| **SOAR/Automation** | ❌ | Must build or integrate |

### The Gap: What's Hard to Replicate in Snowflake

| Splunk Capability | Challenge in Snowflake | Workaround |
|-------------------|------------------------|------------|
| **Sub-second Alerting** | Min ~1 minute latency | Accept delay or use streaming tool |
| **Pre-built Detections** | Years of security research | Buy from Panther, Hunters, Anvilogic |
| **Threat Intel Feeds** | Need to source & maintain | Recorded Future, CrowdStrike APIs |
| **SOAR Playbooks** | Complex to build | Tines, Torq, or custom |
| **SPL Expertise** | Different skill set | SQL is more common |

---

## Optimal Architecture

### Recommended: Snowflake-First Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ALL LOG SOURCES                           │
│     (Firewall, EDR, Auth, Cloud, Web, App, DNS, NetFlow)        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     ROUTING LAYER                                │
│              (Vector, Kafka, Fluent Bit, Cribl)                 │
│                                                                  │
│   ┌──────────────────────────────────────────────────────────┐  │
│   │                    DISK BUFFER                            │  │
│   │            (Ensures no data loss)                         │  │
│   └──────────────────────────────────────────────────────────┘  │
│                    │                           │                 │
│                    │ ALL DATA                  │ CRITICAL ONLY   │
│                    ▼                           ▼                 │
└─────────────────────────────────────────────────────────────────┘
                    │                           │
                    ▼                           ▼
┌──────────────────────────┐      ┌──────────────────────────┐
│       SNOWFLAKE          │      │         SPLUNK           │
│   (Security Data Lake)   │      │   (Real-time Detection)  │
│                          │      │                          │
│  • ALL logs              │◀────▶│  • Critical subset only  │
│  • Years of retention    │      │  • 30-90 day retention   │
│  • ~$23-40/TB/month      │      │  • ES for detections     │
│  • Threat hunting        │      │  • Real-time alerts      │
│  • Compliance            │      │  • SOAR integration      │
│  • ML/Analytics          │      │                          │
└──────────────────────────┘      └──────────────────────────┘
         ▲                                    │
         │            DB Connect              │
         └────────────────────────────────────┘
              (Federated Search for Investigation)
```

### Data Flow

1. **All logs** → Routing layer (Vector/Kafka)
2. **All logs** → Snowflake (cheap storage, full retention)
3. **Critical logs** → Also to Splunk (real-time detection)
4. **Splunk retention** → Auto-delete after 30-90 days
5. **Investigation** → Splunk queries Snowflake via DB Connect

### What Goes Where

| Data Type | Volume | To Snowflake | To Splunk | Rationale |
|-----------|--------|--------------|-----------|-----------|
| **Authentication (AD, Okta, SSO)** | Medium | ✅ | ✅ | Critical for real-time detection |
| **Firewall/IDS/IPS** | High | ✅ | ✅ | Attack detection |
| **EDR (CrowdStrike, Defender)** | Medium | ✅ | ✅ | Endpoint threats |
| **Cloud Audit (AWS, Azure, GCP)** | Medium | ✅ | ✅ | Cloud security |
| **Email Security** | Medium | ✅ | ✅ | Phishing detection |
| **Web/Proxy Logs** | Very High | ✅ | ⚠️ Sample | Volume too high for full ingest |
| **Application Logs** | Very High | ✅ | ❌ | Investigation only |
| **DNS Logs** | Massive | ✅ | ⚠️ Sample | Hunting, not real-time |
| **NetFlow/PCAP Metadata** | Massive | ✅ | ❌ | Forensics only |
| **Vulnerability Scans** | Low | ✅ | ⚠️ Optional | Correlation |

**Result:** ~20-30% of data goes to Splunk, 100% goes to Snowflake.

---

## Data Routing Strategies

### Strategy 1: Dual-Write with Filtering

```
Source → Router → Filter(critical) → Splunk
              └──→ ALL → Snowflake
```

- Simple and effective
- Router handles buffering
- Each destination independent

### Strategy 2: Snowflake-First with Selective Forward

```
Source → Snowflake (via Snowpipe) 
              └──→ Snowflake Stream → Task → Forward to Splunk
```

- All data lands in Snowflake first
- Stream detects new data
- Task forwards critical subset to Splunk
- More complex, but Snowflake is source of truth

### Strategy 3: Kafka Hub (Enterprise Scale)

```
Source → Kafka (persistent buffer)
              ├──→ Consumer A → Snowflake (all topics)
              └──→ Consumer B → Splunk (critical topics)
```

- Most reliable (replay capability)
- Best for very high volume
- More infrastructure to manage

---

## Tool Options

### Comparison Matrix

| Tool | Complexity | Reliability | Buffer | Replay | Cost | Best For |
|------|------------|-------------|--------|--------|------|----------|
| **Vector** | Low | Very Good | Disk | No | Free | Medium scale, simple |
| **Fluent Bit** | Low | Good | Limited | No | Free | Edge/lightweight |
| **Fluentd** | Medium | Good | Plugin | No | Free | Flexible routing |
| **Kafka** | High | Excellent | Unlimited | Yes | Free* | Enterprise, mission-critical |
| **Cribl** | Medium | Excellent | Yes | No | $$$ | Splunk-focused |

*Kafka is free but requires infrastructure

### Recommended: Vector

**Why Vector:**
- Single binary, easy to deploy
- Disk-based buffering (survives restarts)
- Native Splunk HEC and S3 outputs
- Low resource usage (Rust-based)
- Simple TOML configuration

---

## Implementation Guide

### Phase 1: Set Up Vector for Dual-Write

**Install Vector:**
```bash
curl --proto '=https' --tlsv1.2 -sSfL https://sh.vector.dev | bash
```

**Configuration (`/etc/vector/vector.toml`):**

```toml
# ====================
# SOURCES
# ====================

[sources.syslog]
type = "syslog"
address = "0.0.0.0:514"

[sources.http]
type = "http_server"
address = "0.0.0.0:8080"

# ====================
# TRANSFORMS
# ====================

[transforms.classify]
type = "remap"
inputs = ["syslog", "http"]
source = '''
  # Classify logs
  if contains(string!(.source), "auth") || contains(string!(.source), "okta") {
    .log_type = "auth"
    .is_critical = true
  } else if contains(string!(.source), "firewall") || contains(string!(.source), "palo") {
    .log_type = "firewall"
    .is_critical = true
  } else if contains(string!(.source), "crowdstrike") || contains(string!(.source), "edr") {
    .log_type = "edr"
    .is_critical = true
  } else if contains(string!(.source), "cloudtrail") || contains(string!(.source), "aws") {
    .log_type = "cloud"
    .is_critical = true
  } else {
    .log_type = "other"
    .is_critical = false
  }
'''

[transforms.critical_only]
type = "filter"
inputs = ["classify"]
condition = '.is_critical == true'

# ====================
# SINKS
# ====================

# ALL logs to S3 (for Snowflake)
[sinks.snowflake_s3]
type = "aws_s3"
inputs = ["classify"]
bucket = "security-logs-lake"
region = "us-east-1"
key_prefix = "logs/{{ log_type }}/%Y/%m/%d/"
compression = "gzip"
encoding.codec = "json"

[sinks.snowflake_s3.buffer]
type = "disk"
max_size = 10737418240  # 10GB
when_full = "block"

# CRITICAL logs to Splunk
[sinks.splunk]
type = "splunk_hec_logs"
inputs = ["critical_only"]
endpoint = "https://your-instance.splunkcloud.com:8088"
token = "${SPLUNK_HEC_TOKEN}"
index = "security"

[sinks.splunk.buffer]
type = "disk"
max_size = 5368709120  # 5GB
when_full = "block"
```

### Phase 2: Set Up Snowflake Auto-Ingestion

```sql
-- Create database and schema
CREATE DATABASE security_lake;
CREATE SCHEMA security_lake.logs;

-- Create table for logs
CREATE TABLE security_lake.logs.all_logs (
    timestamp TIMESTAMP_NTZ,
    log_type STRING,
    source STRING,
    message VARIANT,
    raw_log STRING,
    ingestion_time TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

-- Create stage for S3
CREATE STAGE security_logs_stage
  URL = 's3://security-logs-lake/logs/'
  CREDENTIALS = (AWS_KEY_ID = '...' AWS_SECRET_KEY = '...')
  FILE_FORMAT = (TYPE = JSON);

-- Create Snowpipe for auto-ingestion
CREATE PIPE security_logs_pipe AUTO_INGEST = TRUE AS
  COPY INTO security_lake.logs.all_logs (timestamp, log_type, source, message, raw_log)
  FROM (
    SELECT 
      $1:timestamp::TIMESTAMP_NTZ,
      $1:log_type::STRING,
      $1:source::STRING,
      $1,
      $1::STRING
    FROM @security_logs_stage
  )
  FILE_FORMAT = (TYPE = JSON);

-- Get notification channel for S3 event setup
SELECT SYSTEM$PIPE_STATUS('security_logs_pipe');
```

### Phase 3: Configure Splunk Retention

In Splunk Cloud, set retention via support ticket or Admin Config Service:

```
# indexes.conf settings to request
[security]
frozenTimePeriodInSecs = 2592000  # 30 days
maxTotalDataSizeMB = 500000       # 500GB limit
```

### Phase 4: Set Up DB Connect for Federated Search

See `SPLUNK_SNOWFLAKE_DEMO_GUIDE.md` for detailed DB Connect setup.

---

## What Works & What Doesn't

### ✅ What Works with DB Connect (Tested)

| Capability | Status | Notes |
|------------|--------|-------|
| Dashboards | ✅ | Full visualization support |
| Scheduled Reports | ✅ | PDF, CSV export |
| Scheduled Alerts | ✅ | 1-5 minute intervals |
| Ad-hoc Search | ✅ | Interactive investigation |
| Join Splunk + Snowflake | ✅ | Hybrid correlation |
| Subsearch with dbxquery | ✅ | With correct syntax |
| SPL Post-Processing | ✅ | stats, eval, where work |

### ⚠️ What Has Limitations

| Capability | Limitation | Workaround |
|------------|------------|------------|
| Real-time Alerts | Batch only (1+ min) | Use Splunk for real-time on critical data |
| MLTK | Needs indexed data | Use Snowflake Cortex ML |
| Data Models | Needs indexed data | Query Snowflake directly |
| Sub-second Queries | 1-5 second latency | Acceptable for investigation |

### ❌ What Doesn't Work

| Capability | Why | Alternative |
|------------|-----|-------------|
| Real-time streaming from Snowflake | dbxquery is batch | Keep real-time data in Splunk |
| Splunk ES detections on Snowflake data | ES needs indexed data | Run detections on Splunk subset |
| SOAR on Snowflake events | SOAR needs Splunk events | Alert from Snowflake → webhook → SOAR |

---

## Cost Savings Analysis

### Before: All Data to Splunk

| Data Source | Daily Volume | Splunk Cost/Month |
|-------------|--------------|-------------------|
| Firewall | 30 GB | $4,500 |
| EDR | 15 GB | $2,250 |
| Auth | 5 GB | $750 |
| Cloud Audit | 10 GB | $1,500 |
| Web/Proxy | 25 GB | $3,750 |
| App Logs | 10 GB | $1,500 |
| DNS | 5 GB | $750 |
| **Total** | **100 GB/day** | **~$15,000/month** |

### After: Hybrid Architecture

| Data Source | To Snowflake | To Splunk | Snowflake Cost | Splunk Cost |
|-------------|--------------|-----------|----------------|-------------|
| Firewall | 30 GB | 30 GB | $23 | $4,500 |
| EDR | 15 GB | 15 GB | $12 | $2,250 |
| Auth | 5 GB | 5 GB | $4 | $750 |
| Cloud Audit | 10 GB | 10 GB | $8 | $1,500 |
| Web/Proxy | 25 GB | ❌ | $19 | $0 |
| App Logs | 10 GB | ❌ | $8 | $0 |
| DNS | 5 GB | ❌ | $4 | $0 |
| **Total** | **100 GB** | **60 GB** | **~$78/month** | **~$9,000/month** |

### Savings Summary

| Metric | Before | After | Savings |
|--------|--------|-------|---------|
| Monthly Splunk Cost | $15,000 | $9,000 | **$6,000 (40%)** |
| Monthly Snowflake Cost | $0 | $78 | - |
| **Net Monthly Savings** | - | - | **~$5,900** |
| **Annual Savings** | - | - | **~$71,000** |

**Note:** Savings increase as you reduce Splunk percentage. At 20% to Splunk: ~$12,000/month savings.

---

## Decision Framework

### When to Use Splunk

- ✅ Real-time detection (sub-minute)
- ✅ Pre-built security detections (with ES)
- ✅ SOAR automation and response
- ✅ Existing SPL expertise
- ✅ Compliance requiring specific SIEM

### When to Use Snowflake

- ✅ Long-term retention (years)
- ✅ Cost-effective storage
- ✅ Threat hunting on historical data
- ✅ Compliance archives
- ✅ Custom analytics and ML
- ✅ Data sharing across teams

### When to Use Both (Recommended)

- ✅ Cost optimization while maintaining detection
- ✅ Best-of-breed approach
- ✅ Gradual migration strategy
- ✅ Separation of hot/cold data

---

## Quick Reference

### Architecture Decision Tree

```
Is real-time detection (<1 min) required?
├── YES → Send to Splunk + Snowflake
└── NO → Send to Snowflake only

Is data volume very high (>50 GB/day per source)?
├── YES → Consider sampling for Splunk, full to Snowflake
└── NO → Full to both if critical

Is this data used for ES detections?
├── YES → Must go to Splunk
└── NO → Snowflake only is fine

Retention requirement >90 days?
├── YES → Snowflake (cost-effective)
└── NO → Either works
```

### Tool Quick Reference

| Need | Tool |
|------|------|
| Simple dual-write | Vector |
| Enterprise scale | Kafka |
| Lightweight/edge | Fluent Bit |
| Splunk-native | Cribl ($$) |
| Snowflake ingestion | Snowpipe |
| Federated search | DB Connect |

---

## Next Steps

1. **Assess current state:** What's your daily ingest volume and sources?
2. **Identify critical sources:** Which need real-time detection?
3. **Set up routing layer:** Start with Vector for simplicity
4. **Configure Snowflake:** Database, Snowpipe, tables
5. **Configure DB Connect:** Federated search capability
6. **Test hybrid queries:** Validate correlation works
7. **Adjust Splunk retention:** Reduce to 30-90 days
8. **Monitor costs:** Track savings over time

---

## Related Documents

- `DEMO_GUIDE.md` - DB Connect setup instructions
- `DEMO_QUERIES.md` - Demo queries and use cases
- `../data/sample_web_logs.csv` - Sample data for testing

---

*Last Updated: January 2026*

