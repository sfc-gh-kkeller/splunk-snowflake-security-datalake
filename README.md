# Splunk + Snowflake Security Data Lake

A reference architecture and demo toolkit for building a **hybrid security data lake** using Snowflake for cost-effective storage/analytics and Splunk for real-time detection — connected via federated search.

## Why This Exists

Traditional SIEM architectures force a trade-off: ingest everything into Splunk (expensive) or lose visibility. This project demonstrates a hybrid approach:

| Metric | All-Splunk | Hybrid (Splunk + Snowflake) |
|--------|------------|----------------------------|
| **Ingestion Cost** | $$$$$$ | $$ (70-80% savings) |
| **Real-time Detection** | Full | Critical data subset |
| **Historical Investigation** | Limited by cost | Years of data |
| **Compliance/Retention** | Very expensive | Cheap (years) |

Run the [savings calculator](#savings-calculator) with your own volumes to see the exact impact.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ALL LOG SOURCES                        │
│   (Firewall, EDR, Auth, Cloud, Web, App, DNS, NetFlow)  │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                   ROUTING LAYER                          │
│            (Vector, Kafka, Fluent Bit, Cribl)           │
│                 │                        │               │
│           ALL DATA                 CRITICAL ONLY         │
└────────────┬─────────────────────────────┬──────────────┘
             │                             │
             ▼                             ▼
┌────────────────────────┐   ┌────────────────────────────┐
│      SNOWFLAKE         │   │          SPLUNK             │
│  (Security Data Lake)  │   │   (Real-time Detection)    │
│                        │   │                            │
│  • ALL logs            │◄─▶│  • Critical subset (~20%)  │
│  • Years of retention  │   │  • 30-90 day retention     │
│  • ~$23-40/TB/month    │   │  • ES for detections       │
│  • Threat hunting      │   │  • Real-time alerts        │
│  • Compliance          │   │  • SOAR integration        │
└────────────────────────┘   └────────────────────────────┘
         ▲         DB Connect / Federated Search         │
         └───────────────────────────────────────────────┘
```

## Quick Start

Choose the path that fits your situation:

### Path A: Pre-built Dataset (5 minutes, recommended for demos)

Load the 100K-row demo dataset into Snowflake and connect Splunk immediately.

```bash
# Option 1: Using make
make quickstart

# Option 2: Using snow CLI directly
snow sql -f data/demo/setup_workbook.sql -c your_connection

# Upload CSVs to stage
snow stage copy data/demo/access_logs.csv @CTF.PUBLIC.CTF_UPLOAD_STAGE/access_logs -c your_connection
snow stage copy data/demo/asset_inventory.csv @CTF.PUBLIC.CTF_UPLOAD_STAGE/asset_inventory -c your_connection
snow stage copy data/demo/vulnerabilities.csv @CTF.PUBLIC.CTF_UPLOAD_STAGE/vulnerabilities -c your_connection
snow stage copy data/demo/security_findings.csv @CTF.PUBLIC.CTF_UPLOAD_STAGE/security_findings -c your_connection
```

Then import the [pre-built Splunk dashboard](#pre-built-splunk-dashboard) and connect via [DB Connect](docs/DEMO_GUIDE.md).

### Path B: Generate Fresh Data with Pixi (10 minutes)

Generate realistic attack logs and upload them to your own Snowflake tables.

```bash
cd vector-ingestion-demo
curl -fsSL https://pixi.sh/install.sh | bash   # install pixi if needed
cp env.example .env                              # edit with your Snowflake creds
pixi install
pixi run quickstart                              # creates tables, generates logs, uploads
```

### Path C: Docker Demo (5 minutes, no local installs)

Generate attack logs without installing Python or pixi locally. Snowflake upload still uses `snow` CLI.

```bash
docker compose up                                # generates logs in ./vector-ingestion-demo/output/
# Then upload the output files to Snowflake using snow CLI or the Snowflake UI
```

## What's Included

### Documentation

| Document | Description |
|----------|-------------|
| [`docs/ARCHITECTURE_GUIDE.md`](docs/ARCHITECTURE_GUIDE.md) | Full architecture guide — cost analysis, data routing strategies, feature comparison, implementation phases |
| [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md) | Splunk DB Connect setup + Native Federated Search readiness (GA July 2026) |
| [`docs/DEMO_QUERIES.md`](docs/DEMO_QUERIES.md) | 15+ copy-paste SPL queries — correlations, CTEs, hybrid joins, dashboards, advanced analytics |

### Pre-built Splunk Dashboard

Import [`splunk/dashboards/snowflake_security_lake.xml`](splunk/dashboards/snowflake_security_lake.xml) directly into Splunk:

1. Go to **Settings > User Interface > Dashboards**
2. Click **Create New Dashboard** > **Source (XML)**
3. Paste the contents of `snowflake_security_lake.xml`

The dashboard includes: KPI panels, request method distribution, status code breakdown, endpoint risk assessment (CTE), vulnerability severity heatmap, backend server health, security findings, and statistical anomaly detection (Z-scores).

### Savings Calculator

Estimate your cost savings with a personalized report:

```bash
python3 tools/savings_calculator.py              # interactive prompts
python3 tools/savings_calculator.py --total 100  # quick: 100 GB/day total
python3 tools/savings_calculator.py --csv        # export as CSV
```

### Mock Splunk Demo (No Splunk Required)

Don't have a Splunk instance? Run the mock Splunk UI to show prospects what federated search looks like:

```bash
make splunk-demo                    # or: streamlit run tools/splunk_demo.py
```

This launches a Streamlit app with a Splunk-like dark theme that includes:
- **Dashboard tab** — KPI metrics, charts, and risk tables, all populated by "federated queries"
- **Search tab** — pick pre-built SPL queries, click Search, watch results come back from Snowflake
- **Job Inspector** — shows "0 events scanned" proving compute offloading to Snowflake
- **Dual mode** — works offline with mock data (default), or toggle to live Snowflake queries

### Vector Ingestion Demo

A working demo that generates realistic security logs with attack patterns and routes them via [Vector](https://vector.dev):

```
vector-ingestion-demo/
├── config/
│   ├── vector.toml              # Vector routing config (Snowflake + Splunk)
│   ├── snowflake_setup.sql      # Table creation DDL (source of truth)
│   └── credentials.example.toml # Credential template
├── scripts/
│   ├── snowflake_setup.py       # Create Snowflake tables from SQL file
│   ├── generate_all_logs.py     # Generate Nginx + PostgreSQL attack logs
│   ├── upload_to_snowflake.py   # Direct CSV upload to Snowflake
│   ├── simple_web_server.py     # Local web server for live attack sim
│   └── ...
├── pixi.toml                    # Dependencies and task definitions
├── Dockerfile                   # For Docker-based demos
└── env.example                  # Environment variable template
```

### Demo Data

| File | Rows | Description |
|------|------|-------------|
| [`data/demo/setup_workbook.sql`](data/demo/setup_workbook.sql) | --- | Full SQL workbook: DDL, staging, COPY INTO, verification |
| `data/demo/access_logs.csv` | 100,000 | Web access logs with realistic attack patterns |
| `data/demo/asset_inventory.csv` | 844 | Server/resource catalog (OS, specs, cloud provider) |
| `data/demo/vulnerabilities.csv` | 15,000 | Vulnerability scan results with severity and status |
| `data/demo/security_findings.csv` | 106 | Security findings derived from access log anomalies |
| `data/sample_web_logs.csv` | 50 | Overlapping IPs for Splunk hybrid correlation demos |

## Key Findings

### What Works with Federated Search

| Capability | Status |
|------------|--------|
| Dashboards & Visualizations | Fully supported |
| Scheduled Alerts (1-5 min) | Fully supported |
| Ad-hoc Threat Hunting | Fully supported |
| Hybrid Joins (Splunk + Snowflake) | Fully supported |
| Subsearch Filters | Fully supported |
| SPL Post-Processing | Fully supported |

### Known Limitations

| Capability | Limitation | Workaround |
|------------|------------|------------|
| Real-time Alerts | Batch only (1+ min) | Keep critical data in Splunk |
| MLTK / ML Toolkit | Needs indexed data | Use Snowflake SQL analytics (Z-scores, window functions) |
| Data Models / ES Detections | Needs indexed data | Run detections on Splunk subset |
| Query Latency | 1-5 seconds | Acceptable for investigation use cases |

## Cost Comparison

| Storage | Approximate Cost |
|---------|-----------------|
| Splunk Cloud | ~$1,500-$3,000/GB/year |
| Snowflake | ~$276-$480/TB/year |
| **Ratio** | **~50-100x cheaper** for historical data |

**Strategy**: Keep 7-30 days in Splunk for real-time detection. Keep 1-5 years in Snowflake for investigations and compliance. Federated search bridges the gap.

Run `python3 tools/savings_calculator.py --total <your_daily_GB>` for a personalized breakdown.

## Industry Context

Cisco announced **Splunk Federated Search for Snowflake** at .conf25 (September 2025), with GA planned for July 2026 on Splunk Cloud AWS. This provides native SPL integration beyond DB Connect.

**This repo works today** using DB Connect. When the native integration is GA, only the Splunk query syntax changes — the Snowflake tables and data model remain identical. See [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md) for the migration path.

## Attack Patterns Simulated

### Web (Nginx)
- SQL Injection (`' OR '1'='1`, `UNION SELECT`)
- XSS (`<script>alert()</script>`)
- Path Traversal (`../../../etc/passwd`)
- Command Injection (`;cat /etc/passwd`)
- Reconnaissance (`/.git/config`, `/.env`)
- Brute Force (repeated login attempts)

### Database (PostgreSQL)
- SQL Injection attempts
- Privilege escalation (`UPDATE users SET role='admin'`)
- Data exfiltration (`SELECT * FROM credit_cards`)
- Schema reconnaissance (`information_schema` queries)
- Timing attacks (`pg_sleep()`)

## Requirements

- **Snowflake**: Any edition (Enterprise recommended)
- **Splunk Cloud**: With DB Connect app installed (or Native Federated Search when GA)
- **Local**: One of:
  - [pixi](https://pixi.sh) package manager (recommended)
  - Docker (for zero-install demo)
  - Python 3.11+ (manual setup)
- **Optional**: Vector (for continuous ingestion), PostgreSQL (for live attack simulation)

## License

MIT
