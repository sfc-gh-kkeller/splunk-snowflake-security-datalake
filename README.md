# Splunk + Snowflake Security Data Lake

A comprehensive reference architecture and demo toolkit for building a **hybrid security data lake** using Snowflake for cost-effective storage/analytics and Splunk for real-time detection — connected via federated search.

## Why This Exists

Traditional SIEM architectures force a trade-off: ingest everything into Splunk (expensive) or lose visibility. This project demonstrates a hybrid approach:

| Metric | All-Splunk | Hybrid (Splunk + Snowflake) |
|--------|------------|----------------------------|
| **Ingestion Cost** | $$$$$$ | $$ (70-80% savings) |
| **Real-time Detection** | Full | Critical data subset |
| **Historical Investigation** | Limited by cost | Years of data |
| **Compliance/Retention** | Very expensive | Cheap (years) |

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

## What's Included

### Documentation

| Document | Description |
|----------|-------------|
| [`docs/ARCHITECTURE_GUIDE.md`](docs/ARCHITECTURE_GUIDE.md) | Full architecture guide — cost analysis, data routing strategies, feature comparison, implementation phases |
| [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md) | Splunk DB Connect setup — JDBC config, connection setup, troubleshooting |
| [`docs/DEMO_QUERIES.md`](docs/DEMO_QUERIES.md) | 15+ copy-paste SPL queries — correlations, CTEs, hybrid joins, dashboards, advanced analytics |

### Vector Ingestion Demo

A working demo that generates realistic security logs with attack patterns and ingests them into Snowflake (and optionally Splunk) via [Vector](https://vector.dev).

```
vector-ingestion-demo/
├── config/
│   ├── vector.toml              # Vector routing config (Snowflake + Splunk)
│   ├── snowflake_setup.sql      # Table creation DDL
│   └── credentials.example.toml # Credential template
├── scripts/
│   ├── generate_all_logs.py     # Generate Nginx + PostgreSQL attack logs
│   ├── postgres_attacks.py      # Simulate database attacks
│   ├── upload_to_snowflake.py   # Direct CSV upload to Snowflake
│   ├── simple_web_server.py     # Local web server for live attack sim
│   └── ...
├── pixi.toml                    # Dependencies (pixi package manager)
└── env.example                  # Environment variable template
```

### Sample Data

| File | Description |
|------|-------------|
| `data/sample_web_logs.csv` | 50 realistic web log events with overlapping IPs for correlation demos |

## Quick Start

### 1. Generate Security Logs

```bash
cd vector-ingestion-demo

# Install pixi (if needed)
curl -fsSL https://pixi.sh/install.sh | bash

# Install dependencies and generate logs
pixi install
pixi run generate-all
```

This creates CSV/JSON files in `vector-ingestion-demo/logs/` with simulated:
- **Nginx attacks**: SQL injection, XSS, path traversal, command injection, brute force, recon
- **PostgreSQL attacks**: Privilege escalation, data exfiltration, timing attacks

### 2. Set Up Snowflake Tables

```bash
# Via Snow CLI
snow sql -f vector-ingestion-demo/config/snowflake_setup.sql

# Or paste config/snowflake_setup.sql into Snowflake Web UI
```

### 3. Upload to Snowflake

```bash
cp vector-ingestion-demo/env.example vector-ingestion-demo/.env
# Edit .env with your Snowflake credentials

pixi run upload-csv
```

### 4. Connect Splunk to Snowflake

See [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md) for full DB Connect setup instructions.

### 5. Run Queries

See [`docs/DEMO_QUERIES.md`](docs/DEMO_QUERIES.md) for 15+ ready-to-use SPL queries demonstrating:
- Aggregation pushdown (100K rows scanned → 1 row returned)
- CTE-based threat classification
- Hybrid correlations (Splunk + Snowflake joins)
- Statistical anomaly detection (Z-scores via SQL)
- Dashboard XML

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

## Industry Context

Cisco announced **Splunk Federated Search for Snowflake** (GA planned July 2026), providing native integration beyond DB Connect. This repo demonstrates capabilities available today using DB Connect.

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
- **Splunk Cloud**: With DB Connect app installed
- **Local**: Python 3.11+, [pixi](https://pixi.sh) package manager
- **Optional**: Vector (for continuous ingestion), PostgreSQL (for live attack simulation)

## License

MIT
