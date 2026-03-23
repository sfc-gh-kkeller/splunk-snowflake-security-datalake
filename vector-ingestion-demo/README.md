# Vector Ingestion Demo: Snowflake + Splunk

A demo project showing how to ingest security logs into both Snowflake (for storage/analytics) and Splunk (for real-time alerting).

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│  PostgreSQL     │     │  Nginx Logs     │
│  (Suspicious    │     │  (Attack        │
│   Queries)      │     │   Patterns)     │
└────────┬────────┘     └────────┬────────┘
         │                       │
         ▼                       ▼
    ┌────────────────────────────────────┐
    │              VECTOR                │
    │         (Log Router)               │
    └──────────┬──────────────┬──────────┘
               │              │
    ┌──────────▼──────────┐   │
    │     SNOWFLAKE       │   │  Only Nginx
    │   (All Logs)        │   │  attack logs
    │   - PostgreSQL ✓    │   │
    │   - Nginx ✓         │   │
    └─────────────────────┘   │
                              ▼
                    ┌─────────────────────┐
                    │       SPLUNK        │
                    │  (Critical Logs)    │
                    │   - Nginx attacks ✓ │
                    │   - PostgreSQL ✗    │
                    └─────────────────────┘
```

**Routing Strategy:**
- **Nginx logs (CRITICAL)** → Snowflake + Splunk
- **PostgreSQL logs** → Snowflake only (not real-time critical)

## Quick Start

### 1. Install Dependencies

```bash
# Install pixi if not already installed
curl -fsSL https://pixi.sh/install.sh | bash

# Install project dependencies
cd vector-ingestion-demo
pixi install
```

### 2. Setup

```bash
# Run complete setup
pixi run setup

# This creates directories and installs Vector
```

### 3. Generate Logs (Quick Demo - No Database Required)

```bash
# Generate sample Nginx + PostgreSQL logs with attack patterns
pixi run generate-all

# This creates CSV and JSON files in ./logs/
```

### 4. Upload to Snowflake (Quick Method)

```bash
# Configure credentials in .env file first
cp env.example .env
# Edit .env with your Snowflake credentials

# Upload CSV files directly to Snowflake
pixi run upload-csv
```

## Full Demo with PostgreSQL

### Initialize PostgreSQL

```bash
# Initialize PostgreSQL (first time only)
pixi run pg-init

# Start PostgreSQL
pixi run pg-start

# Check status
pixi run pg-status
```

### Run Attack Simulation

```bash
# Run suspicious queries against PostgreSQL
# All queries are logged for ingestion
pixi run pg-attacks

# Or run comprehensive suspicious query simulation
pixi run pg-suspicious
```

### Stop PostgreSQL

```bash
pixi run pg-stop
```

## Vector Ingestion (Production-like)

For continuous ingestion instead of CSV upload:

```bash
# Validate Vector configuration
pixi run vector-validate

# Run Vector
pixi run vector-run
```

## Configuration

### Environment Variables (.env)

```bash
# Snowflake
SNOWFLAKE_ACCOUNT=your_account
SNOWFLAKE_USER=your_user
SNOWFLAKE_PASSWORD=your_password
SNOWFLAKE_WAREHOUSE=COMPUTE_WH
SNOWFLAKE_DATABASE=SECURITY_LOGS
SNOWFLAKE_SCHEMA=PUBLIC

# Splunk HEC (for Vector)
SPLUNK_HEC_URL=https://your-instance.splunkcloud.com:8088
SPLUNK_HEC_TOKEN=your-hec-token
```

### Snowflake Setup

Create tables in Snowflake before uploading:

```bash
# Run via snow cli
snow sql -f config/snowflake_setup.sql

# Or copy/paste config/snowflake_setup.sql into Snowflake Web UI
```

## Files Generated

| File | Description | Destination |
|------|-------------|-------------|
| `logs/nginx_access_*.csv` | Nginx logs with attacks | Snowflake + Splunk |
| `logs/nginx_access_*.json` | JSON format for Vector | Snowflake + Splunk |
| `logs/postgresql_*.csv` | PostgreSQL query logs | Snowflake only |
| `logs/postgresql_*.json` | JSON format for Vector | Snowflake only |

## Attack Patterns Simulated

### Nginx (Web Attacks)
- SQL Injection (`' OR '1'='1`, `UNION SELECT`, etc.)
- XSS (`<script>alert()</script>`)
- Path Traversal (`../../../etc/passwd`)
- Command Injection (`;cat /etc/passwd`)
- Reconnaissance (`/.git/config`, `/.env`)
- Brute Force (repeated login attempts)

### PostgreSQL (Database Attacks)
- SQL Injection attempts
- Privilege escalation (`UPDATE users SET role='admin'`)
- Data exfiltration (`SELECT * FROM credit_cards`)
- Reconnaissance (`information_schema` queries)
- Timing attacks (`pg_sleep()`)

## Pixi Commands Reference

| Command | Description |
|---------|-------------|
| `pixi run setup` | Complete initial setup |
| `pixi run pg-init` | Initialize PostgreSQL |
| `pixi run pg-start` | Start PostgreSQL |
| `pixi run pg-stop` | Stop PostgreSQL |
| `pixi run pg-attacks` | Run attack simulation |
| `pixi run generate-all` | Generate sample logs |
| `pixi run upload-csv` | Upload CSVs to Snowflake |
| `pixi run vector-run` | Run Vector for ingestion |

## Sample Snowflake Queries

After uploading data, try these queries:

```sql
-- Attack summary
SELECT attack_type, COUNT(*) as count
FROM SECURITY_LOGS.PUBLIC.NGINX_LOGS
WHERE is_attack = TRUE
GROUP BY attack_type
ORDER BY count DESC;

-- Suspicious PostgreSQL queries
SELECT log_time, user_name, attack_pattern, query
FROM SECURITY_LOGS.PUBLIC.POSTGRES_LOGS
WHERE is_suspicious = TRUE
LIMIT 20;

-- Cross-system correlation
SELECT 
    n.client_ip,
    n.attack_type,
    p.attack_pattern,
    n.timestamp
FROM NGINX_LOGS n
JOIN POSTGRES_LOGS p 
    ON n.client_ip = p.connection_from
WHERE n.is_attack = TRUE AND p.is_suspicious = TRUE;
```

## Integration with Splunk

Use Splunk DB Connect to query Snowflake data:

```spl
| dbxquery connection="snowflake" 
    query="SELECT * FROM SECURITY_LOGS.PUBLIC.NGINX_LOGS 
           WHERE is_attack = TRUE 
           ORDER BY timestamp DESC LIMIT 100"
| table timestamp, client_ip, attack_type, request_path
```

For hybrid correlation (Splunk local + Snowflake):

```spl
| dbxquery connection="snowflake" 
    query="SELECT client_ip, attack_type FROM NGINX_LOGS WHERE is_attack=TRUE"
| rename client_ip as src_ip
| join src_ip [search index=main sourcetype=access_combined]
```

## Project Structure

```
vector-ingestion-demo/
├── config/
│   ├── vector.toml           # Vector configuration
│   ├── snowflake_setup.sql   # Snowflake table creation
│   └── credentials.example.toml
├── scripts/
│   ├── setup_all.sh          # Complete setup
│   ├── install_vector.sh     # Vector installation
│   ├── postgres_init.sh      # PostgreSQL initialization
│   ├── generate_all_logs.py  # Log generator
│   ├── postgres_attacks.py   # Attack simulator
│   ├── upload_to_snowflake.py # CSV uploader
│   └── ...
├── logs/                     # Generated logs
├── output/                   # Vector output
├── data/                     # PostgreSQL data
├── pixi.toml                 # Dependencies
├── env.example               # Environment template
└── README.md
```
