#!/usr/bin/env python3
"""
Quick CSV Upload to Snowflake

A quick and dirty alternative to S3/Snowpipe for demo purposes.
This script:
1. Reads generated log files (CSV format)
2. Uploads directly to Snowflake using PUT/COPY INTO

Usage:
    pixi run upload-csv
    python scripts/upload_to_snowflake.py --file logs/nginx_access.csv --table NGINX_LOGS
"""

import os
import sys
import glob
import argparse
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()

# Check for snowflake connector
try:
    import snowflake.connector
    from snowflake.connector.pandas_tools import write_pandas
    import pandas as pd
except ImportError:
    console.print("[red]Error: snowflake-connector-python and pandas required[/red]")
    console.print("Install with: pixi install")
    sys.exit(1)


def get_snowflake_config():
    """Load Snowflake configuration from environment or config file."""
    config = {
        "account": os.environ.get("SNOWFLAKE_ACCOUNT", ""),
        "user": os.environ.get("SNOWFLAKE_USER", ""),
        "password": os.environ.get("SNOWFLAKE_PASSWORD", ""),
        "warehouse": os.environ.get("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH"),
        "database": os.environ.get("SNOWFLAKE_DATABASE", "SECURITY_LOGS"),
        "schema": os.environ.get("SNOWFLAKE_SCHEMA", "PUBLIC"),
    }
    
    # Try loading from .env file if environment vars not set
    env_file = Path(__file__).parent.parent / ".env"
    if env_file.exists() and not config["account"]:
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    env_key = key.strip()
                    if env_key.startswith("SNOWFLAKE_"):
                        config[env_key.replace("SNOWFLAKE_", "").lower()] = value.strip().strip('"\'')
    
    return config


def connect_snowflake(config):
    """Establish Snowflake connection."""
    if not config["account"] or not config["user"]:
        console.print("[red]❌ Snowflake credentials not configured![/red]")
        console.print()
        console.print("Set environment variables or create .env file:")
        console.print("  SNOWFLAKE_ACCOUNT=your_account")
        console.print("  SNOWFLAKE_USER=your_user")
        console.print("  SNOWFLAKE_PASSWORD=your_password")
        console.print("  SNOWFLAKE_WAREHOUSE=COMPUTE_WH")
        console.print("  SNOWFLAKE_DATABASE=SECURITY_LOGS")
        return None
    
    try:
        conn = snowflake.connector.connect(
            account=config["account"],
            user=config["user"],
            password=config["password"],
            warehouse=config["warehouse"],
            database=config["database"],
            schema=config["schema"],
        )
        console.print(f"[green]✓ Connected to Snowflake ({config['account']})[/green]")
        return conn
    except Exception as e:
        console.print(f"[red]❌ Connection failed: {e}[/red]")
        return None


def ensure_tables_exist(conn, config):
    """Create tables if they don't exist using the canonical SQL file."""
    sql_file = Path(__file__).parent.parent / "config" / "snowflake_setup.sql"

    if not sql_file.exists():
        console.print("[yellow]Warning: config/snowflake_setup.sql not found, skipping table creation[/yellow]")
        console.print("[yellow]Run 'pixi run create-snowflake-tables' first[/yellow]")
        return

    cursor = conn.cursor()
    sql_text = sql_file.read_text()

    for statement in sql_text.split(";"):
        statement = statement.strip()
        lines = [l for l in statement.splitlines() if l.strip() and not l.strip().startswith("--")]
        if not lines:
            continue
        try:
            cursor.execute(statement)
        except Exception as e:
            console.print(f"[yellow]Warning: {e}[/yellow]")

    console.print("[green]Tables verified/created (from config/snowflake_setup.sql)[/green]")
    cursor.close()


def upload_csv_file(conn, csv_path: str, table_name: str, config: dict):
    """Upload a CSV file to Snowflake table using PUT + COPY INTO."""
    cursor = conn.cursor()
    
    csv_path = Path(csv_path)
    if not csv_path.exists():
        console.print(f"[red]❌ File not found: {csv_path}[/red]")
        return False
    
    console.print(f"[cyan]📤 Uploading {csv_path.name} to {table_name}...[/cyan]")
    
    try:
        # Create a temporary stage for this upload
        stage_name = f"TEMP_STAGE_{table_name}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Create internal stage
        cursor.execute(f"CREATE OR REPLACE TEMPORARY STAGE {stage_name}")
        
        # PUT file to stage
        put_sql = f"PUT file://{csv_path.absolute()} @{stage_name} AUTO_COMPRESS=TRUE"
        cursor.execute(put_sql)
        console.print(f"  [green]✓ File staged[/green]")
        
        # COPY INTO table
        copy_sql = f"""
        COPY INTO {table_name}
        FROM @{stage_name}
        FILE_FORMAT = (
            TYPE = 'CSV'
            FIELD_DELIMITER = ','
            SKIP_HEADER = 1
            FIELD_OPTIONALLY_ENCLOSED_BY = '"'
            NULL_IF = ('', 'NULL', 'null')
            ERROR_ON_COLUMN_COUNT_MISMATCH = FALSE
        )
        ON_ERROR = 'CONTINUE'
        """
        
        cursor.execute(copy_sql)
        result = cursor.fetchone()
        
        if result:
            rows_loaded = result[3] if len(result) > 3 else "unknown"
            console.print(f"  [green]✓ Loaded {rows_loaded} rows into {table_name}[/green]")
        
        # Clean up stage
        cursor.execute(f"DROP STAGE IF EXISTS {stage_name}")
        
        return True
        
    except Exception as e:
        console.print(f"[red]❌ Upload failed: {e}[/red]")
        return False
    finally:
        cursor.close()


def upload_dataframe(conn, df: pd.DataFrame, table_name: str):
    """Upload a pandas DataFrame directly to Snowflake."""
    try:
        success, num_chunks, num_rows, _ = write_pandas(
            conn, df, table_name.upper(),
            auto_create_table=False,
            overwrite=False
        )
        if success:
            console.print(f"  [green]✓ Loaded {num_rows} rows into {table_name}[/green]")
        return success
    except Exception as e:
        console.print(f"[red]❌ Upload failed: {e}[/red]")
        return False


def find_log_files():
    """Find all log files in the logs directory."""
    logs_dir = Path(__file__).parent.parent / "logs"
    
    files = {
        "nginx": list(logs_dir.glob("nginx*.csv")),
        "postgres": list(logs_dir.glob("postgresql*.csv")),
        "attack": list(logs_dir.glob("attack*.csv")),
        "security": list(logs_dir.glob("security*.csv")),
    }
    
    return files


def main():
    parser = argparse.ArgumentParser(description="Upload CSV logs to Snowflake")
    parser.add_argument("--file", "-f", help="Specific CSV file to upload")
    parser.add_argument("--table", "-t", help="Target table name")
    parser.add_argument("--all", "-a", action="store_true", help="Upload all found log files")
    args = parser.parse_args()
    
    console.print("[bold cyan]" + "="*60 + "[/bold cyan]")
    console.print("[bold cyan]❄️  Snowflake CSV Upload Tool[/bold cyan]")
    console.print("[bold cyan]" + "="*60 + "[/bold cyan]")
    console.print()
    
    # Load config and connect
    config = get_snowflake_config()
    conn = connect_snowflake(config)
    
    if not conn:
        return
    
    try:
        # Ensure tables exist
        ensure_tables_exist(conn, config)
        
        if args.file and args.table:
            # Upload specific file
            upload_csv_file(conn, args.file, args.table, config)
        elif args.all or not args.file:
            # Upload all found files
            files = find_log_files()
            
            table = Table(title="Log Files Found")
            table.add_column("Type", style="cyan")
            table.add_column("Files", style="green")
            
            for log_type, paths in files.items():
                table.add_row(log_type, ", ".join(p.name for p in paths) or "none")
            
            console.print(table)
            console.print()
            
            # Upload mapping
            upload_map = {
                "nginx": "NGINX_LOGS",
                "postgres": "POSTGRES_LOGS",
                "attack": "NGINX_LOGS",  # Attack logs go to nginx table
                "security": "SECURITY_EVENTS",
            }
            
            for log_type, paths in files.items():
                target_table = upload_map.get(log_type)
                if target_table and paths:
                    for path in paths:
                        upload_csv_file(conn, str(path), target_table, config)
        
        console.print()
        console.print("[bold green]✅ Upload complete![/bold green]")
        console.print()
        console.print("[cyan]Query your data in Snowflake:[/cyan]")
        console.print(f"  SELECT * FROM {config['database']}.{config['schema']}.NGINX_LOGS LIMIT 10;")
        console.print(f"  SELECT * FROM {config['database']}.{config['schema']}.POSTGRES_LOGS LIMIT 10;")
        
    finally:
        conn.close()


if __name__ == "__main__":
    main()

