#!/usr/bin/env python3
"""
Snowflake Table Setup

Reads config/snowflake_setup.sql and executes it against Snowflake
to create the SECURITY_LOGS database, tables, file formats, and stage.

Usage:
    pixi run create-snowflake-tables
    python scripts/snowflake_setup.py
"""

import os
import sys
from pathlib import Path

from rich.console import Console

console = Console()

try:
    import snowflake.connector
except ImportError:
    console.print("[red]Error: snowflake-connector-python required[/red]")
    console.print("Install with: pixi install")
    sys.exit(1)


SQL_FILE = Path(__file__).parent.parent / "config" / "snowflake_setup.sql"


def get_snowflake_config():
    """Load Snowflake configuration from environment or .env file."""
    config = {
        "account": os.environ.get("SNOWFLAKE_ACCOUNT", ""),
        "user": os.environ.get("SNOWFLAKE_USER", ""),
        "password": os.environ.get("SNOWFLAKE_PASSWORD", ""),
        "warehouse": os.environ.get("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH"),
        "role": os.environ.get("SNOWFLAKE_ROLE", "SYSADMIN"),
    }

    env_file = Path(__file__).parent.parent / ".env"
    if env_file.exists() and not config["account"]:
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    env_key = key.strip()
                    if env_key.startswith("SNOWFLAKE_"):
                        config[env_key.replace("SNOWFLAKE_", "").lower()] = value.strip().strip("\"'")

    return config


def main():
    console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")
    console.print("[bold cyan]Snowflake Table Setup[/bold cyan]")
    console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")
    console.print()

    if not SQL_FILE.exists():
        console.print(f"[red]SQL file not found: {SQL_FILE}[/red]")
        sys.exit(1)

    config = get_snowflake_config()
    if not config["account"] or not config["user"]:
        console.print("[red]Snowflake credentials not configured![/red]")
        console.print()
        console.print("Set environment variables or create .env file:")
        console.print("  SNOWFLAKE_ACCOUNT=your_account")
        console.print("  SNOWFLAKE_USER=your_user")
        console.print("  SNOWFLAKE_PASSWORD=your_password")
        sys.exit(1)

    try:
        conn = snowflake.connector.connect(
            account=config["account"],
            user=config["user"],
            password=config["password"],
            warehouse=config["warehouse"],
            role=config.get("role", "SYSADMIN"),
        )
        console.print(f"[green]Connected to Snowflake ({config['account']})[/green]")
    except Exception as e:
        console.print(f"[red]Connection failed: {e}[/red]")
        sys.exit(1)

    sql_text = SQL_FILE.read_text()

    # Split on semicolons, filtering out empty statements and comments-only blocks
    statements = [s.strip() for s in sql_text.split(";") if s.strip()]

    cursor = conn.cursor()
    executed = 0
    skipped = 0

    for stmt in statements:
        # Skip comment-only blocks
        lines = [l for l in stmt.splitlines() if l.strip() and not l.strip().startswith("--")]
        if not lines:
            skipped += 1
            continue

        try:
            cursor.execute(stmt)
            executed += 1
            # Show a short summary of what ran
            first_line = lines[0].strip()[:80]
            console.print(f"  [green]OK[/green]  {first_line}")
        except Exception as e:
            console.print(f"  [yellow]WARN[/yellow]  {e}")

    cursor.close()
    conn.close()

    console.print()
    console.print(f"[bold green]Done: {executed} statements executed, {skipped} skipped[/bold green]")
    console.print()
    console.print("[cyan]Next steps:[/cyan]")
    console.print("  pixi run generate-all    # Generate sample logs")
    console.print("  pixi run upload-csv      # Upload logs to Snowflake")


if __name__ == "__main__":
    main()
