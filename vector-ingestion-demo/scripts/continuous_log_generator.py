#!/usr/bin/env python3
"""
Continuous log generator for realistic streaming simulation.

Runs indefinitely, generating logs at configurable rate with
periodic attack bursts.
"""

import json
import random
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

from faker import Faker
from rich.console import Console
from rich.live import Live
from rich.table import Table

# Import attack generators from main script
from generate_attack_logs import (
    generate_normal_log,
    generate_brute_force_logs,
    generate_sql_injection_logs,
    generate_path_traversal_logs,
    generate_scanner_logs,
    generate_credential_stuffing_logs,
    generate_sensitive_file_access_logs,
    OUTPUT_DIR,
)

fake = Faker()
console = Console()

# Configuration
LOGS_PER_SECOND = 5  # Normal log rate
ATTACK_INTERVAL_SECONDS = 60  # How often to inject attack
ROTATION_SIZE_MB = 10  # Rotate log file after this size

# Global state
running = True
stats = {
    "total_logs": 0,
    "normal_logs": 0,
    "attack_logs": 0,
    "files_written": 0,
    "start_time": None,
}


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    global running
    console.print("\n[yellow]Shutting down...[/yellow]")
    running = False


def get_current_log_file() -> Path:
    """Get current log file, rotating if needed."""
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H")
    return OUTPUT_DIR / f"security_logs_{timestamp}.json"


def append_log(log: dict, log_file: Path):
    """Append a single log to file."""
    with open(log_file, "a") as f:
        f.write(json.dumps(log) + "\n")


def inject_attack() -> list[dict]:
    """Randomly select and generate an attack pattern."""
    now = datetime.utcnow()
    attack_type = random.choice([
        "brute_force",
        "sql_injection",
        "path_traversal",
        "scanner",
        "sensitive_file",
        "credential_stuffing",
    ])
    
    if attack_type == "brute_force":
        return generate_brute_force_logs(now, count=random.randint(10, 25))
    elif attack_type == "sql_injection":
        return generate_sql_injection_logs(now, count=random.randint(5, 15))
    elif attack_type == "path_traversal":
        return generate_path_traversal_logs(now, count=random.randint(5, 10))
    elif attack_type == "scanner":
        return generate_scanner_logs(now, count=random.randint(15, 30))
    elif attack_type == "sensitive_file":
        return generate_sensitive_file_access_logs(now)
    else:
        return generate_credential_stuffing_logs(now, count=random.randint(10, 20))


def create_stats_table() -> Table:
    """Create a live stats table."""
    table = Table(title="🔐 Continuous Log Generator")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green", justify="right")
    
    elapsed = time.time() - stats["start_time"] if stats["start_time"] else 0
    rate = stats["total_logs"] / elapsed if elapsed > 0 else 0
    
    table.add_row("Total Logs", f"{stats['total_logs']:,}")
    table.add_row("Normal Logs", f"{stats['normal_logs']:,}")
    table.add_row("Attack Logs", f"[red]{stats['attack_logs']:,}[/red]")
    table.add_row("Logs/Second", f"{rate:.1f}")
    table.add_row("Runtime", f"{elapsed:.0f}s")
    table.add_row("Log File", get_current_log_file().name)
    
    return table


def main():
    """Run continuous log generation."""
    global running
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    stats["start_time"] = time.time()
    last_attack_time = time.time()
    
    console.print("[bold blue]🚀 Starting continuous log generator...[/bold blue]")
    console.print(f"   Rate: {LOGS_PER_SECOND} logs/second")
    console.print(f"   Attack interval: every {ATTACK_INTERVAL_SECONDS}s")
    console.print("   Press Ctrl+C to stop\n")
    
    with Live(create_stats_table(), refresh_per_second=2, console=console) as live:
        while running:
            now = datetime.utcnow()
            log_file = get_current_log_file()
            
            # Generate normal logs
            for _ in range(LOGS_PER_SECOND):
                if not running:
                    break
                log = generate_normal_log(now)
                append_log(log, log_file)
                stats["total_logs"] += 1
                stats["normal_logs"] += 1
            
            # Check if it's time for an attack
            if time.time() - last_attack_time >= ATTACK_INTERVAL_SECONDS:
                attack_logs = inject_attack()
                for log in attack_logs:
                    append_log(log, log_file)
                    stats["total_logs"] += 1
                    stats["attack_logs"] += 1
                last_attack_time = time.time()
                console.print(f"[red]⚠️  Injected {len(attack_logs)} attack logs[/red]")
            
            # Update display
            live.update(create_stats_table())
            
            # Sleep to maintain rate
            time.sleep(1)
    
    console.print(f"\n[green]✅ Generated {stats['total_logs']:,} total logs[/green]")
    console.print(f"   Normal: {stats['normal_logs']:,}")
    console.print(f"   Attack: {stats['attack_logs']:,}")


if __name__ == "__main__":
    main()

