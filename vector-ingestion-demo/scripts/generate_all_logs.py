#!/usr/bin/env python3
"""
Combined Log Generator for Splunk/Snowflake Demo

Generates:
1. Nginx access logs (with attack patterns) → Snowflake + Splunk
2. PostgreSQL logs (with suspicious queries) → Snowflake only

Output formats:
- CSV for direct Snowflake upload
- JSON for Vector ingestion
"""

import os
import sys
import json
import csv
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any

from faker import Faker
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()
fake = Faker()

# Ensure logs directory exists
LOGS_DIR = Path(__file__).parent.parent / "logs"
LOGS_DIR.mkdir(exist_ok=True)


# ============================================================
# NGINX LOG GENERATION
# ============================================================

ATTACK_PATTERNS = {
    "sql_injection": [
        "/api/users?id=1' OR '1'='1",
        "/api/search?q='; DROP TABLE users;--",
        "/login?username=admin'--&password=x",
        "/api/products?category=1 UNION SELECT * FROM passwords",
        "/api/data?id=1; SELECT * FROM credit_cards",
    ],
    "xss": [
        "/search?q=<script>alert('xss')</script>",
        "/comment?text=<img src=x onerror=alert(1)>",
        "/profile?name=<svg/onload=alert('xss')>",
        "/api/message?body=javascript:alert(document.cookie)",
    ],
    "path_traversal": [
        "/files/../../../etc/passwd",
        "/download?file=....//....//etc/shadow",
        "/api/logs?path=/var/log/../../etc/passwd",
        "/static/..%2f..%2f..%2fetc/passwd",
    ],
    "command_injection": [
        "/api/ping?host=127.0.0.1;cat /etc/passwd",
        "/health?cmd=`whoami`",
        "/api/dns?domain=example.com|ls -la",
        "/shell?exec=$(cat /etc/shadow)",
    ],
    "brute_force": [
        "/login",  # Repeated login attempts
        "/admin/login",
        "/api/auth",
        "/wp-admin/",
    ],
    "reconnaissance": [
        "/.git/config",
        "/.env",
        "/wp-config.php",
        "/api/swagger.json",
        "/.aws/credentials",
        "/server-status",
        "/actuator/env",
        "/api/v1/config",
    ],
    "scanner": [
        "/admin/",
        "/phpmyadmin/",
        "/wp-login.php",
        "/.htaccess",
        "/backup.sql",
        "/database.sql.gz",
    ],
}

NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact",
    "/api/products", "/api/products/1", "/api/products/2",
    "/api/users/profile", "/api/cart", "/api/checkout",
    "/static/css/main.css", "/static/js/app.js",
    "/images/logo.png", "/favicon.ico",
    "/api/search?q=laptop", "/api/search?q=phone",
]

USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
    "Mozilla/5.0 (Linux; Android 11; SM-G991B)",
    # Suspicious user agents
    "sqlmap/1.4.7#stable",
    "nikto/2.1.6",
    "Nmap Scripting Engine",
    "python-requests/2.25.1",
    "curl/7.64.1",
]

MALICIOUS_IPS = [
    "185.220.101.1", "185.220.101.2", "185.220.101.3",  # Tor exit nodes
    "45.155.205.10", "45.155.205.20",  # Known malicious
    "89.248.167.131", "89.248.167.132",  # Scanner IPs
]

NORMAL_IPS = [f"10.0.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(20)]


def generate_nginx_log(is_attack: bool = False) -> Dict[str, Any]:
    """Generate a single nginx log entry."""
    timestamp = datetime.now() - timedelta(seconds=random.randint(0, 3600))
    
    if is_attack:
        attack_type = random.choice(list(ATTACK_PATTERNS.keys()))
        path = random.choice(ATTACK_PATTERNS[attack_type])
        client_ip = random.choice(MALICIOUS_IPS)
        user_agent = random.choice(USER_AGENTS[-5:])  # Suspicious UAs
        status = random.choice([200, 400, 403, 500])
        severity = "high" if attack_type in ["sql_injection", "command_injection"] else "medium"
    else:
        attack_type = None
        path = random.choice(NORMAL_PATHS)
        client_ip = random.choice(NORMAL_IPS)
        user_agent = random.choice(USER_AGENTS[:4])
        status = random.choices([200, 301, 304, 404], weights=[80, 5, 10, 5])[0]
        severity = "info"
    
    return {
        "timestamp": timestamp.isoformat(),
        "client_ip": client_ip,
        "request_method": random.choice(["GET", "POST"]) if is_attack else "GET",
        "request_path": path,
        "http_status": status,
        "response_size": random.randint(100, 50000),
        "user_agent": user_agent,
        "referer": fake.url() if random.random() > 0.5 else "-",
        "response_time_ms": random.uniform(10, 500),
        "is_attack": is_attack,
        "attack_type": attack_type or "",
        "severity": severity,
        "raw_log": f'{client_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{random.choice(["GET", "POST"])} {path} HTTP/1.1" {status} {random.randint(100, 50000)} "-" "{user_agent}"'
    }


def generate_nginx_logs(count: int = 500, attack_ratio: float = 0.15) -> List[Dict]:
    """Generate nginx logs with specified attack ratio."""
    logs = []
    attack_count = int(count * attack_ratio)
    normal_count = count - attack_count
    
    # Generate attacks
    for _ in range(attack_count):
        logs.append(generate_nginx_log(is_attack=True))
    
    # Generate normal traffic
    for _ in range(normal_count):
        logs.append(generate_nginx_log(is_attack=False))
    
    # Shuffle and sort by time
    random.shuffle(logs)
    logs.sort(key=lambda x: x["timestamp"])
    
    return logs


# ============================================================
# POSTGRESQL LOG GENERATION  
# ============================================================

SUSPICIOUS_QUERIES = {
    "sql_injection": [
        "SELECT * FROM users WHERE username = '' OR '1'='1'",
        "SELECT * FROM users WHERE id = 1; DROP TABLE users;--",
        "UNION SELECT password_hash FROM users",
        "SELECT * FROM credit_cards WHERE 1=1",
    ],
    "privilege_escalation": [
        "UPDATE users SET role = 'admin' WHERE username = 'attacker'",
        "GRANT ALL PRIVILEGES ON ALL TABLES TO public",
        "ALTER USER postgres WITH PASSWORD 'hacked'",
        "CREATE USER backdoor WITH SUPERUSER",
    ],
    "data_exfiltration": [
        "SELECT username, password_hash FROM users",
        "COPY users TO '/tmp/dump.csv'",
        "SELECT * FROM credit_cards",
        "SELECT pg_read_file('/etc/passwd')",
    ],
    "reconnaissance": [
        "SELECT table_name FROM information_schema.tables",
        "SELECT column_name FROM information_schema.columns WHERE table_name='users'",
        "SELECT version()",
        "SELECT current_user, current_database()",
    ],
}

NORMAL_QUERIES = [
    "SELECT id, name, price FROM products WHERE category = 'electronics'",
    "INSERT INTO orders (user_id, product_id, quantity) VALUES (1, 5, 2)",
    "UPDATE cart SET quantity = 3 WHERE user_id = 1",
    "SELECT COUNT(*) FROM orders WHERE status = 'completed'",
    "DELETE FROM sessions WHERE expires_at < NOW()",
    "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
]


def generate_postgres_log(is_suspicious: bool = False) -> Dict[str, Any]:
    """Generate a single PostgreSQL log entry."""
    timestamp = datetime.now() - timedelta(seconds=random.randint(0, 3600))
    
    if is_suspicious:
        attack_pattern = random.choice(list(SUSPICIOUS_QUERIES.keys()))
        query = random.choice(SUSPICIOUS_QUERIES[attack_pattern])
        user = random.choice(["unknown", "guest", "app_user"])
        error_severity = random.choice(["ERROR", "WARNING", "LOG"])
    else:
        attack_pattern = ""
        query = random.choice(NORMAL_QUERIES)
        user = random.choice(["app_user", "api_service", "admin"])
        error_severity = "LOG"
    
    return {
        "log_time": timestamp.isoformat(),
        "user_name": user,
        "database_name": "demo_app",
        "process_id": random.randint(1000, 9999),
        "connection_from": f"10.0.1.{random.randint(1, 254)}",
        "session_id": str(uuid.uuid4())[:8],
        "session_line_num": random.randint(1, 100),
        "command_tag": "SELECT" if "SELECT" in query else "UPDATE",
        "session_start_time": (timestamp - timedelta(minutes=random.randint(1, 60))).isoformat(),
        "virtual_transaction_id": f"{random.randint(1,100)}/{random.randint(1,1000)}",
        "transaction_id": random.randint(100000, 999999),
        "error_severity": error_severity,
        "sql_state_code": "00000" if not is_suspicious else random.choice(["42501", "42703", "28000"]),
        "message": f"statement: {query}",
        "detail": "",
        "hint": "",
        "internal_query": "",
        "internal_query_pos": 0,
        "context": "",
        "query": query,
        "query_pos": 0,
        "location": "",
        "application_name": "psql" if is_suspicious else "app_backend",
        "is_suspicious": is_suspicious,
        "attack_pattern": attack_pattern,
    }


def generate_postgres_logs(count: int = 300, suspicious_ratio: float = 0.20) -> List[Dict]:
    """Generate PostgreSQL logs with specified suspicious query ratio."""
    logs = []
    suspicious_count = int(count * suspicious_ratio)
    normal_count = count - suspicious_count
    
    for _ in range(suspicious_count):
        logs.append(generate_postgres_log(is_suspicious=True))
    
    for _ in range(normal_count):
        logs.append(generate_postgres_log(is_suspicious=False))
    
    random.shuffle(logs)
    logs.sort(key=lambda x: x["log_time"])
    
    return logs


# ============================================================
# OUTPUT FUNCTIONS
# ============================================================

def save_to_csv(logs: List[Dict], filename: str):
    """Save logs to CSV file."""
    if not logs:
        return
    
    filepath = LOGS_DIR / filename
    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=logs[0].keys())
        writer.writeheader()
        writer.writerows(logs)
    
    console.print(f"  [green]✓[/green] {filepath.name} ({len(logs)} rows)")


def save_to_json(logs: List[Dict], filename: str):
    """Save logs to JSON file (one JSON per line for Vector)."""
    filepath = LOGS_DIR / filename
    with open(filepath, 'w') as f:
        for log in logs:
            f.write(json.dumps(log) + "\n")
    
    console.print(f"  [green]✓[/green] {filepath.name} ({len(logs)} events)")


def main():
    console.print("[bold cyan]" + "="*60 + "[/bold cyan]")
    console.print("[bold cyan]🔧 Security Log Generator[/bold cyan]")
    console.print("[bold cyan]" + "="*60 + "[/bold cyan]")
    console.print()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        
        # Generate Nginx logs
        task1 = progress.add_task("[cyan]Generating Nginx logs...", total=2)
        nginx_logs = generate_nginx_logs(count=500, attack_ratio=0.15)
        progress.advance(task1)
        
        save_to_csv(nginx_logs, f"nginx_access_{timestamp}.csv")
        save_to_json(nginx_logs, f"nginx_access_{timestamp}.json")
        progress.advance(task1)
        
        # Generate PostgreSQL logs
        task2 = progress.add_task("[cyan]Generating PostgreSQL logs...", total=2)
        postgres_logs = generate_postgres_logs(count=300, suspicious_ratio=0.20)
        progress.advance(task2)
        
        save_to_csv(postgres_logs, f"postgresql_{timestamp}.csv")
        save_to_json(postgres_logs, f"postgresql_{timestamp}.json")
        progress.advance(task2)
    
    # Summary
    console.print()
    console.print("[bold green]✅ Log generation complete![/bold green]")
    console.print()
    
    nginx_attacks = sum(1 for l in nginx_logs if l["is_attack"])
    pg_suspicious = sum(1 for l in postgres_logs if l["is_suspicious"])
    
    console.print("[bold]Summary:[/bold]")
    console.print(f"  📁 Nginx logs:      {len(nginx_logs)} total, {nginx_attacks} attacks")
    console.print(f"  📁 PostgreSQL logs: {len(postgres_logs)} total, {pg_suspicious} suspicious")
    console.print()
    console.print("[bold]Destination Mapping:[/bold]")
    console.print("  [cyan]Nginx logs[/cyan]      → Snowflake + Splunk (critical)")
    console.print("  [yellow]PostgreSQL logs[/yellow] → Snowflake only (not critical)")
    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print("  1. Quick CSV upload:  [cyan]pixi run upload-csv[/cyan]")
    console.print("  2. Vector ingestion:  [cyan]pixi run vector-run[/cyan]")


if __name__ == "__main__":
    main()

