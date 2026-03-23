#!/usr/bin/env python3
"""
Generate realistic security logs with attack patterns.

This script generates logs that simulate:
- Normal web traffic
- Brute force attacks
- SQL injection attempts
- Path traversal attacks
- Credential stuffing
- Scanner activity
"""

import json
import random
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generator
import hashlib

from faker import Faker
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

# Initialize
fake = Faker()
console = Console()

# Configuration
OUTPUT_DIR = Path(__file__).parent.parent / "logs"
OUTPUT_DIR.mkdir(exist_ok=True)

# Attack source IPs (these will be flagged)
ATTACKER_IPS = [
    "185.220.101.42",   # Known Tor exit
    "45.155.205.233",   # Scanner
    "193.32.162.89",    # Brute forcer
    "91.240.118.172",   # SQL injection source
    "5.188.206.14",     # Credential stuffer
]

# Normal IPs
NORMAL_IPS = [fake.ipv4() for _ in range(50)]

# Backend servers
BACKEND_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"]

# User agents
NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.2",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile Safari/17.2",
]

MALICIOUS_USER_AGENTS = [
    "sqlmap/1.7.12#stable",
    "nikto/2.1.6",
    "Nmap Scripting Engine",
    "masscan/1.3",
    "python-requests/2.31.0",
    "curl/7.68.0",
    "gobuster/3.6",
    "dirbuster/1.0",
]

# SQL injection payloads
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "1; DROP TABLE users--",
    "' UNION SELECT * FROM users--",
    "admin'--",
    "1' AND '1'='1",
    "' OR 1=1--",
    "'; EXEC xp_cmdshell('whoami')--",
    "1 AND (SELECT COUNT(*) FROM users) > 0",
]

# Path traversal payloads
PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
]

# Sensitive files to probe
SENSITIVE_FILES = [
    "/.env",
    "/config.php",
    "/wp-config.php",
    "/.git/config",
    "/backup.sql",
    "/database.yml",
    "/.htpasswd",
    "/phpinfo.php",
    "/server-status",
    "/admin/config.php",
]

# Scanner paths
SCANNER_PATHS = [
    "/admin",
    "/administrator",
    "/phpmyadmin",
    "/wp-admin",
    "/wp-login.php",
    "/.git",
    "/.svn",
    "/backup",
    "/db",
    "/sql",
    "/test",
    "/dev",
    "/staging",
    "/api/debug",
    "/console",
    "/manager/html",
]

# Normal paths
NORMAL_PATHS = [
    "/",
    "/index.html",
    "/about",
    "/contact",
    "/products",
    "/api/v1/users",
    "/api/v1/products",
    "/static/css/main.css",
    "/static/js/app.js",
    "/images/logo.png",
    "/login",
    "/register",
    "/dashboard",
    "/profile",
    "/settings",
]

# Usernames for brute force
COMMON_USERNAMES = ["admin", "administrator", "root", "user", "test", "guest", "info", "support"]


def generate_timestamp(base_time: datetime = None) -> str:
    """Generate ISO format timestamp."""
    if base_time is None:
        base_time = datetime.utcnow()
    return base_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def generate_session_id() -> str:
    """Generate a session ID."""
    return hashlib.md5(str(random.random()).encode()).hexdigest()[:16]


def generate_normal_log(timestamp: datetime) -> dict:
    """Generate a normal web access log."""
    return {
        "timestamp": generate_timestamp(timestamp),
        "log_type": "web_access",
        "source": "nginx",
        "is_critical": False,
        "ip_address": random.choice(NORMAL_IPS),
        "request_method": random.choice(["GET", "GET", "GET", "POST", "PUT"]),
        "request_path": random.choice(NORMAL_PATHS),
        "query_string": "",
        "status_code": random.choice([200, 200, 200, 200, 201, 301, 302, 304]),
        "bytes_sent": random.randint(500, 50000),
        "response_time_ms": random.randint(10, 500),
        "user_agent": random.choice(NORMAL_USER_AGENTS),
        "referer": random.choice(["https://google.com", "https://example.com", "-"]),
        "backend_ip": random.choice(BACKEND_IPS),
        "session_id": generate_session_id(),
    }


def generate_brute_force_logs(timestamp: datetime, count: int = 20) -> list[dict]:
    """Generate brute force attack logs - many failed logins from same IP."""
    attacker_ip = random.choice(ATTACKER_IPS)
    logs = []
    
    for i in range(count):
        log_time = timestamp + timedelta(seconds=i * random.uniform(0.5, 2))
        username = random.choice(COMMON_USERNAMES) if i < count - 1 else "admin"
        
        logs.append({
            "timestamp": generate_timestamp(log_time),
            "log_type": "auth",
            "source": "nginx",
            "is_critical": True,
            "ip_address": attacker_ip,
            "request_method": "POST",
            "request_path": "/login",
            "query_string": "",
            "status_code": 401 if i < count - 1 else 200,  # Last one might succeed
            "bytes_sent": 256,
            "response_time_ms": random.randint(100, 300),
            "user_agent": random.choice(MALICIOUS_USER_AGENTS[:2]),
            "referer": "-",
            "backend_ip": random.choice(BACKEND_IPS),
            "username": username,
            "auth_result": "failure" if i < count - 1 else "success",
            "attack_type": "brute_force",
        })
    
    return logs


def generate_sql_injection_logs(timestamp: datetime, count: int = 10) -> list[dict]:
    """Generate SQL injection attempt logs."""
    attacker_ip = ATTACKER_IPS[3]  # SQL injection source
    logs = []
    
    paths = ["/search", "/products", "/users", "/api/v1/query", "/login"]
    
    for i in range(count):
        log_time = timestamp + timedelta(seconds=i * random.uniform(1, 5))
        payload = random.choice(SQL_INJECTION_PAYLOADS)
        
        logs.append({
            "timestamp": generate_timestamp(log_time),
            "log_type": "web_access",
            "source": "nginx",
            "is_critical": True,
            "ip_address": attacker_ip,
            "request_method": random.choice(["GET", "POST"]),
            "request_path": random.choice(paths),
            "query_string": f"id={payload}",
            "status_code": random.choice([400, 403, 500]),
            "bytes_sent": random.randint(100, 500),
            "response_time_ms": random.randint(50, 200),
            "user_agent": "sqlmap/1.7.12#stable",
            "referer": "-",
            "backend_ip": random.choice(BACKEND_IPS),
            "attack_type": "sql_injection",
            "payload": payload,
        })
    
    return logs


def generate_path_traversal_logs(timestamp: datetime, count: int = 8) -> list[dict]:
    """Generate path traversal attack logs."""
    attacker_ip = random.choice(ATTACKER_IPS)
    logs = []
    
    for i in range(count):
        log_time = timestamp + timedelta(seconds=i * random.uniform(1, 3))
        payload = random.choice(PATH_TRAVERSAL_PAYLOADS)
        
        logs.append({
            "timestamp": generate_timestamp(log_time),
            "log_type": "web_access",
            "source": "nginx",
            "is_critical": True,
            "ip_address": attacker_ip,
            "request_method": "GET",
            "request_path": f"/files/{payload}",
            "query_string": "",
            "status_code": random.choice([400, 403, 404]),
            "bytes_sent": random.randint(100, 300),
            "response_time_ms": random.randint(10, 50),
            "user_agent": random.choice(MALICIOUS_USER_AGENTS),
            "referer": "-",
            "backend_ip": random.choice(BACKEND_IPS),
            "attack_type": "path_traversal",
            "payload": payload,
        })
    
    return logs


def generate_scanner_logs(timestamp: datetime, count: int = 30) -> list[dict]:
    """Generate scanner/enumeration logs."""
    attacker_ip = ATTACKER_IPS[1]  # Scanner
    logs = []
    
    for i, path in enumerate(SCANNER_PATHS[:count]):
        log_time = timestamp + timedelta(seconds=i * random.uniform(0.1, 0.5))
        
        logs.append({
            "timestamp": generate_timestamp(log_time),
            "log_type": "web_access",
            "source": "nginx",
            "is_critical": True,
            "ip_address": attacker_ip,
            "request_method": "GET",
            "request_path": path,
            "query_string": "",
            "status_code": 404,
            "bytes_sent": 162,
            "response_time_ms": random.randint(5, 20),
            "user_agent": random.choice(MALICIOUS_USER_AGENTS[4:]),
            "referer": "-",
            "backend_ip": random.choice(BACKEND_IPS),
            "attack_type": "scanner",
        })
    
    return logs


def generate_sensitive_file_access_logs(timestamp: datetime) -> list[dict]:
    """Generate sensitive file access attempts."""
    attacker_ip = random.choice(ATTACKER_IPS)
    logs = []
    
    for i, path in enumerate(SENSITIVE_FILES):
        log_time = timestamp + timedelta(seconds=i * random.uniform(1, 3))
        
        logs.append({
            "timestamp": generate_timestamp(log_time),
            "log_type": "web_access",
            "source": "nginx",
            "is_critical": True,
            "ip_address": attacker_ip,
            "request_method": "GET",
            "request_path": path,
            "query_string": "",
            "status_code": random.choice([403, 403, 404]),
            "bytes_sent": random.randint(100, 300),
            "response_time_ms": random.randint(5, 30),
            "user_agent": random.choice(MALICIOUS_USER_AGENTS),
            "referer": "-",
            "backend_ip": random.choice(BACKEND_IPS),
            "attack_type": "sensitive_file_probe",
        })
    
    return logs


def generate_credential_stuffing_logs(timestamp: datetime, count: int = 15) -> list[dict]:
    """Generate credential stuffing logs - different usernames, same IP."""
    attacker_ip = ATTACKER_IPS[4]  # Credential stuffer
    logs = []
    
    # Generate fake email/username combinations
    creds = [(fake.email(), fake.password()) for _ in range(count)]
    
    for i, (email, _) in enumerate(creds):
        log_time = timestamp + timedelta(seconds=i * random.uniform(2, 5))
        
        logs.append({
            "timestamp": generate_timestamp(log_time),
            "log_type": "auth",
            "source": "nginx",
            "is_critical": True,
            "ip_address": attacker_ip,
            "request_method": "POST",
            "request_path": "/api/v1/auth/login",
            "query_string": "",
            "status_code": 401,
            "bytes_sent": 256,
            "response_time_ms": random.randint(200, 500),
            "user_agent": "python-requests/2.31.0",
            "referer": "-",
            "backend_ip": random.choice(BACKEND_IPS),
            "username": email,
            "auth_result": "failure",
            "attack_type": "credential_stuffing",
        })
    
    return logs


def write_logs(logs: list[dict], filename: str):
    """Write logs to JSON file."""
    output_file = OUTPUT_DIR / filename
    with open(output_file, "w") as f:
        for log in logs:
            f.write(json.dumps(log) + "\n")
    return output_file


def main():
    """Generate attack logs."""
    console.print("\n[bold blue]🔐 Security Log Generator with Attack Patterns[/bold blue]\n")
    
    base_time = datetime.utcnow()
    all_logs = []
    attack_summary = {}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # Generate normal traffic
        task = progress.add_task("Generating normal traffic...", total=None)
        normal_logs = [generate_normal_log(base_time + timedelta(seconds=i * random.uniform(0.5, 2))) 
                       for i in range(100)]
        all_logs.extend(normal_logs)
        attack_summary["normal_traffic"] = len(normal_logs)
        progress.update(task, completed=True)
        
        # Generate brute force attack
        task = progress.add_task("Simulating brute force attack...", total=None)
        brute_force = generate_brute_force_logs(base_time + timedelta(minutes=2))
        all_logs.extend(brute_force)
        attack_summary["brute_force"] = len(brute_force)
        progress.update(task, completed=True)
        
        # Generate SQL injection attempts
        task = progress.add_task("Simulating SQL injection...", total=None)
        sql_injection = generate_sql_injection_logs(base_time + timedelta(minutes=5))
        all_logs.extend(sql_injection)
        attack_summary["sql_injection"] = len(sql_injection)
        progress.update(task, completed=True)
        
        # Generate path traversal
        task = progress.add_task("Simulating path traversal...", total=None)
        path_traversal = generate_path_traversal_logs(base_time + timedelta(minutes=7))
        all_logs.extend(path_traversal)
        attack_summary["path_traversal"] = len(path_traversal)
        progress.update(task, completed=True)
        
        # Generate scanner activity
        task = progress.add_task("Simulating scanner activity...", total=None)
        scanner = generate_scanner_logs(base_time + timedelta(minutes=10))
        all_logs.extend(scanner)
        attack_summary["scanner"] = len(scanner)
        progress.update(task, completed=True)
        
        # Generate sensitive file probes
        task = progress.add_task("Simulating sensitive file probes...", total=None)
        sensitive = generate_sensitive_file_access_logs(base_time + timedelta(minutes=12))
        all_logs.extend(sensitive)
        attack_summary["sensitive_file_probe"] = len(sensitive)
        progress.update(task, completed=True)
        
        # Generate credential stuffing
        task = progress.add_task("Simulating credential stuffing...", total=None)
        cred_stuff = generate_credential_stuffing_logs(base_time + timedelta(minutes=15))
        all_logs.extend(cred_stuff)
        attack_summary["credential_stuffing"] = len(cred_stuff)
        progress.update(task, completed=True)
    
    # Sort by timestamp
    all_logs.sort(key=lambda x: x["timestamp"])
    
    # Write to file
    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"security_logs_{timestamp_str}.json"
    output_file = write_logs(all_logs, filename)
    
    # Print summary
    console.print("\n[bold green]✅ Log generation complete![/bold green]\n")
    
    table = Table(title="Generated Logs Summary")
    table.add_column("Attack Type", style="cyan")
    table.add_column("Count", style="magenta", justify="right")
    
    for attack_type, count in attack_summary.items():
        table.add_row(attack_type.replace("_", " ").title(), str(count))
    
    table.add_row("[bold]Total[/bold]", f"[bold]{len(all_logs)}[/bold]")
    
    console.print(table)
    console.print(f"\n📁 Output file: [blue]{output_file}[/blue]")
    console.print(f"📊 Total events: [green]{len(all_logs)}[/green]")
    console.print(f"🚨 Attack events: [red]{len(all_logs) - attack_summary['normal_traffic']}[/red]")
    
    # Show attacker IPs
    console.print("\n[bold]Attacker IPs to watch:[/bold]")
    for ip in ATTACKER_IPS:
        console.print(f"  • {ip}")
    
    console.print("\n[dim]Run 'pixi run vector-run' to start ingesting logs[/dim]")


if __name__ == "__main__":
    main()

