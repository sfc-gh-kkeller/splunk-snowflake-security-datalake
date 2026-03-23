#!/usr/bin/env python3
"""
Attack Simulator - Sends real attack requests to the web server.

Use this to generate authentic attack traffic that will be logged
by the web server and picked up by Vector.

Usage:
    # Start the web server first:
    pixi run start-server
    
    # Then run the attack simulator:
    python scripts/attack_simulator.py
"""

import random
import time
from datetime import datetime

import httpx
from rich.console import Console
from rich.progress import Progress

console = Console()

# Target server
BASE_URL = "http://localhost:8000"

# Attack payloads
SQL_INJECTIONS = [
    "/search?q=' OR '1'='1",
    "/search?id=1; DROP TABLE users--",
    "/products?id=' UNION SELECT * FROM users--",
    "/login?user=admin'--",
    "/api/v1/query?filter=1 AND 1=1",
]

PATH_TRAVERSALS = [
    "/files/../../../etc/passwd",
    "/download?file=../../../etc/shadow",
    "/static/....//....//....//etc/passwd",
    "/images/%2e%2e%2f%2e%2e%2fetc/passwd",
]

SCANNER_PATHS = [
    "/.env",
    "/.git/config",
    "/wp-admin",
    "/phpmyadmin",
    "/admin",
    "/backup.sql",
    "/database.yml",
    "/.htpasswd",
    "/config.php",
    "/wp-config.php",
    "/server-status",
    "/manager/html",
    "/.svn/entries",
    "/api/debug",
    "/console",
]

BRUTE_FORCE_USERS = ["admin", "root", "administrator", "user", "test", "guest"]

MALICIOUS_USER_AGENTS = [
    "sqlmap/1.7.12#stable",
    "nikto/2.1.6",
    "python-requests/2.31.0 (malicious)",
    "curl/7.68.0",
    "gobuster/3.6",
]


def send_request(path: str, method: str = "GET", user_agent: str = None, data: dict = None):
    """Send a request to the server."""
    headers = {}
    if user_agent:
        headers["User-Agent"] = user_agent
    
    try:
        if method == "GET":
            response = httpx.get(f"{BASE_URL}{path}", headers=headers, timeout=5)
        else:
            response = httpx.post(f"{BASE_URL}{path}", headers=headers, data=data, timeout=5)
        return response.status_code
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return None


def run_brute_force(count: int = 20):
    """Simulate brute force attack."""
    console.print("\n[bold red]🔓 Running Brute Force Attack...[/bold red]")
    
    user_agent = random.choice(MALICIOUS_USER_AGENTS)
    
    for i in range(count):
        username = random.choice(BRUTE_FORCE_USERS)
        status = send_request(
            "/login",
            method="POST",
            user_agent=user_agent,
            data={"username": username, "password": f"password{i}"}
        )
        console.print(f"  Login attempt: {username} -> {status}")
        time.sleep(random.uniform(0.2, 0.5))


def run_sql_injection():
    """Simulate SQL injection attempts."""
    console.print("\n[bold red]💉 Running SQL Injection Attack...[/bold red]")
    
    for payload in SQL_INJECTIONS:
        status = send_request(payload, user_agent="sqlmap/1.7.12#stable")
        console.print(f"  SQLi: {payload[:50]}... -> {status}")
        time.sleep(random.uniform(0.5, 1))


def run_path_traversal():
    """Simulate path traversal attempts."""
    console.print("\n[bold red]📁 Running Path Traversal Attack...[/bold red]")
    
    for payload in PATH_TRAVERSALS:
        status = send_request(payload, user_agent="curl/7.68.0")
        console.print(f"  Traversal: {payload[:40]}... -> {status}")
        time.sleep(random.uniform(0.3, 0.7))


def run_scanner():
    """Simulate vulnerability scanner."""
    console.print("\n[bold red]🔍 Running Scanner/Enumeration...[/bold red]")
    
    user_agent = random.choice(["gobuster/3.6", "nikto/2.1.6", "dirbuster/1.0"])
    
    for path in SCANNER_PATHS:
        status = send_request(path, user_agent=user_agent)
        console.print(f"  Scan: {path} -> {status}")
        time.sleep(random.uniform(0.1, 0.3))


def run_normal_traffic(count: int = 10):
    """Generate some normal traffic for comparison."""
    console.print("\n[bold green]🌐 Generating Normal Traffic...[/bold green]")
    
    paths = ["/", "/about", "/products", "/contact", "/api/v1/status"]
    
    for i in range(count):
        path = random.choice(paths)
        status = send_request(path)
        console.print(f"  Normal: {path} -> {status}")
        time.sleep(random.uniform(0.2, 0.5))


def main():
    """Run all attack simulations."""
    console.print("\n[bold blue]🎯 Attack Simulator[/bold blue]")
    console.print(f"   Target: {BASE_URL}")
    console.print(f"   Time: {datetime.utcnow().isoformat()}")
    console.print("\n[dim]Make sure the web server is running: pixi run start-server[/dim]")
    
    # Check if server is running
    try:
        httpx.get(BASE_URL, timeout=2)
    except Exception:
        console.print("\n[red]❌ Cannot connect to web server![/red]")
        console.print("   Start it with: pixi run start-server")
        return
    
    console.print("\n[green]✅ Server is running[/green]")
    
    with Progress() as progress:
        task = progress.add_task("Running attacks...", total=5)
        
        # Run normal traffic first
        run_normal_traffic(10)
        progress.update(task, advance=1)
        
        # Run attacks
        run_brute_force(15)
        progress.update(task, advance=1)
        
        run_sql_injection()
        progress.update(task, advance=1)
        
        run_path_traversal()
        progress.update(task, advance=1)
        
        run_scanner()
        progress.update(task, advance=1)
    
    console.print("\n[bold green]✅ Attack simulation complete![/bold green]")
    console.print("   Check the logs/ directory for generated logs")
    console.print("   Vector will pick these up and send to Splunk/Snowflake")


if __name__ == "__main__":
    main()

