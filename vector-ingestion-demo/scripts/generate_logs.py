#!/usr/bin/env python3
"""
Basic log generator for testing.

Generates a simple batch of normal web access logs.
For attack patterns, use generate_attack_logs.py instead.
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

from faker import Faker
from rich.console import Console

fake = Faker()
console = Console()

OUTPUT_DIR = Path(__file__).parent.parent / "logs"
OUTPUT_DIR.mkdir(exist_ok=True)


def generate_log(timestamp: datetime) -> dict:
    """Generate a single normal web log entry."""
    paths = ["/", "/index.html", "/about", "/contact", "/products", 
             "/api/v1/users", "/login", "/dashboard", "/profile"]
    
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.2",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2) Mobile Safari/17.2",
    ]
    
    return {
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "log_type": "web_access",
        "source": "nginx",
        "is_critical": False,
        "ip_address": fake.ipv4(),
        "request_method": random.choice(["GET", "GET", "GET", "POST"]),
        "request_path": random.choice(paths),
        "query_string": "",
        "status_code": random.choice([200, 200, 200, 200, 201, 301, 302, 304]),
        "bytes_sent": random.randint(500, 50000),
        "response_time_ms": random.randint(10, 500),
        "user_agent": random.choice(user_agents),
        "referer": "-",
        "backend_ip": f"192.168.1.{random.randint(10, 20)}",
    }


def main():
    """Generate a batch of logs."""
    console.print("\n[bold blue]📝 Generating normal web logs...[/bold blue]\n")
    
    count = 100
    base_time = datetime.utcnow()
    logs = []
    
    for i in range(count):
        timestamp = base_time + timedelta(seconds=i * random.uniform(0.5, 2))
        logs.append(generate_log(timestamp))
    
    # Write to file
    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_file = OUTPUT_DIR / f"normal_logs_{timestamp_str}.json"
    
    with open(output_file, "w") as f:
        for log in logs:
            f.write(json.dumps(log) + "\n")
    
    console.print(f"✅ Generated {count} logs")
    console.print(f"📁 Output: {output_file}")


if __name__ == "__main__":
    main()

