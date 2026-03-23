#!/usr/bin/env python3
"""
Simple web server that logs requests in JSON format.

This creates a real web server that Vector can monitor,
generating authentic access logs.
"""

import json
import logging
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import random

from rich.console import Console

console = Console()
OUTPUT_DIR = Path(__file__).parent.parent / "logs"
OUTPUT_DIR.mkdir(exist_ok=True)

# Configure logging to file
log_file = OUTPUT_DIR / f"webserver_{datetime.utcnow().strftime('%Y%m%d')}.json"


class JSONLogHandler(BaseHTTPRequestHandler):
    """HTTP handler that logs requests in JSON format."""
    
    def log_request_json(self, status_code: int, bytes_sent: int = 0):
        """Write request to JSON log file."""
        log_entry = {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "log_type": "web_access",
            "source": "python_webserver",
            "is_critical": status_code in [401, 403, 500, 502, 503],
            "ip_address": self.client_address[0],
            "request_method": self.command,
            "request_path": self.path,
            "query_string": "",
            "status_code": status_code,
            "bytes_sent": bytes_sent,
            "response_time_ms": random.randint(10, 200),
            "user_agent": self.headers.get("User-Agent", "-"),
            "referer": self.headers.get("Referer", "-"),
            "backend_ip": "127.0.0.1",
        }
        
        # Check for attack patterns
        path_lower = self.path.lower()
        if "../" in self.path or "..%2f" in path_lower:
            log_entry["attack_type"] = "path_traversal"
            log_entry["is_critical"] = True
        elif any(sql in path_lower for sql in ["'", "union", "select", "drop", "--"]):
            log_entry["attack_type"] = "sql_injection"
            log_entry["is_critical"] = True
        elif any(scan in path_lower for scan in [".git", ".env", "wp-admin", "phpmyadmin"]):
            log_entry["attack_type"] = "scanner"
            log_entry["is_critical"] = True
        
        with open(log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
        
        return log_entry
    
    def do_GET(self):
        """Handle GET requests."""
        # Simulate different responses
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            response = b"<html><body><h1>Demo Web Server</h1><p>Logging to Vector</p></body></html>"
            self.wfile.write(response)
            self.log_request_json(200, len(response))
        
        elif self.path == "/login":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            response = b"<html><body><h1>Login Page</h1></body></html>"
            self.wfile.write(response)
            self.log_request_json(200, len(response))
        
        elif self.path.startswith("/api/"):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = b'{"status": "ok"}'
            self.wfile.write(response)
            self.log_request_json(200, len(response))
        
        elif any(p in self.path for p in [".env", ".git", "wp-admin", "phpmyadmin"]):
            # Suspicious request - return 404 but log as critical
            self.send_response(404)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            response = b"Not Found"
            self.wfile.write(response)
            self.log_request_json(404, len(response))
        
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            response = b"Not Found"
            self.wfile.write(response)
            self.log_request_json(404, len(response))
    
    def do_POST(self):
        """Handle POST requests."""
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length else b""
        
        if self.path == "/login":
            # Simulate login - sometimes fail
            if random.random() < 0.3:  # 30% failure rate
                self.send_response(401)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                response = b'{"error": "Invalid credentials"}'
                self.wfile.write(response)
                log_entry = self.log_request_json(401, len(response))
                log_entry["auth_result"] = "failure"
            else:
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                response = b'{"status": "logged_in"}'
                self.wfile.write(response)
                log_entry = self.log_request_json(200, len(response))
                log_entry["auth_result"] = "success"
        else:
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = b'{"status": "ok"}'
            self.wfile.write(response)
            self.log_request_json(200, len(response))
    
    def log_message(self, format, *args):
        """Override to suppress default logging."""
        pass


def run_server(port: int = 8000):
    """Run the web server."""
    server_address = ("", port)
    httpd = HTTPServer(server_address, JSONLogHandler)
    
    console.print(f"\n[bold blue]🌐 Starting web server on port {port}[/bold blue]")
    console.print(f"   Log file: {log_file}")
    console.print(f"   URL: http://localhost:{port}")
    console.print("\n[dim]Press Ctrl+C to stop[/dim]\n")
    
    console.print("[bold]Test URLs:[/bold]")
    console.print(f"  Normal:     curl http://localhost:{port}/")
    console.print(f"  Login:      curl -X POST http://localhost:{port}/login")
    console.print(f"  API:        curl http://localhost:{port}/api/test")
    console.print(f"  Scanner:    curl http://localhost:{port}/.env")
    console.print(f"  SQLi:       curl \"http://localhost:{port}/search?q=' OR 1=1--\"")
    console.print("")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down...[/yellow]")
        httpd.shutdown()


if __name__ == "__main__":
    run_server()

