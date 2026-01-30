# Aperture Science Red Team Framework v2.0
## BYU CCDC Invitational 2026

"We do what we must, because we can." - GLaDOS

Welcome to the Aperture Science Red Team Framework. This toolkit is designed for fair, equitable, and educational red team operations against all competition teams.

## Design Philosophy

1. Equitable: Same scripts run against all teams simultaneously
2. Educational: Persistence is obvious enough to find, but requires skill to fully remediate
3. Non-Destructive: We degrade services, we do not brick machines
4. Reversible: Every action has a revert function
5. Staged: Attacks are paced manually by the operator
6. Themed: Everything is Portal/Aperture Science themed for fun
7. Cross-Platform: Works on all Linux distros and Windows versions

## What Changed in This Version

- The main orchestrator is `orchestrator/glados.py`
- Operations are invoked manually with no predefined timing
- IP generation uses the 192.168.200-212 scheme with host IDs
- C2 and persistence automatically use the local IP from `ip a`
- Standalone scripts exist for each action category

## Quick Start

### Start the Orchestrator

```bash
python3 orchestrator/glados.py
```

### Run Individual Components

```bash
# Start C2 beacon receiver
python3 payloads/portal_gun.py --port 8080

# Run credential spray
python3 init_access/default_cred_spray.py --teams 1-12

# Deploy persistence
python3 orchestrator/persistence.py --teams-count 12

# User management
python3 orchestrator/user_management.py --teams-count 12 --action create_themed_users --targets all

# Service degradation
python3 orchestrator/service_degradation.py --teams-count 12 --action stop_http --targets storage,safety

# Website defacement
python3 orchestrator/defacement.py --teams-count 12 --action deface_prestashop --targets storage

# Chaos mode
python3 orchestrator/chaos_mode.py --teams-count 12 --action deploy_matrix_rain --targets linux
```

## Project Structure

```
.
├── attacks/
│   └── web/
│       ├── WEB_TESTING_GUIDE.md
│       └── prestashop_deface.sh
├── assets/
│   └── images/
│       └── seizure/
│           └── seized_banner.png
├── init_access/
│   └── default_cred_spray.py
├── lib/
│   ├── common.py
│   └── operations.py
├── orchestrator/
│   ├── aperture_console.py  # Wrapper for glados
│   ├── chaos_mode.py
│   ├── defacement.py
│   ├── glados.py            # Main orchestrator
│   ├── persistence.py
│   ├── service_degradation.py
│   ├── turret.py            # Wrapper for service_degradation
│   └── user_management.py
├── payloads/
│   └── portal_gun.py
└── docs/
    └── (deprecated; content consolidated here)
```

## IP Scheme and Team Range

Everything is 1:1 NATed and lives in a single 192.168 subnet. Teams start at subnet 200 and go through 212. The host ID is the last octet of each system.

Example: safety on team 12 is 192.168.212.12.

Formula:

```
Team X, Host ID N
WAN IP = 192.168.(200 + X).N
```

The scripts will prompt for how many teams are playing and compute addresses accordingly.

## Target Quick Reference

| Hostname | Host ID | OS | Services |
|----------|---------|----|----------|
| curiosity | 140 | Win Server 2016 | SMB, WinRM, RDP |
| morality | 10 | Win Server 2016 | SMB, WinRM, HTTP |
| anger | 70 | Win Server 2019 | SMB, WinRM, DNS |
| space | 141 | Windows 10 | SMB, WinRM, RDP |
| scalable | 73 | openSUSE 42.1 | SSH, HTTP |
| safety | 12 | Fedora 34 | SSH, HTTP, FTP |
| storage | 14 | Ubuntu 18.04 | SSH, HTTP, MySQL |
| cake | 143 | Arch Linux | SSH, HTTP |

## Operations Guide

### SSH Key Handling

If a script needs SSH key authentication, it will prompt to create an SSH key if none exists. If a key already exists, it will use the existing key.

### 1) Start C2 Server

```bash
python3 payloads/portal_gun.py --port 8080
```

C2 endpoints:

```
http://RED_TEAM_IP:8080/beacon      - Generic beacon
http://RED_TEAM_IP:8080/smh         - Linux SMH beacon
http://RED_TEAM_IP:8080/wheatley    - Windows Wheatley beacon
http://RED_TEAM_IP:8080/cube        - Companion Cube beacon
http://RED_TEAM_IP:8080/dashboard   - Live dashboard
http://RED_TEAM_IP:8080/stats       - JSON statistics
```

The server uses the local IP from `ip a` unless `RED_TEAM_IP` is set in the environment.

### 2) Run Credential Spray

```bash
python3 init_access/default_cred_spray.py --teams 1-12 --json results.json
```

### 3) Deploy Persistence

```bash
python3 orchestrator/persistence.py --teams-count 12 --targets all
```

Persistence uses the local IP from `ip a` for beacon callbacks.

### 4) Service Degradation

```bash
python3 orchestrator/service_degradation.py --teams-count 12 --action stop_http --targets storage,safety
```

### 5) User Management

```bash
python3 orchestrator/user_management.py --teams-count 12 --action create_glados_admin --targets all
```

### 6) Website Defacement

```bash
python3 orchestrator/defacement.py --teams-count 12 --action deface_prestashop --targets storage
```

### 7) Chaos Mode

```bash
python3 orchestrator/chaos_mode.py --teams-count 12 --action deploy_nyan_cat --targets linux
```

## Persistence Locations

### Linux

```
Directories:
  /tmp/.aperture_science/
  /var/tmp/.apsci/

Files:
  /tmp/.aperture_science/smh
  /tmp/.aperture_science/turret
  /tmp/.aperture_science/README.aperture

Cron:
  */5 * * * * /tmp/.aperture_science/smh --maintain
  */3 * * * * /tmp/.aperture_science/turret
```

### Windows

```
Directories:
  %TEMP%\ApertureScience\
  %APPDATA%\Microsoft\Windows\Wheatley\

Scheduled Tasks:
  ApertureEnrichment
  WindowsDefenderUpdate (decoy name)

Registry:
  HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ApertureUpdate
  HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsOptimization

Startup:
  %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.lnk
  %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\update.vbs
```

## Blue Team Remediation Hints

### Linux

```bash
# Check and remove cron
crontab -l | grep -v aperture | crontab -

# Find and remove files
find /tmp /var/tmp -name "*aperture*" -exec rm -rf {} \; 2>/dev/null

# Check systemd user services
systemctl --user disable aperture-enrichment.timer
rm -rf ~/.config/systemd/user/aperture*

# Check bashrc/profile
sed -i '/aperture/d' ~/.bashrc ~/.profile

# Check SSH keys
sed -i '/aperture/d' ~/.ssh/authorized_keys

# Check firewall
iptables -L -n --line-numbers
```

### Windows

```powershell
# Remove scheduled tasks
Get-ScheduledTask | Where {$_.TaskName -match "Aperture|Enrichment"} | Unregister-ScheduledTask -Confirm:$false

# Clean registry
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Aperture*" -ErrorAction SilentlyContinue

# Clean startup folder
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\*aperture*" -Force
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\update.vbs" -Force

# Remove directories
Remove-Item -Recurse -Force "$env:TEMP\ApertureScience"
Remove-Item -Recurse -Force "$env:APPDATA\Microsoft\Windows\Wheatley"

# Check firewall
Get-NetFirewallRule | Where {$_.DisplayName -match "Aperture"} | Remove-NetFirewallRule
```

## Rules Reminder

Do:
- Use default credentials for initial access
- Establish persistence that is findable
- Temporarily disable services
- Create themed artifacts
- Always be able to revert

Do not:
- Delete system files
- Corrupt databases irreparably
- Install actual malware
- DoS the infrastructure
- Attack out-of-scope systems

"Thank you for participating in this Aperture Science computer-aided enrichment activity."
