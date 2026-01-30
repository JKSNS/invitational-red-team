# Aperture Science Red Team Framework v2.0
## BYU CCDC Invitational 2026

> "We do what we must, because we can." - GLaDOS

Welcome to the Aperture Science Red Team Framework! This comprehensive toolkit is designed for **fair, equitable, and educational** red team operations against all competition teams.

## Design Philosophy

1. **Equitable**: Same scripts run against all teams simultaneously
2. **Educational**: Persistence is obvious enough to find, but requires skill to fully remediate
3. **Non-Destructive**: We degrade services, we DON'T brick machines
4. **Reversible**: Every action has a revert function
5. **Staged**: Attacks are paced throughout the competition
6. **Themed**: Everything is Portal/Aperture Science themed for fun!
7. **Cross-Platform**: Works on all Linux distros and Windows versions

## New in v2.0

- **Interactive Menu Console** - Full TUI for attack management
- **Staged Execution** - Automatic pacing throughout competition
- **Full Revert Capabilities** - Undo any action
- **User Management Attacks** - pkill users, create backdoor accounts
- **Chaos Mode** - End-of-competition fun (Nyan Cat, Bee Movie, etc.)
- **Website Defacement** - PrestaShop defacement with auto-backup
- **Universal Linux Persistence** - Works on any distro

## Quick Start

### Start the Console
```bash
cd ccdc-red-team/orchestration
python3 aperture_console.py
```

### Or Run Individual Components
```bash
# Start C2 beacon receiver
python3 payloads/portal_gun.py --port 8080

# Run credential spray
python3 enumeration/default_cred_spray.py --teams 1-12

# Deploy persistence
python3 orchestration/glados.py --full-attack --teams 1-12
```

## Project Structure

```
ccdc-red-team/
├── orchestration/
│   ├── aperture_console.py  # Interactive menu console
│   ├── glados.py            # Master attack orchestrator
│   └── turret.py            # Service degradation scheduler
├── enumeration/
│   └── default_cred_spray.py
├── persistence/
│   ├── linux/
│   │   ├── universal_persistence.sh  # Cross-distro installer
│   │   ├── smh_daemon.sh
│   │   └── companion_cube.sh
│   └── windows/
│       └── wheatley.ps1
├── payloads/
│   └── portal_gun.py        # C2 beacon server
├── web-exploits/
│   ├── WEB_TESTING_GUIDE.md
│   └── prestashop_deface.sh  # PrestaShop defacement
└── docs/
    ├── OPERATIONS_GUIDE.md
    └── BLUE_TEAM_HUNTING_GUIDE.md
```

## Competition Stages

The console automatically tracks competition stages:

| Stage | Time | Activities |
|-------|------|------------|
| **RECON** | T+0 to T+15 | Let teams settle, scan only |
| **INITIAL_ACCESS** | T+15 to T+30 | Credential spraying |
| **PERSISTENCE** | T+30 to T+60 | Deploy SMH/Wheatley |
| **DEGRADATION** | T+60 to T+180 | Service attacks, firewall blocking |
| **ESCALATION** | T+180 to T+240 | User management, password changes |
| **CHAOS** | T+240 to END | Nyan Cat, Bee Movie, defacement |

## Attack Modules

### User Management
- `pkill_users` - Kill non-red-team user sessions
- `create_themed_users` - Create turret, companion, atlas, etc.
- `create_glados_admin` - Admin account with weak password
- `weaken_root_password` - Change root to "password"

### Service Degradation
- `block_scoring` / `unblock_scoring` - Firewall manipulation
- `stop_http` / `start_http` - Web server control
- `stop_dns` / `start_dns` - DNS server control

### Website Defacement
- `deface_prestashop` - Replace homepage with seized banner
- `restore_prestashop` - Restore from backup

### Chaos Mode 
- `deploy_nyan_cat` - Nyan Cat on login
- `deploy_bee_movie` - Bee Movie script greeting
- `deploy_matrix_rain` - Matrix rain effect
- `deploy_desktop_goose` - Wall message spam

## Revert Capabilities

Every attack has a revert function:

| Attack | Revert |
|--------|--------|
| `block_scoring` | `unblock_scoring` |
| `stop_http` | `start_http` |
| `create_themed_users` | `remove_themed_users` |
| `deface_prestashop` | `restore_prestashop` |
| `deploy_*_chaos` | `remove_chaos` |

## Target Quick Reference

| Hostname | LAN IP | OS | In Scope |
|----------|--------|-----|----------|
| curiosity | 172.16.3.140 | Win Server 2016 | ✅ |
| morality | 172.16.1.10 | Win Server 2016 | ✅ |
| anger | 172.16.2.70 | Win Server 2019 | ✅ |
| space | 172.16.3.141 | Windows 10 | ✅ |
| scalable | 172.16.2.73 | openSUSE 42.1 | ✅ |
| safety | 172.16.1.12 | Fedora 34 | ✅ |
| storage | 172.16.1.14 | Ubuntu 18.04 | ✅ |
| cake | 172.16.3.143 | Arch Linux | ✅ |

### IP Formula
```
Team X, Host with LAN IP 172.16.Y.Z
WAN IP = 192.168.(200+X).Z
```

## Themed Backdoor Accounts

| Username | Password | Notes |
|----------|----------|-------|
| glados | password | Admin account |
| turret | idonthate | Standard user |
| companion | thecake | Standard user |
| atlas | p-body | Standard user |
| pbody | atlas123 | Standard user |

## Rules Reminder

### DO:
- ✅ Use default credentials for initial access
- ✅ Establish persistence that's findable
- ✅ Temporarily disable services
- ✅ Create themed artifacts
- ✅ Always be able to revert

### DON'T:
- ❌ Delete system files
- ❌ Corrupt databases irreparably
- ❌ Install actual malware
- ❌ DoS the infrastructure
- ❌ Attack out-of-scope systems

---

*"Thank you for participating in this Aperture Science computer-aided enrichment activity."*
