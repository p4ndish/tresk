#!/bin/bash
################################################################################
# Tresk - VPS Security Hardening Module
# Version: 1.0.0
# Description: Automated VPS hardening for fresh installations
################################################################################

set -o pipefail

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Configuration
readonly HARDENING_CONF="/etc/tresk/hardening.conf"
readonly LOG_FILE="/var/log/tresk/hardening.log"

# Hardening categories
declare -A INSTALL_STATUS

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    case "$level" in
        INFO)    echo -e "${GREEN}[INFO]${NC} $message" ;;
        SUCCESS) echo -e "${GREEN}[✓]${NC} $message" ;;
        WARNING) echo -e "${YELLOW}[WARNING]${NC} $message" ;;
        ERROR)   echo -e "${RED}[ERROR]${NC} $message" ;;
        STEP)    echo -e "${CYAN}[STEP]${NC} $message" ;;
    esac
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    elif [[ -f /etc/redhat-release ]]; then
        OS="centos"
        OS_VERSION=$(grep -oE '[0-9]+' /etc/redhat-release | head -1)
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
        OS_VERSION=$(cat /etc/debian_version)
    else
        OS="unknown"
        OS_VERSION="unknown"
    fi
}

get_package_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    elif command -v apk &>/dev/null; then
        echo "apk"
    else
        echo "unknown"
    fi
}

install_packages() {
    local pm=$(get_package_manager)
    local packages=("$@")
    
    log STEP "Installing packages: ${packages[*]}"
    
    case "$pm" in
        apt)
            apt-get update -qq
            apt-get install -y -qq "${packages[@]}" 2>/dev/null || {
                log WARNING "Some packages may have failed to install"
            }
            ;;
        dnf)
            dnf install -y -q "${packages[@]}" 2>/dev/null || true
            ;;
        yum)
            yum install -y -q "${packages[@]}" 2>/dev/null || true
            ;;
        pacman)
            pacman -Sy --noconfirm --quiet "${packages[@]}" 2>/dev/null || true
            ;;
        apk)
            apk add --no-cache "${packages[@]}" 2>/dev/null || true
            ;;
        *)
            log ERROR "Unknown package manager"
            return 1
            ;;
    esac
}

# ===============================
# Network Security
# ===============================

harden_network() {
    log STEP "Hardening Network Security..."
    
    local pm=$(get_package_manager)
    
    # Install UFW/Firewalld
    case "$pm" in
        apt)
            install_packages ufw
            setup_ufw
            ;;
        dnf|yum)
            install_packages firewalld
            setup_firewalld
            ;;
        pacman)
            install_packages ufw
            setup_ufw
            ;;
    esac
    
    # Install Fail2ban
    install_packages fail2ban
    setup_fail2ban
    
    INSTALL_STATUS["network"]="done"
    log SUCCESS "Network hardening completed"
}

setup_ufw() {
    log INFO "Configuring UFW firewall..."
    
    # Default deny
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (be careful!)
    ufw allow 22/tcp comment 'SSH'
    
    # Allow common ports
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Enable
    ufw --force enable
    
    log SUCCESS "UFW configured and enabled"
}

setup_firewalld() {
    log INFO "Configuring Firewalld..."
    
    systemctl enable firewalld
    systemctl start firewalld
    
    # Default zone
    firewall-cmd --set-default-zone=public
    
    # Allow services
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    
    # Reload
    firewall-cmd --reload
    
    log SUCCESS "Firewalld configured"
}

setup_fail2ban() {
    log INFO "Configuring Fail2ban..."
    
    # Create custom jail config
    cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
# Ban for 1 hour
bantime = 3600
# 3 failed attempts
maxretry = 3
# Check every 10 minutes
findtime = 600
# Email notifications (optional)
destemail = root@localhost
sendername = Fail2Ban

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[nginx-http-auth]
enabled = false

[nginx-limit-req]
enabled = false
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log SUCCESS "Fail2ban configured"
}

# ===============================
# SSH Hardening
# ===============================

harden_ssh() {
    log STEP "Hardening SSH..."
    
    local ssh_config="/etc/ssh/sshd_config"
    local ssh_config_backup="/etc/ssh/sshd_config.backup.$(date +%Y%m%d)"
    
    # Backup original
    cp "$ssh_config" "$ssh_config_backup"
    log INFO "SSH config backed up to $ssh_config_backup"
    
    # Apply hardening
    cat >> "$ssh_config" <<'EOF'

# Tresk Security Hardening
PermitRootLogin no
PasswordAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60
X11Forwarding no
AllowTcpForwarding no
PermitTunnel no
Banner /etc/ssh/banner
EOF
    
    # Create banner
    echo "Authorized access only. All activity is monitored." > /etc/ssh/banner
    
    # Test config
    if sshd -t; then
        systemctl restart sshd
        log SUCCESS "SSH hardened and restarted"
    else
        log ERROR "SSH config test failed, restoring backup"
        cp "$ssh_config_backup" "$ssh_config"
        systemctl restart sshd
    fi
    
    INSTALL_STATUS["ssh"]="done"
}

# ===============================
# Malware Protection
# ===============================

harden_malware() {
    log STEP "Installing Malware Protection..."
    
    local pm=$(get_package_manager)
    
    case "$pm" in
        apt)
            install_packages rkhunter chkrootkit clamav clamav-daemon aide
            ;;
        dnf|yum)
            install_packages rkhunter chkrootkit clamav clamav-update aide
            ;;
        pacman)
            install_packages rkhunter chkrootkit clamav aide
            ;;
    esac
    
    setup_clamav
    setup_aide
    setup_rkhunter
    
    INSTALL_STATUS["malware"]="done"
    log SUCCESS "Malware protection installed"
}

setup_clamav() {
    log INFO "Configuring ClamAV..."
    
    # Update virus definitions
    if command -v freshclam &>/dev/null; then
        freshclam 2>/dev/null || log WARNING "ClamAV definitions update may have failed"
    fi
    
    # Create scan script
    cat > /etc/cron.daily/clamav-scan <<'EOF'
#!/bin/bash
# Daily ClamAV scan
LOG_FILE="/var/log/clamav/daily.log"
QUARANTINE_DIR="/var/quarantine"

mkdir -p "$QUARANTINE_DIR"

clamscan -r /tmp /var/tmp /home --infected --move="$QUARANTINE_DIR" -l "$LOG_FILE" 2>/dev/null
EOF
    chmod +x /etc/cron.daily/clamav-scan
    
    # Enable service
    systemctl enable clamav-daemon 2>/dev/null || true
    systemctl start clamav-daemon 2>/dev/null || true
    
    log SUCCESS "ClamAV configured"
}

setup_aide() {
    log INFO "Configuring AIDE..."
    
    # Initialize database
    if command -v aideinit &>/dev/null; then
        aideinit 2>/dev/null || true
    elif command -v aide &>/dev/null; then
        aide --init 2>/dev/null || true
    fi
    
    # Create daily check cron
    cat > /etc/cron.daily/aide-check <<'EOF'
#!/bin/bash
# Daily AIDE check
LOG_FILE="/var/log/aide/aide.log"
mkdir -p "$(dirname $LOG_FILE)"
aide --check >> "$LOG_FILE" 2>&1 || true
EOF
    chmod +x /etc/cron.daily/aide-check
    
    log SUCCESS "AIDE configured"
}

setup_rkhunter() {
    log INFO "Configuring Rkhunter..."
    
    # Update
    rkhunter --update 2>/dev/null || true
    rkhunter --propupd 2>/dev/null || true
    
    # Create daily check
    cat > /etc/cron.daily/rkhunter-check <<'EOF'
#!/bin/bash
# Daily rkhunter check
rkhunter --check --sk --rwo 2>/dev/null || true
EOF
    chmod +x /etc/cron.daily/rkhunter-check
    
    log SUCCESS "Rkhunter configured"
}

# ===============================
# System Monitoring
# ===============================

harden_monitoring() {
    log STEP "Installing System Monitoring..."
    
    local pm=$(get_package_manager)
    
    case "$pm" in
        apt)
            install_packages auditd sysstat
            ;;
        dnf|yum)
            install_packages audit sysstat
            ;;
        pacman)
            install_packages audit sysstat
            ;;
    esac
    
    setup_auditd
    
    INSTALL_STATUS["monitoring"]="done"
    log SUCCESS "Monitoring tools installed"
}

setup_auditd() {
    log INFO "Configuring Auditd..."
    
    # Basic audit rules
    cat > /etc/audit/rules.d/tresk.rules <<'EOF'
# Monitor privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege_escalation

# Monitor sudoers changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Monitor passwd changes
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes

# Monitor SSH config
-w /etc/ssh/sshd_config -p wa -k ssh_config_changes
EOF
    
    systemctl enable auditd 2>/dev/null || true
    systemctl restart auditd 2>/dev/null || true
    
    log SUCCESS "Auditd configured"
}

# ===============================
# Auto Updates
# ===============================

harden_updates() {
    log STEP "Configuring Automatic Updates..."
    
    local pm=$(get_package_manager)
    
    case "$pm" in
        apt)
            install_packages unattended-upgrades apt-listchanges needrestart
            setup_unattended_upgrades
            ;;
        dnf|yum)
            install_packages dnf-automatic
            setup_dnf_automatic
            ;;
    esac
    
    INSTALL_STATUS["updates"]="done"
    log SUCCESS "Auto-updates configured"
}

setup_unattended_upgrades() {
    log INFO "Configuring unattended-upgrades..."
    
    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
    
    systemctl enable unattended-upgrades
    systemctl start unattended-upgrades
    
    log SUCCESS "Unattended-upgrades configured"
}

setup_dnf_automatic() {
    log INFO "Configuring dnf-automatic..."
    
    systemctl enable dnf-automatic.timer
    systemctl start dnf-automatic.timer
    
    log SUCCESS "DNF automatic configured"
}

# ===============================
# Main Functions
# ===============================

show_status() {
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║         TRESK HARDENING STATUS                            ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo
    
    echo "Network Security:"
    systemctl is-active ufw &>/dev/null && echo "  ✓ UFW: Active" || echo "  ✗ UFW: Not active"
    systemctl is-active fail2ban &>/dev/null && echo "  ✓ Fail2ban: Active" || echo "  ✗ Fail2ban: Not active"
    
    echo
    echo "Malware Protection:"
    command -v rkhunter &>/dev/null && echo "  ✓ Rkhunter: Installed" || echo "  ✗ Rkhunter: Not installed"
    command -v chkrootkit &>/dev/null && echo "  ✓ Chkrootkit: Installed" || echo "  ✗ Chkrootkit: Not installed"
    command -v clamscan &>/dev/null && echo "  ✓ ClamAV: Installed" || echo "  ✗ ClamAV: Not installed"
    command -v aide &>/dev/null && echo "  ✓ AIDE: Installed" || echo "  ✗ AIDE: Not installed"
    
    echo
    echo "Monitoring:"
    systemctl is-active auditd &>/dev/null && echo "  ✓ Auditd: Active" || echo "  ✗ Auditd: Not active"
    
    echo
    echo "Auto Updates:"
    systemctl is-active unattended-upgrades &>/dev/null && echo "  ✓ Unattended-upgrades: Active" || echo "  ✗ Unattended-upgrades: Not active"
}

run_hardening() {
    local mode="$1"
    
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║         TRESK VPS SECURITY HARDENING                      ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo
    
    detect_os
    log INFO "Detected OS: $OS $OS_VERSION"
    
    mkdir -p "$(dirname $LOG_FILE)"
    
    case "$mode" in
        network)
            harden_network
            ;;
        ssh)
            harden_ssh
            ;;
        malware)
            harden_malware
            ;;
        monitoring)
            harden_monitoring
            ;;
        updates)
            harden_updates
            ;;
        full|*)
            harden_network
            harden_ssh
            harden_malware
            harden_monitoring
            harden_updates
            ;;
    esac
    
    echo
    log SUCCESS "Hardening completed! Check $LOG_FILE for details."
    echo
    echo "Next steps:"
    echo "  1. Review SSH config: sudo nano /etc/ssh/sshd_config"
    echo "  2. Check firewall: sudo ufw status"
    echo "  3. Test fail2ban: sudo fail2ban-client status"
    echo "  4. Run first malware scan: sudo rkhunter --check"
    echo "  5. Initialize AIDE: sudo aideinit"
}

show_help() {
    cat <<'EOF'
Tresk VPS Security Hardening

Usage: tresk harden [OPTIONS] [CATEGORY]

Categories:
    full        Run all hardening (default)
    network     Network security only (firewall, fail2ban)
    ssh         SSH hardening only
    malware     Malware protection only (rkhunter, clamav, aide)
    monitoring  System monitoring only (auditd)
    updates     Auto-updates configuration

Options:
    --status    Show hardening status
    --help      Show this help

Examples:
    sudo tresk harden              # Full hardening
    sudo tresk harden network      # Network only
    sudo tresk harden --status     # Check status
EOF
}

# Main
main() {
    case "${1:-full}" in
        --status)
            show_status
            ;;
        --help|-h)
            show_help
            ;;
        network|ssh|malware|monitoring|updates|full)
            run_hardening "$1"
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
