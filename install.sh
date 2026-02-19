#!/bin/bash
################################################################################
# VPS Security Monitor - Installation Script
# Version: 1.0.0
# Description: One-command installation for VPS Security Monitor
################################################################################

set -e

# =============================================================================
# CONFIGURATION
# =============================================================================
readonly SCRIPT_VERSION="1.0.0"
readonly INSTALL_DIR="/opt/tresk"
readonly CONFIG_DIR="/etc/tresk"
readonly LOG_DIR="/var/log/tresk"
readonly SYSTEMD_DIR="/etc/systemd/system"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

print_banner() {
    cat <<'EOF'
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║              VPS SECURITY MONITOR - Installation Script                   ║
║                                                                           ║
║     Production-grade Linux VPS security monitoring and alerting          ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
}

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%H:%M:%S')
    
    case "$level" in
        INFO)    echo -e "${GREEN}[INFO]${NC} $message" ;;
        SUCCESS) echo -e "${GREEN}[✓]${NC} $message" ;;
        WARNING) echo -e "${YELLOW}[WARNING]${NC} $message" ;;
        ERROR)   echo -e "${RED}[ERROR]${NC} $message" ;;
        STEP)    echo -e "${CYAN}[STEP]${NC} $message" ;;
    esac
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log ERROR "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    log INFO "Detecting operating system..."
    
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        OS_NAME="$NAME"
    elif [[ -f /etc/redhat-release ]]; then
        OS="centos"
        OS_VERSION=$(grep -oE '[0-9]+' /etc/redhat-release | head -1)
        OS_NAME=$(cat /etc/redhat-release)
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
        OS_VERSION=$(cat /etc/debian_version)
        OS_NAME="Debian $OS_VERSION"
    else
        log ERROR "Unable to detect operating system"
        exit 1
    fi
    
    log SUCCESS "Detected: $OS_NAME"
}

check_docker() {
    if [[ -f /.dockerenv ]] || grep -qE "docker|kubepods" /proc/1/cgroup 2>/dev/null; then
        log WARNING "Running inside Docker container - some features may be limited"
        IN_DOCKER=true
    else
        IN_DOCKER=false
    fi
}

# =============================================================================
# DEPENDENCY INSTALLATION (MODULAR)
# =============================================================================

# Source the package manager module if available
source_package_manager() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "${script_dir}/lib/package_manager.sh" ]]; then
        # shellcheck source=/dev/null
        source "${script_dir}/lib/package_manager.sh"
        return 0
    else
        return 1
    fi
}

# Legacy dependency installation for fallback
install_dependencies_legacy() {
    log STEP "Installing dependencies (legacy mode)..."
    
    local deps=("curl" "jq" "bc" "net-tools" "lsof" "psmisc" "procps")
    local security_tools=("rkhunter" "chkrootkit")
    
    case "$OS" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq "${deps[@]}" "${security_tools[@]}" aide auditd python3 python3-pip 2>/dev/null || {
                log WARNING "Some packages failed to install, continuing..."
            }
            ;;
        
        centos|rhel|rocky|almalinux|fedora)
            if command -v dnf &> /dev/null; then
                dnf install -y -q "${deps[@]}" "${security_tools[@]}" aide audit python3 python3-pip 2>/dev/null || {
                    log WARNING "Some packages failed to install, continuing..."
                }
            else
                yum install -y -q "${deps[@]}" "${security_tools[@]}" aide audit python3 python3-pip 2>/dev/null || {
                    log WARNING "Some packages failed to install, continuing..."
                }
            fi
            ;;
        
        alpine)
            apk add --no-cache curl jq bc net-tools lsof psmisc procps rkhunter python3 py3-pip 2>/dev/null || {
                log WARNING "Some packages failed to install, continuing..."
            }
            ;;
        
        arch|manjaro)
            pacman -Sy --noconfirm --quiet curl jq bc net-tools lsof psmisc procps rkhunter python python-pip 2>/dev/null || {
                log WARNING "Some packages failed to install, continuing..."
            }
            ;;
        
        opensuse|suse)
            zypper refresh
            zypper install -y "${deps[@]}" "${security_tools[@]}" aide audit python3 python3-pip 2>/dev/null || {
                log WARNING "Some packages failed to install, continuing..."
            }
            ;;
        
        *)
            log WARNING "Unknown OS, attempting generic package installation"
            ;;
    esac
    
    # Install Python dependencies
    pip3 install --quiet requests 2>/dev/null || {
        log WARNING "Failed to install Python requests module"
    }
    
    log SUCCESS "Dependencies installed"
}

install_dependencies() {
    log STEP "Installing dependencies..."
    
    if source_package_manager; then
        log INFO "Using modular package manager..."
        install_dependencies_modular || {
            log WARNING "Modular install failed, falling back to legacy mode..."
            install_dependencies_legacy
        }
    else
        log INFO "Package manager module not found, using legacy mode..."
        install_dependencies_legacy
    fi
    
    log SUCCESS "Dependencies installation completed"
}

# =============================================================================
# INSTALLATION
# =============================================================================

create_directories() {
    log STEP "Creating directories..."
    
    mkdir -p "$INSTALL_DIR"/{bin,lib,config,signatures,systemd,logs}
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "${INSTALL_DIR}/.baseline"
    mkdir -p "${INSTALL_DIR}/.alert_state"
    
    log SUCCESS "Directories created"
}

install_files() {
    log STEP "Installing files..."
    
    # Get the directory where this script is located
    local source_dir
    source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Copy main monitoring script
    if [[ -f "${source_dir}/bin/monitor.sh" ]]; then
        cp "${source_dir}/bin/monitor.sh" "${INSTALL_DIR}/bin/"
        chmod +x "${INSTALL_DIR}/bin/monitor.sh"
    else
        log ERROR "monitor.sh not found in source directory"
        exit 1
    fi
    
    # Copy Python modules
    if [[ -f "${source_dir}/lib/telegram_notifier.py" ]]; then
        cp "${source_dir}/lib/telegram_notifier.py" "${INSTALL_DIR}/lib/"
        chmod +x "${INSTALL_DIR}/lib/telegram_notifier.py"
    fi
    
    # Copy signatures
    if [[ -f "${source_dir}/signatures/threat_signatures.json" ]]; then
        cp "${source_dir}/signatures/threat_signatures.json" "${INSTALL_DIR}/signatures/"
    fi
    
    # Copy configuration
    if [[ -f "${source_dir}/config/config.conf" ]]; then
        cp "${source_dir}/config/config.conf" "${CONFIG_DIR}/config.conf"
    fi
    
    # Copy systemd files
    if [[ -d "${source_dir}/systemd" ]]; then
        cp "${source_dir}/systemd/"*.service "${INSTALL_DIR}/systemd/"
        cp "${source_dir}/systemd/"*.timer "${INSTALL_DIR}/systemd/"
    fi
    
    log SUCCESS "Files installed"
}

setup_systemd() {
    log STEP "Setting up systemd services..."
    
    # Copy systemd files to system directory
    cp "${INSTALL_DIR}/systemd/"tresk*.service "$SYSTEMD_DIR/" 2>/dev/null || true
    cp "${INSTALL_DIR}/systemd/"tresk*.timer "$SYSTEMD_DIR/" 2>/dev/null || true
    
    # Reload systemd
    systemctl daemon-reload
    
    log SUCCESS "Systemd services configured"
}

configure_telegram() {
    log STEP "Configuring Telegram notifications..."
    
    echo
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Telegram Bot Setup${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo
    echo "To receive Telegram notifications, you need to:"
    echo "1. Create a bot with @BotFather on Telegram"
    echo "2. Get your chat ID"
    echo
    echo "Would you like to configure Telegram now? (y/n)"
    read -r configure_now
    
    if [[ "$configure_now" =~ ^[Yy]$ ]]; then
        echo
        echo "Enter your Telegram Bot Token (from @BotFather):"
        read -r bot_token
        
        echo "Enter your Telegram Chat ID:"
        read -r chat_id
        
        # Update configuration
        sed -i "s/TELEGRAM_ENABLED=\"false\"/TELEGRAM_ENABLED=\"true\"/" "${CONFIG_DIR}/config.conf"
        sed -i "s/TELEGRAM_BOT_TOKEN=\"\"/TELEGRAM_BOT_TOKEN=\"${bot_token}\"/" "${CONFIG_DIR}/config.conf"
        sed -i "s/TELEGRAM_CHAT_ID=\"\"/TELEGRAM_CHAT_ID=\"${chat_id}\"/" "${CONFIG_DIR}/config.conf"
        
        log SUCCESS "Telegram configuration updated"
        
        # Test connection
        echo
        echo "Would you like to test the Telegram connection now? (y/n)"
        read -r test_now
        
        if [[ "$test_now" =~ ^[Yy]$ ]]; then
            log INFO "Testing Telegram connection..."
            if "${INSTALL_DIR}/lib/telegram_notifier.py" test; then
                log SUCCESS "Telegram test successful!"
            else
                log WARNING "Telegram test failed - please check your configuration"
            fi
        fi
    else
        log INFO "Skipping Telegram configuration"
        echo "You can configure it later by editing ${CONFIG_DIR}/config.conf"
    fi
}

configure_auto_response() {
    log STEP "Configuring auto-response settings..."
    
    echo
    echo -e "${YELLOW}⚠️  WARNING: Auto-response can kill processes automatically${NC}"
    echo "This feature should be used with extreme caution!"
    echo
    echo "Enable auto-kill for CRITICAL threats? (y/n)"
    read -r enable_auto_kill
    
    if [[ "$enable_auto_kill" =~ ^[Yy]$ ]]; then
        sed -i 's/AUTO_RESPONSE_ENABLED="false"/AUTO_RESPONSE_ENABLED="true"/' "${CONFIG_DIR}/config.conf"
        sed -i 's/AUTO_KILL_CRITICAL="false"/AUTO_KILL_CRITICAL="true"/' "${CONFIG_DIR}/config.conf"
        log SUCCESS "Auto-response enabled"
    else
        log INFO "Auto-response disabled (recommended for initial setup)"
    fi
}

setup_logrotate() {
    log STEP "Setting up log rotation..."
    
    cat > /etc/logrotate.d/tresk <<'EOF'
/var/log/tresk/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        systemctl reload tresk 2>/dev/null || true
    endscript
}
EOF
    
    log SUCCESS "Log rotation configured"
}

setup_cron() {
    log STEP "Setting up cron jobs (portable mode)..."
    
    local cron_file="/etc/cron.d/vps-security-monitor"
    
    cat > "$cron_file" <<EOF
# VPS Security Monitor Cron Jobs
# Generated by install.sh --portable

# Run monitoring every 5 minutes
*/5 * * * * root ${INSTALL_DIR}/bin/monitor.sh quick >/dev/null 2>&1

# Daily deep scan at 3:00 AM
0 3 * * * root ${INSTALL_DIR}/bin/monitor.sh deep >/dev/null 2>&1

# Daily summary at 8:00 AM
0 8 * * * root ${INSTALL_DIR}/bin/monitor.sh summary >/dev/null 2>&1

# Weekly report on Sundays at 9:00 AM
0 9 * * 0 root ${INSTALL_DIR}/bin/monitor.sh weekly >/dev/null 2>&1
EOF
    
    chmod 644 "$cron_file"
    log SUCCESS "Cron jobs configured"
}

# =============================================================================
# SERVICES MANAGEMENT
# =============================================================================

start_services() {
    log STEP "Starting services..."
    
    echo
    echo "Which services would you like to enable?"
    echo "1) Full monitoring (recommended)"
    echo "2) Monitoring only (no reports)"
    echo "3) Manual start (don't enable anything)"
    read -r service_choice
    
    case "$service_choice" in
        1)
            systemctl enable tresk.service
            systemctl enable tresk-deep-scan.timer
            systemctl enable tresk-summary.timer
            systemctl enable tresk-weekly.timer
            
            systemctl start tresk.service
            systemctl start tresk-deep-scan.timer
            systemctl start tresk-summary.timer
            systemctl start tresk-weekly.timer
            
            log SUCCESS "All services enabled and started"
            ;;
        
        2)
            systemctl enable tresk.service
            systemctl start tresk.service
            
            log SUCCESS "Monitoring service enabled and started"
            ;;
        
        3)
            log INFO "Services not started automatically"
            echo "You can start them manually with:"
            echo "  systemctl start vps-security-monitor"
            ;;
        
        *)
            log WARNING "Invalid choice, starting monitoring service only"
            systemctl enable tresk.service
            systemctl start tresk.service
            ;;
    esac
}

# =============================================================================
# VERIFICATION
# =============================================================================

verify_installation() {
    log STEP "Verifying installation..."
    
    local errors=0
    
    # Check files
    [[ -f "${INSTALL_DIR}/bin/monitor.sh" ]] || { log ERROR "monitor.sh missing"; ((errors++)); }
    [[ -f "${INSTALL_DIR}/lib/telegram_notifier.py" ]] || { log ERROR "telegram_notifier.py missing"; ((errors++)); }
    [[ -f "${INSTALL_DIR}/signatures/threat_signatures.json" ]] || { log ERROR "threat_signatures.json missing"; ((errors++)); }
    [[ -f "${CONFIG_DIR}/config.conf" ]] || { log ERROR "config.conf missing"; ((errors++)); }
    
    # Check executables
    [[ -x "${INSTALL_DIR}/bin/monitor.sh" ]] || { log ERROR "monitor.sh not executable"; ((errors++)); }
    
    # Check directories
    [[ -d "$LOG_DIR" ]] || { log ERROR "Log directory missing"; ((errors++)); }
    
    if [[ $errors -eq 0 ]]; then
        log SUCCESS "Installation verified successfully"
        return 0
    else
        log ERROR "Installation verification failed with $errors errors"
        return 1
    fi
}

# =============================================================================
# UNINSTALL
# =============================================================================

uninstall() {
    log STEP "Uninstalling VPS Security Monitor..."
    
    # Stop and disable services
    systemctl stop vps-security-monitor.service 2>/dev/null || true
    systemctl stop vps-security-deep-scan.timer 2>/dev/null || true
    systemctl stop vps-security-summary.timer 2>/dev/null || true
    systemctl stop vps-security-weekly.timer 2>/dev/null || true
    
    systemctl disable vps-security-monitor.service 2>/dev/null || true
    systemctl disable vps-security-deep-scan.timer 2>/dev/null || true
    systemctl disable vps-security-summary.timer 2>/dev/null || true
    systemctl disable vps-security-weekly.timer 2>/dev/null || true
    
    # Remove systemd files
    rm -f "${SYSTEMD_DIR}/tresk.service"
    rm -f "${SYSTEMD_DIR}/tresk-*.service"
    rm -f "${SYSTEMD_DIR}/tresk-*.timer"
    systemctl daemon-reload
    
    # Remove installation directory
    rm -rf "$INSTALL_DIR"
    rm -rf "$CONFIG_DIR"
    rm -rf "$LOG_DIR"
    
    # Remove logrotate config
    rm -f /etc/logrotate.d/vps-security-monitor
    
    log SUCCESS "Tresk uninstalled successfully"
}

# =============================================================================
# SYSTEMD CHECK
# =============================================================================

check_systemd() {
    if [[ "$IN_DOCKER" == true ]]; then
        log WARNING "Running in container - systemd may not be available"
        return 1
    fi
    
    if ! command -v systemctl &>/dev/null; then
        log WARNING "systemctl not found - systemd is not available"
        return 1
    fi
    
    if [[ ! -d "/run/systemd/system" ]] && [[ ! -d "/var/run/systemd/system" ]]; then
        log WARNING "systemd runtime directory not found"
        return 1
    fi
    
    return 0
}

# =============================================================================
# MAIN
# =============================================================================

show_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
    -h, --help        Show this help message
    -u, --uninstall   Uninstall VPS Security Monitor
    --no-telegram     Skip Telegram configuration
    --auto-kill       Enable auto-kill for critical threats
    --portable        Force portable mode (no systemd)
    -v, --version     Show version

Examples:
    $0                    # Full installation (auto-detect)
    $0 --no-telegram      # Install without Telegram setup
    $0 --portable         # Install without systemd (cron-based)
    $0 --uninstall        # Remove all components

EOF
}

main() {
    local uninstall_mode=false
    local skip_telegram=false
    local enable_auto_kill=false
    local force_portable=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -u|--uninstall)
                uninstall_mode=true
                shift
                ;;
            --no-telegram)
                skip_telegram=true
                shift
                ;;
            --auto-kill)
                enable_auto_kill=true
                shift
                ;;
            --portable)
                force_portable=true
                shift
                ;;
            -v|--version)
                echo "VPS Security Monitor Installer v${SCRIPT_VERSION}"
                exit 0
                ;;
            *)
                log ERROR "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    print_banner
    
    if [[ "$uninstall_mode" == true ]]; then
        uninstall
        exit 0
    fi
    
    check_root
    detect_os
    check_docker
    
    # Check for systemd availability
    local use_systemd=true
    if [[ "$force_portable" == true ]]; then
        log INFO "Portable mode forced via --portable flag"
        use_systemd=false
    elif ! check_systemd; then
        log WARNING "systemd is not available on this system"
        echo
        echo "Options:"
        echo "  1) Continue with portable installation (uses cron)"
        echo "  2) Exit and install manually"
        echo
        read -p "Choose option (1/2): " choice
        if [[ "$choice" == "1" ]]; then
            use_systemd=false
        else
            log INFO "Exiting. You can run the portable installer with:"
            log INFO "  sudo ./install-portable.sh"
            exit 0
        fi
    fi
    
    log INFO "Starting installation of VPS Security Monitor v${SCRIPT_VERSION}"
    
    install_dependencies
    create_directories
    install_files
    
    if [[ "$use_systemd" == true ]]; then
        setup_systemd
    else
        setup_cron
    fi
    
    setup_logrotate
    
    if [[ "$skip_telegram" == false ]]; then
        configure_telegram
    fi
    
    if [[ "$enable_auto_kill" == true ]]; then
        configure_auto_response
    fi
    
    verify_installation
    
    if [[ "$use_systemd" == true ]]; then
        start_services
    else
        log INFO "Portable installation uses cron for scheduling"
        log INFO "Logs are available at: ${LOG_DIR}/monitor.log"
    fi
    
    echo
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                           ║${NC}"
    echo -e "${GREEN}║              Installation completed successfully!                         ║${NC}"
    echo -e "${GREEN}║                                                                           ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo "Installation directory: $INSTALL_DIR"
    echo "Configuration file: ${CONFIG_DIR}/config.conf"
    echo "Log directory: $LOG_DIR"
    echo
    
    if [[ "$use_systemd" == true ]]; then
        echo "Useful commands:"
        echo "  systemctl status vps-security-monitor    # Check service status"
        echo "  journalctl -u vps-security-monitor -f    # View live logs"
    else
        echo "Cron jobs are configured for periodic scanning."
        echo "To run manually: ${INSTALL_DIR}/bin/monitor.sh quick"
    fi
    
    echo "  ${INSTALL_DIR}/bin/monitor.sh quick      # Run quick scan"
    echo "  ${INSTALL_DIR}/bin/monitor.sh deep       # Run deep scan"
    echo "  ${INSTALL_DIR}/bin/monitor.sh test-telegram  # Test Telegram"
    echo
    echo "For help: ${INSTALL_DIR}/bin/monitor.sh --help"
    echo
}

main "$@"
