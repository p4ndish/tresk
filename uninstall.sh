#!/bin/bash
################################################################################
# Tresk - VPS Security Monitor Uninstallation
# Version: 1.0.0
################################################################################

set -e

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

log() {
    local level="$1"
    shift
    local message="$*"
    
    case "$level" in
        INFO)    echo -e "${GREEN}[INFO]${NC} $message" ;;
        SUCCESS) echo -e "${GREEN}[✓]${NC} $message" ;;
        WARNING) echo -e "${YELLOW}[WARNING]${NC} $message" ;;
        ERROR)   echo -e "${RED}[ERROR]${NC} $message" ;;
    esac
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log ERROR "This script must be run as root"
        exit 1
    fi
}

uninstall() {
    log INFO "Uninstalling Tresk..."
    
    # Stop and disable services
    log INFO "Stopping services..."
    systemctl stop tresk.service 2>/dev/null || true
    systemctl stop tresk-network.service 2>/dev/null || true
    systemctl stop tresk-deep-scan.timer 2>/dev/null || true
    systemctl stop tresk-summary.timer 2>/dev/null || true
    systemctl stop tresk-weekly.timer 2>/dev/null || true
    
    systemctl disable tresk.service 2>/dev/null || true
    systemctl disable tresk-network.service 2>/dev/null || true
    systemctl disable tresk-deep-scan.timer 2>/dev/null || true
    systemctl disable tresk-summary.timer 2>/dev/null || true
    systemctl disable tresk-weekly.timer 2>/dev/null || true
    
    # Remove systemd files
    log INFO "Removing systemd files..."
    rm -f /etc/systemd/system/tresk.service
    rm -f /etc/systemd/system/tresk-*.service
    rm -f /etc/systemd/system/tresk-*.timer
    systemctl daemon-reload
    
    # Remove installation directory
    log INFO "Removing installation files..."
    rm -rf /opt/tresk
    rm -rf /etc/tresk
    
    # Ask about logs
    echo
    read -p "Remove log files? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf /var/log/tresk
        log INFO "Log files removed"
    else
        log INFO "Log files preserved at /var/log/tresk"
    fi
    
    # Remove logrotate config
    rm -f /etc/logrotate.d/tresk
    rm -f /etc/logrotate.d/vps-security-monitor  # Legacy cleanup
    
    # Remove cron file if using portable mode
    rm -f /etc/cron.d/tresk
    rm -f /etc/cron.d/vps-security-monitor  # Legacy cleanup
    
    log SUCCESS "Tresk has been uninstalled successfully"
}

# Main
check_root
uninstall
