#!/bin/bash
################################################################################
# Tresk - VPS Security Monitor Uninstallation
# Version: 1.0.0
# Description: Clean, graceful removal of Tresk and all its components
################################################################################

# Don't use set -e as we want to handle errors gracefully
# set -e

# Configuration
readonly INSTALL_DIR="/opt/tresk"
readonly CONFIG_DIR="/etc/tresk"
readonly LOG_DIR="/var/log/tresk"
readonly SYSTEMD_DIR="/etc/systemd/system"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Counters for summary
REMOVED_COUNT=0
FAILED_COUNT=0
SKIPPED_COUNT=0

log() {
    local level="$1"
    shift
    local message="$*"
    
    case "$level" in
        INFO)    echo -e "${CYAN}[INFO]${NC} $message" ;;
        SUCCESS) echo -e "${GREEN}[✓]${NC} $message" ;;
        WARNING) echo -e "${YELLOW}[⚠]${NC} $message" ;;
        ERROR)   echo -e "${RED}[✗]${NC} $message" ;;
        DRY)     echo -e "${CYAN}[DRY-RUN]${NC} $message" ;;
    esac
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log ERROR "This script must be run as root"
        exit 1
    fi
}

# Check if systemd is available
has_systemd() {
    command -v systemctl &>/dev/null && [[ -d "/run/systemd/system" || -d "/var/run/systemd/system" ]]
}

# Safe remove function with dry-run support
safe_remove() {
    local path="$1"
    local description="${2:-$path}"
    local is_dir="${3:-false}"
    
    if [[ ! -e "$path" ]]; then
        log INFO "Not found: $description"
        ((SKIPPED_COUNT++))
        return 0
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        if [[ "$is_dir" == "true" ]]; then
            log DRY "Would remove directory: $description"
        else
            log DRY "Would remove file: $description"
        fi
        return 0
    fi
    
    if [[ "$is_dir" == "true" ]]; then
        rm -rf "$path" 2>/dev/null
    else
        rm -f "$path" 2>/dev/null
    fi
    
    if [[ ! -e "$path" ]]; then
        log SUCCESS "Removed: $description"
        ((REMOVED_COUNT++))
        return 0
    else
        log ERROR "Failed to remove: $description"
        ((FAILED_COUNT++))
        return 1
    fi
}

# Stop and disable a systemd service
stop_service() {
    local service="$1"
    
    # Check if service exists
    if ! systemctl list-unit-files "${service}" &>/dev/null; then
        log INFO "Service not found: $service"
        return 0
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log DRY "Would stop and disable: $service"
        return 0
    fi
    
    # Stop service (ignore errors if already stopped)
    systemctl stop "$service" 2>/dev/null || true
    
    # Disable service
    systemctl disable "$service" 2>/dev/null || true
    
    log SUCCESS "Stopped and disabled: $service"
    ((REMOVED_COUNT++))
}

# Show what will be uninstalled
show_what_will_be_removed() {
    echo
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              TRESK UNINSTALLATION PLAN                       ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    echo "Services to stop and disable:"
    local services=("tresk.service" "tresk-network.service" "tresk-deep-scan.timer" "tresk-summary.timer" "tresk-weekly.timer")
    for svc in "${services[@]}"; do
        if systemctl list-unit-files "$svc" &>/dev/null 2>&1; then
            echo "  • $svc"
        else
            echo "  • $svc (not found - will skip)"
        fi
    done
    
    echo
    echo "Files and directories to remove:"
    
    # Systemd files
    if [[ -d "$SYSTEMD_DIR" ]]; then
        for f in "$SYSTEMD_DIR"/tresk*.service "$SYSTEMD_DIR"/tresk*.timer; do
            [[ -e "$f" ]] && echo "  • $f"
        done
    fi
    
    # Main directories
    [[ -d "$INSTALL_DIR" ]] && echo "  • $INSTALL_DIR (installation directory)"
    [[ -d "$CONFIG_DIR" ]] && echo "  • $CONFIG_DIR (configuration directory)"
    [[ -d "$LOG_DIR" ]] && echo "  • $LOG_DIR (log directory) - optional"
    
    # Other files
    [[ -f "/etc/logrotate.d/tresk" ]] && echo "  • /etc/logrotate.d/tresk"
    [[ -f "/etc/cron.d/tresk" ]] && echo "  • /etc/cron.d/tresk"
    [[ -L "/usr/local/bin/tresk" ]] && echo "  • /usr/local/bin/tresk (symlink)"
    
    echo
    echo -e "${YELLOW}Note: This action is irreversible. Configuration and logs will be lost.${NC}"
    echo
}

uninstall() {
    log INFO "Uninstalling Tresk..."
    
    # Show plan first
    show_what_will_be_removed
    
    # Confirm in interactive mode (unless --yes flag)
    if [[ -t 0 && "$SKIP_CONFIRM" != "true" && "$DRY_RUN" != "true" ]]; then
        echo
        read -p "Are you sure you want to proceed? (yes/no): " confirm
        if [[ "$confirm" != "yes" ]]; then
            log INFO "Uninstallation cancelled"
            exit 0
        fi
        echo
    fi
    
    # Stop and disable services
    if has_systemd; then
        log INFO "Stopping and disabling services..."
        stop_service "tresk.service"
        stop_service "tresk-network.service"
        stop_service "tresk-deep-scan.timer"
        stop_service "tresk-summary.timer"
        stop_service "tresk-weekly.timer"
        
        # Reload systemd
        if [[ "$DRY_RUN" != "true" ]]; then
            systemctl daemon-reload 2>/dev/null || true
            log SUCCESS "Systemd daemon reloaded"
        fi
    else
        log INFO "Systemd not available, skipping service management"
    fi
    
    # Remove systemd files
    log INFO "Removing systemd files..."
    safe_remove "$SYSTEMD_DIR/tresk.service" "tresk.service"
    safe_remove "$SYSTEMD_DIR/tresk-network.service" "tresk-network.service"
    safe_remove "$SYSTEMD_DIR/tresk-deep-scan.service" "tresk-deep-scan.service"
    safe_remove "$SYSTEMD_DIR/tresk-deep-scan.timer" "tresk-deep-scan.timer"
    safe_remove "$SYSTEMD_DIR/tresk-summary.service" "tresk-summary.service"
    safe_remove "$SYSTEMD_DIR/tresk-summary.timer" "tresk-summary.timer"
    safe_remove "$SYSTEMD_DIR/tresk-weekly.service" "tresk-weekly.service"
    safe_remove "$SYSTEMD_DIR/tresk-weekly.timer" "tresk-weekly.timer"
    
    # Legacy cleanup
    safe_remove "/etc/systemd/system/vps-security-monitor.service" "legacy vps-security-monitor.service"
    safe_remove "/etc/systemd/system/vps-security-network.service" "legacy vps-security-network.service"
    safe_remove "/etc/systemd/system/vps-security-*.timer" "legacy timers"
    
    # Remove cron files
    log INFO "Removing cron files..."
    safe_remove "/etc/cron.d/tresk" "tresk cron file"
    safe_remove "/etc/cron.d/vps-security-monitor" "legacy cron file"
    
    # Remove logrotate config
    log INFO "Removing logrotate configuration..."
    safe_remove "/etc/logrotate.d/tresk" "tresk logrotate config"
    safe_remove "/etc/logrotate.d/vps-security-monitor" "legacy logrotate config"
    
    # Remove command symlink
    log INFO "Removing command symlink..."
    safe_remove "/usr/local/bin/tresk" "tresk command symlink"
    
    # Remove installation directory
    log INFO "Removing installation files..."
    safe_remove "$INSTALL_DIR" "installation directory" "true"
    
    # Remove configuration directory
    log INFO "Removing configuration files..."
    safe_remove "$CONFIG_DIR" "configuration directory" "true"
    
    # Handle logs
    log INFO "Handling log files..."
    if [[ -d "$LOG_DIR" ]]; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log DRY "Would ask about log files (or preserve in non-interactive mode)"
        elif [[ -t 0 && "$REMOVE_LOGS" == "" ]]; then
            # Interactive mode - ask user
            echo
            read -p "Remove log files at $LOG_DIR? (y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                safe_remove "$LOG_DIR" "log directory" "true"
            else
                log INFO "Log files preserved at $LOG_DIR"
                ((SKIPPED_COUNT++))
            fi
        elif [[ "$REMOVE_LOGS" == "true" ]]; then
            safe_remove "$LOG_DIR" "log directory" "true"
        else
            log INFO "Log files preserved at $LOG_DIR (use --remove-logs to delete)"
            ((SKIPPED_COUNT++))
        fi
    else
        log INFO "No log directory found"
    fi
    
    # Summary
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                   UNINSTALLATION SUMMARY                     ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "Dry-run completed. No changes were made."
    else
        echo -e "  ${GREEN}✓ Removed: $REMOVED_COUNT${NC}"
        echo -e "  ${YELLOW}⚠ Skipped/Not found: $SKIPPED_COUNT${NC}"
        [[ $FAILED_COUNT -gt 0 ]] && echo -e "  ${RED}✗ Failed: $FAILED_COUNT${NC}"
        echo
        log SUCCESS "Tresk has been uninstalled successfully"
        echo
        echo "If you used 'tresk harden' to install security tools (fail2ban, etc.),"
        echo "those tools remain installed. Remove them manually if desired:"
        echo "  sudo apt remove fail2ban rkhunter chkrootkit clamav aide"
    fi
    echo
}

show_help() {
    cat <<'EOF'
Tresk Uninstallation Script

Usage: sudo ./uninstall.sh [OPTIONS]

Options:
    --dry-run       Show what would be removed without actually removing
    --yes, -y       Skip confirmation prompt
    --remove-logs   Also remove log files without asking
    --help, -h      Show this help message

Examples:
    sudo ./uninstall.sh           # Interactive uninstallation
    sudo ./uninstall.sh --dry-run # Preview what will be removed
    sudo ./uninstall.sh --yes     # Uninstall without confirmation
    sudo ./uninstall.sh --remove-logs  # Remove everything including logs

EOF
}

# Parse arguments
DRY_RUN="false"
SKIP_CONFIRM="false"
REMOVE_LOGS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN="true"
            shift
            ;;
        --yes|-y)
            SKIP_CONFIRM="true"
            shift
            ;;
        --remove-logs)
            REMOVE_LOGS="true"
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            log ERROR "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Main
check_root
uninstall
