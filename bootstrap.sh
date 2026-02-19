#!/bin/bash
################################################################################
# Tresk - Bootstrap Installer
# Version: 1.0.0
# Description: One-command installation from GitHub/curl
# Usage: curl -fsSL https://your-domain.com/install.sh | sudo bash
################################################################################

set -e

readonly REPO_URL="https://raw.githubusercontent.com/p4ndish/tresk/main"
readonly INSTALLER_URL="${REPO_URL}/install.sh"
readonly TEMP_DIR="/tmp/tresk-install"

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

main() {
    # Check root
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This script must be run as root"
        echo "Try: curl -fsSL ${INSTALLER_URL} | sudo bash"
        exit 1
    fi

    echo "Tresk - Bootstrap Installer"
    echo "=========================================="
    echo

    # Detect package manager for prerequisites
    if command -v curl &>/dev/null; then
        DOWNLOAD_CMD="curl -fsSL"
    elif command -v wget &>/dev/null; then
        DOWNLOAD_CMD="wget -qO-"
    else
        echo "Installing curl..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y -qq curl
        elif command -v dnf &>/dev/null; then
            dnf install -y -q curl
        elif command -v yum &>/dev/null; then
            yum install -y -q curl
        elif command -v apk &>/dev/null; then
            apk add --no-cache curl
        elif command -v pacman &>/dev/null; then
            pacman -Sy --noconfirm curl
        else
            echo "Error: Neither curl nor wget found. Please install curl manually."
            exit 1
        fi
        DOWNLOAD_CMD="curl -fsSL"
    fi

    # Create temp directory
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"

    echo "Downloading installer..."
    $DOWNLOAD_CMD "$INSTALLER_URL" > install.sh
    chmod +x install.sh

    echo "Downloading required files..."
    mkdir -p bin lib config signatures systemd
    
    # Download all necessary files
    $DOWNLOAD_CMD "${REPO_URL}/bin/monitor.sh" > bin/monitor.sh || true
    $DOWNLOAD_CMD "${REPO_URL}/lib/telegram_notifier.py" > lib/telegram_notifier.py || true
    $DOWNLOAD_CMD "${REPO_URL}/lib/process_analyzer.py" > lib/process_analyzer.py || true
    $DOWNLOAD_CMD "${REPO_URL}/config/config.conf" > config/config.conf || true
    $DOWNLOAD_CMD "${REPO_URL}/signatures/threat_signatures.json" > signatures/threat_signatures.json || true
    
    # Download systemd files
    for file in tresk.service tresk-network.service \
                tresk-deep-scan.service tresk-deep-scan.timer \
                tresk-summary.service tresk-summary.timer \
                tresk-weekly.service tresk-weekly.timer; do
        $DOWNLOAD_CMD "${REPO_URL}/systemd/${file}" > "systemd/${file}" || true
    done

    # Check if we got the main script
    if [[ ! -s "bin/monitor.sh" ]]; then
        echo "Error: Failed to download required files."
        echo "Please check your internet connection or install manually."
        exit 1
    fi

    echo "Running installer..."
    echo
    ./install.sh "$@"
}

main "$@"
