#!/bin/bash
################################################################################
# Tresk - Package Manager Module
# Version: 1.0.0
# Description: Modular package manager abstraction layer
################################################################################

# =============================================================================
# PACKAGE MANAGER DETECTION
# =============================================================================

detect_package_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    elif command -v apk &>/dev/null; then
        echo "apk"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    elif command -v zypper &>/dev/null; then
        echo "zypper"
    elif command -v xbps-install &>/dev/null; then
        echo "xbps"
    elif command -v emerge &>/dev/null; then
        echo "portage"
    else
        echo "unknown"
    fi
}

# =============================================================================
# PACKAGE INSTALLATION
# =============================================================================

pm_update() {
    local pm="$1"
    case "$pm" in
        apt)     apt-get update -qq ;;
        dnf)     dnf check-update -y || true ;;
        yum)     yum makecache -q ;;
        apk)     apk update ;;
        pacman)  pacman -Sy --quiet ;;
        zypper)  zypper refresh ;;
        xbps)    xbps-install -Sy ;;
        portage) emerge --sync --quiet ;;
    esac
}

pm_install() {
    local pm="$1"
    shift
    local packages=("$@")
    
    case "$pm" in
        apt)     apt-get install -y -qq "${packages[@]}" 2>/dev/null || return 1 ;;
        dnf)     dnf install -y -q "${packages[@]}" 2>/dev/null || return 1 ;;
        yum)     yum install -y -q "${packages[@]}" 2>/dev/null || return 1 ;;
        apk)     apk add --no-cache "${packages[@]}" 2>/dev/null || return 1 ;;
        pacman)  pacman -Sy --noconfirm --quiet "${packages[@]}" 2>/dev/null || return 1 ;;
        zypper)  zypper install -y "${packages[@]}" 2>/dev/null || return 1 ;;
        xbps)    xbps-install -y "${packages[@]}" 2>/dev/null || return 1 ;;
        portage) emerge --quiet-build "${packages[@]}" 2>/dev/null || return 1 ;;
        *)       return 1 ;;
    esac
}

# =============================================================================
# PACKAGE AVAILABILITY CHECK
# =============================================================================

pm_is_installed() {
    local package="$1"
    
    if command -v dpkg-query &>/dev/null; then
        dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"
    elif command -v rpm &>/dev/null; then
        rpm -q "$package" &>/dev/null
    elif command -v apk &>/dev/null; then
        apk info -e "$package" &>/dev/null
    elif command -v pacman &>/dev/null; then
        pacman -Q "$package" &>/dev/null
    else
        return 1
    fi
}

# =============================================================================
# PACKAGE NAME MAPPING (distro-specific package names)
# =============================================================================

get_package_name() {
    local pm="$1"
    local generic_name="$2"
    
    case "$generic_name" in
        python3)
            case "$pm" in
                apk) echo "python3" ;;
                *)   echo "python3" ;;
            esac
            ;;
        python3-pip)
            case "$pm" in
                apk)     echo "py3-pip" ;;
                pacman)  echo "python-pip" ;;
                *)       echo "python3-pip" ;;
            esac
            ;;
        net-tools)
            case "$pm" in
                apk) echo "net-tools" ;;
                *)   echo "net-tools" ;;
            esac
            ;;
        procps)
            case "$pm" in
                apk)    echo "procps" ;;
                pacman) echo "procps-ng" ;;
                *)      echo "procps" ;;
            esac
            ;;
        psmisc)
            case "$pm" in
                apk|pacman|zypper) echo "" ;;  # often built-in or different name
                *)                 echo "psmisc" ;;
            esac
            ;;
        aide)
            case "$pm" in
                apk)    echo "" ;;  # may not be available
                zypper) echo "aide" ;;
                *)      echo "aide" ;;
            esac
            ;;
        auditd)
            case "$pm" in
                alpine) echo "" ;;  # not typically available
                arch)   echo "audit" ;;
                *)      echo "auditd" ;;
            esac
            ;;
        rkhunter)
            case "$pm" in
                alpine) echo "" ;;  # may not be available
                arch)   echo "rkhunter" ;;
                *)      echo "rkhunter" ;;
            esac
            ;;
        chkrootkit)
            case "$pm" in
                alpine) echo "" ;;  # may not be available
                arch)   echo "chkrootkit" ;;
                *)      echo "chkrootkit" ;;
            esac
            ;;
        *)
            echo "$generic_name"
            ;;
    esac
}

# =============================================================================
# DEPENDENCY INSTALLATION (Main Function)
# =============================================================================

install_dependencies_modular() {
    local pm
    pm=$(detect_package_manager)
    
    if [[ "$pm" == "unknown" ]]; then
        echo "WARNING: Unknown package manager. Dependencies may need manual installation."
        return 1
    fi
    
    echo "Using package manager: $pm"
    
    # Update package lists
    pm_update "$pm"
    
    # Define base dependencies (always required)
    local base_deps=("curl" "jq" "bc" "lsof" "python3")
    local base_to_install=()
    
    for dep in "${base_deps[@]}"; do
        local pkg_name
        pkg_name=$(get_package_name "$pm" "$dep")
        if [[ -n "$pkg_name" ]] && ! pm_is_installed "$pkg_name"; then
            base_to_install+=("$pkg_name")
        fi
    done
    
    if [[ ${#base_to_install[@]} -gt 0 ]]; then
        echo "Installing base dependencies: ${base_to_install[*]}"
        pm_install "$pm" "${base_to_install[@]}" || echo "Warning: Some packages failed to install"
    fi
    
    # Optional but recommended dependencies
    local optional_deps=("net-tools" "procps" "psmisc")
    local optional_to_install=()
    
    for dep in "${optional_deps[@]}"; do
        local pkg_name
        pkg_name=$(get_package_name "$pm" "$dep")
        if [[ -n "$pkg_name" ]] && ! pm_is_installed "$pkg_name"; then
            optional_to_install+=("$pkg_name")
        fi
    done
    
    if [[ ${#optional_to_install[@]} -gt 0 ]]; then
        echo "Installing optional dependencies: ${optional_to_install[*]}"
        pm_install "$pm" "${optional_to_install[@]}" || echo "Warning: Some optional packages failed to install"
    fi
    
    # Security tools (best effort)
    local security_deps=("rkhunter" "chkrootkit")
    local security_to_install=()
    
    for dep in "${security_deps[@]}"; do
        local pkg_name
        pkg_name=$(get_package_name "$pm" "$dep")
        if [[ -n "$pkg_name" ]] && ! pm_is_installed "$pkg_name"; then
            security_to_install+=("$pkg_name")
        fi
    done
    
    if [[ ${#security_to_install[@]} -gt 0 ]]; then
        echo "Installing security tools: ${security_to_install[*]}"
        pm_install "$pm" "${security_to_install[@]}" || echo "Warning: Some security tools failed to install"
    fi
    
    # Python pip and requests module
    local pip_pkg
    pip_pkg=$(get_package_name "$pm" "python3-pip")
    if [[ -n "$pip_pkg" ]] && ! command -v pip3 &>/dev/null; then
        pm_install "$pm" "$pip_pkg" || true
    fi
    
    # Install Python requests module
    if command -v pip3 &>/dev/null; then
        pip3 install --quiet requests 2>/dev/null || echo "Warning: Failed to install Python requests module"
    fi
    
    return 0
}

# If script is run directly, install dependencies
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    install_dependencies_modular
fi
