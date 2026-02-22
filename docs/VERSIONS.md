# 📋 Tresk Component Versions & Compatibility

## Core Components

| Component | Minimum Version | Recommended | Latest Tested | Notes |
|-----------|----------------|-------------|---------------|-------|
| **Bash** | 4.0+ | 5.0+ | 5.2 | Script interpreter |
| **Python** | 3.6+ | 3.9+ | 3.11 | AI analyzer & Telegram |
| **Systemd** | 232+ | 245+ | 252 | Service management |
| **Linux Kernel** | 3.10+ | 5.4+ | 6.2 | Core functionality |

## External Dependencies

### System Packages

| Package | Purpose | Debian/Ubuntu | RHEL/CentOS | Arch | Alpine |
|---------|---------|---------------|-------------|------|--------|
| **curl** | HTTP requests | 7.68+ | 7.61+ | 8.0+ | 8.0+ |
| **jq** | JSON parsing | 1.6+ | 1.6+ | 1.6+ | 1.6+ |
| **bc** | Calculations | 1.07+ | 1.07+ | 1.07+ | 1.07+ |
| **lsof** | Process inspection | 4.93+ | 4.87+ | 4.94+ | 4.94+ |
| **psmisc** | Process tools | 23.3+ | 23.1+ | 23.5+ | N/A |

### Security Tools (Installed by `tresk harden`)

| Tool | Purpose | Latest Version | Repository |
|------|---------|----------------|------------|
| **UFW** | Firewall | 0.36.2 | Ubuntu/Debian universe |
| **Fail2ban** | Brute force protection | 1.0.2 | All major repos |
| **Rkhunter** | Rootkit detection | 1.4.6 | All major repos |
| **Chkrootkit** | Rootkit detection | 0.55 | All major repos |
| **ClamAV** | Antivirus | 1.0.5 | All major repos |
| **AIDE** | File integrity | 0.17.4 | All major repos |
| **Auditd** | System auditing | 3.0.9 | All major repos |

### Python Packages

| Package | Minimum | Latest | Purpose |
|---------|---------|--------|---------|
| **requests** | 2.25.0 | 2.31.0 | HTTP library for API calls |

## API Integrations

| Service | API Version | Endpoint | Status |
|---------|-------------|----------|--------|
| **Moonshot AI** | v1 | api.moonshot.cn | ✅ Active |
| **Kimi Code** | v1 | api.kimi.com | ✅ Active |
| **Telegram** | Bot API 6.9 | api.telegram.org | ✅ Active |

## OS Compatibility Matrix

| OS | Version | Systemd | Support Status |
|----|---------|---------|----------------|
| **Ubuntu** | 18.04, 20.04, 22.04, 24.04 | ✅ | ✅ Full support |
| **Debian** | 10, 11, 12 | ✅ | ✅ Full support |
| **CentOS** | 7, 8 | ✅ | ✅ Full support |
| **RHEL** | 7, 8, 9 | ✅ | ✅ Full support |
| **Rocky Linux** | 8, 9 | ✅ | ✅ Full support |
| **AlmaLinux** | 8, 9 | ✅ | ✅ Full support |
| **Fedora** | 37, 38, 39 | ✅ | ✅ Full support |
| **Arch Linux** | Rolling | ✅ | ✅ Full support |
| **Manjaro** | Rolling | ✅ | ✅ Full support |
| **Alpine** | 3.16+ | ❌ (portable) | ⚠️ Portable mode only |
| **openSUSE** | Leap 15.4+ | ✅ | ✅ Full support |
| **Void Linux** | Rolling | ❌ | ⚠️ Portable mode only |

## Version Check Commands

### Check Your System

```bash
# Bash version
bash --version

# Python version
python3 --version

# Systemd version
systemd --version

# Kernel version
uname -r

# Check all at once
echo "Bash: $(bash --version | head -1)"
echo "Python: $(python3 --version)"
echo "Systemd: $(systemd --version | head -1)"
echo "Kernel: $(uname -r)"
```

### Check Security Tools

```bash
# After running 'tresk harden', verify versions:
ufw version          # Firewall
fail2ban-server --version  # Brute force protection
rkhunter --version   # Rootkit scanner
clamscan --version   # Antivirus
aide --version       # File integrity
auditctl --version   # System auditing
```

## Checking for Updates

### Update Tresk Itself

```bash
# Check current version
tresk --version

# Update to latest
sudo curl -fsSL https://raw.githubusercontent.com/p4ndish/tresk/main/install.sh | sudo bash
```

### Update System Packages

```bash
# Debian/Ubuntu
sudo apt update && sudo apt upgrade -y

# RHEL/CentOS/Rocky
sudo dnf update -y

# Arch
sudo pacman -Syu

# Alpine
sudo apk update && sudo apk upgrade
```

### Update Python Dependencies

```bash
# Update requests
sudo pip3 install --upgrade requests
```

### Update Security Tools

```bash
# Update ClamAV definitions
sudo freshclam

# Update Rkhunter
sudo rkhunter --update

# Update AIDE database
sudo aide --update
```

## Deprecated Components

| Component | Status | Replacement | Removal Date |
|-----------|--------|-------------|--------------|
| Python 2.7 | ❌ Removed | Python 3.6+ | N/A |
| SysV init | ⚠️ Legacy | Systemd | Future |
| ifconfig | ⚠️ Deprecated | ip command | N/A |
| netstat | ⚠️ Deprecated | ss command | N/A |

## Security Advisory

### Current Vulnerabilities Status

| CVE | Component | Status | Action |
|-----|-----------|--------|--------|
| N/A | Tresk | ✅ No known CVEs | Keep updated |
| Check | Bash | Variable | Update via package manager |
| Check | Python | Variable | Update via package manager |

### Recommended Security Practices

1. **Update weekly**:
   ```bash
   sudo tresk harden --status  # Check tool versions
   sudo apt update && sudo apt upgrade  # Update system
   ```

2. **Monitor EOL dates**:
   - Ubuntu 18.04: EOL April 2023 (upgrade to 20.04+)
   - CentOS 7: EOL June 2024 (migrate to Rocky/Alma)
   - Debian 10: EOL June 2024 (upgrade to 11+)

3. **Test updates in staging** before production

## Changelog

### Version 1.0.0 (Current)
- Initial release
- Core monitoring functionality
- Telegram integration
- AI analysis (Kimi K2)
- VPS hardening module

### Planned 1.1.0
- Docker security scanning
- Kubernetes integration
- Web dashboard
- Multi-server management

## Reporting Issues

If you find compatibility issues with specific versions:

1. Check this document first
2. Test with latest versions
3. Report at: https://github.com/p4ndish/tresk/issues

Include:
- OS and version
- Component versions
- Error messages
- Steps to reproduce
