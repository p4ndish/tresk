# Tresk - Installation Guide

## Quick Start (One Command)

### Method 1: Bootstrap Script (Recommended)

Install directly from GitHub without downloading anything first:

```bash
# Using curl
curl -fsSL https://raw.githubusercontent.com/yourusername/tresk/main/bootstrap.sh | sudo bash

# Using wget
wget -qO- https://raw.githubusercontent.com/yourusername/tresk/main/bootstrap.sh | sudo bash
```

### Method 2: Clone and Install

```bash
git clone https://github.com/yourusername/tresk.git
cd tresk
sudo ./install.sh
```

### Method 3: Download Release

```bash
wget https://github.com/yourusername/tresk/releases/download/v1.0.0/tresk-1.0.0.tar.gz
tar -xzf tresk-1.0.0.tar.gz
cd tresk
sudo ./install.sh
```

---

## Installation Options

### Standard Installation (with systemd)

For most Linux distributions with systemd:

```bash
sudo ./install.sh
```

**What it does:**
- Automatically detects your OS and package manager
- Installs all required dependencies
- Sets up systemd services and timers
- Configures log rotation
- Optionally configures Telegram notifications

### Portable Installation (without systemd)

For containers, WSL, or systems without systemd:

```bash
# Auto-detect (will offer portable mode if systemd unavailable)
sudo ./install.sh

# Force portable mode
sudo ./install.sh --portable

# Or use the dedicated portable installer
sudo ./install-portable.sh
```

**What it does:**
- Uses cron instead of systemd
- Same functionality, different scheduling mechanism
- Works in Docker containers, WSL, Alpine, etc.

### Non-Interactive Installation

```bash
# Skip Telegram setup
sudo ./install.sh --no-telegram

# Enable auto-kill for critical threats (use with caution!)
sudo ./install.sh --auto-kill

# Combine options
sudo ./install.sh --no-telegram --auto-kill
```

---

## Supported Operating Systems

| OS | Package Manager | Status |
|----|----------------|--------|
| Ubuntu 18.04+ | apt | ✅ Fully Supported |
| Debian 9+ | apt | ✅ Fully Supported |
| CentOS 7+ | yum/dnf | ✅ Fully Supported |
| RHEL 7+ | yum/dnf | ✅ Fully Supported |
| Rocky Linux 8+ | dnf | ✅ Fully Supported |
| AlmaLinux 8+ | dnf | ✅ Fully Supported |
| Fedora 30+ | dnf | ✅ Fully Supported |
| Alpine Linux | apk | ✅ Portable Mode |
| Arch Linux | pacman | ✅ Fully Supported |
| Manjaro | pacman | ✅ Fully Supported |
| openSUSE | zypper | ✅ Fully Supported |
| Void Linux | xbps | ⚠️ Portable Mode |

---

## Dependencies

### Automatic Installation

The installer **automatically installs** all dependencies. You don't need to install anything manually.

### Required Dependencies

| Package | Purpose |
|---------|---------|
| curl | Downloads, API calls |
| jq | JSON parsing |
| bc | Math calculations |
| lsof | Network connection monitoring |
| python3 | Telegram notifications |
| python3-pip | Python package management |

### Optional Dependencies

| Package | Purpose |
|---------|---------|
| net-tools | Network interface info |
| procps | Process monitoring |
| psmisc | Additional process tools |
| rkhunter | Rootkit detection |
| chkrootkit | Rootkit detection |
| aide | File integrity monitoring |
| auditd | System call auditing |

### Python Dependencies

- `requests` - For Telegram API calls

---

## Pre-Installation Requirements

### Minimum Requirements

- Linux kernel 3.10+
- Bash 4.0+
- Python 3.6+ (for notifications)
- Root access (sudo)
- 50 MB disk space
- 50 MB RAM

### Network Requirements

- Outbound HTTPS (port 443) for Telegram notifications
- No inbound ports required

---

## Troubleshooting Installation

### "systemctl not found"

This means systemd is not available. The installer will offer portable mode:

```bash
# Choose option 1 for portable installation
# Or force it:
sudo ./install.sh --portable
```

### Package Installation Fails

Some packages may not be available in your repos. The installer continues anyway:

```bash
# Check what failed
cat /var/log/tresk/install.log

# Manually install missing packages if needed
# Then re-run the installer
```

### Permission Denied

```bash
# Make sure you're root
sudo -i
./install.sh

# Or use sudo
sudo ./install.sh
```

### "curl: command not found"

```bash
# Install curl manually first
apt-get update && apt-get install -y curl    # Debian/Ubuntu
yum install -y curl                           # CentOS/RHEL
apk add curl                                  # Alpine

# Then run installer
sudo ./install.sh
```

---

## Post-Installation Verification

```bash
# Check if installation was successful
/opt/tresk/bin/monitor.sh quick

# Test Telegram (if configured)
/opt/tresk/bin/monitor.sh test-telegram

# Check service status (systemd)
systemctl status tresk

# View logs
tail -f /var/log/tresk/monitor.log
```

---

## Uninstallation

```bash
# Method 1: Using install script
sudo ./install.sh --uninstall

# Method 2: Using uninstall script
sudo ./uninstall.sh

# Method 3: Manual removal
sudo rm -rf /opt/tresk
sudo rm -rf /etc/tresk
sudo rm -rf /var/log/tresk
sudo rm -f /etc/systemd/system/vps-security-*.service
sudo rm -f /etc/systemd/system/vps-security-*.timer
sudo rm -f /etc/cron.d/tresk
sudo rm -f /etc/logrotate.d/tresk
```

---

## Docker Installation

For Docker containers, use portable mode:

```dockerfile
FROM alpine:latest

RUN apk add --no-cache bash curl jq bc lsof python3 py3-pip

COPY . /tmp/tresk
RUN cd /tmp/tresk && ./install-portable.sh --no-telegram

CMD ["/opt/tresk/bin/monitor.sh", "monitor"]
```

Or use docker-compose:

```yaml
version: '3'
services:
  security-monitor:
    build: .
    privileged: true
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /var/log:/host/var/log:ro
```

---

## WSL Installation

Windows Subsystem for Linux works with portable mode:

```bash
# In WSL terminal
cd /mnt/c/Users/YourName/Downloads/tresk
sudo ./install.sh --portable
```

---

## Custom Installation Paths

To install to custom locations, edit the installer:

```bash
# Edit these variables in install.sh
readonly INSTALL_DIR="/opt/tresk"
readonly CONFIG_DIR="/etc/tresk"
readonly LOG_DIR="/var/log/tresk"
```

Then run the installer normally.

---

## Silent/Automated Installation

For automated deployments (Ansible, cloud-init, etc.):

```bash
#!/bin/bash
# Automated installation script

cd /tmp
wget -q https://github.com/yourusername/tresk/releases/download/v1.0.0/tresk.tar.gz
tar -xzf tresk.tar.gz
cd tresk

# Pre-configure Telegram
cat > config/config.conf <<EOF
TELEGRAM_ENABLED="true"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID}"
EOF

# Run installer non-interactively
sudo ./install.sh --no-telegram

# Configure Telegram separately
sudo sed -i "s/TELEGRAM_ENABLED=\"false\"/TELEGRAM_ENABLED=\"true\"/" /etc/tresk/config.conf
sudo sed -i "s/TELEGRAM_BOT_TOKEN=\"\"/TELEGRAM_BOT_TOKEN=\"${TELEGRAM_BOT_TOKEN}\"/" /etc/tresk/config.conf
sudo sed -i "s/TELEGRAM_CHAT_ID=\"\"/TELEGRAM_CHAT_ID=\"${TELEGRAM_CHAT_ID}\"/" /etc/tresk/config.conf

# Test
telegram_notifier=$(find /opt -name "telegram_notifier.py" 2>/dev/null | head -1)
python3 "$telegram_notifier" test
```

---

## Getting Help

- **Documentation**: See `docs/` directory
- **Troubleshooting**: See `docs/TROUBLESHOOTING.md`
- **Quick Start**: See `docs/QUICK_START.md`
- **Issues**: https://github.com/yourusername/tresk/issues
