# 🛡️ Tresk VPS Hardening Guide

## Overview

The `tresk harden` command provides automated VPS security hardening for fresh installations. It installs and configures industry-standard security tools with sensible defaults.

## Security Layers

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Network Security                                  │
│  - Firewall (UFW)                                           │
│  - Fail2ban (brute force protection)                        │
│  - Port scanning detection                                  │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Access Control                                    │
│  - SSH hardening                                            │
│  - Sudo configuration                                       │
│  - User account audit                                       │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Malware Protection                                │
│  - Rootkit detection (rkhunter/chkrootkit)                  │
│  - Antivirus (ClamAV)                                       │
│  - File integrity (AIDE)                                    │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: System Monitoring                                 │
│  - Auditd (system call auditing)                            │
│  - Log aggregation                                          │
│  - Process monitoring                                       │
├─────────────────────────────────────────────────────────────┤
│  Layer 5: Automated Maintenance                             │
│  - Unattended security updates                              │
│  - Log rotation                                             │
│  - Backup automation                                        │
└─────────────────────────────────────────────────────────────┘
```

## Tools Included

### Network Security

| Tool | Purpose | Default Config |
|------|---------|---------------|
| **UFW** | Firewall | Deny all incoming, allow SSH/HTTP/HTTPS |
| **Fail2ban** | Brute force protection | SSH: 3 failed attempts = 1 hour ban |
| **PSAD** | Port scan detection | Alert on suspicious scanning |

### Access Control

| Tool | Purpose | Default Config |
|------|---------|---------------|
| **SSH Hardening** | Secure remote access | Key-only, no root, port 22 |
| **PAM Configuration** | Auth policies | Strong password requirements |
| **Sudo Audit** | Privilege escalation | Log all sudo commands |

### Malware Protection

| Tool | Purpose | Tresk Integration |
|------|---------|-------------------|
| **Rkhunter** | Rootkit detection | Daily scans, alerts via Telegram |
| **Chkrootkit** | Rootkit detection | Weekly scans |
| **ClamAV** | Antivirus | Daily scan /tmp, /var/tmp, /home |
| **AIDE** | File integrity | Daily checks on critical files |

### System Monitoring

| Tool | Purpose | Tresk Integration |
|------|---------|-------------------|
| **Auditd** | System call auditing | Monitor privilege escalation |
| **Logwatch** | Log analysis | Daily summary reports |
| **Sysstat** | Performance monitoring | Resource usage tracking |

### Maintenance

| Tool | Purpose | Schedule |
|------|---------|----------|
| **Unattended-upgrades** | Auto security updates | Daily |
| **Needrestart** | Service restart after updates | After each upgrade |
| **Logrotate** | Log management | Daily rotation |

## Usage

### Basic Hardening
```bash
sudo tresk harden
```

### Interactive Mode (choose what to install)
```bash
sudo tresk harden --interactive
```

### Specific Categories
```bash
sudo tresk harden --network      # Only network security
sudo tresk harden --access       # Only access control
sudo tresk harden --malware      # Only malware protection
sudo tresk harden --monitoring   # Only monitoring tools
```

### Dry Run (see what would be installed)
```bash
sudo tresk harden --dry-run
```

### Check Current Hardening Status
```bash
sudo tresk harden --status
```

## Configuration

Edit `/etc/tresk/hardening.conf`:

```bash
# Network
INSTALL_UFW="true"
INSTALL_FAIL2BAN="true"
INSTALL_PSAD="false"  # Port scan detection (optional)

# SSH
SSH_PORT="22"
SSH_PERMIT_ROOT="no"
SSH_PASSWORD_AUTH="no"  # Key-only recommended
SSH_MAX_AUTH_TRIES="3"

# Fail2ban
FAIL2BAN_SSH_ENABLED="true"
FAIL2BAN_MAX_RETRY="3"
FAIL2BAN_BANTIME="3600"

# Updates
AUTO_UPDATES="true"
AUTO_REBOOT="false"  # Reboot after kernel updates?
REBOOT_TIME="03:00"  # When to reboot if needed

# ClamAV
CLAMAV_SCAN_SCHEDULE="daily"  # daily/weekly
CLAMAV_QUARANTINE="true"
CLAMAV_SCAN_PATHS="/tmp /var/tmp /home"
```

## What Gets Installed

### Debian/Ubuntu
```bash
# Network
ufw fail2ban

# Malware
rkhunter chkrootkit clamav clamav-daemon aide

# Monitoring
auditd sysstat

# Maintenance
unattended-upgrades needrestart

# Utilities
logwatch apt-listchanges
```

### RHEL/CentOS/Rocky
```bash
# Network
firewalld fail2ban

# Malware
rkhunter chkrootkit clamav aide

# Monitoring
audit sysstat

# Maintenance
yum-cron
```

### Arch
```bash
# Network
ufw fail2ban

# Malware
rkhunter chkrootkit clamav aide

# Monitoring
audit sysstat

# Maintenance
unattended-upgrades (AUR)
```

## Post-Installation Checklist

After running `tresk harden`:

1. **Configure SSH key authentication**
   ```bash
   # On your local machine
   ssh-copy-id user@vps-ip
   # Then disable password auth in /etc/ssh/sshd_config
   sudo tresk harden --ssh-restart
   ```

2. **Review firewall rules**
   ```bash
   sudo ufw status verbose
   # Add custom ports if needed
   sudo ufw allow 8080/tcp
   ```

3. **Check fail2ban status**
   ```bash
   sudo fail2ban-client status sshd
   sudo fail2ban-client status
   ```

4. **Run first malware scan**
   ```bash
   sudo rkhunter --check
   sudo chkrootkit
   sudo freshclam && sudo clamscan -r /tmp
   ```

5. **Initialize AIDE database**
   ```bash
   sudo aideinit
   ```

6. **Test Telegram alerts**
   ```bash
   sudo tresk test-telegram
   ```

## Security Score

After hardening, check your security score:

```bash
sudo tresk harden --audit
```

This runs checks like:
- SSH configuration security
- Firewall enabled and configured
- All security tools installed and running
- No default passwords
- Critical services not exposed
- File permissions on sensitive files

## Comparison: Before vs After

| Aspect | Fresh VPS | After Tresk Harden |
|--------|-----------|-------------------|
| **Firewall** | ❌ Disabled | ✅ UFW enabled, deny all |
| **Brute Force** | ❌ No protection | ✅ Fail2ban active |
| **Rootkits** | ❌ No detection | ✅ Daily scans |
| **Antivirus** | ❌ None | ✅ ClamAV + definitions |
| **File Integrity** | ❌ None | ✅ AIDE monitoring |
| **Auto Updates** | ❌ Manual | ✅ Unattended upgrades |
| **System Auditing** | ❌ None | ✅ Auditd logging |
| **Tresk Monitoring** | ❌ None | ✅ 24/7 threat detection |

## Reverting Changes

If something breaks:

```bash
# Show what was installed
sudo tresk harden --installed

# Remove specific tool
sudo apt remove fail2ban  # or your package manager

# Full revert (use with caution)
sudo tresk harden --revert
```

## Best Practices

1. **Always test in staging first**
2. **Have console access** (not just SSH) when hardening
3. **Backup SSH config** before changes
4. **Add your IP to whitelist** before enabling fail2ban
5. **Review all config files** after installation

## Troubleshooting

### Can't SSH after hardening
```bash
# From console
sudo ufw disable  # Temporarily disable firewall
sudo nano /etc/ssh/sshd_config  # Fix SSH config
sudo systemctl restart sshd
sudo ufw enable
```

### Fail2ban banned your IP
```bash
# From console
sudo fail2ban-client set sshd unbanip YOUR_IP
```

### Too many alerts
```bash
# Adjust Tresk sensitivity
sudo nano /etc/tresk/config.conf
# Increase ALERT_COOLDOWN_* values
sudo systemctl restart tresk
```

## Integration with Tresk Monitor

Hardening tools work together with Tresk monitoring:

```
Fail2ban blocks IP → Tresk logs event → Telegram notification
Rkhunter finds rootkit → Tresk analyzes → Telegram alert with details
ClamAV detects virus → Tresk quarantines → Telegram notification
AIDE detects changes → Tresk verifies with AI → Alert if suspicious
```

## Future Enhancements

Planned features for `tresk harden`:

- [ ] CIS Benchmark compliance checking
- [ ] Automatic SSL certificate setup (Let's Encrypt)
- [ ] Docker security hardening
- [ ] Kubernetes security policies
- [ ] Database hardening (MySQL/PostgreSQL)
- [ ] Web server hardening (Nginx/Apache)
- [ ] Intrusion Detection System (IDS)
- [ ] VPN setup (WireGuard/OpenVPN)
