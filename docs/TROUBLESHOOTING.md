# Troubleshooting Guide

Common issues and solutions for Tresk.

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Service Issues](#service-issues)
3. [Telegram Issues](#telegram-issues)
4. [Performance Issues](#performance-issues)
5. [False Positives](#false-positives)
6. [Detection Issues](#detection-issues)

---

## Installation Issues

### "Command not found" during installation

**Problem**: Script fails with command not found errors.

**Solution**:
```bash
# Ensure script is executable
chmod +x install.sh

# Run with bash explicitly
sudo bash install.sh
```

### Package installation fails

**Problem**: Dependencies fail to install.

**Solution**:
```bash
# Update package lists
sudo apt-get update  # Debian/Ubuntu
sudo yum update      # CentOS/RHEL

# Install manually
sudo apt-get install -y curl jq net-tools lsof psmisc procps rkhunter chkrootkit

# Then run installer
sudo ./install.sh
```

### "Permission denied"

**Problem**: Cannot write to directories.

**Solution**:
```bash
# Check you're root
whoami  # Should show 'root'

# Or use sudo
sudo -i
./install.sh
```

---

## Service Issues

### Service fails to start

**Problem**: `systemctl start tresk` fails.

**Diagnosis**:
```bash
# Check status
systemctl status tresk

# View logs
journalctl -u tresk -n 50

# Check for errors
/opt/tresk/bin/monitor.sh quick 2>&1
```

**Common Solutions**:

1. **Missing dependencies**:
   ```bash
   sudo apt-get install -y jq curl
   ```

2. **Configuration errors**:
   ```bash
   # Validate config
   bash -n /etc/tresk/config.conf
   
   # Check syntax
   grep -E '^[A-Z_]+=' /etc/tresk/config.conf | head -20
   ```

3. **Permission issues**:
   ```bash
   # Fix permissions
   chown -R root:root /opt/tresk
   chmod -R 755 /opt/tresk/bin
   ```

### Service keeps restarting

**Problem**: Service enters restart loop.

**Diagnosis**:
```bash
# Check restart count
systemctl show tresk --property=NRestarts

# View recent logs
journalctl -u tresk --since "5 minutes ago"
```

**Solutions**:

1. **Check for crashes**:
   ```bash
   # Run manually to see errors
   sudo /opt/tresk/bin/monitor.sh monitor
   ```

2. **Increase restart delay**:
   ```bash
   sudo systemctl edit tresk
   ```
   Add:
   ```ini
   [Service]
   RestartSec=30
   ```

3. **Check resource limits**:
   ```bash
   # Edit service file
   sudo nano /etc/systemd/system/tresk.service
   
   # Increase limits
   CPUQuota=20%
   MemoryLimit=200M
   ```

### Service stops unexpectedly

**Problem**: Service stops without error.

**Diagnosis**:
```bash
# Check for OOM kills
dmesg | grep -i "killed process"

# Check memory usage
free -h

# Check systemd logs
journalctl -u tresk --since "1 hour ago"
```

**Solutions**:

1. **Increase memory limit**:
   ```bash
   sudo systemctl edit tresk
   ```
   Add:
   ```ini
   [Service]
   MemoryLimit=200M
   ```

2. **Reduce monitoring intensity**:
   ```bash
   # Edit config
   sudo nano /etc/tresk/config.conf
   
   # Increase intervals
   PROCESS_CHECK_INTERVAL=10
   NETWORK_CHECK_INTERVAL=30
   ```

---

## Telegram Issues

### Test message fails

**Problem**: `monitor.sh test-telegram` fails.

**Diagnosis**:
```bash
# Check configuration
grep TELEGRAM /etc/tresk/config.conf

# Test API directly
curl -s "https://api.telegram.org/bot<TOKEN>/getMe"

# Check chat ID
curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates"
```

**Solutions**:

1. **Invalid token**:
   - Get new token from @BotFather
   - Update config: `TELEGRAM_BOT_TOKEN="new_token"`

2. **Wrong chat ID**:
   - Use @userinfobot to get correct ID
   - For groups, ID is negative (e.g., `-123456789`)

3. **Bot blocked**:
   - Unblock bot in Telegram
   - Send `/start` to bot

### Messages not received

**Problem**: No Telegram messages despite test working.

**Diagnosis**:
```bash
# Check if alerts are enabled
grep ALERT /etc/tresk/config.conf

# Check log for send attempts
tail -f /var/log/tresk/monitor.log | grep -i telegram
```

**Solutions**:

1. **Check alert levels**:
   ```bash
   # Enable all alerts for testing
   sed -i 's/ALERT_CRITICAL="false"/ALERT_CRITICAL="true"/' /etc/tresk/config.conf
   sed -i 's/ALERT_HIGH="false"/ALERT_HIGH="true"/' /etc/tresk/config.conf
   ```

2. **Check cooldown**:
   ```bash
   # Clear alert state
   rm -f /opt/tresk/.alert_state/*
   ```

3. **Test manually**:
   ```bash
   /opt/tresk/lib/telegram_notifier.py alert \
     --severity HIGH \
     --title "Test" \
     --details "Testing" \
     --recommendation "None"
   ```

### Rate limiting

**Problem**: "Too Many Requests" errors.

**Solution**:
```bash
# Increase cooldown periods
sudo nano /etc/tresk/config.conf

ALERT_COOLDOWN_HIGH=300      # 5 minutes
ALERT_COOLDOWN_MEDIUM=600    # 10 minutes
```

---

## Performance Issues

### High CPU usage

**Problem**: Monitor using too much CPU.

**Diagnosis**:
```bash
# Check monitor CPU usage
top -p $(pgrep -f monitor.sh)

# Check specific processes
ps aux | grep monitor
```

**Solutions**:

1. **Increase check intervals**:
   ```bash
   sudo nano /etc/tresk/config.conf
   
   PROCESS_CHECK_INTERVAL=10    # Was 5
   NETWORK_CHECK_INTERVAL=30    # Was 10
   QUICK_SCAN_INTERVAL=7200     # Was 3600
   ```

2. **Reduce scan intensity**:
   ```bash
   # Disable some checks
   DETECT_HIDDEN_PROCESSES="false"
   DNS_MONITORING="false"
   ```

3. **Add CPU limit**:
   ```bash
   sudo systemctl edit tresk
   ```
   Add:
   ```ini
   [Service]
   CPUQuota=5%
   ```

### High memory usage

**Problem**: Monitor using too much RAM.

**Diagnosis**:
```bash
# Check memory usage
ps aux | grep monitor.sh

# Check system memory
free -h
```

**Solutions**:

1. **Reduce memory limit**:
   ```bash
   sudo systemctl edit tresk
   ```
   Add:
   ```ini
   [Service]
   MemoryLimit=50M
   ```

2. **Clear caches**:
   ```bash
   # Clear alert state cache
   rm -f /opt/tresk/.alert_state/*
   
   # Clear old logs
   find /var/log/tresk -name "*.log" -mtime +7 -delete
   ```

### Disk space issues

**Problem**: Logs filling up disk.

**Solution**:
```bash
# Check log size
du -sh /var/log/tresk/

# Manual cleanup
find /var/log/tresk -name "*.log" -mtime +7 -delete

# Adjust log retention
sudo nano /etc/tresk/config.conf
LOG_RETENTION_DAYS=7
```

---

## False Positives

### Legitimate process flagged

**Problem**: Normal process detected as threat.

**Solution**:

1. **Add to whitelist**:
   ```bash
   # Edit config
   sudo nano /etc/tresk/config.conf
   
   # Add to protected processes
   PROTECTED_PROCESSES="sshd|systemd|myapp|anotherapp"
   ```

2. **Adjust thresholds**:
   ```bash
   # Increase CPU threshold
   CPU_THRESHOLD=95
   
   # Increase duration threshold
   CPU_DURATION_THRESHOLD=600
   ```

### File integrity false alarms

**Problem**: Legitimate file changes trigger alerts.

**Solution**:
```bash
# Update baseline
sudo rm -rf /opt/tresk/.baseline/*
sudo /opt/tresk/bin/monitor.sh quick

# Or exclude specific files
# Edit config and remove file from CRITICAL_FILES
```

### Network connection alerts

**Problem**: Legitimate connections flagged.

**Solution**:
```bash
# Add IP to whitelist
sudo nano /etc/tresk/config.conf

IP_WHITELIST="127.0.0.1|::1|10.0.0.0/8|192.168.1.0/24"
```

---

## Detection Issues

### Miner not detected

**Problem**: Cryptominer running but not detected.

**Diagnosis**:
```bash
# Check process list
ps aux | grep -i xmrig

# Check for deleted processes
ls -la /proc/*/exe 2>/dev/null | grep deleted

# Check CPU usage
top -bn1 | head -20
```

**Solutions**:

1. **Update signatures**:
   ```bash
   # Add new miner pattern
   sudo nano /opt/tresk/signatures/threat_signatures.json
   ```

2. **Lower thresholds**:
   ```bash
   CPU_THRESHOLD=70
   CPU_DURATION_THRESHOLD=180
   ```

3. **Manual scan**:
   ```bash
   sudo /opt/tresk/bin/monitor.sh deep
   ```

### Rootkit not detected

**Problem**: Suspected rootkit not found.

**Diagnosis**:
```bash
# Check for LD_PRELOAD
cat /etc/ld.so.preload

# Check for hidden processes
ps aux | wc -l
ls /proc/ | grep -E '^[0-9]+$' | wc -l

# Run external tools
sudo rkhunter --check
sudo chkrootkit
```

**Solutions**:

1. **Run full audit**:
   ```bash
   sudo /opt/tresk/bin/monitor.sh full
   ```

2. **Check kernel modules**:
   ```bash
   lsmod | grep -v "^Module"
   ls /sys/module/ | wc -l
   ```

3. **Memory analysis**:
   ```bash
   # If possible, take memory dump
   # Analyze with volatility
   ```

### SSH attacks not detected

**Problem**: Brute force not detected.

**Diagnosis**:
```bash
# Check auth.log exists
ls -la /var/log/auth.log

# Check for failed attempts
grep "Failed password" /var/log/auth.log | tail -10

# Check log format
head -5 /var/log/auth.log
```

**Solutions**:

1. **Adjust threshold**:
   ```bash
   BRUTE_FORCE_THRESHOLD=3
   BRUTE_FORCE_WINDOW=300
   ```

2. **Check log path**:
   ```bash
   # For systems with different log locations
   # Edit monitor.sh to use correct path
   ```

3. **Use fail2ban**:
   ```bash
   sudo apt-get install fail2ban
   sudo systemctl enable fail2ban
   ```

---

## Getting Help

### Collect diagnostic information

```bash
#!/bin/bash
# Run this and share output

echo "=== System Info ==="
uname -a
cat /etc/os-release | head -5

echo "=== Service Status ==="
systemctl status tresk --no-pager

echo "=== Recent Logs ==="
journalctl -u tresk --since "1 hour ago" --no-pager

echo "=== Config ==="
grep -v "^#" /etc/tresk/config.conf | grep -v "^$"

echo "=== Processes ==="
ps aux | grep monitor

echo "=== Resources ==="
free -h
df -h /var/log
```

### Report an issue

1. Collect diagnostic info (above)
2. Check existing issues on GitHub
3. Create new issue with:
   - OS version
   - Tresk version
   - Description of problem
   - Steps to reproduce
   - Diagnostic output

---

## Quick Fixes

### Reset everything

```bash
# Stop services
sudo systemctl stop tresk

# Clear state
sudo rm -rf /opt/tresk/.alert_state/*
sudo rm -rf /opt/tresk/.baseline/*

# Clear logs
sudo rm -f /var/log/tresk/*.log

# Restart
sudo systemctl start tresk
```

### Reinstall

```bash
# Uninstall
sudo /opt/tresk/uninstall.sh

# Reinstall
sudo ./install.sh
```

### Emergency stop

```bash
# Stop all monitoring
sudo systemctl stop tresk
sudo systemctl disable tresk
sudo systemctl stop vps-security-deep-scan.timer
sudo systemctl stop vps-security-summary.timer
sudo systemctl stop vps-security-weekly.timer
```
