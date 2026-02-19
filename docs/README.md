# Tresk

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/tresk)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)](https://github.com/tresk)

A production-grade Linux VPS security monitoring and alerting system with Telegram integration, systemd watchdog architecture, and comprehensive threat detection.

## Features

### Multi-Layer Threat Detection

- **Cryptominers**: XMRig, Kinsing, Kdevtmpfsi, and all variants
- **Rootkits**: LD_PRELOAD hijacking, kernel modules, hidden processes
- **Backdoors**: SUID binaries, reverse shells, web shells
- **Ransomware**: File encryption activity, suspicious extensions
- **Botnets/C2**: Suspicious network connections, beaconing
- **Container Escapes**: Docker socket abuse, privileged containers
- **SSH Attacks**: Brute force, unauthorized access
- **Persistence**: Cron jobs, systemd services, shell profiles
- **Fileless Malware**: Memory-only attacks, /dev/shm execution
- **Supply Chain**: Tampered binaries, malicious packages

### Notification System

- **Instant Alerts**: Critical threats within 5 seconds
- **Daily Summaries**: 24-hour statistics at 8 AM
- **Weekly Reports**: Security posture analysis
- **Emergency Broadcast**: System compromise alerts
- **Rich Formatting**: Markdown with emojis and code blocks

### Systemd Architecture

- **Main Service**: Continuous monitoring with auto-restart
- **Network Monitor**: Real-time network threat detection
- **Deep Scan Timer**: Scheduled comprehensive scans
- **Report Timers**: Automated daily/weekly reports
- **Resource Limits**: CPU <10%, RAM <100MB

## Quick Start

### One-Command Installation

```bash
curl -sSL https://raw.githubusercontent.com/tresk/main/install.sh | sudo bash
```

Or clone and install manually:

```bash
git clone https://github.com/tresk/tresk.git
cd tresk
sudo ./install.sh
```

### Telegram Setup

1. Create a bot with [@BotFather](https://t.me/botfather)
2. Get your chat ID using [@userinfobot](https://t.me/userinfobot)
3. Enter credentials during installation
4. Test with: `/opt/tresk/bin/monitor.sh test-telegram`

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Tresk                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Process    │  │   Network    │  │    File      │      │
│  │  Monitoring  │  │  Monitoring  │  │  Integrity   │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                 │                 │              │
│         └─────────────────┼─────────────────┘              │
│                           │                                │
│                    ┌──────┴──────┐                        │
│                    │  Detection  │                        │
│                    │   Engine    │                        │
│                    └──────┬──────┘                        │
│                           │                                │
│         ┌─────────────────┼─────────────────┐              │
│         │                 │                 │              │
│  ┌──────┴──────┐  ┌──────┴──────┐  ┌──────┴──────┐       │
│  │  Telegram   │  │   Systemd   │  │    JSON     │       │
│  │   Alerts    │  │   Journal   │  │    Logs     │       │
│  └─────────────┘  └─────────────┘  └─────────────┘       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Installation Options

### Standard Installation

```bash
sudo ./install.sh
```

### Without Telegram

```bash
sudo ./install.sh --no-telegram
```

### With Auto-Kill Enabled

```bash
sudo ./install.sh --auto-kill
```

### Uninstall

```bash
sudo ./install.sh --uninstall
```

## Configuration

Edit `/etc/tresk/config.conf`:

```bash
# Telegram Settings
TELEGRAM_ENABLED="true"
TELEGRAM_BOT_TOKEN="your_bot_token"
TELEGRAM_CHAT_ID="your_chat_id"

# Alert Levels
ALERT_CRITICAL="true"
ALERT_HIGH="true"
ALERT_MEDIUM="true"
ALERT_LOW="false"

# Auto-Response (USE WITH CAUTION)
AUTO_RESPONSE_ENABLED="false"
AUTO_KILL_CRITICAL="false"

# Monitoring Intervals
PROCESS_CHECK_INTERVAL=5
NETWORK_CHECK_INTERVAL=10
QUICK_SCAN_INTERVAL=3600
DEEP_SCAN_INTERVAL=86400
```

## Usage

### Manual Scans

```bash
# Quick scan (processes, network, users)
/opt/tresk/bin/monitor.sh quick

# Deep scan (rootkits, malware signatures)
/opt/tresk/bin/monitor.sh deep

# Full system audit
/opt/tresk/bin/monitor.sh full
```

### Service Management

```bash
# Start monitoring
systemctl start tresk

# Stop monitoring
systemctl stop tresk

# Check status
systemctl status tresk

# View logs
journalctl -u tresk -f
```

### Telegram Commands

```bash
# Test Telegram connection
/opt/tresk/bin/monitor.sh test-telegram

# Send daily summary manually
/opt/tresk/lib/telegram_notifier.py summary

# Send weekly report manually
/opt/tresk/lib/telegram_notifier.py weekly
```

## Threat Detection Coverage

### Cryptocurrency Miners

| Indicator | Detection Method |
|-----------|------------------|
| Known binaries | Process name matching |
| High CPU usage | CPU threshold monitoring |
| Mining pools | Network connection analysis |
| Deleted executables | /proc/PID/exe monitoring |
| Fileless miners | /dev/shm executable detection |

### Rootkits

| Type | Detection Method |
|------|------------------|
| LD_PRELOAD | /etc/ld.so.preload monitoring |
| Kernel modules | Module list comparison |
| Hidden processes | ps vs /proc comparison |
| Reptile/Diamorphine | Specific file indicators |

### Backdoors

| Type | Detection Method |
|------|------------------|
| SUID binaries | Permission scanning |
| Reverse shells | Command pattern matching |
| Web shells | PHP/code signature detection |
| SSH keys | authorized_keys monitoring |

### Network Threats

| Type | Detection Method |
|------|------------------|
| C2 connections | Port and domain analysis |
| DNS tunneling | Query volume monitoring |
| IRC botnets | Port 6667 detection |
| Malicious IPs | Blocklist comparison |

## Systemd Services

| Service | Description | Schedule |
|---------|-------------|----------|
| `tresk` | Main monitoring service | Always on |
| `vps-security-deep-scan` | Comprehensive scan | Daily |
| `vps-security-summary` | Daily report | 8:00 AM |
| `vps-security-weekly` | Weekly report | Sunday 9:00 AM |

## Performance

- **CPU Overhead**: <5% average, <10% peak
- **Memory Usage**: <100MB
- **Disk Usage**: ~50MB installation, rotating logs
- **Network**: Minimal (Telegram API calls only)

## Supported Platforms

| OS | Version | Status |
|----|---------|--------|
| Ubuntu | 20.04, 22.04, 24.04 | ✅ Supported |
| Debian | 11, 12 | ✅ Supported |
| CentOS | 8, 9 | ✅ Supported |
| RHEL | 8, 9 | ✅ Supported |
| Rocky Linux | 8, 9 | ✅ Supported |
| AlmaLinux | 8, 9 | ✅ Supported |
| Fedora | 38+ | ✅ Supported |
| Alpine | 3.16+ | ⚠️ Limited |
| Arch | Latest | ⚠️ Limited |

## Telegram Alert Examples

### Critical Alert

```
🚨 *CRITICAL: Cryptominer Detected*

*Host:* `web-server-01 (203.0.113.10)`
*Time:* `2025-02-20 14:32:05 UTC`

*Details:*
```
Process: /tmp/xmrig --url pool.minexmr.com:443
PID: 12345
CPU: 95%
Runtime: 3600s
```

*Recommended Actions:*
```
1. Kill process: kill -9 12345
2. Check persistence: crontab -l
3. Review user access
4. Scan for additional malware
```
```

### Daily Summary

```
📊 *Daily Security Summary*

*Host:* `web-server-01 (203.0.113.10)`
*Report Time:* `2025-02-20 08:00:00 UTC`

*System Status:*
├─ Load Average: `0.52, 0.48, 0.45`
├─ CPU Usage: `23.5%`
├─ Memory Usage: `45.2%`
├─ Disk Usage: `67%`
└─ Active Users: `2`

*Security Metrics:*
├─ Failed SSH Attempts: `15`
├─ Active Connections: `234`
├─ Total Processes: `142`
├─ Docker Containers: `5`
├─ Critical Alerts: `0`
└─ High Alerts: `1`
```

## Troubleshooting

### Telegram Not Working

```bash
# Test connection
/opt/tresk/bin/monitor.sh test-telegram

# Check configuration
cat /etc/tresk/config.conf | grep TELEGRAM

# Verify bot token
curl -s "https://api.telegram.org/bot<TOKEN>/getMe"
```

### High CPU Usage

```bash
# Check monitoring process
ps aux | grep monitor.sh

# Adjust CPU limit in config
sed -i 's/CPU_LIMIT=.*/CPU_LIMIT=5/' /etc/tresk/config.conf

# Restart service
systemctl restart tresk
```

### False Positives

```bash
# Add to whitelist
echo "my_legitimate_process" >> /etc/tresk/whitelist.txt

# Adjust thresholds
sed -i 's/CPU_THRESHOLD=.*/CPU_THRESHOLD=95/' /etc/tresk/config.conf
```

## Security Considerations

### Auto-Response (Kill Switch)

⚠️ **Use with extreme caution!**

```bash
# Enable in config
AUTO_RESPONSE_ENABLED="true"
AUTO_KILL_CRITICAL="true"

# Protected processes (never kill)
PROTECTED_PROCESSES="sshd|systemd|dbus|network|cron|rsyslog"
```

### Network Security

- All Telegram API calls use HTTPS
- No sensitive data in logs
- Configurable log rotation
- IP whitelisting supported

### File Permissions

```bash
# Monitor should run as root for full access
# Configuration files: 640
# Log files: 640
# Scripts: 755
```

## Incident Response Playbook

### Cryptominer Detected

1. **Isolate** (if critical)
   ```bash
   iptables -A OUTPUT -p tcp --dport 443 -j DROP
   ```

2. **Kill Process**
   ```bash
   kill -9 <PID>
   ```

3. **Check Persistence**
   ```bash
   crontab -l
   ls -la /etc/cron.*
   systemctl list-timers
   ```

4. **Investigate**
   ```bash
   cat /proc/<PID>/cmdline
   ls -la /proc/<PID>/fd
   strings /proc/<PID>/exe | head -50
   ```

5. **Clean Up**
   ```bash
   find /tmp /var/tmp -type f -executable -delete
   rkhunter --check
   chkrootkit
   ```

### Rootkit Detected

⚠️ **System may be fully compromised**

1. **Do NOT trust the system**
2. **Take memory dump** (if possible)
3. **Boot from live CD/USB**
4. **Scan from clean system**
5. **Consider complete rebuild**

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file

## Support

- GitHub Issues: [github.com/tresk/issues](https://github.com/tresk/issues)
- Documentation: [docs.tresk.com](https://docs.tresk.com)
- Telegram: [@vps_security_monitor](https://t.me/vps_security_monitor)

## Acknowledgments

- Threat signatures from [MITRE ATT&CK](https://attack.mitre.org/)
- IOCs from [ abuse.ch](https://abuse.ch/)
- Community contributions

---

**Disclaimer**: This tool is for defensive security purposes only. Always ensure you have proper authorization before deploying security monitoring tools.
