# Tresk - Agent Guide

## Project Overview

Tresk is a production-grade Linux VPS security monitoring and alerting system written in Bash and Python 3. It provides comprehensive threat detection with Telegram integration and systemd-based watchdog architecture.

**Name**: Tresk (from Ge'ez "tresk" - to guard/watch)  
**Version**: 1.0.0  
**License**: MIT  
**Primary Language**: English (all documentation and code comments)

## Technology Stack

| Component | Technology |
|-----------|------------|
| Main Monitor | Bash 4.0+ |
| Notification Module | Python 3.6+ |
| Process Analysis | Python 3.6+ |
| Service Management | systemd |
| Data Format | JSON (signatures), shell config |
| API Integration | Telegram Bot API (HTTPS) |

### Dependencies

**System Packages**: `curl`, `jq`, `bc`, `net-tools`, `lsof`, `psmisc`, `procps`, `rkhunter`, `chkrootkit`, `aide`, `auditd`

**Python Packages**: `requests` (installed via pip3)

## Project Structure

```
tresk/
├── bin/
│   └── monitor.sh                    # Main monitoring script (1400+ lines)
├── lib/
│   ├── telegram_notifier.py          # Telegram notification module
│   └── process_analyzer.py           # Advanced process analysis
├── config/
│   └── config.conf                   # Configuration template
├── signatures/
│   └── threat_signatures.json        # IOC database (JSON)
├── systemd/
│   ├── tresk.service  # Main service
│   ├── tresk-network.service  # Network monitoring service
│   ├── tresk-deep-scan.service + .timer  # Daily deep scan
│   ├── tresk-summary.service + .timer    # Daily summary @ 08:00
│   └── tresk-weekly.service + .timer     # Weekly report @ Sunday 09:00
├── docs/
│   ├── README.md                     # Main documentation
│   ├── QUICK_START.md                # 5-minute setup guide
│   ├── TELEGRAM_SETUP.md             # Telegram configuration
│   ├── TROUBLESHOOTING.md            # Common issues
│   ├── INCIDENT_RESPONSE.md          # IR playbooks
│   └── ARCHITECTURE.md               # Technical architecture
├── install.sh                        # Installation script
└── uninstall.sh                      # Uninstallation script
```

## Installation and Build

### One-Command Installation (Remote)

```bash
# Using curl
curl -fsSL https://raw.githubusercontent.com/yourusername/vps-security-monitor/main/bootstrap.sh | sudo bash

# Using wget
wget -qO- https://raw.githubusercontent.com/yourusername/vps-security-monitor/main/bootstrap.sh | sudo bash
```

### Local Installation Commands

```bash
# Full installation (interactive)
sudo ./install.sh

# Without Telegram setup
sudo ./install.sh --no-telegram

# With auto-kill enabled
sudo ./install.sh --auto-kill

# Portable mode (no systemd, uses cron)
sudo ./install.sh --portable

# Uninstall
sudo ./install.sh --uninstall
# OR
sudo ./uninstall.sh
```

### Supported Operating Systems

- **Debian/Ubuntu**: apt-based installation
- **CentOS/RHEL/Rocky/AlmaLinux**: yum/dnf-based installation
- **Fedora**: dnf-based installation
- **Alpine Linux**: apk-based installation (portable mode recommended)
- **Arch Linux/Manjaro**: pacman-based installation
- **openSUSE**: zypper-based installation
- **Void Linux**: xbps-based installation (portable mode)
- **Docker/WSL**: Portable mode (cron-based)

### Installation Paths

| Path | Purpose |
|------|---------|
| `/opt/tresk` | Installation directory |
| `/etc/tresk/config.conf` | Runtime configuration |
| `/var/log/tresk` | Log files |
| `/etc/systemd/system/vps-security-*.service` | Systemd services |
| `/etc/systemd/system/vps-security-*.timer` | Systemd timers |

### Service Management

```bash
# Start/stop/restart
sudo systemctl start vps-security-monitor
sudo systemctl stop vps-security-monitor
sudo systemctl restart vps-security-monitor

# View status and logs
systemctl status vps-security-monitor
journalctl -u vps-security-monitor -f

# Enable/disable on boot
sudo systemctl enable vps-security-monitor
sudo systemctl disable vps-security-monitor
```

## Code Organization

### Main Script (`bin/monitor.sh`)

**Structure**:
1. Metadata and constants (SCRIPT_VERSION, paths)
2. Logging functions (`log_init`, `log`)
3. Utility functions (`check_root`, `load_config`, `load_signatures`)
4. Detection modules (one function per threat type):
   - `detect_cryptominers()`
   - `detect_rootkits()`
   - `detect_backdoors()`
   - `detect_ransomware()`
   - `detect_container_escapes()`
   - `detect_network_threats()`
   - `detect_ssh_attacks()`
   - `detect_persistence()`
   - `detect_file_integrity()`
   - `detect_cloud_metadata_abuse()`
   - `detect_redis_exploitation()`
   - `detect_docker_api_abuse()`
5. Alert functions (`send_alert`, `send_daily_summary`, `send_weekly_report`)
6. Main execution functions (`run_quick_scan`, `run_deep_scan`, `run_full_audit`, `start_monitoring`)
7. CLI parsing (`main()`)

### Python Modules

**`lib/telegram_notifier.py`**:
- `TelegramNotifier` class handles all Telegram communication
- Methods: `send_alert()`, `send_daily_summary()`, `send_weekly_report()`, `test_connection()`
- CLI interface via `argparse` with commands: `alert`, `summary`, `weekly`, `test`

**`lib/process_analyzer.py`**:
- `ProcessInfo` dataclass for process data
- `ProcessAnalyzer` class for process analysis
- Methods: `scan_all_processes()`, `detect_cryptominers()`, `detect_reverse_shells()`, `detect_suspicious_processes()`, `generate_report()`
- CLI interface with `--scan`, `--pid`, `--report`, `--json` options

## Configuration System

Configuration is stored in `/etc/tresk/config.conf` as a shell-sourced file:

```bash
# Key sections:
# - GENERAL SETTINGS (LOG_LEVEL, LOG_DIR, etc.)
# - TELEGRAM SETTINGS (TELEGRAM_ENABLED, TELEGRAM_BOT_TOKEN, etc.)
# - AUTO-RESPONSE SETTINGS (AUTO_KILL_CRITICAL, PROTECTED_PROCESSES)
# - MONITORING SETTINGS (intervals, thresholds)
# - FILE INTEGRITY MONITORING (CRITICAL_FILES array)
# - PROCESS MONITORING (SUSPICIOUS_PATTERNS array)
# - NETWORK MONITORING (BLOCKLIST_URLS array)
# - CONTAINER SECURITY (DOCKER_SOCKET, etc.)
# - SSH SECURITY (BRUTE_FORCE_THRESHOLD)
# - EXTERNAL TOOLS INTEGRATION (RKHUNTER_ENABLED, etc.)
# - PERFORMANCE SETTINGS (CPU_LIMIT, MEMORY_LIMIT)
```

## Testing and Debugging

### Manual Testing Commands

```bash
# Test Telegram connectivity
/opt/tresk/bin/monitor.sh test-telegram

# Run scans manually
/opt/tresk/bin/monitor.sh quick   # Quick scan
/opt/tresk/bin/monitor.sh deep    # Deep scan
/opt/tresk/bin/monitor.sh full    # Full audit

# Python module tests
/opt/tresk/lib/telegram_notifier.py test
/opt/tresk/lib/process_analyzer.py --scan
/opt/tresk/lib/process_analyzer.py --report --json
```

### Debug Mode

```bash
# Run with debug output
/opt/tresk/bin/monitor.sh -d quick

# Dry run (detect but don't alert)
/opt/tresk/bin/monitor.sh --dry-run quick
```

### Log Files

| Log File | Purpose |
|----------|---------|
| `/var/log/tresk/monitor.log` | Main application log |
| `/var/log/tresk/alerts.log` | Alert history |
| `/var/log/tresk/events.json` | Structured JSON logs |
| `/var/log/tresk/rkhunter.log` | RKHunter output |
| `/var/log/tresk/chkrootkit.log` | Chkrootkit output |

View logs: `journalctl -u vps-security-monitor -f` or `tail -f /var/log/tresk/monitor.log`

## Code Style Guidelines

### Bash Style

1. **Shebang**: `#!/bin/bash`
2. **Strict mode**: `set -o pipefail`, `set -o nounset` (where applicable)
3. **Readonly constants**: `readonly SCRIPT_VERSION="1.0.0"`
4. **Function comments**: Use `# ===` style headers
5. **Logging**: Use the `log()` function with levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
6. **Color codes**: Use defined constants (`$RED`, `$GREEN`, `$YELLOW`, `$BLUE`, `$NC`)
7. **Root check**: All scripts call `check_root()` before operations requiring root

### Python Style

1. **Shebang**: `#!/usr/bin/env python3`
2. **Docstrings**: Module and class docstrings required
3. **Type hints**: Use `typing` module (Dict, List, Optional, Any)
4. **Class structure**: Follow `TelegramNotifier` and `ProcessAnalyzer` patterns
5. **Error handling**: Use try/except with specific exceptions
6. **Configuration loading**: Parse shell-style config files manually

### File Headers

All source files must include:
```bash
#!/bin/bash
################################################################################
# VPS Security Monitor - <Component Name>
# Version: 1.0.0
# Description: <Brief description>
# Author: VPS Security Monitor
# License: MIT
################################################################################
```

## Security Considerations

### Privilege Requirements
- Monitor runs as **root** for full system access
- Required for: /proc access, network inspection, file integrity checks

### Auto-Response Risks
- `AUTO_KILL_CRITICAL` can terminate legitimate processes
- `PROTECTED_PROCESSES` whitelist prevents killing system services
- IP whitelist prevents blocking localhost (`127.0.0.1`, `::1`)

### Data Protection
- Telegram API uses HTTPS encryption
- No sensitive data in logs (passwords, keys redacted)
- Config files should have restricted permissions (640)
- Alert state stored in `/opt/tresk/.alert_state/`

### File Permissions
- Configuration: 640 (root:root)
- Scripts: 755 (root:root)
- Log files: 640 (root:root)

## Threat Detection Categories

| Category | Severity | Key Detection Methods |
|----------|----------|----------------------|
| Cryptominers | CRITICAL | Process names, CPU usage, deleted executables |
| Rootkits | CRITICAL | LD_PRELOAD, kernel modules, hidden processes |
| Backdoors | CRITICAL | SUID binaries, reverse shells, web shells |
| Ransomware | CRITICAL | File extensions, ransom notes, mass modifications |
| Container Escapes | CRITICAL | Docker socket access, privileged mode |
| C2/Botnets | HIGH | Suspicious ports, IRC connections, beaconing |
| SSH Attacks | HIGH | Auth log analysis, brute force detection |
| Persistence | HIGH | Cron jobs, systemd services, shell profiles |

## Alert System

### Severity Levels

| Level | Emoji | Cooldown | Description |
|-------|-------|----------|-------------|
| CRITICAL | 🚨 | 0 sec | Immediate response required |
| HIGH | ⚠️ | 60 sec | Urgent attention needed |
| MEDIUM | 🔶 | 300 sec | Should be investigated |
| LOW | ℹ️ | 3600 sec | Informational |

### Alert Cooldown
- Implemented via state files in `.alert_state/`
- Key = SHA256 hash of alert title
- Prevents spam by tracking last alert time

## Development Workflow

### Adding New Detection

1. Add detection function in `bin/monitor.sh`
2. Add signature patterns to `signatures/threat_signatures.json` if applicable
3. Add configuration options to `config/config.conf`
4. Update documentation in `docs/`
5. Test with `monitor.sh --dry-run`

### Adding New Signatures

Edit `signatures/threat_signatures.json`:
```json
{
  "category_name": {
    "description": "...",
    "severity": "critical|high|medium|low",
    "indicators": ["..."]
  }
}
```

### Testing Changes

```bash
# Validate bash syntax
bash -n bin/monitor.sh

# Validate JSON
jq . signatures/threat_signatures.json

# Test locally
sudo ./bin/monitor.sh quick
```

## Common Tasks

### Update Threat Signatures
```bash
curl -o /opt/tresk/signatures/threat_signatures.json \
  https://raw.githubusercontent.com/vps-security-monitor/main/signatures/threat_signatures.json
```

### Reset Alert State
```bash
rm -f /opt/tresk/.alert_state/*
```

### Update File Integrity Baseline
```bash
rm -rf /opt/tresk/.baseline/*
sudo /opt/tresk/bin/monitor.sh quick
```

### Manual Log Rotation
```bash
find /var/log/tresk -name "*.log" -mtime +7 -delete
```

## External Tool Integration

The monitor integrates with these external security tools (optional):
- **RKHunter** - Rootkit detection
- **Chkrootkit** - Rootkit detection
- **AIDE** - File integrity monitoring
- **Auditd** - System call auditing
- **ClamAV** - Antivirus scanning
- **Lynis** - Security auditing

Enable/disable via configuration: `RKHUNTER_ENABLED`, `CHKROOTKIT_ENABLED`, etc.

## Resources

- **Main Documentation**: `docs/README.md`
- **Quick Start**: `docs/QUICK_START.md`
- **Troubleshooting**: `docs/TROUBLESHOOTING.md`
- **Architecture**: `ARCHITECTURE.md`
- **Project Summary**: `PROJECT_SUMMARY.md`
