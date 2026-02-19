# 🔒 Tresk - VPS Security Monitor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/yourusername/tresk)
[![Platform](https://img.shields.io/badge/platform-Linux-green.svg)](https://github.com/yourusername/tresk)

**Tresk** is a production-grade Linux VPS security monitoring and alerting system. Named after "threat" + "risk" detection, it provides comprehensive threat detection with Telegram integration and systemd-based watchdog architecture.

> 🛡️ *From the Ge'ez word "tresk" - to guard, to watch over*

---

## ✨ Features

- 🔍 **Real-time Threat Detection** - Cryptominers, rootkits, backdoors, ransomware
- 📱 **Telegram Alerts** - Instant notifications for critical events
- 🤖 **Auto-Response** - Optional automatic threat mitigation
- 📊 **Scheduled Reports** - Daily summaries and weekly reports
- 🐳 **Container Support** - Works in Docker, WSL, and systemd-less systems
- 🔧 **Multi-OS Support** - Ubuntu, Debian, CentOS, RHEL, Alpine, Arch, and more

---

## 🚀 Quick Start

### One-Command Installation

```bash
# Using curl
curl -fsSL https://raw.githubusercontent.com/yourusername/tresk/main/bootstrap.sh | sudo bash

# Using wget
wget -qO- https://raw.githubusercontent.com/yourusername/tresk/main/bootstrap.sh | sudo bash
```

### Manual Installation

```bash
git clone https://github.com/yourusername/tresk.git
cd tresk
sudo ./install.sh
```

---

## 📋 Requirements

- Linux (kernel 3.10+)
- Root/sudo access
- 50 MB disk space
- 50 MB RAM

### Supported Operating Systems

| OS | Status |
|----|--------|
| Ubuntu 18.04+ | ✅ |
| Debian 9+ | ✅ |
| CentOS/RHEL 7+ | ✅ |
| Rocky/AlmaLinux 8+ | ✅ |
| Fedora 30+ | ✅ |
| Alpine Linux | ✅ (portable) |
| Arch/Manjaro | ✅ |
| openSUSE | ✅ |

---

## 🎯 Usage

### Manual Scans

```bash
# Quick scan (5 minutes)
sudo /opt/tresk/bin/monitor.sh quick

# Deep scan (comprehensive)
sudo /opt/tresk/bin/monitor.sh deep

# Full audit
sudo /opt/tresk/bin/monitor.sh full
```

### Service Management (systemd)

```bash
# Check status
sudo systemctl status tresk

# View logs
sudo journalctl -u tresk -f

# Start/Stop/Restart
sudo systemctl start tresk
sudo systemctl stop tresk
sudo systemctl restart tresk
```

### Telegram Commands

```bash
# Test connection
/opt/tresk/bin/monitor.sh test-telegram

# Send test alert
/opt/tresk/lib/telegram_notifier.py alert "Test message"
```

---

## 📁 Project Structure

```
tresk/
├── bin/
│   └── monitor.sh              # Main monitoring script
├── lib/
│   ├── telegram_notifier.py    # Telegram notifications
│   ├── process_analyzer.py     # Process analysis
│   └── package_manager.sh      # Package manager abstraction
├── config/
│   └── config.conf             # Configuration file
├── signatures/
│   └── threat_signatures.json  # IOC database
├── systemd/                    # Systemd service files
├── docs/                       # Documentation
├── install.sh                  # Main installer
├── install-portable.sh         # Portable installer
├── bootstrap.sh               # One-command installer
└── uninstall.sh               # Uninstaller
```

---

## 🔧 Configuration

Edit `/etc/tresk/config.conf`:

```bash
# Telegram Settings
TELEGRAM_ENABLED="true"
TELEGRAM_BOT_TOKEN="your_bot_token"
TELEGRAM_CHAT_ID="your_chat_id"

# Auto-Response
AUTO_KILL_CRITICAL="false"
PROTECTED_PROCESSES="sshd,cron,systemd"

# Monitoring Intervals
QUICK_SCAN_INTERVAL="300"
DEEP_SCAN_INTERVAL="3600"
```

---

## 📚 Documentation

- [Quick Start Guide](docs/QUICK_START.md)
- [Installation Guide](docs/INSTALLATION.md)
- [Telegram Setup](docs/TELEGRAM_SETUP.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Incident Response](docs/INCIDENT_RESPONSE.md)
- [Architecture](ARCHITECTURE.md)

---

## 🛡️ Security

- Runs as root for full system access
- No sensitive data in logs
- Telegram API uses HTTPS
- Configurable protected processes whitelist
- Alert cooldown prevents spam

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Name inspired by Ge'ez/Amharic word for "guard/watch"
- Built for the Linux VPS community

---

## 💬 Support

- 📧 Issues: [GitHub Issues](https://github.com/yourusername/tresk/issues)
- 📖 Docs: [Full Documentation](docs/)

---

<p align="center">
  <b>🔒 Tresk - Always Watching</b>
</p>
