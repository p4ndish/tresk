# Quick Start Guide

Get Tresk running in 5 minutes.

## Installation

```bash
# Download and install
cd /tmp
git clone https://github.com/tresk/tresk.git
cd tresk
sudo ./install.sh
```

## Telegram Setup

### 1. Create Bot

1. Message [@BotFather](https://t.me/botfather)
2. Send `/newbot`
3. Follow prompts
4. **Save the token** (looks like: `123456789:ABCdef...`)

### 2. Get Chat ID

1. Message [@userinfobot](https://t.me/userinfobot)
2. Note your **Id** number

### 3. Configure

```bash
sudo nano /etc/tresk/config.conf
```

Update:
```bash
TELEGRAM_ENABLED="true"
TELEGRAM_BOT_TOKEN="your_token_here"
TELEGRAM_CHAT_ID="your_chat_id"
```

### 4. Test

```bash
sudo /opt/tresk/bin/monitor.sh test-telegram
```

You should receive a test message in Telegram.

## Basic Usage

### Start Monitoring

```bash
sudo systemctl start tresk
sudo systemctl enable tresk
```

### Check Status

```bash
systemctl status tresk
```

### View Logs

```bash
# Real-time logs
journalctl -u tresk -f

# Recent alerts
tail -f /var/log/tresk/alerts.log
```

### Manual Scans

```bash
# Quick scan
/opt/tresk/bin/monitor.sh quick

# Deep scan
/opt/tresk/bin/monitor.sh deep

# Full audit
/opt/tresk/bin/monitor.sh full
```

## Common Commands

| Command | Description |
|---------|-------------|
| `systemctl start tresk` | Start monitoring |
| `systemctl stop tresk` | Stop monitoring |
| `systemctl restart tresk` | Restart monitoring |
| `systemctl status tresk` | Check status |
| `monitor.sh quick` | Quick security scan |
| `monitor.sh deep` | Deep security scan |
| `monitor.sh test-telegram` | Test Telegram |

## Alert Levels

| Level | Emoji | Response Time | Example |
|-------|-------|---------------|---------|
| CRITICAL | 🚨 | Immediate | Cryptominer, Rootkit |
| HIGH | ⚠️ | 5 minutes | Reverse shell, Backdoor |
| MEDIUM | 🔶 | 15 minutes | Suspicious connection |
| LOW | ℹ️ | Hourly | Informational |

## First Alert Response

### If you receive a CRITICAL alert:

1. **Don't panic** - Read the full alert
2. **Verify** - Check if it's a false positive
3. **Assess** - Determine scope of compromise
4. **Act** - Follow incident response procedures
5. **Document** - Save evidence and actions taken

### Quick verification:

```bash
# Check the process mentioned in alert
ps -f -p <PID>

# Check network connections
ss -tanp | grep <PID>

# Check process details
cat /proc/<PID>/cmdline
ls -la /proc/<PID>/exe
```

## Configuration Tips

### Reduce False Positives

```bash
sudo nano /etc/tresk/config.conf

# Increase CPU threshold
CPU_THRESHOLD=95

# Add legitimate processes to whitelist
PROTECTED_PROCESSES="sshd|systemd|myapp"

# Disable low-priority alerts
ALERT_LOW="false"
```

### Enable Auto-Response (Use with Caution!)

```bash
# Only enable after testing
AUTO_RESPONSE_ENABLED="true"
AUTO_KILL_CRITICAL="true"
```

## Troubleshooting

### No Telegram messages

```bash
# Test connection
/opt/tresk/bin/monitor.sh test-telegram

# Check config
grep TELEGRAM /etc/tresk/config.conf

# Verify bot token
curl "https://api.telegram.org/bot<TOKEN>/getMe"
```

### Service won't start

```bash
# Check logs
journalctl -u tresk -n 50

# Check config syntax
bash -n /etc/tresk/config.conf

# Fix permissions
sudo chown -R root:root /opt/tresk
```

### High CPU usage

```bash
# Increase check intervals
sudo nano /etc/tresk/config.conf
PROCESS_CHECK_INTERVAL=10
NETWORK_CHECK_INTERVAL=30

# Restart service
sudo systemctl restart tresk
```

## Next Steps

1. [Read Full Documentation](README.md)
2. [Configure Auto-Response](INCIDENT_RESPONSE.md)
3. [Review Threat Signatures](../signatures/threat_signatures.json)
4. [Set Up Weekly Reports](TELEGRAM_SETUP.md)

## Support

- GitHub Issues: [github.com/tresk/issues](https://github.com/tresk/issues)
- Documentation: [docs.tresk.com](https://docs.tresk.com)

---

**Remember**: Security monitoring is just one layer of defense. Keep your system updated, use strong passwords, and follow security best practices!
