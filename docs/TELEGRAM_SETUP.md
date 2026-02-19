# Telegram Bot Setup Guide

This guide will walk you through setting up Telegram notifications for Tresk.

## Table of Contents

1. [Create a Bot](#1-create-a-bot)
2. [Get Your Chat ID](#2-get-your-chat-id)
3. [Configure Tresk](#3-configure-tresk)
4. [Test Your Setup](#4-test-your-setup)
5. [Advanced Configuration](#5-advanced-configuration)

---

## 1. Create a Bot

### Using BotFather

1. Open Telegram and search for **@BotFather**
2. Start a chat and send `/newbot`
3. Follow the prompts:
   - Enter a name for your bot (e.g., "My VPS Monitor")
   - Enter a username (must end in `bot`, e.g., `myvpsmonitorbot`)

4. BotFather will respond with your **HTTP API token**:
   ```
   Use this token to access the HTTP API:
   123456789:ABCdefGHIjklMNOpqrSTUvwxyz
   ```

5. **Save this token** - you'll need it for configuration

### Bot Commands (Optional)

You can add commands to your bot for easier interaction:

```
/setcommands
```

Then enter:
```
status - Get system status
alerts - Show recent alerts
summary - Get daily summary
help - Show help
```

---

## 2. Get Your Chat ID

### Method 1: Using @userinfobot

1. Search for **@userinfobot** in Telegram
2. Start the bot
3. It will reply with your user information:
   ```
   @p4ndish
   Id: 123456789
   First: Your
   Last: Name
   ```
4. Save the **Id** number

### Method 2: Using the Bot API

1. Send a message to your new bot
2. Visit this URL in your browser:
   ```
   https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
   ```
3. Look for the `chat` object:
   ```json
   {
     "message": {
       "chat": {
         "id": 123456789,
         "type": "private"
       }
     }
   }
   ```
4. The `id` field is your chat ID

### Method 3: For Group Chats

1. Add your bot to a group
2. Send a message in the group
3. Check the API response:
   ```
   https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
   ```
4. Look for negative chat ID:
   ```json
   {
     "message": {
       "chat": {
         "id": -1234567890123,
         "type": "group"
       }
     }
   }
   ```

---

## 3. Configure Tresk

### During Installation

The installer will prompt you for:
- Bot Token
- Chat ID

### Manual Configuration

Edit the configuration file:

```bash
sudo nano /etc/tresk/config.conf
```

Update these settings:

```bash
# Enable Telegram
TELEGRAM_ENABLED="true"

# Your bot token from BotFather
TELEGRAM_BOT_TOKEN="123456789:ABCdefGHIjklMNOpqrSTUvwxyz"

# Your chat ID
TELEGRAM_CHAT_ID="123456789"

# Optional: Forum topic ID for group chats
TELEGRAM_THREAD_ID=""
```

Save and exit (Ctrl+X, Y, Enter)

---

## 4. Test Your Setup

### Test Command

```bash
sudo /opt/tresk/bin/monitor.sh test-telegram
```

You should receive a message like:
```
🧪 Test message from Tresk on my-vps
```

### Manual Test with Python

```bash
sudo /opt/tresk/lib/telegram_notifier.py test
```

### Test Alert

```bash
sudo /opt/tresk/lib/telegram_notifier.py alert \
  --severity HIGH \
  --title "Test Alert" \
  --details "This is a test alert from Tresk" \
  --recommendation "No action needed"
```

---

## 5. Advanced Configuration

### Alert Levels

Configure which severity levels send notifications:

```bash
# Critical alerts (always recommended)
ALERT_CRITICAL="true"

# High severity alerts
ALERT_HIGH="true"

# Medium severity alerts
ALERT_MEDIUM="true"

# Low severity alerts (may be noisy)
ALERT_LOW="false"
```

### Rate Limiting

Prevent alert spam with cooldown periods:

```bash
# No cooldown for critical
ALERT_COOLDOWN_CRITICAL=0

# 1 minute for high
ALERT_COOLDOWN_HIGH=60

# 5 minutes for medium
ALERT_COOLDOWN_MEDIUM=300

# 1 hour for low
ALERT_COOLDOWN_LOW=3600
```

### Scheduled Reports

```bash
# Enable daily summary
SEND_DAILY_SUMMARY="true"
DAILY_SUMMARY_TIME="08:00"

# Enable weekly report
SEND_WEEKLY_REPORT="true"
WEEKLY_REPORT_DAY="Sunday"
WEEKLY_REPORT_TIME="09:00"
```

### Group Chat Configuration

For group or channel notifications:

```bash
# Group chat ID (negative number)
TELEGRAM_CHAT_ID="-1234567890123"

# Forum topic ID (optional)
TELEGRAM_THREAD_ID="123"
```

Make sure your bot is an admin in the group/channel.

---

## Troubleshooting

### "Telegram test failed"

1. **Check token format**:
   ```bash
   grep TELEGRAM_BOT_TOKEN /etc/tresk/config.conf
   ```
   Should be: `123456789:ABCdefGHIjklMNOpqrSTUvwxyz`

2. **Verify token with API**:
   ```bash
   curl -s "https://api.telegram.org/bot<TOKEN>/getMe"
   ```
   Should return bot information.

3. **Check chat ID**:
   ```bash
   curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates"
   ```
   Look for `chat.id` in the response.

### "Bot not receiving messages"

1. Start a chat with your bot
2. Send `/start`
3. Check privacy settings:
   - Go to @BotFather
   - Select your bot
   - Choose "Bot Settings" → "Group Privacy"
   - Turn OFF (so bot can see all messages)

### "Messages not formatting"

Telegram uses MarkdownV2 which requires escaping:
- Characters to escape: `_ * [ ] ( ) ~ ` > # + - = | { } . !`
- The monitor handles this automatically

### Rate Limiting

Telegram API limits:
- 20 messages per minute to the same chat
- 30 messages per second overall

The monitor has built-in rate limiting to respect these limits.

---

## Example Alert Messages

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
```

*Recommended Actions:*
```
1. Kill process: kill -9 12345
2. Check persistence: crontab -l
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
└─ Disk Usage: `67%`

*Security Metrics:*
├─ Failed SSH Attempts: `15`
├─ Critical Alerts: `0`
└─ High Alerts: `1`
```

---

## Security Best Practices

1. **Keep token secret** - Never commit to git
2. **Use environment variables** for sensitive data
3. **Rotate tokens** periodically
4. **Monitor bot activity** in BotFather
5. **Use private chats** for sensitive alerts

---

## Next Steps

- [Configure Auto-Response](AUTO_RESPONSE.md)
- [Customize Alert Templates](CUSTOMIZATION.md)
- [Set Up Multiple Recipients](ADVANCED.md)
