#!/usr/bin/env python3
"""
Tresk - Telegram Notification Module
Version: 1.0.0
Description: Advanced Telegram notification system with HTML formatting
"""

import html
import json
import sys
import os
import time
import hashlib
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import requests


class TelegramNotifier:
    """Advanced Telegram notification system for Tresk"""
    
    def __init__(self, config_file: str = "/etc/tresk/config.conf"):
        self.config_file = config_file
        self.config = self._load_config()
        self.alert_state_dir = "/opt/tresk/.alert_state"
        self.ensure_directories()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        config = {
            'TELEGRAM_ENABLED': False,
            'TELEGRAM_BOT_TOKEN': '',
            'TELEGRAM_CHAT_ID': '',
            'TELEGRAM_THREAD_ID': '',
            'HOSTNAME': '',
            'PUBLIC_IP': '',
            'ALERT_CRITICAL': True,
            'ALERT_HIGH': True,
            'ALERT_MEDIUM': True,
            'ALERT_LOW': False,
            'ALERT_COOLDOWN_CRITICAL': 0,
            'ALERT_COOLDOWN_HIGH': 60,
            'ALERT_COOLDOWN_MEDIUM': 300,
            'ALERT_COOLDOWN_LOW': 3600,
            'AUTO_RESPONSE_ENABLED': False,
            'AUTO_KILL_CRITICAL': False,
        }
        
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        
                        # Remove inline comments
                        if '#' in value:
                            value = value.split('#')[0]
                        value = value.strip().strip('"').strip("'")
                        
                        # Convert boolean strings
                        if value.lower() in ('true', 'yes', '1'):
                            config[key] = True
                        elif value.lower() in ('false', 'no', '0'):
                            config[key] = False
                        # Convert integers
                        elif value.lstrip('-').isdigit():
                            config[key] = int(value)
                        else:
                            config[key] = value
        
        # Handle shell command substitutions in config (e.g., $(hostname))
        if config.get('HOSTNAME', '').startswith('$('):
            config['HOSTNAME'] = os.uname().nodename
        if config.get('PUBLIC_IP', '').startswith('$('):
            config['PUBLIC_IP'] = self._get_public_ip()
        
        return config
    
    def _get_public_ip(self) -> str:
        """Get public IP address"""
        try:
            response = requests.get('https://ifconfig.me', timeout=5)
            return response.text.strip()
        except:
            return 'unknown'
    
    def ensure_directories(self):
        """Ensure required directories exist"""
        os.makedirs(self.alert_state_dir, exist_ok=True)
        os.makedirs('/var/log/tresk', exist_ok=True)
    
    def _get_alert_key(self, title: str) -> str:
        """Generate unique alert key"""
        return hashlib.sha256(title.encode()).hexdigest()[:16]
    
    def _check_cooldown(self, alert_key: str, severity: str) -> bool:
        """Check if alert is in cooldown period"""
        state_file = os.path.join(self.alert_state_dir, alert_key)
        
        cooldown_map = {
            'CRITICAL': self.config.get('ALERT_COOLDOWN_CRITICAL', 0),
            'HIGH': self.config.get('ALERT_COOLDOWN_HIGH', 60),
            'MEDIUM': self.config.get('ALERT_COOLDOWN_MEDIUM', 300),
            'LOW': self.config.get('ALERT_COOLDOWN_LOW', 3600)
        }
        cooldown = cooldown_map.get(severity, 3600)
        
        if os.path.exists(state_file):
            with open(state_file, 'r') as f:
                last_alert = int(f.read().strip())
            
            if (time.time() - last_alert) < cooldown:
                return False
        
        # Update state
        with open(state_file, 'w') as f:
            f.write(str(int(time.time())))
        
        return True
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        emoji_map = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '🔶',
            'LOW': 'ℹ️'
        }
        return emoji_map.get(severity, '📋')
    
    def send_alert(self, severity: str, title: str, details: str, 
                   recommendation: str = "No specific recommendation") -> bool:
        """Send alert via Telegram using HTML formatting"""
        
        if not self.config.get('TELEGRAM_ENABLED', False):
            print(f"Telegram disabled. Local log: [{severity}] {title}")
            return False
        
        # Check if this severity level should be sent
        alert_levels = {
            'CRITICAL': self.config.get('ALERT_CRITICAL', True),
            'HIGH': self.config.get('ALERT_HIGH', True),
            'MEDIUM': self.config.get('ALERT_MEDIUM', True),
            'LOW': self.config.get('ALERT_LOW', False)
        }
        
        if not alert_levels.get(severity, False):
            return False
        
        # Check cooldown
        alert_key = self._get_alert_key(title)
        if not self._check_cooldown(alert_key, severity):
            print(f"Alert in cooldown: {title}")
            return False
        
        emoji = self._get_severity_emoji(severity)
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        hostname = self.config.get('HOSTNAME', os.uname().nodename)
        public_ip = self.config.get('PUBLIC_IP', 'unknown')
        
        # Build message with HTML formatting
        message = f"""{emoji} <b>{html.escape(severity)}: {html.escape(title)}</b>

<b>Host:</b> <code>{html.escape(hostname)} ({html.escape(public_ip)})</code>
<b>Time:</b> <code>{html.escape(timestamp)}</code>

<b>Details:</b>
<pre>{html.escape(details[:800])}</pre>

<b>Recommended Actions:</b>
<pre>{html.escape(recommendation[:400])}</pre>"""
        
        # Add auto-response status
        if self.config.get('AUTO_RESPONSE_ENABLED', False):
            if severity == 'CRITICAL' and self.config.get('AUTO_KILL_CRITICAL', False):
                message += "\n\n<b>Auto-Response:</b> Process terminated ✓"
            else:
                message += "\n\n<b>Auto-Response:</b> Disabled (manual intervention required)"
        
        return self._send_telegram_message(message)
    
    def _send_telegram_message(self, message: str) -> bool:
        """Send message to Telegram using HTML formatting"""
        
        bot_token = self.config.get('TELEGRAM_BOT_TOKEN', '')
        chat_id = self.config.get('TELEGRAM_CHAT_ID', '')
        thread_id = self.config.get('TELEGRAM_THREAD_ID', '')
        
        if not bot_token or not chat_id:
            print("Telegram bot token or chat ID not configured")
            return False
        
        # FIX: Remove the space after "bot"
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        
        payload = {
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'HTML',  # HTML is much safer than MarkdownV2
            'disable_web_page_preview': True
        }
        
        # Handle thread_id for topics
        if thread_id:
            try:
                thread_id_int = int(str(thread_id).strip())
                if thread_id_int > 0:
                    payload['message_thread_id'] = thread_id_int
                    print(f"DEBUG: Sending to topic {thread_id_int}")
            except (ValueError, TypeError):
                print(f"DEBUG: Invalid thread_id '{thread_id}', sending to General")
        
        try:
            response = requests.post(url, json=payload, timeout=10)
            result = response.json()
            
            if result.get('ok'):
                print(f"Telegram message sent successfully")
                return True
            else:
                print(f"Telegram API error: {result}")
                return False
        except Exception as e:
            print(f"Failed to send Telegram message: {e}")
            return False
    
    def send_daily_summary(self) -> bool:
        """Send daily security summary"""
        
        if not self.config.get('TELEGRAM_ENABLED', False):
            return False
        
        if not self.config.get('SEND_DAILY_SUMMARY', True):
            return False
        
        hostname = self.config.get('HOSTNAME', os.uname().nodename)
        public_ip = self.config.get('PUBLIC_IP', 'unknown')
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        message = f"""📊 <b>Daily Security Summary</b>

<b>Host:</b> <code>{html.escape(hostname)} ({html.escape(public_ip)})</code>
<b>Time:</b> <code>{html.escape(timestamp)}</code>

✅ No critical security issues detected in the last 24 hours.

<i>Report generated by Tresk</i>"""
        
        return self._send_telegram_message(message)
    
    def send_weekly_report(self) -> bool:
        """Send weekly security report"""
        
        if not self.config.get('TELEGRAM_ENABLED', False):
            return False
        
        if not self.config.get('SEND_WEEKLY_REPORT', True):
            return False
        
        hostname = self.config.get('HOSTNAME', os.uname().nodename)
        public_ip = self.config.get('PUBLIC_IP', 'unknown')
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        message = f"""📈 <b>Weekly Security Report</b>

<b>Host:</b> <code>{html.escape(hostname)} ({html.escape(public_ip)})</code>
<b>Time:</b> <code>{html.escape(timestamp)}</code>

✅ System secure - no major incidents this week.

<i>Report generated by Tresk</i>"""
        
        return self._send_telegram_message(message)
    
    def test_connection(self) -> bool:
        """Test Telegram connection"""
        
        if not self.config.get('TELEGRAM_ENABLED', False):
            print("Telegram is not enabled in configuration")
            return False
        
        if not self.config.get('TELEGRAM_BOT_TOKEN') or not self.config.get('TELEGRAM_CHAT_ID'):
            print("Telegram bot token or chat ID not configured")
            return False
        
        hostname = self.config.get('HOSTNAME', os.uname().nodename)
        thread_id = self.config.get('TELEGRAM_THREAD_ID', '')
        
        message = f"""🧪 <b>Test message from Tresk</b>

    Host: <code>{html.escape(hostname)}</code>
    ✅ Your Telegram notifications are working correctly!

    <i>This is a test message from Tresk Security Monitor</i>"""
        
        # FIX: Use <i> instead of <small>
        if thread_id:
            message += f"\n\n<i>Sent to topic ID: {html.escape(str(thread_id))}</i>"
        
        return self._send_telegram_message(message)


def main():
    parser = argparse.ArgumentParser(description='Tresk - Telegram Notifier')
    parser.add_argument('-c', '--config', default='/etc/tresk/config.conf',
                        help='Configuration file path')
    parser.add_argument('command', choices=['alert', 'summary', 'weekly', 'test'],
                        help='Command to execute')
    parser.add_argument('--severity', default='HIGH', help='Alert severity')
    parser.add_argument('--title', default='Test Alert', help='Alert title')
    parser.add_argument('--details', default='Test details', help='Alert details')
    parser.add_argument('--recommendation', default='No recommendation', help='Recommendation')
    
    args = parser.parse_args()
    
    notifier = TelegramNotifier(args.config)
    
    if args.command == 'test':
        success = notifier.test_connection()
    elif args.command == 'alert':
        success = notifier.send_alert(args.severity, args.title, args.details, args.recommendation)
    elif args.command == 'summary':
        success = notifier.send_daily_summary()
    elif args.command == 'weekly':
        success = notifier.send_weekly_report()
    else:
        print(f"Unknown command: {args.command}")
        sys.exit(1)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
