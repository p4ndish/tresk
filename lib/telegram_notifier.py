#!/usr/bin/env python3
"""
VPS Security Monitor - Telegram Notification Module
Version: 1.0.0
Description: Advanced Telegram notification system with rich formatting
"""

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
    """Advanced Telegram notification system for VPS Security Monitor"""
    
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
            'ALERT_CRITICAL': True,
            'ALERT_HIGH': True,
            'ALERT_MEDIUM': True,
            'ALERT_LOW': False,
            'ALERT_COOLDOWN_CRITICAL': 0,
            'ALERT_COOLDOWN_HIGH': 60,
            'ALERT_COOLDOWN_MEDIUM': 300,
            'ALERT_COOLDOWN_LOW': 3600,
            'HOSTNAME': os.uname().nodename,
            'PUBLIC_IP': self._get_public_ip(),
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
                        value = value.strip().strip('"').strip("'")
                        
                        # Convert boolean strings
                        if value.lower() in ('true', 'yes', '1'):
                            config[key] = True
                        elif value.lower() in ('false', 'no', '0'):
                            config[key] = False
                        # Convert integers
                        elif value.isdigit():
                            config[key] = int(value)
                        else:
                            config[key] = value
        
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
            'LOW': 'ℹ️',
            'INFO': '📋'
        }
        return emoji_map.get(severity, '📋')
    
    def _escape_markdown(self, text: str) -> str:
        """Escape special characters for Telegram Markdown"""
        # Escape special characters
        chars_to_escape = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
        for char in chars_to_escape:
            text = text.replace(char, f'\\{char}')
        return text
    
    def send_alert(self, severity: str, title: str, details: str, 
                   recommendation: str = "No specific recommendation") -> bool:
        """Send alert via Telegram"""
        
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
        
        # Build message
        message = f"""{emoji} *{self._escape_markdown(severity)}: {self._escape_markdown(title)}*

*Host:* `{hostname} ({public_ip})`
*Time:* `{timestamp}`

*Details:*
```
{details[:800]}
```

*Recommended Actions:*
```
{recommendation[:400]}
```"""
        
        # Add auto-response status
        if self.config.get('AUTO_RESPONSE_ENABLED', False):
            if severity == 'CRITICAL' and self.config.get('AUTO_KILL_CRITICAL', False):
                message += "\n\n*Auto\-Response:* Process terminated ✓"
            else:
                message += "\n\n*Auto\-Response:* Disabled \(manual intervention required\)"
        
        return self._send_telegram_message(message)
    
    def _send_telegram_message(self, message: str) -> bool:
        """Send message to Telegram"""
        
        bot_token = self.config.get('TELEGRAM_BOT_TOKEN', '')
        chat_id = self.config.get('TELEGRAM_CHAT_ID', '')
        thread_id = self.config.get('TELEGRAM_THREAD_ID', '')
        
        if not bot_token or not chat_id:
            print("Telegram bot token or chat ID not configured")
            return False
        
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        
        payload = {
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'MarkdownV2',
            'disable_web_page_preview': True
        }
        
        if thread_id:
            payload['message_thread_id'] = thread_id
        
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
        
        # Gather system statistics
        try:
            import subprocess
            
            # Get system info
            uptime = subprocess.check_output(['uptime'], text=True).strip()
            load_avg = uptime.split('load average:')[-1].strip() if 'load average:' in uptime else 'N/A'
            
            # Get CPU usage
            try:
                cpu_info = subprocess.check_output(['top', '-bn1'], text=True)
                cpu_line = [l for l in cpu_info.split('\n') if 'Cpu(s)' in l]
                cpu_usage = cpu_line[0].split(',')[0].split(':')[1].strip() if cpu_line else 'N/A'
            except:
                cpu_usage = 'N/A'
            
            # Get memory usage
            try:
                mem_info = subprocess.check_output(['free'], text=True)
                mem_line = [l for l in mem_info.split('\n') if l.startswith('Mem:')]
                if mem_line:
                    parts = mem_line[0].split()
                    mem_usage = f"{float(parts[2]) / float(parts[1]) * 100:.1f}%"
                else:
                    mem_usage = 'N/A'
            except:
                mem_usage = 'N/A'
            
            # Get disk usage
            try:
                disk_info = subprocess.check_output(['df', '-h', '/'], text=True)
                disk_usage = disk_info.split('\n')[1].split()[4]
            except:
                disk_usage = 'N/A'
            
            # Get active users
            try:
                users = subprocess.check_output(['who'], text=True).strip().split('\n')
                active_users = len([u for u in users if u.strip()])
            except:
                active_users = 0
            
            # Get failed SSH attempts
            try:
                auth_log = subprocess.check_output(
                    ['grep', '-c', 'Failed password', '/var/log/auth.log'],
                    text=True, stderr=subprocess.DEVNULL
                ).strip()
                failed_ssh = auth_log
            except:
                failed_ssh = '0'
            
            # Get active connections
            try:
                conns = subprocess.check_output(['ss', '-tan'], text=True, stderr=subprocess.DEVNULL)
                active_conns = len(conns.split('\n')) - 1
            except:
                try:
                    conns = subprocess.check_output(['netstat', '-tan'], text=True, stderr=subprocess.DEVNULL)
                    active_conns = len(conns.split('\n')) - 1
                except:
                    active_conns = 'N/A'
            
            # Get process count
            try:
                procs = subprocess.check_output(['ps', 'aux'], text=True)
                total_procs = len(procs.split('\n')) - 1
            except:
                total_procs = 'N/A'
            
            # Get Docker containers
            try:
                containers = subprocess.check_output(
                    ['docker', 'ps', '-q'],
                    text=True, stderr=subprocess.DEVNULL
                ).strip().split('\n')
                docker_containers = len([c for c in containers if c.strip()])
            except:
                docker_containers = 0
            
        except Exception as e:
            print(f"Error gathering system stats: {e}")
            load_avg = cpu_usage = mem_usage = disk_usage = 'N/A'
            active_users = failed_ssh = active_conns = total_procs = docker_containers = 0
        
        # Get alert counts
        log_dir = '/var/log/tresk'
        try:
            with open(f'{log_dir}/alerts.log', 'r') as f:
                alerts = f.read()
                critical_alerts = alerts.count('CRITICAL')
                high_alerts = alerts.count('HIGH')
        except:
            critical_alerts = high_alerts = 0
        
        # Build message
        message = f"""📊 *Daily Security Summary*

*Host:* `{hostname} ({public_ip})`
*Report Time:* `{timestamp}`
*Period:* Last 24 hours

*System Status:*
├─ Load Average: `{load_avg}`
├─ CPU Usage: `{cpu_usage}`
├─ Memory Usage: `{mem_usage}`
├─ Disk Usage: `{disk_usage}`
└─ Active Users: `{active_users}`

*Security Metrics:*
├─ Failed SSH Attempts: `{failed_ssh}`
├─ Active Connections: `{active_conns}`
├─ Total Processes: `{total_procs}`
├─ Docker Containers: `{docker_containers}`
├─ Critical Alerts: `{critical_alerts}`
└─ High Alerts: `{high_alerts}`

_Monitor is running normally_"""
        
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
        
        # Get alert counts
        log_dir = '/var/log/tresk'
        try:
            with open(f'{log_dir}/alerts.log', 'r') as f:
                alerts = f.read()
                total_alerts = len(alerts.split('\n'))
                critical_count = alerts.count('CRITICAL')
                high_count = alerts.count('HIGH')
        except:
            total_alerts = critical_count = high_count = 0
        
        security_score = "✅ Good" if critical_count == 0 else "⚠️ Review Needed"
        
        # Build message
        message = f"""📈 *Weekly Security Report*

*Host:* `{hostname} ({public_ip})`
*Report Time:* `{timestamp}`
*Period:* Last 7 days

*Alert Summary:*
├─ Total Alerts: `{total_alerts}`
├─ Critical: `{critical_count}`
├─ High: `{high_count}`
└─ Security Score: `{security_score}`

*Recommendations:*
"""
        
        if critical_count > 0:
            message += "• Review all critical alerts immediately\n"
        if high_count > 5:
            message += "• Investigate recurring high\-severity issues\n"
        
        message += """• Keep system packages updated
• Review user access regularly
• Verify backup integrity

_Next report: Next week_"""
        
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
        message = f"🧪 Test message from VPS Security Monitor on {hostname}"
        
        return self._send_telegram_message(message)


def main():
    parser = argparse.ArgumentParser(description='VPS Security Monitor - Telegram Notifier')
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
    
    if args.command == 'alert':
        success = notifier.send_alert(args.severity, args.title, args.details, args.recommendation)
        sys.exit(0 if success else 1)
    
    elif args.command == 'summary':
        success = notifier.send_daily_summary()
        sys.exit(0 if success else 1)
    
    elif args.command == 'weekly':
        success = notifier.send_weekly_report()
        sys.exit(0 if success else 1)
    
    elif args.command == 'test':
        success = notifier.test_connection()
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
