# Tresk - Architecture Overview

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Tresk                               │
│                           v1.0.0 - Architecture                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                              MONITORING LAYER                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   Process    │  │   Network    │  │    File      │  │   Container  │    │
│  │  Monitoring  │  │  Monitoring  │  │  Integrity   │  │   Security   │    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
│         │                 │                 │                 │            │
│         │  ┌──────────────┴─────────────────┴─────────────────┘            │
│         │  │                                                                │
│         │  ▼                                                                │
│         │  ┌─────────────────────────────────────────────────────────┐     │
│         │  │              DETECTION ENGINE                           │     │
│         │  ├─────────────────────────────────────────────────────────┤     │
│         │  │  • Signature Matching    • Behavioral Analysis          │     │
│         │  │  • Pattern Recognition   • Anomaly Detection            │     │
│         │  │  • IOC Comparison        • Heuristic Analysis           │     │
│         │  └─────────────────────────┬───────────────────────────────┘     │
│         │                            │                                     │
│         └────────────────────────────┼─────────────────────────────────────┘
│                                      │
└──────────────────────────────────────┼──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────┼──────────────────────────────────────┐
│                           ANALYSIS LAYER                               │
├──────────────────────────────────────┼──────────────────────────────────────┤
│                                      │
│  ┌───────────────────────────────────┴───────────────────────────────────┐  │
│  │                         THREAT CLASSIFIER                              │  │
│  ├───────────────────────────────────────────────────────────────────────┤  │
│  │  CRITICAL  │  HIGH      │  MEDIUM    │  LOW       │  INFO             │  │
│  │ ───────────┼────────────┼────────────┼────────────┼────────           │  │
│  │  Rootkits  │  Backdoors │  Suspicious│  Info      │  Status           │  │
│  │  Miners    │  C2 Conn   │  Processes │  Events    │  Updates          │  │
│  │  Ransomware│  Web Shells│  Anomalies │            │                   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                      │
└──────────────────────────────────────┼──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────┼──────────────────────────────────────┐
│                          RESPONSE LAYER                                │
├──────────────────────────────────────┼──────────────────────────────────────┤
│                                      │
│         ┌────────────────────────────┼────────────────────────────┐         │
│         │                            │                            │         │
│         ▼                            ▼                            ▼         │
│  ┌──────────────┐           ┌──────────────┐           ┌──────────────┐    │
│  │   Telegram   │           │   Auto-      │           │   Systemd    │    │
│  │   Alerts     │           │   Response   │           │   Journal    │    │
│  └──────────────┘           └──────────────┘           └──────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                         SYSTEMD INTEGRATION                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    tresk.service                      │   │
│  │  ┌───────────────────────────────────────────────────────────────┐  │   │
│  │  │  Main Service: Continuous monitoring with auto-restart       │  │   │
│  │  │  • Process checks every 5 seconds                            │  │   │
│  │  │  • Network checks every 10 seconds                           │  │   │
│  │  │  • CPU limit: 10%                                            │  │   │
│  │  │  • Memory limit: 100MB                                       │  │   │
│  │  └───────────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌─────────────────────────┐  ┌─────────────────────────────────────────┐  │
│  │  vps-security-deep-scan │  │  vps-security-summary                   │  │
│  │  ├─ timer: Daily        │  │  ├─ timer: Daily @ 08:00               │  │
│  │  └─ service: Deep scan  │  │  └─ service: Daily report               │  │
│  └─────────────────────────┘  └─────────────────────────────────────────┘  │
│                                                                              │
│  ┌─────────────────────────┐                                                │
│  │  vps-security-weekly    │                                                │
│  │  ├─ timer: Sunday 09:00 │                                                │
│  │  └─ service: Weekly     │                                                │
│  └─────────────────────────┘                                                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                        DATA FLOW DIAGRAM                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐             │
│   │  System  │───▶│  Monitor │───▶│  Detect  │───▶│  Alert   │             │
│   │  Events  │    │  Daemon  │    │  Engine  │    │  Router  │             │
│   └──────────┘    └──────────┘    └──────────┘    └────┬─────┘             │
│                                                        │                     │
│                              ┌─────────────────────────┼─────────┐          │
│                              │                         │         │          │
│                              ▼                         ▼         ▼          │
│                        ┌──────────┐            ┌──────────┐ ┌──────────┐   │
│                        │ Telegram │            │  Auto-   │ │  JSON    │   │
│                        │   API    │            │  Kill    │ │  Logs    │   │
│                        └──────────┘            └──────────┘ └──────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                      THREAT DETECTION MATRIX                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Threat Category        │ Detection Method          │ Severity │ Response   │
│  ───────────────────────┼───────────────────────────┼──────────┼─────────── │
│  Cryptominers           │ Process names, CPU usage  │ CRITICAL │ Auto-kill* │
│  Rootkits (LD_PRELOAD)  │ /etc/ld.so.preload check  │ CRITICAL │ Alert only │
│  Rootkits (Kernel)      │ Module comparison         │ CRITICAL │ Alert only │
│  Hidden Processes       │ ps vs /proc comparison    │ CRITICAL │ Alert only │
│  Reverse Shells         │ Command pattern matching  │ CRITICAL │ Auto-kill* │
│  SUID Backdoors         │ Permission scanning       │ CRITICAL │ Alert only │
│  Web Shells             │ Code signature detection  │ HIGH     │ Alert only │
│  Ransomware             │ File extension monitoring │ CRITICAL │ Alert only │
│  C2 Connections         │ Network analysis          │ HIGH     │ Alert only │
│  SSH Brute Force        │ Auth log analysis         │ HIGH     │ Auto-block*│
│  Container Escapes      │ Docker socket monitoring  │ CRITICAL │ Auto-kill* │
│  Persistence Mechanisms │ Cron/systemd monitoring   │ HIGH     │ Alert only │
│  Fileless Malware       │ /dev/shm, deleted exe     │ CRITICAL │ Auto-kill* │
│                                                                              │
│  * Requires AUTO_KILL_CRITICAL="true" in configuration                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                      FILE STRUCTURE                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  /opt/tresk/                                                  │
│  ├── bin/                                                                    │
│  │   └── monitor.sh              # Main monitoring script                   │
│  ├── lib/                                                                    │
│  │   ├── telegram_notifier.py    # Telegram notification module            │
│  │   └── process_analyzer.py     # Advanced process analysis               │
│  ├── config/                                                                 │
│  │   └── config.conf             # Configuration file                        │
│  ├── signatures/                                                             │
│  │   └── threat_signatures.json  # IOC and signature database              │
│  ├── systemd/                                                                │
│  │   ├── tresk.service      # Main service                  │
│  │   ├── vps-security-deep-scan.service    # Deep scan service             │
│  │   ├── vps-security-deep-scan.timer      # Daily scan timer              │
│  │   ├── vps-security-summary.service      # Daily summary service         │
│  │   ├── vps-security-summary.timer        # Daily summary timer           │
│  │   ├── vps-security-weekly.service       # Weekly report service         │
│  │   └── vps-security-weekly.timer         # Weekly report timer           │
│  ├── docs/                                                                   │
│  │   ├── README.md               # Main documentation                      │
│  │   ├── QUICK_START.md          # Quick start guide                       │
│  │   ├── TELEGRAM_SETUP.md       # Telegram configuration                  │
│  │   ├── TROUBLESHOOTING.md      # Troubleshooting guide                   │
│  │   ├── INCIDENT_RESPONSE.md    # Incident response playbook             │
│  │   └── ARCHITECTURE.md         # This file                               │
│  ├── install.sh                  # Installation script                     │
│  └── uninstall.sh                # Uninstallation script                   │
│                                                                              │
│  /etc/tresk/                                                  │
│  └── config.conf                 # Runtime configuration                   │
│                                                                              │
│  /var/log/tresk/                                              │
│  ├── monitor.log                 # Main log file                           │
│  ├── alerts.log                  # Alert history                           │
│  └── events.json                 # Structured JSON logs                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                      SECURITY CONSIDERATIONS                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. PRIVILEGE REQUIREMENTS                                                   │
│     • Monitor runs as root for full system access                           │
│     • Required for: /proc access, network inspection, file integrity        │
│                                                                              │
│  2. DATA PROTECTION                                                          │
│     • Telegram API uses HTTPS encryption                                    │
│     • No sensitive data in logs (passwords, keys)                           │
│     • Config files have restricted permissions (640)                        │
│                                                                              │
│  3. AUTO-RESPONSE RISKS                                                      │
│     • Auto-kill can terminate legitimate processes                          │
│     • Protected processes list prevents killing system services             │
│     • Manual review recommended before enabling auto-kill                   │
│                                                                              │
│  4. NETWORK SECURITY                                                         │
│     • Outbound connections only to Telegram API                             │
│     • No inbound ports required                                             │
│     • Can run in air-gapped environments (no Telegram)                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                      PERFORMANCE CHARACTERISTICS                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Resource Usage:                                                             │
│  ─────────────────────────────────────────────────────────────────────────  │
│  │ Metric          │ Target    │ Maximum    │ Notes                        │
│  │─────────────────│───────────│────────────│──────────────────────────────│
│  │ CPU Usage       │ < 5%      │ < 10%      │ Configurable via systemd     │
│  │ Memory Usage    │ < 50 MB   │ < 100 MB   │ Includes all components      │
│  │ Disk Usage      │ < 50 MB   │ < 500 MB   │ Depends on log retention     │
│  │ Network         │ Minimal   │ < 1 KB/s   │ Telegram API calls only      │
│  │ I/O Operations  │ Low       │ Moderate   │ During deep scans            │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  Scan Performance:                                                           │
│  ─────────────────────────────────────────────────────────────────────────  │
│  │ Scan Type       │ Duration  │ Frequency  │ CPU Impact                   │
│  │─────────────────│───────────│────────────│──────────────────────────────│
│  │ Quick Scan      │ 5-15 sec  │ Hourly     │ Low                          │
│  │ Deep Scan       │ 1-5 min   │ Daily      │ Moderate                     │
│  │ Full Audit      │ 5-30 min  │ Weekly     │ High (configurable)          │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
