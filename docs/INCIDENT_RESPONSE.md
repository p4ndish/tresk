# Incident Response Playbook

Step-by-step response procedures for security incidents detected by Tresk.

## Table of Contents

1. [General Incident Response](#general-incident-response)
2. [Cryptominer Response](#cryptominer-response)
3. [Rootkit Response](#rootkit-response)
4. [Backdoor Response](#backdoor-response)
5. [Ransomware Response](#ransomware-response)
6. [Container Escape Response](#container-escape-response)
7. [SSH Compromise Response](#ssh-compromise-response)
8. [Post-Incident Activities](#post-incident-activities)

---

## General Incident Response

### Immediate Actions (First 5 minutes)

1. **Acknowledge the alert**
   - Note severity and type
   - Record timestamp
   - Identify affected system

2. **Preserve evidence**
   ```bash
   # Create incident directory
   mkdir -p /root/incidents/$(date +%Y%m%d_%H%M%S)
   INCIDENT_DIR=/root/incidents/$(date +%Y%m%d_%H%M%S)
   
   # Save process info
   ps aux > $INCIDENT_DIR/processes.txt
   
   # Save network connections
   ss -tan > $INCIDENT_DIR/connections.txt
   
   # Save recent logs
   tail -1000 /var/log/auth.log > $INCIDENT_DIR/auth.log
   ```

3. **Assess scope**
   - Single system or multiple?
   - User or root compromise?
   - Data access potential?

### Decision Tree

```
                    ┌─────────────────┐
                    │  Alert Received │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
        ┌─────────┐   ┌──────────┐   ┌──────────┐
        │CRITICAL │   │   HIGH   │   │  MEDIUM  │
        └────┬────┘   └────┬─────┘   └────┬─────┘
             │             │              │
             ▼             ▼              ▼
    ┌────────────────┐  ┌──────────┐  ┌──────────┐
    │ ISOLATE SYSTEM │  │ INVESTIGATE│ │ MONITOR  │
    └────────────────┘  └──────────┘  └──────────┘
```

---

## Cryptominer Response

### Alert Indicators

- 🚨 CRITICAL: Cryptominer Detected
- 🚨 CRITICAL: Suspicious High CPU Process
- 🚨 CRITICAL: Deleted Process Executable Detected

### Response Steps

#### 1. Immediate Containment (0-5 min)

```bash
# Get process details from alert
PID=<PID_FROM_ALERT>

# Isolate network (optional but recommended)
iptables -A OUTPUT -p tcp --dport 443 -j DROP
iptables -A OUTPUT -p tcp --dport 3333 -j DROP
iptables -A OUTPUT -p tcp --dport 7777 -j DROP

# Kill the process
kill -9 $PID

# Verify killed
ps -p $PID || echo "Process killed"
```

#### 2. Investigation (5-30 min)

```bash
# Create incident directory
INCIDENT_DIR=/root/incidents/miner_$(date +%Y%m%d_%H%M%S)
mkdir -p $INCIDENT_DIR

# Collect process artifacts
cat /proc/$PID/cmdline 2>/dev/null | tr '\0' ' ' > $INCIDENT_DIR/cmdline.txt
ls -la /proc/$PID/exe 2>/dev/null > $INCIDENT_DIR/exe.txt
ls -la /proc/$PID/fd/ 2>/dev/null > $INCIDENT_DIR/fds.txt
cat /proc/$PID/environ 2>/dev/null | tr '\0' '\n' > $INCIDENT_DIR/environ.txt

# Get binary hash (if exists)
EXE_PATH=$(readlink /proc/$PID/exe 2>/dev/null | sed 's/ (deleted)//')
if [[ -f "$EXE_PATH" ]]; then
    sha256sum $EXE_PATH > $INCIDENT_DIR/hash.txt
    file $EXE_PATH > $INCIDENT_DIR/file_type.txt
fi

# Check network connections
ss -tan | grep $PID > $INCIDENT_DIR/network.txt

# Check process tree
pstree -p | grep $PID > $INCIDENT_DIR/tree.txt
```

#### 3. Persistence Check (30-60 min)

```bash
# Check cron jobs
crontab -l > $INCIDENT_DIR/crontab.txt 2>&1
ls -la /etc/cron* > $INCIDENT_DIR/cron_dirs.txt
cat /etc/crontab > $INCIDENT_DIR/system_crontab.txt
find /etc/cron.* -type f -exec cat {} \; > $INCIDENT_DIR/cron_jobs.txt

# Check systemd
systemctl list-timers --all > $INCIDENT_DIR/timers.txt
find /etc/systemd/system -type f -newer /etc/passwd > $INCIDENT_DIR/new_systemd.txt

# Check startup scripts
cat /etc/rc.local > $INCIDENT_DIR/rc.local.txt 2>&1
ls -la /etc/init.d/ > $INCIDENT_DIR/initd.txt

# Check shell profiles
cat /root/.bashrc > $INCIDENT_DIR/root_bashrc.txt
cat /root/.profile > $INCIDENT_DIR/root_profile.txt
find /home -name ".bashrc" -exec cat {} \; > $INCIDENT_DIR/user_bashrcs.txt

# Check SSH keys
find /root /home -name "authorized_keys" -exec cat {} \; > $INCIDENT_DIR/ssh_keys.txt

# Check for other miners
find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | xargs ls -la > $INCIDENT_DIR/suspicious_files.txt
```

#### 4. Eradication

```bash
# Remove cron entries
crontab -r  # If malicious entries found
# Manually edit /etc/crontab and /etc/cron.* if needed

# Remove systemd services
# systemctl disable <malicious-service>
# rm /etc/systemd/system/<malicious-service>

# Clean temp directories
find /tmp /var/tmp /dev/shm -type f -executable -delete 2>/dev/null

# Remove suspicious files
# rm -f <identified-files>

# Clear caches
sync; echo 3 > /proc/sys/vm/drop_caches
```

#### 5. Recovery

```bash
# Remove network isolation
iptables -D OUTPUT -p tcp --dport 443 -j DROP
iptables -D OUTPUT -p tcp --dport 3333 -j DROP
iptables -D OUTPUT -p tcp --dport 7777 -j DROP

# Restart services if needed
# systemctl restart <affected-service>

# Monitor for recurrence
/opt/tresk/bin/monitor.sh quick
```

---

## Rootkit Response

### Alert Indicators

- 🚨 CRITICAL: LD_PRELOAD Rootkit Detected
- 🚨 CRITICAL: Suspicious Kernel Module Detected
- 🚨 CRITICAL: Hidden Process Detected
- 🚨 CRITICAL: Reptile/Diamorphine Rootkit Detected

### ⚠️ WARNING

**Rootkit detection indicates potential full system compromise. The system may not be trustworthy.**

### Response Steps

#### 1. Immediate Actions

```bash
# DO NOT trust any system information
# Assume all commands may be intercepted

# If possible, disconnect from network immediately
ip link set eth0 down  # or your interface

# Document everything externally
# Use camera to photograph screen
```

#### 2. Evidence Collection (From External System)

```bash
# If system is virtual, take snapshot
# If physical, consider memory dump

# Boot from live CD/USB if possible
# Mount compromised filesystem read-only

# Collect from live system (untrusted):
mkdir -p /root/incidents/rootkit_$(date +%Y%m%d_%H%M%S)
INCIDENT_DIR=/root/incidents/rootkit_$(date +%Y%m%d_%H%M%S)

# Save LD_PRELOAD
cat /etc/ld.so.preload > $INCIDENT_DIR/ld.so.preload.txt

# List modules
lsmod > $INCIDENT_DIR/lsmod.txt
ls /sys/module/ > $INCIDENT_DIR/sys_module.txt

# Check for hidden modules
diff <(lsmod | awk 'NR>1 {print $1}') <(ls /sys/module/) > $INCIDENT_DIR/hidden_modules.txt

# List processes
ps aux > $INCIDENT_DIR/ps.txt
ls /proc/ | grep -E '^[0-9]+$' | sort -n > $INCIDENT_DIR/proc_pids.txt

# Check for hidden processes
diff <(ps aux | awk 'NR>1 {print $2}' | sort -n) $INCIDENT_DIR/proc_pids.txt > $INCIDENT_DIR/hidden_procs.txt
```

#### 3. Analysis

```bash
# Check kernel module signatures
for mod in $(lsmod | awk 'NR>1 {print $1}'); do
    modinfo $mod >> $INCIDENT_DIR/modinfo.txt 2>&1
done

# Check for Reptile
find /reptile /lib/modules/*/kernel/drivers/reptile 2>/dev/null > $INCIDENT_DIR/reptile_files.txt

# Check for Diamorphine
ls -la /proc/diamorphine* 2>/dev/null > $INCIDENT_DIR/diamorphine.txt

# Check syscall table (if possible)
cat /proc/kallsyms | grep sys_call_table > $INCIDENT_DIR/syscall_table.txt
```

#### 4. Decision Point

**Option A: Attempt Removal (High Risk)**
- Only if rootkit is known and removal procedure documented
- Requires deep kernel knowledge
- May leave backdoors

**Option B: Rebuild System (Recommended)**
- Backup data (from live CD)
- Wipe system completely
- Reinstall OS from trusted media
- Restore data after verification

#### 5. Rebuild Procedure

```bash
# 1. Boot from trusted live CD/USB

# 2. Mount data partitions read-only
mkdir -p /mnt/data
mount -o ro /dev/sda1 /mnt/data  # adjust device

# 3. Copy critical data
cp -r /mnt/data/important /external/backup/

# 4. Verify backup integrity
sha256sum /external/backup/important/* > checksums.txt

# 5. Wipe disk
shred -vfz -n 3 /dev/sda  # or use DBAN

# 6. Reinstall OS from trusted ISO

# 7. Restore data after scanning
clamscan -r /external/backup/

# 8. Reinstall Tresk
```

---

## Backdoor Response

### Alert Indicators

- 🚨 CRITICAL: Suspicious SUID Binary
- 🚨 CRITICAL: Reverse Shell Detected
- 🚨 CRITICAL: Potential Web Shell
- 🔶 HIGH: Suspicious SSH Key Found

### Response Steps

#### 1. Reverse Shell Response

```bash
# Get PID from alert
PID=<PID_FROM_ALERT>

# Get connection details
ss -tanp | grep $PID
lsof -p $PID | grep TCP

# Identify source IP
SOURCE_IP=$(ss -tanp | grep $PID | awk '{print $5}' | cut -d: -f1)

# Block source IP
iptables -A INPUT -s $SOURCE_IP -j DROP

# Kill process
kill -9 $PID

# Check for other shells
ps aux | grep -E "(bash|sh|python|perl|ruby)" | grep -v grep
```

#### 2. SUID Binary Response

```bash
# Get file path from alert
SUID_FILE=<FILE_FROM_ALERT>

# Check file details
ls -la $SUID_FILE
file $SUID_FILE
sha256sum $SUID_FILE

# Check if in temp directory
if [[ "$SUID_FILE" =~ ^(/tmp/|/var/tmp/|/dev/shm/) ]]; then
    # Likely malicious - remove
    rm -f $SUID_FILE
    echo "Removed suspicious SUID binary: $SUID_FILE"
else
    # Check if legitimate
    dpkg -S $SUID_FILE 2>/dev/null || rpm -qf $SUID_FILE 2>/dev/null
    
    # If not owned by package, investigate
    # Check against known good list
fi

# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null | while read f; do
    echo "SUID: $f"
    ls -la $f
done > /root/incidents/suid_list_$(date +%Y%m%d).txt
```

#### 3. Web Shell Response

```bash
# Get file path from alert
WEBSHELL=<FILE_FROM_ALERT>

# Quarantine file
mkdir -p /root/quarantine
chmod 700 /root/quarantine
cp $WEBSHELL /root/quarantine/

# Remove from web directory
rm -f $WEBSHELL

# Check web server logs
WEBROOT=$(dirname $WEBSHELL)
grep -r "$(basename $WEBSHELL)" /var/log/apache2/ /var/log/nginx/ 2>/dev/null | tail -20

# Find other potential shells
find /var/www /usr/share/nginx /opt/tomcat -type f \( \
    -name "*.php" -o -name "*.jsp" -o -name "*.asp" -o -name "*.aspx" \
    -o -name "*.sh" -o -name "*.pl" -o -name "*.py" \
\) -exec grep -lE "(eval\(|exec\(|system\(|shell_exec|passthru|base64_decode)" {} \; 2>/dev/null

# Check for recently modified files
find /var/www -type f -mtime -7 -ls

# Check upload directories
find /var/www -type d -name "*upload*" -exec ls -la {} \;
```

#### 4. SSH Key Response

```bash
# Get file path from alert
AUTH_KEYS=<FILE_FROM_ALERT>

# Backup original
cp $AUTH_KEYS ${AUTH_KEYS}.bak.$(date +%Y%m%d)

# Review keys
cat $AUTH_KEYS

# Remove suspicious keys
# Edit file and remove lines with:
# - command="*" restrictions
# - Unknown keys
# - Keys with unusual options

# Identify key owners
for key in $(cat $AUTH_KEYS | grep ssh-rsa | awk '{print $3}'); do
    echo "Key: $key"
done

# Rotate keys if compromise suspected
# Generate new key pair
ssh-keygen -t ed25519 -f ~/.ssh/new_key

# Remove old keys from authorized_keys
# Add new public key

# Check SSH config
grep -E "(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)" /etc/ssh/sshd_config
```

---

## Ransomware Response

### Alert Indicators

- 🚨 CRITICAL: Ransomware Indicators Detected
- 🚨 CRITICAL: Ransom Note Found
- 🔶 HIGH: Mass File Modification Detected

### Response Steps

#### 1. Immediate Isolation

```bash
# DISCONNECT NETWORK IMMEDIATELY
ip link set eth0 down

# Stop all non-essential services
systemctl stop apache2 nginx mysql postgresql

# Kill user sessions
who | awk '{print $2}' | xargs -I {} pkill -t {}
```

#### 2. Assessment

```bash
# Identify encrypted files
find /home /var/www /opt -type f \( \
    -name "*.encrypted" -o -name "*.locked" -o -name "*.crypto" \
    -o -name "*.crypt" -o -name "*.vault" -o -name "*.ransom" \
\) 2>/dev/null | head -50

# Find ransom notes
find / -type f \( \
    -iname "*README*DECRYPT*" -o -iname "*HOW_TO_DECRYPT*" \
    -o -iname "*RECOVER_FILES*" -o -iname "*YOUR_FILES_ARE_ENCRYPTED*" \
\) 2>/dev/null

# Check shadow copies/backups
ls -la /var/backups/
ls -la ~/.snapshot/ 2>/dev/null
```

#### 3. DO NOT

- ❌ Do NOT pay the ransom
- ❌ Do NOT run decryption tools from attackers
- ❌ Do NOT delete encrypted files yet
- ❌ Do NOT reconnect to network

#### 4. Recovery

```bash
# 1. Identify ransomware variant
cat /root/incidents/ransom_notes.txt

# 2. Check for free decryptors
# Visit: https://www.nomoreransom.org/

# 3. Restore from backups
# Verify backup integrity first

# 4. If no backups, preserve encrypted files
# Some decryptors may be released later

# 5. Rebuild system from scratch
# Do not trust compromised system
```

---

## Container Escape Response

### Alert Indicators

- 🚨 CRITICAL: Container Escape Detected
- 🚨 CRITICAL: Container with Docker Socket Access
- 🚨 CRITICAL: Privileged Container Detected
- 🔶 HIGH: Suspicious Container Mounts

### Response Steps

#### 1. Immediate Containment

```bash
# Stop the container
CONTAINER_ID=<ID_FROM_ALERT>
docker stop $CONTAINER_ID
docker rm $CONTAINER_ID

# If escape suspected, stop Docker daemon
systemctl stop docker

# Check for host compromise
ps aux | grep -v containerd | grep -v docker
```

#### 2. Investigation

```bash
# Get container details
docker inspect $CONTAINER_ID > /root/incidents/container_$(date +%Y%m%d).json

# Check container logs
docker logs $CONTAINER_ID > /root/incidents/container_logs.txt 2>&1

# List all containers
docker ps -a > /root/incidents/all_containers.txt

# Check for privileged containers
docker ps -q | xargs -I {} docker inspect {} --format='{{.Name}}: {{.HostConfig.Privileged}}'

# Check for dangerous mounts
docker ps -q | xargs -I {} docker inspect {} --format='{{.Name}}: {{.Mounts}}'

# Check for exposed Docker socket
ss -tan | grep -E '237[56]'
curl -s http://localhost:2375/containers/json 2>/dev/null
```

#### 3. Host Assessment

```bash
# Check for new users
cat /etc/passwd | tail -10

# Check sudoers
cat /etc/sudoers
cat /etc/sudoers.d/*

# Check for new SSH keys
find /root /home -name "authorized_keys" -newer /etc/passwd

# Check running processes from containers
ps aux | grep -E "(docker|containerd)" | grep -v grep

# Check for kernel module loading
lsmod | tail -10
```

#### 4. Remediation

```bash
# Remove compromised containers
docker rm -f <compromised-container>

# Remove untrusted images
docker rmi <untrusted-image>

# Prune everything
docker system prune -a -f

# Review Docker daemon configuration
cat /etc/docker/daemon.json

# Disable TCP socket if enabled
# Edit /etc/docker/daemon.json
# Remove: "hosts": ["tcp://0.0.0.0:2375"]

# Enable user namespace remapping
# Add to daemon.json:
# {
#   "userns-remap": "default"
# }

# Restart Docker
systemctl restart docker

# Run security scan
lynis audit system
```

---

## SSH Compromise Response

### Alert Indicators

- 🔶 HIGH: SSH Brute Force Attack
- 🔶 MEDIUM: Root Login Detected
- 🔶 HIGH: Suspicious SSH Key Found

### Response Steps

#### 1. Brute Force Response

```bash
# Get attacking IPs from logs
grep "Failed password" /var/log/auth.log | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -rn | head -10

# Block top attackers
for ip in $(grep "Failed password" /var/log/auth.log | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -rn | head -5 | awk '{print $2}'); do
    iptables -A INPUT -s $ip -j DROP
    echo "Blocked: $ip"
done

# Install/configure fail2ban
apt-get install fail2ban
cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF
systemctl restart fail2ban
```

#### 2. Unauthorized Access Response

```bash
# Check current sessions
who
w

# Check login history
last | head -20
lastb | head -20  # Failed logins

# Check for new users
cat /etc/passwd | tail -10

# Check sudoers for modifications
cat /etc/sudoers
cat /etc/sudoers.d/*

# Check for new SSH keys
find /root /home -name "authorized_keys" -newer /etc/passwd -exec cat {} \;

# Review SSH config changes
diff /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null

# Check for port forwarding
ss -tan | grep -E '127\.0\.0\.1:[0-9]+'
```

#### 3. Key Compromise Response

```bash
# Remove all authorized_keys temporarily
find /root /home -name "authorized_keys" -exec mv {} {}.bak.$(date +%Y%m%d) \;

# Generate new key pair
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_new -C "new-key-$(date +%Y%m%d)"

# Add new key to authorized_keys
cat ~/.ssh/id_ed25519_new.pub >> ~/.ssh/authorized_keys

# Distribute new private key securely

# Rotate passwords
passwd
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
    passwd $user
done
```

---

## Post-Incident Activities

### 1. Documentation

```bash
# Create incident report
cat > /root/incidents/REPORT_$(date +%Y%m%d).md <<EOF
# Incident Report

## Summary
- Date: $(date)
- Type: <incident-type>
- Severity: <severity>
- Systems Affected: <systems>

## Timeline
- Alert received: <time>
- Containment: <time>
- Eradication: <time>
- Recovery: <time>

## Actions Taken
1. <action>
2. <action>

## Indicators of Compromise
- <IOC>
- <IOC>

## Lessons Learned
- <lesson>
- <lesson>

## Recommendations
- <recommendation>
- <recommendation>
EOF
```

### 2. Hardening

```bash
# Update all packages
apt-get update && apt-get upgrade -y

# Review and apply security configurations
# - Disable password auth for SSH
# - Enable 2FA
# - Configure firewall
# - Enable audit logging
# - Set up centralized logging

# Run security audit
lynis audit system
```

### 3. Monitoring Enhancement

```bash
# Review and update detection rules
nano /opt/tresk/signatures/threat_signatures.json

# Adjust thresholds based on baseline
nano /etc/tresk/config.conf

# Add new detection patterns
# Based on observed attack techniques

# Test detection
/opt/tresk/bin/monitor.sh deep
```

### 4. Communication

- Notify stakeholders
- Update security policies
- Train users on new procedures
- Schedule follow-up review

---

## Emergency Contacts

| Role | Contact | Purpose |
|------|---------|---------|
| Security Team | security@company.com | Incident escalation |
| System Admin | admin@company.com | Technical support |
| Management | management@company.com | Business decisions |
| Legal | legal@company.com | Compliance issues |

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│                    EMERGENCY RESPONSE                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ISOLATE:  ip link set eth0 down                            │
│  KILL:     kill -9 <PID>                                    │
│  BLOCK:    iptables -A INPUT -s <IP> -j DROP               │
│  SAVE:     mkdir -p /root/incidents/$(date +%Y%m%d)        │
│  LOGS:     journalctl -u tresk -n 100       │
│  STATUS:   systemctl status tresk           │
│                                                              │
│  EMERGENCY STOP:                                            │
│  systemctl stop tresk                        │
│  systemctl disable tresk                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```
