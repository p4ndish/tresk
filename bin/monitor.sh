#!/bin/bash
################################################################################
# Tresk - Main Monitoring Script
# Version: 1.0.0
# Description: Production-grade Linux VPS security monitoring and alerting
# Author: Tresk Contributors
# License: MIT
################################################################################

set -o pipefail
set -o nounset

# =============================================================================
# SCRIPT METADATA
# =============================================================================
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_NAME="Tresk"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BASE_DIR="$(dirname "$SCRIPT_DIR")"

# =============================================================================
# CONFIGURATION
# =============================================================================
CONFIG_FILE="/etc/tresk/config.conf"
SIGNATURE_DB="${BASE_DIR}/signatures/threat_signatures.json"
LOG_DIR="/var/log/tresk"
WORK_DIR="/opt/tresk"
PID_FILE="/var/run/tresk.pid"
ALERT_STATE_DIR="${WORK_DIR}/.alert_state"

# =============================================================================
# COLOR CODES FOR OUTPUT
# =============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# =============================================================================
# LOGGING FUNCTIONS
# =============================================================================

log_init() {
    mkdir -p "$LOG_DIR" "$ALERT_STATE_DIR"
    touch "${LOG_DIR}/monitor.log"
    touch "${LOG_DIR}/alerts.log"
    touch "${LOG_DIR}/events.json"
}

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Console output with colors
    case "$level" in
        DEBUG)   echo -e "${BLUE}[DEBUG]${NC} $message" ;;
        INFO)    echo -e "${GREEN}[INFO]${NC} $message" ;;
        WARNING) echo -e "${YELLOW}[WARNING]${NC} $message" ;;
        ERROR)   echo -e "${RED}[ERROR]${NC} $message" ;;
        CRITICAL)echo -e "${RED}[CRITICAL]${NC} $message" ;;
    esac
    
    # File logging
    echo "[$timestamp] [$level] $message" >> "${LOG_DIR}/monitor.log"
    
    # JSON logging
    if [[ "${ENABLE_JSON_LOGGING:-false}" == "true" ]]; then
        printf '{"timestamp":"%s","level":"%s","message":"%s"}\n' \
            "$timestamp" "$level" "$message" >> "${LOG_DIR}/events.json"
    fi
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log ERROR "This script must be run as root"
        exit 1
    fi
}

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
        log INFO "Configuration loaded from $CONFIG_FILE"
    else
        log WARNING "Configuration file not found, using defaults"
    fi
}

load_signatures() {
    if [[ -f "$SIGNATURE_DB" ]]; then
        if command -v jq &> /dev/null; then
            log INFO "Signature database loaded"
        else
            log WARNING "jq not installed, signature parsing may be limited"
        fi
    else
        log ERROR "Signature database not found: $SIGNATURE_DB"
    fi
}

get_json_value() {
    local json_file="$1"
    local key="$2"
    if command -v jq &> /dev/null; then
        jq -r "$key" "$json_file" 2>/dev/null || echo ""
    else
        echo ""
    fi
}

# =============================================================================
# PROCESS MONITORING FUNCTIONS
# =============================================================================

detect_cryptominers() {
    log INFO "Scanning for cryptocurrency miners..."
    
    local threats_found=()
    
    # Check for known miner process names
    local miner_patterns
    miner_patterns=$(get_json_value "$SIGNATURE_DB" '.cryptominers.process_names[]' 2>/dev/null | tr '\n' '|' | sed 's/|$//')
    
    if [[ -n "$miner_patterns" ]]; then
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local pid
                local cmd
                pid=$(echo "$line" | awk '{print $2}')
                cmd=$(echo "$line" | cut -d' ' -f11-)
                
                if [[ -n "$pid" && "$pid" =~ ^[0-9]+$ ]]; then
                    # Check if process is in protected list
                    if [[ ! "$cmd" =~ $PROTECTED_PROCESSES ]]; then
                        threats_found+=("PID:$pid|CMD:$cmd")
                        send_alert "CRITICAL" "Cryptominer Detected" \
                            "Process: $cmd\nPID: $pid\nType: Known cryptominer signature" \
                            "kill -9 $pid"
                        
                        if [[ "${AUTO_KILL_CRITICAL:-false}" == "true" ]]; then
                            kill -9 "$pid" 2>/dev/null && log INFO "Killed cryptominer process $pid"
                        fi
                    fi
                fi
            fi
        done < <(ps aux | grep -iE "$miner_patterns" | grep -v grep | grep -v "monitor.sh")
    fi
    
    # Check for high CPU usage patterns
    if [[ "${CPU_THRESHOLD:-85}" -gt 0 ]]; then
        while IFS= read -r line; do
            local cpu
            local pid
            local cmd
            cpu=$(echo "$line" | awk '{print $3}' | cut -d. -f1)
            pid=$(echo "$line" | awk '{print $2}')
            cmd=$(echo "$line" | cut -d' ' -f11-)
            
            if [[ "$cpu" -gt "${CPU_THRESHOLD:-85}" && -n "$pid" ]]; then
                # Check if process has been running with high CPU for a while
                local runtime
                runtime=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
                if [[ -n "$runtime" && "$runtime" -gt "${CPU_DURATION_THRESHOLD:-300}" ]]; then
                    # Additional check for suspicious patterns
                    if echo "$cmd" | grep -qiE "(base64|decode|curl|wget| mining|pool|stratum|xmr)"; then
                        threats_found+=("PID:$pid|CPU:$cpu%")
                        send_alert "CRITICAL" "Suspicious High CPU Process" \
                            "Process: $cmd\nPID: $pid\nCPU: $cpu%\nRuntime: ${runtime}s" \
                            "Investigate with: ps -f -p $pid"
                    fi
                fi
            fi
        done < <(ps aux | awk '$3 > 50 {print}' | tail -20)
    fi
    
    # Check for deleted process executables (common miner technique)
    if [[ "${DETECT_DELETED_PROCESSES:-true}" == "true" ]]; then
        while IFS= read -r line; do
            local pid
            local exe
            pid=$(echo "$line" | awk '{print $1}')
            exe=$(echo "$line" | awk '{print $2}')
            
            if [[ -n "$pid" && "$exe" == "(deleted)" ]]; then
                local cmdline
                cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
                if [[ -n "$cmdline" && ! "$cmdline" =~ $PROTECTED_PROCESSES ]]; then
                    threats_found+=("DELETED_PID:$pid")
                    send_alert "CRITICAL" "Deleted Process Executable Detected" \
                        "PID: $pid\nCommand: $cmdline\nStatus: Running from deleted executable (fileless malware indicator)" \
                        "kill -9 $pid; check /proc/$pid/exe"
                fi
            fi
        done < <(ls -la /proc/*/exe 2>/dev/null | grep deleted | awk '{print $9,$11}')
    fi
    
    # Check /dev/shm for suspicious executables
    if [[ -d "/dev/shm" ]]; then
        while IFS= read -r file; do
            if [[ -n "$file" && -x "$file" ]]; then
                local file_hash
                file_hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
                send_alert "HIGH" "Executable in /dev/shm" \
                    "File: $file\nHash: $file_hash\nNote: /dev/shm is RAM-backed, often used for fileless attacks" \
                    "Investigate: file $file; ls -la $file"
            fi
        done < <(find /dev/shm -type f -executable 2>/dev/null | head -10)
    fi
    
    if [[ ${#threats_found[@]} -eq 0 ]]; then
        log INFO "No cryptominers detected"
    else
        log WARNING "Found ${#threats_found[@]} potential cryptominer indicators"
    fi
}

detect_rootkits() {
    log INFO "Scanning for rootkit indicators..."
    
    # Check for LD_PRELOAD hijacking
    if [[ "${DETECT_LD_PRELOAD:-true}" == "true" ]]; then
        if [[ -f "/etc/ld.so.preload" ]]; then
            local preload_content
            preload_content=$(cat /etc/ld.so.preload 2>/dev/null)
            if [[ -n "$preload_content" ]]; then
                # Check against whitelist
                local whitelist="libprocesshider|libc\.so|pam_unix|libns2|libncom"
                if echo "$preload_content" | grep -qE "$whitelist"; then
                    send_alert "CRITICAL" "LD_PRELOAD Rootkit Detected" \
                        "File: /etc/ld.so.preload\nContent: $preload_content\nType: Library injection rootkit" \
                        "Remove malicious libraries, check /etc/ld.so.preload"
                else
                    log INFO "LD_PRELOAD configured: $preload_content (review if unexpected)"
                fi
            fi
        fi
        
        # Check environment variables for LD_PRELOAD
        local env_preload
        env_preload=$(env | grep -i "LD_PRELOAD" 2>/dev/null)
        if [[ -n "$env_preload" ]]; then
            send_alert "CRITICAL" "LD_PRELOAD Environment Variable Set" \
                "LD_PRELOAD=$env_preload\nType: Runtime library injection" \
                "Investigate: echo $LD_PRELOAD; env | grep LD"
        fi
    fi
    
    # Check for suspicious kernel modules
    if [[ "${KERNEL_MODULE_MONITORING:-true}" == "true" ]]; then
        local suspicious_modules
        suspicious_modules=$(get_json_value "$SIGNATURE_DB" '.rootkits.kernel_module_indicators[]' 2>/dev/null | tr '\n' '|' | sed 's/|$//')
        
        if [[ -n "$suspicious_modules" ]]; then
            local found_modules
            found_modules=$(lsmod 2>/dev/null | grep -iE "$suspicious_modules" || true)
            if [[ -n "$found_modules" ]]; then
                send_alert "CRITICAL" "Suspicious Kernel Module Detected" \
                    "Modules:\n$found_modules\nType: Kernel-level rootkit" \
                    "Investigate: modinfo <module>; rmmod <module> (careful!)"
            fi
        fi
        
        # Check for hidden modules (module hiding technique)
        local sys_modules
        local lsmod_modules
        sys_modules=$(ls /sys/module/ 2>/dev/null | wc -l)
        lsmod_modules=$(lsmod 2>/dev/null | tail -n +2 | wc -l)
        
        if [[ $((sys_modules - lsmod_modules)) -gt 5 ]]; then
            send_alert "CRITICAL" "Possible Hidden Kernel Modules" \
                "sys/module count: $sys_modules\nlsmod count: $lsmod_modules\nDifference suggests module hiding" \
                "Investigate: ls /sys/module/ | diff - <(lsmod | awk 'NR>1 {print $1}')"
        fi
    fi
    
    # Check for hidden processes
    if [[ "${DETECT_HIDDEN_PROCESSES:-true}" == "true" ]]; then
        # Compare ps output with /proc using associative array for O(1) lookup
        local -A ps_pid_map
        local pid
        
        # Build hash map of ps PIDs for fast lookup
        while read -r pid; do
            [[ -n "$pid" ]] && ps_pid_map[$pid]=1
        done < <(ps aux | awk 'NR>1 {print $2}')
        
        # Check for processes hidden from ps but in /proc
        while read -r pid; do
            if [[ -d "/proc/$pid" && -z "${ps_pid_map[$pid]:-}" ]]; then
                local cmdline
                cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 100)
                if [[ -n "$cmdline" ]]; then
                    send_alert "CRITICAL" "Hidden Process Detected" \
                        "PID: $pid\nCommand: $cmdline\nType: Process hiding (rootkit indicator)" \
                        "Investigate: cat /proc/$pid/status; ls -la /proc/$pid/"
                fi
            fi
        done < <(ls /proc/ 2>/dev/null | grep -E '^[0-9]+$')
    fi
    
    # Check for Reptile rootkit indicators
    if [[ -d "/reptile" || -d "/lib/modules/$(uname -r)/kernel/drivers/reptile" ]]; then
        send_alert "CRITICAL" "Reptile Rootkit Detected" \
            "Reptile rootkit files found\nLocation: /reptile or kernel drivers" \
            "Emergency: System may be fully compromised. Consider rebuild."
    fi
    
    # Check for Diamorphine rootkit
    if [[ -f "/proc/diamorphine" || -d "/proc/diamorphine_hidden" ]]; then
        send_alert "CRITICAL" "Diamorphine Rootkit Detected" \
            "Diamorphine rootkit indicators found in /proc" \
            "Emergency: System may be fully compromised. Consider rebuild."
    fi
}

detect_backdoors() {
    log INFO "Scanning for backdoors..."
    
    # Check for suspicious SUID binaries
    if [[ "${SUID_CHECK:-true}" == "true" ]]; then
        local suid_list
        suid_list=$(find / -perm -4000 -type f 2>/dev/null | grep -vE "${SUID_WHITELIST:-\/usr\/bin\/passwd|\/usr\/bin\/sudo}" || true)
        
        while IFS= read -r file; do
            if [[ -n "$file" ]]; then
                # Check if in suspicious location
                if [[ "$file" =~ ^(/tmp/|/var/tmp/|/dev/shm/|/home/[^/]+/.local/) ]]; then
                    local file_info
                    file_info=$(ls -la "$file" 2>/dev/null)
                    send_alert "CRITICAL" "Suspicious SUID Binary" \
                        "File: $file\nDetails: $file_info\nType: Potential backdoor (SUID in temp location)" \
                        "Remove: rm -f $file; Check: file $file; sha256sum $file"
                fi
            fi
        done <<< "$suid_list"
    fi
    
    # Check for reverse shells
    local reverse_shell_patterns
    reverse_shell_patterns=$(get_json_value "$SIGNATURE_DB" '.backdoors.reverse_shell_patterns[]' 2>/dev/null | tr '\n' '|' | sed 's/|$//')
    
    if [[ -n "$reverse_shell_patterns" ]]; then
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local pid
                local cmd
                pid=$(echo "$line" | awk '{print $2}')
                cmd=$(echo "$line" | cut -d' ' -f11-)
                
                send_alert "CRITICAL" "Reverse Shell Detected" \
                    "PID: $pid\nCommand: $cmd\nType: Active reverse shell connection" \
                    "Kill: kill -9 $pid; Investigate: lsof -p $pid"
                
                if [[ "${AUTO_KILL_CRITICAL:-false}" == "true" ]]; then
                    kill -9 "$pid" 2>/dev/null
                fi
            fi
        done < <(ps aux | grep -iE "$reverse_shell_patterns" | grep -v grep | grep -v monitor.sh)
    fi
    
    # Check for web shells
    if [[ ${#WEB_DIRS[@]} -gt 0 ]]; then
        local web_shell_patterns
        web_shell_patterns=$(get_json_value "$SIGNATURE_DB" '.backdoors.web_shell_signatures[]' 2>/dev/null | tr '\n' '|' | sed 's/|$//')
        
        for webdir in "${WEB_DIRS[@]}"; do
            if [[ -d "$webdir" ]]; then
                while IFS= read -r file; do
                    if [[ -n "$file" ]]; then
                        send_alert "HIGH" "Potential Web Shell" \
                            "File: $file\nType: Suspicious PHP/code patterns detected" \
                            "Investigate: cat $file | head -50; Check file history"
                    fi
                done < <(timeout 30 find "$webdir" -type f \( -name "*.php" -o -name "*.pl" -o -name "*.py" -o -name "*.jsp" -o -name "*.asp" -o -name "*.aspx" \) -exec grep -lE "$web_shell_patterns" {} \; 2>/dev/null | head -10)
            fi
        done
    fi
}

detect_ransomware() {
    log INFO "Scanning for ransomware indicators..."
    
    # Check for ransomware file extensions
    local ransom_extensions
    ransom_extensions=$(get_json_value "$SIGNATURE_DB" '.ransomware.file_extensions[]' 2>/dev/null | tr '\n' '|' | sed 's/\./\\./g' | sed 's/|$//')
    
    if [[ -n "$ransom_extensions" ]]; then
        local found_files
        found_files=$(find /home /var/www /opt /root -type f 2>/dev/null | grep -iE "($ransom_extensions)$" | head -20 || true)
        
        if [[ -n "$found_files" ]]; then
            send_alert "CRITICAL" "Ransomware Indicators Detected" \
                "Encrypted files found:\n$found_files\n\nType: Possible ransomware infection" \
                "1. ISOLATE SYSTEM IMMEDIATELY\n2. Do not pay ransom\n3. Check backups\n4. Incident response required"
        fi
    fi
    
    # Check for ransom notes
    local ransom_notes
    ransom_notes=$(get_json_value "$SIGNATURE_DB" '.ransomware.ransom_notes[]' 2>/dev/null | tr '\n' '|' | sed 's/|$//')
    
    if [[ -n "$ransom_notes" ]]; then
        local found_notes
        found_notes=$(find /home /root /var/www /opt -type f -iname "*README*" -o -type f -iname "*DECRYPT*" -o -type f -iname "*RECOVER*" 2>/dev/null | grep -iE "($ransom_notes)" | head -10 || true)
        
        if [[ -n "$found_notes" ]]; then
            send_alert "CRITICAL" "Ransom Note Found" \
                "Ransom notes detected:\n$found_notes\n\nType: Active ransomware infection" \
                "EMERGENCY: System compromised. Isolate immediately."
        fi
    fi
    
    # Monitor for rapid file modification (behavioral)
    # This is a simplified check - in production, use inotify or auditd
    local recent_modifications
    recent_modifications=$(find /home /var/www -type f -mmin -5 2>/dev/null | wc -l)
    
    if [[ "$recent_modifications" -gt 1000 ]]; then
        send_alert "HIGH" "Mass File Modification Detected" \
            "Files modified in last 5 minutes: $recent_modifications\nType: Possible ransomware activity" \
            "Investigate: find /home -type f -mmin -5 | head -20"
    fi
}

detect_container_escapes() {
    log INFO "Scanning for container security issues..."
    
    # Check if running in container
    if [[ -f "/.dockerenv" ]] || grep -qE "docker|kubepods" /proc/1/cgroup 2>/dev/null; then
        log INFO "Running inside container - checking for escape indicators"
        
        # Check for docker socket access
        if [[ -S "/var/run/docker.sock" || -S "${DOCKER_SOCKET:-/var/run/docker.sock}" ]]; then
            if [[ -r "/var/run/docker.sock" || -w "/var/run/docker.sock" ]]; then
                send_alert "CRITICAL" "Container with Docker Socket Access" \
                    "Container has read/write access to Docker socket\nType: Container escape risk" \
                    "Remove docker socket mount from container"
            fi
        fi
        
        # Check for privileged mode
        if [[ -f "/proc/1/status" ]]; then
            local cap_eff
            cap_eff=$(awk '/CapEff/{print $2}' /proc/1/status 2>/dev/null)
            if [[ "$cap_eff" == "0000003fffffffff" || "$cap_eff" == "0000001fffffffff" ]]; then
                send_alert "CRITICAL" "Privileged Container Detected" \
                    "Container running in privileged mode\nCapabilities: $cap_eff\nType: Full host access risk" \
                    "Remove --privileged flag, use specific capabilities instead"
            fi
        fi
        
        # Check for host namespace sharing
        if [[ -f "/proc/1/mountinfo" ]]; then
            if grep -q " / / " /proc/1/mountinfo 2>/dev/null; then
                send_alert "HIGH" "Container with Host Root Mounted" \
                    "Container has host root filesystem mounted\nType: Container escape risk" \
                    "Remove host root mount from container"
            fi
        fi
    fi
    
    # Check host for suspicious container activity
    if command -v docker &> /dev/null; then
        # Check for containers with suspicious mounts
        local suspicious_mounts
        suspicious_mounts=$(docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Mounts}}" 2>/dev/null | grep -E "(/:/mnt|/root:/root|docker\.sock)" || true)
        
        if [[ -n "$suspicious_mounts" ]]; then
            send_alert "HIGH" "Suspicious Container Mounts" \
                "Containers with dangerous mounts:\n$suspicious_mounts" \
                "Review: docker inspect <container_id> | grep -A5 Mounts"
        fi
        
        # Check for privileged containers
        local privileged_containers
        privileged_containers=$(docker ps --format "{{.ID}}\t{{.Names}}\t{{.Image}}" --filter "privileged=true" 2>/dev/null || true)
        
        if [[ -n "$privileged_containers" ]]; then
            send_alert "HIGH" "Privileged Containers Running" \
                "Privileged containers:\n$privileged_containers\nType: Full host access" \
                "Review necessity: docker inspect --format='{{.HostConfig.Privileged}}' <id>"
        fi
    fi
}

detect_network_threats() {
    log INFO "Scanning for network-based threats..."
    
    # Check for suspicious network connections
    local suspicious_ports
    suspicious_ports=$(get_json_value "$SIGNATURE_DB" '.botnets_c2.suspicious_ports[]' 2>/dev/null | tr '\n' '|' | sed 's/|$//')
    
    if [[ -n "$suspicious_ports" ]]; then
        local suspicious_conns
        suspicious_conns=$(ss -tulpn 2>/dev/null | grep -E ":($suspicious_ports)" || \
                          netstat -tulpn 2>/dev/null | grep -E ":($suspicious_ports)" || true)
        
        if [[ -n "$suspicious_conns" ]]; then
            send_alert "HIGH" "Suspicious Ports Open" \
                "Suspicious ports listening:\n$suspicious_conns\nType: Possible backdoor/C2" \
                "Investigate: lsof -i :<port>; ss -p | grep <port>"
        fi
    fi
    
    # Check for IRC connections (botnet indicator)
    local irc_patterns
    irc_patterns=$(get_json_value "$SIGNATURE_DB" '.botnets_c2.irc_botnet_signatures[]' 2>/dev/null | head -3 | tr '\n' '|' | sed 's/|$//')
    
    if [[ -n "$irc_patterns" ]]; then
        local irc_conns
        irc_conns=$(ss -tulpn 2>/dev/null | grep -E ":666[5-7]" || true)
        
        if [[ -n "$irc_conns" ]]; then
            send_alert "HIGH" "IRC Connection Detected" \
                "IRC connections found:\n$irc_conns\nType: Possible botnet C2" \
                "Investigate: ss -p | grep 666; lsof -i :6667"
        fi
    fi
    
    # Check for DNS tunneling indicators
    if [[ "${DNS_MONITORING:-true}" == "true" ]]; then
        # High volume of DNS queries
        local dns_queries
        dns_queries=$(ss -tan 2>/dev/null | grep -c ":53 " || echo "0")
        
        if [[ "$dns_queries" -gt 100 ]]; then
            send_alert "MEDIUM" "High DNS Query Volume" \
                "Current DNS connections: $dns_queries\nType: Possible DNS tunneling" \
                "Investigate: tcpdump -i any port 53 | head -50"
        fi
    fi
    
    # Check for connections to known malicious IPs
    if [[ ${#BLOCKLIST_URLS[@]} -gt 0 ]]; then
        local blocklist_file="${WORK_DIR}/.blocklist.cache"
        
        # Update blocklist daily
        if [[ ! -f "$blocklist_file" ]] || [[ $(find "$blocklist_file" -mtime +1 2>/dev/null) ]]; then
            > "$blocklist_file"
            for url in "${BLOCKLIST_URLS[@]}"; do
                # Download and validate IPs strictly (allow CIDR notation)
                curl -s -m 10 "$url" 2>/dev/null | \
                    grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$' | \
                    while read -r ip; do
                        # Validate each octet is 0-255
                        if [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}) ]]; then
                            local valid=true
                            for octet in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
                                if [[ "$octet" -gt 255 ]]; then
                                    valid=false
                                    break
                                fi
                            done
                            [[ "$valid" == true ]] && echo "$ip"
                        fi
                    done >> "$blocklist_file" || true
            done
        fi
        
        # Check current connections against blocklist
        if [[ -s "$blocklist_file" ]]; then
            local active_connections
            active_connections=$(ss -tan 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | sort -u || true)
            
            local matches
            matches=$(echo "$active_connections" | grep -F -f "$blocklist_file" | head -10 || true)
            
            if [[ -n "$matches" ]]; then
                send_alert "CRITICAL" "Connection to Known Malicious IP" \
                    "Active connections to blocklisted IPs:\n$matches\nType: Possible C2 communication" \
                    "Block immediately: iptables -A OUTPUT -d <ip> -j DROP"
            fi
        fi
    fi
}

detect_ssh_attacks() {
    log INFO "Scanning for SSH attacks..."
    
    # Check auth.log for brute force attempts
    if [[ -f "/var/log/auth.log" ]]; then
        local failed_attempts
        failed_attempts=$(grep -E "Failed password|authentication failure" /var/log/auth.log 2>/dev/null | tail -100 | wc -l)
        
        if [[ "$failed_attempts" -gt "${BRUTE_FORCE_THRESHOLD:-5}" ]]; then
            # Get attacking IPs
            local attacking_ips
            attacking_ips=$(grep -E "Failed password" /var/log/auth.log 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -rn | head -5)
            
            send_alert "HIGH" "SSH Brute Force Attack" \
                "Failed attempts: $failed_attempts (last 100 lines)\nTop attacking IPs:\n$attacking_ips" \
                "1. Enable fail2ban\n2. Consider key-only auth\n3. Change SSH port\n4. Block IPs: iptables -A INPUT -s <ip> -j DROP"
        fi
        
        # Check for successful root logins
        if [[ "${ALERT_ROOT_LOGIN:-true}" == "true" ]]; then
            local root_logins
            root_logins=$(grep -E "Accepted.*for root" /var/log/auth.log 2>/dev/null | tail -5)
            
            if [[ -n "$root_logins" ]]; then
                # Check if from new IP
                local last_login_ip
                last_login_ip=$(echo "$root_logins" | tail -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
                
                if [[ -n "$last_login_ip" ]]; then
                    send_alert "MEDIUM" "Root Login Detected" \
                        "Root login from: $last_login_ip\nRecent root logins:\n$(echo "$root_logins" | tail -3)" \
                        "Verify legitimacy: last root; Check: grep 'root' /var/log/auth.log | tail -10"
                fi
            fi
        fi
    fi
    
    # Check for authorized_keys modifications
    if [[ "${MONITOR_AUTHORIZED_KEYS:-true}" == "true" ]]; then
        local auth_keys_files
        auth_keys_files=$(find /root /home -name "authorized_keys" -type f 2>/dev/null)
        
        for keys_file in $auth_keys_files; do
            if [[ -f "$keys_file" ]]; then
                local key_count
                key_count=$(wc -l < "$keys_file" 2>/dev/null)
                
                # Check for suspicious keys
                local suspicious_keys
                suspicious_keys=$(grep -E "(command=|no-pty|permitopen)" "$keys_file" 2>/dev/null || true)
                
                if [[ -n "$suspicious_keys" ]]; then
                    send_alert "HIGH" "Suspicious SSH Key Found" \
                        "File: $keys_file\nSuspicious entries:\n$suspicious_keys\nType: Possible backdoor key" \
                        "Review: cat $keys_file; Remove suspicious keys"
                fi
            fi
        done
    fi
}

detect_persistence() {
    log INFO "Scanning for persistence mechanisms..."
    
    # Check cron jobs
    local cron_files
    cron_files=$(find /etc/cron* /var/spool/cron -type f 2>/dev/null)
    
    for cron_file in $cron_files; do
        if [[ -f "$cron_file" ]]; then
            local cron_content
            cron_content=$(cat "$cron_file" 2>/dev/null)
            
            # Check for suspicious patterns in cron
            if echo "$cron_content" | grep -qE "(curl|wget|fetch|base64|decode|eval|\/dev\/tcp|\/dev\/udp)"; then
                send_alert "CRITICAL" "Suspicious Cron Job" \
                    "File: $cron_file\nContent:\n$(echo "$cron_content" | grep -E "(curl|wget|fetch|base64|decode|eval)" | head -5)" \
                    "Investigate: cat $cron_file; Check creation time: stat $cron_file"
            fi
        fi
    done
    
    # Check systemd services
    local systemd_services
    systemd_services=$(find /etc/systemd/system /lib/systemd/system -name "*.service" -type f 2>/dev/null)
    
    for service in $systemd_services; do
        if [[ -f "$service" ]]; then
            local service_content
            service_content=$(cat "$service" 2>/dev/null)
            
            # Check for suspicious service configurations
            if echo "$service_content" | grep -qE "(ExecStart.*curl|ExecStart.*wget|ExecStart.*base64|ExecStart.*\/dev\/tcp)"; then
                send_alert "CRITICAL" "Suspicious Systemd Service" \
                    "File: $service\nSuspicious ExecStart detected" \
                    "Investigate: cat $service; systemctl cat $(basename $service)"
            fi
        fi
    done
    
    # Check shell profile files
    local profile_files
    profile_files=$(find /root /home -maxdepth 2 -name ".bashrc" -o -name ".bash_profile" -o -name ".profile" -o -name ".zshrc" 2>/dev/null)
    
    for profile in $profile_files; do
        if [[ -f "$profile" ]]; then
            local profile_content
            profile_content=$(cat "$profile" 2>/dev/null)
            
            # Check for suspicious additions
            if echo "$profile_content" | grep -qE "(curl.*\|.*bash|wget.*\|.*sh|base64.*\|.*decode|eval\s*\()"; then
                send_alert "CRITICAL" "Suspicious Shell Profile Modification" \
                    "File: $profile\nSuspicious content detected" \
                    "Investigate: cat $profile | tail -20; Check: stat $profile"
            fi
        fi
    done
    
    # Check for new systemd timers
    local systemd_timers
    systemd_timers=$(find /etc/systemd/system /lib/systemd/system -name "*.timer" -type f -mtime -7 2>/dev/null)
    
    if [[ -n "$systemd_timers" ]]; then
        send_alert "MEDIUM" "New Systemd Timer Detected" \
            "Recently created timers:\n$systemd_timers" \
            "Review: systemctl list-timers --all"
    fi
}

detect_file_integrity() {
    log INFO "Checking file integrity..."
    
    if [[ "${FIM_ENABLED:-true}" != "true" ]]; then
        return
    fi
    
    local baseline_dir="${WORK_DIR}/.baseline"
    mkdir -p "$baseline_dir"
    
    # Check critical files
    for file in "${CRITICAL_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            local current_hash
            local stored_hash_file
            current_hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
            stored_hash_file="${baseline_dir}$(echo "$file" | tr '/' '_').hash"
            
            if [[ -f "$stored_hash_file" ]]; then
                local stored_hash
                stored_hash=$(cat "$stored_hash_file" 2>/dev/null)
                
                if [[ "$current_hash" != "$stored_hash" ]]; then
                    send_alert "HIGH" "Critical File Modified" \
                        "File: $file\nOld hash: $stored_hash\nNew hash: $current_hash" \
                        "Investigate: diff <(echo $stored_hash) <(echo $current_hash); Check: stat $file"
                fi
            else
                # First run - create baseline
                echo "$current_hash" > "$stored_hash_file"
                log INFO "Created baseline for $file"
            fi
        fi
    done
}

detect_cloud_metadata_abuse() {
    log INFO "Checking for cloud metadata exploitation..."
    
    # Check for IMDSv1 exploitation attempts
    local cloud_patterns
    cloud_patterns=$(get_json_value "$SIGNATURE_DB" '.cloud_metadata_exploitation.indicators[]' 2>/dev/null | tr '\n' '|' | sed 's/|$//')
    
    if [[ -n "$cloud_patterns" ]]; then
        # Check running processes
        local suspicious_processes
        suspicious_processes=$(ps aux 2>/dev/null | grep -iE "$cloud_patterns" | grep -v grep | grep -v monitor.sh || true)
        
        if [[ -n "$suspicious_processes" ]]; then
            send_alert "CRITICAL" "Cloud Metadata Service Exploitation" \
                "Suspicious processes accessing metadata service:\n$suspicious_processes\nType: Credential theft attempt" \
                "Investigate: ps -f -p <pid>; Check AWS/Cloud provider logs"
        fi
        
        # Check for recent access to metadata IP
        if command -v ss &> /dev/null; then
            local metadata_conns
            metadata_conns=$(ss -tan 2>/dev/null | grep "169.254.169.254" || true)
            
            if [[ -n "$metadata_conns" ]]; then
                send_alert "HIGH" "Active Metadata Service Connection" \
                    "Active connections to metadata service:\n$metadata_conns" \
                    "Investigate: ss -p | grep 169.254.169.254"
            fi
        fi
    fi
}

detect_redis_exploitation() {
    log INFO "Checking for Redis exploitation..."
    
    # Check for Redis processes
    if pgrep -x "redis-server" &> /dev/null; then
        # Check for suspicious Redis commands in process list
        local redis_patterns
        redis_patterns=$(get_json_value "$SIGNATURE_DB" '.redis_exploitation.indicators[]' 2>/dev/null | tr '\n' '|' | sed 's/|$//')
        
        if [[ -n "$redis_patterns" ]]; then
            local suspicious_redis
            suspicious_redis=$(ps aux 2>/dev/null | grep -iE "$redis_patterns" | grep -v grep || true)
            
            if [[ -n "$suspicious_redis" ]]; then
                send_alert "CRITICAL" "Redis Exploitation Detected" \
                    "Suspicious Redis activity:\n$suspicious_redis\nType: Possible RedisRaider or similar attack" \
                    "1. Check Redis auth: redis-cli AUTH\n2. Review config: redis-cli CONFIG GET *\n3. Check for rogue modules"
            fi
        fi
        
        # Check if Redis is bound to all interfaces without auth
        local redis_config
        redis_config=$(find /etc -name "redis*.conf" -type f 2>/dev/null | head -1)
        
        if [[ -f "$redis_config" ]]; then
            if grep -qE "^bind 0\.0\.0\.0" "$redis_config" 2>/dev/null && ! grep -qE "^requirepass" "$redis_config" 2>/dev/null; then
                send_alert "HIGH" "Insecure Redis Configuration" \
                    "Redis bound to 0.0.0.0 without password\nConfig: $redis_config" \
                    "1. Set requirepass\n2. Bind to specific IPs\n3. Enable protected-mode"
            fi
        fi
    fi
}

detect_docker_api_abuse() {
    log INFO "Checking for Docker API abuse..."
    
    # Check if Docker API is exposed
    local docker_patterns
    docker_patterns=$(get_json_value "$SIGNATURE_DB" '.docker_api_abuse.indicators[]' 2>/dev/null | tr '\n' '|' | sed 's/|$//')
    
    # Check for exposed Docker daemon
    if ss -tulpn 2>/dev/null | grep -qE ":237[56]"; then
        send_alert "CRITICAL" "Docker API Exposed" \
            "Docker daemon listening on TCP port (2375/2376)\nType: Container escape and host compromise risk" \
            "1. Disable TCP socket\n2. Use Unix socket with proper permissions\n3. Enable TLS if remote access needed"
    fi
    
    # Check for suspicious Docker API usage
    if [[ -n "$docker_patterns" ]]; then
        local suspicious_docker
        suspicious_docker=$(ps aux 2>/dev/null | grep -iE "$docker_patterns" | grep -v grep | grep -v monitor.sh || true)
        
        if [[ -n "$suspicious_docker" ]]; then
            send_alert "CRITICAL" "Suspicious Docker API Usage" \
                "Suspicious Docker commands:\n$suspicious_docker" \
                "Investigate: Check Docker logs; Review container creation events"
        fi
    fi
}

# =============================================================================
# TELEGRAM NOTIFICATION FUNCTION
# =============================================================================

send_alert() {
    local severity="$1"
    local title="$2"
    local details="$3"
    local recommendation="${4:-No specific recommendation}"
    
    # Check if Telegram is enabled
    if [[ "${TELEGRAM_ENABLED:-false}" != "true" ]]; then
        log INFO "Telegram disabled, logging locally only"
        log "$severity" "$title: $details"
        return
    fi
    
    # Check alert cooldown
    local alert_key
    alert_key=$(echo "$title" | sha256sum | awk '{print $1}')
    local state_file="${ALERT_STATE_DIR}/${alert_key}"
    
    local cooldown=0
    case "$severity" in
        CRITICAL) cooldown="${ALERT_COOLDOWN_CRITICAL:-0}" ;;
        HIGH) cooldown="${ALERT_COOLDOWN_HIGH:-60}" ;;
        MEDIUM) cooldown="${ALERT_COOLDOWN_MEDIUM:-300}" ;;
        LOW) cooldown="${ALERT_COOLDOWN_LOW:-3600}" ;;
    esac
    
    if [[ -f "$state_file" ]]; then
        local last_alert
        last_alert=$(cat "$state_file" 2>/dev/null)
        local current_time
        current_time=$(date +%s)
        
        if [[ $((current_time - last_alert)) -lt "$cooldown" ]]; then
            log DEBUG "Alert cooldown active for: $title"
            return
        fi
    fi
    
    # Update alert state
    date +%s > "$state_file"
    
    # Determine emoji based on severity
    local emoji
    case "$severity" in
        CRITICAL) emoji="🚨" ;;
        HIGH) emoji="⚠️" ;;
        MEDIUM) emoji="🔶" ;;
        LOW) emoji="ℹ️" ;;
        *) emoji="📋" ;;
    esac
    
    # Format message
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S UTC')
    
    local hostname
    hostname="${HOSTNAME:-$(hostname)}"
    
    local public_ip
    public_ip="${PUBLIC_IP:-$(curl -s -m 3 ifconfig.me 2>/dev/null || echo 'unknown')}"
    
    # Escape special Markdown characters in details and recommendation
    local escaped_details escaped_recommendation
    escaped_details=$(echo "$details" | sed 's/[_*\[\]()~`>#+=|{}.!-]/\\&/g')
    escaped_recommendation=$(echo "$recommendation" | sed 's/[_*\[\]()~`>#+=|{}.!-]/\\&/g')
    
    # Build Telegram message
    local message
    message=$(cat <<EOF
${emoji} *${severity}: ${title}*

*Host:* \`${hostname} (${public_ip})\`
*Time:* \`${timestamp}\`

*Details:*
\`\`\`
${escaped_details}
\`\`\`

*Recommended Actions:*
\`\`\`
${escaped_recommendation}
\`\`\`
EOF
)
    
    # Add auto-response status
    if [[ "${AUTO_RESPONSE_ENABLED:-false}" == "true" ]]; then
        if [[ "$severity" == "CRITICAL" && "${AUTO_KILL_CRITICAL:-false}" == "true" ]]; then
            message="${message}

*Auto-Response:* Process terminated ✓"
        else
            message="${message}

*Auto-Response:* Disabled (manual intervention required)"
        fi
    fi
    
    # Send to Telegram
    local telegram_url="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"
    
    local response
    response=$(curl -s -X POST "$telegram_url" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        -d "text=${message}" \
        -d "parse_mode=Markdown" \
        -d "disable_web_page_preview=true" \
        -m 10 2>/dev/null)
    
    if echo "$response" | grep -q '"ok":true'; then
        log INFO "Telegram alert sent: $title"
        echo "[$timestamp] [$severity] $title" >> "${LOG_DIR}/alerts.log"
    else
        log ERROR "Failed to send Telegram alert: $response"
    fi
}

# =============================================================================
# SUMMARY AND REPORTING FUNCTIONS
# =============================================================================

send_daily_summary() {
    log INFO "Generating daily summary..."
    
    if [[ "${TELEGRAM_ENABLED:-false}" != "true" ]] || [[ "${SEND_DAILY_SUMMARY:-true}" != "true" ]]; then
        return
    fi
    
    local hostname
    hostname="${HOSTNAME:-$(hostname)}"
    
    local public_ip
    public_ip="${PUBLIC_IP:-$(curl -s -m 3 ifconfig.me 2>/dev/null || echo 'unknown')}"
    
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S UTC')
    
    # Gather statistics
    local uptime_info
    uptime_info=$(uptime 2>/dev/null || echo "N/A")
    
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | xargs)
    
    local cpu_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    
    local memory_usage
    memory_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    
    local disk_usage
    disk_usage=$(df -h / | tail -1 | awk '{print $5}')
    
    local active_users
    active_users=$(who | wc -l)
    
    local failed_ssh
    failed_ssh=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo "0")
    
    local active_connections
    active_connections=$(ss -tan 2>/dev/null | wc -l || netstat -tan 2>/dev/null | wc -l || echo "N/A")
    
    # Process counts
    local total_processes
    total_processes=$(ps aux 2>/dev/null | wc -l)
    
    local docker_containers
    docker_containers=$(docker ps -q 2>/dev/null | wc -l || echo "0")
    
    # Alert counts from log
    local critical_alerts
    critical_alerts=$(grep -c "CRITICAL" "${LOG_DIR}/alerts.log" 2>/dev/null || echo "0")
    
    local high_alerts
    high_alerts=$(grep -c "HIGH" "${LOG_DIR}/alerts.log" 2>/dev/null || echo "0")
    
    # Build summary message
    local message
    message=$(cat <<EOF
📊 *Daily Security Summary*

*Host:* \`${hostname} (${public_ip})\`
*Report Time:* \`${timestamp}\`
*Period:* Last 24 hours

*System Status:*
├─ Uptime: \`${uptime_info}\`
├─ Load Average: \`${load_avg}\`
├─ CPU Usage: \`${cpu_usage}%\`
├─ Memory Usage: \`${memory_usage}%\`
├─ Disk Usage: \`${disk_usage}\`
└─ Active Users: \`${active_users}\`

*Security Metrics:*
├─ Failed SSH Attempts: \`${failed_ssh}\`
├─ Active Connections: \`${active_connections}\`
├─ Total Processes: \`${total_processes}\`
├─ Docker Containers: \`${docker_containers}\`
├─ Critical Alerts: \`${critical_alerts}\`
└─ High Alerts: \`${high_alerts}\`

*Top Processes by CPU:*
\`\`\`
$(ps aux --sort=-%cpu | head -6 | tail -5 | awk '{printf "%-8s %5s %5s %s\n", $1, $3, $4, $11}')
\`\`\`

*Top Processes by Memory:*
\`\`\`
$(ps aux --sort=-%mem | head -6 | tail -5 | awk '{printf "%-8s %5s %5s %s\n", $1, $3, $4, $11}')
\`\`\`

_Monitor is running normally. Next report: Tomorrow at ${DAILY_SUMMARY_TIME:-08:00}_
EOF
)
    
    # Send to Telegram
    local telegram_url="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"
    
    curl -s -X POST "$telegram_url" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        -d "text=${message}" \
        -d "parse_mode=Markdown" \
        -d "disable_web_page_preview=true" \
        -m 15 2>/dev/null
    
    log INFO "Daily summary sent"
}

send_weekly_report() {
    log INFO "Generating weekly report..."
    
    if [[ "${TELEGRAM_ENABLED:-false}" != "true" ]] || [[ "${SEND_WEEKLY_REPORT:-true}" != "true" ]]; then
        return
    fi
    
    local hostname
    hostname="${HOSTNAME:-$(hostname)}"
    
    local public_ip
    public_ip="${PUBLIC_IP:-$(curl -s -m 3 ifconfig.me 2>/dev/null || echo 'unknown')}"
    
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S UTC')
    
    # Calculate weekly stats
    local total_alerts
    total_alerts=$(wc -l < "${LOG_DIR}/alerts.log" 2>/dev/null || echo "0")
    
    local critical_count
    critical_count=$(grep -c "CRITICAL" "${LOG_DIR}/alerts.log" 2>/dev/null || echo "0")
    
    local high_count
    high_count=$(grep -c "HIGH" "${LOG_DIR}/alerts.log" 2>/dev/null || echo "0")
    
    # Build report message
    local message
    message=$(cat <<EOF
📈 *Weekly Security Report*

*Host:* \`${hostname} (${public_ip})\`
*Report Time:* \`${timestamp}\`
*Period:* Last 7 days

*Alert Summary:*
├─ Total Alerts: \`${total_alerts}\`
├─ Critical: \`${critical_count}\`
├─ High: \`${high_count}\`
└─ Security Score: \`$(if [[ "$critical_count" -eq 0 ]]; then echo "✅ Good"; else echo "⚠️ Review Needed"; fi)\`

*Recommendations:*
$(if [[ "$critical_count" -gt 0 ]]; then echo "• Review all critical alerts immediately"; fi)
$(if [[ "$high_count" -gt 5 ]]; then echo "• Investigate recurring high-severity issues"; fi)
• Keep system packages updated
• Review user access regularly
• Verify backup integrity

_Next report: Next ${WEEKLY_REPORT_DAY:-Sunday} at ${WEEKLY_REPORT_TIME:-09:00}_
EOF
)
    
    # Send to Telegram
    local telegram_url="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"
    
    curl -s -X POST "$telegram_url" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        -d "text=${message}" \
        -d "parse_mode=Markdown" \
        -d "disable_web_page_preview=true" \
        -m 15 2>/dev/null
    
    log INFO "Weekly report sent"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

show_help() {
    cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION}

Usage: $(basename "$0") [OPTIONS] [COMMAND]

Commands:
    quick           Run quick scan (processes, network, users)
    deep            Run deep scan (rootkits, malware signatures)
    full            Run full system audit
    monitor         Start continuous monitoring (default)
    summary         Send daily summary report
    weekly          Send weekly report
    test-telegram   Test Telegram connectivity
    help            Show this help message

Options:
    -c, --config    Specify config file (default: $CONFIG_FILE)
    -v, --verbose   Enable verbose output
    -d, --debug     Enable debug mode
    --dry-run       Detect but don't send alerts

Examples:
    $(basename "$0") quick                    # Quick security scan
    $(basename "$0") deep                     # Deep security scan
    $(basename "$0") monitor                  # Start monitoring
    $(basename "$0") -c /path/to/config.conf  # Use custom config

EOF
}

run_quick_scan() {
    log INFO "Starting quick security scan..."
    
    detect_cryptominers
    detect_ssh_attacks
    detect_network_threats
    detect_file_integrity
    
    log INFO "Quick scan completed"
}

run_deep_scan() {
    log INFO "Starting deep security scan..."
    
    detect_cryptominers
    detect_rootkits
    detect_backdoors
    detect_ransomware
    detect_container_escapes
    detect_ssh_attacks
    detect_network_threats
    detect_persistence
    detect_file_integrity
    detect_cloud_metadata_abuse
    detect_redis_exploitation
    detect_docker_api_abuse
    
    log INFO "Deep scan completed"
}

run_full_audit() {
    log INFO "Starting full system audit..."
    
    # Run all detection modules
    run_deep_scan
    
    # Additional audit checks
    log INFO "Running additional audit checks..."
    
    # Check for unowned files
    if [[ "${UNOWNED_FILES_CHECK:-true}" == "true" ]]; then
        local unowned_files
        unowned_files=$(find / -nouser -nogroup -type f 2>/dev/null | head -20)
        
        if [[ -n "$unowned_files" ]]; then
            send_alert "MEDIUM" "Unowned Files Found" \
                "Files without valid owner/group:\n$(echo "$unowned_files" | head -10)" \
                "Review and fix ownership: chown user:group <file>"
        fi
    fi
    
    # Check for world-writable files
    if [[ "${WORLD_WRITABLE_CHECK:-true}" == "true" ]]; then
        local world_writable
        world_writable=$(find / -xdev -type f -perm -0002 2>/dev/null | grep -v "/proc/" | head -20)
        
        if [[ -n "$world_writable" ]]; then
            send_alert "MEDIUM" "World-Writable Files Found" \
                "World-writable files:\n$(echo "$world_writable" | head -10)" \
                "Review permissions: chmod o-w <file>"
        fi
    fi
    
    # Run external tools if enabled
    if [[ "${RKHUNTER_ENABLED:-true}" == "true" ]] && [[ -x "${RKHUNTER_PATH:-/usr/bin/rkhunter}" ]]; then
        log INFO "Running RKHunter..."
        "${RKHUNTER_PATH:-/usr/bin/rkhunter}" --check --sk --nocolors 2>/dev/null | tail -50 >> "${LOG_DIR}/rkhunter.log"
    fi
    
    if [[ "${CHKROOTKIT_ENABLED:-true}" == "true" ]] && [[ -x "${CHKROOTKIT_PATH:-/usr/sbin/chkrootkit}" ]]; then
        log INFO "Running Chkrootkit..."
        "${CHKROOTKIT_PATH:-/usr/sbin/chkrootkit}" 2>/dev/null | tail -50 >> "${LOG_DIR}/chkrootkit.log"
    fi
    
    log INFO "Full audit completed"
}

start_monitoring() {
    log INFO "Starting continuous monitoring..."
    
    # Create PID file
    echo $$ > "$PID_FILE"
    
    # Set up signal handlers
    trap 'log INFO "Monitoring stopped"; rm -f "$PID_FILE"; exit 0' SIGTERM SIGINT
    
    local last_quick_scan=0
    local last_deep_scan=0
    local last_full_audit=0
    local last_summary=0
    local last_weekly=0
    
    while true; do
        local current_time
        current_time=$(date +%s)
        
        # Real-time checks (every interval)
        detect_cryptominers
        detect_network_threats
        
        # Quick scan (hourly)
        if [[ $((current_time - last_quick_scan)) -ge "${QUICK_SCAN_INTERVAL:-3600}" ]]; then
            run_quick_scan
            last_quick_scan=$current_time
        fi
        
        # Deep scan (daily)
        if [[ $((current_time - last_deep_scan)) -ge "${DEEP_SCAN_INTERVAL:-86400}" ]]; then
            run_deep_scan
            last_deep_scan=$current_time
        fi
        
        # Full audit (weekly)
        if [[ $((current_time - last_full_audit)) -ge "${FULL_AUDIT_INTERVAL:-604800}" ]]; then
            run_full_audit
            last_full_audit=$current_time
        fi
        
        # Daily summary
        if [[ "${SEND_DAILY_SUMMARY:-true}" == "true" ]]; then
            local current_hour
            current_hour=$(date +%H:%M)
            if [[ "$current_hour" == "${DAILY_SUMMARY_TIME:-08:00}" ]] && [[ $((current_time - last_summary)) -ge 82800 ]]; then
                send_daily_summary
                last_summary=$current_time
            fi
        fi
        
        # Weekly report
        if [[ "${SEND_WEEKLY_REPORT:-true}" == "true" ]]; then
            local current_day
            current_day=$(date +%A)
            local current_hour
            current_hour=$(date +%H:%M)
            if [[ "$current_day" == "${WEEKLY_REPORT_DAY:-Sunday}" ]] && [[ "$current_hour" == "${WEEKLY_REPORT_TIME:-09:00}" ]] && [[ $((current_time - last_weekly)) -ge 518400 ]]; then
                send_weekly_report
                last_weekly=$current_time
            fi
        fi
        
        # Sleep before next iteration
        sleep "${PROCESS_CHECK_INTERVAL:-5}"
    done
}

test_telegram() {
    log INFO "Testing Telegram connectivity..."
    
    if [[ "${TELEGRAM_ENABLED:-false}" != "true" ]]; then
        log ERROR "Telegram is not enabled in configuration"
        return 1
    fi
    
    if [[ -z "${TELEGRAM_BOT_TOKEN:-}" ]] || [[ -z "${TELEGRAM_CHAT_ID:-}" ]]; then
        log ERROR "Telegram bot token or chat ID not configured"
        return 1
    fi
    
    local telegram_url="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"
    
    local response
    response=$(curl -s -X POST "$telegram_url" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        -d "text=🧪 Test message from VPS Security Monitor on $(hostname)" \
        -m 10 2>/dev/null)
    
    if echo "$response" | grep -q '"ok":true'; then
        log INFO "Telegram test successful!"
        return 0
    else
        log ERROR "Telegram test failed: $response"
        return 1
    fi
}

# =============================================================================
# COMMAND LINE PARSING
# =============================================================================

main() {
    local command=""
    
    # Show help if no arguments
    if [[ $# -eq 0 ]]; then
        show_help
        exit 0
    fi
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE="true"
                shift
                ;;
            -d|--debug)
                DEBUG="true"
                LOG_LEVEL="DEBUG"
                shift
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            quick|deep|full|monitor|summary|weekly|test-telegram|help)
                command="$1"
                shift
                ;;
            *)
                log ERROR "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Default to monitor if no command specified (but args were given)
    if [[ -z "$command" ]]; then
        command="monitor"
    fi
    
    # Initialize
    log_init
    load_config
    load_signatures
    
    # Execute command
    case "$command" in
        quick)
            check_root
            run_quick_scan
            ;;
        deep)
            check_root
            run_deep_scan
            ;;
        full)
            check_root
            run_full_audit
            ;;
        monitor)
            check_root
            start_monitoring
            ;;
        summary)
            send_daily_summary
            ;;
        weekly)
            send_weekly_report
            ;;
        test-telegram)
            test_telegram
            ;;
        help)
            show_help
            ;;
        *)
            log ERROR "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
