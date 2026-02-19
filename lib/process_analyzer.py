#!/usr/bin/env python3
"""
VPS Security Monitor - Process Analyzer Module
Version: 1.0.0
Description: Advanced process analysis for threat detection
"""

import os
import sys
import json
import hashlib
import subprocess
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
import re


@dataclass
class ProcessInfo:
    """Process information container"""
    pid: int
    ppid: int
    uid: int
    gid: int
    user: str
    command: str
    exe_path: Optional[str]
    cpu_percent: float
    memory_percent: float
    create_time: float
    connections: List[Dict]
    open_files: List[str]
    environ: Dict[str, str]
    is_deleted: bool
    is_hidden: bool


class ProcessAnalyzer:
    """Advanced process analyzer for threat detection"""
    
    # Known cryptominer patterns
    CRYPTOMINER_PATTERNS = [
        r'xmrig', r'xmr-stak', r'minerd', r'cgminer', r'bfgminer',
        r'kdevtmpfsi', r'kinsing', r'kthreaddi', r'sysupdate',
        r'networkservice', r'sysguard', r'stratum\+',
        r'pool\.minexmr\.com', r'nanopool\.org',
        r'supportxmr\.com', r'minergate\.com'
    ]
    
    # Reverse shell patterns
    REVERSE_SHELL_PATTERNS = [
        r'bash\s+-i\s+>&\s+/dev/tcp/',
        r'/bin/sh\s+-i\s+>&\s+/dev/tcp/',
        r'python\s+-c\s+[\'"].*import\s+socket.*subprocess',
        r'python3\s+-c\s+[\'"].*import\s+socket.*subprocess',
        r'perl\s+-e\s+[\'"].*use\s+Socket',
        r'ruby\s+-rsocket\s+-e',
        r'nc\s+-e\s+/bin/(?:sh|bash)',
        r'ncat\s+-e\s+/bin/(?:sh|bash)',
        r'mkfifo\s+/tmp/f.*nc\s+',
        r'socat\s+TCP4-LISTEN:.*(?:/bin/bash|/bin/sh)'
    ]
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = [
        r'base64\s+(-d|--decode)',
 r'eval\s*\(',
        r'exec\s*\(',
        r'system\s*\(',
        r'curl.*\|.*bash',
        r'wget.*\|.*sh',
        r'fetch.*\|.*sh',
        r'/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+',
        r'/dev/udp/\d+\.\d+\.\d+\.\d+/\d+'
    ]
    
    def __init__(self, signature_db_path: str = "/opt/tresk/signatures/threat_signatures.json"):
        self.signature_db_path = signature_db_path
        self.signatures = self._load_signatures()
        
    def _load_signatures(self) -> Dict:
        """Load threat signatures from database"""
        try:
            with open(self.signature_db_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load signatures: {e}")
            return {}
    
    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """Get detailed information about a process"""
        try:
            proc_path = f"/proc/{pid}"
            
            if not os.path.exists(proc_path):
                return None
            
            # Read status file
            status = {}
            try:
                with open(f"{proc_path}/status", 'r') as f:
                    for line in f:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            status[key.strip()] = value.strip()
            except:
                pass
            
            # Read cmdline
            try:
                with open(f"{proc_path}/cmdline", 'r') as f:
                    cmdline = f.read().replace('\x00', ' ').strip()
            except:
                cmdline = ""
            
            # Check if executable is deleted
            exe_path = None
            is_deleted = False
            try:
                exe_path = os.readlink(f"{proc_path}/exe")
                if "(deleted)" in exe_path:
                    is_deleted = True
                    exe_path = exe_path.replace(" (deleted)", "")
            except:
                pass
            
            # Get open files
            open_files = []
            try:
                fd_dir = f"{proc_path}/fd"
                if os.path.exists(fd_dir):
                    for fd in os.listdir(fd_dir):
                        try:
                            link = os.readlink(f"{fd_dir}/{fd}")
                            open_files.append(link)
                        except:
                            pass
            except:
                pass
            
            # Get environment variables
            environ = {}
            try:
                with open(f"{proc_path}/environ", 'r') as f:
                    env_data = f.read()
                    for env in env_data.split('\x00'):
                        if '=' in env:
                            key, value = env.split('=', 1)
                            environ[key] = value
            except:
                pass
            
            # Check if hidden from ps
            is_hidden = self._is_hidden_process(pid)
            
            # Get network connections
            connections = self._get_process_connections(pid)
            
            # Get CPU and memory info from stat
            cpu_percent = 0.0
            memory_percent = 0.0
            create_time = 0.0
            
            try:
                with open(f"{proc_path}/stat", 'r') as f:
                    stat_data = f.read().split()
                    if len(stat_data) > 21:
                        # Calculate CPU usage (simplified)
                        utime = int(stat_data[13])
                        stime = int(stat_data[14])
                        total_time = utime + stime
                        
                        # Get process start time
                        starttime = int(stat_data[21])
                        create_time = starttime
            except:
                pass
            
            return ProcessInfo(
                pid=pid,
                ppid=int(status.get('PPid', 0)),
                uid=int(status.get('Uid', '0').split()[0]),
                gid=int(status.get('Gid', '0').split()[0]),
                user=status.get('Uid', 'unknown').split()[0],
                command=cmdline or status.get('Name', 'unknown'),
                exe_path=exe_path,
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                create_time=create_time,
                connections=connections,
                open_files=open_files,
                environ=environ,
                is_deleted=is_deleted,
                is_hidden=is_hidden
            )
            
        except Exception as e:
            print(f"Error getting process info for PID {pid}: {e}")
            return None
    
    def _is_hidden_process(self, pid: int) -> bool:
        """Check if process is hidden from ps but exists in /proc"""
        try:
            # Get list of PIDs from ps
            ps_output = subprocess.check_output(['ps', '-e', '-o', 'pid='], 
                                                text=True, stderr=subprocess.DEVNULL)
            ps_pids = set(int(p.strip()) for p in ps_output.split('\n') if p.strip().isdigit())
            
            return pid not in ps_pids
        except:
            return False
    
    def _get_process_connections(self, pid: int) -> List[Dict]:
        """Get network connections for a process"""
        connections = []
        
        try:
            # Read /proc/PID/net/tcp and /proc/PID/net/tcp6
            for proto in ['tcp', 'tcp6']:
                net_file = f"/proc/{pid}/net/{proto}"
                if os.path.exists(net_file):
                    with open(net_file, 'r') as f:
                        lines = f.readlines()[1:]  # Skip header
                        for line in lines:
                            parts = line.split()
                            if len(parts) >= 4:
                                local_addr = self._parse_proc_net_addr(parts[1])
                                rem_addr = self._parse_proc_net_addr(parts[2])
                                state = parts[3]
                                
                                connections.append({
                                    'protocol': proto,
                                    'local_address': local_addr,
                                    'remote_address': rem_addr,
                                    'state': state
                                })
        except:
            pass
        
        return connections
    
    def _parse_proc_net_addr(self, addr_str: str) -> str:
        """Parse address from /proc/net/tcp format"""
        try:
            ip_hex, port_hex = addr_str.split(':')
            ip_parts = [str(int(ip_hex[i:i+2], 16)) for i in (6, 4, 2, 0)]
            ip = '.'.join(reversed(ip_parts))
            port = int(port_hex, 16)
            return f"{ip}:{port}"
        except:
            return addr_str
    
    def scan_all_processes(self) -> List[ProcessInfo]:
        """Scan all processes and return list of ProcessInfo"""
        processes = []
        
        try:
            for pid_str in os.listdir('/proc'):
                if pid_str.isdigit():
                    pid = int(pid_str)
                    proc_info = self.get_process_info(pid)
                    if proc_info:
                        processes.append(proc_info)
        except Exception as e:
            print(f"Error scanning processes: {e}")
        
        return processes
    
    def detect_cryptominers(self, processes: List[ProcessInfo]) -> List[Dict]:
        """Detect cryptocurrency mining processes"""
        threats = []
        
        for proc in processes:
            cmd_lower = proc.command.lower()
            
            # Check command patterns
            for pattern in self.CRYPTOMINER_PATTERNS:
                if re.search(pattern, cmd_lower, re.IGNORECASE):
                    threats.append({
                        'type': 'cryptominer',
                        'severity': 'CRITICAL',
                        'pid': proc.pid,
                        'command': proc.command,
                        'pattern_matched': pattern,
                        'indicators': ['known_miner_signature']
                    })
                    break
            
            # Check for high CPU usage with suspicious patterns
            if proc.cpu_percent > 85:
                suspicious = any(re.search(p, cmd_lower, re.IGNORECASE) 
                               for p in ['base64', 'decode', 'curl', 'wget', 'pool', 'stratum', 'xmr'])
                if suspicious:
                    threats.append({
                        'type': 'suspicious_high_cpu',
                        'severity': 'HIGH',
                        'pid': proc.pid,
                        'command': proc.command,
                        'cpu_percent': proc.cpu_percent,
                        'indicators': ['high_cpu', 'suspicious_command']
                    })
            
            # Check for deleted executables
            if proc.is_deleted:
                threats.append({
                    'type': 'fileless_malware',
                    'severity': 'CRITICAL',
                    'pid': proc.pid,
                    'command': proc.command,
                    'exe_path': proc.exe_path,
                    'indicators': ['deleted_executable']
                })
        
        return threats
    
    def detect_reverse_shells(self, processes: List[ProcessInfo]) -> List[Dict]:
        """Detect reverse shell processes"""
        threats = []
        
        for proc in processes:
            cmd = proc.command
            
            for pattern in self.REVERSE_SHELL_PATTERNS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    threats.append({
                        'type': 'reverse_shell',
                        'severity': 'CRITICAL',
                        'pid': proc.pid,
                        'command': proc.command,
                        'pattern_matched': pattern,
                        'connections': proc.connections,
                        'indicators': ['reverse_shell_signature']
                    })
                    break
            
            # Check for suspicious network connections
            for conn in proc.connections:
                remote = conn.get('remote_address', '')
                if remote and not remote.startswith('127.') and not remote.startswith('0.'):
                    port = int(remote.split(':')[-1]) if ':' in remote else 0
                    if port in [4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321]:
                        threats.append({
                            'type': 'suspicious_connection',
                            'severity': 'HIGH',
                            'pid': proc.pid,
                            'command': proc.command,
                            'connection': conn,
                            'indicators': ['suspicious_port']
                        })
        
        return threats
    
    def detect_suspicious_processes(self, processes: List[ProcessInfo]) -> List[Dict]:
        """Detect suspicious process behavior"""
        threats = []
        
        for proc in processes:
            cmd = proc.command
            indicators = []
            
            # Check for suspicious patterns
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    indicators.append(f'pattern:{pattern}')
            
            # Check for hidden processes
            if proc.is_hidden:
                indicators.append('hidden_from_ps')
            
            # Check environment variables
            if 'LD_PRELOAD' in proc.environ:
                indicators.append('ld_preload_set')
            
            # Check for suspicious open files
            for f in proc.open_files:
                if '/dev/shm/' in f and f.endswith(('.sh', '.bin', '')):
                    indicators.append('executable_in_shm')
                if '.so' in f and any(x in f for x in ['hide', 'rootkit', 'hook']):
                    indicators.append('suspicious_library')
            
            if indicators:
                severity = 'CRITICAL' if len(indicators) >= 3 else 'HIGH' if len(indicators) >= 2 else 'MEDIUM'
                threats.append({
                    'type': 'suspicious_process',
                    'severity': severity,
                    'pid': proc.pid,
                    'command': proc.command,
                    'indicators': indicators,
                    'environ': {k: v for k, v in proc.environ.items() if any(x in k for x in ['LD_', 'PATH', 'HOME'])}
                })
        
        return threats
    
    def analyze_process_tree(self, root_pid: Optional[int] = None) -> Dict[int, List[int]]:
        """Analyze process tree structure"""
        tree = {}
        processes = self.scan_all_processes()
        
        for proc in processes:
            if proc.ppid not in tree:
                tree[proc.ppid] = []
            tree[proc.ppid].append(proc.pid)
        
        return tree
    
    def get_process_hash(self, pid: int) -> Optional[str]:
        """Calculate hash of process executable"""
        try:
            exe_path = os.readlink(f"/proc/{pid}/exe")
            if os.path.exists(exe_path):
                with open(exe_path, 'rb') as f:
                    return hashlib.sha256(f.read()).hexdigest()
        except:
            pass
        return None
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive process analysis report"""
        processes = self.scan_all_processes()
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_processes': len(processes),
            'cryptominers': self.detect_cryptominers(processes),
            'reverse_shells': self.detect_reverse_shells(processes),
            'suspicious': self.detect_suspicious_processes(processes),
            'hidden_processes': [p.pid for p in processes if p.is_hidden],
            'deleted_executables': [p.pid for p in processes if p.is_deleted],
            'high_cpu_processes': [
                {'pid': p.pid, 'command': p.command[:100], 'cpu': p.cpu_percent}
                for p in processes if p.cpu_percent > 50
            ]
        }
        
        return report


def main():
    """CLI interface for process analyzer"""
    import argparse
    
    parser = argparse.ArgumentParser(description='VPS Security Monitor - Process Analyzer')
    parser.add_argument('--scan', action='store_true', help='Scan all processes')
    parser.add_argument('--pid', type=int, help='Analyze specific PID')
    parser.add_argument('--report', action='store_true', help='Generate full report')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    analyzer = ProcessAnalyzer()
    
    if args.pid:
        info = analyzer.get_process_info(args.pid)
        if info:
            print(f"PID: {info.pid}")
            print(f"Command: {info.command}")
            print(f"Exe: {info.exe_path}")
            print(f"Deleted: {info.is_deleted}")
            print(f"Hidden: {info.is_hidden}")
            print(f"Connections: {len(info.connections)}")
        else:
            print(f"Process {args.pid} not found")
    
    elif args.report:
        report = analyzer.generate_report()
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"Process Analysis Report - {report['timestamp']}")
            print(f"Total Processes: {report['total_processes']}")
            print(f"Cryptominers Found: {len(report['cryptominers'])}")
            print(f"Reverse Shells Found: {len(report['reverse_shells'])}")
            print(f"Suspicious Processes: {len(report['suspicious'])}")
            print(f"Hidden Processes: {len(report['hidden_processes'])}")
            print(f"Deleted Executables: {len(report['deleted_executables'])}")
            
            if report['cryptominers']:
                print("\n--- Cryptominers ---")
                for threat in report['cryptominers']:
                    print(f"  PID {threat['pid']}: {threat['command'][:80]}")
            
            if report['reverse_shells']:
                print("\n--- Reverse Shells ---")
                for threat in report['reverse_shells']:
                    print(f"  PID {threat['pid']}: {threat['command'][:80]}")
    
    elif args.scan:
        processes = analyzer.scan_all_processes()
        print(f"Scanned {len(processes)} processes")
        
        cryptominers = analyzer.detect_cryptominers(processes)
        if cryptominers:
            print(f"\n⚠️  Found {len(cryptominers)} cryptominer(s)!")
            for c in cryptominers:
                print(f"  PID {c['pid']}: {c['command'][:80]}")
        
        shells = analyzer.detect_reverse_shells(processes)
        if shells:
            print(f"\n⚠️  Found {len(shells)} reverse shell(s)!")
            for s in shells:
                print(f"  PID {s['pid']}: {s['command'][:80]}")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
