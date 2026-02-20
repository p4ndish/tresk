#!/usr/bin/env python3
"""
Tresk - AI Threat Analyzer (Kimi K2 Integration)
Version: 1.0.0
Description: AI-powered analysis to reduce false positives and provide threat context
"""

import json
import os
import sys
import requests
from typing import Dict, Optional, Tuple
from datetime import datetime


class AIThreatAnalyzer:
    """AI-powered threat analysis using Kimi K2"""
    
    def __init__(self, api_key: Optional[str] = None, config_file: str = "/etc/tresk/config.conf"):
        self.config_file = config_file
        self.api_key = api_key or self._load_api_key(config_file)
        self.api_url = self._load_api_url()
        self.model = self._load_model()
        self.enabled = self.api_key is not None and len(self.api_key) > 10
        
    def _load_api_key(self, config_file: str) -> Optional[str]:
        """Load API key from config file"""
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('KIMI_API_KEY='):
                            return line.split('=', 1)[1].strip().strip('"').strip("'")
                        # Also check for KIMI_CODE_API_KEY
                        if line.startswith('KIMI_CODE_API_KEY='):
                            return line.split('=', 1)[1].strip().strip('"').strip("'")
        except Exception as e:
            print(f"Error loading API key: {e}")
        return None
    
    def _load_api_url(self) -> str:
        """Load API URL from config or use default"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('KIMI_API_URL='):
                            return line.split('=', 1)[1].strip().strip('"').strip("'")
        except:
            pass
        # Default to Moonshot API
        return "https://api.moonshot.cn/v1/chat/completions"
    
    def _load_model(self) -> str:
        """Load model from config or use default"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('KIMI_MODEL='):
                            return line.split('=', 1)[1].strip().strip('"').strip("'")
        except:
            pass
        # Default model
        return "kimi-k2-0712-preview"
    
    def analyze_process(self, pid: str, cmd: str, detection_reason: str) -> Tuple[bool, str, float]:
        """
        Analyze a detected process using AI
        
        Returns:
            Tuple of (is_threat: bool, explanation: str, confidence: float)
        """
        if not self.enabled:
            return True, "AI analysis disabled (no API key)", 0.0
        
        # Build prompt for AI analysis
        prompt = self._build_process_analysis_prompt(pid, cmd, detection_reason)
        
        try:
            response = self._call_kimi_api(prompt)
            return self._parse_ai_response(response)
        except Exception as e:
            print(f"AI analysis error: {e}")
            # Fail open - assume it's a threat if AI fails
            return True, f"AI analysis failed: {e}", 0.0
    
    def _build_process_analysis_prompt(self, pid: str, cmd: str, detection_reason: str) -> str:
        """Build analysis prompt for Kimi K2"""
        return f"""You are a Linux security expert analyzing a potentially malicious process.

PROCESS DETAILS:
- PID: {pid}
- Command: {cmd}
- Detection Reason: {detection_reason}

ANALYSIS TASK:
1. Determine if this process is LEGITIMATE (normal system process) or MALICIOUS (malware/cryptominer/backdoor)
2. Consider: Is this a known Linux kernel process? Is it a system service? Common application?
3. Look for red flags: Deleted executables, suspicious network connections, high CPU, obfuscated code

RESPONSE FORMAT (JSON only):
{{
    "is_threat": true/false,
    "confidence": 0.0-1.0,
    "explanation": "Brief explanation of why this is or isn't a threat",
    "recommendation": "What action to take",
    "category": "legitimate_system_process|cryptominer|backdoor|rootkit|unknown_suspicious"
}}

Be conservative - when in doubt, classify as suspicious."""
    
    def _call_kimi_api(self, prompt: str) -> str:
        """Call Kimi K2 API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a Linux security expert. Respond only with valid JSON."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,  # Low temperature for consistent results
            "max_tokens": 500
        }
        
        response = requests.post(
            self.api_url,
            headers=headers,
            json=payload,
            timeout=30
        )
        
        response.raise_for_status()
        result = response.json()
        
        # Extract content from response
        if 'choices' in result and len(result['choices']) > 0:
            return result['choices'][0]['message']['content']
        
        raise Exception("Invalid API response format")
    
    def _parse_ai_response(self, response: str) -> Tuple[bool, str, float]:
        """Parse AI JSON response"""
        try:
            # Clean up response (remove markdown code blocks if present)
            response = response.strip()
            if response.startswith('```json'):
                response = response[7:]
            if response.startswith('```'):
                response = response[3:]
            if response.endswith('```'):
                response = response[:-3]
            response = response.strip()
            
            data = json.loads(response)
            
            is_threat = data.get('is_threat', True)
            confidence = float(data.get('confidence', 0.5))
            explanation = data.get('explanation', 'No explanation provided')
            recommendation = data.get('recommendation', '')
            category = data.get('category', 'unknown')
            
            # Build full explanation
            full_explanation = f"[{category.upper()}] {explanation}"
            if recommendation:
                full_explanation += f" | Recommendation: {recommendation}"
            
            return is_threat, full_explanation, confidence
            
        except json.JSONDecodeError as e:
            print(f"Failed to parse AI response: {e}")
            print(f"Raw response: {response}")
            return True, f"AI parsing failed: {e}", 0.0
    
    def quick_check(self, process_name: str) -> Optional[str]:
        """Quick whitelist check for common legitimate processes"""
        # Known legitimate processes that often trigger false positives
        whitelist = {
            'kthreadd': 'Linux kernel thread daemon (PID 2)',
            'ksoftirqd': 'Kernel softirq handler',
            'kworker': 'Kernel worker process',
            'migration': 'CPU migration thread',
            'watchdog': 'Kernel watchdog',
            'systemd': 'System and service manager',
            'systemd-journal': 'Systemd journal service',
            'sshd': 'OpenSSH server',
            'cron': 'Cron daemon',
            'dbus-daemon': 'D-Bus message bus',
            'networkd': 'Network management',
            'irqbalance': 'IRQ balancing daemon',
            'rsyslogd': 'System logging',
            'snapd': 'Snap package manager',
            'containerd': 'Container runtime',
            'dockerd': 'Docker daemon',
            'kubelet': 'Kubernetes node agent',
        }
        
        for known_name, description in whitelist.items():
            if known_name in process_name.lower():
                return description
        
        return None


def analyze_threat(pid: str, cmd: str, detection_type: str, use_ai: bool = True) -> Dict:
    """
    Analyze a detected threat with optional AI verification
    
    Args:
        pid: Process ID
        cmd: Process command line
        detection_type: How it was detected (cryptominer, rootkit, etc.)
        use_ai: Whether to use AI analysis
    
    Returns:
        Dict with analysis results
    """
    analyzer = AIThreatAnalyzer()
    
    result = {
        'timestamp': datetime.utcnow().isoformat(),
        'pid': pid,
        'cmd': cmd,
        'detection_type': detection_type,
        'is_threat': True,  # Default to threat (fail secure)
        'confidence': 0.0,
        'explanation': '',
        'ai_analyzed': False,
        'ai_enabled': analyzer.enabled
    }
    
    # Quick whitelist check first (fast, no API call)
    whitelist_reason = analyzer.quick_check(cmd)
    if whitelist_reason:
        result['is_threat'] = False
        result['confidence'] = 0.95
        result['explanation'] = f"WHITELISTED: {whitelist_reason}"
        result['source'] = 'local_whitelist'
        return result
    
    # Skip AI for system PIDs (< 100)
    try:
        if int(pid) < 100:
            result['is_threat'] = False
            result['confidence'] = 0.90
            result['explanation'] = "SYSTEM PROCESS: PID < 100, kernel/system init process"
            result['source'] = 'pid_heuristic'
            return result
    except ValueError:
        pass
    
    # AI Analysis if enabled
    if use_ai and analyzer.enabled:
        try:
            is_threat, explanation, confidence = analyzer.analyze_process(
                pid, cmd, detection_type
            )
            result['is_threat'] = is_threat
            result['confidence'] = confidence
            result['explanation'] = explanation
            result['ai_analyzed'] = True
            result['source'] = 'kimi_k2_ai'
        except Exception as e:
            result['explanation'] = f"AI analysis failed: {e}"
            result['source'] = 'error'
    else:
        result['explanation'] = "AI analysis disabled or no API key"
        result['source'] = 'no_ai'
    
    return result


def main():
    """CLI for testing AI analyzer"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Tresk AI Threat Analyzer')
    parser.add_argument('pid', help='Process ID')
    parser.add_argument('cmd', help='Process command')
    parser.add_argument('--reason', default='Manual check', help='Detection reason')
    parser.add_argument('--config', default='/etc/tresk/config.conf', help='Config file')
    
    args = parser.parse_args()
    
    result = analyze_threat(args.pid, args.cmd, args.reason)
    
    print(json.dumps(result, indent=2))
    
    if result['is_threat']:
        print("\n⚠️  THREAT DETECTED")
        sys.exit(1)
    else:
        print("\n✅ LIKELY LEGITIMATE")
        sys.exit(0)


if __name__ == '__main__':
    main()
