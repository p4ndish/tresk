# 🤖 AI-Powered Threat Analysis (Kimi K2 Integration)

Tresk now includes AI-powered threat analysis using Kimi K2 to reduce false positives and provide intelligent context about detected threats.

## Overview

When Tresk detects a potential threat, the AI analyzer:
1. Performs quick local checks (whitelist, PID heuristics)
2. Sends process details to Kimi K2 for analysis
3. Receives a verdict (threat/legitimate) with confidence score
4. Only alerts if AI confirms it's a threat (in conservative mode)

## Benefits

- **Reduced False Positives**: AI validates detections before alerting
- **Intelligent Context**: Understands process purpose and behavior
- **Self-Improving**: Learns from your system's normal behavior
- **Detailed Explanations**: Knows why something is or isn't a threat

## Setup

### 1. Get Kimi API Key

Choose ONE of the following options:

#### Option A: Moonshot API (Recommended)
1. Visit https://platform.moonshot.cn/
2. Create an account
3. Generate an API key
4. Copy the key (starts with `sk-`)

#### Option B: Kimi Code API
1. Visit https://www.kimi.com/code/console
2. Look for API Keys section
3. Generate an API key
4. Note the API endpoint URL (may differ from Moonshot)

### 2. Configure Tresk

Edit `/etc/tresk/config.conf`:

#### For Moonshot API:
```bash
# Enable AI analysis
AI_ANALYSIS_ENABLED="true"

# Moonshot API Settings
KIMI_API_KEY="sk-your-moonshot-api-key"
KIMI_API_URL="https://api.moonshot.cn/v1/chat/completions"
KIMI_MODEL="kimi-k2-0712-preview"

# Confidence threshold (0.0 - 1.0)
AI_CONFIDENCE_THRESHOLD="0.75"

# AI Mode
AI_MODE="conservative"
```

#### For Kimi Code API:
```bash
# Enable AI analysis
AI_ANALYSIS_ENABLED="true"

# Kimi Code API Settings
KIMI_API_KEY="sk-your-kimi-code-api-key"
KIMI_API_URL="https://api.kimi.com/v1/chat/completions"
KIMI_MODEL="kimi-k2-0712-preview"

# Confidence threshold
AI_CONFIDENCE_THRESHOLD="0.75"

# AI Mode
AI_MODE="conservative"
```

### 3. Restart Tresk

```bash
sudo systemctl restart tresk
```

### 4. Test API Connection

Test your API key before enabling in Tresk:

#### Test Moonshot API:
```bash
export KIMI_API_KEY="sk-your-moonshot-key"
curl -s -X POST https://api.moonshot.cn/v1/chat/completions \
  -H "Authorization: Bearer $KIMI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"kimi-k2-0712-preview","messages":[{"role":"user","content":"Hello"}]}'
```

#### Test Kimi Code API:
```bash
export KIMI_API_KEY="sk-your-kimi-code-key"
curl -s -X POST https://api.kimi.com/v1/chat/completions \
  -H "Authorization: Bearer $KIMI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"kimi-k2-0712-preview","messages":[{"role":"user","content":"Hello"}]}'
```

### 5. Test Tresk AI Module

```bash
# Test AI analyzer directly
sudo /opt/tresk/lib/ai_analyzer.py 1234 "xmrig --donate-level 1" --reason "cryptominer_signature"

# Run a scan
sudo tresk quick
```

## How It Works

### Detection Flow

```
1. Tresk detects potential threat
   ↓
2. Quick local checks (fast)
   - Is PID < 100? (system process)
   - Is it in whitelist? (kthreadd, systemd, etc.)
   ↓
3. Send to Kimi K2 AI
   - Process details
   - Command line
   - Detection reason
   ↓
4. AI analyzes and returns:
   - is_threat: true/false
   - confidence: 0.0 - 1.0
   - explanation: Why it's a threat or legitimate
   - category: malware type or "legitimate_system_process"
   ↓
5. Decision
   - If AI says legitimate + high confidence → No alert
   - If AI says threat or low confidence → Send alert with AI analysis
```

### AI Response Format

```json
{
  "is_threat": false,
  "confidence": 0.95,
  "explanation": "This is kthreadd, a legitimate Linux kernel thread daemon (PID 2)",
  "recommendation": "No action needed",
  "category": "legitimate_system_process"
}
```

## AI Modes

### Conservative Mode (Recommended)
```bash
AI_MODE="conservative"
```
- AI must confirm threat before alerting
- If AI says legitimate → No alert
- If AI unsure → Alerts anyway (fail secure)
- Best for: Production environments

### Assisted Mode
```bash
AI_MODE="assisted"
```
- AI analyzes but alerts anyway
- AI opinion included in alert
- Human makes final decision
- Best for: Learning/ tuning phase

### Disabled
```bash
AI_MODE="disabled"
```
- No AI analysis
- Original Tresk behavior
- Best for: No API key or offline systems

## Local Whitelist

The AI analyzer includes a built-in whitelist of known legitimate processes:

- `kthreadd` - Kernel thread daemon
- `ksoftirqd` - Kernel softirq handler
- `kworker` - Kernel worker process
- `systemd` - System manager
- `sshd` - SSH daemon
- `cron` - Cron daemon
- `dbus-daemon` - D-Bus message bus
- `dockerd` - Docker daemon
- `containerd` - Container runtime

These are checked instantly without API call.

## Telegram Alert Format

With AI analysis enabled, alerts include AI context:

```
🚨 CRITICAL: Cryptominer Detected

Host: myserver (192.168.1.100)
Time: 2025-02-20 15:30:00 UTC

Details:
Process: xmrig --donate-level 1 -o pool.minexmr.com:4444
PID: 12345
Type: Known cryptominer signature

🤖 AI Analysis:
This is XMRig cryptocurrency miner. It connects to 
minexmr.com mining pool and uses 95% CPU. 
Category: cryptominer
Confidence: 0.98

Recommended Actions:
kill -9 12345
```

## Troubleshooting

### AI Analysis Not Working

1. **Check API key:**
   ```bash
   grep KIMI_API_KEY /etc/tresk/config.conf
   ```

2. **Test AI module:**
   ```bash
   sudo /opt/tresk/lib/ai_analyzer.py 1234 "test" --reason "test"
   ```

3. **Check logs:**
   ```bash
   sudo tail -f /var/log/tresk/monitor.log | grep -i ai
   ```

### API Rate Limits

Kimi K2 has rate limits. If you hit limits:
- Increase `AI_CONFIDENCE_THRESHOLD` to reduce API calls
- Use local whitelist for known processes
- AI analysis is skipped for PID < 100 (system processes)

### False Positives Still Happening

1. Lower confidence threshold:
   ```bash
   AI_CONFIDENCE_THRESHOLD="0.60"
   ```

2. Add to protected processes:
   ```bash
   PROTECTED_PROCESSES="sshd|systemd|yourapp"
   ```

3. Report to us: Open issue at https://github.com/p4ndish/tresk

## Privacy & Security

- Process data is sent to Moonshot AI (Kimi K2) for analysis
- No file contents are sent, only process metadata
- API key is stored locally in config file
- Use environment variable for API key if preferred:
  ```bash
  export KIMI_API_KEY="sk-..."
  ```

## Cost

Kimi K2 API has usage-based pricing:
- Check https://platform.moonshot.cn/pricing
- Each process analysis uses ~500 tokens
- With conservative mode, only suspicious processes are analyzed
- Most systems: ~10-50 analyses per day = minimal cost

## Comparison

| Feature | Without AI | With AI |
|---------|-----------|---------|
| False Positives | High | Low |
| Context | Basic | Detailed |
| Learning | No | Yes |
| Cost | Free | API usage |
| Speed | Instant | +1-2 seconds |

## Examples

### Example 1: False Positive Prevented

**Detection:** Process named `kthreaddi` (malware mimicking `kthreadd`)

**Without AI:** Would alert as cryptominer

**With AI:** 
```json
{
  "is_threat": true,
  "confidence": 0.92,
  "explanation": "This is NOT the real kthreadd. The real one is PID 2. This process uses 95% CPU and has no parent process.",
  "category": "cryptominer"
}
```
**Result:** Alert sent with explanation

### Example 2: Legitimate Process Saved

**Detection:** Process `kthreadd` flagged by signature

**Without AI:** Alert sent (false positive)

**With AI:**
```json
{
  "is_threat": false,
  "confidence": 0.99,
  "explanation": "This is the legitimate Linux kernel thread daemon, PID 2, started by init",
  "category": "legitimate_system_process"
}
```
**Result:** No alert, logged as legitimate

---

For questions or issues: https://github.com/p4ndish/tresk/issues
