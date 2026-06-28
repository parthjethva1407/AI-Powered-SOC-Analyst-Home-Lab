# 🛡️ AI-Powered SOC Analyst Home Lab

An end-to-end autonomous threat detection pipeline built on a home network using Python, tshark, and an Airia AI agent trained on a custom SOC playbook.

> **Simulates a real SOC Tier 1 workflow:** live traffic capture → anomaly detection → structured JSON alert → AI triage → MITRE ATT&CK mapped report.

---

## Architecture

```
Attacker Machine (Windows)
        │
        │  ICMP flood (ping -n 50)
        ▼
Internal Server (Kali Linux)
        │
        │  tshark capture → CSV parsing → IP threshold check
        ▼
  alert.json (structured SOC alert)
        │
        │  POST /v2/PipelineExecution
        ▼
  Airia AI Agent (Gemini 3.5 Flash)
        │
        │  SOC Playbook: classify → risk score → MITRE map → action plan
        ▼
  Triage Report (JSON response)
```

---

## What It Does

| Step | Component | Description |
|------|-----------|-------------|
| 1 | `capture_traffic()` | tshark captures ICMP packets on `eth0` for a configurable duration |
| 2 | `convert_to_csv()` | Exports frame timestamp, src/dst IP, protocol, and frame length to CSV |
| 3 | `analyze_traffic()` | Counts packets per source IP; flags IPs exceeding the threshold |
| 4 | `generate_alert()` | Builds a structured JSON alert with SOC-standard fields and a unique alert ID |
| 5 | `send_to_airia()` | POSTs the alert to a published Airia AI agent via REST API |
| 6 | AI Triage | Agent responds with threat classification, risk score, MITRE mapping, and recommended actions |

---

## Lab Setup

### Network Topology

| Machine | OS | Role | IP |
|---------|----|------|----|
| Internal Server | Kali Linux | Runs Python script, victim of traffic | 192.168.1.16 |
| Attacker Machine | Windows 11 | Simulates reconnaissance via ICMP | 192.168.1.3 |

Both machines on the same subnet (bridged adapter in VirtualBox).

### Requirements

**On the Kali/Linux internal server:**
```bash
sudo apt install tshark python3-pip
pip3 install requests
```

---

## Configuration

Edit the top of `Junior_SOC_Analyst.py`:

```python
INTERFACE = "eth0"          # Verify with: ip a
CAPTURE_DURATION = 100      # Seconds to capture
THRESHOLD = 40              # Alert if an IP exceeds this packet count

DESTINATION_IP = "192.168.1.16"   # Your internal server IP

AIRIA_API_URL = "YOUR_AIRIA_API_URL"
AIRIA_API_KEY = "YOUR_AIRIA_API_KEY"
```

---

## Setting Up the Airia AI Agent

1. Sign up at [airia.ai](https://airia.ai) and create a new project
2. Add an AI model (Gemini 3.5 Flash or GPT-4o Nano work well)
3. Paste the contents of `SOC_playbook.txt` as the system prompt / agent instructions
4. Publish the agent and copy the Pipeline Execution API URL and API key
5. Paste both into the configuration block above

The playbook trains the agent on:
- Input validation (required alert fields)
- Threat classification (7 categories)
- Risk scoring model (0–100 with defined modifiers)
- MITRE ATT&CK tactic/technique mapping
- Tier 1 SOC action plans tied to risk level
- Escalation logic (thresholds at 60 and 80)
- Executive summary generation (plain language, 2–3 sentences)

---

## Running the Lab

**Step 1 — Start the Python script on the internal server:**
```bash
sudo python3 Junior_SOC_Analyst.py
```

**Step 2 — Generate traffic from the attacker machine:**
```cmd
ping 192.168.1.16 -n 50
```
Or use hping3 / nmap for more realistic scanning simulation.

**Step 3 — Watch the automated pipeline execute:**
```
[+] Capturing on eth0 for 100s
[+] Capture saved to traffic.pcap
[+] CSV created at traffic.csv
[+] Traffic volume per source IP:
192.168.1.3: 45 packets
[!] Suspicious IP detected: 192.168.1.3
[+] Alert JSON written to alert.json
[+] Sending alert to Airia Agent Execution API...
[+] Airia responded with status 200
[+] Workflow complete.
```

---

## Sample Output

**Alert JSON sent to Airia:**
```json
{
    "alert_id": "SOC-7A9BD574",
    "alert_type": "Suspicious Network Volume",
    "indicator_type": "ip",
    "indicator_value": "192.168.1.3",
    "source_host": "Unknown",
    "destination_host": "Internal-server",
    "destination_ip": "192.168.1.16",
    "protocol": "ICMP",
    "evidence": {
        "packet_count": 45,
        "time_window_seconds": 100,
        "data_source": "traffic.pcap"
    }
}
```

**AI Triage Response:**
```json
{
  "alert_id": "SOC-7A9BD574",
  "threat_classification": "Network Reconnaissance / Scanning",
  "risk_score": 35,
  "risk_level": "Medium",
  "confidence_level": "Medium",
  "mitre_mapping": {
    "tactic": "Discovery",
    "technique_id": "T1046",
    "technique_name": "Network Service Scanning"
  },
  "recommended_actions": [
    "Monitor the source IP 192.168.1.3 for further anomalies",
    "Enrich with internal asset inventory to identify device owner",
    "Review network ACLs to restrict unauthorized ICMP to internal servers"
  ],
  "escalation_required": false,
  "executive_summary": "An unknown internal device was observed sending ping requests to an internal server. This minor anomaly does not pose an immediate danger but may indicate a routine network scan. We are monitoring the source device to ensure no further suspicious behavior is attempted."
}
```

---

## Files

| File | Purpose |
|------|---------|
| `Junior_SOC_Analyst.py` | Main automation script |
| `SOC_playbook.txt` | System prompt / agent instructions for Airia |
| `traffic.pcap` | Generated — raw packet capture |
| `traffic.csv` | Generated — parsed fields from pcap |
| `alert.json` | Generated — structured SOC alert |

---

## Extensions to Try

- Swap ICMP filter for TCP SYN packets to detect port scanning
- Add multi-IP tracking (currently alerts on the first offending IP only)
- Integrate with Wazuh or Splunk as a SIEM instead of Airia
- Schedule the script with `cron` for continuous monitoring
- Add email/Slack notification when escalation is required

---

## MITRE ATT&CK Coverage

| Scenario | Tactic | Technique |
|----------|--------|-----------|
| ICMP flood / ping sweep | Discovery | T1046 — Network Service Scanning |
| High-volume TCP SYN | Discovery | T1046 — Network Service Scanning |
| Repeated auth failures | Credential Access | T1110 — Brute Force |

---

## Author

**Parth Jethva** — M.Sc. Cyber Security & Digital Forensics, Rashtriya Raksha University  
[LinkedIn](https://linkedin.com/in/parthjethva) · [TryHackMe](https://tryhackme.com/p/parthjethva1107) · [Portfolio](https://parthjethva1407.github.io)
