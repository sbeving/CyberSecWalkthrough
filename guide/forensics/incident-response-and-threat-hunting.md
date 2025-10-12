---
icon: car-burst
---

# Incident Response & Threat Hunting

## **Incident Response & Threat Hunting — Tracking the Adversary**

***

Incident Response (IR) is the structured process of **detecting, investigating, and remediating security incidents**.\
Threat Hunting extends IR — proactively searching for hidden attackers using evidence across endpoints, networks, and memory.

This guide teaches you the **full operator lifecycle**: detection → triage → containment → forensics → hunt → recovery.

***

### I. 🧩 Core Concepts

| Concept                                   | Description                                                            |
| ----------------------------------------- | ---------------------------------------------------------------------- |
| **Incident Response (IR)**                | Coordinated actions to detect, contain, and recover from attacks.      |
| **Threat Hunting (TH)**                   | Proactive search for adversaries that evade detection.                 |
| **IOC (Indicator of Compromise)**         | Observable evidence: hash, IP, domain, registry key, etc.              |
| **TTP (Tactics, Techniques, Procedures)** | Behavior patterns used by attackers (MITRE ATT\&CK).                   |
| **Artifact**                              | Evidence collected during an investigation (memory, logs, disk, etc.). |
| **Containment**                           | Isolating infected systems to prevent lateral spread.                  |

***

### II. ⚙️ The IR Lifecycle

| Phase                        | Description                                       | Example Tools             |
| ---------------------------- | ------------------------------------------------- | ------------------------- |
| **1️⃣ Preparation**          | Build playbooks, define contacts, gather baseline | Security Onion, ELK       |
| **2️⃣ Detection & Analysis** | Identify suspicious activity                      | SIEM, EDR, YARA           |
| **3️⃣ Containment**          | Isolate and prevent damage                        | Firewalls, host isolation |
| **4️⃣ Eradication**          | Remove malware, close exploits                    | EDR, scripts              |
| **5️⃣ Recovery**             | Restore systems, verify security                  | Backups, reimaging        |
| **6️⃣ Lessons Learned**      | Document and update defenses                      | Reports, IOC sharing      |

***

### III. ⚙️ Rapid Detection & Triage

#### 🧠 1. Quick IOC Matching

```bash
yara -r rules/apt.yar /mnt/disk
grep -i -E "C2|POST|/admin" /var/log/httpd/access.log
```

#### ⚙️ 2. Hash Check

```bash
sha256sum sample.exe
virustotal-search 9f3a7d...
```

#### 💣 3. Triage Memory Image

```bash
volatility3 -f mem.raw windows.pslist
volatility3 -f mem.raw windows.malfind
```

#### ⚙️ 4. Timeline Review

```bash
log2timeline.py case.plaso /mnt/evidence/
psort.py -o L2tcsv case.plaso > timeline.csv
```

***

### IV. ⚙️ Artifact Correlation Workflow

#### 🧩 1. Collect Everything

* Memory (`winpmem`, `LiME`)
* Disk (`dd`, `FTK Imager`)
* Network (`tcpdump`, `Wireshark`)
* Logs (Windows EVTX, Sysmon, Linux journal)

#### ⚙️ 2. Correlate Timestamps

```bash
cat timeline.csv | grep "svchost.exe"
grep "192.168" network.log
```

→ Trace initial infection → process execution → C2 traffic.

***

### V. ⚙️ Threat Hunting Foundations

| Hunt Type         | Focus                       | Example Query                 |
| ----------------- | --------------------------- | ----------------------------- |
| **Behavioral**    | Suspicious sequences        | “powershell -enc”, “rundll32” |
| **Anomaly-Based** | Deviations from baseline    | “spike in DNS requests”       |
| **Intel-Led**     | Known IOCs / threat intel   | YARA, Sigma, MISP             |
| **Hybrid**        | Combined contextual + intel | ELK + EDR telemetry           |

***

### VI. ⚙️ Endpoint Hunting (Windows & Linux)

#### 🧠 1. Process & Command Line Analysis

```bash
volatility3 -f mem.raw windows.cmdline
grep "powershell" /var/log/syslog
```

#### ⚙️ 2. Registry and Autoruns

```bash
volatility3 -f mem.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

#### 💣 3. Scheduled Task Abuse

```powershell
schtasks /query /fo LIST /v
```

#### ⚙️ 4. Suspicious Network Use

```bash
netstat -an | grep ESTABLISHED
```

or in memory:

```bash
volatility3 -f mem.raw windows.netstat
```

***

### VII. ⚙️ Network Threat Hunting

#### 🧩 1. Extract Network Indicators

```bash
tshark -r capture.pcap -Y "http.request"
```

#### ⚙️ 2. Detect C2 Patterns

Look for:

* Long beacon intervals
* DNS tunneling (`TXT` or random subdomains)
* HTTP `POST /update.php` with base64 payloads

#### 🧠 3. Decode Encrypted Payloads

```bash
cat payload.b64 | base64 -d | xxd
```

***

### VIII. ⚙️ SIEM & Log-Based Hunting

#### 🧩 1. Sysmon (Windows)

Event IDs:

| ID | Description        |
| -- | ------------------ |
| 1  | Process Creation   |
| 3  | Network Connection |
| 7  | Image Load         |
| 11 | File Creation      |
| 13 | Registry Event     |

Example Query (Elastic / KQL):

```
process.command_line : "*powershell*" and event.code : 1
```

#### ⚙️ 2. Linux Log Hunting

```bash
grep -i "Accepted password" /var/log/auth.log
grep -i "sudo" /var/log/secure
journalctl --grep "runc" --since "2h ago"
```

#### 💣 3. Web Logs

```bash
grep -E "(cmd=|php\?|shell=)" /var/log/nginx/access.log
```

***

### IX. ⚙️ Memory + Disk + Network Fusion

Example adversary chain:

1️⃣ Suspicious PowerShell in Sysmon →\
2️⃣ Same PID in `pslist` (Volatility) →\
3️⃣ DLL injected (`malfind`) →\
4️⃣ HTTP POST observed (Wireshark) →\
5️⃣ IOC match in YARA.

→ **Confirmed beaconing malware.**

***

### X. ⚙️ Threat Intel Integration

| Source                       | Use                        |
| ---------------------------- | -------------------------- |
| **MISP**                     | Share IOCs with community  |
| **AlienVault OTX**           | Get TTPs / threat feeds    |
| **Abuse.ch / Feodo Tracker** | Known malware IPs          |
| **Sigma Rules**              | Generic detection patterns |
| **MITRE ATT\&CK**            | Map observed techniques    |

Example:

```
Execution → T1059.001 (PowerShell)
Persistence → T1053.005 (Scheduled Task)
Exfiltration → T1048.003 (Exfil via HTTP)
```

***

### XI. ⚙️ Case Study Example

**Incident: Suspicious outbound connections**

#### 🧩 Step 1: Initial Alert

EDR detects `rundll32.exe` spawning `powershell.exe`.

#### ⚙️ Step 2: Memory Analysis

```bash
volatility3 -f mem.raw windows.pslist | grep powershell
volatility3 -f mem.raw windows.malfind --pid <pid>
```

Finds shellcode injected into PowerShell.

#### 💣 Step 3: Network Review

Wireshark shows beacon to `api-update[.]com` every 60s.

#### ⚙️ Step 4: IOC Generation

```
SHA256: a912f...  
Domain: api-update.com  
Parent: rundll32.exe  
Technique: T1059.001, T1055
```

#### ⚙️ Step 5: Containment & Eradication

* Isolate host from network
* Dump process memory
* Delete scheduled tasks
* Rotate credentials

***

### XII. ⚙️ Threat Hunting Playbook Snippets

#### 🧠 PowerShell Abuse Hunt

```
EventID:1 AND process.command_line:"-enc" OR "IEX("
```

#### ⚙️ RDP Lateral Movement

```
EventID:4624 AND LogonType:10 AND SourceNetworkAddress!="internal_subnet"
```

#### 💣 Suspicious Child Process Chains

```
ParentImage: winword.exe AND ChildImage: powershell.exe
```

***

### XIII. ⚙️ Automation and Reporting

#### 🧩 1. Use SOAR (Security Orchestration Automation)

Platforms:

* **TheHive**
* **Cortex**
* **Shuffle**
* **Phantom (Splunk)**

Automate: IOC lookup → containment → enrichment.

#### ⚙️ 2. Incident Report Template

| Field            | Example                      |
| ---------------- | ---------------------------- |
| Incident ID      | IR-2025-041                  |
| Description      | PowerShell-based persistence |
| Detection Method | Sysmon + YARA                |
| Root Cause       | Malicious document execution |
| Impact           | Credential exfiltration      |
| Actions          | Host isolation, patching     |
| IOCs             | Domain, hash, IP             |
| MITRE Mapping    | T1059.001, T1053.005         |

***

### XIV. ⚙️ Pro Threat Hunting Tools

| Category               | Tools                             |
| ---------------------- | --------------------------------- |
| **Memory Analysis**    | Volatility3, Rekall               |
| **Network Analysis**   | Wireshark, Zeek, NetworkMiner     |
| **Endpoint Telemetry** | Sysmon, Velociraptor, OSQuery     |
| **Hunting / EDR**      | ELK, Wazuh, LimaCharlie, Sentinel |
| **Threat Intel**       | MISP, ATT\&CK Navigator, Malpedia |
| **Automation**         | SOAR (TheHive + Cortex), Shuffle  |

***

### XV. ⚔️ Pro Tips & Operator Tricks

✅ **Baseline Everything** — Know normal before you hunt abnormal.\
✅ **Correlate, Don’t Guess** — Processes + Logs + PCAPs = truth.\
✅ **Use Timestamps Aggressively** — Attackers trip on timing inconsistencies.\
✅ **Memory First on Live Hosts** — Evidence fades fast.\
✅ **Tag All IOCs** — For later correlation with future incidents.\
✅ **Pivot From One Artifact** — Every DLL, PID, or IP leads somewhere.\
✅ **Automate IOC Enrichment** — VirusTotal, AbuseIPDB, GreyNoise APIs.\
✅ **Work Backwards From Persistence** — The end of the chain often reveals the beginning.

***

### XVI. ⚙️ Quick Reference Table

| Task               | Command / Tool       | Description                   |
| ------------------ | -------------------- | ----------------------------- |
| Memory Acquisition | `winpmem`, `lime`    | Dump live RAM                 |
| Disk Imaging       | `dd`, `FTK Imager`   | Collect disk evidence         |
| Network Capture    | `tcpdump`, `tshark`  | Capture traffic               |
| Timeline           | `log2timeline.py`    | Combine logs chronologically  |
| IOC Detection      | `yara`, `sigma`      | Match known threat indicators |
| Correlation        | `ELK`, `Splunk`      | Log aggregation               |
| Threat Intel       | `MISP`, `ATT&CK`     | Map to known groups           |
| Forensics          | `volatility3`        | Deep memory analysis          |
| Automation         | `TheHive`, `Shuffle` | Response playbooks            |

***
