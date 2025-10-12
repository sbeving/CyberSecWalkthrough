---
icon: face-lying
---

# Deception & Active Defense

## **Deception & Active Defense — Turning the Hunter into the Hunted**

***

**Deception** is the deliberate placement of **false data, traps, and breadcrumbs** to mislead, detect, and study adversaries.\
**Active Defense** extends this — **engaging** intruders through controlled counter-intelligence, observation, and containment.

This chapter covers how to **design deception layers**, **deploy honeypots & honeytokens**, and **turn attacker behavior into actionable intelligence**.

***

### I. 🧩 Core Concepts

| Concept                  | Description                                                     |
| ------------------------ | --------------------------------------------------------------- |
| **Deception Technology** | Use of decoys and traps to detect attackers early.              |
| **Active Defense**       | Dynamic responses that observe, engage, and counter intrusions. |
| **Honeypot**             | Fake system designed to attract attackers.                      |
| **Honeytoken**           | Bait data element (credential, file, API key).                  |
| **Breadcrumbs**          | Subtle clues that guide attackers toward monitored traps.       |
| **Adversary Engagement** | Controlled, legal interaction to gather intelligence.           |

***

### II. ⚙️ The Deception Pyramid

| Layer                         | Goal                            | Example                               |
| ----------------------------- | ------------------------------- | ------------------------------------- |
| **L1: Data Deception**        | Bait credentials, fake API keys | `.env` file with decoy tokens         |
| **L2: Endpoint Deception**    | Fake processes or registry keys | Dummy “AVService.exe”                 |
| **L3: Network Deception**     | Honeypots, decoy hosts          | Cowrie, Honeyd                        |
| **L4: Application Deception** | Fake admin panels, portals      | Django honeypages                     |
| **L5: Active Engagement**     | Controlled attacker interaction | Canarytokens, T-Pot, custom sinkholes |

***

### III. ⚙️ Design Principles

✅ **Believability:** Deceptions must appear realistic within your environment.\
✅ **Isolation:** All honeynets run sandboxed — never connect to production.\
✅ **Attribution Value:** Capture metadata (IP, commands, payloads, time).\
✅ **Scalability:** Automate deployment and resets after each attack.\
✅ **Telemetry Integration:** Log everything into SIEM (ELK, Wazuh, Splunk).

***

### IV. ⚙️ Data & Credential Deception

#### 🧠 1. Honeytokens

Fake credentials or secrets that trigger alerts when used.

Example `.env`:

```bash
AWS_SECRET_KEY=ABCD1234FAKEKEY
DB_PASSWORD=SuperSecret!2025
```

Monitor via:

* **Canarytokens.org**
* **Thinkst Canary**
* **Akamai Guardicore Deception**

#### ⚙️ 2. Fake SSH Keys

```bash
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCfakekey test@canary
```

→ Log if key is used in authentication attempts.

#### 💣 3. Embedded Traps in Files

* Office docs with tracking pixels (Microsoft 365 logs beacon).
* PDFs with unique URIs (detect open attempts).
* Fake “passwords.txt” with a canary credential.

***

### V. ⚙️ Endpoint Deception

#### 🧩 1. Fake Processes / Services

Use Sysinternals or scripts to create false registry entries:

```powershell
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityUpdate" -Value "C:\Windows\Temp\monitor.exe"
```

→ No actual binary — attempts to run trigger alerts.

#### ⚙️ 2. Process Doppelgängers

Create dummy binaries with known malware names (`mimikatz.exe`, `lsass_dump.exe`) to detect unauthorized execution.

#### 💣 3. File Watchers

Use **OSQuery** or **Sysmon** to alert when honeypot files are accessed:

```sql
SELECT * FROM file_events WHERE path LIKE 'C:\FakeHRData\%';
```

***

### VI. ⚙️ Network Deception

#### 🧠 1. Low-Interaction Honeypots

Simulate services to collect connection data:

```bash
sudo apt install cowrie
sudo systemctl start cowrie
```

Logs: credentials, commands, IPs.

#### ⚙️ 2. High-Interaction Honeynets

Deploy isolated VMs or containers with real services:

* **T-Pot Framework**
* **Dionaea** (malware collection)
* **Conpot** (ICS simulation)

#### 💣 3. Fake Admin Portals

Serve convincing decoy web interfaces with embedded trackers:

```bash
python3 -m http.server 8080
```

Include hidden `<img src="https://logserver/pixel?id={{uuid}}">` to log hits.

***

### VII. ⚙️ Application & Cloud Deception

| Layer                          | Technique           | Example                                   |
| ------------------------------ | ------------------- | ----------------------------------------- |
| **Web App**                    | Decoy admin pages   | `/admin_fake_panel/`                      |
| **Database**                   | Dummy tables        | `user_credentials_fake`                   |
| **Cloud (AWS, Azure)**         | Fake IAM roles      | “backup-admin-deprecated”                 |
| **Containerized Environments** | Honeypod containers | Dockerized decoys linked to logging stack |

***

### VIII. ⚙️ Adversary Engagement

#### 🧩 1. Controlled Interaction

Mirror real systems with **limited functionality** and full logging.

#### ⚙️ 2. Command Capture

Record attacker commands (Cowrie or Kippo logs) for behavioral profiling.

#### 💣 3. Attribution Through Engagement

Correlate:

* Reused IPs → infrastructure fingerprinting
* Command patterns → specific groups
* Toolkits → reused malware / TTPs

***

### IX. ⚙️ Active Defense Integration

| Activity       | Tool                | Goal                            |
| -------------- | ------------------- | ------------------------------- |
| **Detection**  | Sysmon + ELK        | Monitor honeypot access         |
| **Enrichment** | MISP, ThreatFox     | Tag attacker IOCs               |
| **Automation** | TheHive + Cortex    | Auto-case generation            |
| **Response**   | Firewall API / SOAR | Block IP, isolate host          |
| **Analysis**   | CAPEv2, Volatility  | Analyze payloads from honeypots |

***

### X. ⚙️ Detection Use Cases (SIEM / KQL)

#### 🧠 Honeytoken Access

```kql
event.dataset : "authentication" and account.name : "decoy_user"
```

#### ⚙️ Fake File Access

```kql
file.path : "C:\\FakeHRData\\*" and event.action : "read"
```

#### 💣 SSH Honeypot Login

```kql
event.dataset : "cowrie" and event.action : "login.success"
```

***

### XI. ⚙️ Intelligence Value from Deception

| Artifact          | Extracted Data    | Use                             |
| ----------------- | ----------------- | ------------------------------- |
| SSH Commands      | Attacker tactics  | Build YARA or Sigma rules       |
| Malware Uploads   | Samples           | Sandbox for signature dev       |
| Source IPs        | Infra mapping     | Correlate via VirusTotal/Shodan |
| Timing / Behavior | Schedule patterns | Identify operator time zones    |
| Credential Use    | Account targeting | Assess lateral movement intent  |

***

### XII. ⚙️ Deception Automation

Deploy full deception environments via code:

```bash
git clone https://github.com/telekom-security/tpotce
cd tpotce
sudo ./install.sh
```

Pre-bundled decoys: Cowrie, Dionaea, Elastic stack, Suricata, p0f, and Kibana dashboards.

***

### XIII. ⚙️ Legal & Ethical Guidelines

✅ Always isolate honeynets from production.\
✅ Never retaliate or counter-hack.\
✅ Collect intelligence passively.\
✅ Comply with data privacy laws (GDPR, NIST, ISO 27035).\
✅ Store and share data responsibly via vetted TIPs.

***

### XIV. ⚔️ Pro Tips & Operator Habits

✅ **Every Access = Suspicious.** If someone finds your bait, they’re already inside.\
✅ **Rotate Tokens.** Change honeycredentials frequently.\
✅ **Don’t Overdo.** Too many decoys break realism.\
✅ **Chain Alerts.** Combine honeypot logs with Sysmon for context.\
✅ **Profile, Don’t Panic.** Every hit teaches attacker methodology.\
✅ **Use Behavioral Signatures.** Detect unique commands (`uname -a`, `whoami`, `ls /home`).\
✅ **Automate Enrichment.** Push honeypot data → MISP for IOC correlation.\
✅ **Visualize Campaigns.** Use Kibana or Maltego to graph attacker flow.

***

### XV. ⚙️ Quick Reference Table

| Goal            | Tool / Command                        | Description                   |
| --------------- | ------------------------------------- | ----------------------------- |
| Fake Credential | `Canarytokens.org`                    | Triggers alert on use         |
| SSH Honeypot    | `Cowrie`                              | Logs brute-force + commands   |
| Web Decoy       | `HoneyDB`, `Django honeypages`        | Captures HTTP payloads        |
| Malware Catcher | `Dionaea`                             | Stores dropped binaries       |
| Full Honeynet   | `T-Pot`                               | All-in-one deception platform |
| Cloud Deception | `Thinkst Canary`, `Akamai Guardicore` | SaaS-level decoys             |
| Alerting        | `SIEM / SOAR`                         | Automate detections           |
| Analysis        | `Volatility`, `CAPEv2`                | Reverse captured payloads     |

***
