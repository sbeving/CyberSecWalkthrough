---
icon: user-shakespeare
---

# Threat Intel & Attribution

## **Threat Intelligence & Attribution — Hunting the Hunters**

***

Threat Intelligence (TI) is the art and science of **collecting, analyzing, and contextualizing adversary data** to predict and prevent attacks.\
Attribution is the process of **connecting indicators, behaviors, and infrastructure** back to a specific threat actor, campaign, or nation-state.

This guide is your **strategic and analytical playbook** — covering OSINT, malware clustering, infrastructure tracking, and APT profiling.

***

### I. 🧩 Core Concepts

| Concept                             | Description                                                    |
| ----------------------------------- | -------------------------------------------------------------- |
| **Threat Intelligence**             | Knowledge that helps understand and counter adversaries.       |
| **Attribution**                     | Associating activity with specific threat actors.              |
| **Indicators of Compromise (IOCs)** | Observable artifacts (hashes, IPs, domains).                   |
| **TTPs**                            | Tactics, Techniques, and Procedures from MITRE ATT\&CK.        |
| **Campaign**                        | A series of attacks with consistent tools and infrastructure.  |
| **Threat Actor**                    | Individual or group behind the campaign (e.g., APT29, FIN7).   |
| **Cluster**                         | A collection of linked activities (shared C2s, malware, code). |

***

### II. ⚙️ Intelligence Cycle

| Phase                 | Description                         | Example Tools                                                |
| --------------------- | ----------------------------------- | ------------------------------------------------------------ |
| **1️⃣ Direction**     | Define what to investigate          | Define: “Track phishing infrastructure targeting healthcare” |
| **2️⃣ Collection**    | Gather indicators & data            | Shodan, VirusTotal, MISP                                     |
| **3️⃣ Processing**    | Clean and correlate data            | Python scripts, YARA, Sigma                                  |
| **4️⃣ Analysis**      | Identify patterns and intent        | ATT\&CK mapping, campaign profiling                          |
| **5️⃣ Dissemination** | Share intel with teams or community | MISP, ThreatConnect                                          |
| **6️⃣ Feedback**      | Reassess effectiveness              | Update IOCs and detection rules                              |

***

### III. ⚙️ Sources of Threat Intelligence

| Type                    | Source Examples                                         |
| ----------------------- | ------------------------------------------------------- |
| **Open Source (OSINT)** | VirusTotal, Shodan, Abuse.ch, AlienVault OTX, ThreatFox |
| **Internal**            | Logs, SIEM alerts, EDR telemetry                        |
| **Closed/Commercial**   | Mandiant, Recorded Future, CrowdStrike Falcon X         |
| **Dark Web / Telegram** | Breach forums, marketplaces, paste sites                |
| **Honeypots**           | Cowrie, Dionaea, T-Pot                                  |
| **Community Feeds**     | MISP, MalwareBazaar, Feodo Tracker                      |

***

### IV. ⚙️ Indicator Types & Use

| Indicator                | Example                             | Usage                   |
| ------------------------ | ----------------------------------- | ----------------------- |
| **File Hash**            | `9f3a7d12345abcd...`                | Detect malware          |
| **Domain / IP**          | `update-microsoft[.]xyz`            | Block C2 comms          |
| **URL**                  | `hxxp://malicioussite.com/load.php` | Detect phishing         |
| **Mutex / Service Name** | `Global\WindowsUpdateSvc`           | Identify persistence    |
| **Registry Key**         | `HKCU\Software\Backdoor`            | Detect implant activity |
| **YARA Signature**       | Code fingerprint                    | Detect similar malware  |

***

### V. ⚙️ Infrastructure Analysis (OSINT)

#### 🧠 1. Passive DNS Lookups

```bash
whois domain.com
dig +short domain.com
```

#### ⚙️ 2. Subdomain Enumeration

```bash
subfinder -d domain.com
amass enum -passive -d domain.com
```

#### 💣 3. IP / ASN Pivoting

```bash
shodan search org:"Contoso Ltd"
censys search services.http.response.body="update.php"
```

#### ⚙️ 4. Correlate Infrastructure

Use:

* **PassiveTotal**
* **RiskIQ**
* **VirusTotal Graph**
* **Maltego**\
  to visualize C2 and phishing clusters.

***

### VI. ⚙️ Malware Intelligence & Clustering

#### 🧠 1. Collect Samples

From:

* MalwareBazaar
* VXVault
* ANY.RUN
* Hybrid Analysis

#### ⚙️ 2. Extract IOCs

```bash
strings sample.exe | grep -E "http|cmd|key"
```

#### 💣 3. Automated Analysis

Upload to:

* **CAPEv2** (sandbox automation)
* **Joe Sandbox**
* **Intezer Analyze**

#### ⚙️ 4. Code Similarity Analysis

```bash
ssdeep sample1.exe sample2.exe
```

→ If match ≥ 80%, likely same campaign.

#### 🧩 5. YARA Detection Example

```yara
rule EvilLoader {
  strings:
    $s1 = "VirtualAllocEx"
    $s2 = "cmd.exe /c"
    $s3 = "POST /upload"
  condition:
    all of them
}
```

***

### VII. ⚙️ MITRE ATT\&CK-Based Correlation

Map malware behavior to ATT\&CK techniques.

| Phase             | Technique       | ID        |
| ----------------- | --------------- | --------- |
| Execution         | PowerShell      | T1059.001 |
| Persistence       | Scheduled Task  | T1053.005 |
| Credential Access | LSASS Dump      | T1003.001 |
| Defense Evasion   | Obfuscation     | T1027     |
| Exfiltration      | Web Upload      | T1048.003 |
| C2                | HTTPS Beaconing | T1071.001 |

→ Pattern repetition helps attribute campaigns to known APTs.

***

### VIII. ⚙️ Threat Actor Profiling

| Actor                    | Region         | Targets          | TTP Highlights                |
| ------------------------ | -------------- | ---------------- | ----------------------------- |
| **APT29 (Cozy Bear)**    | Russia         | Gov, NGOs        | Spearphishing, cloud abuse    |
| **APT32 (OceanLotus)**   | Vietnam        | Asia-Pacific     | Custom backdoors              |
| **FIN7**                 | Eastern Europe | Finance, Retail  | C2 automation, phishing lures |
| **Lazarus Group**        | North Korea    | Crypto, defense  | Supply-chain, DGA domains     |
| **TA505**                | Global         | Financial        | Malspam, loaders              |
| **UNC2452 (SolarWinds)** | Russia         | Software vendors | Supply-chain injection        |

Use frameworks like:

* **MITRE ATT\&CK Groups**
* **Malpedia**
* **APTMap**

***

### IX. ⚙️ Campaign Correlation & Clustering

#### 🧠 1. Shared Artifacts

Compare between samples:

* Same mutex
* Reused C2 domains
* Identical encryption keys
* Common code fragments

#### ⚙️ 2. Infrastructure Overlap

Use `VirusTotal Graph` or `RiskIQ` to correlate domains:

```
domain → IP → SSL Cert → ASN → Org → New domains
```

#### 💣 3. Temporal Analysis

Track timestamps of:

* Domain registration
* Sample submission
* C2 activity

→ Identify campaign waves.

***

### X. ⚙️ Threat Intelligence Platforms (TIPs)

| Platform          | Purpose                             |
| ----------------- | ----------------------------------- |
| **MISP**          | Open-source sharing & enrichment    |
| **OpenCTI**       | Graph-based cyber threat modeling   |
| **ThreatConnect** | Enterprise-grade TIP with workflows |
| **EclecticIQ**    | Threat intel analysis and sharing   |
| **IntelOwl**      | Automated enrichment framework      |

***

### XI. ⚙️ Enrichment & Correlation Tools

| Task                   | Tool                                   | Description                 |
| ---------------------- | -------------------------------------- | --------------------------- |
| Hash / Domain Lookup   | `VirusTotal`, `ThreatFox`, `AbuseIPDB` | IOC reputation              |
| IP / ASN Mapping       | `Censys`, `Shodan`, `Greynoise`        | Infra pivoting              |
| Graph Analysis         | `Maltego`, `OpenCTI`                   | Relationship visualization  |
| Malware Similarity     | `Intezer`, `CAPEv2`, `ssdeep`          | Code DNA comparison         |
| Threat Feed Management | `MISP`, `OpenCTI`                      | IOC sharing and correlation |

***

### XII. ⚙️ Threat Actor Attribution Workflow

1️⃣ Collect artifacts (hashes, C2s, filenames, code).\
2️⃣ Cluster samples by similarity.\
3️⃣ Enrich infrastructure using OSINT.\
4️⃣ Compare TTPs to ATT\&CK framework.\
5️⃣ Cross-reference known APT profiles.\
6️⃣ Hypothesize actor attribution.\
7️⃣ Validate over multiple data points (not just indicators).

**Remember:** Attribution ≠ Proof — it’s confidence-based analysis.

***

### XIII. ⚙️ Confidence Scoring System

| Confidence Level | Description                                      |
| ---------------- | ------------------------------------------------ |
| **High**         | Multiple strong overlaps (infra + TTP + tooling) |
| **Medium**       | Shared tools or partial overlap                  |
| **Low**          | Coincidental indicators, no behavior match       |
| **None**         | No verifiable linkage                            |

***

### XIV. ⚙️ Reporting & Dissemination

#### 🧩 Intelligence Report Template

| Field           | Example                                  |
| --------------- | ---------------------------------------- |
| Report ID       | TI-2025-004                              |
| Threat Actor    | APT29                                    |
| Campaign        | Arctic Fox 2.0                           |
| Summary         | Credential phishing & cloud persistence  |
| IOCs            | Hashes, domains, IPs                     |
| TTPs            | T1059, T1071                             |
| Confidence      | High                                     |
| Recommendations | Harden MFA, monitor unusual OAuth tokens |

#### ⚙️ Sharing Platforms

* **MISP** — for IOC exchange.
* **STIX/TAXII** — for machine-readable intel sharing.
* **OpenCTI** — visual, graph-based sharing with context.

***

### XV. ⚔️ Pro Tips & Analyst Habits

✅ **Correlate Code + Infrastructure + TTPs** — True attribution lies at their intersection.\
✅ **Timeline Everything** — Attackers leave patterns in time.\
✅ **Track Dev Mistakes** — Reused compile paths or strings are gold.\
✅ **Cluster First, Attribute Later** — Don’t force names too early.\
✅ **Use OSINT + Sandbox + Memory Dumps Together** — Full visibility.\
✅ **Leverage YARA Automation** — Continuous detection of known patterns.\
✅ **Tag Everything with MITRE IDs** — Enables automatic TTP correlation.\
✅ **Stay Objective** — Attribution is probabilistic, not political.

***

### XVI. ⚙️ Quick Reference Table

| Goal                 | Tool / Command                     | Purpose                          |
| -------------------- | ---------------------------------- | -------------------------------- |
| IOC Lookup           | `VirusTotal`, `Abuse.ch`           | Identify known indicators        |
| Infrastructure Pivot | `Shodan`, `Censys`, `PassiveTotal` | Track C2 relationships           |
| Code Comparison      | `ssdeep`, `CAPEv2`, `Intezer`      | Cluster malware samples          |
| TTP Mapping          | `MITRE ATT&CK`                     | Identify attacker behavior       |
| Actor Research       | `Malpedia`, `ATT&CK Groups`        | Find known APTs                  |
| Threat Sharing       | `MISP`, `OpenCTI`                  | Collaborate and distribute intel |
| Confidence Tracking  | Analyst Scoring                    | Evaluate attribution strength    |

***
