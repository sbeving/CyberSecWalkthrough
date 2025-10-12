---
icon: person-falling
---

# Incident Response & Blue Team Correlation Matrix

## **Incident Response & Blue Team Correlation Matrix — Detect, Analyze, Contain, Recover**

> 🧠 The goal isn’t only to hack — it’s to understand how defenders catch you.\
> This playbook turns your offensive mastery into defensive insight: **every action leaves evidence**.

***

### I. 🧩 Core Incident Response Lifecycle

| Phase               | Objective                                  | Example                           |
| ------------------- | ------------------------------------------ | --------------------------------- |
| **Preparation**     | Build detection, hardening, response plans | SOC baseline setup                |
| **Identification**  | Detect & confirm malicious activity        | Log anomaly, IDS alert            |
| **Containment**     | Isolate infected assets                    | Network quarantine                |
| **Eradication**     | Remove malware, persistence                | Delete payloads, registry cleanup |
| **Recovery**        | Restore normal operations                  | Validate system integrity         |
| **Lessons Learned** | Update detections & playbooks              | Add new IOC signatures            |

🧠 _Good IR = data + discipline._ Don’t jump to wipe before you analyze.

***

### II. 🧱 Log Source Correlation Overview

| System       | Primary Source                   | Description                       |
| ------------ | -------------------------------- | --------------------------------- |
| **Windows**  | Event Viewer, Sysmon, Defender   | Processes, registry, network, AV  |
| **Linux**    | /var/log, auditd, journald       | Authentication & execution        |
| **Network**  | IDS/IPS, Netflow, Zeek, Suricata | Traffic anomalies                 |
| **Cloud**    | CloudTrail, Azure Activity Logs  | API actions, IAM changes          |
| **Endpoint** | EDR/AV logs                      | In-memory & behavioral detections |

🧩 _Correlate horizontally_: if PowerShell executes + HTTP POST anomaly → possible exfil.

***

### III. 🧠 Event Correlation Matrix (Red → Blue Mapping)

| Red Activity                        | Detection Source       | Key Events / Indicators                                                                |
| ----------------------------------- | ---------------------- | -------------------------------------------------------------------------------------- |
| **Privilege Escalation**            | Sysmon, Security       | 4672 (Special Logon), 4688 (Process Creation), privilege escalation from user → SYSTEM |
| **Service Abuse**                   | System                 | 7045 (Service Install), Sysmon ID 1                                                    |
| **Scheduled Task Creation**         | TaskScheduler / Sysmon | 4698                                                                                   |
| **Registry Persistence**            | Sysmon                 | 13 (Registry Value Set)                                                                |
| **WMI Persistence**                 | WMI-Activity           | 5858                                                                                   |
| **PowerShell Execution**            | ScriptBlockLogging     | 4104, command lines with `IEX`, `DownloadString`                                       |
| **Mimikatz / LSASS Dump**           | Sysmon / Defender      | 10 (ProcessAccess), AMSI alert, lsass.exe handle                                       |
| **Credential Theft (DCSync)**       | AD / Security          | 4662 with “GetChangesAll” rights                                                       |
| **Network Pivot (Chisel/Socat)**    | Firewall / Netflow     | Unusual long-lived outbound connections                                                |
| **NTLM Relay / Responder**          | Domain Controller      | Event 4624 Type 3 bursts, authentication errors                                        |
| **Reverse Shell / Exfil**           | Proxy / IDS            | Suspicious HTTP POST, encoded base64                                                   |
| **Token Impersonation**             | Sysmon                 | 10, privilege escalation to SYSTEM without login                                       |
| **AMSI Bypass**                     | Defender               | Script alert “amsiutils” keyword                                                       |
| **Lateral Movement**                | WinRM / SMB Logs       | 4624 Type 3, new administrative sessions                                               |
| **Privilege Abuse (sudo)**          | auditd / syslog        | “COMMAND=/bin/bash” by non-root                                                        |
| **Binary Execution (Linux)**        | auditd                 | `execve` events with uncommon args                                                     |
| **Fileless Execution**              | EDR                    | memory-only PowerShell or MSHTA detection                                              |
| **Persistence via rc.local / cron** | auditd                 | File modification / cron job creation                                                  |

🧠 _Each offensive move maps to at least one blue control — your job: identify which ones._

***

### IV. 🔎 Log Analysis Cheat Sheet

| Source                   | Key Event IDs / Logs                                                                                       | Notes                      |
| ------------------------ | ---------------------------------------------------------------------------------------------------------- | -------------------------- |
| **Windows Security Log** | 4624 (Logon), 4625 (Failed Logon), 4688 (Process Creation), 4672 (Privileged Logon), 4698 (Scheduled Task) | Base of all investigations |
| **Sysmon**               | 1 (Process), 3 (Network), 7 (Image Load), 10 (Process Access), 13 (Registry), 22 (DNS)                     | Deep visibility            |
| **Defender AV**          | Threat detections                                                                                          | Correlate with file hash   |
| **Auditd (Linux)**       | `execve`, `chmod`, `sudo`, `setuid`                                                                        | Linux process tracing      |
| **auth.log**             | `Accepted password`, `Failed password`                                                                     | SSH / sudo activity        |
| **Zeek / Suricata**      | conn.log, dns.log, http.log                                                                                | Traffic-level view         |
| **Firewall / Proxy**     | Blocked/allowed connections                                                                                | Outbound exfil             |

🧠 _Always pivot from log event → process tree → network connection → user context._

***

### V. 🧱 Forensic Artifacts (Windows + Linux)

| Artifact                         | Description                   | Tool                        |
| -------------------------------- | ----------------------------- | --------------------------- |
| **Prefetch / Shimcache**         | Evidence of executed binaries | PEcmd, AppCompatCacheParser |
| **SRUM / Amcache**               | App usage & network data      | Eric Zimmerman tools        |
| **Registry Hives**               | Persistence & configuration   | RegRipper                   |
| **$MFT / USN Journal**           | File creation timelines       | MFTECmd                     |
| **Memory Dump**                  | Live process evidence         | Volatility / Rekall         |
| **Browser Data**                 | Credential & history info     | Nirsoft WebBrowserPassView  |
| **Bash History / .zsh\_history** | Command history               | Simple text parsing         |
| **Syslog / Auditd Logs**         | Process and privilege trail   | ausearch, aureport          |

***

### VI. 🧠 Memory Forensics Quick Reference

| Goal                   | Volatility Plugin / Command |
| ---------------------- | --------------------------- |
| Process list           | `pslist` / `psscan`         |
| Network connections    | `netscan`                   |
| Command history        | `cmdscan` / `consoles`      |
| DLLs / modules         | `dlllist`                   |
| LSASS dump detection   | `malfind`, `ldrmodules`     |
| Injected code          | `malfind`                   |
| Persistence indicators | `autoruns`                  |

🧠 _If you suspect fileless malware → always dump memory first._

***

### VII. 🧩 Network Anomaly Detection

| Indicator                       | Possible Cause                  | Follow-up                        |
| ------------------------------- | ------------------------------- | -------------------------------- |
| Long-lived TCP session          | Tunneling (chisel, SSH reverse) | Inspect destination / User-Agent |
| High entropy payloads           | Encrypted exfil / beaconing     | Check periodicity & jitter       |
| Outbound HTTP to uncommon ports | C2 evasion                      | Decode headers                   |
| DNS TXT / large queries         | DNS tunneling                   | Base64 decode                    |
| Internal-to-internal SMB        | Lateral movement                | Check process + username         |

🧠 Combine network + endpoint telemetry → complete attack timeline.

***

### VIII. 🔒 Triage Playbook (IR Tactics)

| Step              | Action                                                 |
| ----------------- | ------------------------------------------------------ |
| **1️⃣ Identify**  | Check alert source → validate event with endpoint logs |
| **2️⃣ Isolate**   | Disconnect network interface / isolate VM              |
| **3️⃣ Preserve**  | Memory dump, disk image, volatile data                 |
| **4️⃣ Analyze**   | Timeline, process tree, log correlation                |
| **5️⃣ Contain**   | Remove persistence, revoke credentials                 |
| **6️⃣ Eradicate** | Patch exploited vector                                 |
| **7️⃣ Recover**   | Rebuild systems, monitor                               |
| **8️⃣ Report**    | Document TTPs, update detections                       |

***

### IX. 🧰 Detection Engineering (ATT\&CK Mapping)

| Tactic               | Technique                     | Detection Hint              | Tool          |
| -------------------- | ----------------------------- | --------------------------- | ------------- |
| Initial Access       | Phishing (T1566)              | Mail logs + attachment hash | SIEM          |
| Execution            | PowerShell (T1059.001)        | Sysmon 4104                 | Sigma rule    |
| Persistence          | Registry Run Keys (T1547.001) | Sysmon 13                   | Sysmon config |
| Privilege Escalation | Token Manipulation (T1134)    | Sysmon 10                   | EDR           |
| Defense Evasion      | AMSI Bypass (T1562.001)       | AMSI logs                   | Defender      |
| Credential Access    | LSASS Dump (T1003)            | Sysmon 10 + AV              | EDR           |
| Discovery            | Network Scan (T1046)          | Zeek conn.log               | IDS           |
| Lateral Movement     | SMB / WinRM (T1021)           | 4624 Type 3 / 10            | SIEM          |
| Collection           | File Access (T1005)           | Auditd / FIM                | Auditd        |
| Exfiltration         | HTTP / DNS Tunnel (T1048)     | Zeek http.log               | Proxy logs    |
| Impact               | File Encryption (T1486)       | Mass file changes           | FIM           |

🧠 Use Sigma → convert → Splunk / ELK / KQL rules.

***

### X. ⚙️ Rapid Response Tools Arsenal

| Category               | Tool                         | Description                  |
| ---------------------- | ---------------------------- | ---------------------------- |
| **Log Analysis**       | ELK, Splunk, Wazuh, Graylog  | SIEM platforms               |
| **Endpoint Forensics** | Velociraptor, KAPE, DFIR-ORC | Collect artifacts            |
| **Memory Forensics**   | Volatility, Rekall           | Analyze RAM dumps            |
| **Network Capture**    | Zeek, Suricata, Wireshark    | Inspect traffic              |
| **IR Coordination**    | TheHive, Cortex, MISP        | Case management, IOC sharing |
| **Malware Sandboxing** | Cuckoo, Any.Run              | Behavioral analysis          |

***

### XI. 🧠 IOC (Indicators of Compromise) Checklist

| IOC Type                     | Example                                              |
| ---------------------------- | ---------------------------------------------------- |
| **File Hashes (MD5/SHA256)** | b8f5a5d6c76db…                                       |
| **Domain / IP**              | `c2-stage.evilcdn.net`                               |
| **Registry Keys**            | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| **Mutexes / Pipes**          | `Global\svc_mutex_123`                               |
| **Scheduled Tasks**          | `\Updater`                                           |
| **File Paths**               | `/tmp/.xservice`, `C:\Users\Public\updater.exe`      |
| **User Agents**              | `Mozilla/5.0 CustomBeacon`                           |
| **Email Artifacts**          | Subject: “Invoice2025.zip”                           |

***

### XII. 🔥 Response Playbook Examples

#### 🪟 Windows Compromise

1. Collect:
   * `wevtutil epl Security sec.evtx`
   * `tasklist /v > tasks.txt`
2. Acquire memory:
   * `procdump -ma lsass.exe`
3. Preserve network trace:
   * `netsh trace start capture=yes`
4. Isolate, dump artifacts, rebuild.

#### 🐧 Linux Compromise

1. `ps aux`, `netstat -tulnp`
2. `last -a`, `grep "Accepted" /var/log/auth.log`
3. `find / -mmin -10` (recently modified)
4. Tar `/etc`, `/var/log`, `/tmp`, `/home`.

***

### XIII. 🧱 Post-Incident Review Template

```
Incident: Unauthorized PowerShell Activity (T1059.001)
Date/Time: 2025-10-12
Scope: 2 endpoints, 1 domain account

Root Cause:
- Malicious PowerShell payload loaded via mshta.

Indicators:
- Sysmon ID 1 (mshta.exe → powershell.exe)
- Event 4104 (DownloadString detected)
- Outbound HTTP to 45.77.x.x

Response:
- Isolated host
- Disabled account
- Removed persistence (HKCU Run Key)
- Added Sigma rule: powershell + mshta chain

Lessons:
- Enforce PowerShell Constrained Language Mode
- Add network rule for suspicious User-Agents
```

***

### XIV. 🧩 Red-to-Blue Correlation Summary

| Offensive Step      | Defensive View              |
| ------------------- | --------------------------- |
| PrivEsc             | Elevated process spawn      |
| Pivoting            | New listening ports         |
| Token Impersonation | New session from same token |
| Exfiltration        | Unusual POST + base64       |
| AMSI Bypass         | AMSI keyword                |
| Fileless Exec       | Memory-only PowerShell      |
| Persistence         | WMI / Task creation         |

🧠 _Everything the red team does leaves echoes — train to hear them._

***

### XV. 🧠 Defensive Hardening Recap

| Category             | Action                                 |
| -------------------- | -------------------------------------- |
| **Windows**          | Enable Sysmon + PowerShell logging     |
| **Linux**            | Auditd + AppArmor enforcement          |
| **Active Directory** | Tiered admin model, disable LLMNR/NBNS |
| **Endpoints**        | EDR + AMSI                             |
| **Network**          | Segmentation + TLS inspection          |
| **Detection**        | Sigma + MITRE ATT\&CK coverage mapping |
| **Response**         | Defined escalation & containment SOPs  |

***
