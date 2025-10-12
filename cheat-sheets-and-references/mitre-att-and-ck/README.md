---
icon: bow-arrow
---

# MITRE ATT\&CK

## **MITRE ATT\&CK Cheat Sheet — The Operator’s TTP Bible**

> ⚠️ educational and authorized environments only.\
> this isn’t a “how to hack” guide — it’s a **map of adversary behaviors** that defenders and red teamers use to simulate and understand attacks.

***

### I. 🧩 MITRE ATT\&CK Framework Overview

| Layer             | Description                                                            |
| ----------------- | ---------------------------------------------------------------------- |
| **Tactic**        | The _why_ — adversary goal (e.g., persistence, privilege escalation).  |
| **Technique**     | The _how_ — method used to achieve that goal (e.g., registry run key). |
| **Sub-Technique** | A specific implementation of a technique.                              |
| **Procedure**     | Real-world example or tooling.                                         |

📘 Reference: [https://attack.mitre.org/](https://attack.mitre.org/)

***

### II. ⚡ MITRE ATT\&CK Tactics Overview (Enterprise)

| Phase                    | Tactic ID | Description                                        |
| ------------------------ | --------- | -------------------------------------------------- |
| **Reconnaissance**       | TA0043    | Gather victim data, open-source intel, scanning.   |
| **Resource Development** | TA0042    | Prepare infrastructure (domains, accounts).        |
| **Initial Access**       | TA0001    | Entry point — exploit, phishing, supply chain.     |
| **Execution**            | TA0002    | Run malicious code (scripts, binaries, payloads).  |
| **Persistence**          | TA0003    | Maintain foothold (autostart, accounts, registry). |
| **Privilege Escalation** | TA0004    | Gain higher permissions.                           |
| **Defense Evasion**      | TA0005    | Hide presence, disable security.                   |
| **Credential Access**    | TA0006    | Dump or steal credentials.                         |
| **Discovery**            | TA0007    | Enumerate environment and network.                 |
| **Lateral Movement**     | TA0008    | Move across systems.                               |
| **Collection**           | TA0009    | Gather sensitive data.                             |
| **Command & Control**    | TA0011    | Maintain communication channel.                    |
| **Exfiltration**         | TA0010    | Transfer data outside network.                     |
| **Impact**               | TA0040    | Disrupt, destroy, encrypt, or manipulate data.     |

***

### III. 🧠 Common Techniques by Phase (Quick Lookup)

#### 🧭 Reconnaissance

| Technique                      | ID    | Description                      |
| ------------------------------ | ----- | -------------------------------- |
| Active Scanning                | T1595 | Network and service scans.       |
| Gathering Victim Identity Info | T1589 | Harvest usernames, emails, etc.  |
| Search Open Websites/Domains   | T1593 | OSINT, GitHub, LinkedIn, Shodan. |

***

#### ⚡ Initial Access

| Technique                    | ID        | Description                       |
| ---------------------------- | --------- | --------------------------------- |
| Exploit Public-Facing App    | T1190     | Web app exploits, RCEs.           |
| Phishing: Spearphishing Link | T1566.002 | Malicious links.                  |
| Drive-by Compromise          | T1189     | Exploit via browsing.             |
| Valid Accounts               | T1078     | Using stolen credentials.         |
| Supply Chain Compromise      | T1195     | Compromised third-party software. |

***

#### 💣 Execution

| Technique                       | ID    | Description                             |
| ------------------------------- | ----- | --------------------------------------- |
| Command & Scripting Interpreter | T1059 | Bash, PowerShell, Python, etc.          |
| Scheduled Task / Job            | T1053 | Execute code on schedule.               |
| User Execution                  | T1204 | Trick user into running malicious file. |
| Compiled HTML File              | T1223 | Weaponized CHM for execution.           |

***

#### ♾️ Persistence

| Technique                          | ID    | Description                            |
| ---------------------------------- | ----- | -------------------------------------- |
| Registry Run Keys / Startup Folder | T1547 | Autostart persistence.                 |
| Scheduled Task / Cron              | T1053 | Periodic execution.                    |
| New Service                        | T1543 | Create system service for persistence. |
| Account Manipulation               | T1098 | Add or modify user accounts.           |

***

#### 🚀 Privilege Escalation

| Technique                 | ID        | Description                       |
| ------------------------- | --------- | --------------------------------- |
| Exploitation for PrivEsc  | T1068     | Kernel or SUID escalation.        |
| Setuid / Setgid           | T1548.001 | Linux file permission escalation. |
| Access Token Manipulation | T1134     | Windows impersonation.            |
| Bypass UAC                | T1548.002 | Elevate via UAC abuse.            |

***

#### 🕶️ Defense Evasion

| Technique                  | ID        | Description                      |
| -------------------------- | --------- | -------------------------------- |
| Obfuscated/Encrypted Files | T1027     | Encoded payloads, base64, XOR.   |
| File Deletion              | T1070.004 | Delete logs or traces.           |
| Masquerading               | T1036     | Rename or mimic system binaries. |
| Timestomping               | T1070.006 | Modify timestamps for stealth.   |
| Rootkit / Hooking          | T1014     | Modify OS behavior to hide.      |

***

#### 🧩 Credential Access

| Technique             | ID        | Description                        |
| --------------------- | --------- | ---------------------------------- |
| OS Credential Dumping | T1003     | Dump SAM/LSASS.                    |
| Keylogging            | T1056.001 | Capture input keystrokes.          |
| Brute Force           | T1110     | Password guessing.                 |
| Unsecured Credentials | T1552     | Hardcoded passwords, config leaks. |
| Pass-the-Hash         | T1550.002 | NTLM relay authentication.         |

***

#### 🔍 Discovery

| Technique                    | ID    | Description                 |
| ---------------------------- | ----- | --------------------------- |
| System Information Discovery | T1082 | Host info gathering.        |
| Network Service Scanning     | T1046 | Enumerate open ports.       |
| File and Directory Discovery | T1083 | Find important data.        |
| Account Discovery            | T1087 | Enumerate users and groups. |
| Cloud Service Discovery      | T1526 | Cloud resource enumeration. |

***

#### 🔄 Lateral Movement

| Technique                       | ID        | Description                 |
| ------------------------------- | --------- | --------------------------- |
| Remote Services (SMB, RDP, SSH) | T1021     | Access via remote services. |
| Pass-the-Hash                   | T1550.002 | Auth reuse via NTLM hashes. |
| Remote Desktop Protocol         | T1021.001 | RDP connection pivoting.    |
| Windows Admin Shares            | T1077     | Move through C$ and ADMIN$. |

***

#### 📦 Collection

| Technique      | ID    | Description                |
| -------------- | ----- | -------------------------- |
| Clipboard Data | T1115 | Harvest copy-paste info.   |
| Screen Capture | T1113 | Take screenshots.          |
| Input Capture  | T1056 | Log keystrokes and inputs. |
| Audio Capture  | T1123 | Microphone recording.      |

***

#### 🛰️ Command & Control (C2)

| Technique                  | ID        | Description                        |
| -------------------------- | --------- | ---------------------------------- |
| Web Protocols              | T1071.001 | HTTP/S C2 traffic.                 |
| Custom C2 Protocol         | T1095     | Non-standard comms.                |
| Domain Fronting            | T1090.004 | Hide C2 through CDN or legit host. |
| Encrypted Channel          | T1573     | TLS/SSL C2 sessions.               |
| Application Layer Protocol | T1071     | Use HTTP/HTTPS, DNS, or WebSocket. |

***

#### 📤 Exfiltration

| Technique                      | ID        | Description                        |
| ------------------------------ | --------- | ---------------------------------- |
| Exfiltration Over Web Services | T1567.002 | Upload to Dropbox, Slack, etc.     |
| Exfiltration Over C2 Channel   | T1041     | Send data through command channel. |
| Automated Exfiltration         | T1020     | Scripted or scheduled.             |

***

#### 💥 Impact

| Technique                  | ID    | Description                    |
| -------------------------- | ----- | ------------------------------ |
| Data Encryption for Impact | T1486 | Ransomware encryption.         |
| Defacement                 | T1491 | Website vandalism.             |
| Inhibit System Recovery    | T1490 | Delete backups/shadow copies.  |
| Data Destruction           | T1485 | Wipe disks or overwrite files. |

***

### IV. ⚙️ Quick Mappings for CTFs / Labs

| Scenario                   | Relevant Tactics           | Example Techniques |
| -------------------------- | -------------------------- | ------------------ |
| Web Shell Upload           | Initial Access / Execution | T1190, T1059       |
| PrivEsc via SUID           | Privilege Escalation       | T1068, T1548.001   |
| Lateral Movement via SMB   | Lateral Movement           | T1021.002          |
| Exfil via HTTP             | Exfiltration               | T1041, T1071.001   |
| AV Evasion via Base64      | Defense Evasion            | T1027              |
| Password Dump via Mimikatz | Credential Access          | T1003              |
| C2 over HTTPS              | Command & Control          | T1071.001, T1573   |

***

### V. 🧰 MITRE in Practice — How Red & Blue Teams Use It

| Team            | Use Case                                                                       |
| --------------- | ------------------------------------------------------------------------------ |
| **Red Team**    | Plan realistic attack paths, align payloads to techniques, simulate real APTs. |
| **Blue Team**   | Detect via logs & telemetry, correlate events with MITRE IDs.                  |
| **Purple Team** | Run exercises and build detections for each MITRE technique.                   |
| **CTF Player**  | Recognize real-world mappings and chain attacks logically.                     |

***

### VI. 🧱 Example MITRE Chains (Mini Scenarios)

#### 🧩 Windows Lateral Movement Chain

```
TA0001 (Initial Access) → Exploit Public-Facing App (T1190)
TA0002 (Execution) → PowerShell (T1059.001)
TA0006 (Credential Access) → LSASS Dump (T1003.001)
TA0008 (Lateral Movement) → SMB Admin Share (T1077)
TA0011 (C2) → HTTPS Beacon (T1071.001)
```

#### 🧩 Linux Privilege Escalation Chain

```
TA0001 (Initial Access) → SSH Key Auth (T1078)
TA0004 (PrivEsc) → SUID Exploit (T1068)
TA0005 (Defense Evasion) → Delete Logs (T1070.004)
TA0010 (Exfil) → SCP to Attacker (T1041)
```

***

### VII. ⚡ Detection Mapping Example

| Technique                        | Log Source            | Detection Idea                                                |
| -------------------------------- | --------------------- | ------------------------------------------------------------- |
| PowerShell Execution (T1059.001) | Windows Event Logs    | Command line contains suspicious parameters (`-nop`, `-enc`). |
| Credential Dumping (T1003)       | Sysmon, LSASS Access  | Unexpected process handles LSASS memory.                      |
| Persistence via Run Key (T1547)  | Registry              | Monitor changes to Run/RunOnce.                               |
| Lateral Movement (T1021)         | Windows Security Logs | LogonType=3 from unexpected host.                             |
| Exfiltration via HTTP (T1041)    | Proxy Logs            | Large POST requests to unknown domains.                       |

***

### VIII. 🧠 Tool Mapping by MITRE Technique

| Tool / Utility             | Technique    | Purpose                       |
| -------------------------- | ------------ | ----------------------------- |
| **PowerShell**             | T1059.001    | Execution / C2                |
| **Netcat**                 | T1071, T1041 | C2 / Exfil                    |
| **Mimikatz**               | T1003        | Credential Access             |
| **Impacket**               | T1021        | Lateral Movement              |
| **Empire / Cobalt Strike** | T1071, T1059 | Full-chain Red Team Framework |
| **BloodHound**             | T1087, T1482 | AD Discovery                  |
| **ProcDump**               | T1003        | Dump LSASS memory             |
| **PsExec**                 | T1569.002    | Remote Service Execution      |

***

### IX. 🧩 MITRE & Threat Intelligence (APT Examples)

| Threat Group         | Typical Chain                                                    | Example Tools                 |
| -------------------- | ---------------------------------------------------------------- | ----------------------------- |
| **APT28**            | Initial Access → Phishing → PowerShell → Credential Dump → Exfil | PowerShell, SMB, HTTP(S)      |
| **Lazarus**          | Spearphish → Dropper → Persistence → C2                          | custom loaders, SSL tunneling |
| **FIN7**             | Valid Accounts → Lateral Movement → Data Exfil                   | RDP, PowerShell               |
| **Conti Ransomware** | Cobalt Strike → LSASS Dump → Lateral Movement → Encrypt          | SMB, AD exploitation          |

***

### X. 🧱 Resources

* **MITRE ATT\&CK Navigator:** [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/)
* **Atomic Red Team (Detection Testing):** [https://github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)
* **Sigma Rules:** [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
* **ATT\&CK for ICS:** [https://attack.mitre.org/matrices/ics/](https://attack.mitre.org/matrices/ics/)
* **ATT\&CK for Mobile:** [https://attack.mitre.org/matrices/mobile/](https://attack.mitre.org/matrices/mobile/)

***
