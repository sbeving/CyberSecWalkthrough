# 😰 Blue Team Countermeasure Playbook

## **Blue Team Countermeasure Playbook — Detect, Deny, Deceive, Defend**

> 🧠 Goal: For every MITRE ATT\&CK tactic, this playbook gives defenders:
>
> * **Detection logic (what to look for)**
> * **Response strategy (what to do)**
> * **Hardening measures (how to prevent)**
>
> Built for SOC analysts, blue teamers, detection engineers, and anyone turning attack knowledge into protection.

***

### I. 🧩 Reconnaissance Defense

| Attack Behavior                  | Detection                                   | Mitigation                             | Tools                     |
| -------------------------------- | ------------------------------------------- | -------------------------------------- | ------------------------- |
| Network Scanning (T1595)         | High rate of SYN packets, ICMP sweeps       | Rate-limit ICMP, segment network       | Zeek, Suricata, Nmap logs |
| OSINT / Domain Discovery (T1593) | Monitor DNS query anomalies                 | Restrict WHOIS, sanitize external info | SIEM, Threat Intel feeds  |
| Banner Grabbing                  | Web server access logs with common scanners | Remove version banners                 | ModSecurity, WAF          |

🧠 **Tip:** Detect **enumeration patterns** before exploitation (multiple 404s, `/admin`, `/cgi-bin`).

***

### II. ⚡ Initial Access Defense

| Attack Vector                     | Detection                                    | Mitigation                         | Tools                      |
| --------------------------------- | -------------------------------------------- | ---------------------------------- | -------------------------- |
| Phishing Emails (T1566)           | Suspicious attachments, macro execution logs | Sandbox email attachments          | Proofpoint, O365 ATP       |
| Exploit Public-Facing App (T1190) | Web error spikes, WAF alerts                 | Patch management, input validation | ModSecurity, Burp, WAF     |
| Valid Accounts (T1078)            | Logon from new IP/device                     | MFA, disable dormant accounts      | AD logs, Azure AD Sign-ins |

🧠 **SIEM Queries:**

```splunk
index=auth (eventtype=logon) src_ip!=known_ips user=* action=success
```

***

### III. 💣 Execution Defense

| Technique                        | Detection                                   | Mitigation                           | Tools                      |
| -------------------------------- | ------------------------------------------- | ------------------------------------ | -------------------------- |
| PowerShell Execution (T1059.001) | Command line contains “-nop”, “-enc”, “IEX” | PowerShell Constrained Language Mode | Sysmon, Windows Event 4104 |
| Bash / Scripting (T1059.004)     | New script files in temp or /dev/shm        | Read-only mount for temp             | auditd, OSSEC              |
| Scheduled Task Execution (T1053) | `schtasks.exe` creation events              | Least privilege, audit task creation | Windows 4698 event         |

🧠 **Sysmon Rule:**\
Detect `ParentImage` = explorer.exe spawning PowerShell → alert.

***

### IV. 🕶️ Persistence Defense

| Technique                | Detection                            | Mitigation                         | Tools                   |
| ------------------------ | ------------------------------------ | ---------------------------------- | ----------------------- |
| Registry Run Key (T1547) | Registry change events to “Run”      | Group Policy restrictions          | Sysmon, RegMon          |
| Startup Folder Abuse     | File write to `Startup\` directory   | File integrity monitoring (FIM)    | Tripwire, OSSEC         |
| Service Creation         | `sc create` or `New-Service` command | Disable service creation for users | Sysmon 7045, Event 4697 |

🧠 _Monitor for persistence after reboot — it’s the hallmark of compromise._

***

### V. 🚀 Privilege Escalation Defense

| Attack                        | Detection                                               | Mitigation                   | Tools                  |
| ----------------------------- | ------------------------------------------------------- | ---------------------------- | ---------------------- |
| UAC Bypass (T1548.002)        | “fodhelper.exe”, “eventvwr.exe” spawned by user context | Enforce Admin Approval Mode  | Sysmon, AppLocker      |
| SUID Binary Abuse (Linux)     | Non-standard SUID files                                 | Regular baseline audits      | Lynis, AIDE            |
| Token Impersonation (Windows) | DuplicateHandle on privileged processes                 | Least privilege token policy | Event 4624 + Sysmon 10 |

🧠 **Windows Event Query Example:**

```splunk
EventCode=4624 LogonType=2 OR LogonType=10 user!=SYSTEM
```

***

### VI. 🧩 Defense Evasion

| Technique                | Detection                                                  | Mitigation                  | Tools                     |
| ------------------------ | ---------------------------------------------------------- | --------------------------- | ------------------------- |
| Log Deletion (T1070.004) | Sudden log size drop                                       | Centralized logging         | WEF, SIEM, Sysmon         |
| Masquerading (T1036)     | Processes with system-like names but wrong paths           | File name verification      | Sysmon, ELK               |
| Timestomping (T1070.006) | Files with modified timestamps inconsistent with FS events | File integrity monitoring   | OSSEC, Tripwire           |
| Disable Security Tools   | Stop of AV or EDR service                                  | Tamper protection, alerting | Defender ATP, Sysmon 7040 |

🧠 **Golden Rule:** Security tools should _report their own death._

***

### VII. 🧠 Credential Access Defense

| Vector          | Detection                                          | Mitigation                              | Tools                |
| --------------- | -------------------------------------------------- | --------------------------------------- | -------------------- |
| LSASS Dumping   | Non-Microsoft process opening LSASS                | Credential Guard                        | Sysmon Event ID 10   |
| Mimikatz Usage  | “sekurlsa::logonpasswords” in process command line | Disable WDigest, enforce LSA protection | Defender ATP, EDR    |
| Keylogging      | Frequent read of input buffers                     | App whitelisting                        | CrowdStrike, Sysmon  |
| Unsecured Creds | Config files with “password=”                      | Secret scanning                         | Gitleaks, TruffleHog |

🧠 **Blue Team Command:**

```powershell
Get-WinEvent -FilterHashtable @{Id=10; LogName='Microsoft-Windows-Sysmon/Operational'} | ? { $_.Message -like '*lsass.exe*' }
```

***

### VIII. 🔍 Discovery Defense

| Behavior         | Detection                                      | Mitigation                      | Tools                  |
| ---------------- | ---------------------------------------------- | ------------------------------- | ---------------------- |
| Network Scanning | High-volume port probes                        | Segment network, IDS signatures | Zeek, Suricata         |
| User Enumeration | Many failed logons                             | Lockout policy                  | SIEM Correlation Rules |
| Process Listing  | “tasklist” or “ps aux” from suspicious context | RBAC                            | Auditd, Sysmon         |

🧠 **Hunt Query (Splunk):**

```splunk
index=sysmon CommandLine="tasklist*" OR CommandLine="net user*"
```

***

### IX. 🔄 Lateral Movement Defense

| Technique            | Detection                       | Mitigation                              | Tools                    |
| -------------------- | ------------------------------- | --------------------------------------- | ------------------------ |
| SMB Lateral Movement | Admin shares access logs        | Disable SMBv1, segment internal subnets | Event 5140, Sysmon       |
| Pass-the-Hash        | Reuse of same NTLM hash         | LAPS, disable LM/NTLMv1                 | AD logs                  |
| RDP                  | Brute-force logins, new devices | MFA for RDP, restricted groups          | Event 4625, Defender ATP |

🧠 **Tip:** Monitor for multiple logins from _different subnets_ under the same user.

***

### X. 📦 Collection & Exfil Defense

| Vector            | Detection                      | Mitigation                                | Tools                 |
| ----------------- | ------------------------------ | ----------------------------------------- | --------------------- |
| Screen Capture    | Graphics subsystem calls       | Disable screen capture APIs               | EDR                   |
| File Compression  | Unexpected use of `rar`, `zip` | Block archive utilities in servers        | Sysmon                |
| HTTP Exfiltration | Large POSTs to unknown domains | Proxy / DLP controls                      | Zscaler, Defender ATP |
| DNS Tunneling     | High entropy DNS queries       | DNS firewall, detect via entropy analysis | Security Onion        |

🧠 **ELK Detection Rule:**\
Flag outbound DNS queries with >50 chars per label.

***

### XI. 🛰️ Command & Control Defense

| Behavior      | Detection                                     | Mitigation                   | Tools              |
| ------------- | --------------------------------------------- | ---------------------------- | ------------------ |
| C2 via HTTP/S | Repetitive periodic POSTs                     | Proxy logs anomaly detection | Zeek, Splunk       |
| DNS C2        | Randomized domains                            | DNS RPZ, sinkhole            | Security Onion     |
| Encrypted C2  | Long-duration TLS sessions to unknown domains | SSL inspection               | Defender ATP, Zeek |

🧠 **SIGMA Rule Example:**

```yaml
title: Potential HTTP C2 Traffic
logsource:
  category: proxy
detection:
  selection:
    url|contains: "/index.php"
    method: POST
condition: selection
```

***

### XII. 💥 Impact & Recovery Defense

| Technique            | Detection                 | Mitigation                               | Tools                     |
| -------------------- | ------------------------- | ---------------------------------------- | ------------------------- |
| Ransomware           | Rapid encryption of files | EDR behavioral blocks, immutable backups | Defender ATP, SentinelOne |
| Data Wiping          | Mass file deletion        | File deletion anomaly                    | Sysmon, SIEM              |
| Shadow Copy Deletion | `vssadmin delete shadows` | Disable vssadmin for users               | Sysmon 1/11               |

🧠 _Monitor for compression or encryption tools running on endpoints unexpectedly._

***

### XIII. 🧠 Blue Team TTP → Log Mapping Table

| Category                  | Source               | Key Event IDs / Indicators |
| ------------------------- | -------------------- | -------------------------- |
| **Authentication**        | Windows Security Log | 4624, 4625                 |
| **Service Creation**      | System               | 7045                       |
| **Process Execution**     | Sysmon               | 1, 10, 11                  |
| **Network Connection**    | Sysmon               | 3                          |
| **Registry**              | Sysmon               | 13                         |
| **File Creation / Write** | Sysmon               | 11                         |
| **PowerShell**            | PowerShell Logs      | 4104                       |
| **DNS / Proxy**           | Firewall / Proxy     | Domain anomalies           |

***

### XIV. 🧰 Blue Team Toolkit (Recommended Stack)

| Type                  | Tool                                   |
| --------------------- | -------------------------------------- |
| **SIEM**              | Splunk, Elastic, Graylog               |
| **EDR/XDR**           | Defender ATP, CrowdStrike, SentinelOne |
| **IDS/IPS**           | Zeek, Suricata, Snort                  |
| **Threat Intel**      | MISP, OpenCTI                          |
| **Detection Testing** | Atomic Red Team                        |
| **Sysmon Config**     | SwiftOnSecurity Sysmon XML             |
| **Automation / SOAR** | TheHive, Cortex, Shuffle               |

***

### XV. ⚡ Blue Team Ops Checklist

✅ Centralized logging (Sysmon + SIEM)\
✅ Baseline normal activity\
✅ Use MITRE IDs in correlation rules\
✅ Hunt weekly: high-priv processes, lateral logons, encoded commands\
✅ Enforce least privilege\
✅ Keep golden images hardened\
✅ Test detections with **Atomic Red Team** regularly\
✅ Document playbooks for each MITRE tactic

***
