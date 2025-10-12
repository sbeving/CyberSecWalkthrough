---
icon: gears
---

# Port & Service Reference

## **Port & Service Cheat Reference — The Operator’s Port Bible**

> ⚠️ Use only on authorized networks or lab systems. Port scanning and service enumeration can be disruptive.\
> Always get explicit permission before scanning external assets.

***

### I. 🧠 Port Scanning Essentials

#### 🔹 Nmap Fast Scans

```bash
# Top 1000 ports (default)
nmap -sC -sV -oA scan target

# Full TCP scan
nmap -p- -T4 -sV target

# UDP scan
nmap -sU --top-ports 100 -v target

# Aggressive scan
nmap -A target

# With output for parsing
nmap -sS -Pn -p- --min-rate 5000 -oN full.txt target
```

#### 🔹 RustScan (faster)

```bash
rustscan -a target --ulimit 5000 -- -sV -sC
```

***

### II. ⚙️ Common TCP Ports & Attack Surface Map

| Port                 | Service                              | Notes & Attack Paths                                                                       |
| -------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------ |
| **21**               | FTP                                  | Anonymous login, cleartext creds, directory traversal, backdoors.                          |
| **22**               | SSH                                  | Weak passwords, key reuse, outdated algorithms, SSH tunneling.                             |
| **23**               | Telnet                               | Cleartext creds, legacy systems, banner leaks OS info.                                     |
| **25**               | SMTP                                 | Open relay, VRFY/EXPN, spoofing, email injection.                                          |
| **53**               | DNS                                  | Zone transfers (`dig axfr`), cache poisoning, DNS rebinding.                               |
| **67/68**            | DHCP                                 | Rogue DHCP/mitm in labs.                                                                   |
| **69**               | TFTP                                 | Anonymous file transfer, boot images, config leaks.                                        |
| **80 / 8080 / 8000** | HTTP                                 | Default pages, vhosts, directory traversal, hidden admin panels, CVEs, file upload bypass. |
| **81 / 8888 / 8181** | Alternate Web                        | Webmin, Jenkins, Tomcat panels, misconfig APIs.                                            |
| **88**               | Kerberos                             | AS-REP roasting, Kerberoasting, SPN abuse.                                                 |
| **110 / 995**        | POP3 / SSL                           | Cleartext passwords, weak SSL.                                                             |
| **135 / 445**        | MSRPC / SMB                          | Lateral movement, null sessions, EternalBlue, smbclient enumeration.                       |
| **139**              | NetBIOS                              | SMBv1 fallback, user enumeration.                                                          |
| **143 / 993**        | IMAP / SSL                           | Credential reuse, email dump.                                                              |
| **161 / 162**        | SNMP                                 | `snmpwalk`, default community strings, system dump.                                        |
| **389 / 636**        | LDAP / LDAPS                         | AD user dump, unauthenticated binds, LDAP injection.                                       |
| **443**              | HTTPS                                | SSL/TLS misconfig, hidden paths, `robots.txt`, CSP bypass.                                 |
| **445**              | SMB                                  | Shares, NTLM relay, named pipes, WinRM pivot.                                              |
| **465 / 587**        | SMTPS                                | Credential reuse, mail exfil.                                                              |
| **512–514**          | Rexec/Rlogin/Rsh                     | Legacy remote shell, trust relationships.                                                  |
| **548**              | AFP                                  | macOS file sharing vulnerabilities.                                                        |
| **554**              | RTSP                                 | Stream grabbing, camera feeds.                                                             |
| **5900**             | VNC                                  | No authentication, weak passwords.                                                         |
| **5985 / 5986**      | WinRM / HTTPS                        | PowerShell remoting, lateral movement, use `evil-winrm`.                                   |
| **636**              | LDAPS                                | Encrypted LDAP, still vulnerable to misconfig binds.                                       |
| **8080 / 8443**      | Alternate HTTPS                      | Jenkins, Tomcat, API consoles.                                                             |
| **873**              | Rsync                                | Anonymous modules, file exfiltration.                                                      |
| **1080**             | SOCKS Proxy                          | Pivoting & data exfil.                                                                     |
| **1433**             | MSSQL                                | Weak creds, xp\_cmdshell, remote query injection.                                          |
| **1521**             | Oracle                               | TNS listener, weak auth.                                                                   |
| **2049**             | NFS                                  | Exported shares, root\_squash bypass.                                                      |
| **2181**             | Zookeeper                            | No auth by default, sensitive configs.                                                     |
| **2375**             | Docker API                           | Root RCE via exposed API (`docker run`).                                                   |
| **3306**             | MySQL                                | Weak creds, file reads, command exec via `UDF`.                                            |
| **3389**             | RDP                                  | Brute-force, clipboard leaks, BlueKeep (CVE-2019-0708).                                    |
| **3632**             | distcc                               | Remote command execution.                                                                  |
| **4444**             | Metasploit                           | Payload listener; monitor open connections.                                                |
| **4848**             | GlassFish                            | Admin console default creds.                                                               |
| **5000 / 5001**      | Flask, UPnP, Docker registry         | Sensitive APIs, token dumps.                                                               |
| **5432**             | PostgreSQL                           | Trust relationships, weak auth, file read via `COPY`.                                      |
| **5601**             | Kibana                               | XSS, RCE in outdated versions.                                                             |
| **5900 / 5901**      | VNC                                  | Weak/no auth remote desktops.                                                              |
| **5985 / 5986**      | WinRM                                | Remote PowerShell sessions.                                                                |
| **6379**             | Redis                                | No auth → RCE (write SSH keys / cron jobs).                                                |
| **6660–6667**        | IRC                                  | Botnets, remote control channels.                                                          |
| **8009**             | AJP (Tomcat)                         | Ghostcat file read/execution.                                                              |
| **8081 / 8090**      | Jenkins, Nexus                       | Privilege escalation, RCE via plugin endpoints.                                            |
| **8443**             | HTTPS alt                            | Admin dashboards, misconfigs.                                                              |
| **9000**             | PHP-FPM                              | RCE via crafted FastCGI.                                                                   |
| **9090**             | Web interfaces (Prometheus, Cockpit) | Credential leaks, metrics exposure.                                                        |
| **9200 / 9300**      | Elasticsearch                        | RCE, data leak (CVE-2015-1427).                                                            |
| **11211**            | Memcached                            | Data exfiltration, DoS amplification.                                                      |
| **27017**            | MongoDB                              | No auth → data dump.                                                                       |
| **50070 / 50075**    | Hadoop                               | Data exposure.                                                                             |
| **56000+**           | Dynamic                              | ephemeral ports; watch live connections.                                                   |

***

### III. 🔎 UDP Highlights

| Port      | Service   | Key Attack Vectors                             |
| --------- | --------- | ---------------------------------------------- |
| **53**    | DNS       | Zone transfer, amplification.                  |
| **67/68** | DHCP      | Rogue server/mitm.                             |
| **69**    | TFTP      | No auth file pulls.                            |
| **123**   | NTP       | Amplification, version leak.                   |
| **161**   | SNMP      | Community string = “public”? Dump system info. |
| **500**   | IKE (VPN) | VPN enumeration, PSK cracking.                 |
| **1900**  | SSDP      | Discovery flood, UPnP exploits.                |
| **5353**  | mDNS      | Local discovery, leak hostnames.               |

***

### IV. 🧰 Quick Recon Recipes

#### 🔹 SMB Enumeration

```bash
smbclient -L //10.10.10.5/ -N
rpcclient -U "" 10.10.10.5
enum4linux-ng 10.10.10.5
```

#### 🔹 LDAP Dump

```bash
ldapsearch -x -h 10.10.10.5 -b "dc=lab,dc=local"
```

#### 🔹 Web Enumeration

```bash
whatweb http://target
nikto -h http://target
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
```

#### 🔹 Database

```bash
mysql -u root -p -h 10.10.10.5
psql -h 10.10.10.5 -U postgres
```

***

### V. 🧠 Port Pivoting & Tunneling Quicklist

| Tool            | Example                                           | Purpose                  |
| --------------- | ------------------------------------------------- | ------------------------ |
| **SSH**         | `ssh -L 8080:10.10.10.5:80 user@pivot`            | Local port forward       |
| **Chisel**      | `chisel client attacker:8080 R:9001:127.0.0.1:80` | Reverse tunnel           |
| **Socat**       | `socat TCP-LISTEN:9001,fork TCP:127.0.0.1:80`     | TCP bridge               |
| **ProxyChains** | `proxychains nmap -sT -Pn 10.10.10.0/24`          | Use SOCKS proxy for scan |

***

### VI. 🧩 Fingerprinting by Banner

| Service       | Sample Banner                        | Indicator                 |
| ------------- | ------------------------------------ | ------------------------- |
| Apache        | `Server: Apache/2.4.29 (Ubuntu)`     | Web server type/version   |
| SSH           | `SSH-2.0-OpenSSH_8.4p1 Debian`       | OpenSSH, OS fingerprint   |
| FTP           | `vsFTPd 3.0.3`                       | Version-based RCE history |
| SMB           | `Windows Server 2016 Standard 14393` | Host OS                   |
| SMTP          | `220 mail.lab.local ESMTP Postfix`   | Mail relay                |
| MySQL         | `5.7.33-0ubuntu0.18.04.1`            | Database target           |
| Redis         | `+PONG`                              | No auth setup             |
| Elasticsearch | JSON `{ "cluster_name": ... }`       | Misconfigured API         |

***

### VII. ⚡ Service-Specific Exploit Reminders

| Service           | Typical Exploits                        |
| ----------------- | --------------------------------------- |
| **FTP**           | Anonymous login, writable directory RCE |
| **SSH**           | Key reuse, outdated cipher downgrade    |
| **SMB**           | EternalBlue, PrintNightmare, NTLM relay |
| **HTTP**          | LFI/RFI, upload bypass, SSRF, XXE       |
| **SQL**           | SQLi → RCE via file writes              |
| **RDP**           | BlueKeep, weak credentials              |
| **WinRM**         | Evil-WinRM interactive shells           |
| **Redis**         | Write cron or authorized\_keys for RCE  |
| **Docker API**    | `docker run -v /:/mnt` → root shell     |
| **Jenkins**       | Script Console RCE                      |
| **Tomcat**        | WAR file deploy RCE                     |
| **Elasticsearch** | Script execution CVEs                   |
| **LDAP**          | Unauthenticated dump, AD data leak      |

***

### VIII. 🧠 Recon Tools by Category

| Category            | Tools                               |
| ------------------- | ----------------------------------- |
| **Port Scan**       | Nmap, Masscan, RustScan             |
| **Web Enum**        | Dirsearch, Gobuster, Nikto, WhatWeb |
| **SMB Enum**        | smbclient, rpcclient, enum4linux-ng |
| **LDAP / Kerberos** | ldapsearch, kerbrute, impacket      |
| **Mail Services**   | smtp-user-enum, swaks               |
| **Databases**       | sqlmap, hydra, metasploit modules   |
| **SNMP**            | snmpwalk, onesixtyone               |
| **Remote Shells**   | nc, socat, psexec.py, winrm, ssh    |

***

### IX. 🧠 Quick Reference Summary

| Port    | Protocol      | Target       | Key Command                        |
| ------- | ------------- | ------------ | ---------------------------------- |
| 21      | FTP           | File service | `ftp <IP>`                         |
| 22      | SSH           | Secure shell | `ssh user@IP`                      |
| 80      | HTTP          | Web          | `curl -I http://IP`                |
| 139/445 | SMB           | File share   | `smbclient -L //<IP>/`             |
| 1433    | MSSQL         | DB           | `sqsh -S <IP> -U sa -P <pass>`     |
| 3306    | MySQL         | DB           | `mysql -h <IP>`                    |
| 5432    | PostgreSQL    | DB           | `psql -h <IP>`                     |
| 6379    | Redis         | Cache        | `redis-cli -h <IP>`                |
| 8080    | HTTP-alt      | Web admin    | `whatweb http://IP:8080`           |
| 9200    | Elasticsearch | Logs         | `curl http://IP:9200/_cat/indices` |

***
