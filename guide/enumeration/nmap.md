---
icon: eye
---

# Nmap

## **Nmap Deep Dive — The Art of Stealth and Discovery**

***

The **Network Mapper (Nmap)** is the **Swiss Army Knife of network reconnaissance**.\
It identifies hosts, services, operating systems, firewalls, and potential vulnerabilities across networks.\
In the hands of a skilled CTF or red team operator, Nmap becomes **a surgical instrument for mapping and exploiting the unknown** — from stealthy scans to custom NSE scripting.

***

### I. 🧩 Core Capabilities Overview

| Command    | Purpose                                                                  |
| ---------- | ------------------------------------------------------------------------ |
| `nmap`     | Primary binary for host discovery and port scanning.                     |
| `ncat`     | Netcat replacement for communication, file transfer, and shell handling. |
| `ndiff`    | Compares scan results to identify changes.                               |
| `nping`    | Custom packet generator and latency measurement tool.                    |
| `nmap -sC` | Default script scan for common vulnerabilities.                          |
| `nmap -sV` | Detects service versions on open ports.                                  |
| `nmap -A`  | Aggressive mode: combines OS, version, script, and traceroute scans.     |

***

### II. 🧠 Scan Types and Modes

| Flag  | Description                                                            |
| ----- | ---------------------------------------------------------------------- |
| `-sS` | **TCP SYN Scan** (Stealth Scan). Default and fastest for root users.   |
| `-sT` | **TCP Connect Scan**. Uses system calls, less stealthy but universal.  |
| `-sU` | **UDP Scan**. Detects DNS, SNMP, and other UDP services.               |
| `-sV` | **Version Detection**. Identifies software and version info.           |
| `-O`  | **OS Fingerprinting**. Determines target OS and device type.           |
| `-sC` | **Default Script Scan** (uses safe NSE scripts).                       |
| `-A`  | **Aggressive Scan** – includes `-O`, `-sV`, `-sC`, and `--traceroute`. |
| `-Pn` | **No Ping**. Assumes host is up, bypasses ICMP echo restrictions.      |

***

### III. ⚙️ Practical Workflow Examples

#### 1. 🎯 Quick Host Discovery

```bash
nmap -sn 10.10.10.0/24
```

Performs a **ping sweep** to identify live hosts.\
Add `-PE` or `-PS` for custom ICMP/TCP ping probes.

***

#### 2. 🧩 Service and Version Scan

```bash
nmap -sV -sC -oN service_scan.txt 10.10.10.5
```

Performs default script + version detection scan and saves output to file.\
Ideal first pass on a new target.

***

#### 3. 🕵️ Deep Reconnaissance

```bash
nmap -A -T4 -p- 10.10.10.5
```

Aggressive scan on **all ports**, useful for finding **hidden services**.\
`-T4` increases speed, `-p-` scans all 65,535 TCP ports.

***

#### 4. 🔒 Firewall Evasion & Stealth

```bash
nmap -sS -Pn -T0 --source-port 53 10.10.10.5
```

* **`-Pn`**: Skip host discovery
* **`-T0`**: Very slow, stealthy timing
* **`--source-port 53`**: Mimic DNS traffic to evade filters

***

#### 5. 🧠 OS & Version Fingerprinting

```bash
nmap -O -sV 10.10.10.5
```

Combines TCP/IP stack analysis and banner grabbing.\
Useful in identifying targets for kernel or service-based exploits.

***

#### 6. ⚙️ Specific Port and Protocol Targeting

```bash
nmap -p 21,22,80,443 10.10.10.5
nmap -sU -p 53,161 10.10.10.5
```

Targeted scans to reduce noise and focus on known attack surfaces.

***

#### 7. 💣 Aggressive All-Port Enumeration

```bash
nmap -p- -T4 -v -oA fullscan 10.10.10.5
```

Performs a **full TCP scan**, outputs to all formats (`.nmap`, `.xml`, `.gnmap`).

***

### IV. 🔬 NSE (Nmap Scripting Engine) — Offensive Modules

The **Nmap Scripting Engine** (NSE) allows automation of vulnerability detection, brute forcing, and exploitation.

| Script Category | Example              | Description                      |
| --------------- | -------------------- | -------------------------------- |
| `default`       | `--script=default`   | Safe, informational scripts      |
| `vuln`          | `--script=vuln`      | Checks for known vulnerabilities |
| `auth`          | `--script=auth`      | Authentication-related checks    |
| `brute`         | `--script=brute`     | Brute-force attacks              |
| `exploit`       | `--script=exploit`   | Automated exploitation attempts  |
| `discovery`     | `--script=discovery` | Network mapping and enumeration  |

#### 🧩 Example: HTTP Vulnerability Check

```bash
nmap -p80 --script http-vuln-cve2017-5638 10.10.10.5
```

#### 🧠 Example: SMB Enumeration

```bash
nmap -p445 --script smb-enum-shares.nse,smb-enum-users.nse 10.10.10.5
```

#### 💣 Example: Full Vulnerability Sweep

```bash
nmap --script vuln -T4 10.10.10.5
```

***

### V. 🧰 Advanced Techniques & Scenarios

#### 🧠 Combine XML Output with External Tools

```bash
nmap -sC -sV -oX scan.xml 10.10.10.5
xsltproc scan.xml -o report.html
```

Converts scan results to an **HTML report** for easier analysis.

***

#### 🧩 Integrating with Searchsploit

```bash
searchsploit --nmap scan.xml
```

Automatically matches detected versions to known exploits in **Exploit-DB**.

***

#### 💀 Banner Grabbing & Fuzzing

```bash
nmap -p80 --script banner,http-methods,http-headers 10.10.10.5
```

Extracts banners and potential HTTP method misconfigurations.

***

#### 🔐 Bruteforcing with NSE

```bash
nmap -p22 --script ssh-brute --script-args userdb=users.txt,passdb=rockyou.txt 10.10.10.5
```

Automates password brute-force using built-in NSE scripts.

***

#### 🧬 Diffing Between Scans

```bash
ndiff old_scan.xml new_scan.xml
```

Shows changes between two scans — helpful in detecting system updates or patching.

***

### VI. 🧩 Real-World Workflow Example

#### 1️⃣ Identify Live Hosts

```bash
nmap -sn 10.10.10.0/24 -oG hosts.gnmap
```

#### 2️⃣ Extract Targets

```bash
grep "Up" hosts.gnmap | cut -d " " -f2 > live.txt
```

#### 3️⃣ Full Enumeration on Each Host

```bash
for ip in $(cat live.txt); do
    nmap -sC -sV -oN $ip.txt $ip
done
```

#### 4️⃣ Vulnerability Sweep

```bash
for ip in $(cat live.txt); do
    nmap --script vuln -oN vuln_$ip.txt $ip
done
```

#### 5️⃣ Export to Report

```bash
xsltproc *.xml -o nmap_report.html
```

***

### VII. 🧠 Pro Tips & Best Practices

✅ **Top CTF Scanning Tips**

* Always start with `-p-` scans — never assume default ports.
* Chain `nmap` → `searchsploit` → `metasploit` for instant exploitation flow.
* Use `-T3` or `-T4` for good balance between speed and stealth.
* Combine TCP and UDP for maximum coverage.
* Use output redirection (`-oN`, `-oA`) to save every scan — you’ll need them later for writeups.
* Leverage NSE scripts like `vulners` or `http-enum` to find low-hanging fruit quickly.

✅ **Red Team Stealth Tricks**

* Spoof MAC: `--spoof-mac 0` (randomize hardware address).
* Fragment packets: `-f` to bypass simple firewalls.
* Use decoys: `-D RND:10` sends extra fake traffic.
* Rate limit: `--min-rate 100` to throttle noise.
* Schedule scans for low-traffic hours (`cron` + `nmap` = stealth).

✅ **Data Pipeline Magic**\
Export → Parse → Exploit:

```bash
nmap -oX scan.xml 10.10.10.5 && searchsploit --nmap scan.xml
```

***

### VIII. ⚔️ Reference Commands

| Purpose             | Command                                                                 |
| ------------------- | ----------------------------------------------------------------------- |
| All TCP Ports       | `nmap -p- 10.10.10.5`                                                   |
| All UDP Ports       | `nmap -sU -p- 10.10.10.5`                                               |
| Version + OS        | `nmap -A 10.10.10.5`                                                    |
| Full Recon Script   | `nmap -sC -sV -O -p- -T4 -oA recon 10.10.10.5`                          |
| Vulnerability Check | `nmap --script vuln -oN vuln.txt 10.10.10.5`                            |
| HTTP Enum           | `nmap -p80 --script http-enum 10.10.10.5`                               |
| SMB Enum            | `nmap -p445 --script smb-enum-shares.nse,smb-enum-users.nse 10.10.10.5` |

***
