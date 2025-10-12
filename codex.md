---
icon: hand-back-point-left
---

# Codex

## 🧠 **The CyberSec Codex — Master Index**

> _“Learn. Break. Defend. Repeat.”_
>
> A complete, field-grade collection of notes, guides, and references for CTFs, Penetration Testing, and Cyber Operations — powered by knowledge, discipline, and creativity.
>
> Authored by **Saleh Eddine Touil (Sbeve)**.

***

### 🏁 **Getting Started**

* **Welcome Page** — Introduction, author bio, social links, mindset
* **Why These Notes Exist** — Training for real-world security through games and challenges
* **Mindset & Methodology** — Learn → Exploit → Report → Reflect
* **Tools Setup** — OSINT essentials, lab virtualization, pentest environment build
* **Legal & Ethics** — Responsible hacking, sandbox-only execution

***

### 💻 **Scripting & Automation**

| Topic                                | Description                                        |
| ------------------------------------ | -------------------------------------------------- |
| **Bash for CTFs**                    | The ultimate command-line handbook                 |
| **Python for Pentesters**            | Exploits, socketing, and automation                |
| **PowerShell for Post-Exploitation** | Windows privilege & persistence scripting          |
| **Go for Pentesters**                | Concurrency, network tooling, and payload delivery |
| **JavaScript for Bug Bounties**      | XSS, web automation, browser exploitation          |

***

### 🧩 **Enumeration & Reconnaissance**

| Section                              | Description                                 |
| ------------------------------------ | ------------------------------------------- |
| **Network Recon (Active & Passive)** | nmap, masscan, Shodan, p0f, etc.            |
| **DNS Enumeration**                  | Subdomain discovery, zone transfer, records |
| **Web Enumeration**                  | Dirbuster, BurpSuite, parameter fuzzing     |
| **Service Fingerprinting**           | Banner analysis, OS guessing                |
| **Automation Pipelines**             | Recon scripts and workflow chaining         |

***

### 🧱 **Privilege Escalation & Post-Exploitation**

| Platform                         | Key Topics                                       |
| -------------------------------- | ------------------------------------------------ |
| **Linux PrivEsc**                | SUIDs, misconfigurations, kernel exploits        |
| **Windows PrivEsc**              | UAC bypass, token impersonation, scheduled tasks |
| **macOS PrivEsc**                | Sandbox escapes, system integrity                |
| **Docker & Cloud PrivEsc**       | Container breakout, misconfigured volumes        |
| **Post-Exploitation Frameworks** | Meterpreter, Empire, Pupy                        |

***

### 🧠 **Reverse Engineering**

| Section                      | Description                         |
| ---------------------------- | ----------------------------------- |
| **Foundations**              | Assembly, ELF/PE, debugging flow    |
| **Static Analysis**          | Ghidra, IDA, Binary Ninja           |
| **Dynamic Analysis**         | GDB, radare2, Frida                 |
| **Decompilation & Patching** | Crackmes, function tracing          |
| **Malware Analysis**         | Sandbox testing, behavioral tracing |

***

### 🧱 **System Hardening**

| Platform                | Coverage                                       |
| ----------------------- | ---------------------------------------------- |
| **Windows**             | Group Policy, audit policy, registry hardening |
| **Linux**               | Sysctl, AppArmor, fail2ban, ssh configs        |
| **macOS**               | SIP, keychain, permission lockdown             |
| **Docker & Containers** | Image scanning, privilege minimization         |
| **Cloud**               | IAM least privilege, logging, zero trust intro |

***

### 🔐 **Cryptography for CTFs**

| Volume                                    | Content                                                  |
| ----------------------------------------- | -------------------------------------------------------- |
| **Volume 1 – Classical & Encodings**      | Caesar, Vigenère, bases, hex, binary                     |
| **Volume 2 – Modern Crypto & Attacks**    | RSA, AES, DES, HMAC, Nonce, padding, LFSR                |
| **Volume 3 – Professional Cryptanalysis** | Math, research workflow, ethics, real-world case studies |

***

### 🕵️‍♂️ **Steganography & Hidden Data**

* Common Techniques (LSB, audio, video, recursive files)
* Tools (steghide, zsteg, stegsolve, exiftool, wavsteg, binwalk)
* Spectrum & metadata analysis
* Practical challenge walkthroughs

***

### 🧩 **Cheat Sheets & References**

| Sheet                                  | Description                                            |
| -------------------------------------- | ------------------------------------------------------ |
| **Linux Commands for Hackers**         | Every command that matters                             |
| **Windows Command-Line for Operators** | PowerShell + CMD quickref                              |
| **Reverse Shells (All Languages)**     | Templates & listener syntax                            |
| **File Transfer Cheat Sheet**          | From wget to certutil                                  |
| **Port/Service Reference**             | Common banners & ports                                 |
| **Exploit Template Snippets**          | Python, PHP, Bash skeletons                            |
| **Payload Index**                      | Safe test payloads for encoding, staging, and chaining |
| **MITRE ATT\&CK Cheat Sheet**          | Common TTPs by phase & actor behavior                  |

***

### 🧬 **Miscellaneous Forensics**

* Disk & Memory Analysis
* Log forensics
* Email header tracing
* Metadata correlation
* Timeline reconstruction
* Carving hidden partitions

***

### 🪙 **Blockchain & Smart Contract CTFs**

| Topic                  | Description                                |
| ---------------------- | ------------------------------------------ |
| **Solidity Basics**    | Smart contract structure and pitfalls      |
| **EVM Debugging**      | Opcodes, reentrancy, gas manipulation      |
| **Web3 Enumeration**   | RPC, ABI, bytecode inspection              |
| **Common Attacks**     | Integer overflow, delegatecall, reentrancy |
| **Defensive Auditing** | Testnets, fuzzing, symbolic execution      |

***

### 🧠 **AI & ML in CTFs**

| Volume                                    | Description                                          |
| ----------------------------------------- | ---------------------------------------------------- |
| **1. AI & LLM Challenges**                | Prompt injection, context poisoning, model inference |
| **2. AI Forensics & Reverse Engineering** | Inspect weights, tokenizer leaks, embedding flags    |
| **3. Model Poisoning & Dataset Attacks**  | Label flips, backdoors, detection techniques         |
| **4. Adversarial Evasion Challenges**     | Image, text, and multimodal perturbations            |
| **5. AI Defense Engineering**             | Hardening, monitoring, adversarial training          |
| **6. AI CyberOps Integration**            | Automating recon, exploitation, and writeups         |

***

### 🧰 **Tools & Frameworks**

| Category              | Examples                               |
| --------------------- | -------------------------------------- |
| **Enumeration**       | nmap, ffuf, gobuster, dnsenum          |
| **Exploitation**      | Metasploit, sqlmap, burpsuite, wfuzz   |
| **Post-Exploitation** | BloodHound, linpeas, winpeas, mimikatz |
| **Forensics**         | Volatility, autopsy, strings, binwalk  |
| **Cryptography**      | CyberChef, hashcat, john, RsaCtfTool   |
| **AI Security**       | Garak, TextAttack, Foolbox, ART        |
| **Automation**        | Python, Go, PowerShell, Bash pipelines |

***

### ⚡ **Mega Workflow: How to Approach a CTF Machine**

```
1️⃣ Recon: Identify open ports, web services, banners
2️⃣ Enumeration: Fuzz directories, parse configs, find credentials
3️⃣ Exploitation: Gain shell or trigger vulnerability
4️⃣ Foothold: Stabilize access, enumerate users and environment
5️⃣ PrivEsc: Kernel, misconfig, or SUID exploitation
6️⃣ Loot: Read flags, dump creds, pivot if needed
7️⃣ Post-Exploitation: Analyze, document, clean up
8️⃣ Writeup: Document methodology and flag proofs
```

🧠 Tip: Use your AI Recon pipelines to summarize logs and scan outputs fast.

***

### 📚 **Extra Reference Modules**

* **CTF Mindset & Team Dynamics**
* **Reporting & Writeup Templates**
* **Cyber Threat Intelligence (CTI) Basics**
* **Vulnerability Disclosure & Ethics**
* **Recommended Labs & Practice Platforms**
  * HackTheBox
  * TryHackMe
  * OverTheWire
  * Root-Me
  * VulnHub

***

### 🧩 **Appendix: The Hacker’s Toolkit**

| Category                 | Highlights                                 |
| ------------------------ | ------------------------------------------ |
| **OSINT**                | Maltego, Spiderfoot, Recon-ng              |
| **Exfiltration**         | Netcat, SCP, PowerShell transfer           |
| **Web Exploits**         | SSRF, LFI/RFI, template injection          |
| **Network Exploits**     | SMB, FTP, SNMP misconfigurations           |
| **Privilege Escalation** | PEAS scripts, dirtycow, token abuse        |
| **Post Exploitation**    | Tunneling, persistence, lateral movement   |
| **Hardening**            | Auditd, firewalld, SELinux, group policies |

***

### 🎯 **Vision**

> “To turn curiosity into mastery — and play into defense.”
>
> This GitBook isn’t just notes; it’s your personal cyber warfare archive:\
> **offensive**, **defensive**, **analytical**, and **AI-augmented** — all designed for mastery in CTFs and real-world penetration testing.

***

### 🧠 **Future Expansions**

* 💡 _Blue vs Red Simulation Labs (LLM Agents in Security)_
* 🧬 _Binary Exploitation Mega Compendium (ROP, Heap, Kernel)_
* ☁️ _Cloud Security & Pentesting Series (AWS, GCP, Azure)_
* 🛰️ _ICS/IoT Security Notes (Hardware, Firmware, Radio)_
* 🧰 _Custom Tools Showcase (Your Python, Go, and AI Projects)_

***
