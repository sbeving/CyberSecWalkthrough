# Guide

## CPTS Preparation Guide 2025

The Hack The Box Certified Penetration Testing Specialist (HTB CPTS) is a highly practical, hands-on certification designed to validate intermediate-level penetration testing skills in real-world scenarios. Unlike other certifications, HTB CPTS emphasizes enterprise-like environments, requiring candidates to complete the Penetration Tester job-role path on HTB Academy, including the Owen module, and pass a challenging 10-day exam. This guide provides a beginner-friendly, step-by-step roadmap to prepare for the HTB CPTS exam, incorporating the Owen module and other HTB Academy resources, along with a comprehensive list of tools and resources to ensure success. Whether you’re new to cybersecurity or have some experience, this guide will help you build the skills and confidence needed to earn the HTB CPTS certification. Let’s get started!

### Understanding the HTB CPTS Exam

The HTB CPTS exam is a 10-day, hands-on penetration testing challenge where candidates must compromise a real-world, enterprise-like network, capture a minimum number of flags (e.g., 12/14 user and root flags), and submit a commercial-grade report. The exam environment, accessible via VPN or HTB’s Pwnbox, simulates a black-box penetration test with web applications, network services, and Active Directory (AD) components. Key features include:

* **Focus Areas**: Web application security, network exploitation, Active Directory attacks, privilege escalation, and vulnerability chaining.
* **Practical Nature**: No multiple-choice questions; candidates must perform actual pentesting tasks and document findings.
* **Report Requirement**: A detailed, professional report is mandatory, including methodology, vulnerabilities, attack chains, and remediation advice.
* **Difficulty**: Labeled as intermediate but considered challenging, even for experienced pentesters, due to its emphasis on creative vulnerability chaining and real-world scenarios. X posts highlight its difficulty, with some comparing it to OSCP but noting its longer duration and enterprise focus.

**Exam Prerequisites**: Candidates must complete 100% of the **Penetration Tester job-role path** (28 modules, 1980 Cubes) on HTB Academy, including the Owen module, before purchasing an exam voucher (\~$210 USD).

**Sentiment on X**: Recent posts praise HTB CPTS for its affordability, practical focus, and relevance to modern pentesting, especially AD exploitation. Some users report it as more challenging than OSCP or PNPT due to its complexity and report requirements.

For beginners, expect 3–6 months of preparation, depending on prior experience.

### Prerequisites for HTB CPTS Preparation

Before starting HTB CPTS prep, ensure you have the following foundational knowledge:

* **Basic Networking**: Understand TCP/IP, OSI model, common ports (e.g., 80 for HTTP, 445 for SMB), and protocols. CompTIA Network+ is a good starting point.
* **Linux Basics**: Familiarity with Linux commands (ls, cd, grep, etc.) and navigation. OverTheWire Bandit is ideal for beginners.
* **Basic Security Concepts**: Knowledge of vulnerabilities (e.g., SQL injection, XSS) and security principles (e.g., CompTIA Security+ level).
* **Scripting Basics**: Basic Python or Bash scripting for automation or exploit modification.
* **Time Commitment**: Dedicate 10–20 hours per week for 3–6 months.

If you’re a complete beginner, the resources and steps below will guide you through building these skills.

### Step-by-Step Preparation Plan

#### **Step 1: Build a Strong Foundation**

**Goal**: Establish a baseline understanding of networking, Linux, and security concepts.

* **Learn Networking Basics**:
* Study TCP/IP, OSI model, subnets, and common services (HTTP, FTP, SMB).
* **Resource**: HTB Academy’s _Networking Fundamentals_ module (Tier 0, free) or CompTIA Network+ study materials.
* **Get Comfortable with Linux**:
* Learn basic commands (ls, cd, cat, grep, etc.) and file system navigation.
* Practice on **OverTheWire Bandit** (free) to build Linux terminal skills.
* **Resource**: HTB Academy’s _Linux Fundamentals_ module (Tier 0, free).
* **Understand Security Fundamentals**:
* Study common vulnerabilities (e.g., SQL injection, XSS, misconfigurations).
* **Resource**: Read _Web Application Hacker’s Handbook_ by Dafydd Stuttard and Marcus Pinto.

**Time**: 2–4 weeks for beginners.&#x20;

#### **Step 2: Set Up and Master Kali Linux or Pwnbox**

**Goal**: Get comfortable with Kali Linux or HTB’s Pwnbox, the primary platforms for CPTS.

* **Set Up Kali Linux**:
* Install Kali Linux on a virtual machine using VirtualBox or VMware.
* **Resource**: Official Kali Linux documentation (https://www.kali.org/docs/).
* **Explore HTB’s Pwnbox**:
* Use HTB Academy’s browser-based Pwnbox for module exercises and exam practice.
* Ensure a stable internet connection for VPN access.
* **Learn Key Tools**:
* Familiarize yourself with tools like Nmap, Metasploit, Burp Suite, and Nikto.
* Practice basic commands (e.g., nmap -sC -sV -p- \<IP> for service enumeration).
* **Create a Lab Environment**:
* Set up vulnerable VMs like Metasploitable or VulnHub machines for practice.

**Time**: 1–2 weeks.&#x20;

#### **Step 3: Complete HTB Academy’s Fundamental Modules**

**Goal**: Complete foundational HTB Academy modules to prepare for the Owen module and CPTS.

* **Tier 0 Modules** (Free, 10 Cubes each, refunded upon completion):
* **Introduction to Academy**: Understand HTB Academy’s interface and learning process.
* **Linux Fundamentals**: Master Linux commands, file systems, and package management.
* **Windows Fundamentals**: Learn Windows CLI, PowerShell, and basic administration.
* **Networking Fundamentals**: Understand TCP/IP, ports, and protocols.
* **Introduction to Web Applications**: Learn web app basics and security principles.
* **Tips**:
* Complete interactive exercises and skills assessments.
* Take detailed notes using Notion or CherryTree for reference.
* Use Pwnbox or your Kali VM for hands-on tasks.

**Time**: 2–3 weeks.

#### **Step 4: Master the Module in HTB Academy**

**Goal**: Complete the module, a critical component of the Penetration Tester path, to build real-world pentesting skills.

* **Overview of the Owen Module**:
* Part of HTB Academy’s Penetration Tester path (Tier I, \~20–50 Cubes).
* Simulates a real-world pentesting scenario with a single target system.
* Focuses on **enumeration, vulnerability identification, exploitation, and privilege escalation** to capture user and root flags.
* **Example Tasks**:
* Use Nmap to enumerate open ports and services (e.g., HTTP, SMB).
* Identify vulnerabilities (e.g., outdated software, misconfigurations).
* Exploit vulnerabilities (e.g., web app file upload to gain a reverse shell).
* Escalate privileges (e.g., exploit SUID binary or weak credentials).
* **Steps to Complete** :

1. **Enumeration**: Run nmap -sC -sV -p- \<IP> to identify services and versions.
2. **Vulnerability Identification**: Use Searchsploit or manual research to find exploits for identified services.
3. **Exploitation**: Gain a foothold (e.g., upload a PHP reverse shell via a web vulnerability).
4. **Privilege Escalation**: Use tools like LinPeas to find escalation vectors.
5. **Submit Flags**: Capture user.txt and root.txt flags to complete the module.

* **Resources**:
* HTB Academy’s module (requires Silver subscription or Cube purchase).
* HackTricks for enumeration and exploitation checklists (https://book.hacktricks.xyz/).
* IppSec’s YouTube videos for similar HTB machines (https://ippsec.rocks/).
* **Tips**:
* Document every step (commands, outputs, screenshots) for report-writing practice.
* If stuck, use HTB’s Discord or forums for hints (avoid spoilers).
* Revisit theory sections to understand concepts before attempting skills assessments.

**Time**: 1–2 weeks.

#### **Step 5: Tackle Web Application Attacks**

**Goal**: Build expertise in web-based vulnerabilities, a core CPTS focus.

* **Learn Web Attacks**:
* Study SQL injection, XSS, file inclusion, and command injection.
* Use Burp Suite Free to intercept and manipulate web traffic.
* **HTB Academy Modules**:
* **Introduction to Web Applications** (Tier 0, free): Web app basics.
* **Attacking Authentication Mechanisms** (Tier III, \~50 Cubes): Authentication bypass, brute-forcing, session hijacking.
* **Cross-Site Scripting (XSS)** (Tier I, \~20 Cubes): Exploit XSS vulnerabilities.
* **Practice Platforms**:
* PortSwigger Web Security Academy (free labs for SQLi, XSS, etc.).
* TryHackMe’s “OWASP Top 10” room.
* DVWA (Damn Vulnerable Web Application) on a local VM.
* **Resources**:
* OWASP Top 10 (https://owasp.org/www-project-top-ten/).
* HTB Academy’s _Web Attacks_ module (Tier I, \~20 Cubes).

**Time**: 2–3 weeks.

#### **Step 6: Focus on Active Directory Exploitation**

**Goal**: Master AD-specific skills, a major CPTS component.

* **Learn AD Basics**:
* Understand AD components (domains, users, groups, Kerberos, NTLM).
* **Resource**: HTB Academy’s _Active Directory Enumeration and Attacks_ module (Tier I, \~20 Cubes).
* **Practice AD Attacks**:
* Learn techniques like Kerberoasting, ASREPRoast, pass-the-hash, and Golden Ticket attacks.
* Use tools like BloodHound, Impacket, CrackMapExec, and PowerView.
* **Resource**: HackTricks AD section (https://book.hacktricks.xyz/windows/active-directory-methodology).
* **HTB Academy Modules**:
* **Active Directory Enumeration and Attacks** (Tier I, \~20 Cubes): AD enumeration and basic attacks.
* **Attacking Active Directory Trust Relationships** (Tier II, \~30 Cubes): Intra-forest and cross-forest attacks.
* **Practice Platforms**:
* HTB’s AD-focused machines (e.g., Active, Forest).
* TryHackMe’s “Attacktive Directory” room.
* GOAD (Game of Active Directory) for local AD lab practice (https://github.com/Orange-Cyberdefense/GOAD).

**Time**: 2–3 weeks.

#### **Step 7: Practice Privilege Escalation**

**Goal**: Develop skills to escalate privileges on Linux and Windows systems.

* **Learn Techniques**:
* Linux: Misconfigured permissions, SUID binaries, kernel exploits.
* Windows: Misconfigured services, DLL hijacking, token impersonation.
* **HTB Academy Modules**:
* **Linux Privilege Escalation** (Tier I, \~20 Cubes): SUID binaries, cron jobs, kernel exploits.
* **Windows Privilege Escalation** (Tier I, \~20 Cubes): Misconfigurations, token abuse.
* **Resources**:
* HackTricks Linux/Windows privilege escalation guides.
* LinPeas/WinPeas scripts for automated enumeration.
* **Practice**:
* HTB boxes like Lame (Linux) or Legacy (Windows).
* TryHackMe’s “Linux Privilege Escalation” and “Windows Privilege Escalation” rooms.

**Time**: 2–3 weeks.

#### **Step 8: Explore HTB Pro Labs and External Platforms**

**Goal**: Gain hands-on experience with enterprise-like networks and CTFs.

* **HTB Academy Machines and Pro Labs**:
* Complete machines in the Penetration Tester path (e.g., Owen, Starting Point Tier 1–2).
* Practice on **Attacking Enterprise Networks (AEN)** module (Tier II, \~30 Cubes) blind to simulate exam conditions. AEN integrates techniques from the entire path.
* Explore HTB Pro Labs (e.g., Dante, Zephyr) for multi-machine AD environments (requires VIP+ subscription, \~$20/month).
* **External Platforms**:
* **TryHackMe (THM)**: Start with “Intro to Offensive Security” and progress to “Blue” or “Web Scanning” rooms ($10/month for full access).
* **Hack The Box (HTB)**: Practice Easy/Medium boxes from TJ Null’s OSCP-like list (https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/) ($12/month for VIP).
* **VulnHub**: Beginner-friendly VMs like Kioptrix, DC-1, or Mr. Robot (free).
* **VulnLab/GOAD**: Local AD labs for advanced practice (free or paid).
* **Tips**:
* Solve 15–20 Easy/Medium boxes on HTB/THM.
* Watch IppSec’s HTB walkthroughs (https://ippsec.rocks/) or 0xdf’s write-ups (https://0xdf.gitlab.io/) after attempting machines.
* Document every machine for report-writing practice.

**Time**: 4–6 weeks.

#### **Step 9: Hone Reporting Skills**

**Goal**: Learn to write commercial-grade penetration test reports.

* **Understand Requirements**:
* Reports must include methodology, vulnerabilities, attack chains, screenshots, and remediation advice.
* Follow HTB’s report template (provided in the _Documentation & Reporting_ module, Tier I, \~20 Cubes).
* **Practice Writing**:
* Write reports for every machine/module (e.g., Owen, AEN) you complete.
* Use **Sysreptor** (https://sysreptor.com/) for professional report generation, pre-configured for HTB certifications.
* **HTB Academy Resource**:
* **Documentation & Reporting** module (Tier I, \~20 Cubes): Learn to structure reports and document attack chains.
* **Tips**:
* Be concise and professional; ensure clarity for non-technical readers.
* Include CVE numbers, severity ratings, and actionable mitigations.
* Take screenshots of all steps (e.g., Nmap output, exploit execution).

**Time**: Ongoing during lab practice.

#### **Step 10: Simulate the Exam Environment**

**Goal**: Prepare for the 10-day exam format.

* **Mock Exams**:
* Practice on HTB’s _Attacking Enterprise Networks_ module blind to simulate exam conditions.
* Use HTB Pro Labs (e.g., Dante, Zephyr) or GOAD for multi-machine AD scenarios.
* Attempt 3–5 machines in a 48-hour period to mimic exam pressure.
* **Time Management**:
* Allocate \~6–8 hours per machine; move on if stuck after 2–3 hours.
* Take breaks to stay focused and avoid burnout.
* Draft reports during practice to save time in the exam.
* **Environment Setup**:
* Configure a Kali VM or use Pwnbox with all tools ready.
* Test VPN connectivity (HTB provides VPN files or Pwnbox access).
* Back up your VM and notes before the exam.
* **Exam Tips**:
* **Read the Letter of Engagement**: Understand scope and objectives.
* **Enumerate Thoroughly**: Use tools like Nmap, Enum4linux, and BloodHound.
* **Document Everything**: Take screenshots and notes for the report.
* **Chain Vulnerabilities**: Combine multiple weaknesses for maximum impact.
* **Submit Early**: Upload your report before the 10-day deadline.

**Time**: 2–3 weeks.

#### Recommended Resources

Free Resources

* **HTB Academy Tier 0 Modules**: Introduction to Academy, Linux Fundamentals, Windows Fundamentals, Networking Fundamentals, Introduction to Web Applications (https://academy.hackthebox.com/).
* **HackTricks**: Comprehensive pentesting cheatsheets (https://book.hacktricks.xyz/).
* **GTFOBins**: Unix binary exploitation guide (https://gtfobins.github.io/).
* **PortSwigger Web Security Academy**: Free web app security labs (https://portswigger.net/web-security).
* **OverTheWire Bandit**: Linux basics (https://overthewire.org/wargames/bandit/).
* **IppSec YouTube**: HTB walkthroughs (https://ippsec.rocks/).
* **0xdf Write-Ups**: Detailed HTB machine guides (https://0xdf.gitlab.io/).
* **Exploit-DB**: Public exploits (https://www.exploit-db.com/).
* **OWASP Top 10**: Web vulnerability guide (https://owasp.org/www-project-top-ten/).
* **Zagnox’s CPTS Cheatsheet**: Practical reference (https://github.com/zagnox/HTB-CPTS-Cheatsheet).

<br>

#### Paid Resources

* **HTB Academy Penetration Tester Path**: Includes Owen module and 27 others (\~$20/month Silver subscription or Cube purchases) (https://academy.hackthebox.com/).
* **HTB Pro Labs (Dante, Zephyr)**: Multi-machine AD environments (\~$20/month VIP+).
* **TryHackMe**: Beginner-friendly platform ($10/month).
* **Hack The Box**: Practice platform ($12/month for VIP).
* **Motasem Hamdan’s CPTS Study Notes**: 1252-page PDF guide (\~$30) (https://motasemhamdan.medium.com/).
* **VulnLab**: AD-focused labs (\~$15/month).

<br>

**Books**

* _Web Application Hacker’s Handbook_ by Dafydd Stuttard and Marcus Pinto.
* _The Hacker Playbook 3_: Practical pentesting guide.
* _Penetration Testing: A Hands-On Introduction to Hacking_ by Georgia Weidman.

<br>

**Tools**

* **Nmap**: Port scanning.
* **Metasploit**: Exploitation framework.
* **Burp Suite Free**: Web app testing.
* **BloodHound/Impacket/CrackMapExec**: AD exploitation.
* **LinPeas/WinPeas**: Privilege escalation scripts.
* **SQLMap**: Automated SQL injection.
* **Hashcat/John the Ripper**: Password cracking.
* **Sysreptor**: Report generation.

**Tips for Success**

* **Complete All Modules**: Finish the Penetration Tester path 100%, including Owen and AEN, to qualify for the exam.
* **Practice Methodology**: Develop a systematic approach (enumerate, exploit, escalate, document) to avoid missing vulnerabilities.
* **Take Notes**: Use Notion, CherryTree, or Joplin to organize commands, tools, and checklists.
* **Learn from Walkthroughs**: After attempting machines/modules (e.g., Owen), review IppSec’s videos or 0xdf’s write-ups for alternative approaches.
* **Join Communities**: Engage with HTB’s Discord or Reddit’s r/hackthebox for support (avoid exam spoilers).
* **Avoid Burnout**: Take breaks, exercise, and sleep well during the 10-day exam.
* **Think Outside the Box**: Practice chaining vulnerabilities, as CPTS rewards creative exploitation.
* **Prepare for Reporting**: Start drafting reports during practice to streamline the exam process.

#### Conclusion

The HTB CPTS is a challenging yet rewarding certification that validates practical, intermediate-level pentesting skills in enterprise environments. By mastering the **Owen module** and the Penetration Tester path on HTB Academy, practicing on Pro Labs and external platforms, and honing your reporting skills, you’ll be well-equipped to pass the 10-day exam. Stay dedicated, embrace the challenge, and leverage the recommended resources to become a certified penetration tester. Good luck on your HTB CPTS journey!
