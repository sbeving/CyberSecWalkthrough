---
icon: ankh
---

# Nessus

## The Nessus Masterclass: Professional Vulnerability Scanning & Assessment

Nessus is an industry-leading vulnerability scanning tool trusted by penetration testers and security teams globally. It provides comprehensive host, network, and web application scanning, deep configuration options, credentialed scanning, compliance checks, and highly detailed actionable reports.

***

### I. Environment Setup: Dynamic Variables

Prepare dynamic session variables to streamline recurring scans and reporting:

```bash
export TARGETS_FILE="targets.txt"           # List of hosts/IPs/ranges to scan
export SCAN_POLICY="Advanced Scan"          # Scan template ("Advanced Scan", "Web App Test", "Compliance Check", etc.)
export SCAN_NAME="HTB Internal Audit"
export OUTPUT_DIR="nessus-results"
export REPORT_FILE="$OUTPUT_DIR/report.html"
export AUTH_USER="admin"
export AUTH_PASS="password"
export PORT_RANGE="1-65535"
export PLUGIN_SET="ALL"
export CREDENTIAL_TYPE="SSH"
export CREDENTIALS="vagrant:vagrant"

```

***

### II. Core Capabilities & Workflow

* **Comprehensive Vulnerability Detection:** Scans for thousands of vulnerabilities (CVEs, misconfigurations, outdated software) using over 100,000 plugins updated daily.
* **Credentialed Deep Scanning:** Authenticated scans reveal internal software versions, patch status, default credentials, misconfigurations, and privilege escalation paths\[1]\[2].
* **Advanced Configuration & Policies:** Custom scan templates to throttle speed, tune assessment modules, optimize plugin use, and limit scan scope for sensitive targets\[3].
* **Web Application Testing:** Specialized scans for web apps, identifying common CVEs, input validation issues, SSL/TLS misconfigurations, and authentication flaws\[4].
* **Compliance & Configuration Auditing:** Automated audits against CIS, PCI DSS, HIPAA, and custom policies, assessing system hardening and regulatory adherence.
* **Detailed Reporting & Prioritization:** Severity-based reports (Critical/High/Medium/Low/Info), asset grouping, exploitability analysis, and mitigation/patching guidance\[1].
* **Integration:** Exports for SIEM, ticketing, reporting, and post-exploitation workflows (Metasploit, Burp, etc.)\[5]\[2].

***

### III. Professional Usage Workflow & Examples

#### 1. Create & Configure Scan

* Use “Advanced Scan” for full host and service assessment.
* Upload `targets.txt` for IPs, ranges, hostnames.
* Set port range (default: top 1000; often use: `1-65535` for deep enumeration).
* Select/modify plugins per engagement scope (enable web, compliance, ICS, custom plugins).

#### 2. Credentialed/Internal Scanning

* Add credentials for SSH/SMB/RDP/SNMP to reveal local vulnerabilities and privilege escalation vectors.
* Set scan policy to use `CREDENTIAL_TYPE` for host authentication.

#### 3. Web Application Testing

* Enable web scanning plugins, configure authentication for app testing.
* Set crawler options and custom input validation payloads.

#### 4. Throttling, Stealth, and Performance

* Tune scan speed (performance settings), number of concurrent checks, timeouts, and exclusions for critical/fragile assets\[3].

#### 5. Run Scan & Monitor Progress

* Launch scan from Nessus web UI or API.
* Monitor in real-time, pause for sensitive assets, restart/resume as required.

#### 6. Review & Prioritize Results

* Sort vulnerabilities by severity, exploitability, external-facing importance\[1].
* Triage and correlate findings with exploit databases or SIEM.

#### 7. Export & Integrate Reports

* Export as HTML/PDF/CSV for stakeholders\[1]\[2].
* Import findings to SIEM/ticketing for remediation tracking.
* Map results to Mitre ATT\&CK and compliance standards.

***

### IV. Advanced Techniques & Scenarios

* **Scan for Unauthenticated & Weak Credentials:** Test for public services and default/weak password vulnerabilities.
* **Configure Custom Plugins:** Upload custom scripts and modules to extend scanning features or target unique infrastructure.
* **Authenticated Scan + Metasploit Integration:** Map discovered vulnerabilities to Metasploit modules for immediate exploitation follow-up\[2].
* **Continuous/Automated Audit:** Schedule recurring scans, export differential reports for change management.
* **Compliance Benchmarking:** Use built-in templates for regulatory audits (CIS, PCI, HIPAA, custom).

***

### V. Real-World Workflow Example

1. **Prepare Targets and Credentials:**
   * `targets.txt`: List of IPs/ranges to test
   * Add SSH credentials for Linux; SMB/RDP for Windows
2. **“Advanced Scan” Configuration:**
   * Port range: `1-65535`
   * Enable web app and credentialed plugins
   * Enable deep enumeration features if required
3. **Run Credentialed Scan:**
   * Monitor progress, pause as needed
4. **Export Findings:**
   * Export HTML and CSV for report and patching
5. **Map Critical Vulns to Exploit Modules:**
   * Cross-reference with Metasploit for chained engagement
6. **Remediation & Reporting:**
   * Document patches/fixes, run rescan to validate remediation

***

### VI. Pro Tips & Best Practices

* **Always scan within explicit scope and authorization.**
* **Always test/corraborate credentialed access before running deep scans.**
* **Prioritize remediation with severity/exploitability context.**
* **Tune performance for fragile or high-value targets (limit concurrent plugins, timeouts).**
* **Document configuration settings for reproducibility.**
* **Integrate with ticketing and SIEM for efficient workflow.**
* **Use recurring scans for ongoing change detection and compliance assurance.**
* **Leverage Nessus REST API for automation and integration.**

