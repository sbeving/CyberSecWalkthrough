---
icon: display-chart-up
---

# Nikto

## The Nikto Masterclass: Professional Web Server Scanning & Automation

Nikto is a mature, open-source web server scanner relied upon by penetration testers, bug bounty hunters, and security teams for rapid discovery of vulnerabilities, misconfigurations, outdated software, dangerous files, and server security issues. Its extensible checks, advanced tuning, and flexible reporting support modern workflows and regulatory needs.

***

### I. Environment Setup: Dynamic Variables

Organize assessment sessions with reusable environment variables:

```bash
export TARGET_URL="<https://target.com>"
export PORTS="80,443,8443"
export OUTPUT_DIR="nikto-results"
export OUTPUT_FILE="$OUTPUT_DIR/scan.txt"
export OUTPUT_HTML="$OUTPUT_DIR/scan.html"
export OUTPUT_JSON="$OUTPUT_DIR/scan.json"
export TUNING="1234789abc"      # Nikto tuning codes for scan focus
export TIMEOUT=10
export USER_AGENT="CustomNikto"
export PROXY="<http://127.0.0.1:8080>"

```

***

### II. Core Capabilities & Workflow

* **Comprehensive Vulnerability Checks:** Tests for 6,700+ dangerous files, outdated servers/software, 1,250+ server versions, and 270+ specific server issues.\[1]\[2]
* **Extensive Tuning:** Refine scans using tuning codes to focus on file uploads, injection, outdated components, CGI, and specific vulnerabilities.\[3]\[1]
* **Advanced IDS Evasion:** Uses LibWhisker to randomize requests—encoding, self-reference, header manipulation—for anti-detection/defense tests.\[1]
* **Batch Scanning:** Accepts host files for mass assessment or integration into CI/CD bug bounty pipelines.\[2]\[3]
* **Flexible Reporting:** Saves results as text, CSV, HTML, or JSON for review, sharing, or audit.\[4]\[5]\[3]
* **Timeout, Proxy, and Custom Header Support:** Throttle requests, evade network limits, and scan behind authentication or WAF.\[6]\[2]
* **Compliance Monitoring:** Suits regulatory assessments (PCI DSS, SOC 2, etc.) with formatted, exportable audit reports.\[1]
* **Baseline Monitoring:** Schedule Nikto to establish security baselines and detect configuration drift or regression.\[1]

***

### III. Professional Usage Examples

#### 1. Basic Web Server Scan

```bash
nikto -h "$TARGET_URL"

```

#### 2. Scan on Specific Ports

```bash
nikto -h "$TARGET_URL" -p "80,443,8080"

```

#### 3. Save Output in Multiple Formats

```bash
nikto -h "$TARGET_URL" -o "$OUTPUT_FILE"         # Plain text
nikto -h "$TARGET_URL" -Format htm -o "$OUTPUT_HTML"
nikto -h "$TARGET_URL" -Format json -o "$OUTPUT_JSON"

```

#### 4. Advanced Tuning (Targeting Injection, Uploads, CGI)

```bash
nikto -h "$TARGET_URL" -Tuning 4                # File upload checks
nikto -h "$TARGET_URL" -Tuning 5                # Injection checks
nikto -h "$TARGET_URL" -Tuning 1234789abc       # Custom scan focus

```

#### 5. Set Custom Timeout, User-Agent, Proxy

```bash
nikto -h "$TARGET_URL" -timeout $TIMEOUT -useragent "$USER_AGENT" -useproxy "$PROXY"

```

#### 6. Scan Multiple Hosts from File

```bash
nikto -h "sites.txt" -o "$OUTPUT_DIR/batch_scan.txt"

```

***

### IV. Advanced Techniques & Scenarios

* **Tuning Codes:** Restrict scans to categories (1–files, 2–CGI, 3–default files, 4–uploads, 5–injection, etc.) for focused, faster assessments.\[3]\[4]
* **IDS/IPS Evasion Testing:** Enable encoding and randomization features to assess detection capabilities of blue team.\[1]
* **CI/CD Integration:** Schedule regular scans as part of DevSecOps pipelines; fail builds on critical findings.\[1]
* **Compliance Checks:** Export reports in HTML or CSV for auditors, or use scan baselining for drift detection.\[4]\[1]
* **Combine with Recon Tools:** Use Nikto post-recon (with Dirsearch, ffuf, Nuclei, etc.) for deep surface analysis.
* **Critical Path Monitoring:** Periodic scanning for high-value endpoints—admin panels, extranet portals, deprecated apps.
* **Proxy & Auth Scans:** Authenticate with web apps using custom headers or proxy traffic for internal/external hybrid testing.

***

### V. Real-World Workflow Example

1. **Export Variables**

```bash
export TARGET_URL="<https://shop.htb>"
export OUTPUT_DIR="nikto_reports"

```

1. **Focused Injection/Uploads/CGI Scan, HTML Report**

```bash
nikto -h "$TARGET_URL" -Tuning 458 -Format htm -o "$OUTPUT_DIR/target_scan.html"

```

1. **Batch Scan from File, Save as JSON**

```bash
nikto -h "urls.txt" -Format json -o "$OUTPUT_DIR/batch.json"

```

1. **Analyze and Report**

* Review findings for vulnerabilities, misconfigurations, admin panels, credentials, outdated components, and more.
* Validate high/medium issues and create patch/mitigation tickets.

***

### VI. Pro Tips & Best Practices

* Always keep Nikto’s check database up to date for new vulnerability coverage.
* Use tuning to optimize scans for specific bug bounty or compliance requirements.
* Integrate Nikto output with reporting platforms or SIEM for alerting and remediation tracking.
* Use IDS/IPS evasion features in defensive security assessments.
* Combine with manual and other automated scanners for maximal web application coverage.
* Use appropriate scheduling and baselining to track security posture over time or after major updates.
* Demarcate Nikto scan results by environment and regularly export for compliance/audit documentation.

***

This professional Nikto guide enables you to run thorough, configurable, and automation-friendly web server security scans, accelerating bug bounty investigation, compliance checks, and continuous web security monitoring.\[2]\[6]\[3]\[4]\[1]

Sources \[1] Nikto: Open-Source Web Vulnerability Scanner [https://www.wiz.io/academy/nikto-overview](https://www.wiz.io/academy/nikto-overview) \[2] nikto | Kali Linux Tools [https://www.kali.org/tools/nikto/](https://www.kali.org/tools/nikto/) \[3] Web Vulnerability Scanning with Nikto [https://www.infosectrain.com/blog/web-vulnerability-scanning-with-nikto/](https://www.infosectrain.com/blog/web-vulnerability-scanning-with-nikto/) \[4] Nikto vulnerability scanner: Complete guide [https://www.hackercoolmagazine.com/nikto-vulnerability-scanner-complete-guide/](https://www.hackercoolmagazine.com/nikto-vulnerability-scanner-complete-guide/) \[5] Web Penetration Testing with Kali Linux - Nikto [https://www.oreilly.com/library/view/web-penetration-testing/9781788623377/50ff015b-d05d-4ad3-b816-dfb2817d3f1a.xhtml](https://www.oreilly.com/library/view/web-penetration-testing/9781788623377/50ff015b-d05d-4ad3-b816-dfb2817d3f1a.xhtml) \[6] Unveiling Nikto: A Beginner's Guide to Web Server Security ... [https://infosecwriteups.com/unveiling-nikto-a-beginners-guide-to-web-server-security-scanning-e4f52c5961e7](https://infosecwriteups.com/unveiling-nikto-a-beginners-guide-to-web-server-security-scanning-e4f52c5961e7)
