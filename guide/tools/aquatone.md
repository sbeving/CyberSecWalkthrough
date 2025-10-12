---
icon: dolphin
---

# Aquatone

## The Aquatone Masterclass: Professional Visual Reconnaissance & Asset Review

Aquatone is a powerful tool for visual reconnaissance—automatically gathering screenshots, web metadata, and insights from discovered hosts, domains, and IPs. It enables bug bounty hunters, red teamers, and penetration testers to rapidly map web attack surfaces, spot anomalies, and prioritize promising leads through visual report triage.

***

### I. Environment Setup: Dynamic Variables

Create session variables for scalable, reproducible workflows:

```bash
export HOSTS_FILE="hosts.txt"             # File with domains/IPs (from Amass, Subfinder, etc.)
export OUTPUT_DIR="aquatone-results"
export PORTS="80,443,8080,8000,8443"
export THREADS=50
export TIMEOUT=10                         # Time (sec) to wait for screenshotting/loading
export RESOLUTION="1440,900"              # Screenshot resolution
export PROXY="<http://127.0.0.1:8080>"

```

***

### II. Core Capabilities & Workflow

* **Visual Web Reconnaissance:** Takes screenshots of URLs/domains across specified ports, consolidates metadata (titles, headers, etc.), and facilitates fast triage for vulnerabilities, misconfigurations, and unique endpoints.\[1]\[2]\[3]\[4]\[5]\[6]\[7]
* **Integration with Recon Tools:** Pipes URL targets from assetfinders, subdomain enumerators, and port scanners (Amass, Subfinder, Nmap, Masscan) for streamlined, automated reconnaissance.\[5]\[7]
* **Metadata Collection:** Captures server headers, page titles, unique strings, and technologies for deeper context.\[8]\[5]
* **Custom Port Selection & Threading:** Supports scanning non-standard HTTP ports and parallelizes screenshotting process for speed.\[7]\[8]
* **Report Generation:** Provides navigable HTML reports for easy manual review and annotation.\[1]
* **Takeover Checks:** Feature for domain takeover vulnerability screening (CloudFront, S3, Heroku, etc.).\[4]\[5]
* **Triage & Prioritization:** Group and structure output for efficient analysis in bug bounty/enterprise workflows.\[9]\[1]

***

### III. Professional Usage Examples

#### 1. Screenshot All URLs from Hosts File

```bash
cat $HOSTS_FILE | aquatone -out $OUTPUT_DIR

```

#### 2. Specify Custom Ports to Scan

```bash
cat $HOSTS_FILE | aquatone -ports $PORTS -out $OUTPUT_DIR

```

#### 3. Integrate with Subdomain or Asset Discovery

```bash
amass -active -brute -d example.com -o hosts.txt
cat hosts.txt | aquatone -out $OUTPUT_DIR

```

#### 4. Use Nmap/Masscan XML for Visual Inspection

```bash
cat scan.xml | aquatone -nmap -out $OUTPUT_DIR

```

#### 5. Set Threads and Screenshot Timeout

```bash
cat $HOSTS_FILE | aquatone -threads $THREADS -scan-timeout $TIMEOUT -out $OUTPUT_DIR

```

#### 6. Proxy Support for Internal/Lab Environments

```bash
cat $HOSTS_FILE | aquatone -proxy $PROXY -out $OUTPUT_DIR

```

***

### IV. Advanced Techniques & Scenarios

* **Multi-Source Aggregation:** Merge host lists from Subfinder, Amass, Nmap, and other recon tools before passing to Aquatone.
* **Resolution and Report Customization:** Set screenshot resolution for best review experience or for client documentation.
* **Domain Takeover Detection:** Leverage built-in takeover checks as part of cloud asset reviews.\[4]\[5]
* **Automated Report Triage:** Script regular scans and report reviews for quick bug bounty/enterprise audits.\[10]\[11]\[1]
* **Manual Metadata and UI Analysis:** Review visual quirks—admin panels, outdated CMS, exposed APIs—that automated scanners may miss.\[6]\[8]\[1]
* **Continuous Monitoring:** Periodically rerun Aquatone to track infrastructure changes, new assets, and web interface updates.\[1]

***

### V. Real-World Workflow Example

1. **Export Variables:**

```bash
export HOSTS_FILE="scope_urls.txt"
export OUTPUT_DIR="aquatone_scans"
export PORTS="80,443,8080,8443"

```

1. **Run Combined Subdomain & Port Scan:**

```bash
cat $HOSTS_FILE | aquatone -ports $PORTS -threads 40 -out $OUTPUT_DIR

```

1. **Review HTML Report:**

* Open `$OUTPUT_DIR/aquatone_report.html` for visual inspection.
* Sort screenshots by anomalies, login screens, admin panels, error messages.

1. **Follow Up on High-Value Findings:**

* Combine insights with other vulnerability scanners and manual validation.

***

### VI. Pro Tips & Best Practices

* Use Aquatone after mass subdomain/asset enumeration to visually spot misconfigurations, forgotten endpoints, or new attack surfaces.
* Review generated reports manually—visual clues often highlight bugs missed by automated scanners.\[6]\[8]\[1]
* Integrate screenshotting into regular recon pipelines for ongoing monitoring.
* Organize output directory by scope, project, or vulnerability for efficient access and reporting.
* Share insights, tips, and discoveries with the bug bounty community for feedback and strategy improvement.\[1]
* Prioritize visually unique screenshots—these often uncover interesting conditions or custom web apps.
* Always respect scope and legal boundaries when conducting automated web reconnaissance.

***

This professional Aquatone guide enables efficient, visually enriched reconnaissance, expanding attack surface awareness and enhancing bug bounty/penetration testing workflows for maximum successful discovery.# The Aquatone Masterclass: Professional Visual Reconnaissance & Reporting\[5]\[7]\[8]\[10]\[4]\[1]

Aquatone is a powerful asset review tool for bug bounty hunters, penetration testers, and red teams. It automates the process of taking screenshots and gathering metadata from URLs and domains discovered during recon, enabling rapid triage for anomalies, vulnerabilities, and noteworthy endpoints.

***

### Core Capabilities & Workflow

* **Screenshots and Metadata:** Automatically collects screenshots and website metadata (titles, headers, technologies) for all targets, including custom port support.
* **Integration:** Pipes in targets from asset/discovery tools (Amass, Subfinder, Nmap, Masscan) for efficient, automated reconnaissance.
* **Report Generation:** Creates navigable HTML reports for easy manual review and annotation.
* **Domain Takeover Checks:** Performs checks against vulnerable cloud assets (S3, CloudFront, Heroku, etc.).
* **Prioritization:** Enables fast visual triage for login panels, admin interfaces, error pages, outdated CMS, and other high-value findings.

***

### Professional Usage Examples

*   Screenshot URLs from host/domain file:

    ```bash
    cat hosts.txt | aquatone -out aquatone-results

    ```
*   Scan custom ports:

    ```bash
    cat hosts.txt | aquatone -ports 80,443,8080,8000,8443 -out aquatone-results

    ```
*   Use Nmap/Masscan XML:

    ```bash
    cat scan.xml | aquatone -nmap -out aquatone-results

    ```
*   Set threads, timeout, and custom resolution:

    ```bash
    cat hosts.txt | aquatone -threads 40 -scan-timeout 10 -out aquatone-results

    ```
*   Proxy for internal/lab testing:

    ```bash
    cat hosts.txt | aquatone -proxy <http://127.0.0.1:8080> -out aquatone-results

    ```

***

### Advanced Techniques

* Merge host lists from Subfinder, Amass, Nmap, and feed them to Aquatone for comprehensive scans.
* Customize resolution and report layout for best experience and client evidence.
* Automate regular scans and visually review for changes, new assets, or compromised endpoints.
* Use built-in takeover and metadata checks for quick bug bounty wins.
* Triaging visually unique screenshots is key; prioritize manual review of anything abnormal.

***

### Pro Tips & Best Practices

* Always pipe enumerated hosts from your recon workflow for immediate, organized visual reports.
* Use Aquatone’s HTML report and metadata to complement vulnerability scanner results.
* Keep report data organized by project/scope for efficient follow-up and reporting.
* Regularly update and review findings—visual clues often reveal bugs missed by automated scanners.
* Respect program scope and scan etiquette when automating screenshotting and reporting.

***

This Aquatone guide equips professionals for rapid, structured visual review, asset triage, and uncovering novel vulnerabilities missed by traditional recon alone.

Sources \[1] Leveraging Aquatone for Visual Reconnaissance... [https://bugbustersunited.com/leveraging-aquatone-for-visual-reconnaissance/](https://bugbustersunited.com/leveraging-aquatone-for-visual-reconnaissance/) \[2] PenTesting - Basic Active Reconnaissance Cheat Sheet [https://www.publish0x.com/cyb3r-s3c/pentesting-basic-active-reconnaissance-cheat-sheet-xxvejlm](https://www.publish0x.com/cyb3r-s3c/pentesting-basic-active-reconnaissance-cheat-sheet-xxvejlm) \[3] ‍♂️ Recon to Master: The Complete Bug Bounty Checklist[https://osintteam.blog/️-️-recon-to-master-the-complete-bug-bounty-checklist-239ecca2fd5c](https://osintteam.blog/%EF%B8%8F-%EF%B8%8F-recon-to-master-the-complete-bug-bounty-checklist-239ecca2fd5c) \[4] Subdomain Takeover: A Complete Security Defense Guide [https://www.startupdefense.io/cyberattacks/subdomain-takeover](https://www.startupdefense.io/cyberattacks/subdomain-takeover) \[5] michenriksen/aquatone: A Tool for Domain Flyovers [https://github.com/michenriksen/aquatone](https://github.com/michenriksen/aquatone) \[6] Reconnaissance and Scanning | s0cm0nkey's Security ... [https://s0cm0nkey.gitbook.io/s0cm0nkeys-security-reference-guide/red-offensive/scanning-active-recon](https://s0cm0nkey.gitbook.io/s0cm0nkeys-security-reference-guide/red-offensive/scanning-active-recon) \[7] What tools I use for my recon during #BugBounty | by Adrien [https://infosecwriteups.com/whats-tools-i-use-for-my-recon-during-bugbounty-ec25f7f12e6d](https://infosecwriteups.com/whats-tools-i-use-for-my-recon-during-bugbounty-ec25f7f12e6d) \[8] Application Enumeration Tips using Aquatone and Burp Suite [https://www.ryanwendel.com/2019/09/27/application-enumeration-tips-using-aquatone-and-burp-suite/](https://www.ryanwendel.com/2019/09/27/application-enumeration-tips-using-aquatone-and-burp-suite/) \[9] $4500 Bounty — How I got lucky [https://infosecwriteups.com/4500-bounty-how-i-got-lucky-99d8bc933f75](https://infosecwriteups.com/4500-bounty-how-i-got-lucky-99d8bc933f75) \[10] Recon to Master: The Complete Bug Bounty Checklist [https://infosecwriteups.com/recon-to-master-the-complete-bug-bounty-checklist-95b80ea55ff0](https://infosecwriteups.com/recon-to-master-the-complete-bug-bounty-checklist-95b80ea55ff0) \[11] Advanced Bug Hunting: Tips, Tricks and Methodology [https://osintteam.blog/advanced-bug-hunting-tips-tricks-and-methodology-9962b05ee740](https://osintteam.blog/advanced-bug-hunting-tips-tricks-and-methodology-9962b05ee740)
