---
icon: atom-simple
---

# Nuclei

## The Nuclei Masterclass: Professional Vulnerability Scanning & Automation

Nuclei is a fast, template-based vulnerability scanner trusted by bug bounty hunters, penetration testers, and security researchers for web, API, and cloud reconnaissance. Its power lies in its massive YAML template library, custom template creation, advanced filtering, and seamless integration with recon automation pipelines.

***

### I. Environment Setup: Dynamic Variables

Set session variables for organized, repeatable scans and rapid reporting:

```bash
export TARGET_URL="<https://target.com>"
export TARGET_LIST="urls.txt"
export TEMPLATES_DIR="~/nuclei-templates"
export OUTPUT_DIR="nuclei-results"
export OUTPUT_FILE="$OUTPUT_DIR/scan.txt"
export SEVERITY="critical,high,medium"
export TAGS="xss,cors,ssrf,open-redirect"
export EXCLUDE_TAGS="dos,performance"
export THREADS=50
export RATE_LIMIT=100           # Requests per second
export PROXY="<http://127.0.0.1:8080>"

```

***

### II. Core Capabilities & Workflow

* **Template-Driven Scanning:** Uses thousands of community and custom YAML templates for CVEs, misconfigurations, exposures, panels, and more.\[1]\[2]\[3]\[4]\[5]
* **Massive Coverage:** Scans HTTP, DNS, TCP, SSL, API, cloud, panels, and more with precision and speed.\[6]\[7]\[8]\[9]\[1]
* **Advanced Filtering:** Scan by severity, tag, author, template path, name, exclusions, and more for laser-focused bug bounty and enterprise workflows.\[9]\[10]\[6]
* **Automation & Integration:** Works seamlessly with Subfinder, Amass, httpx, GF, and other recon tools as part of CI/CD, pipeline automation, and continuous bug hunting.\[3]\[7]\[10]\[11]\[1]
* **Custom Template Creation:** Easily build YAML templates for 0days, unique environments, or underreported bugs; export and apply in collaboration.\[2]\[4]\[8]\[9]
* **Output Formats:** Simple text, JSON, CSV for reporting, integrations, and bug bounty proof.\[12]\[13]
* **Performance Tuning:** Threading, rate limiting, request delays, proxying, and exclusion options for stealth and precision.\[3]\[6]

***

### III. Professional Usage Examples

#### 1. Scan a Single URL or List With All HTTP Templates

```bash
nuclei -u "$TARGET_URL" -t "$TEMPLATES_DIR/http/"
nuclei -l "$TARGET_LIST" -t "$TEMPLATES_DIR/http/"

```

#### 2. Scan with Multiple Tags, Severity, and Exclusions

```bash
nuclei -l "$TARGET_LIST" -tags $TAGS -severity $SEVERITY -exclude-tags $EXCLUDE_TAGS -o "$OUTPUT_FILE"

```

#### 3. Scan for Specific CVEs

```bash
nuclei -u "$TARGET_URL" -t "$TEMPLATES_DIR/cves/CVE-2022-XXXX.yaml"

```

#### 4. Custom Template Scan (For Your Own YAML File)

```bash
nuclei -u "$TARGET_URL" -t "$TEMPLATES_DIR/custom/my-zeroday.yaml"

```

#### 5. Using Rate Limit, Threads, and Proxy

```bash
nuclei -l "$TARGET_LIST" -rate-limit $RATE_LIMIT -threads $THREADS -proxy $PROXY

```

#### 6. Exclude/Include Specific Template Files

```bash
nuclei -l "$TARGET_LIST" -t "$TEMPLATES_DIR/" -exclude-templates "http/misc/robots-txt.yaml"

```

#### 7. Save in JSON or CSV for Automation

```bash
nuclei -l "$TARGET_LIST" -t "$TEMPLATES_DIR/http/" -json -o "$OUTPUT_DIR/results.json"
nuclei -l "$TARGET_LIST" -t "$TEMPLATES_DIR/http/" -csv -o "$OUTPUT_DIR/results.csv"

```

#### 8. Run as Part of a Bug Bounty Pipeline

```bash
cat liveurls.txt | nuclei -t "$TEMPLATES_DIR/" -tags xss,ssrf,idor -severity high,critical -o "$OUTPUT_DIR/highvalue.txt"

```

#### 9. Find Only New/Latest Templates (Rapid Response)

```bash
nuclei -l "$TARGET_LIST" -nt

```

***

### IV. Advanced Techniques & Scenarios

* **Custom Template Creation:** Write YAML templates to codify exploit logic for unique findings or new CVEs; share with the security community.\[4]\[8]\[9]
* **Combine With Recon Automation:** Run Subfinder → httpx → GF → Nuclei for continuous asset and bug hunting.\[7]\[14]\[1]
* **Author/Tag/Severity-Driven Scans:** Focus on specific researchers, bug classes, or high-priority risks for triage and reporting.\[10]
* **Workflow & Fuzzing:** Leverage advanced workflow templates for multi-step logic and state-based testing.\[6]
* **Output Integration:** Feed JSON/CSV output into custom dashboards, reporting tools, ticketing, or further scanner/validation steps.
* **Exclude/Include Logic:** Refine template pools for stealth, compliance, or environment-specific bug hunting.

***

### V. Real-World Workflow Example

1. **Set Variables and Prepare Recon/Lists**

```bash
export TARGET_LIST="assets.txt"
export OUTPUT_DIR="nuclei_reports"
export TAGS="xss,idor,open-redirect,ssrf"
export SEVERITY="critical,high"

```

1. **Rapid Targeted Scan With Filtering**

```bash
nuclei -l "$TARGET_LIST" -tags $TAGS -severity $SEVERITY -threads 60 -rate-limit 200 -o "$OUTPUT_DIR/high_priority.txt"

```

1. **Custom Template for Unique Bug**

```bash
nuclei -u "<https://app.htb>" -t "$TEMPLATES_DIR/custom/myunique.yaml" -o "$OUTPUT_DIR/custom.txt"

```

1. **Automate from Recon Pipeline to Reporting**

***

### VI. Pro Tips & Best Practices

* Update templates regularly for best coverage—the community is constantly sharing new exploits.\[5]\[4]\[10]
* Learn YAML; custom template writing is the best way to exploit new and unique environments.
* Use tag/severity filtering for focused bug bounty scans.
* Integrate nuclei output with dashboards for continuous monitoring and team collaboration.\[15]
* Leverage rate limits, thread counts, and proxies for stealth on production engagements.
* Always manually verify high/critical findings; nuclei is high signal, but direct exploitation is essential for bug bounty submission.
* Regularly contribute new templates to maximize value for the entire security research community.

***

This professional Nuclei guide streamlines vulnerability scanning, from broad asset sweeps to targeted bug hunting, with advanced automation, filtering, and extensibility.\[8]\[1]\[4]\[7]\[9]\[10]\[15]\[3]\[6]

Sources \[1] The Ultimate Guide to Finding Bugs With Nuclei [https://projectdiscovery.io/blog/ultimate-nuclei-guide](https://projectdiscovery.io/blog/ultimate-nuclei-guide) \[2] Beginners guide to Nuclei vulnerability scanner [https://www.hackercoolmagazine.com/beginners-guide-to-nuclei-vulnerability-scanner/](https://www.hackercoolmagazine.com/beginners-guide-to-nuclei-vulnerability-scanner/) \[3] How to Perform Security Testing Using Nuclei [https://www.linkedin.com/pulse/how-perform-security-testing-using-nuclei-extensive-guide-guha-vncmc](https://www.linkedin.com/pulse/how-perform-security-testing-using-nuclei-extensive-guide-guha-vncmc) \[4] projectdiscovery/nuclei-templates: Community curated list ... [https://github.com/projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) \[5] Nuclei Templates [https://hackmd.io/ty9\_-T1IT4Gi-MeamRrNKg](https://hackmd.io/ty9_-T1IT4Gi-MeamRrNKg) \[6] projectdiscovery/nuclei [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) \[7] Advanced Techniques & Use Cases of Nuclei for Bug Bounty ... [https://osintteam.blog/part-3-advanced-techniques-use-cases-of-nuclei-for-bug-bounty-1fb810800b8c](https://osintteam.blog/part-3-advanced-techniques-use-cases-of-nuclei-for-bug-bounty-1fb810800b8c) \[8] The Ultimate Guide to Nuclei Enumeration Scanner [https://parrot-ctfs.com/blog/the-ultimate-guide-to-nuclei-enumeration-scanner/](https://parrot-ctfs.com/blog/the-ultimate-guide-to-nuclei-enumeration-scanner/) \[9] Introduction to Nuclei, an Open Source Vulnerability Scanner [https://www.vaadata.com/blog/introduction-to-nuclei-an-open-source-vulnerability-scanner/](https://www.vaadata.com/blog/introduction-to-nuclei-an-open-source-vulnerability-scanner/) \[10] The ultimate beginner's guide to Nuclei [https://www.bugcrowd.com/blog/the-ultimate-beginners-guide-to-nuclei/](https://www.bugcrowd.com/blog/the-ultimate-beginners-guide-to-nuclei/) \[11] Bug Bounty Automation with Nuclei Course [https://www.stationx.net/courses/bug-bounty-automation/](https://www.stationx.net/courses/bug-bounty-automation/) \[12] Nuclei User Guide | PDF | Software Engineering [https://www.scribd.com/document/890240113/Nuclei-User-Guide](https://www.scribd.com/document/890240113/Nuclei-User-Guide) \[13] Bug bounty automation - Nuclei templates [https://bugbase.ai/blog/automating-bug-bounties-with-nuclei](https://bugbase.ai/blog/automating-bug-bounties-with-nuclei) \[14] Building a Fast One-Shot Recon Script for Bug Bounty [https://projectdiscovery.io/blog/building-one-shot-recon](https://projectdiscovery.io/blog/building-one-shot-recon) \[15] A Tool Far Beyond Bug Bounty and Vulnerability Assessment [https://www.linkedin.com/pulse/nuclei-tool-far-beyond-bug-bounty-vulnerability-assessment-aneke-kkugc](https://www.linkedin.com/pulse/nuclei-tool-far-beyond-bug-bounty-vulnerability-assessment-aneke-kkugc)
