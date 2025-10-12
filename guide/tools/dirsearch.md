---
icon: folder
---

# Dirsearch

## The Dirsearch Masterclass: Professional Web Directory Brute-Forcing Guide

Dirsearch is a high-performance, feature-rich command-line web path scanner for discovering hidden directories and files on web servers. It supports recursion, extensible wordlists, multithreading, and fine-tuned reporting, making it essential for bug bounty hunters, penetration testers, and red teams.

***

### I. Environment Setup: Dynamic Variables

Organize your Dirsearch sessions with dynamic variables:

```bash
export TARGET_URL="<https://target.com>"
export WORDLIST="db/dicc.txt"
export EXTENSIONS="php,html,js,txt,zip"
export OUTPUT_DIR="dirsearch-results"
export OUTPUT_JSON="$OUTPUT_DIR/scan.json"
export THREADS=50
export DEPTH=3
export DELAY=0                    # Delay (seconds) between requests
export PROXY="<http://127.0.0.1:8080>"
export USER_AGENT="custom-agent"
export EXCLUDE_TEXTS="NotFound,ErrorPage"
export RECURSION_STATUS="200-399"
export EXCLUDE_SUBDIRS="static/,img/,css/"

```

***

### II. Core Capabilities & Workflow

* **Directory and File Brute-Forcing:** Discovers hidden resources on web servers using configurable wordlists and extensions.\[1]\[2]\[3]\[4]
* **Recursive and Deep Recursion:** Automatically brute-forces discovered directories with options for custom recursion depth, forced, and deep recursive scanning.\[3]\[5]\[1]
* **Multithreading and Rate Control:** Faster scans with configurable thread count and delays to evade rate-limiting or WAF detection.\[2]\[1]
* **Custom HTTP Options:** Supports custom headers, proxies, random user agents, cookie strings, and report filtering.\[5]\[1]
* **Advanced Reporting:** JSON, plain-text, and simple text reports for parsing, automation, and bug bounty submission.\[5]
* **Smart Filtering:** Output only specific response codes, length ranges, exclude by content, or suffix filenames for advanced filtering.\[1]\[5]
* **Batch/Automation Support:** Scans URL lists and integrates with recon workflows and CI/CD pipelines.\[6]\[7]
* **Integration:** Commonly chained with Nmap, Masscan, Gau, or recon automation scripts for robust asset discovery.\[7]\[8]

***

### III. Professional Usage Examples

#### 1. Basic Directory Scan

```bash
python3 dirsearch.py -u "$TARGET_URL" -e "$EXTENSIONS"

```

#### 2. Scan with Custom Wordlist & Extensions

```bash
python3 dirsearch.py -u "$TARGET_URL" -w "$WORDLIST" -e "$EXTENSIONS"

```

#### 3. Recursive Scan with Custom Depth and Status Filtering

```bash
python3 dirsearch.py -u "$TARGET_URL" -e "$EXTENSIONS" -r --max-recursion-depth $DEPTH --recursion-status $RECURSION_STATUS

```

#### 4. Multithreaded Scan with Custom Delay

```bash
python3 dirsearch.py -u "$TARGET_URL" -e "$EXTENSIONS" -t $THREADS --delay $DELAY

```

#### 5. Use Proxy and Custom User-Agent

```bash
python3 dirsearch.py -u "$TARGET_URL" -e "$EXTENSIONS" -H "User-Agent: $USER_AGENT" --proxy "$PROXY"

```

#### 6. Exclude Specific Subdirectories

```bash
python3 dirsearch.py -u "$TARGET_URL" -e "$EXTENSIONS" -r --exclude-subdirs $EXCLUDE_SUBDIRS

```

#### 7. Save Results as JSON

```bash
python3 dirsearch.py -u "$TARGET_URL" -e "$EXTENSIONS" --json-report="$OUTPUT_JSON"

```

#### 8. Show Only Specific Status Codes (e.g., 200, 403)

```bash
python3 dirsearch.py -u "$TARGET_URL" -e "$EXTENSIONS" -i 200,403

```

#### 9. Batch Scanning Multiple URLs

```bash
python3 dirsearch.py -L "urls.txt" -e "$EXTENSIONS" -t $THREADS --json-report="$OUTPUT_DIR/batch.json"

```

***

### IV. Advanced Techniques & Scenarios

* **Smart Suffixes/Filtering:** Remove output with certain lengths, add custom suffixes (e.g., `.BAK`, `.old`) to brute retired/backup files.\[5]
* **Exclude Content Terms:** Use `-exclude-texts` to ignore responses that include error phrases or default pages.
* **Chained Recon Automation:** Pipe targets from subdomain/VHost discovery directly into Dirsearch for immediate fuzzing.\[8]\[7]
* **Scan Specific Subdirectories:** Limit scan to known sensitive folders (`-scan-subdirs=/,/wp-admin/`).
* **Bypass Simple Defenses:** Employ random user agents, proxy rotation, and delayed requests.
* **Report Parsing and Prioritization:** Use JSON and text reports for triage, automation, and collaboration platforms.

***

### V. Real-World Workflow Example

1. **Export Variables**

```bash
export TARGET_URL="<https://shop.htb>"
export WORDLIST="db/medium.txt"
export EXTENSIONS="php,js,html"
export OUTPUT_DIR="dirsearch_reports"

```

1. **Full Directory Scan (With Multithreading and Recursion)**

```bash
python3 dirsearch.py -u "$TARGET_URL" -w "$WORDLIST" -e "$EXTENSIONS" -r --max-recursion-depth 2 -t 40 --json-report="$OUTPUT_DIR/results.json"

```

1. **Batch Scan Multiple Targets from Recon**

```bash
python3 dirsearch.py -L "targets.txt" -e "$EXTENSIONS" -t 30 --json-report="$OUTPUT_DIR/batch.json"

```

1. **Automate with Custom Filtering**

```bash
python3 dirsearch.py -u "$TARGET_URL" -e "$EXTENSIONS" --exclude-texts="Error,Not Found,Default"

```

1. **Manual Validation of Interesting Results**

***

### VI. Pro Tips & Best Practices

* Custom wordlists yield deeper results in targeted environments.
* Use recursive scans and custom exclusion to avoid infinite loops and wasted requests.
* Always monitor rate limiting, delays, and threads.
* Integrate Dirsearch with overall recon workflow (subdomain, port discovery, parameter scanning).
* Review JSON/text reports for easy collaboration with teams or for bug bounty proof.
* Respect the scope and avoid crashing target servers with excessive requests.
* Validate findings manually—especially directories with sensitive permissions or anomalous error codes.

***

This Dirsearch guide equips bug bounty hunters and penetration testers to efficiently enumerate hidden web directories, prioritize promising leads, and seamlessly incorporate directory fuzzing into their recon automation workflows.# The Dirsearch Masterclass: Professional Web Directory Brute-Forcing Guide\[4]\[2]\[3]\[6]\[7]\[8]\[1]\[5]

Dirsearch is a fast, feature-rich command-line web path scanner designed to discover hidden directories and files on webservers. It supports recursion, custom extensions, advanced filtering, multithreading, batch scanning, and precision output, making it essential for penetration testers and bug bounty hunters.

***

### I. Environment Setup: Dynamic Variables

Create variables for automated and reproducible scanning:

```bash
export TARGET_URL="<https://target.com>"
export WORDLIST="db/dicc.txt"
export EXTENSIONS="php,html,js,txt"
export OUTPUT_DIR="dirsearch-results"
export OUTPUT_JSON="$OUTPUT_DIR/scan.json"
export THREADS=30
export DEPTH=2
export DELAY=1
export PROXY="<http://127.0.0.1:8080>"
export USER_AGENT="ReconTool"
export RECURSION_STATUS="200-399"
export EXCLUDE_SUBDIRS="static/,img/"
export STATUS_INCLUDE="200,403,500"

```

***

### II. Core Capabilities & Workflow

* **Directory & File Bruteforce:** Uncovers hidden directories/files using user-specified wordlists and extensions.\[2]\[4]\[1]\[5]
* **Recursive/Deep Scanning:** Brute-forces found directories and subdirectories recursively to user-set depth.\[1]\[5]
* **Multithreading:** Accelerates scans with dozens of simultaneous requests; lower delays for stealth.\[1]\[5]
* **Custom Output:** Supports text, JSON, and simple reports for easy parsing and collaboration.\[5]
* **Fine Filtering:** Restrict output to specific status codes, lengths, or exclude by page content.\[1]\[5]
* **Proxy & Headers:** Pass traffic through proxies and set custom headers for testing WAFs, authentication, etc..\[5]\[1]
* **Wordlist Flexibility:** Choose from bundled or custom lists for targeted scans.\[1]\[5]
* **Batch Scanning:** Process lists of URLs/domains for broad reconnaissance.\[6]\[7]

***

### III. Professional Usage Examples

#### 1. Basic Directory Scan

```bash
python3 dirsearch.py -u "$TARGET_URL" -e "$EXTENSIONS"

```

#### 2. Use Custom Wordlist and Multithread

```bash
python3 dirsearch.py -u "$TARGET_URL" -w "$WORDLIST" -e "$EXTENSIONS" -t $THREADS

```

#### 3. Recursive Scan with Filtering

```bash
python3 dirsearch.py -u "$TARGET_URL" -e "$EXTENSIONS" -r --max-recursion-depth $DEPTH --recursion-status $RECURSION_STATUS

```

#### 4. Save Results as JSON

```bash
python3 dirsearch.py -u "$TARGET_URL" -e "$EXTENSIONS" --json-report="$OUTPUT_JSON"

```

#### 5. Set Custom User-Agent and Proxy

```bash
python3 dirsearch.py -u "$TARGET_URL" -e "$EXTENSIONS" -H "User-Agent:$USER_AGENT" --proxy="$PROXY"

```

#### 6. Exclude Subdirectories

```bash
python3 dirsearch.py -u "$TARGET_URL" -e "$EXTENSIONS" -r --exclude-subdirs $EXCLUDE_SUBDIRS

```

#### 7. Batch Scan Multiple URLs

```bash
python3 dirsearch.py -L "urls.txt" -e "$EXTENSIONS" -t $THREADS

```

#### 8. Include Only Specific Status Codes

```bash
python3 dirsearch.py -u "$TARGET_URL" -e "$EXTENSIONS" -i "$STATUS_INCLUDE"

```

***

### IV. Advanced Techniques & Scenarios

* **Suffix Brute-force & Content Exclusion:** Append `.bak`, `.old`, etc.; filter out responses by content or length for deeper results.\[5]
* **Bypass Defenses:** Rotate user agents, delay requests, and use proxies to dodge rate limits and honeypots.\[1]\[5]
* **Combined Recon Workflow:** Chain Dirsearch after subdomain enumeration or vulnerable endpoint discovery for full surface mapping.\[7]\[8]
* **Automated Scripting:** Batch and parse results for integration with reporting tools or bug bounty automation.\[6]\[7]
* **Custom Recursion:** Force or deep recursive to brute-force nested paths, skipping unnecessary subdirectories.\[1]

***

### V. Real-World Workflow Example

1. **Export Variables**

```bash
export TARGET_URL="<https://app.htb>"
export WORDLIST="db/wordlist.txt"
export EXTENSIONS="php,js,html"
export OUTPUT_DIR="dirsearch_reports"

```

1. **Full Scan with Recursion, Filtering, and JSON Output**

```bash
python3 dirsearch.py -u "$TARGET_URL" -w "$WORDLIST" -e "$EXTENSIONS" -r --max-recursion-depth 2 -t 20 --json-report="$OUTPUT_DIR/report.json"

```

1. **Batch Scan from Recon File**

```bash
python3 dirsearch.py -L "discovered_urls.txt" -e "$EXTENSIONS" -t 30 --json-report="$OUTPUT_DIR/batch.json"

```

1. **Manual Verification**

* Review reports for interesting paths; test found endpoints manually.

***

### VI. Pro Tips & Best Practices

* Start with custom wordlists for specific targets or technologies.
* Use recursion thoughtfully—balance coverage versus speed.
* Filter and parse JSON output for efficient bug bounty reporting.
* Integrate Dirsearch into automated pipelines for continuous recon.
* Monitor requests for rate limits or WAF blocks—adjust threads and delays as needed.
* Always respect engagement scope and avoid overwhelming production targets.

***

This Dirsearch guide empowers you for rapid, comprehensive, and customizable web directory enumeration as part of full-scope recon and penetration testing.\[3]\[7]\[6]\[5]\[1]

Sources \[1] maurosoria/dirsearch: Web path scanner [https://github.com/maurosoria/dirsearch](https://github.com/maurosoria/dirsearch) \[2] dirsearch | Kali Linux Tools [https://www.kali.org/tools/dirsearch/](https://www.kali.org/tools/dirsearch/) \[3] Comprehensive Guide on Dirsearch (Part 2) [https://www.hackingarticles.in/comprehensive-guide-on-dirsearch-part-2/](https://www.hackingarticles.in/comprehensive-guide-on-dirsearch-part-2/) \[4] How to use Dirsearch for web directory brute forcing [https://www.linkedin.com/posts/matege-billbright-85aa74268\_dirsearch-is-a-powerful-command-line-tool-activity-7341804849430155264-H2kA](https://www.linkedin.com/posts/matege-billbright-85aa74268_dirsearch-is-a-powerful-command-line-tool-activity-7341804849430155264-H2kA) \[5] DIRSEARCH [https://www.briskinfosec.com/tooloftheday/toolofthedaydetail/DIRSEARCH](https://www.briskinfosec.com/tooloftheday/toolofthedaydetail/DIRSEARCH) \[6] Dirsearch - Penetration Testing Playbook [https://ptplaybook.mfbktech.academy/tools/dirsearch](https://ptplaybook.mfbktech.academy/tools/dirsearch) \[7] Automating Information Gathering for Bug Bounty Hunters [https://osintteam.blog/automating-information-gathering-for-bug-bounty-hunters-161f23dad2ae](https://osintteam.blog/automating-information-gathering-for-bug-bounty-hunters-161f23dad2ae) \[8] Hunting Hidden Attack Surfaces , using Nmap, Masscan & ... [https://infosecwriteups.com/day4-recon-hunting-hidden-attack-surfaces-using-nmap-masscan-dirsearch-for-service-c623de2fcdf6](https://infosecwriteups.com/day4-recon-hunting-hidden-attack-surfaces-using-nmap-masscan-dirsearch-for-service-c623de2fcdf6)
