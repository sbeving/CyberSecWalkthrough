---
icon: list-check
---

# Sublist3r

## The Sublist3r Masterclass: Professional Subdomain Enumeration Workflow

Sublist3r is a fast, robust Python-based tool for subdomain enumeration, trusted by bug bounty hunters, pentesters, and red teams to uncover the full breadth of an organization's public-facing assets. It aggregates OSINT sources, search engines, APIs, and brute-forcing to maximize coverage and efficiently map attack surfaces.

***

### I. Environment Setup: Dynamic Variables

Design repeatable and organized enumeration campaigns using:

```bash
export DOMAIN="target.com"
export OUTPUT_DIR="sublist3r-results"
export OUTPUT_FILE="$OUTPUT_DIR/subdomains.txt"
export THREADS=50
export PORTS="80,443,8080"
export ENGINES="google,yahoo,bing,baidu,ask,netcraft,virustotal"
export BRUTEFORCE=false
export VERBOSE=true

```

***

### II. Core Capabilities & Workflow

* **OSINT Subdomain Discovery:** Queries multiple search engines (Google, Bing, Yahoo, Baidu, Ask), public APIs (Netcraft, VirusTotal, ThreatCrowd, DNSdumpster), and archives for subdomain data.\[1]\[2]\[3]\[4]\[5]
* **Brute Force Enumeration:** Optional brute-forcing of subdomains using custom or built-in wordlists for non-public assets.\[4]\[6]\[1]
* **Custom Engine Selection:** Focus scans using specific data sources and combine results for broader coverage.\[3]\[4]
* **Multithreaded Performance:** Handles large targets quickly with configurable thread counts.\[1]\[3]
* **Export & Integration:** Outputs deduplicated subdomains to text files ready for downstream recon, probing, or vulnerability assessment (httpx, ffuf, nuclei, aquatone, etc.).\[7]\[8]\[3]
* **Silent and Verbose Modes:** Choose quiet operation for automation or enable verbose output for progress and troubleshooting.\[9]\[4]
* **Module Usage:** Sublist3r can be imported in custom Python scripts for workflow automation or chained recon.\[4]

***

### III. Professional Usage Examples

#### 1. Basic Subdomain Enumeration

```bash
python3 sublist3r.py -d "$DOMAIN"

```

#### 2. Save Results to File

```bash
python3 sublist3r.py -d "$DOMAIN" -o "$OUTPUT_FILE"

```

#### 3. Use Specific Search Engines Only

```bash
python3 sublist3r.py -d "$DOMAIN" -e "$ENGINES"

```

#### 4. Enable Brute-Force Mode (Deeper Enumeration)

```bash
python3 sublist3r.py -d "$DOMAIN" --bruteforce

```

#### 5. Verbose Output for Real-Time Progress

```bash
python3 sublist3r.py -d "$DOMAIN" -v

```

#### 6. Scan Ports and DNS Probe

_Use results for fast probing with other tools:_

```bash
cat "$OUTPUT_FILE" | httpx -ports $PORTS -o "$OUTPUT_DIR/active.txt"

```

#### 7. Automation/Batch Scanning

```bash
for d in $(cat domains.txt); do python3 sublist3r.py -d $d -o "$OUTPUT_DIR/$d.txt"; done

```

#### 8. Module Usage (Python scripting)

```python
import sublist3r
subdomains = sublist3r.main(DOMAIN, THREADS, OUTPUT_FILE, ports=None, silent=False, verbose=True, enable_bruteforce=False, engines=None)

```

***

### IV. Advanced Techniques & Scenarios

* **Combine Engines Strategically:** Use only engines/APIs likely to yield non-overlapping results for the target sector.\[5]
* **Batch Automation:** Enumerate multiple domains for bug bounty or enterprise attack surface management.\[7]
* **Post-Enumeration Chaining:** Pipe results into vulnerability scanners, visual recon tools (Aquatone), brute forcers, or HTTP service enumerators for a deep asset review.\[10]\[3]\[7]
* **Brute-Force for Forgotten Assets:** Enable `-bruteforce` with custom lists to reveal assets missed by APIs/search engines.\[6]
* **Silent/Integration Mode:** Set silent output for scripted recon or integration with Slack, dashboards, or CI/CD triggers.

***

### V. Real-World Workflow Example

1. **Save and Probe**

```bash
python3 sublist3r.py -d devcorp.htb -o sublist3r-results/subs.txt
cat sublist3r-results/subs.txt | httpx -ports 80,443,8080,8443 -o sublist3r-results/live.txt

```

1. **Batch Scan Multiple Domains**

```bash
for d in $(cat targets.txt); do python3 sublist3r.py -d $d -o recon/$d.txt; done

```

1. **Brute-Force Hidden Subdomains**

```bash
python3 sublist3r.py -d target.com --bruteforce -o recon/target_brute.txt

```

1. **Use in Python Automation**

```python
import sublist3r
result = sublist3r.main("target.com", 50, "recon/target.txt", ports=None, silent=True, verbose=False, enable_bruteforce=True, engines="google,netcraft")

```

***

### VI. Pro Tips & Best Practices

* Always validate discovered subdomains with DNS resolution probes to confirm they are active.\[8]\[3]
* Combine Sublist3r output with visual evidence (Aquatone) for bug bounty submission.
* Use diverse engines and brute-force for maximum coverage on security-critical domains.
* Implement verbose output for troubleshooting or silent mode for automation.
* Regularly update both the tool and associated wordlists/APIs for best results.\[3]\[1]
* Combine output with other asset discovery tools for holistic recon coverage.\[7]
* Respect program scope and legal authorization before scanning.

***

This professional Sublist3r guide accelerates thorough, automated subdomain enumeration and asset discovery—maximizing attack surface awareness and boosting bug bounty and red team success.\[2]\[11]\[12]\[5]\[8]\[10]\[1]\[3]\[4]\[7]

Sources \[1] sublist3r | Kali Linux Tools [https://www.kali.org/tools/sublist3r/](https://www.kali.org/tools/sublist3r/) \[2] Discovering subdomains with Sublist3r - Hacking Tutorials [https://www.hackingtutorials.org/web-application-hacking/discovering-subdomains-with-sublist3r/](https://www.hackingtutorials.org/web-application-hacking/discovering-subdomains-with-sublist3r/) \[3] How to Use Sublist3r for Reconnaissance - Hacker Haven [https://hackerhaven.io/2025/01/21/find-subdomains-fast-how-to-use-sublist3r-for-reconnaissance/](https://hackerhaven.io/2025/01/21/find-subdomains-fast-how-to-use-sublist3r-for-reconnaissance/) \[4] aboul3la/Sublist3r: Fast subdomains enumeration tool for ... [https://github.com/aboul3la/Sublist3r](https://github.com/aboul3la/Sublist3r) \[5] Best Subdomain Finders for Reconnaissance in Bug Bounty ... [https://ahmad.science/2024/07/05/best-subdomain-finders-for-reconnaissance-in-bug-bounty-and-hacking/](https://ahmad.science/2024/07/05/best-subdomain-finders-for-reconnaissance-in-bug-bounty-and-hacking/) \[6] Turbolist3r - Subdomain enumeration tool [https://www.geeksforgeeks.org/linux-unix/turbolist3r-subdomain-enumeration-tool/](https://www.geeksforgeeks.org/linux-unix/turbolist3r-subdomain-enumeration-tool/) \[7] tedmdelacruz/recon-scripts: A simple reconnaissance ... [https://github.com/tedmdelacruz/recon-scripts](https://github.com/tedmdelacruz/recon-scripts) \[8] “Day 2: Reconnaissance — How I Found My First Real Bug ... [https://infosecwriteups.com/day-2-reconnaissance-how-i-found-my-first-real-bug-and-how-you-can-too-dbf81cb44069](https://infosecwriteups.com/day-2-reconnaissance-how-i-found-my-first-real-bug-and-how-you-can-too-dbf81cb44069) \[9] Day 47 - Sublist3r - 100 tools in 100 days! - | Matthew McCorkle [https://matthewomccorkle.github.io/day\_047\_sublist3r/](https://matthewomccorkle.github.io/day_047_sublist3r/) \[10] How I Found 50 Bugs With Just 3 Recon Tools - OSINT Team [https://osintteam.blog/how-i-found-50-bugs-with-just-3-recon-tools-42b2a004c141](https://osintteam.blog/how-i-found-50-bugs-with-just-3-recon-tools-42b2a004c141) \[11] Day3 Recon: Subdomain Enumeration for Beginners: A ... [https://infosecwriteups.com/day3-recon-subdomain-enumeration-for-beginners-a-hands-on-guide-using-sublist3r-amass-gobuster-20ce5cacab81](https://infosecwriteups.com/day3-recon-subdomain-enumeration-for-beginners-a-hands-on-guide-using-sublist3r-amass-gobuster-20ce5cacab81) \[12] Subdomain Enumeration: 2019 Workflow - Patrik Hudak [https://0xpatrik.com/subdomain-enumeration-2019/](https://0xpatrik.com/subdomain-enumeration-2019/)
