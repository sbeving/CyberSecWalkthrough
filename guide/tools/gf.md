---
icon: rotate-exclamation
---

# Gf

## The ParamSpider Masterclass: Professional Web Parameter Discovery

ParamSpider is an advanced Python tool for automated discovery of hidden and uncommon parameters in URLs, leveraging web archives, subdomains, and other sources. It empowers bug bounty hunters, penetration testers, and security engineers to maximize their attack surface and uncover high-value vulnerabilities such as XSS, SSRF, IDOR, and open redirects.

***

### I. Environment Setup: Dynamic Variables

Set up variables for consistent, automated scans:

```bash
export DOMAIN="target.com"
export OUTPUT_DIR="paramspider-results"
export OUTPUT_FILE="$OUTPUT_DIR/params.txt"
export LEVEL="high"               # crawling depth: default, medium, high
export EXCLUDE_EXT="jpg,jpeg,png,gif,svg,css,ico,woff,ttf"
export MAX_DEPTH=6                # max crawl levels
export INCLUDE_SUBS=true          # include subdomains
export THREADS=10

```

***

### II. Core Capabilities & Workflow

* **Web Archive & Subdomain Mining:** Extracts URLs & parameters from Internet Archive (Wayback), subdomains, and live HTTP endpoints for the target domain.\[1]\[2]\[3]\[4]
* **Comprehensive Parameter Extraction:** Detects classic, nested, and 'dark corner' parameters often missed by basic tools, including in archived, hidden, and JS-referenced URLs.\[2]\[3]\[5]\[6]\[7]
* **Exclusion & Customization:** Exclude commonly non-interesting extensions (images, fonts, media) for cleaner results, or adjust to target further.\[4]\[7]\[1]
* **Output for Automation:** Writes clean, deduplicated result files usable for chaining into GF, Dalfox, KXSS, Nuclei, fuzzers, or penetration test scripts.\[2]\[4]
* **Pipeline Integration:** Pairs smoothly with other recon tools, GF patterns, and vulnerability scanners for streamlined bug bounty workflows.\[8]\[1]\[4]
* **Lightweight & API Efficient:** Uses APIs efficiently to avoid overloading targets or breaching rate limits.\[1]

***

### III. Professional Usage Examples

#### 1. Basic Parameter Discovery (Default Scan)

```bash
python3 paramspider.py -d "$DOMAIN"

```

#### 2. Deep Crawl with Exclusions, Save Output

```bash
python3 paramspider.py -d "$DOMAIN" --level high --exclude-extensions "$EXCLUDE_EXT" --output "$OUTPUT_FILE"

```

#### 3. Include Subdomains in Parameter Mining

```bash
python3 paramspider.py -d "$DOMAIN" --include-subdomains --output "$OUTPUT_FILE"

```

#### 4. Custom Output for Workflow Pipelines

```bash
python3 paramspider.py -d "$DOMAIN" --level medium --output "$OUTPUT_FILE"
cat "$OUTPUT_FILE" | gf xss > "$OUTPUT_DIR/xss_candidates.txt"
cat "$OUTPUT_DIR/xss_candidates.txt" | dalfox pipe

```

#### 5. Control Maximum Crawl Depth

```bash
python3 paramspider.py -d "$DOMAIN" --max-crawl $MAX_DEPTH --output "$OUTPUT_FILE"

```

#### 6. Batch or Scripting for Multiple Domains

```bash
for domain in $(cat domains.txt); do \\\\
  python3 paramspider.py -d "$domain" --level high --output "$OUTPUT_DIR/$domain.txt"; \\\\
done

```

***

### IV. Advanced Techniques & Scenarios

* **Nested & Obfuscated Parameter Discovery:** Finds "weird" formats, e.g., in base64, as path variables, or in obscure query/JSON formats.\[5]\[6]
* **Workflow Automation:** Use ParamSpider output with GF's patterns for rapid bug class triage (XSS, SSRF, Open Redirect, etc.), then feed high-signal URLs into Dalfox, KXSS, Nuclei for vulnerability validation.\[9]\[5]\[1]\[2]
* **JS & API Recon:** Parse URLs/params from external JavaScript files and non-standard entry points, increasing footprint.\[10]
* **Exclude Extension Control:** Prevents noisy/filler params from polluting actionable output for high signal bug bounty workflows.\[4]\[1]
* **Stealth Recon:** No active requests to the target—uses passive archival/API scraping to minimize detection.\[11]\[1]

***

### V. Real-World Workflow Example

1. **Deep, Clean Param Discovery & Filtering XSS Candidates**

```bash
python3 paramspider.py -d hackinglab.htb --level high --exclude-extensions "jpg,png,gif,css,ico,woff,svg" --output paramspider-results/params.txt
cat paramspider-results/params.txt | gf xss > paramspider-results/xss.txt

```

1. **Automate Further with Dalfox for XSS**

```bash
cat paramspider-results/xss.txt | dalfox pipe

```

1. **Batch for a Domain List**

```bash
for d in $(cat scope.txt); do python3 paramspider.py -d $d --output paramspider-batch/$d.txt; done

```

***

### VI. Pro Tips & Best Practices

* Start with high-level scanning and include subdomains for maximum parameter coverage.\[7]\[4]
* Always exclude noise extensions (media/fonts) unless specifically needed for the target.
* Chain ParamSpider → GF → Dalfox/Nuclei for fast, automated bughunting.
* Review and validate findings manually to confirm true vulnerabilities.
* Regularly update tool and wordlists for most effective mining.\[4]
* Use batch mode for recon across broad scopes or enterprise systems.
* Respect API usage—avoid abusive automated requests, especially for public web archives.

***

This professional ParamSpider guide positions bug bounty professionals and pentesters to maximize parameter discovery, automate bug class triage, and scale their attack surface awareness for high-impact security research.\[3]\[6]\[5]\[7]\[1]\[2]\[4]

Sources \[1] ParamSpider: New tool helps in the discovery of URL ... [https://portswigger.net/daily-swig/paramspider-new-tool-helps-in-the-discovery-of-url-parameter-vulnerabilities](https://portswigger.net/daily-swig/paramspider-new-tool-helps-in-the-discovery-of-url-parameter-vulnerabilities) \[2] Discover ParamSpider: A Powerful Tool for Web ... [https://www.linkedin.com/posts/asim-khan-a1b175303\_cybersecurity-webreconnaissance-paramspider-activity-7349174553077547008-Tv9c](https://www.linkedin.com/posts/asim-khan-a1b175303_cybersecurity-webreconnaissance-paramspider-activity-7349174553077547008-Tv9c) \[3] ParamSpider - Digging parameters from dark corners of ... [https://www.geeksforgeeks.org/linux-unix/paramspider-digging-parameters-from-dark-corners-of-web-archives/](https://www.geeksforgeeks.org/linux-unix/paramspider-digging-parameters-from-dark-corners-of-web-archives/) \[4] devanshbatham/ParamSpider [https://github.com/devanshbatham/ParamSpider](https://github.com/devanshbatham/ParamSpider) \[5] Parameter Discovery: A quick guide to start [https://www.yeswehack.com/learn-bug-bounty/parameter-discovery-quick-guide-to-start](https://www.yeswehack.com/learn-bug-bounty/parameter-discovery-quick-guide-to-start) \[6] Advanced ParamSpider Tactics Every Hacker Must Know ... [https://systemweakness.com/unlock-hidden-web-vulnerabilities-advanced-paramspider-tactics-every-hacker-must-know-62487db3e8c8](https://systemweakness.com/unlock-hidden-web-vulnerabilities-advanced-paramspider-tactics-every-hacker-must-know-62487db3e8c8) \[7] 0xKayala/ParamSpider: Mining URLs from dark corners of ... [https://github.com/0xKayala/ParamSpider](https://github.com/0xKayala/ParamSpider) \[8] Getting Started With the Advanced Filtering Extension [https://docs.gravitykit.com/article/833-getting-started-with-the-advanced-filtering-extension](https://docs.gravitykit.com/article/833-getting-started-with-the-advanced-filtering-extension) \[9] Combining ParamSpider and Dalfox in Kali Linux for ... [https://systemweakness.com/combining-paramspider-and-dalfox-in-kali-linux-for-enhanced-security-testing-2bd095c8d1a1](https://systemweakness.com/combining-paramspider-and-dalfox-in-kali-linux-for-enhanced-security-testing-2bd095c8d1a1) \[10] Advanced Free Resources for Bug Bounty Hunters [https://infosecwriteups.com/advanced-free-resources-for-bug-bounty-hunters-b830c4a99e2f](https://infosecwriteups.com/advanced-free-resources-for-bug-bounty-hunters-b830c4a99e2f) \[11] Bug Bounty Hunting, Part 02: Stealthy Parameter Detection ... [https://hackers-arise.com/bug-bounty-hunting-part-2-stealthy-parameter-detection-with-paramspider/](https://hackers-arise.com/bug-bounty-hunting-part-2-stealthy-parameter-detection-with-paramspider/)
