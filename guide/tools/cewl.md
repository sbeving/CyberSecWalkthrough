---
icon: wordpress-simple
---

# Cewl

## The CeWL Masterclass: Professional Custom Wordlist Generation for Penetration Testing

CeWL (Custom Word List) is a powerful Ruby-based tool used to spider and crawl websites to generate tailored wordlists. These wordlists enhance password cracking efforts by using keywords and unique terms extracted from the target domain, maximizing relevance and reducing guesswork. CeWL is widely used by penetration testers, bug bounty hunters, and security researchers.

***

### I. Environment Setup: Dynamic Variables

Set these variables for consistent, repeatable wordlist generation workflows:

```bash
export TARGET_URL="<https://target.com>"
export DEPTH=2                   # Depth to crawl (levels)
export MIN_WORD_LENGTH=5         # Minimum length of words to include
export OUTPUT_DIR="cewl-results"
export WORDLIST_FILE="$OUTPUT_DIR/custom_wordlist.txt"
export LOWERCASE=false           # Convert words to lowercase (true/false)
export EMAIL_EXTRACTION=true     # Enable email address scraping
export VERBOSE=true              # Enable detailed output
export AUTH_TYPE="basic"         # Authentication type if needed (basic/digest)
export AUTH_USER="user"
export AUTH_PASS="pass"
export PROXY="<http://127.0.0.1:8080>"

```

***

### II. Core Capabilities & Workflow

* **Targeted Web Crawling:** Spiders target URLs using depth settings to extract unique and specific words.
* **Wordlist Generation:** Extracts keywords and stores them in plain text files for use in password cracking tools like John the Ripper or Hashcat.
* **Email Address Harvesting:** Optionally scrapes emails from "mailto" links to build username lists.
* **Authentication Support:** Supports Basic and Digest authentication for crawling behind login walls.
* **Proxy Support:** Route crawling through proxies or VPNs.
* **Verbose Mode:** Display crawling and extraction details during generation.
* **Word Filtering:** Minimum word length and configurable rules to clean up wordlists.
* **Output Flexibility:** Save to file or standard output.

***

### III. Professional Usage Examples

#### 1. Basic Crawl and Wordlist Generation

```bash
cewl -d $DEPTH -m $MIN_WORD_LENGTH -w $WORDLIST_FILE $TARGET_URL

```

#### 2. Crawl with Lowercase Wordlist

```bash
cewl -d $DEPTH -m $MIN_WORD_LENGTH --lowercase -w $WORDLIST_FILE $TARGET_URL

```

#### 3. Extract Email Addresses in Addition to Words

```bash
cewl -d $DEPTH -m $MIN_WORD_LENGTH -e -w $WORDLIST_FILE $TARGET_URL

```

#### 4. Crawl with Basic Authentication

```bash
cewl -d $DEPTH -m $MIN_WORD_LENGTH --auth_type $AUTH_TYPE --auth_user $AUTH_USER --auth_pass $AUTH_PASS -w $WORDLIST_FILE $TARGET_URL

```

#### 5. Use Proxy Server While Crawling

```bash
cewl --proxy_host $(echo $PROXY | cut -d':' -f2 | sed 's#//##') --proxy_port $(echo $PROXY | cut -d':' -f3) -w $WORDLIST_FILE $TARGET_URL

```

#### 6. Verbose Mode for Debugging

```bash
cewl -d $DEPTH -m $MIN_WORD_LENGTH -v -w $WORDLIST_FILE $TARGET_URL

```

***

### IV. Advanced Techniques & Scenarios

* **Deep Domain Crawling:** Increase depth cautiously to balance coverage and crawl duration.
* **Filtered Wordlists:** Post-process generated lists to remove common words or create specialized password lists.
* **Combine with FAB Tool:** Extract metadata-based usernames from documents to complement CeWL wordlists.
* **Target-Specific Wordlists:** Crawl multiple related sites or subdomains and merge wordlists for unique coverage.
* **Email Harvesting for Social Engineering:** Use harvested emails as username seeds for password guessing.
* **Integration with Password Cracking:** Use CeWL wordlists directly with Hashcat, John the Ripper, or Hydra.
* **Automate in Recon Pipelines:** Script CeWL runs as part of bug bounty or pentesting automated workflows.
* **Use Proxies & Authentication:** For stealthy crawling behind restricted access or anti-scraping mechanisms.

***

### V. Real-World Workflow Example

1. **Export Variables**

```bash
export TARGET_URL="<https://portal.htb>"
export DEPTH=3
export MIN_WORD_LENGTH=6
export WORDLIST_FILE="wordlists/portal_words.txt"

```

1. **Generate Wordlist with Emails**

```bash
cewl -d $DEPTH -m $MIN_WORD_LENGTH -e -w $WORDLIST_FILE $TARGET_URL

```

1. **Use Wordlist in Password Cracking**

```bash
hashcat -a 0 -m 0 hashes.txt $WORDLIST_FILE

```

1. **Combine with Metadata Usernames for Brute Force**

***

### VI. Pro Tips & Best Practices

* Always tailor wordlist depth and filters to scope and time constraints.
* Combine CeWL outputs with other sources (meta-data, breach dumps) for richer user/pass lists.
* Use authentication options when crawling protected sites to access deeper content.
* Validate and clean large generated lists before usage.
* Combine with contextual recon tools for maximum attack surface coverage.
* Update CeWL periodically to benefit from bug fixes and new features.
* Avoid crawling production sites aggressively to prevent detection or disruption.

***

This professional CeWL guide empowers security professionals to generate high-quality, targeted wordlists that improve password cracking success and user enumeration during security assessments and bug bounty hunts.

Sources \[1] cewl | Kali Linux Tools [https://www.kali.org/tools/cewl/](https://www.kali.org/tools/cewl/) \[2] Create Custom Password List with Cewl [https://www.youtube.com/watch?v=dPx7-TC-cTI](https://www.youtube.com/watch?v=dPx7-TC-cTI) \[3] CeWLeR - Custom Word List generator Redefined. CeWL ... [https://github.com/roys/cewler](https://github.com/roys/cewler) \[4] Cewl Tools – Secuneus Tech | Learn Cyber Security [https://www.secuneus.com/cewl-tools/](https://www.secuneus.com/cewl-tools/) \[5] CeWL Cheat Sheet: A Comprehensive Guide [https://denizhalil.com/2025/01/27/cewl-cheat-sheet/](https://denizhalil.com/2025/01/27/cewl-cheat-sheet/) \[6] aw-junaid/Kali-Linux [https://github.com/aw-junaid/Kali-Linux](https://github.com/aw-junaid/Kali-Linux) \[7] Tool for Automated Testing of Web Servers [https://excel.fit.vutbr.cz/submissions/2023/034/34.pdf](https://excel.fit.vutbr.cz/submissions/2023/034/34.pdf) \[8] Making a Better Wordlist [https://www.triaxiomsecurity.com/making-a-better-wordlist/](https://www.triaxiomsecurity.com/making-a-better-wordlist/)
