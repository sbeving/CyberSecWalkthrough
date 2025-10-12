---
icon: hackerrank
---

# HackyCV

## The HackyCV Masterclass: Professional Vulnerability Scanning & Exploitation

HackyCV is a modern, modular vulnerability scanner and exploitation framework designed for professional penetration testers, bug bounty hunters, and red teamers. It automates the detection of common web vulnerabilities, supports custom payloads, and integrates with other tools for advanced exploitation and reporting.

***

### I. Environment Setup: Dynamic Variables

Export variables for flexible, repeatable workflows and organized output:

```bash
export URL="<http://target.com/login>"
export OUTPUT_DIR="hackycv-results"
export COOKIE="SESSION=abcd1234; other=xyz"
export USER_AGENT="Mozilla/5.0 (HackyCV)"
export PROXY="<http://127.0.0.1:8080>"
export THREADS=20
export PAYLOAD_FILE="/path/to/custom_payloads.txt"
export MODULE="xss"         # Supported modules: xss, sqli, lfi, rce, etc.
export PARAM="username"    # Parameter to fuzz

```

***

### II. Core Capabilities & Workflow

* **Automated Vulnerability Scanning:** Detects XSS, SQLi, LFI, RCE, SSRF, and other web vulnerabilities using both generic and context-aware payloads.
* **Modular Exploitation:** Supports modules for different vulnerability classes, each with tailored payloads and detection logic.
* **Custom Payloads:** Allows use of custom payload lists for bypassing filters and targeting specific contexts.
* **Multi-threaded Fuzzing:** Scans multiple parameters and endpoints in parallel for speed and coverage.
* **Proxy & Header Support:** Integrates with proxies (e.g., Burp Suite) and supports custom headers, cookies, and user-agent strings.
* **Output Management:** Saves results in organized formats for reporting and further analysis.
* **Integration:** Can be used in conjunction with other tools for chained exploitation and workflow automation.

***

### III. Professional Usage Examples

#### 1. Basic Vulnerability Scan (XSS Example)

```bash
python3 hackycv.py -u "$URL" -m "$MODULE" -p "$PARAM"

```

#### 2. Scan with Custom Headers, Cookies, and User-Agent

```bash
python3 hackycv.py -u "$URL" -m "$MODULE" -p "$PARAM" --cookie "$COOKIE" --user-agent "$USER_AGENT"

```

#### 3. Use Proxy (e.g., Burp Suite)

```bash
python3 hackycv.py -u "$URL" -m "$MODULE" -p "$PARAM" --proxy "$PROXY"

```

#### 4. Multi-threaded Fuzzing

```bash
python3 hackycv.py -u "$URL" -m "$MODULE" -p "$PARAM" --threads $THREADS

```

#### 5. Custom Payloads (Bypass Filters)

```bash
python3 hackycv.py -u "$URL" -m "$MODULE" -p "$PARAM" --payload "$PAYLOAD_FILE"

```

#### 6. Scan Multiple Parameters

```bash
python3 hackycv.py -u "$URL" -m "$MODULE" -p "username,password,email"

```

#### 7. Save Output to File

```bash
python3 hackycv.py -u "$URL" -m "$MODULE" -p "$PARAM" --output "$OUTPUT_DIR/scan.txt"

```

***

### IV. Advanced Techniques & Scenarios

* **Contextual Payloads:** HackyCV analyzes parameter context (e.g., inside HTML, JavaScript, attributes) to select optimal payloads.
* **Blind Vulnerability Detection:** Supports time-based, out-of-band, and error-based techniques for blind SQLi, XSS, and SSRF.
* **Chained Exploitation:** Use HackyCV results as input for other tools (e.g., SQLMap, XSStrike) for deeper exploitation.
* **Batch Scanning:** Script HackyCV to iterate over multiple endpoints or parameter sets for large-scale assessments.
* **Custom Reporting:** Export results in formats suitable for compliance, bug bounty, or client reporting.

***

### V. Real-World Workflow Example

1.  **Export Variables:**

    ```bash
    export URL="<http://app.htb/login>"
    export MODULE="sqli"
    export PARAM="username"
    export OUTPUT_DIR="hackycv_htb"

    ```
2.  **Run SQL Injection Scan:**

    ```bash
    python3 hackycv.py -u "$URL" -m "$MODULE" -p "$PARAM" --output "$OUTPUT_DIR/sqli.txt"

    ```
3.  **Scan for XSS with Custom Payloads:**

    ```bash
    python3 hackycv.py -u "$URL" -m xss -p "search" --payload "/path/to/xss_payloads.txt" --output "$OUTPUT_DIR/xss.txt"

    ```
4.  **Fuzz Multiple Parameters in Parallel:**

    ```bash
    python3 hackycv.py -u "$URL" -m lfi -p "file,template" --threads 20 --output "$OUTPUT_DIR/lfi.txt"

    ```
5.  **Integrate with Burp Suite Proxy:**

    ```bash
    python3 hackycv.py -u "$URL" -m rce -p "cmd" --proxy "$PROXY" --output "$OUTPUT_DIR/rce.txt"

    ```
6. **Document Findings:**
   * Save all output and exploitation steps for reporting and future reference.

***

### VI. Pro Tips & Best Practices

* **Always start with context-aware payloads** for higher reliability and fewer false positives.
* **Use custom payloads** to bypass advanced filters and WAFs.
* **Integrate with proxies** for manual validation and traffic inspection.
* **Document all findings and save outputs** for reporting and compliance.
* **Scan only with explicit authorization**—never test targets without permission.
* **Combine HackyCV with manual testing and other tools** for comprehensive vulnerability coverage.

***

This professional HackyCV guide equips you for advanced, modular vulnerability detection, exploitation, and reporting in real-world web application security assessments.
