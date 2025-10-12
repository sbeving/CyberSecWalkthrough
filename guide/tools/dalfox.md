---
icon: firefox
---

# Dalfox

## The Dalfox Masterclass: Professional XSS Scanning & Automation Guide

Dalfox is an advanced open-source XSS scanner and parameter analyzer built for speed, automation, and depth. It’s trusted by bug bounty hunters and penetration testers for its intelligent payload generation, mining, context awareness, and support for blind, stored, and reflected XSS scenarios.

***

### I. Environment Setup: Dynamic Variables

Organize sessions and automation with environment variables:

```bash
export TARGET_URL="<https://target.com/search?q=test>"
export INPUT_FILE="urls.txt"
export BLIND_XSS_CALLBACK="<https://yourxss.htb>"
export PROXY="<http://127.0.0.1:8080>"
export COOKIE="SESSIONID=abcd1234"
export HEADERS="Authorization: Bearer xyz"
export THREADS=30
export OUTPUT_FILE="dalfox-results/scan.json"

```

***

### II. Core Capabilities & Workflow

* **Parameter Analysis:** Automatically finds and analyzes URL/query parameters and forms for possible injection points.
* **Reflected, Stored, and Blind XSS:** Includes dedicated modes for reflected, stored (SXSS), and blind XSS (with custom callback endpoints).
* **Mining & Optimization:** Mines for parameters, optimizes payloads per context, and detects "evil" characters/contexts for higher accuracy and lower noise.
* **Multiple Input Modes:** Supports single URLs, input files, or stdin pipeline (for automation with tools like gau, waybackurls, etc.).
* **Context/DOM Analysis:** DOM and static analysis to find client-side sinks and XSS gadgets.
* **Rich Output:** JSON and text reporting for CI/CD, automation, and human review.
* **HTTP Options:** Custom headers, cookies, proxy support, user-agent randomization, rate limiting, and delays for fine control.
* **REST API:** Run as a server for integration/automation.

***

### III. Professional Usage Examples

#### 1. Scan a Single URL for XSS

```bash
dalfox url "$TARGET_URL"

```

#### 2. Blind XSS Test with Callback

```bash
dalfox url "$TARGET_URL" -b "$BLIND_XSS_CALLBACK"

```

#### 3. Scan Multiple URLs from File

```bash
dalfox file "$INPUT_FILE"

```

#### 4. Pipeline Mode (Input from Stdin / Recon Tools)

```bash
cat urls.txt | dalfox pipe

```

#### 5. Stored XSS (SXSS) Testing

```bash
dalfox sxss "$INPUT_FILE"

```

#### 6. Set Custom Cookie, Headers, or Proxy

```bash
dalfox url "$TARGET_URL" --cookie "$COOKIE" --header "$HEADERS" --proxy "$PROXY"

```

#### 7. Set Threads and Timeout

```bash
dalfox url "$TARGET_URL" --threads $THREADS --timeout 10

```

#### 8. Output Results as JSON

```bash
dalfox url "$TARGET_URL" --format json --output "$OUTPUT_FILE"

```

#### 9. Run as an API Server for Automation

```bash
dalfox server --host 0.0.0.0 --port 8080

```

***

### IV. Advanced Techniques & Scenarios

* **Parameter Mining:** Dalfox automatically finds hidden/new parameters via open APIs, common wordlists, heuristics, and parameter mining.
* **Aggressive DOM Mining:** Enable deeper DOM/JavaScript analysis with flags like `-mining-dom --deep-domxss` for modern, AJAX-heavy apps.
* **Filter/Tag Results:** Integrate with symbols, tags, or custom output flags to automate workflow prioritization and integration with dashboards.
* **Custom Payloads and Templates:** Extend Dalfox with custom payloads for context-specific bypasses or advanced WAF evasion.
* **Combine with Recon Tools:** Pipe results from assetfinder, gau, waybackurls, or ffuf directly into Dalfox for mass coverage.
* **RESTful Integration:** Use server mode to automate scans across organizations in CI/CD or bug bounty pipelines.
* **Manual Verification:** Always validate high/critical findings in-browser, especially stored XSS or complex chained scenarios.

***

### V. Real-World Workflow Example

1. **Set Up Automation Variables**

```bash
export TARGET_URL="<https://app.htb/page?search=test>"
export INPUT_FILE="live_endpoints.txt"
export BLIND_XSS_CALLBACK="<https://teamxss.xss.ht>"
export OUTPUT_FILE="dalfox_scans/full_scan.json"

```

1. **Comprehensive Scan of Multiple Endpoints**

```bash
dalfox file "$INPUT_FILE" --blind "$BLIND_XSS_CALLBACK" --threads 40 --format json --output "$OUTPUT_FILE"

```

1. **Pipeline Recon for Real-Time Discovery**

```bash
cat recon_urls.txt | dalfox pipe --proxy <http://127.0.0.1:8080>

```

1. **Analyze and Report**

* Review `full_scan.json` for critical, high, and informational findings.
* Manually test promising XSS vectors in a browser with security tools enabled.

***

### VI. Pro Tips & Best Practices

* Leverage Dalfox’s pipe mode for seamless integration with other recon and endpoint discovery tools.
* Always use Blind XSS testing (`b`) with a custom callback (e.g., XSS Hunter) for deeper, real-world bug bounty workflows.
* Use mining and deep DOM flags for single-page or heavily scripted apps.
* Incorporate Dalfox’s JSON output in automated vulnerability management dashboards or CI/CD pipelines.
* Regularly update Dalfox for new bypasses, context heuristics, and community improvements.
* Validate critical findings in different browsers and devices.
* Respect target scope and rules of engagement at all times.

***

This comprehensive Dalfox guide enables thorough, automated, and advanced XSS vulnerability detection and workflow integration—accelerating both bug bounty and professional penetration testing success.# The Dalfox Masterclass: Professional XSS Scanning & Automation Guide

Dalfox is an advanced open-source XSS scanner and parameter analyzer built for speed, automation, and depth. It is trusted by bug bounty hunters and penetration testers for intelligent payload generation, mining, context awareness, and support for blind, stored, and reflected XSS detection.

***

### Environment Setup

Organize scans using environment variables for consistency:

```bash
export TARGET_URL="<https://target.com/search?q=test>"
export INPUT_FILE="urls.txt"
export BLIND_XSS_CALLBACK="<https://yourxss.htb>"
export PROXY="<http://127.0.0.1:8080>"
export COOKIE="SESSIONID=abcd1234"
export HEADERS="Authorization: Bearer xyz"
export THREADS=30
export OUTPUT_FILE="dalfox-results/scan.json"

```

***

### Core Capabilities & Workflow

* Parameter Analysis for injection points
* Reflected, stored (SXSS), and blind XSS detection with custom callbacks
* Mining & payload optimization per context, detecting tricky characters/contexts
* Supports single URL, file input, and stdin pipeline modes
* DOM and static analysis for client-side sinks and XSS gadgets
* JSON and text reporting for automation
* HTTP options for headers, cookies, user-agent rotation, proxies, throttling
* REST API server mode for integration and automation

***

### Professional Usage Examples

* Scan a single URL: `dalfox url "$TARGET_URL"`
* Blind XSS with callback: `dalfox url "$TARGET_URL" -b "$BLIND_XSS_CALLBACK"`
* Scan multiple URLs from file: `dalfox file "$INPUT_FILE"`
* Pipe URLs into dalfox: `cat urls.txt | dalfox pipe`
* Stored XSS scanning: `dalfox sxss "$INPUT_FILE"`
* Set cookies, headers, proxy: `dalfox url "$TARGET_URL" --cookie "$COOKIE" --header "$HEADERS" --proxy "$PROXY"`
* Set threads and timeout: `dalfox url "$TARGET_URL" --threads $THREADS --timeout 10`
* Output JSON: `dalfox url "$TARGET_URL" --format json --output "$OUTPUT_FILE"`
* Run REST API server: `dalfox server --host 0.0.0.0 --port 8080`

***

### Advanced Techniques & Workflow Integration

* Automatic parameter mining and analysis
* Aggressive DOM mining for AJAX-heavy apps
* Result filtering and tagging for prioritization
* Custom payloads for WAF evasion
* Integrate with recon tools like assetfinder, gau, waybackurls
* REST API automation and continuous scanning
* Manual validation recommended especially for stored and complex XSS

***

### Real-World Workflow Sample

* Export variables for endpoints and callbacks
* Comprehensive file-based scanning with blind XSS callbacks enabled
* Use pipeline mode for continuous discovery
* Aggregate and review results, perform manual exploitation

***

### Pro Tips

* Use pipe mode to integrate with recon pipelines
* Test blind XSS with dedicated callback services
* Enable mining and deep DOM flags for modern sites
* Use JSON outputs for reporting and automation
* Regularly update Dalfox to capture new bug types
* Validate findings manually before reporting

***

This guide empowers efficient and in-depth XSS discovery, perfect for bug bounty hunters and pentesters aiming for rapid, high-quality recon and exploitation workflows.

Sources
