---
icon: wordpress
---

# WPscan

## The WPScan Masterclass: Professional WordPress Vulnerability Scanner Guide

WPScan is a specialized command-line WordPress security scanner used by penetration testers, bug bounty hunters, and WordPress administrators to discover vulnerabilities in WordPress core, plugins, themes, and user enumeration. It leverages a comprehensive, regularly updated vulnerability database.

***

### I. Environment Setup: Dynamic Variables

Define your environment variables for structured and repeatable scans:

```bash
export TARGET_URL="<https://targetwordpresssite.com>"
export API_TOKEN="YOUR_WPSCAN_API_TOKEN"
export OUTPUT_DIR="wpscan-results"
export LOG_FILE="$OUTPUT_DIR/scan.log"
export WORDLIST="/usr/share/wordlists/rockyou.txt"
export USERNAME="admin"
export PASSWORD_WORDLIST="/usr/share/wordlists/wordpress_passwords.txt"
```

***

### II. Core Capabilities & Workflow

* **WordPress Core Detection:** Identifies WordPress version and checks for known vulnerabilities.
* **Plugin & Theme Enumeration:** Enumerates installed plugins/themes; checks their versions against the vulnerability database.
* **Vulnerability Detection:** Matches vulnerabilities from WPScan’s reliable, community-updated database.
* **User Enumeration & Brute-Force:** Enumeration of usernames and weak password detection.
* **File & Directory Discovery:** Detects sensitive files like wp-config.php backups, database exports, logs, and XML-RPC access.
* **Authentication & Rate Limit Handling:** Supports API token for vulnerability data and rate-limiting options for stealth.
* **Output Reporting:** Detailed terminal output with findings and recommendations; JSON export for automation.

***

### III. Professional Usage Examples

### 1. Basic Scan for WordPress Version and Config

```bash
wpscan --url $TARGET_URL
```

### 2. Enumerate Plugins and Detect Vulnerabilities

```bash
wpscan --url $TARGET_URL --enumerate p --api-token $API_TOKEN
```

### 3. Enumerate Themes Vulnerable Versions

```bash
wpscan --url $TARGET_URL --enumerate t --api-token $API_TOKEN
```

### 4. User Enumeration and Password Brute Forcing

```bash
wpscan --url $TARGET_URL --enumerate u --passwords $PASSWORD_WORDLIST
```

### 5. Detect Exposed Sensitive Files and Directories

```bash
wpscan --url $TARGET_URL --enumerate ap
```

### 6. Use Random User Agent to Bypass Simple Firewalls

```bash
wpscan --url $TARGET_URL --random-user-agent
```

### 7. Throttle Requests to Prevent Rate Limiting or Detection

```bash
wpscan --url $TARGET_URL --throttle 1500
```

### 8. Save Output to JSON File

```bash
wpscan --url $TARGET_URL -o $OUTPUT_DIR/scan_results.json --format json
```

***

### IV. Advanced Techniques & Scenarios

* **Use API Token:** Register at WPScan website to get vulnerability database API token, unlocking up-to-date plugin/theme vulnerabilities.
* **Stealth Scanning:** Enable passive detection mode and throttling to evade detection by web application firewalls.
* **Password Lists:** Use targeted password lists for brute forcing users, customized to the client environment.
* **Integration with CI/CD:** Automate scans during deployment pipelines to discover vulnerabilities in development.
* **Combine with Manual Testing:** Use WPScan results to augment manual research with Burp Suite or other scanners.
* **Enumerate All Possible Assets:** Use full enumeration modes (`-enumerate ap,at,ua`) for comprehensive scans.
* **Detect Common Misconfigurations:** Reports on exposed debug logs, XML-RPC, file permissions, and public backups.

***

### V. Real-World Workflow Example

1. **Set Environment Variables**

```bash
export TARGET_URL="<https://example.com>"
export API_TOKEN="abcdef1234567890"
export OUTPUT_DIR="wpscan_results"
```

1. **Basic Scan and Plugin Enumeration**

```bash
wpscan --url $TARGET_URL -e p --api-token $API_TOKEN -o $OUTPUT_DIR/plugins.json --format json
```

1. **User Enumeration and Password Brute Force**

```bash
wpscan --url $TARGET_URL -e u --passwords /usr/share/wordlists/wordpress_passwords.txt -o $OUTPUT_DIR/user_bruteforce.txt
```

1. **Save Detailed Scan Report**

```bash
wpscan --url $TARGET_URL -o $OUTPUT_DIR/full_scan.txt
```

1. **Analyze and Report**

* Review vulnerable plugins/themes flagged.
* Check weak credentials detected.
* Plan manual verification and remediation.

***

### VI. Pro Tips & Best Practices

* **Keep WPScan’s vulnerability database up to date** via API token usage.
* **Run scans with throttling and random user agents** to avoid detection.
* **Utilize extensive enumeration options** to broaden visibility during recon.
* **Use fresh and specific password lists** for targeted brute forcing.
* **Combine automated output with manual testing** for confirmation and further discovery.
* **Respect legal boundaries and scope**—only scan authorized targets.
* **Review non-vulnerability findings** like exposed files or misconfigurations for additional vectors.

***

This professional WPScan guide prepares penetration testers and bug bounty hunters to efficiently identify WordPress vulnerabilities, exposed sensitive data, and weak credentials, greatly improving security assessment accuracy and scope.

1. [https://wpscan.com](https://wpscan.com)
2. [https://wpscan.com/wordpress-cli-scanner/](https://wpscan.com/wordpress-cli-scanner/)
3. [https://blog.sucuri.net/2023/12/wpscan-intro-how-to-scan-for-wordpress-vulnerabilities.html](https://blog.sucuri.net/2023/12/wpscan-intro-how-to-scan-for-wordpress-vulnerabilities.html)
4. [https://www.freecodecamp.org/news/how-to-use-wpscan-to-keep-your-wordpress-site-secure/](https://www.freecodecamp.org/news/how-to-use-wpscan-to-keep-your-wordpress-site-secure/)
5. [https://melapress.com/how-to-use-wpscan/](https://melapress.com/how-to-use-wpscan/)
6. [https://wordpress.com/plugins/wpscan](https://wordpress.com/plugins/wpscan)
7. [https://github.com/wpscanteam/wpscan](https://github.com/wpscanteam/wpscan)
8. [https://www.youtube.com/watch?v=mXhT6fZX8oc](https://www.youtube.com/watch?v=mXhT6fZX8oc)
9. [https://runcloud.io/blog/best-wordpress-vulnerability-scanner](https://runcloud.io/blog/best-wordpress-vulnerability-scanner)
