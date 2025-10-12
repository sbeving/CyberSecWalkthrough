---
icon: rocket-launch
---

# GoBuster

## The Gobuster Masterclass: Professional Directory, DNS & VHost EnumerationThe Gobuster Masterclass: Professional Directory, DNS & VHost Enumeration

Gobuster is a high-performance brute-forcing tool written in Go, designed for discovering hidden directories, files, DNS subdomains, virtual hosts, and cloud storage buckets. This comprehensive guide covers environment setup, all operational modes, advanced filtering, and professional techniques for penetration testing and security assessments.Gobuster is a high-performance brute-forcing tool written in Go, designed for discovering hidden directories, files, DNS subdomains, virtual hosts, and cloud storage buckets. This comprehensive guide covers environment setup, all operational modes, advanced filtering, and professional techniques for penetration testing and security assessments.

***

### I. Export Environment Variables SetupI. Export Environment Variables Setup

Define your dynamic enumeration environment:Define your dynamic enumeration environment:

```bash
export URL="<https://example.com>"
export DOMAIN="[example.com](<http://example.com>)"
export WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
export DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
export PARAM_WORDLIST="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
export OUTPUT_DIR="gobuster-results"
export THREADS=50
export USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
export COOKIE="PHPSESSID=abcd1234; token=xyz"
export PROXY="127.0.0.1:8080"
export EXTENSIONS="php,html,txt,bak,zip"
export TIMEOUT=10
export DELAY="100ms"
export AUTH_USER="admin"
export AUTH_PASS="password"
export STATUS_CODES="200,204,301,302,307,401,403"
mkdir -p "$OUTPUT_DIR
```

***

### II. Directory & File Enumeration (DIR Mode)II. Directory & File Enumeration (DIR Mode)

Basic directory scan:Basic directory scan:

```bash
gobuster dir -u "$URL" -w "$WORDLIST" -t $THREADS -o "$OUTPUT_DIR/directories.txt"gobuster dir -u "$URL" -w "$WORDLIST" -t $THREADS -o "$OUTPUT_DIR/directories.txt"
```

Directory scan with file extensions:Directory scan with file extensions:

```bash
gobuster dir -u "$URL" -w "$WORDLIST" -x "$EXTENSIONS" -t $THREADS -o "$OUTPUT_DIR/files.txt"gobuster dir -u "$URL" -w "$WORDLIST" -x "$EXTENSIONS" -t $THREADS -o "$OUTPUT_DIR/files.txt"
```

Recursive directory discovery:Recursive directory discovery:

```bash
gobuster dir -u "$URL" -w "$WORDLIST" -r -t $THREADS -o "$OUTPUT_DIR/recursive.txt"gobuster dir -u "$URL" -w "$WORDLIST" -r -t $THREADS -o "$OUTPUT_DIR/recursive.txt"
```

Expanded mode (show full URLs):Expanded mode (show full URLs):

```bash
gobuster dir -u "$URL" -w "$WORDLIST" -e -t $THREADS -o "$OUTPUT_DIR/expanded.txt"gobuster dir -u "$URL" -w "$WORDLIST" -e -t $THREADS -o "$OUTPUT_DIR/expanded.txt"
```

Filter by status codes:Filter by status codes:

```bash
gobuster dir -u "$URL" -w "$WORDLIST" -s "$STATUS_CODES" -t $THREADS -o "$OUTPUT_DIR/filtered.txt"gobuster dir -u "$URL" -w "$WORDLIST" -s "$STATUS_CODES" -t $THREADS -o "$OUTPUT_DIR/filtered.txt"
```

Exclude status codes (e.g., 404):Exclude status codes (e.g., 404):

```bash
gobuster dir -u "$URL" -w "$WORDLIST" -b "404,403" -t $THREADS -o "$OUTPUT_DIR/excluded.txt"gobuster dir -u "$URL" -w "$WORDLIST" -b "404,403" -t $THREADS -o "$OUTPUT_DIR/excluded.txt"
```

***

### III. DNS Subdomain Enumeration (DNS Mode)III. DNS Subdomain Enumeration (DNS Mode)

Basic subdomain discovery:Basic subdomain discovery:

```bash
gobuster dns -d "$DOMAIN" -w "$DNS_WORDLIST" -t $THREADS -o "$OUTPUT_DIR/subdomains.txt"gobuster dns -d "$DOMAIN" -w "$DNS_WORDLIST" -t $THREADS -o "$OUTPUT_DIR/subdomains.txt"
```

DNS with custom resolvers:DNS with custom resolvers:

```bash
gobuster dns -d "$DOMAIN" -w "$DNS_WORDLIST" -r "8.8.8.8,1.1.1.1" -t $THREADS -o "$OUTPUT_DIR/dns-resolved.txt"gobuster dns -d "$DOMAIN" -w "$DNS_WORDLIST" -r "8.8.8.8,1.1.1.1" -t $THREADS -o "$OUTPUT_DIR/dns-resolved.txt"
```

Show CNAME records:Show CNAME records:

```bash
gobuster dns -d "$DOMAIN" -w "$DNS_WORDLIST" -c -t $THREADS -o "$OUTPUT_DIR/dns-cname.txt"gobuster dns -d "$DOMAIN" -w "$DNS_WORDLIST" -c -t $THREADS -o "$OUTPUT_DIR/dns-cname.txt"
```

Show IP addresses:Show IP addresses:

```bash
gobuster dns -d "$DOMAIN" -w "$DNS_WORDLIST" -i -t $THREADS -o "$OUTPUT_DIR/dns-ips.txt"gobuster dns -d "$DOMAIN" -w "$DNS_WORDLIST" -i -t $THREADS -o "$OUTPUT_DIR/dns-ips.txt"
```

Wildcard detection:Wildcard detection:

```bash
gobuster dns -d "$DOMAIN" -w "$DNS_WORDLIST" --wildcard -t $THREADS -o "$OUTPUT_DIR/dns-wildcard.txt"gobuster dns -d "$DOMAIN" -w "$DNS_WORDLIST" --wildcard -t $THREADS -o "$OUTPUT_DIR/dns-wildcard.txt"
```

***

### IV. Virtual Host Discovery (VHOST Mode)IV. Virtual Host Discovery (VHOST Mode)

Basic VHOST enumeration:Basic VHOST enumeration:

```bash
gobuster vhost -u "$URL" -w "$WORDLIST" -t $THREADS -o "$OUTPUT_DIR/vhosts.txt"gobuster vhost -u "$URL" -w "$WORDLIST" -t $THREADS -o "$OUTPUT_DIR/vhosts.txt"
```

VHOST with custom domain append:VHOST with custom domain append:

```bash
gobuster vhost -u "$URL" -w "$WORDLIST" --domain "$DOMAIN" -t $THREADS -o "$OUTPUT_DIR/vhosts-domain.txt"gobuster vhost -u "$URL" -w "$WORDLIST" --domain "$DOMAIN" -t $THREADS -o "$OUTPUT_DIR/vhosts-domain.txt"
```

Append base domain to wordlist entries:Append base domain to wordlist entries:

```bash
gobuster vhost -u "$URL" -w "$WORDLIST" --append-domain -t $THREADS -o "$OUTPUT_DIR/vhosts-appended.txt"gobuster vhost -u "$URL" -w "$WORDLIST" --append-domain -t $THREADS -o "$OUTPUT_DIR/vhosts-appended.txt"
```

***

### V. Fuzzing Mode (FUZZ Mode)V. Fuzzing Mode (FUZZ Mode)

URL parameter fuzzing:URL parameter fuzzing:

```bash
gobuster fuzz -u "$URL/index.php?param=FUZZ" -w "$PARAM_WORDLIST" -t $THREADS -o "$OUTPUT_DIR/fuzz-params.txt"gobuster fuzz -u "$URL/index.php?param=FUZZ" -w "$PARAM_WORDLIST" -t $THREADS -o "$OUTPUT_DIR/fuzz-params.txt"
```

Multiple FUZZ positions:Multiple FUZZ positions:

```bash
gobuster fuzz -u "$URL/FUZZ1/page.php?id=FUZZ2" -w "$WORDLIST:FUZZ1" -w "$PARAM_WORDLIST:FUZZ2" -t $THREADS -o "$OUTPUT_DIR/multi-fuzz.txt"gobuster fuzz -u "$URL/FUZZ1/page.php?id=FUZZ2" -w "$WORDLIST:FUZZ1" -w "$PARAM_WORDLIST:FUZZ2" -t $THREADS -o "$OUTPUT_DIR/multi-fuzz.txt"
```

Exclude response lengths:Exclude response lengths:

```bash
gobuster fuzz -u "$URL/page.php?param=FUZZ" -w "$PARAM_WORDLIST" --exclude-length "1234,5678" -t $THREADS -o "$OUTPUT_DIR/fuzz-filtered.txt"gobuster fuzz -u "$URL/page.php?param=FUZZ" -w "$PARAM_WORDLIST" --exclude-length "1234,5678" -t $THREADS -o "$OUTPUT_DIR/fuzz-filtered.txt"
```

***

### VI. Authentication & HeadersVI. Authentication & Headers

Basic authentication:Basic authentication:

```bash
gobuster dir -u "$URL" -w "$WORDLIST" -U "$AUTH_USER" -P "$AUTH_PASS" -t $THREADS -o "$OUTPUT_DIR/auth-dir.txt"gobuster dir -u "$URL" -w "$WORDLIST" -U "$AUTH_USER" -P "$AUTH_PASS" -t $THREADS -o "$OUTPUT_DIR/auth-dir.txt"
```

Custom headers:Custom headers:

```bash
gobuster dir -u "$URL" -w "$WORDLIST" -H "Authorization: Bearer token123" -H "X-Custom-Header: value" -t $THREADS -o "$OUTPUT_DIR/headers-dir.txt"gobuster dir -u "$URL" -w "$WORDLIST" -H "Authorization: Bearer token123" -H "X-Custom-Header: value" -t $THREADS -o "$OUTPUT_DIR/headers-dir.txt"
```

Custom user-agent:Custom user-agent:

```bash
gobuster dir -u "$URL" -w "$WORDLIST" -a "$USER_AGENT" -t $THREADS -o "$OUTPUT_DIR/useragent-dir.txt"gobuster dir -u "$URL" -w "$WORDLIST" -a "$USER_AGENT" -t $THREADS -o "$OUTPUT_DIR/useragent-dir.txt"
```

Cookie-based authentication:Cookie-based authentication:

```bash
gobuster dir -u "$URL" -w "$WORDLIST" -c "$COOKIE" -t $THREADS -o "$OUTPUT_DIR/cookie-dir.txt"gobuster dir -u "$URL" -w "$WORDLIST" -c "$COOKIE" -t $THREADS -o "$OUTPUT_DIR/cookie-dir.txt"
```

***

### VII. Rate Limiting & Timing ControlVII. Rate Limiting & Timing Control

Add delay between requests:Add delay between requests:

```bash
gobuster dir -u "$URL" -w "$WORDLIST" --delay "$DELAY" -t $THREADS -o "$OUTPUT_DIR/delayed-dir.txt"gobuster dir -u "$URL" -w "$WORDLIST" --delay "$DELAY" -t $THREADS -o "$OUTPUT_DIR/delayed-dir.txt"
```

Set request timeout (seconds):Set request timeout (seconds):

```bash
gobuster dir -u "$URL" -w "$WORDLIST" --timeout "$TIMEOUT"s -t $THREADS -o "$OUTPUT_DIR/timeout-dir.txt"gobuster dir -u "$URL" -w "$WORDLIST" --timeout "$TIMEOUT"s -t $THREADS -o "$OUTPUT_DIR/timeout-dir.txt"
```

Adjust thread count:Adjust thread count:

```bash
gobuster dir -u "$URL" -w "$WORDLIST" -t $THREADS -o "$OUTPUT_DIR/threaded-dir.txt"gobuster dir -u "$URL" -w "$WORDLIST" -t $THREADS -o "$OUTPUT_DIR/threaded-dir.txt"
```

***

### VIII. Advanced Filtering & Output ControlVIII. Advanced Filtering & Output Control

Quiet mode (no banner):Quiet mode (no banner):

```bash
gobuster dir -u "$URL" -w "$WORDLIST" -q -t $THREADS -o "$OUTPUT_DIR/quiet-dir.txt"gobuster dir -u "$URL" -w "$WORDLIST" -q -t $THREADS -o "$OUTPUT_DIR/quiet-dir.txt"
```

Verbose output:Verbose output:

```bash
gobuster dir -u "$URL" -w "$WORDLIST" -v -t $THREADS -o "$OUTPUT_DIR/verbose-dir.txt"gobuster dir -u "$URL" -w "$WORDLIST" -v -t $THREADS -o "$OUTPUT_DIR/verbose-dir.txt"
```

No progress display:No progress display:

```bash
gobuster dir -u "$URL" -w "$WORDLIST" -z -t $THREADS -o "$OUTPUT_DIR/noprogress-dir.txt"gobuster dir -u "$URL" -w "$WORDLIST" -z -t $THREADS -o "$OUTPUT_DIR/noprogress-dir.txt"
```

No errors display:No errors display:

```bash
gobuster dir -u "$URL" -w "$WORDLIST" --no-error -t $THREADS -o "$OUTPUT_DIR/noerror-dir.txt"gobuster dir -u "$URL" -w "$WORDLIST" --no-error -t $THREADS -o "$OUTPUT_DIR/noerror-dir.txt"
```

***

### IX. Pattern Matching & ReplacementIX. Pattern Matching & Replacement

Use pattern file for dynamic payloads:Use pattern file for dynamic payloads:

```bash
echo "{subdomain}.[target.com](<http://target.com>)" > pattern.txt
gobuster dns -d "$DOMAIN" -w "$DNS_WORDLIST" -p pattern.txt -t $THREADS -o "$OUTPUT_DIR/pattern-dns.txt"echo "{subdomain}.[target.com](<http://target.com>)" > pattern.txt
gobuster dns -d "$DOMAIN" -w "$DNS_WORDLIST" -p pattern.txt -t $THREADS -o "$OUTPUT_DIR/pattern-dns.txt"
```

***

### X. Proxy & Traffic InspectionX. Proxy & Traffic Inspection

Route through proxy (Burp Suite):Route through proxy (Burp Suite):

```bash
gobuster dir -u "$URL" -w "$WORDLIST" -p "$PROXY" -t $THREADS -o "$OUTPUT_DIR/proxy-dir.txt"gobuster dir -u "$URL" -w "$WORDLIST" -p "$PROXY" -t $THREADS -o "$OUTPUT_DIR/proxy-dir.txt"
```

Disable certificate validation (self-signed):Disable certificate validation (self-signed):

```bash
gobuster dir -u "$URL" -w "$WORDLIST" -k -t $THREADS -o "$OUTPUT_DIR/insecure-dir.txt"gobuster dir -u "$URL" -w "$WORDLIST" -k -t $THREADS -o "$OUTPUT_DIR/insecure-dir.txt"
```

***

### XI. Real-World Workflow ExamplesXI. Real-World Workflow Examples

Example 1: Comprehensive web application enumerationExample 1: Comprehensive web application enumeration

```bash
export URL="<http://10.10.10.50>"
export WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
export OUTPUT_DIR="gobuster_scans"
export THREADS=50
export EXTENSIONS="php,html,export URL="<http://10.10.10.50>"
export WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
export OUTPUT_DIR="gobuster_scans"
export THREADS=50
export EXTENSIONS="php,html,txt,bak"
mkdir -p "$OUTPUT_DIR"

gobuster dir -u "$URL" -w "$WORDLIST" -t $THREADS -o "$OUTPUT_DIR/initial-dir.txt" -e

gobuster dir -u "$URL" -w "$WORDLIST" -x "$EXTENSIONS" -t $THREADS -o "$OUTPUT_DIR/files.txt" -e

gobuster dir -u "$URL/admin" -w "$WORDLIST" -r -t $THREADS -o "$OUTPUT_DIR/admin-recursive.txt"
```

Here's a comprehensive, professional-grade Gobuster guide covering all modes, advanced techniques, and best practices:Here's a comprehensive, professional-grade Gobuster guide covering all modes, advanced techniques, and best practices:

***

## The Gobuster Masterclass: Professional Directory, DNS & VHost EnumerationThe Gobuster Masterclass: Professional Directory, DNS & VHost Enumeration

Gobuster is a high-performance brute-forcing tool written in Go, designed for discovering hidden directories, files, DNS subdomains, virtual hosts, and cloud storage buckets. This comprehensive guide covers environment setup, all operational modes, advanced filtering, and professional techniques for penetration testing and security assessments.[github+2](https://github.com/OJ/gobuster)Gobuster is a high-performance brute-forcing tool written in Go, designed for discovering hidden directories, files, DNS subdomains, virtual hosts, and cloud storage buckets. This comprehensive guide covers environment setup, all operational modes, advanced filtering, and professional techniques for penetration testing and security assessments.[github+2](https://github.com/OJ/gobuster)

***

### I. Export Environment Variables SetupI. Export Environment Variables Setup

Define your dynamic enumeration environment:Define your dynamic enumeration environment:

```bash
export URL="<http://target.com>"
export DOMAIN="[target.com](<http://target.com>)"
export WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
export DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
export PARAM_WORDLIST="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
export OUTPUT_DIR="gobuster-results"
export THREADS=50
export USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
export COOKIE="PHPSESSID=abcd1234; token=xyz"
export PROXY="<http://127.0.0.1:8080>"
export EXTENSIONS="php,html,txt,bak,zip"
export TIMEOUT=10
export DELAY="100ms"
export AUTH_USER="admin"
export AUTH_PASS="password"
export STATUS_CODES="200,204,301,302,307,401,403"
mkdir -p "$OUTPUT_DIR"export URL="<http://target.com>"
export DOMAIN="[target.com](<http://target.com>)"
export WORDLIST="/
```

Example 2: DNS subdomain discovery

```bash
export DOMAIN="[example.com](<http://example.com>)"
export DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
export OUTPUT_DIR="gobuster_dns"
export THREADS=100
mkdir -p "$OUTPUT_DIR"

gobuster dns -d "$DOMAIN" -w "$DNS_WORDLIST" -t $THREADS -o "$OUTPUT_DIR/subdomains.txt" -i

gobuster dns -d "$DOMAIN" -w "$DNS_WORDLIST" -c -t $THREADS -o "$OUTPUT_DIR/subdomains-cname.txt"
```

Example 3: Virtual host discovery

```bash
export URL="<http://10.10.10.50>"
export WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
export DOMAIN="[example.com](<http://example.com>)"
export OUTPUT_DIR="gobuster_vhost"
export THREADS=50
mkdir -p "$OUTPUT_DIR"

gobuster vhost -u "$URL" -w "$WORDLIST" --append-domain --domain "$DOMAIN" -t $THREADS -o "$OUTPUT_DIR/vhosts.txt"
```

Example 4: Parameter fuzzing

```bash
export URL="<http://10.10.10.50>"
export PARAM_WORDLIST="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
export OUTPUT_DIR="gobuster_fuzz"
export THREADS=50
mkdir -p "$OUTPUT_DIR"

gobuster fuzz -u "$URL?action=FUZZ" -w "$PARAM_WORDLIST" -t $THREADS -o "$OUTPUT_DIR/params.txt"
```

***

### XII. Pro Tips & Best Practices

* Start with smaller wordlists before larger ones to save time.
* Mind your threads. Excessive threads can overwhelm targets and trigger IDS/IPS.
* Use delays to slow requests and avoid detection when needed.
* Use DNS mode first, then DIR mode on discovered subdomains.
* Filter intelligently with status codes and length exclusions.
* Choose wordlists based on target context. SecLists is a strong default.
* Save results to files for documentation and reporting.
* Use recursion selectively to avoid huge scan volumes.
* Route through Burp to manually inspect interesting findings.
* Respect rate limits and always get authorization.

***

### XIII. Troubleshooting Common Issues

* Wildcard DNS: use `--wildcard` in DNS mode.
* Certificate errors: use `-k` to skip SSL/TLS verification.
* Timeouts: increase `--timeout` for slow targets.
* False positives: tune status codes and use `--exclude-length`.
* Too many results: narrow wordlists or stricter filters.
