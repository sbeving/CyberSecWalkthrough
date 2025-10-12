---
icon: puzzle
---

# FFUF

## The FFUF Masterclass: Professional Web Fuzzing at Scale

FFUF (Fuzz Faster U Fool) is a high‑performance web fuzzer built in Go for discovering hidden directories, files, parameters, vhosts, and API endpoints. This guide fixes formatting so commands are clean and copy‑pasteable.[\[1\]](https://infosecwriteups.com/mastering-ffuf-basic-and-advanced-commands-60e53bdbffc7)

***

### I. Export environment variables

Define your dynamic fuzzing environment:

```bash
export URL="<http://target.com>"
export WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
export PARAM_WORDLIST="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
export OUTPUT_DIR="ffuf-results"
export THREADS=100
export USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
export COOKIE="PHPSESSID=abcd1234; token=xyz"
export PROXY="<http://127.0.0.1:8080>"
export POST_DATA='{"username":"admin","password":"FUZZ"}'
export EXTENSIONS="php,html,js,txt,bak"
export TIMEOUT=10
export RATE=0          # requests per second (0 = unlimited)
export DELAY=0         # delay between requests in seconds
export RECURSION_DEPTH=2
export VHOST_DOMAIN="[target.com](<http://target.com>)"
mkdir -p "$OUTPUT_DIR"
```

***

### II. Basic usage

Directory discovery:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -t "$THREADS" -o "$OUTPUT_DIR/directories.json" -of json -c -H "User-Agent: $USER_AGENT"
```

File discovery with extensions:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -e "$EXTENSIONS" -t "$THREADS" -o "$OUTPUT_DIR/files.json" -of json -c -H "User-Agent: $USER_AGENT"
```

GET parameter fuzzing:

```bash
ffuf -w "$PARAM_WORDLIST" -u "$URL/page.php?FUZZ=test" -t "$THREADS" -o "$OUTPUT_DIR/params.json" -of json -c
```

***

### III. Advanced techniques

Recursive directory discovery:[\[2\]](https://hackzone.in/blog/ffuf-bug-bounty-ultimate-guide/)

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -t "$THREADS" -recursion -recursion-depth "$RECURSION_DEPTH" -o "$OUTPUT_DIR/recursive.json" -of json -c
```

Multiple wordlists with multiple FUZZ keywords:[\[3\]](https://www.hackingarticles.in/comprehensive-guide-on-ffuf/)

```bash
ffuf -w "$WORDLIST:FUZZ" -w "$PARAM_WORDLIST:FUZZ2" -u "$URL/FUZZ?param=FUZZ2" -t "$THREADS" -o "$OUTPUT_DIR/multi.json" -of json -c
```

POST data fuzzing (JSON API):

```bash
ffuf -w "$WORDLIST" -u "$URL/api/login" -X POST -H "Content-Type: application/json" -d "$POST_DATA" -t "$THREADS" -o "$OUTPUT_DIR/post-json.json" -of json -c
```

Virtual host (vhost) discovery:

```bash
ffuf -w "$WORDLIST" -u "$URL" -H "Host: FUZZ.$VHOST_DOMAIN" -t "$THREADS" -o "$OUTPUT_DIR/vhost.json" -of json -c -ac
```

Fuzzing headers:

```bash
ffuf -w "$WORDLIST" -u "$URL" -H "X-Forwarded-For: FUZZ" -t "$THREADS" -o "$OUTPUT_DIR/headers.json" -of json -c
```

***

### IV. Filtering and matching

Match HTTP status codes:[\[4\]](https://infosecwriteups.com/mastering-ffuf-basic-and-advanced-commands-60e53bdbffc7)

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -mc 200,301,302,403 -t "$THREADS" -c
```

Filter HTTP status codes:[\[5\]](https://awjunaid.com/kali-linux/ffuf-fuzzing-web-applications-for-vulnerabilities/)

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -fc 404,403 -t "$THREADS" -c
```

Filter by response size:[\[6\]](https://www.hackingarticles.in/comprehensive-guide-on-ffuf/)

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -fs 1234 -t "$THREADS" -c
```

Filter by word count:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -fw 42 -t "$THREADS" -c
```

Filter by line count:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -fl 10 -t "$THREADS" -c
```

Match regular expression:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -mr "admin|root|config" -t "$THREADS" -c
```

Filter regular expression:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -fr "404|not found" -t "$THREADS" -c
```

***

### V. Auto‑calibration and error handling

Auto‑calibration:[\[7\]](https://codingo.com/posts/2020-08-29-everything-you-need-to-know-about-ffuf/)

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -t "$THREADS" -ac -c
```

Custom auto‑calibration baseline:[\[8\]](https://codingo.com/posts/2020-08-29-everything-you-need-to-know-about-ffuf/)

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -t "$THREADS" -acc "nonexistent123" -c
```

Stop on all errors:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -t "$THREADS" -sa -c
```

Stop on spurious errors:[\[9\]](https://codingo.com/posts/2020-08-29-everything-you-need-to-know-about-ffuf/)

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -t "$THREADS" -se -c
```

***

### VI. Rate limiting and timing

Set request rate (requests per second):

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -rate 50 -t "$THREADS" -c
```

Add delay between requests (seconds):

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -p "$DELAY" -t "$THREADS" -c
```

Set timeout per request:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -timeout "$TIMEOUT" -t "$THREADS" -c
```

Set maximum time for entire job:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -maxtime 3600 -t "$THREADS" -c
```

Set maximum time per target:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -maxtime-job 300 -t "$THREADS" -c
```

***

### VII. Output and reporting

JSON output:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -t "$THREADS" -o "$OUTPUT_DIR/scan.json" -of json
```

HTML output:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -t "$THREADS" -o "$OUTPUT_DIR/scan.html" -of html
```

CSV output:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -t "$THREADS" -o "$OUTPUT_DIR/scan.csv" -of csv
```

Save all formats simultaneously:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -t "$THREADS" -o "$OUTPUT_DIR/scan" -of all
```

***

### VIII. Proxy and inspection

Route traffic through Burp Suite:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -x "$PROXY" -t "$THREADS" -c
```

Replay‑proxy for manual inspection:[\[10\]](https://hayageek.com/ffuf-tutorial-alternative-to-gobuster/)

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -t "$THREADS" -replay-proxy "$PROXY" -c
```

***

### IX. Mutators for dynamic payloads

Use external mutators (e.g., Radamsa) to generate variations:[\[11\]](https://www.acceis.fr/ffuf-advanced-tricks/)

```bash
ffuf --input-cmd 'echo "[test@example.com](<mailto:test@example.com>)" | radamsa --seed $FFUF_NUM' \\
     -input-num 100 -u "$URL/FUZZ" -H "Content-Type: application/json" \\
     -X POST -d '{"email":"FUZZ"}' -t "$THREADS" -c
```

***

### X. Real‑world workflow example

Export variables:

```bash
export URL="<http://10.10.10.50>"
export WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
export OUTPUT_DIR="ffuf_scans"
export THREADS=100
mkdir -p "$OUTPUT_DIR"
```

Initial directory discovery:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -t "$THREADS" -o "$OUTPUT_DIR/dir.json" -of json -c -ac
```

Recursive fuzzing on discovered paths:

```bash
ffuf -w "$WORDLIST" -u "$URL/FUZZ" -t "$THREADS" -recursion -recursion-depth 2 -o "$OUTPUT_DIR/recursive.json" -of json -c
```

Parameter fuzzing on login endpoint:

```bash
export POST_DATA='{"username":"admin","password":"FUZZ"}'
ffuf -w "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt" \\
     -u "$URL/api/login" -X POST -H "Content-Type: application/json" -d "$POST_DATA" \\
     -t "$THREADS" -o "$OUTPUT_DIR/login-fuzz.json" -of json -c -fc 401
```

VHOST discovery:

```bash
export VHOST_DOMAIN="[target.com](<http://target.com>)"
ffuf -w "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt" -u "$URL" \\
     -H "Host: FUZZ.$VHOST_DOMAIN" -t "$THREADS" -o "$OUTPUT_DIR/vhost.json" -of json -c -ac
```

***

### XI. Pro tips

* Use `-ac` auto‑calibration to reduce false positives.[\[12\]](https://www.hackingarticles.in/comprehensive-guide-on-ffuf/)
* Combine multiple wordlists for coverage.[\[13\]](https://hackzone.in/blog/ffuf-bug-bounty-ultimate-guide/)
* Leverage recursion for deeper structures.[\[14\]](https://hackzone.in/blog/ffuf-bug-bounty-ultimate-guide/)
* Tune matchers and filters to isolate signal.[\[15\]](https://infosecwriteups.com/mastering-ffuf-basic-and-advanced-commands-60e53bdbffc7)
* Apply rate limiting and delays thoughtfully.[\[16\]](https://awjunaid.com/kali-linux/ffuf-fuzzing-web-applications-for-vulnerabilities/)
* Save output in multiple formats for reports.[\[17\]](https://www.hackingarticles.in/comprehensive-guide-on-ffuf/)
* Integrate with Burp via proxy flags for manual review.[\[18\]](https://hayageek.com/ffuf-tutorial-alternative-to-gobuster/)
* Use mutators for API fuzzing scenarios.[\[19\]](https://www.acceis.fr/ffuf-advanced-tricks/)

***

References

* [https://github.com/ffuf/ffuf](https://github.com/ffuf/ffuf)
* [https://infosecwriteups.com/mastering-ffuf-basic-and-advanced-commands-60e53bdbffc7](https://infosecwriteups.com/mastering-ffuf-basic-and-advanced-commands-60e53bdbffc7)
* [https://codingo.com/posts/2020-08-29-everything-you-need-to-know-about-ffuf/](https://codingo.com/posts/2020-08-29-everything-you-need-to-know-about-ffuf/)
* [https://hackzone.in/blog/ffuf-bug-bounty-ultimate-guide/](https://hackzone.in/blog/ffuf-bug-bounty-ultimate-guide/)
* [https://www.hackingarticles.in/comprehensive-guide-on-ffuf/](https://www.hackingarticles.in/comprehensive-guide-on-ffuf/)
* [https://awjunaid.com/kali-linux/ffuf-fuzzing-web-applications-for-vulnerabilities/](https://awjunaid.com/kali-linux/ffuf-fuzzing-web-applications-for-vulnerabilities/)
* [https://hayageek.com/ffuf-tutorial-alternative-to-gobuster/](https://hayageek.com/ffuf-tutorial-alternative-to-gobuster/)
* [https://www.acceis.fr/ffuf-advanced-tricks/](https://www.acceis.fr/ffuf-advanced-tricks/)
* [https://c9lab.com/991872-fxcaub/](https://c9lab.com/991872-fxcaub/)
* [https://hackviser.com/tactics/tools/ffuf](https://hackviser.com/tactics/tools/ffuf)
* [https://osintteam.blog/ffuf-mastery-the-ultimate-web-fuzzing-guide-f7755c396b92](https://osintteam.blog/ffuf-mastery-the-ultimate-web-fuzzing-guide-f7755c396b92)
* [https://www.kayssel.com/post/hacking-web-3/](https://www.kayssel.com/post/hacking-web-3/)
* [https://www.freecodecamp.org/news/web-security-fuzz-web-applications-using-ffuf/](https://www.freecodecamp.org/news/web-security-fuzz-web-applications-using-ffuf/)
* [https://amrelsagaei.com/fuzz-everything](https://amrelsagaei.com/fuzz-everything)
* [https://www.youtube.com/watch?v=iLFkxAmwXF0](https://www.youtube.com/watch?v=iLFkxAmwXF0)
* [https://ffuf.hashnode.dev/fuzzing-using-ffuf](https://ffuf.hashnode.dev/fuzzing-using-ffuf)
