---
icon: globe-pointer
---

# Web App Enum

## **Web Application Enumeration — Knowing the Target Before the First Shot**

***

Enumeration is the **intelligence phase** of web hacking.\
Every service, directory, parameter, and header is potential entry.\
The better your enumeration, the faster your exploitation.

This guide focuses on **active**, **passive**, and **hybrid reconnaissance** — mapping every part of a web app using professional-grade tools and workflows.

***

### I. 🧩 Core Concepts

| Concept                   | Description                                          |
| ------------------------- | ---------------------------------------------------- |
| **Discovery**             | Identifying accessible paths, subdomains, and files. |
| **Fingerprinting**        | Detecting technologies, CMS, and frameworks.         |
| **Parameter Enumeration** | Finding hidden GET/POST parameters.                  |
| **Crawling**              | Systematically mapping URLs and input points.        |
| **Content Discovery**     | Brute-forcing endpoints and hidden assets.           |

***

### II. ⚙️ Passive Enumeration

#### 🧠 1. View Source & Robots

```bash
curl -s http://target.com/robots.txt
curl -s http://target.com/sitemap.xml
```

#### ⚙️ 2. Google Dorking

```
site:target.com inurl:admin
site:target.com ext:sql | ext:bak | ext:old
intitle:"index of" site:target.com
```

#### 🧠 3. Wayback Machine

```bash
curl "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original" | sort -u
```

Retrieve historical endpoints and parameters.

#### ⚙️ 4. BuiltWith & Wappalyzer

```bash
whatweb target.com
wappalyzer target.com
```

Identify backend stack: PHP, ASPX, Flask, Laravel, etc.

***

### III. ⚙️ Active Web Enumeration

#### 🧩 1. Crawl URLs Automatically

```bash
gospider -s "https://target.com" -d 2 -o spider/
katana -u https://target.com -depth 3 -o urls.txt
```

#### ⚙️ 2. Directory Brute-Forcing

```bash
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,js
```

or

```bash
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 30 -x js,php,txt
```

#### 💣 3. Recursive Directory Discovery

```bash
dirsearch -u https://target.com -e php,asp,aspx,js,txt -r
```

***

### IV. 🧠 Parameter Discovery

Hidden parameters lead to hidden functionalities — and often **injections**.

#### ⚙️ 1. Param Fuzzing

```bash
ffuf -u https://target.com/page.php?FUZZ=value -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -c
```

#### 🧩 2. Wordlist Combo (Params + Values)

```bash
ffuf -u "https://target.com/page.php?FUZZ=INJECT" -w params.txt:FUZZ -w values.txt:INJECT
```

#### ⚙️ 3. Param Mining via Crawlers

```bash
waybackurls target.com | grep "=" | sort -u
```

***

### V. ⚙️ HTTP Header & Method Analysis

#### 🧩 1. Enumerate Headers

```bash
curl -I https://target.com
```

#### ⚙️ 2. Check Allowed Methods

```bash
curl -X OPTIONS https://target.com -i
```

Response:

```
Allow: GET, POST, PUT, DELETE
```

→ Possible endpoint for PUT/DELETE abuse.

#### 💣 3. Identify Security Headers

```bash
curl -sI https://target.com | grep -E "X-Frame|X-XSS|CSP"
```

***

### VI. 🧠 Content Enumeration

#### ⚙️ 1. File Extensions

Common sensitive files:

```
.bak
.old
.sql
.zip
.env
```

#### 💣 2. Identify Backup & Config Files

```bash
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .bak,.old,.zip,.tar,.gz
```

***

### VII. ⚙️ Virtual Host (VHost) Discovery

#### 🧩 1. Subdomain-based VHost

```bash
ffuf -u http://target.com -H "Host: FUZZ.target.com" -w subdomains.txt
```

#### ⚙️ 2. IP-based VHost

```bash
ffuf -u http://10.10.10.10 -H "Host: FUZZ.example.com" -w /usr/share/seclists/Discovery/DNS/subdomains.txt
```

***

### VIII. 💣 JS File Analysis

#### ⚙️ Extract Hidden Endpoints

```bash
curl -s https://target.com/app.js | grep -Eo "https?://[^\"\\']+" | sort -u
```

#### 🧠 Automate with JS Parser

```bash
linkfinder -i https://target.com/app.js -o cli
```

Look for:

```
api/v1/
admin/
auth/
```

***

### IX. ⚙️ API Endpoint Enumeration

#### 🧩 Swagger & OpenAPI Discovery

```bash
curl -s https://target.com/swagger.json
curl -s https://target.com/api-docs
```

#### ⚙️ API Fuzzing

```bash
ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api.txt -t 50
```

***

### X. 🧠 Parameter Pollution & Hidden Parameters

#### ⚙️ Detect Duplicates

```
https://target.com/page.php?id=1&id=2
```

Different responses may indicate **parameter pollution**.

#### 🧩 Hidden Inputs via Burp

Use Burp’s **Param Miner** extension — detects hidden GET/POST parameters.

***

### XI. ⚙️ Authentication & Login Discovery

#### 🧠 Common Login Paths

```
/login
/admin
/cpanel
/wp-login.php
```

#### ⚙️ Wordlist Bruteforce

```bash
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/Login_Pages.fuzz.txt
```

***

### XII. 🧩 Technology Fingerprinting

#### ⚙️ Web Server Banner

```bash
curl -sI https://target.com | grep Server
```

#### 🧠 Framework Detection

```bash
whatweb https://target.com
nmap -sV --script=http-enum -p80,443 target.com
```

#### ⚙️ CMS Detection

```bash
wpscan --url https://target.com
droopescan scan drupal -u https://target.com
```

***

### XIII. ⚙️ Parameter Tampering Detection

#### 🧠 Identify Parameters with Responses

```bash
ffuf -u https://target.com/page.php?id=FUZZ -w nums.txt -fw 0
```

Response size changes → possible logic or validation flaw.

***

### XIV. ⚙️ Form Enumeration

#### ⚙️ Extract Forms from HTML

```bash
curl -s https://target.com | pup 'form attr{action}'
```

#### 💣 Use Arjun for Hidden Parameters

```bash
arjun -u https://target.com/index.php -m GET,POST -oT params.txt
```

***

### XV. ⚙️ Fuzzing for Hidden Directories & APIs (Hybrid Recon)

```bash
subfinder -d target.com -silent | httpx -silent -o hosts.txt
while read host; do
  ffuf -u $host/FUZZ -w common.txt -e .php,.js,.txt -mc 200,403 -t 50 -o $host.json
done < hosts.txt
```

Generates endpoint maps per host.

***

### XVI. 🧠 Advanced Enumeration Techniques

| Technique                 | Example                               | Tool                  |
| ------------------------- | ------------------------------------- | --------------------- |
| **WebSocket Discovery**   | Search “ws://” or “wss://” in JS      | LinkFinder            |
| **Hidden APIs**           | Inspect mobile apps or JS bundles     | Apktool, Burp         |
| **Parameter Brute-Force** | `id`, `file`, `user`, `debug`, `lang` | ffuf                  |
| **Content Discovery**     | `/uploads/`, `/admin/`, `/backup/`    | gobuster, feroxbuster |
| **Error-based Discovery** | Trigger 500/403 errors                | curl, Burp Repeater   |

***

### XVII. ⚙️ Full Automation Pipeline

```bash
# 1. Crawl & extract
katana -u https://target.com -d 2 -o urls.txt

# 2. Subdomain + URL combo
subfinder -d target.com -o subs.txt
httpx -l subs.txt -o live.txt
gospider -S live.txt -d 2 -o spider/

# 3. Directory & parameter fuzzing
ffuf -u https://target.com/FUZZ -w common.txt -mc 200,403
arjun -u https://target.com -o params.txt

# 4. API endpoint & JS parsing
linkfinder -i https://target.com/app.js -o cli
```

Combine results → `urls.txt + params.txt + alive.txt` for exploitation.

***

### XVIII. ⚔️ Pro Tips & Red Team Tricks

✅ **Think Layers**

1. Subdomain enumeration
2. Directory discovery
3. Parameter hunting
4. Technology fingerprinting
5. Version-specific exploit research

✅ **Use Custom Wordlists**

*   Generate from content:

    ```bash
    cewl https://target.com -m 5 -w words.txt
    ```
* Combine with existing lists using `anew`.

✅ **Speed vs. Noise**

* Passive first (safe), then active (controlled).
* Use rate limits on production systems.

✅ **Chain Tools**

* `amass → httpx → katana → nuclei → ffuf`.

✅ **Context = Exploitation**\
Every parameter and header tells a story — “what tech, what auth, what attack.”

***

### XIX. ⚙️ Quick Reference Table

| Goal             | Tool / Command            | Description                     |
| ---------------- | ------------------------- | ------------------------------- |
| Crawl            | `gospider`, `katana`      | Map URLs and endpoints          |
| Brute-Force      | `gobuster`, `feroxbuster` | Hidden dirs & files             |
| Param Fuzz       | `ffuf`, `arjun`           | Find hidden GET/POST parameters |
| Tech Fingerprint | `whatweb`, `wappalyzer`   | Detect stack                    |
| API Enum         | `linkfinder`, `swagger`   | Discover API endpoints          |
| Login Pages      | `ffuf`, `dirsearch`       | Identify auth points            |
| CMS Detection    | `wpscan`, `droopescan`    | WordPress / Drupal recon        |
| JS Analysis      | `linkfinder`              | Extract URLs                    |
| Validation       | `httpx`                   | Check alive hosts, titles, tech |

***
