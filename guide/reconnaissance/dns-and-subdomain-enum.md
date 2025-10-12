---
icon: diagram-subtask
---

# DNS & Subdomain Enum

## **DNS & Subdomain Enumeration — Mapping the Invisible Infrastructure**

***

Every domain hides a web of assets — mail servers, APIs, dev portals, and internal systems.\
DNS is the roadmap.\
By enumerating DNS records, subdomains, and misconfigured zones, attackers can reveal **attack surfaces** long before exploitation begins.

This guide covers **passive**, **active**, and **advanced DNS enumeration**, from OSINT techniques to zone transfer and record analysis.

***

### I. 🧩 Core DNS Concepts

| Concept                   | Description                                                                     |
| ------------------------- | ------------------------------------------------------------------------------- |
| **DNS**                   | Domain Name System — resolves domain names to IP addresses.                     |
| **Zone**                  | Portion of the namespace managed by a DNS server.                               |
| **Record**                | A mapping of data (host → IP, mail server, etc.).                               |
| **Zone Transfer (AXFR)**  | Synchronization mechanism between DNS servers — exploitable when misconfigured. |
| **Subdomain Enumeration** | Discovery of additional hosts under a domain.                                   |

***

### II. ⚙️ Record Types & Their Uses

| Record    | Description                   | Example                               |
| --------- | ----------------------------- | ------------------------------------- |
| **A**     | IPv4 address                  | `api.example.com → 192.168.1.5`       |
| **AAAA**  | IPv6 address                  | `api.example.com → fe80::1`           |
| **MX**    | Mail servers                  | `mail.example.com`                    |
| **NS**    | Nameservers                   | `ns1.example.com`                     |
| **TXT**   | Misc info (SPF, verification) | `v=spf1 include:_spf.google.com`      |
| **CNAME** | Canonical name (alias)        | `dev.example.com → app.herokuapp.com` |
| **PTR**   | Reverse DNS lookup            | `192.168.1.5 → host.example.com`      |
| **SRV**   | Service locator record        | `_ldap._tcp.example.com`              |

***

### III. 🧠 Passive DNS Enumeration

Passive recon leaves no trace on the target.\
You rely on third-party data, archives, and search engines.

#### 🧩 1. WHOIS Lookup

```bash
whois example.com
```

Find registrar, emails, and nameservers — great for pivoting.

#### ⚙️ 2. DNS History & Passive Sources

```bash
crt.sh/?q=example.com
```

or

```bash
curl -s "https://dns.bufferover.run/dns?q=example.com" | jq .
```

#### 🧠 3. Certificate Transparency Logs

```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq '.[].name_value'
```

#### ⚙️ 4. Search Engine Enumeration

```
site:example.com -www
inurl:dev.example.com
```

#### 🧠 5. Subdomain Databases

* `https://securitytrails.com/domain/example.com`
* `https://spyse.com/`
* `https://chaos.projectdiscovery.io/`
* `https://dnsdumpster.com/`

***

### IV. ⚙️ Active DNS Enumeration

Active enumeration interacts directly with the target DNS servers.\
Used when you need **live**, **fresh**, and **verifiable** results.

***

#### 🧩 1. DNS Lookup Basics

```bash
dig example.com any
host -a example.com
nslookup example.com
```

***

#### ⚙️ 2. Find Nameservers

```bash
dig ns example.com +short
```

Then test for **zone transfer**:

```bash
dig axfr example.com @ns1.example.com
```

If successful → **entire domain map** is exposed:

```
ftp.example.com.    A 192.168.1.21
mail.example.com.   A 192.168.1.22
dev.example.com.    A 10.10.0.5
```

***

#### 🧠 3. Reverse Lookup (PTR Records)

```bash
dig -x 192.168.1.10
```

Helps identify naming patterns or hidden hosts.

***

#### ⚙️ 4. Zone Walking (for DNSSEC)

```bash
fierce --domain example.com
ldns-walk example.com
```

***

### V. 🧩 Subdomain Enumeration Techniques

#### ⚙️ 1. Wordlist-based Brute Force

```bash
dnsrecon -d example.com -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt
```

or

```bash
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

***

#### 🧠 2. MassDNS (High-Speed)

```bash
massdns -r resolvers.txt -t A -o S -w results.txt subs.txt
```

***

#### ⚙️ 3. Amass (Hybrid Enumeration)

```bash
amass enum -d example.com -brute -src -o subdomains.txt
```

Sources used: passive + active + certificate + brute force.

***

#### 🧩 4. Subfinder (Fast Passive)

```bash
subfinder -d example.com -all -o subs.txt
```

Combine with **httpx** to find live hosts:

```bash
cat subs.txt | httpx -title -status-code -tech-detect -o alive.txt
```

***

### VI. ⚙️ DNS Record Analysis

#### 🧠 1. SPF & TXT Records

```bash
dig txt example.com
```

Look for SPF misconfigurations allowing spoofing:

```
v=spf1 +all
```

#### ⚙️ 2. CNAME Chains

Follow CNAMEs → find third-party services, e.g.:

```
dev.example.com → example.herokuapp.com
```

Test for **subdomain takeover** if service no longer exists.

***

### VII. 💣 DNS Zone Transfer Exploitation (AXFR)

Zone transfers (AXFR/IXFR) are legitimate admin features — but if open, they leak **every host** in a domain.

#### ⚙️ Check for Zone Transfer

```bash
dig axfr example.com @ns1.example.com
```

#### 🧠 Automate Check

```bash
dnsrecon -d example.com -t axfr
```

If success → save records for future scans:

```bash
awk '{print $1}' zone.txt | sort -u > hosts.txt
```

***

### VIII. 🧬 Advanced DNS Enumeration

#### ⚙️ 1. DNS Cache Snooping

```bash
dig @ns.example.com target.com +nsid
```

If response shows cache hit → you can detect what users query.

***

#### 🧠 2. Reverse DNS Sweep

```bash
for ip in $(seq 1 254); do dig -x 10.10.10.$ip +short; done
```

***

#### ⚙️ 3. DNS Brute Chaining

```bash
amass enum -passive -d example.com
subfinder -d example.com | anew subs.txt
massdns -r resolvers.txt -t A -o S subs.txt
httpx -l subs.txt -status-code -title -tech-detect -o alive.txt
```

Chain tools for complete visibility.

***

### IX. 💣 Subdomain Takeover Identification

#### ⚙️ Detect Dangling CNAMEs

```bash
dig dev.example.com
```

If it points to:

```
dev.example.com.  CNAME  oldapp.herokuapp.com.
```

And that service no longer exists → takeover possible.

#### 🧠 Automate with Nuclei

```bash
nuclei -t takeovers/ -l subs.txt
```

***

### X. ⚙️ Automation Workflow Example

```bash
# 1. Enumerate passively
subfinder -d example.com -o subs.txt

# 2. Active resolution
massdns -r resolvers.txt -t A -o S subs.txt | tee resolved.txt

# 3. Validate live hosts
cat resolved.txt | httpx -title -tech-detect -o alive.txt

# 4. Scan open ports
naabu -list alive.txt -top-ports 100 -o ports.txt

# 5. Vulnerability scan
nuclei -l alive.txt -t cves/ -t misconfig/
```

***

### XI. 🧠 Reverse Engineering DNS Zones in CTFs

#### ⚙️ Common CTF Tricks

| Scenario                   | Clue                    | Solution                    |
| -------------------------- | ----------------------- | --------------------------- |
| Hidden flag in TXT record  | `"flag{...}"`           | `dig txt example.com`       |
| Subdomain in SRV record    | `_ftp._tcp.example.com` | `dig srv example.com`       |
| AXFR allowed               | Zone dump               | `dig axfr example.com @ns1` |
| PTR reveals internal names | `*.corp.local`          | `dig -x` sweep              |

***

### XII. ⚙️ Tools Arsenal

| Category           | Tool                                     | Description                                |
| ------------------ | ---------------------------------------- | ------------------------------------------ |
| Passive            | Subfinder, Amass, SecurityTrails, crt.sh | Collect subdomains without touching target |
| Active             | DNSrecon, Fierce, Dig, MassDNS           | Resolve, brute-force, and test transfers   |
| Hybrid             | Amass, DNSx                              | Combine active and passive                 |
| Validation         | httpx, Nuclei                            | Check live subdomains, tech stacks         |
| Takeover Detection | Subjack, Nuclei                          | Detect dangling CNAMEs                     |

***

### XIII. ⚔️ Pro Tips & Red Team Tricks

✅ **Combine Passive + Active**\
Start passive (safe), confirm with active (accurate).

✅ **Use Resolvers Wisely**\
Custom resolvers avoid blacklisting; use 8.8.8.8, Cloudflare, Quad9.

✅ **Automation Pipelines**\
Chain `subfinder → amass → massdns → httpx` for large-scope orgs.

✅ **Look for Misconfigurations**

* SPF `+all` → mail spoofing
* Zone Transfer (AXFR) → full map
* Old CNAMEs → takeover
* Hidden TXT records → flags / tokens

✅ **Pivot on Registrant Data**\
Same WHOIS emails = new domains of the same org.

***

### XIV. ⚙️ Quick Reference Table

| Goal          | Tool / Command                          | Purpose                  |
| ------------- | --------------------------------------- | ------------------------ |
| Whois Info    | `whois example.com`                     | Domain metadata          |
| NS Lookup     | `dig ns example.com`                    | Find nameservers         |
| AXFR Test     | `dig axfr example.com @ns1.example.com` | Zone transfer            |
| Passive Subs  | `subfinder -d example.com`              | Hidden subdomains        |
| Active Brute  | `dnsrecon -d example.com -t brt`        | Wordlist-based discovery |
| DNSSEC Walk   | `ldns-walk example.com`                 | Enumerate DNSSEC zone    |
| Reverse Sweep | `dig -x IP`                             | PTR enumeration          |
| Validation    | `httpx -l subs.txt`                     | Live host check          |

***
