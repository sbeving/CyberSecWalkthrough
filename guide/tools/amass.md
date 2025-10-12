---
icon: arrow-up-9-1
---

# Amass

## The Amass Masterclass: Professional Reconnaissance & Asset Discovery

Amass is a leading open-source tool for comprehensive attack surface mapping, subdomain enumeration, and external asset discovery. It is essential for penetration testers, bug bounty hunters, and red teamers who need deep, reliable reconnaissance at scale.

***

### I. Environment Setup: Dynamic Variables

Export variables for flexible, repeatable workflows and organized output:

```bash
export DOMAIN="[target.com](<http://target.com>)"
export OUTPUT_DIR="amass-results"
export WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
export CONFIG_FILE="amass-config.ini"
export ASN="AS15169"    # Example: Google
export CIDR="8.8.8.0/24"
export API_KEYS_FILE="~/.config/amass/api_keys.ini"
export RESOLVERS="/etc/resolv.conf"
```

***

### II. Core Capabilities & Workflow

* **Subdomain Enumeration:** Discovers subdomains using passive, active, and brute-force methods from dozens of data sources.[cyberxsociety+2](https://cyberxsociety.com/complete-guide-to-amass-tool-2025-edition-from-beginner-to-pro-in-bug-bounty-recon/)
* **DNS Mapping:** Maps DNS records (A, AAAA, CNAME, MX, TXT, etc.) and visualizes relationships.[hayageek+2](https://hayageek.com/owasp-amass-tutorial/)
* **OSINT Integration:** Leverages APIs, search engines, CT logs, and public datasets for deep asset discovery.[siberoloji+2](https://www.siberoloji.com/amass-a-comprehensive-network-mapping-tool-in-kali-linux/)
* **Network Mapping:** Maps domains to IPs, ASNs, CIDRs, and related infrastructure.[cyberxsociety+2](https://cyberxsociety.com/complete-guide-to-amass-tool-2025-edition-from-beginner-to-pro-in-bug-bounty-recon/)
* **Visualization:** Graphs and exports results for analysis and reporting.[hayageek+2](https://hayageek.com/owasp-amass-tutorial/)
* **Change Tracking:** Monitors asset changes over time for continuous recon.[siberoloji+2](https://www.siberoloji.com/amass-a-comprehensive-network-mapping-tool-in-kali-linux/)
* **Database Support:** Stores and queries results for large-scale, repeatable recon.[cyberxsociety+2](https://cyberxsociety.com/complete-guide-to-amass-tool-2025-edition-from-beginner-to-pro-in-bug-bounty-recon/)

***

### III. Professional Usage Examples

#### 1. Passive Subdomain Enumeration (Stealthy)

```bash
amass enum -passive -d "$DOMAIN" -o "$OUTPUT_DIR/passive.txt"
```

#### 2. Active Subdomain Enumeration (Aggressive, Deep)

```bash
amass enum -active -d "$DOMAIN" -o "$OUTPUT_DIR/active.txt"
```

#### 3. Brute-Force Subdomain Discovery

```bash
amass enum -brute -d "$DOMAIN" -w "$WORDLIST" -o "$OUTPUT_DIR/brute.txt"
```

#### 4. Combined Passive, Active, and Brute-Force

```bash
amass enum -d "$DOMAIN" -active -brute -w "$WORDLIST" -o "$OUTPUT_DIR/full.txt"
```

#### 5. Use Custom Resolvers and API Keys

```bash
amass enum -d "$DOMAIN" -rf "$RESOLVERS" -config "$CONFIG_FILE" -o "$OUTPUT_DIR/custom.txt"
```

#### 6. ASN and CIDR Recon (Infrastructure Mapping)

```bash
amass intel -asn "$ASN" -whois -o "$OUTPUT_DIR/asn.txt"
amass intel -cidr "$CIDR" -whois -o "$OUTPUT_DIR/cidr.txt"
```

#### 7. Visualize Results (Graphical Analysis)

```bash
amass viz -d3 -dir "$OUTPUT_DIR/graphdb"
```

#### 8. Export Graph for Reporting

```bash
amass viz -g > "$OUTPUT_DIR/graph.graphml"
```

#### 9. Track Changes Over Time

```bash
amass track -d "$DOMAIN" -dir "$OUTPUT_DIR/trackdb" -o "$OUTPUT_DIR/track.txt"
```

#### 10. Query Local Database for Results

```bash
amass db -dir "$OUTPUT_DIR/graphdb" -list -d "$DOMAIN"
```

***

### IV. Advanced Techniques & Scenarios

* **API Key Management:** Store and manage API keys for Shodan, Censys, VirusTotal, etc., in your config file for richer data.
* **Recursive Enumeration:** Use `-active -brute` to recursively discover nested subdomains and dev/test environments.[siberoloji+1](https://www.siberoloji.com/amass-a-comprehensive-network-mapping-tool-in-kali-linux/)
* **False Positive Filtering:** Use filtering and cross-check with live host checkers (e.g., httpx) to validate results.[cyberxsociety](https://cyberxsociety.com/complete-guide-to-amass-tool-2025-edition-from-beginner-to-pro-in-bug-bounty-recon/)
* **Automation:** Integrate Amass into bash scripts or CI/CD pipelines for scheduled, continuous recon.[cyberxsociety](https://cyberxsociety.com/complete-guide-to-amass-tool-2025-edition-from-beginner-to-pro-in-bug-bounty-recon/)
* **Visualization for Reporting:** Export graphs to GraphML or DOT for use in Gephi, Maltego, or reporting tools.[hayageek+2](https://hayageek.com/owasp-amass-tutorial/)
* **Periodic Tracking:** Use the `track` module to monitor asset changes and alert on new exposures.[hayageek+2](https://hayageek.com/owasp-amass-tutorial/)

***

### V. Real-World Workflow Example

1. Export Variables:

```bash
export DOMAIN="[example.com](<http://example.com>)"
export OUTPUT_DIR="amass_scans"
export WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
```

1. Passive Recon:

```bash
amass enum -passive -d "$DOMAIN" -o "$OUTPUT_DIR/passive.txt"
```

1. Active & Brute-Force Recon:

```bash
amass enum -active -brute -d "$DOMAIN" -w "$WORDLIST" -o "$OUTPUT_DIR/active_brute.txt"
```

1. Visualize Results:

```bash
amass viz -d3 -dir "$OUTPUT_DIR/graphdb"
```

1. Track Changes Over Time:

```bash
amass track -d "$DOMAIN" -dir "$OUTPUT_DIR/trackdb" -o "$OUTPUT_DIR/track.txt"
```

1. Integrate with Other Tools:

* Pipe results to `httpx` for live host checking
* Use with `nmap` for port scanning
* Screenshot endpoints with `gowitness` or `aquatone`

***

### VI. Pro Tips & Best Practices

* **Start with passive scans** to avoid detection, then escalate to active and brute-force as needed.[siberoloji+1](https://www.siberoloji.com/amass-a-comprehensive-network-mapping-tool-in-kali-linux/)
* **Use multiple data sources and API keys** for maximum coverage.[siberoloji+1](https://www.siberoloji.com/amass-a-comprehensive-network-mapping-tool-in-kali-linux/)
* **Validate subdomains** with live host checkers to filter out dead entries.[cyberxsociety](https://cyberxsociety.com/complete-guide-to-amass-tool-2025-edition-from-beginner-to-pro-in-bug-bounty-recon/)
* **Automate periodic scans** to catch new assets as they appear.[cyberxsociety](https://cyberxsociety.com/complete-guide-to-amass-tool-2025-edition-from-beginner-to-pro-in-bug-bounty-recon/)
* **Visualize and report** using the `viz` module for clear communication with teams or clients.[hayageek+2](https://hayageek.com/owasp-amass-tutorial/)
* **Document and track** all findings for compliance and future reference.[hayageek+2](https://hayageek.com/owasp-amass-tutorial/)
* **Always scan with authorization** and respect scope boundaries.

***

This professional Amass guide equips you for deep, scalable, and repeatable reconnaissance—essential for modern attack surface management and bug bounty success.

1. [https://cyberxsociety.com/complete-guide-to-amass-tool-2025-edition-from-beginner-to-pro-in-bug-bounty-recon/](https://cyberxsociety.com/complete-guide-to-amass-tool-2025-edition-from-beginner-to-pro-in-bug-bounty-recon/)
2. [https://www.youtube.com/watch?v=skoPPyRneCk](https://www.youtube.com/watch?v=skoPPyRneCk)
3. [https://hayageek.com/owasp-amass-tutorial/](https://hayageek.com/owasp-amass-tutorial/)
4. [https://www.siberoloji.com/amass-a-comprehensive-network-mapping-tool-in-kali-linux/](https://www.siberoloji.com/amass-a-comprehensive-network-mapping-tool-in-kali-linux/)
5. [https://awjunaid.com/kali-linux/amass-subdomain-enumeration-tool/](https://awjunaid.com/kali-linux/amass-subdomain-enumeration-tool/)
6. [https://thesecmaster.com/blog/amass-open-source-reconnaissance-tool-for-network-mapping-and-information-gathering](https://thesecmaster.com/blog/amass-open-source-reconnaissance-tool-for-network-mapping-and-information-gathering)
7. [https://projectdiscovery.io/blog/recon-series-2](https://projectdiscovery.io/blog/recon-series-2)
