---
icon: user-ninja
---

# MassDNS

## The MassDNS Masterclass: Professional DNS Reconnaissance & Subdomain Enumeration

MassDNS is a high-performance DNS stub resolver optimized for bulk, scalable DNS lookups—essential for subdomain enumeration, asset discovery, and DNS data analysis in pentesting workflows.

***

### I. Environment Setup: Dynamic Variables

Set your session variables for organized bulk queries:

```bash
export DOMAIN_LIST="domains.txt"            # List of domains/subdomains to resolve
export RESOLVERS="lists/resolvers.txt"      # List of DNS resolvers (included in MassDNS repo)
export OUTPUT_DIR="massdns-results"
export OUTPUT_FILE="$OUTPUT_DIR/resolved.txt"
export RECORD_TYPE="A"                      # DNS record type (A, AAAA, MX, PTR, SRV, etc.)
export ERROR_LOG="$OUTPUT_DIR/error.log"
export HASHMAP_SIZE=10000                   # Number of concurrent lookups (default: 10,000)
export PROCESSES=4                          # Parallel processing jobs

```

***

### II. Core Capabilities & Workflow

* **Bulk DNS Resolution:** Process millions of queries per minute using dozens/hundreds of public DNS resolvers\[1].
* **Flexible Output Formats:** Simple, full text, ndjson, binary, or custom flags for efficient parsing and reporting\[1]\[2].
* **Advanced DNS Record Types:** Supports A, AAAA, MX, PTR, SRV, AXFR, DNSSEC, and more\[1]\[2].
* **Wildcard Filtering:** Detects and removes wildcard DNS responses to improve validity of results\[2].
* **Error Handling & Logging:** Retry logic, error logs, non-responsive resolver filtering, granular output control\[1]\[2].
* **Scripting + Integration:** Works seamlessly with other recon tools (Amass, Assetfinder, Subfinder, etc.) via UNIX pipes\[3].
* **Zone Transfer & DNSSEC Validation:** Attempts AXFR enumerations and DNSSEC checks for deeper insights\[2].

***

### III. Professional Usage Examples

#### 1. Basic Bulk DNS Resolution (A records)

```bash
massdns -r "$RESOLVERS" -t $RECORD_TYPE $DOMAIN_LIST -o S -w "$OUTPUT_FILE"

```

#### 2. Brute-Force Subdomain Enumeration (with wordlist)

```bash
./scripts/subbrute.py example.com lists/names.txt | massdns -r "$RESOLVERS" -t A -o S -w "$OUTPUT_FILE"

```

#### 3. Resolve Multiple Record Types (AAAA, MX, SRV)

```bash
massdns -r "$RESOLVERS" -t AAAA $DOMAIN_LIST -o S -w "$OUTPUT_DIR/AAAA.txt"
massdns -r "$RESOLVERS" -t MX $DOMAIN_LIST -o S -w "$OUTPUT_DIR/mx.txt"
massdns -r "$RESOLVERS" -t SRV $DOMAIN_LIST -o S -w "$OUTPUT_DIR/srv.txt"

```

#### 4. Filter Results: Discard NOERROR with Empty Answers

```bash
massdns -r "$RESOLVERS" -t A $DOMAIN_LIST -o S0 -w "$OUTPUT_FILE"

```

#### 5. Wildcard Filtering

```bash
massdns -r "$RESOLVERS" -w "$OUTPUT_FILE" --wildcard $DOMAIN_LIST

```

#### 6. Error Logging

```bash
massdns -r "$RESOLVERS" -t A $DOMAIN_LIST -o S -l "$ERROR_LOG"

```

#### 7. Zone Transfer Attempt (AXFR)

```bash
massdns -r "$RESOLVERS" -t AXFR $DOMAIN_LIST -o S -w "$OUTPUT_DIR/axfr.txt"

```

#### 8. Pipelining With Discovery Tools

```bash
assetfinder example.com --subs-only | massdns -r "$RESOLVERS" -o S -w "$OUTPUT_FILE"

```

#### 9. PTR (Reverse DNS) Lookup

```bash
python3 scripts/ptr.py | massdns -r "$RESOLVERS" -t PTR -w "$OUTPUT_DIR/ptr.txt"

```

#### 10. Scripting/Automation for Advanced Filtering

```bash
sed 's/A.*//' "$OUTPUT_FILE"  # Strip to domains only, post-processing

```

***

### IV. Advanced Techniques & Scenarios

* **Scaled Enumeration:** Use high-concurrency `-hashmap-size`, parallel `-processes`, and optimal resolver lists to handle large-scale asset maps\[1]\[2].
* **Custom Output Flags:** Combine flags for granular outputs (e.g., `o Sdlt` for record type, indented, TTL, authority data).
* **DNSSEC Validation:** Assess DNSSEC configuration with `-dnssec` flag, useful in compliance audits\[2].
* **Timeout & Retry Controls:** Fine-tune with `-interval`, `-retry`, or `-timeout` for challenging networks\[1].
* **Error Filtering:** Use `-ignore nonresponsive.txt` to clean up bad results.

***

### V. Real-World Workflow Example

1.  **Export Variables:**

    ```bash
    export DOMAIN_LIST="subdomains.txt"
    export RESOLVERS="massdns-resolvers.txt"
    export OUTPUT_DIR="massdns_scans"
    export OUTPUT_FILE="$OUTPUT_DIR/a-records.txt"

    ```
2.  **Bulk Resolution With Filtering:**

    ```bash
    massdns -r "$RESOLVERS" -t A $DOMAIN_LIST -o S -w "$OUTPUT_FILE" --wildcard

    ```
3.  **Integrate With Amass or Assetfinder:**

    ```bash
    amass enum -passive -d example.com -o subdomains.txt
    massdns -r "$RESOLVERS" -t A subdomains.txt -o S -w "$OUTPUT_DIR/active.txt"

    ```
4.  **Parse For Live Hosts:**

    ```bash
    grep " A " "$OUTPUT_FILE" | awk '{ print $1 }' > live_hosts.txt

    ```
5. **Verify Results, Log Errors:**
   * Check `$ERROR_LOG` for resolver issues and rerun as needed.

***

### VI. Pro Tips & Best Practices

* **Use curated resolver lists**—public DNS, filtered for reliability.
* **Monitor resolver performance and rotate as needed.**
* **Automate with scripts/pipes for integration and processing.**
* **Respect DNS infrastructure**: throttle requests, avoid DoS, heed rate limits.
* **Combine with Amass, Subfinder, Assetfinder** for full enumeration.
* \*Document outputs and settings for future audits, reporting, or compliance scans.

