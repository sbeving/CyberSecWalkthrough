---
icon: chart-network
---

# Nmap

## The Nmap Masterclass: Professional Network Scanning & Enumeration

Nmap is the gold standard for network mapping, vulnerability identification, and reconnaissance in penetration testing. This guide covers advanced techniques, workflow integration, and best practices for security professionals—no installation steps included.

***

### I. Environment Setup: Dynamic Variables

Export variables for flexible, repeatable scanning workflows:

```bash
export TARGET="192.168.1.1"
export TARGET_RANGE="192.168.1.0/24"
export PORTS="22,80,443,3389"
export OUTPUT_DIR="nmap-results"
export OUTPUT_FILE="$OUTPUT_DIR/scan.txt"
export THREADS=10
export USER_AGENT="Mozilla/5.0 (Nmap)"
export PROXY="127.0.0.1:8080"
export SCRIPT="vuln"
export EXCLUDE_PORTS="135,445"
export TIMEOUT=5
export RATE=1000
export INTERFACE="eth0"
```

***

### II. Core Capabilities & Workflow

* **Host Discovery:** Identify live hosts in a network.
* **Port Scanning:** Discover open TCP/UDP ports and services.
* **Service & Version Detection:** Identify running services and their versions.
* **OS & Device Fingerprinting:** Determine operating system and device type.
* **NSE Scripting:** Automate vulnerability checks, brute force, and custom tasks.
* **Stealth & Evasion:** Evade IDS/IPS with timing, fragmentation, decoys, and spoofing.
* **Output Versatility:** Save results in multiple formats for reporting and integration.

***

### III. Professional Usage Examples

#### 1. Host Discovery (Ping Sweep)

```bash
nmap -sn "$TARGET_RANGE" -oN "$OUTPUT_DIR/hosts.txt"
```

#### 2. TCP Port Scanning (Full range)

```bash
nmap -p- "$TARGET" -oN "$OUTPUT_FILE"
```

#### 3. Fast Scan (Fewer Ports)

```bash
nmap -F "$TARGET" -oN "$OUTPUT_FILE"
```

#### 4. Service & Version Detection

```bash
nmap -sV -p "$PORTS" "$TARGET" -oN "$OUTPUT_FILE"
```

#### 5. OS Detection

```bash
nmap -O "$TARGET" -oN "$OUTPUT_FILE"
```

#### 6. Aggressive Scan (Comprehensive)

```bash
nmap -A "$TARGET" -oN "$OUTPUT_FILE"
```

Performs OS detection, version detection, script scanning, and traceroute. Use with caution—very noisy!

#### 7. UDP Scanning

```bash
nmap -sU -p 53,161 "$TARGET" -oN "$OUTPUT_FILE"
```

#### 8. Exclude Ports

```bash
nmap -p- --exclude-ports "$EXCLUDE_PORTS" "$TARGET" -oN "$OUTPUT_FILE"
```

#### 9. Save Output in Multiple Formats

```bash
nmap -p "$PORTS" "$TARGET" -oN "$OUTPUT_DIR/scan.txt" -oX "$OUTPUT_DIR/scan.xml" -oG "$OUTPUT_DIR/scan.grep"
```

***

### IV. Advanced Techniques & Scenarios

#### 1. Nmap Scripting Engine (NSE)

Run vulnerability, brute force, or custom scripts:

```bash
nmap --script "$SCRIPT" -p "$PORTS" "$TARGET" -oN "$OUTPUT_DIR/scripted.txt"
```

Popular script categories: auth, vuln, brute, malware, discovery

#### 2. Stealth Scanning (SYN Scan)

```bash
nmap -sS -p "$PORTS" "$TARGET" -oN "$OUTPUT_FILE"
```

Half-open TCP scan, less detectable by firewalls/IDS.

#### 3. Fragmented Packets (Firewall Evasion)

```bash
nmap -f -p "$PORTS" "$TARGET" -oN "$OUTPUT_FILE"
```

#### 4. Decoy Scanning (Obfuscate Source)

```bash
nmap -D RND:10 -p "$PORTS" "$TARGET" -oN "$OUTPUT_FILE"
```

#### 5. Spoof MAC Address

```bash
nmap --spoof-mac 00:11:22:33:44:55 -p "$PORTS" "$TARGET" -oN "$OUTPUT_FILE"
```

#### 6. Timing & Rate Control

```bash
nmap -T4 -p "$PORTS" "$TARGET" -oN "$OUTPUT_FILE"
```

T0 (Paranoid) to T5 (Insane); higher is faster but noisier.

#### 7. Scan via Proxy

```bash
nmap -p "$PORTS" "$TARGET" --proxies "$PROXY" -oN "$OUTPUT_FILE"
```

#### 8. Custom User-Agent for HTTP Scripts

```bash
nmap -p 80 --script http-useragent-tester --script-args "http.useragent=$USER_AGENT" "$TARGET" -oN "$OUTPUT_FILE"
```

#### 9. Output Only Open Ports

```bash
nmap -p "$PORTS" --open "$TARGET" -oN "$OUTPUT_FILE"
```

***

### V. Real-World Workflow Example

1. Export Variables:

```bash
export TARGET="10.10.10.10"
export PORTS="22,80,443,3389"
export OUTPUT_DIR="nmap_scans"
```

2. Host Discovery:

```bash
nmap -sn "$TARGET/24" -oN "$OUTPUT_DIR/hosts.txt"
```

3. Full Port Scan:

```bash
nmap -p- "$TARGET" -oN "$OUTPUT_DIR/full.txt"
```

4. Service & Version Detection:

```bash
nmap -sV -p "$PORTS" "$TARGET" -oN "$OUTPUT_DIR/services.txt"
```

5. Vulnerability Scan with NSE:

```bash
nmap --script vuln -p "$PORTS" "$TARGET" -oN "$OUTPUT_DIR/vuln.txt"
```

6. Aggressive Scan:

```bash
nmap -A "$TARGET" -oN "$OUTPUT_DIR/aggressive.txt"
```

***

### VI. Pro Tips & Best Practices

* Start with host discovery and focused scans before escalating.
* Use NSE scripts for automated vulnerability checks and custom tasks.
* Tune timing and stealth options to avoid detection.
* Always save output for documentation and reporting.
* Combine Nmap with other tools (Nikto, Metasploit) for deeper analysis.
* Scan only with explicit authorization.
* Update Nmap regularly for new scripts and features.

***

### VII. Troubleshooting & OPSEC

* False positives/negatives: Adjust timing, retries, and scan types.
* Firewall/IDS evasion: Use stealth scans, decoys, fragmentation, and spoofing.
* Legal compliance: Scan only within scope and with permission.
* Output management: Use multiple formats for parsing and reporting.

***

This professional Nmap guide equips you for advanced network mapping, vulnerability assessment, and stealthy reconnaissance in real-world penetration testing workflows.

1. [https://www.esecurityplanet.com/products/nmap/](https://www.esecurityplanet.com/products/nmap/)
2. [https://nmap.org/book/nmap-overview-and-demos.html](https://nmap.org/book/nmap-overview-and-demos.html)
3. [https://securemyorg.com/mastering-nmap/](https://securemyorg.com/mastering-nmap/)
4. [https://cyberfrat.com/how-to-use-nmap-commands-for-penetration-testing/](https://cyberfrat.com/how-to-use-nmap-commands-for-penetration-testing/)
5. [https://www.youtube.com/watch?v=wlqUO09J-nw](https://www.youtube.com/watch?v=wlqUO09J-nw)
6. [https://labex.io/tutorials/nmap-how-to-use-nmap-in-penetration-testing-420718](https://labex.io/tutorials/nmap-how-to-use-nmap-in-penetration-testing-420718)
7. [https://nmap.org/book/nse-usage.html](https://nmap.org/book/nse-usage.html)
