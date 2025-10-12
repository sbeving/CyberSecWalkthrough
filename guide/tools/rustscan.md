---
icon: rust
---

# RustScan

## RustScan Professional Guide: Fast Hybrid Scanning with Nmap Integration

RustScan is a modern, ultra-fast port scanner designed for rapid reconnaissance. Its key strength is speed—scanning all 65,535 ports in seconds—and its seamless ability to automatically hand off discovered open ports to Nmap for detailed service and vulnerability enumeration.

***

### Core Capabilities & Workflow

* **Lightning-Fast Port Scanning:** RustScan can scan thousands of ports per second, making it ideal for initial reconnaissance.
* **Automatic Nmap Integration:** After identifying open ports, RustScan can automatically launch Nmap to perform service/version detection and script scanning on just those ports.
* **Flexible Targeting:** Supports single IPs, hostnames, CIDR ranges, and input files.
* **Customizable Output:** Greppable, JSON, and standard output formats for easy parsing and automation.
* **Resource Control:** Adjustable batch size and ulimit for large-scale scans.

***

### Fast Hybrid Scan: RustScan + Nmap

This is the most efficient workflow for both speed and depth:

```bash
rustscan -a <target> -- -sC -sV
```

* `a <target>` specifies the target IP or hostname.
* `-` passes all following arguments directly to Nmap.
* `sC -sV` tells Nmap to run default scripts and service/version detection on the open ports found by RustScan.

**Example:**

```bash
rustscan -a 10.10.10.5 -- -sC -sV
```

This command will:

1. Rapidly scan all ports on 10.10.10.5.
2. Automatically launch Nmap to enumerate services and run scripts only on the open ports, saving significant time.

***

### Advanced Usage

*   **Scan a specific port range:**

    ```bash
    rustscan -a <target> -r 1-1000 -- -sC -sV
    ```
*   **Increase speed for large targets:**

    ```bash
    rustscan -a <target> --ulimit 5000 -- -sC -sV
    ```
*   **Output in greppable format:**

    ```bash
    rustscan -a <target> -g
    ```
*   **Scan multiple targets from a file:**

    ```bash
    rustscan -a targets.txt -- -sC -sV
    ```

***

### Pro Tips

* Use RustScan for the initial sweep, then let Nmap handle the heavy lifting for service and vulnerability detection.
* Adjust `-ulimit` and batch size for very large scans or high-performance environments.
* For stealth, reduce batch size and avoid aggressive Nmap scripts.
* Integrate RustScan into automation pipelines for rapid asset discovery and triage.

***

### Summary

For the fastest and most effective port and service enumeration, use RustScan to identify open ports and immediately hand off to Nmap for detailed analysis. This hybrid approach maximizes both speed and depth, making it ideal for penetration testing, CTFs, and bug bounty reconnaissance.

**Example hybrid command:**

```bash
rustscan -a <target> -- -sC -sV
```

This single line gives you a complete, efficient scan—combining the best of both tools.

1. [https://www.hackingarticles.in/rustscan-network-scanner-detailed-guide/](https://www.hackingarticles.in/rustscan-network-scanner-detailed-guide/)
2. [https://github.com/bee-san/RustScan](https://github.com/bee-san/RustScan)
3. [https://www.scribd.com/document/867383625/A-Detailed-Guide-on-RustScan-1748268863](https://www.scribd.com/document/867383625/A-Detailed-Guide-on-RustScan-1748268863)
4. [https://pentestguy.com/a-detailed-guide-to-rustscan/](https://pentestguy.com/a-detailed-guide-to-rustscan/)
5. [https://cyberpress.org/rustscan/](https://cyberpress.org/rustscan/)
6. [https://matthewomccorkle.github.io/day\_044\_rustscan/](https://matthewomccorkle.github.io/day_044_rustscan/)
7. [https://techyrick.com/rustscan-full-tutorial/](https://techyrick.com/rustscan-full-tutorial/)
8. [https://github.com/RustScan/RustScan/wiki/Usage](https://github.com/RustScan/RustScan/wiki/Usage)
