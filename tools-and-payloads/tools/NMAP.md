# Nmap Scan Types: A Comprehensive Guide

Nmap (Network Mapper) is a powerful and versatile network scanning tool. It's used for various tasks, including network discovery, security auditing, and identifying open ports and services. This document explains some of the most commonly used Nmap scan types, their purposes, arguments, and practical examples.

## Nmap Basics

Before diving into scan types, let's cover a few basics:

*   **Target Specification:** You specify the target using IP addresses, hostnames, or CIDR notation.
    *   Example: `192.168.1.100`, `scanme.nmap.org`, `192.168.1.0/24`
*   **Port Specification:** You can specify which ports to scan, or leave the default ports scanned.
    *   Example: `-p 80,443` (scan ports 80 and 443) or `-p-` (scan all ports)
*   **Output:** Nmap can output results in various formats, including human-readable output (default), XML, JSON, and grepable formats.

## Common Nmap Scan Types

Here's a breakdown of different scan types, categorized for clarity:

### TCP Connection Scans
These scans attempt to establish a full TCP connection with the target, making them the most reliable and easiest to detect.

1.  **TCP Connect Scan (-sT)**
    *   **Description:** Completes a full TCP handshake (SYN, SYN-ACK, ACK) for each port.
    *   **Use Cases:**
        *   Identifying open TCP ports.
        *   General port scanning without advanced evasion techniques.
        *   Suitable when you cannot use SYN scans (e.g., lack of raw socket privileges).
    *   **Arguments:**
        *   `-sT`: Enables TCP connect scan.
    *   **Example:** `nmap -sT 192.168.1.100`

2.  **TCP SYN Scan (-sS)**
    *   **Description:** A "half-open" scan; Nmap sends a SYN packet and checks for SYN-ACK. A SYN-ACK indicates an open port, and Nmap doesn't complete the 3-way handshake, which avoids logging in most applications, and allows for faster scans than TCP connect.
    *   **Use Cases:**
        *   Fast and relatively stealthy port scanning.
        *   Identifying open TCP ports.
        *   Preferred over `-sT` when possible.
    *   **Arguments:**
        *   `-sS`: Enables TCP SYN scan.
    *   **Example:** `nmap -sS 192.168.1.100`

3.  **TCP ACK Scan (-sA)**
    *   **Description:** Sends a TCP ACK packet to the target. It's primarily used to map out firewall rule sets.
    *   **Use Cases:**
        *   Identifying firewall rules and filtering.
        *   Determining if a port is filtered.
    *   **Arguments:**
        *   `-sA`: Enables TCP ACK scan.
    *   **Example:** `nmap -sA 192.168.1.100`

### UDP Scans
UDP scans are used to discover open UDP ports, but are less reliable than TCP scans.

4.  **UDP Scan (-sU)**
    *   **Description:** Sends UDP packets to the specified ports. When a UDP port is open, most applications will not respond, if the port is closed Nmap may receive an ICMP unreachable packet.
    *   **Use Cases:**
        *   Identifying open UDP ports.
        *   Scanning for UDP services like DNS, DHCP, and SNMP.
    *   **Arguments:**
        *   `-sU`: Enables UDP scan.
    *   **Example:** `nmap -sU 192.168.1.100`

### Other Scan Types

5.  **FIN Scan (-sF)**
    *   **Description:** Sends a TCP FIN packet to a port, it's used to bypass firewalls and identify open or filtered ports.
    *   **Use Cases:**
        *   Bypassing some firewalls.
        *   Identifying open ports on specific operating systems
        *   When TCP scan is not possible
    *   **Arguments:**
        *   `-sF`: Enables FIN scan.
    *   **Example:** `nmap -sF 192.168.1.100`

6.  **Null Scan (-sN)**
    *   **Description:** Sends a TCP packet with no flags set (FIN, URG, or PSH). It's similar to the FIN scan, and used for similar use cases.
    *   **Use Cases:**
        *   Identifying open ports on specific operating systems
        *   Bypassing some firewalls.
    *   **Arguments:**
        *   `-sN`: Enables Null scan.
    *   **Example:** `nmap -sN 192.168.1.100`

7.  **Xmas Scan (-sX)**
     *  **Description:** Sends a TCP packet with the FIN, URG, and PSH flags set, and it is similar to the FIN and NULL scans.
    *  **Use Cases:**
        *   Identifying open ports on specific operating systems
        *   Bypassing some firewalls.
    *  **Arguments:**
        *   `-sX`: Enables Xmas scan.
    *  **Example:** `nmap -sX 192.168.1.100`

8.  **Version Detection (-sV)**
    *   **Description:** Attempts to determine the service and version running on open ports. This can provide valuable information on potential vulnerabilities.
    *   **Use Cases:**
        *   Identifying applications and versions running on open ports.
        *   Assessing known vulnerabilities based on version information.
    *   **Arguments:**
        *   `-sV`: Enables version detection.
    *   **Example:** `nmap -sV 192.168.1.100`

9. **Operating System Detection (-O)**
    *   **Description:** Attempts to identify the target operating system, by using multiple methods to fingerprint the OS based on its responses.
    *   **Use Cases:**
        *  Identify the operating system of a target for better attack vectors.
    *   **Arguments:**
         *   `-O`: Enables operating system detection.
    *  **Example:** `nmap -O 192.168.1.100`

10.  **Traceroute (--traceroute)**
    *   **Description:** Performs a traceroute to a host and identifies the hop and number of the network route.
    *   **Use Cases:**
        *  Identify the path to a specific target and the networks used by the target.
    *   **Arguments:**
         * `--traceroute`: Enables trace route.
    *  **Example:** `nmap --traceroute 192.168.1.100`

### Host Discovery

11. **Ping Scan (-sn)**
    *   **Description:** A fast scan to identify live hosts on a network without scanning ports. It uses ICMP ping, or other methods to check if the target is active.
    *   **Use Cases:**
        *   Quickly discover active hosts on a network.
    *   **Arguments:**
        *   `-sn`: Enables ping scan.
        *   `-PE`: Enables ICMP ping scan.
    *   **Example:** `nmap -sn 192.168.1.0/24`
       *   `nmap -PE 192.168.1.0/24`

### Other important options

* **Verbose Output (-v)**: Shows verbose output during the scan
* **Timing Options (-T<0-5>):** Allows you to configure the speed of the scan
    * `-T0` is the slowest and `-T5` is the fastest. The default is `-T3`

   * **Output File (-oN, -oX, -oG, -oJ):** Output the result in a specific file using a specific format
     * Example `-oN output.txt`, `-oX output.xml`, `-oG output.grepable`, `-oJ output.json`

## Practical Nmap Examples

1.  **Basic SYN scan on a single host:**

    ```bash
    nmap -sS 192.168.1.100
    ```
2. **Scan all ports on a single host:**
   ```bash
   nmap -p- 192.168.1.100
   ```
3.  **Version detection on common ports of a network:**

    ```bash
    nmap -sV -p 21,22,23,80,443,3389 192.168.1.0/24
    ```

4.  **OS detection:**
    ```bash
    nmap -O 192.168.1.100
    ```
5. **Ping scan a network:**
    ```bash
    nmap -sn 192.168.1.0/24
    ```
6. **Saving output to a json file:**
    ```bash
     nmap -sS -oJ output.json 192.168.1.100
    ```
## Conclusion

Nmap is an extremely powerful tool with numerous options for scanning and discovery. Understanding the different scan types and how to use them is essential for any security professional. This guide provides a comprehensive introduction to the most commonly used scans, allowing you to use Nmap effectively. Remember to use Nmap responsibly and ethically.

**Disclaimer:** _Use these commands responsibly and only against targets you have permission to scan. Unauthorised scanning can have legal consequences._

---
