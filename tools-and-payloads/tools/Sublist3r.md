

# A Comprehensive Guide

Sublist3r is a powerful, open-source subdomain enumeration tool that helps penetration testers and security researchers discover subdomains of a given domain. It gathers subdomains from a wide range of sources, including search engines, DNS records, and brute-forcing techniques. This document provides an overview of Sublist3r's capabilities, core arguments, and practical use cases.

## Sublist3r Basics

*   **Subdomain Enumeration:** Sublist3r focuses on identifying subdomains associated with a target domain.
*   **Multiple Sources:** It uses various sources, including search engines (Google, Bing, Yahoo), DNS records, Netcraft, and VirusTotal.
*   **Brute-Forcing:** It also includes basic brute-forcing capabilities for subdomain discovery.
*   **Output:** Results are presented in a clear, concise format, and can be saved to files.

## Core Sublist3r Arguments and Options

Here's a breakdown of the most important arguments and options in Sublist3r:

1.  **`<domain>`:** Specifies the target domain for subdomain enumeration.
    *   **Example:** `sublist3r -d example.com`

2. **`-b` / `--bruteforce`:** Enables brute forcing using a wordlist.
    * **Example:** `sublist3r -d example.com -b`

3.  **`-p` / `--ports`:** Perform a portscan of the hosts, this can be used to check if the host has an open port and is reachable.
      * **Example:** `sublist3r -d example.com -p`

4. **`-o <output_file>` / `--output=<output_file>`:** Output the results to a text file.
      * **Example:** `sublist3r -d example.com -o output.txt`

5. **`-e <engines>` / `--engines=<engines>`:** Specify the search engines to be used (comma separated). Some available engines are: `google`, `bing`, `yahoo`, `ask`, `baid` and more.
   * **Example:** `sublist3r -d example.com -e google,bing`

6.  **`-v` / `--verbose`:** Enables verbose output.
   *  **Example:** `sublist3r -d example.com -v`
7. **`-n` / `--nocolor`:** Disable color output in the terminal.
   *  **Example:** `sublist3r -d example.com -n`

8. **`-t <threads>` / `--threads=<threads>`:** Specify the number of threads to use for the scan.
   * **Example:** `sublist3r -d example.com -t 20`

9. **`-a` / `--all`:** Enable all engines for the scan.
    * **Example:** `sublist3r -d example.com -a`

10. **`-i` / `--ip`:** Shows IP addresses of discovered subdomains.
     *  **Example:** `sublist3r -d example.com -i`
11. **`-s` / `--silent`:** Only show subdomains in output, and surpress all the other output.
     *  **Example:** `sublist3r -d example.com -s`

## Practical Sublist3r Examples

1.  **Basic subdomain enumeration for a specific domain:**

    ```bash
    sublist3r -d example.com
    ```

2. **Use multiple engines for subdomain enumeration:**

    ```bash
    sublist3r -d example.com -e google,bing,yahoo
    ```
3. **Brute force and port scan for subdomains:**
  ```bash
    sublist3r -d example.com -b -p
  ```

4.  **Output results to a text file:**

    ```bash
    sublist3r -d example.com -o output.txt
    ```

5.  **Show only subdomains in the output:**
     ```bash
     sublist3r -d example.com -s
    ```
6.  **Show IP addresses in the results:**
    ```bash
    sublist3r -d example.com -i
    ```

## Use Cases

*   **Penetration Testing:** Discovering subdomains of a target for expanded testing scope.
*   **Reconnaissance:** Mapping out the infrastructure of a target organization.
*   **Security Research:** Studying subdomain takeovers and other related vulnerabilities.
*   **Bug Bounty Programs:** Discovering subdomains for bug bounty hunting.

## Conclusion

Sublist3r is a very useful and effective tool for subdomain discovery. Its multiple data sources and ease of use makes it a valuable tool to use for security researchers and penetration testers. Remember to only perform testing on systems and applications that you are authorized to test.

---