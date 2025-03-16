
# A Comprehensive Guide

Nikto is a powerful, open-source web server vulnerability scanner. It's designed to scan web servers and identify various vulnerabilities, misconfigurations, and security issues. Nikto performs thorough scans, checking for outdated server software, dangerous files, and common vulnerabilities. This document will provide a detailed guide covering Nikto's functionalities, arguments, and use cases.

## Nikto Basics

*   **Target Specification:** Nikto targets web servers and applications. You can specify the target using a URL or IP address.
*   **Vulnerability Scanning:** Nikto uses a large database of known vulnerabilities, checks, and exploits to detect security issues.
*   **Output:** Results are presented in a clear, well-structured format, and can be saved to files.

## Core Nikto Arguments and Options

Here’s a breakdown of the most commonly used arguments and options:

1.  **`-h <target>` / `--host=<target>`:** Specifies the target host (URL or IP address). This is the primary option for pointing Nikto to the web server.
    *   **Example:** `nikto -h http://example.com`

2.  **`-p <port>` / `--port=<port>`:** Specifies the target port. By default, Nikto uses ports 80 for HTTP and 443 for HTTPS.
    *   **Example:** `nikto -h http://example.com -p 8080`

3.  **`-u <username:password>` / `--id=<username:password>`:** Specifies username and password for basic authentication.
    *   **Example:** `nikto -h http://example.com -u admin:password`

4.  **`-o <output_file>` / `--output=<output_file>`:** Specify the path to output file, in various formats (-Format)
      * **Example:** `nikto -h http://example.com -o output.txt -Format txt`

5.  **`-C all` / `--CgiDir=all`:** Force checks to include CGI directories. By default, Nikto skips specific CGI directory tests.
     *   **Example:** `nikto -h http://example.com -C all`

6.  **`-ssl`:** Forces Nikto to use SSL when scanning a target.
    *   **Example:** `nikto -h http://example.com --ssl`

7. **`-t <tuning_option>` / `--tuning=<tuning_option>`:** Specify how to tune the scan, based on the following list:
    *   0: File Upload
    *   1: Interesting File/Seen in logs
    *   2: Misconfiguration/Default File
    *   3: Information Disclosure
    *   4: SQL Injection
    *   5: Remote File Inclusion
    *   6: Cross-Site Scripting
    *   7: Command Injection
    *   8: Shellshock
    *   9: HTTPS checks
    *   a: All tunings
   *  **Example:** `nikto -h http://example.com -t 1,2,3`

8.  **`-D <dbcheck>` / `--dbcheck=<dbcheck>`:** Database to check, using: `all`, `apache`, `cisco`, `iis`, and `nginx`
   *   **Example:** `nikto -h http://example.com -D apache`

9. **`-F <format>` / `--Format=<format>`:** Sets the output format.
    * Available format are: `txt`, `xml`, `csv`
    * **Example:** `nikto -h http://example.com -o output.xml -Format xml`

10.  **`-v` / `--verbose`:** Enables verbose output to provide more detailed information during a scan.
    *   **Example:** `nikto -h http://example.com -v`

11. **`-T <timeout>` / `--timeout=<timeout>`:** Set timeout for each request in seconds
     *  **Example:** `nikto -h http://example.com -T 10`

## Practical Nikto Examples

1.  **Basic scan of a single host:**

    ```bash
    nikto -h http://example.com
    ```

2.  **Scan a specific port using SSL:**

    ```bash
    nikto -h https://example.com -p 8443
    ```

3.  **Scan a web server using authentication:**

    ```bash
    nikto -h http://example.com -u admin:password
    ```

4.  **Scan using specific tunings:**

    ```bash
      nikto -h http://example.com -t 3,4,6
    ```

5.  **Output results to an XML file:**

    ```bash
    nikto -h http://example.com -o output.xml -Format xml
    ```
6. **Perform check for specific database:**
  ```bash
   nikto -h http://example.com -D apache
  ```

## Use Cases

*   **Web Application Security Auditing:** Identifying vulnerabilities and misconfigurations in web servers and applications.
*   **Penetration Testing:** Gathering information about a web server's security posture before further exploitation.
*   **Vulnerability Research:** Discovering known vulnerabilities in specific web server configurations.
*   **Automated Scanning:** Integrating into security tools for continuous vulnerability assessments.

## Conclusion

Nikto is a valuable tool for discovering vulnerabilities and misconfigurations in web servers. Its comprehensive checks and ease of use make it a critical component of security assessments. Always remember to use ethical practices and obtain proper authorization before testing systems.

---
