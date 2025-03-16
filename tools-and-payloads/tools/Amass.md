# OWASP Amass: A Comprehensive Guide

OWASP Amass is a powerful, open-source tool used for performing network mapping of attack surfaces and performing reconnaissance. It helps security professionals and researchers discover assets that can be targeted, by gathering information about domains, subdomains, and network infrastructure. This document will provide a detailed overview of OWASP Amass's key features, arguments, and use cases.

## OWASP Amass Basics

*   **Attack Surface Mapping:** Amass is used for discovering all the external and attackable assets associated with an organization, like domains, IPs, ASN's, etc..
*   **Multiple Data Sources:** It uses numerous data sources for enumeration, including APIs, web scraping, DNS, and more.
*   **Active and Passive Recon:** It performs both active and passive techniques to map out the attack surface.
*   **Extensibility:** It has a modular design that allows for expansion and integrations.

## Core OWASP Amass Arguments and Options

Here's a breakdown of the most important arguments and options in OWASP Amass:

1.  **`enum`:** Enables the enumeration of the target domain, and gathers information using a variety of sources.
     * **Example:** `amass enum -d example.com`

2.  **`-d <domain>` / `--domain=<domain>`:** Specifies the target domain for enumeration.
    *   **Example:** `amass enum -d example.com`

3.  **`-passive`:** Only perform passive scanning, which means that the tool does not actively probe the network.
    *   **Example:** `amass enum -d example.com -passive`

4. **`-active`:** Perform active scanning, which includes direct probing, DNS lookups and similar techniques.
   * **Example:** `amass enum -d example.com -active`

5.  **`-brute`:** Enable brute-forcing of subdomains using a wordlist.
     *  **Example:** `amass enum -d example.com -brute`

6.  **`-w <wordlist>` / `--wordlist=<wordlist>`:** Specifies the wordlist used for subdomain brute-forcing.
     *  **Example:** `amass enum -d example.com -brute -w subdomains.txt`

7. **`-o <output_file>` / `--output=<output_file>`:** Output the results to the specified file.
   * **Example:** `amass enum -d example.com -o output.txt`

8. **`-config <file>` / `--config=<file>`:** Loads options from a config file.
   * **Example:** `amass enum -d example.com -config config.yaml`

9.  **`-v` / `--verbose`:** Enables verbose output.
    *   **Example:** `amass enum -d example.com -v`

10. **`-include <ip/net>`:** Only return results that matches a specific IP address or network.
     *  **Example:** `amass enum -d example.com -include 192.168.1.0/24`

11.  **`-exclude <ip/net>`:** Exclude results matching an IP address or network.
      *   **Example:** `amass enum -d example.com -exclude 192.168.1.100`

12.  **`-asn <asn>`:** Filter the results by ASN number.
     *  **Example:** `amass enum -d example.com -asn 12345`

## Practical OWASP Amass Examples

1.  **Basic subdomain enumeration:**

    ```bash
    amass enum -d example.com
    ```

2. **Perform passive subdomain enumeration:**

  ```bash
   amass enum -d example.com -passive
  ```

3.  **Perform active subdomain enumeration:**

    ```bash
     amass enum -d example.com -active
    ```
4. **Perform subdomain brute forcing using specific wordlist:**
  ```bash
   amass enum -d example.com -brute -w subdomains.txt
  ```

5.  **Save the results in an output file:**

    ```bash
    amass enum -d example.com -o output.txt
    ```
6. **Use custom configuration with a configuration file:**
  ```bash
     amass enum -d example.com -config config.yaml
  ```
7. **Filter by IP address:**
   ```bash
     amass enum -d example.com -include 192.168.1.0/24
   ```

## Use Cases

*   **Penetration Testing:** Discovering potential attack surfaces by mapping out assets on the internet, such as subdomains.
*   **Reconnaissance:** Gathering information about a target organization before testing or attacking it.
*   **Attack Surface Management:** Tracking and managing internet facing assets of an organization.
*   **Vulnerability Management:** Identifying potential entry points into the network.

## Conclusion

OWASP Amass is a powerful tool for reconnaissance and attack surface mapping. Its detailed results and active and passive scanning makes it a valuable addition to any security professional's toolkit. Remember to only use this tool ethically, responsibly, and with the proper authorization.

---
