
# GoBuster: A Comprehensive Guide

GoBuster is a popular, open-source, command-line tool used for performing directory and file brute-force enumeration against web servers. It's designed to be fast and efficient, making it useful for quickly discovering hidden directories and files. This document will outline its functionality, arguments, and provide practical usage examples.

## GoBuster Basics

*   **Target URL:** GoBuster works by targeting a specific URL or web application endpoint.
*   **Wordlists:** It uses wordlists containing common directory and file names for brute-forcing.
*   **Output:** Results are displayed in real-time and can be saved to a text file.

## GoBuster Arguments and Options

Here's a breakdown of the most important arguments and options in GoBuster:

1.  **`dir`:** Enables directory brute-forcing mode.
2.  **`-u <url>` / `--url=<url>`:** Specifies the target URL.
    *   **Example:** `gobuster dir -u "http://example.com"`

3.  **`-w <wordlist>` / `--wordlist=<wordlist>`:** Specifies the path to the wordlist file to use for brute-forcing.
    *   **Example:** `gobuster dir -u "http://example.com" -w wordlist.txt`

4.  **`-x <extensions>` / `--extensions=<extensions>`:** Specifies file extensions to look for. Comma separated list.
    *   **Example:** `gobuster dir -u "http://example.com" -w wordlist.txt -x "php,html,txt"`

5. **`-s <status-code>` / `--status=<status-code>`:** Specify which status codes to display, using comma separated list.
   * **Example:** `gobuster dir -u "http://example.com" -w wordlist.txt -s "200,301,302,307"`

6.  **`-t <threads>` / `--threads=<threads>`:** Sets the number of concurrent threads to use for scanning.
    *   **Example:** `gobuster dir -u "http://example.com" -w wordlist.txt -t 20`

7.  **`-o <output_file>` / `--output=<output_file>`:** Output the results to a text file.
    *   **Example:** `gobuster dir -u "http://example.com" -w wordlist.txt -o output.txt`

8.  **`-e` / `--expanded`:** Show full URLs and not only the paths
     *   **Example:** `gobuster dir -u "http://example.com" -w wordlist.txt -e`

9.  **`-z` / `--wildcard`:** Do a wildcard search, useful for testing when getting only 404 responses.
    *    **Example:** `gobuster dir -u "http://example.com" -w wordlist.txt -z`
10. **`-v` / `--verbose`:** Show verbose output during the scan
  *  **Example:** `gobuster dir -u "http://example.com" -w wordlist.txt -v`

11.  **`-q` / `--quiet`:** Suppress banner and other output.
  *  **Example:** `gobuster dir -u "http://example.com" -w wordlist.txt -q`
12.  **`-k` / `--skip-ssl-verify`:** Skip ssl verification.
     *  **Example:** `gobuster dir -u "https://example.com" -w wordlist.txt -k`
13. **`--timeout=<seconds>`:** The timeout in seconds for each request.
     *  **Example:** `gobuster dir -u "http://example.com" -w wordlist.txt --timeout=10`

## Practical GoBuster Examples

1.  **Basic directory brute-force:**

    ```bash
    gobuster dir -u "http://example.com" -w wordlist.txt
    ```

2.  **Directory brute-force with specified extensions:**

    ```bash
    gobuster dir -u "http://example.com" -w wordlist.txt -x "php,html,txt"
    ```

3.  **Directory brute-force with threads and output to file:**

    ```bash
     gobuster dir -u "http://example.com" -w wordlist.txt -t 20 -o output.txt
    ```

4.  **Perform wildcard testing**

    ```bash
     gobuster dir -u "http://example.com" -w wordlist.txt -z
    ```

5.  **Check for specific status code, and show verbose output**

   ```bash
     gobuster dir -u "http://example.com" -w wordlist.txt -s "200,301,302" -v
   ```

## Use Cases

*   **Web Application Penetration Testing:** Discovering hidden directories, files, and other resources on a web server.
*   **Security Audits:** Identifying potential security misconfigurations through exposed directories.
*   **Reconnaissance:** Mapping the attack surface of web applications.
*   **Web Application Security Training:** Practical experience with brute-force enumeration techniques.

## Conclusion

GoBuster is an essential tool for web application security professionals. Its speed and efficiency make it a great option for brute-forcing directories and files. Use this tool responsibly and ethically, only against targets you have explicit permission to test.

---
