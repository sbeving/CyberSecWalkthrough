# A Comprehensive Guide

Wfuzz is a powerful, open-source web application fuzzer. It's designed to be highly flexible and customizable, allowing users to perform various types of attacks, including brute-force, fuzzing, and web crawling. Wfuzz provides an excellent platform for testing web applications for different vulnerabilities and misconfigurations. This guide provides an overview of its capabilities, arguments, and practical examples.

## Wfuzz Basics

*   **Target Specification:** Wfuzz targets web applications, allowing you to specify URLs, headers, and request data.
*   **Fuzzing:** It uses wordlists, payloads, and custom logic to test different inputs in the web application.
*   **Output:** Results are presented in real time, with different options for filtering and saving the output.

## Core Wfuzz Arguments and Options

Here's a breakdown of the most important arguments and options in Wfuzz:

1.  **`<url>`:** Specifies the target URL, where you will put the fuzzer placeholder `FUZZ`
    *   **Example:** `wfuzz -w wordlist.txt http://example.com/FUZZ`

2.  **`-w <wordlist>` / `--wordlist=<wordlist>`:** Specifies a wordlist to be used in the fuzzing, can be a list of files or a single file.
   *   **Example:** `wfuzz -w wordlist.txt http://example.com/FUZZ`

3.  **`-c` / `--color`:** Enables coloured terminal output.
    *  **Example:** `wfuzz -w wordlist.txt -c http://example.com/FUZZ`

4.  **`-z <payload>` / `--payload=<payload>`:** Specify payloads.
    * Use the format: `<encoder>,<payload>,<encoder2>` for using multiple encoders, and/or multiple payloads.
    *   **Example:** `wfuzz -w wordlist.txt  -z "file,payloads.txt" -z "enc,payload2,enc2" http://example.com/FUZZ`

5. **`-b <cookie>` / `--cookie=<cookie>`:** Specify a cookie to be sent.
    *  **Example:** `wfuzz -w wordlist.txt -b "sessionid=12345" http://example.com/FUZZ`

6. **`-H <header>` / `--header=<header>`:** Specify custom headers for the requests.
    *   **Example:** `wfuzz -w wordlist.txt -H "X-Custom-Header: test" http://example.com/FUZZ`

7.  **`-p <parameter>` / `--post=<parameter>`:** Specify POST data, use the format `<param_name>=FUZZ`, to fuzz the parameter.
    *   **Example:** `wfuzz -w wordlist.txt -p "user=FUZZ&pass=test" -m POST http://example.com/login`

8. **`-m <method>` / `--method=<method>`:** Choose between the methods `GET` or `POST`.
    *  **Example:** `wfuzz -w wordlist.txt -m POST -p "user=FUZZ&pass=test" http://example.com/login`

9.  **`--hc <status_code>`:** Hide results based on the HTTP status codes specified using a comma separated list.
     * **Example:** `wfuzz -w wordlist.txt --hc 404 http://example.com/FUZZ`

10. **`--hh <header-value>`:** Hide results based on the response headers content.
     *  **Example:** `wfuzz -w wordlist.txt --hh "Server: nginx"  http://example.com/FUZZ`

11.  **`--hl <length>`:** Hide results based on the response body length.
    *   **Example:** `wfuzz -w wordlist.txt --hl 10  http://example.com/FUZZ`

12.  **`-t <threads>` / `--threads=<threads>`:** Specify the number of concurrent threads to use during the scan.
    *   **Example:** `wfuzz -w wordlist.txt -t 20  http://example.com/FUZZ`

13. **`-s <sleep>` / `--sleep=<sleep>`:** Specify the sleep time between each request in seconds, useful for avoiding rate limits.
   * **Example:** `wfuzz -w wordlist.txt -s 1 http://example.com/FUZZ`

14. **`-o <output_file>` / `--output=<output_file>`:** Output the results to a file.
     *  **Example:** `wfuzz -w wordlist.txt -o output.txt http://example.com/FUZZ`

15. **`--hw <words>`:** Hide responses based on the number of words in the response body.
     *  **Example:** `wfuzz -w wordlist.txt --hw 10 http://example.com/FUZZ`

16. **`-v` / `--verbose`:** Show verbose output during the scan
     *  **Example:** `wfuzz -w wordlist.txt -v http://example.com/FUZZ`

17.  **`--timeout <seconds>`:** The timeout in seconds for each request.
    *   **Example:** `wfuzz -w wordlist.txt --timeout=10 http://example.com/FUZZ`

## Practical Wfuzz Examples

1.  **Basic directory brute-force:**

    ```bash
    wfuzz -w wordlist.txt http://example.com/FUZZ
    ```

2.  **Fuzzing a parameter:**

    ```bash
    wfuzz -w wordlist.txt  -p "id=FUZZ" http://example.com/product.php
    ```

3.  **Fuzzing for subdomains:**

    ```bash
    wfuzz -w subdomains.txt "http://FUZZ.example.com"
    ```

4.  **Fuzzing with custom headers:**

    ```bash
      wfuzz -w wordlist.txt -H "X-Custom: FUZZ" "http://example.com"
    ```

5.  **Fuzzing for files with extensions:**

    ```bash
    wfuzz -w wordlist.txt  -z "file,php,html" "http://example.com/FUZZ"
    ```

6. **Fuzz with multipe payloads**
    ```bash
   wfuzz -w wordlist.txt -z "file,payloads.txt" -z "enc,payload2,enc2" http://example.com/FUZZ
  ```

## Use Cases

*   **Web Application Penetration Testing:** Discovering hidden directories, files, and application logic vulnerabilities.
*   **Vulnerability Research:** Testing for various types of injection and security misconfigurations.
*   **Authentication Bypass:** Attempting to bypass login forms by brute-forcing credentials.
*   **Fuzzing APIs:** Testing APIs for different inputs that could cause unexpected behaviors.

## Conclusion

Wfuzz is a highly flexible and powerful tool for discovering web vulnerabilities. It's essential for penetration testers and security professionals who need a comprehensive and adaptable tool for web application security testing. Always remember to use security tools responsibly and ethically, and only against systems you have permission to test.

---
