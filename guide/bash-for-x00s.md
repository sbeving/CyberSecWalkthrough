---
icon: dollar-sign
---

# Bash for \x00's

### The Ultimate Bash Scripting Handbook for CTFs: Conquer the Command Line

Bash scripting is an invaluable skill for CTF participants. Automating tasks, interacting with tools, parsing data, and manipulating files – Bash empowers you to conquer challenges with efficiency and precision. This comprehensive handbook explores the depths of Bash scripting for CTFs, covering a wide range of techniques and scenarios.

**I. Core Concepts:**

* **Shell:** The command-line interpreter (e.g., Bash).
* **Commands:** Instructions executed by the shell (e.g., `ls`, `grep`, `awk`).
* **Variables:** Store data (strings, numbers, etc.).
* **Control Flow:** `if`, `for`, `while`, `case` – control the execution of your script.
* **Functions:** Reusable blocks of code.
* **Input/Output Redirection:** `<` (input), `>` (output), `>>` (append), `|` (pipe).
* **Pipes:** Connect the output of one command to the input of another.

**II. Essential Bash Commands for CTFs:**

1. **File Manipulation:**
   * `ls`: List files and directories.
   * `cd`: Change directory.
   * `mkdir`: Create directory.
   * `rm`: Remove files or directories.
   * `cp`: Copy files or directories.
   * `mv`: Move or rename files or directories.
   * `cat`: Display 1 file contents. &#x20;
   * `head`: Display the first few lines of a file.
   * `tail`: Display the last few lines of a file.
   * `less`: View file contents one page at a time.
   * `touch`: Create an empty file or update file timestamp.
2. **Text Processing:**
   * `grep`: Search for patterns in text.
   * `awk`: Powerful text processing tool.
   * `sed`: Stream editor for text manipulation.
   * `cut`: Extract parts of lines.
   * `sort`: Sort lines of text.
   * `uniq`: Remove duplicate lines.
   * `tr`: Translate or delete characters.
3. **Networking:**
   * `ping`: Test network connectivity.
   * `curl`: Transfer data with URLs.
   * `wget`: Download files from the web.
   * `netcat (nc)`: Network utility for reading and writing data across network connections.
   * `nmap`: Network scanner. (Covered in a separate manual)
4. **System Information:**
   * `uname`: Display system information.
   * `whoami`: Display current user.
   * `pwd`: Print working directory.
   * `ps`: List processes.
   * `top` or `htop`: Display system resource usage.
5. **Encoding/Decoding:**
   * `base64`: Base64 encode/decode.
   * `urlencode`: URL encode.
6. **Cryptography:**
   * `openssl`: Command-line tool for cryptographic operations.
7. **Automation:**
   * `find`: Search for files and directories.
   * `xargs`: Build and execute command lines from standard input.

**III. Bash Scripting Basics:**

8. **Shebang:** `#!/bin/bash` (tells the system which interpreter to use).
9.  **Variables:**

    Bash

    ```
    name="John"
    echo "Hello, $name!"
    ```
10. **Command Substitution:**

    Bash

    ```
    date=$(date)
    echo "The date is: $date"
    ```
11. **Arithmetic Expansion:**

    Bash

    ```
    x=10
    y=20
    z=$((x + y))
    echo "The sum is: $z"
    ```
12. **Conditional Statements:**

    Bash

    ```
    if [ $x -gt $y ]; then
        echo "$x is greater than $y"
    elif [ $x -lt $y ]; then
        echo "$x is less than $y"
    else
        echo "$x is equal to $y"
    fi
    ```
13. **Loops:**
    *   `for` loop:

        Bash

        ```
        for i in {1..10}; do
            echo $i
        done

        for file in *.txt; do
            echo $file
        done
        ```
    *   `while` loop:

        Bash

        ```
        i=0
        while [ $i -lt 10 ]; do
            echo $i
            i=$((i + 1))
        done
        ```
14. **Functions:**

    Bash

    ```
    greet() {
        echo "Hello, $1!"
    }

    greet "John"
    ```
15. **Input/Output Redirection:**

    Bash

    ```
    cat input.txt  # Read from input.txt
    ls -l > output.txt  # Write to output.txt
    ls -l >> output.txt # Append to output.txt
    command1 | command2  # Pipe output of command1 to command2
    ```
16. **Case Statements:**

    Bash

    ```
    case $variable in
        value1)
            echo "Value 1"
            ;;
        value2)
            echo "Value 2"
            ;;
        *)
            echo "Default value"
            ;;
    esac
    ```

**IV. Advanced Bash Scripting for CTFs:**

17. **Regular Expressions:**

    Bash

    ```
    grep "pattern" file.txt
    awk '/pattern/ {print $1}' file.txt
    sed 's/old/new/g' file.txt
    ```
18. **Working with URLs:**

    Bash

    ```
    url="http://example.com/path?param1=value1&param2=value2"
    echo $url | cut -d '?' -f 2  # Extract query string
    echo $url | sed 's/\?.*//' # Extract base URL
    ```
19. **Encoding/Decoding:**

    Bash

    ```
    echo "data" | base64  # Base64 encode
    echo "ZGF0YQ==" | base64 -d  # Base64 decode
    echo "value with spaces" | urlencode  # URL encode (requires `urlencode` command)
    ```
20. **Networking:**

    Bash

    ```
    nc -nvlp 8080  # Listen on port 8080
    nc 192.168.1.1 80  # Connect to port 80
    curl http://example.com  # Make a web request
    ```
21. **Automation:**

    Bash

    ```
    for i in {1..100}; do
        curl "http://example.com/page/$i"
    done
    ```
22. **File Processing:**

    Bash

    ```
    while read line; do
        echo "Processing: $line"
    done < input.txt
    ```
23. **Subshells:**

    Bash

    ```
    ( cd /tmp; ls )  # Changes directory in a subshell
    ```
24. **Signal Handling:**

    Bash

    ```
    trap "echo 'Exiting...'" INT  # Handle Ctrl+C
    ```

**V. Examples for CTFs:**

25. **Brute-forcing a web directory:**

    Bash

    ```
    for dir in $(cat directories.txt); do
        curl "http://example.com/$dir" 2>/dev/null | grep "200 OK"
    done
    ```
26. **Decoding a base64 encoded string:**

    Bash

    ```
    echo "encoded_string" | base64 -d
    ```
27. **Finding a specific string in a large file:**

    Bash

    ```
    grep "flag" large_file.txt
    ```
28. **Automating interactions with a program:**

    Bash

    ```
    ./vulnerable_program << EOF
    input1
    input2
    EOF
    ```
29. **Port scanning with Nmap and processing the output:**

    Bash

    ```
    nmap 192.168.1.1 -oG - | grep "open" | awk '{print $2}'
    ```

**VI. Tips for CTFs:**

* **Practice:** Write lots of scripts! The more you practice, the more comfortable you'll become.
* **Read Writeups:** Learn from other people's solutions.
* **Use Functions:** Break down your scripts into reusable functions.
* **Be Modular:** Make your scripts easy to modify and extend.
* **Comment Your Code:** Explain what your script does. This will help you and others understand it later.
* **Use `set -x` for Debugging:** This will
