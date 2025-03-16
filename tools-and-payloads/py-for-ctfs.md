---
icon: python
---

# Py for CTFs

### The Python for CTFs Handbook: Scripting Your Way to Victory

Python is an indispensable tool for CTF participants. Its versatility, extensive libraries, and ease of use make it perfect for automating tasks, crafting exploits, and solving a wide range of challenges. This handbook dives into Python's capabilities for CTFs, equipping you to script your way to victory.

**I. Core Concepts:**

* **Variables and Data Types:** Integers, floats, strings, lists, dictionaries – the building blocks of Python.
* **Control Flow:** `if`, `elif`, `else`, `for`, `while` – controlling the execution of your code.
* **Functions:** Reusable blocks of code.
* **Modules and Libraries:** Pre-built code for specific tasks (e.g., networking, cryptography).
* **Object-Oriented Programming (OOP):** Classes and objects for more complex programs (optional, but useful).

**II. Essential Libraries:**

1.  **`requests`:** For making HTTP requests (web challenges).

    Python

    ```
    import requests

    response = requests.get("http://example.com")
    print(response.text)

    data = {"key": "value"}
    response = requests.post("http://example.com/api", json=data)
    ```
2.  **`socket`:** For low-level network communication.

    Python

    ```
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 8080))
    s.sendall(b"Hello")
    data = s.recv(1024)
    s.close()
    ```
3.  **`struct`:** For packing and unpacking binary data (exploits, forensics).

    Python

    ```
    import struct

    packed_data = struct.pack("<i", 12345)  # Pack integer as little-endian
    unpacked_data = struct.unpack("<i", packed_data)[0]
    ```
4.  **`hashlib`:** For hashing algorithms (cryptography).

    Python

    ```
    import hashlib

    md5_hash = hashlib.md5(b"password").hexdigest()
    sha256_hash = hashlib.sha256(b"password").hexdigest()
    ```
5.  **`base64`:** For base64 encoding/decoding (cryptography, web).

    Python

    ```
    import base64

    encoded = base64.b64encode(b"data").decode()
    decoded = base64.b64decode(encoded).decode()
    ```
6.  **`re`:** For regular expressions (parsing, web).

    Python

    ```
    import re

    pattern = r"(\d+)-(\d+)-(\d+)"
    string = "2023-10-27"
    match = re.search(pattern, string)
    if match:
        year, month, day = match.groups()
    ```
7.  **`binascii`:** For converting between binary and ASCII representations.

    Python

    ```
    import binascii

    hex_data = binascii.hexlify(b"data").decode()
    binary_data = binascii.unhexlify(hex_data)
    ```
8.  **`pwn` (pwntools):** A powerful CTF framework (exploits). Install with: `pip install pwntools`

    Python

    ```
    from pwn import *

    r = remote("127.0.0.1", 8080)  # Connect to a remote service
    r.sendline(b"payload")
    shellcode = asm(shellcraft.sh()) # Assemble shellcode
    r.send(shellcode)
    r.interactive()
    ```

**III. Common CTF Tasks and Examples:**

1.  **Web Requests:**

    Python

    ```
    import requests

    url = "http://example.com/api"
    data = {"param1": "value1", "param2": "value2"}

    response = requests.post(url, data=data)  # POST request
    response = requests.get(url, params=data)  # GET request with parameters

    if response.status_code == 200:
        print(response.text)
        json_data = response.json()  # If the response is JSON
    ```
2.  **HTML Parsing (Beautiful Soup):** Install with: `pip install beautifulsoup4`

    Python

    ```
    from bs4 import BeautifulSoup
    import requests

    response = requests.get("http://example.com/page")
    soup = BeautifulSoup(response.content, "html.parser")

    title = soup.title.string
    links = [a.get("href") for a in soup.find_all("a")]
    ```
3.  **Regular Expressions:**

    Python

    ```
    import re

    log_file = "access.log"
    with open(log_file, "r") as f:
        for line in f:
            match = re.search(r"IP: (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ip_address = match.group(1)
                print(ip_address)
    ```
4.  **Encoding/Decoding:**

    Python

    ```
    import base64

    encoded = base64.b64encode(b"flag").decode()
    decoded = base64.b64decode(encoded).decode()

    # URL encoding/decoding
    import urllib.parse
    encoded = urllib.parse.quote("value with spaces")
    decoded = urllib.parse.unquote(encoded)
    ```
5.  **Cryptography:**

    Python

    ```
    import hashlib

    password = "password123"
    md5_hash = hashlib.md5(password.encode()).hexdigest()

    import base64
    encoded = base64.b64encode(b"secret").decode()
    ```
6.  **File I/O:**

    Python

    ```
    with open("flag.txt", "r") as f:
        flag = f.read().strip()

    with open("output.txt", "w") as f:
        f.write("Result: " + flag)
    ```
7.  **Automation:**

    Python

    ```
    import subprocess

    # Run a command and capture the output
    result = subprocess.run(["ls", "-l"], capture_output=True, text=True)
    print(result.stdout)

    # Interact with a program
    process = subprocess.Popen(["./vulnerable_program"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    output, _ = process.communicate(b"input\n")
    print(output.decode())
    ```
8.  **Binary Exploitation (pwntools):**

    Python

    ```
    from pwn import *

    # Connect to the target
    r = remote('target_ip', 1337)

    # Send a payload
    payload = b"A" * 100 + p64(0x401000) # Example: Overwrite return address
    r.sendline(payload)

    # Interactive shell
    r.interactive()
    ```

**IV. Tips for CTFs:**

* **Practice:** The more you code, the better you'll become. Solve old CTF challenges to build your skills.
* **Read Writeups:** Learn from other people's solutions.
* **Use Libraries:** Don't reinvent the wheel. Leverage the power of Python's libraries.
* **Debug:** Use `print()` statements or a debugger to understand what your code is doing.
* **Be Resourceful:** Search for solutions online. The CTF community is a great resource.
* **Combine Tools:** Python can be used to automate interactions with other tools (e.g., Nmap, SQLMap).
