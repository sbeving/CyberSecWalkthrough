---
icon: users-medical
---

# SMBclient

## The SMBClient Masterclass: Professional SMB/CIFS Network Share Access & Enumeration

SMBClient is a versatile command-line tool included in the Samba suite that lets penetration testers, system administrators, and security professionals enumerate, access, and interact with SMB (Server Message Block) shares. It functions similarly to FTP but for SMB, enabling exploration of remote shares, file transfers, user and share enumeration, and scripted operations against Windows and Samba servers.

***

### I. Environment Setup: Dynamic Variables

Configure your environment variables for consistency and automation:

```bash
export TARGET_IP="192.168.1.100"
export SHARE_NAME="SharedDocs"
export USERNAME="john"
export PASSWORD="SuperSecret!"
export DOMAIN="CORP"
export OUTPUT_DIR="smbclient-results"
export COMMAND="ls"                  # SMBClient commands: ls, get, put, cd, etc.
export MOUNT_POINT="/mnt/smbshare"  # For persistent mounts (Linux)
export OPTIONS="-U $USERNAME -W $DOMAIN"

```

***

### II. Core Capabilities & Workflow

* **Enumerate SMB Shares:** List all available shares on a target server.
* **Connect and Browse Shares:** Interactive FTP-like prompt to navigate directories, upload/download files.
* **Null Session Checks:** Connect anonymously to test for misconfigured Null Sessions exposing sensitive data.
* **Authentication:** Support for username/password, NTLM hashes, Kerberos tickets.
* **Scripting Support:** Issue sequences of commands non-interactively for automation.
* **Mount SMB Shares:** Mount remote shares persistently (Linux).
* **Message Passing:** Send messages to Windows hosts on the network.
* **Cross-Platform:** Works on Linux, macOS, and Windows with compatible Samba clients.

***

### III. Professional Usage Examples

#### 1. List Shares on SMB Server

```bash
smbclient -L //$TARGET_IP/ $OPTIONS

```

#### 2. Null Session Enumeration (Anonymous Access)

```bash
smbclient -L //$TARGET_IP/ -U '' -N

```

#### 3. Connect to a Specific Share Interactively

```bash
smbclient //$TARGET_IP/$SHARE_NAME $OPTIONS

```

Use `help` command inside to see available commands. Typical commands:

* `ls` — list files and directories
* `cd directory` — change directory
* `get filename` — download file
* `put filename` — upload file

#### 4. Non-Interactive File Download

```bash
smbclient //$TARGET_IP/$SHARE_NAME $OPTIONS -c "get confidential.docx"

```

#### 5. Upload a File Non-Interactively

```bash
smbclient //$TARGET_IP/$SHARE_NAME $OPTIONS -c "put payload.exe"

```

#### 6. Mount SMB Share Persistently (Linux)

```bash
sudo mount -t cifs //$TARGET_IP/$SHARE_NAME $MOUNT_POINT -o username=$USERNAME,password=$PASSWORD,domain=$DOMAIN

```

#### 7. Use NTLM Hash Authentication (Pass the Hash)

```bash
smbclient //$TARGET_IP/$SHARE_NAME -U $USERNAME --pw-nt-hash $NTLM_HASH

```

***

### IV. Advanced Techniques & Scenarios

* **Null Session Harvesting:** Identify shares and system info without credentials if allowed by the server.
* **SMB Relay Attacks:** Use harvested credentials and intercepted SMB traffic for relay or man-in-the-middle attacks.
* **Scripting Automation:** Batch download/upload operations or scanning via shell scripting.
* **Kerberos Authentication:** Use valid Kerberos tickets for seamless authentication (`k` flag).
* **Message Sending:** Send network messages to SMB-enabled Windows systems with `smbclient -M`.
* **Scanning Systems for Open Shares:** Combine with `nmap` and scripting to map attack surface.

***

### V. Real-World Workflow Example

1. **Export Variables**

```bash
export TARGET_IP="10.10.10.5"
export SHARE_NAME="Documents"
export USERNAME="pentester"
export PASSWORD="P@ssw0rd!"
export DOMAIN="corp.local"

```

1. **Enumerate Shares**

```bash
smbclient -L //$TARGET_IP/ -U $USERNAME -W $DOMAIN

```

1. **Connect to Share**

```bash
smbclient //$TARGET_IP/$SHARE_NAME -U $USERNAME -W $DOMAIN

```

1. **Download Sensitive Files**

```bash
smbclient //$TARGET_IP/$SHARE_NAME -U $USERNAME -W $DOMAIN -c "get secrets.txt"

```

1. **Upload Payload (if authorized)**

```bash
smbclient //$TARGET_IP/$SHARE_NAME -U $USERNAME -W $DOMAIN -c "put shell.exe"

```

***

### VI. Pro Tips & Best Practices

* Avoid putting credentials directly in commands; use interactive prompts when possible to protect secrets.
* Always check for anonymous access or null sessions first as low hanging fruit.
* Use scripting mode to automate repetitive file transfers during engagements.
* Combine `smbclient` enumeration with enumeration tools like `enum4linux` or `CrackMapExec`.
* Use Kerberos authentication with the `k` flag if environment supports it for stealth.
* Mount shares in testing labs for persistent, file-system level access.
* Document accessed shares and files for reporting and compliance.
* Be cautious when uploading payloads; ensure full authorization to avoid unauthorized access or damage.

***

This professional SMBClient guide empowers pentesters and red teamers to enumerate, access, and manipulate SMB shares efficiently and securely within authorized penetration testing engagements.
