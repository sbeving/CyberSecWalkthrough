---
icon: fort
---

# System Hardening

## **System Hardening — Windows • Linux • macOS • Docker Fortress Edition**

***

System hardening is the systematic process of **reducing a system’s vulnerability** by configuring it securely, removing unnecessary services, patching known flaws, and enforcing least privilege.\
Think of it as **building an operating system that fights back** — whether it’s a red-team lab, production server, or your CTF workstation.

***

### I. 🧩 Universal Principles

| Principle                          | Description                                                                     |
| ---------------------------------- | ------------------------------------------------------------------------------- |
| **Least Privilege**                | Every process and user only gets the permissions absolutely required.           |
| **Attack Surface Reduction (ASR)** | Disable or uninstall what you don’t use.                                        |
| **Secure Defaults**                | Enforce strong configurations and protocols.                                    |
| **Patch Discipline**               | Apply OS and software updates regularly.                                        |
| **Visibility**                     | Log everything: auth, system, and network.                                      |
| **Integrity Verification**         | Use cryptographic checks, signing, and monitoring (AIDE, Defender, Gatekeeper). |

***

### II. ⚙️ Windows Hardening 🪟

#### 🧠 1. Accounts & Authentication

* Rename or disable the built-in Administrator account.
*   Enforce strong password policy:

    ```powershell
    net accounts /minpwlen:12 /maxpwage:30 /lockoutthreshold:5
    ```
* Enforce MFA for all remote or privileged accounts.
*   Disable guest accounts:

    ```powershell
    net user guest /active:no
    ```

#### ⚙️ 2. Services & Startup

*   Audit startup programs:

    ```powershell
    Get-Service | Where-Object {$_.StartType -eq "Automatic"}
    ```
* Disable unneeded services:
  * Remote Registry
  * Telnet
  * Fax
  * SMBv1
  * SNMP (if unused)

```powershell
sc config remoteregistry start= disabled
```

#### 💣 3. Windows Defender & Security Baselines

*   Enable Defender & SmartScreen:

    ```powershell
    Set-MpPreference -DisableRealtimeMonitoring 0
    ```
* Use **Microsoft Security Baselines** (Group Policy templates).
* Enable **ASR Rules**, **Controlled Folder Access**, **Exploit Guard**.

#### ⚙️ 4. Network & Firewall

*   Enable firewall on all profiles:

    ```powershell
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    ```
* Block inbound except specific ports (RDP, HTTP).
* Disable unused network adapters.

#### 🧠 5. Logging & Visibility

*   Enable **Advanced Auditing**:

    ```
    Audit Policy > Object Access, Process Tracking, Logon Events
    ```
* Forward logs to SIEM (Wazuh, ELK, Splunk).
* Sysmon: install & configure to capture process, network, and image load events.

#### ⚙️ 6. Application Control

* Enable **AppLocker** or **WDAC** to whitelist trusted binaries.
* Disable macro execution in Office via GPO.
*   Disable PowerShell v2, enable Script Block Logging:

    ```powershell
    Set-ItemProperty HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -Name ScriptBlockLogging -Value 1
    ```

#### 💣 7. RDP & Remote Access

* Change RDP port from 3389.
* Restrict RDP to VPN only.
* Enable NLA (Network Level Authentication).
* Disable clipboard / drive redirection.
* Monitor for Event ID 4625 (failed logon).

#### ⚙️ 8. Patching & Updates

* Use WSUS or Intune for centralized patch management.
* Automate reboots during maintenance windows.

***

### III. ⚙️ Linux Hardening 🐧

#### 🧠 1. Accounts & Authentication

*   Disable root SSH login:

    ```bash
    PermitRootLogin no
    ```
*   Force key-based SSH auth:

    ```bash
    PasswordAuthentication no
    ```
* Use `sudo` for privilege escalation.
*   Lock inactive accounts:

    ```bash
    usermod -L username
    ```

#### ⚙️ 2. Filesystem & Permissions

*   Set correct umask:

    ```bash
    umask 027
    ```
* Remove world-writable permissions.
*   Mount `/tmp`, `/var/tmp`, `/dev/shm` with noexec,nodev,nosuid:

    ```
    /tmp /tmp tmpfs defaults,noexec,nodev,nosuid 0 0
    ```

#### 💣 3. Service Management

*   List running services:

    ```bash
    systemctl list-units --type=service
    ```
*   Disable unused ones (FTP, Telnet, NFS, cups).

    ```bash
    systemctl disable nfs
    systemctl stop telnet
    ```

#### ⚙️ 4. SSH & Network Security

* Enforce SSHv2 only.
* Use fail2ban to block brute-force attempts.
*   Restrict listening ports:

    ```bash
    netstat -tulnp
    ```
*   Configure firewall:

    ```bash
    ufw default deny incoming
    ufw allow 22/tcp
    ufw enable
    ```

#### 🧠 5. Kernel & Sysctl Hardening

Add to `/etc/sysctl.conf`:

```
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
```

Apply:

```bash
sysctl -p
```

#### ⚙️ 6. Logging & Monitoring

*   Install `auditd`:

    ```bash
    apt install auditd
    ```
* Configure `/etc/audit/audit.rules` for execve, write, and user\_modification events.
* Use **OSSEC / Wazuh / Lynis** for automated auditing.

#### 💣 7. SELinux / AppArmor

*   Enforce SELinux:

    ```bash
    setenforce 1
    ```
*   For Ubuntu/Debian:\
    Use **AppArmor** profiles:

    ```bash
    aa-enforce /etc/apparmor.d/*
    ```

#### ⚙️ 8. Updates & Patching

```bash
apt update && apt upgrade -y
unattended-upgrades
```

Use `apt-get install apt-listchanges` to review changelogs.

***

### IV. ⚙️ macOS Hardening 🍎

#### 🧠 1. Accounts & Privacy

*   Disable Guest account:

    ```
    System Preferences → Users & Groups → Guest User → Off
    ```
* Enforce FileVault full-disk encryption.
* Enable automatic logout after inactivity.

#### ⚙️ 2. System Integrity Protection (SIP)

Check status:

```bash
csrutil status
```

Ensure it’s enabled. Prevents root from modifying critical files.

#### 💣 3. Firewall & Networking

Enable application firewall:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
```

Block all inbound by default.

#### ⚙️ 4. Software & Updates

*   Enforce App Store-only apps:

    ```
    System Preferences → Security & Privacy → Allow apps from App Store
    ```
*   Enable automatic updates:

    ```bash
    sudo softwareupdate --schedule on
    ```

#### 🧠 5. Logging & Privacy Monitoring

*   Enable **Unified Logging** and review:

    ```bash
    log show --predicate 'eventMessage contains "login"' --info
    ```
* Use `osquery` to monitor system configuration.

#### ⚙️ 6. Disable Unused Services

*   Turn off remote login, AirDrop, Bluetooth if unused:

    ```bash
    sudo systemsetup -setremotelogin off
    ```

#### 💣 7. Browser & Application Hardening

* Safari → Disable “Open safe files automatically.”
* Use DNS over HTTPS (Cloudflare / NextDNS).
* Prefer open-source security tools (LuLu firewall, BlockBlock).

***

### V. ⚙️ Docker / Container Hardening 🐳

#### 🧠 1. Principle: Containers ≠ Security Boundary

Treat every container as potentially compromised.

#### ⚙️ 2. User & Capability Restrictions

Run containers as non-root:

```bash
docker run --user 1001:1001 myapp
```

Drop unnecessary Linux capabilities:

```bash
--cap-drop=ALL --cap-add=NET_BIND_SERVICE
```

#### 💣 3. File System Controls

*   Use read-only root filesystems:

    ```bash
    docker run --read-only ...
    ```
* Avoid bind-mounting sensitive host directories.
*   Use tmpfs for ephemeral storage:

    ```bash
    --tmpfs /tmp
    ```

#### ⚙️ 4. Networking & Isolation

* Disable container-to-container networking (`--icc=false`).
* Use user-defined bridges for controlled communication.
* Apply firewall rules via `iptables` or Docker’s built-in `--iptables`.

#### 🧠 5. Secrets Management

Never hard-code secrets in images or env vars.\
Use:

* Docker Secrets
* HashiCorp Vault
* AWS Secrets Manager

#### ⚙️ 6. Image Integrity & Vulnerability Scanning

Scan images before deployment:

```bash
trivy image myapp:latest
grype myapp:latest
```

Verify image signatures with Docker Content Trust:

```bash
export DOCKER_CONTENT_TRUST=1
```

#### 💣 7. Runtime Security

Use runtime scanners:

* **Falco** (behavioral detection for containers)
* **Sysdig Secure**
* **Cilium Tetragon**

Example Falco rule:

```yaml
- rule: Unexpected Shell in Container
  condition: container and shell_procs and not user_known_container
  output: "Shell spawned in container (user=%user.name container=%container.name)"
```

***

### VI. ⚙️ Monitoring, Detection & Auditing

| Platform    | Tool           | Purpose                    |
| ----------- | -------------- | -------------------------- |
| **Windows** | Sysmon + ELK   | Process/network tracking   |
| **Linux**   | auditd + Wazuh | File and privilege events  |
| **macOS**   | Osquery        | Endpoint monitoring        |
| **Docker**  | Falco          | Runtime behavior detection |

Centralize logs into:

* **ELK Stack (Elastic, Logstash, Kibana)**
* **Wazuh Manager**
* **Graylog / Splunk**

***

### VII. ⚙️ CIS Benchmarks & Automation

* **CIS-CAT**: Validate compliance with CIS benchmarks.
*   **Lynis (Linux)**:

    ```bash
    lynis audit system
    ```
* **Microsoft Security Compliance Toolkit** for Windows.
*   **Docker Bench for Security**:

    ```bash
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    docker/docker-bench-security
    ```

***

### VIII. ⚙️ Pro Tips & Operator Habits

✅ **Hardening ≠ One-Time Task** — Reassess quarterly.\
✅ **Monitor Baselines** — Hash important binaries.\
✅ **Version Control Configs** — Use Git for `/etc` and policy files.\
✅ **Never Trust Defaults** — Defaults are for convenience, not security.\
✅ **Disable Autostart Everything** — Make startup intentional.\
✅ **Segment Networks** — Docker, servers, and workstations in isolated VLANs.\
✅ **Immutable Infrastructure** — Use containers or images you can rebuild from source.\
✅ **Zero-Trust Thinking** — Every process must authenticate, even internal ones.

***

### IX. ⚙️ Quick Reference Table

| Platform       | Tool / File                           | Purpose                  |
| -------------- | ------------------------------------- | ------------------------ |
| Windows        | `gpedit.msc`, `Secpol.msc`            | Group policy hardening   |
| Linux          | `/etc/ssh/sshd_config`, `/etc/audit/` | Access control, auditing |
| macOS          | `csrutil`, `osquery`                  | Integrity enforcement    |
| Docker         | `docker-bench-security`, `trivy`      | Container scanning       |
| Cross-Platform | `CIS Benchmarks`, `Lynis`             | Automated auditing       |

***
