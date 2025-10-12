---
icon: reply
---

# Responder

## The Responder Masterclass: Professional LLMNR, NBT-NS, and MDNS Poisoning & Credential Harvesting

Responder is a powerful internal network attack tool that poisons name resolution protocols (LLMNR, NBT-NS, MDNS) to capture hashed credentials and gain privileged information on Windows networks during internal assessments and red team engagements.

***

### I. Environment Setup: Dynamic Variables

Export session variables for adaptability and clean output organization:

```bash
export INTERFACE="eth0"                  # Attacker’s network interface in target subnet
export OUTPUT_DIR="responder-results"
export LOG_FILE="$OUTPUT_DIR/captured_hashes.log"
export LMHOSTS_FILE="lmhosts"             # Optional: LMHOSTS file for spoofing names
export BIND_INTERFACE="0.0.0.0"           # IP to bind responder services (default all)
export RESOLVE_NETBIOS=true               # Enable NetBIOS spoofing & resolution
export RESOLVE_LLMNR=true                 # Enable LLMNR spoofing
export RESOLVE_MDNS=true                  # Enable MDNS spoofing
export SMB_LISTENER_PORT=445

```

***

### II. Core Capabilities & Workflow

* **Multicast Name Poisoning:** Responds to LLMNR, NBT-NS, and MDNS requests with attacker-controlled responses to intercept authentication attempts.
* **Hash Capture & Cracking:** Captures NTLMv1/v2 password hashes, SMB challenges, and can perform on-the-fly cracking or offline using external tools.
* **Automatic Relay & Credential Forwarding:** Can relay captured hashes to other SMB services for lateral movement (e.g., using SMBClient or CrackMapExec).
* **Name Resolution Spoofing:** Spoofs common and requested names to redirect traffic to attacker-controlled hosts.
* **Extensive Logging:** Logs captured hashes, request metadata, and authentication attempts.
* **Passive Scanning:** Can operate stealthily to gather data without active poisoning.

***

### III. Professional Usage Examples

#### 1. Basic Poisoning on Interface

```bash
sudo responder -I $INTERFACE -wv

```

#### 2. Log Captured Credentials to File

```bash
sudo responder -I $INTERFACE -wv -r -f --logfile "$LOG_FILE"

```

#### 3. Disable Specific Protocol Spoofing (e.g., disable MDNS)

```bash
sudo responder -I $INTERFACE -wv -r --disable-mdns

```

#### 4. Use Custom LMHOSTS File for Specific Spoofs

```bash
sudo responder -I $INTERFACE -wv --lmhosts $LMHOSTS_FILE

```

#### 5. Relay Captured NTLM Hashes to SMB Target

Using SMB Client or CrackMapExec externally with hashes obtained by Responder.

#### 6. Stealth Mode (Passive Listener Only)

```bash
sudo responder -I $INTERFACE --no-poison -wm

```

***

### IV. Advanced Techniques & Scenarios

* **Internal Network Reconnaissance:** Use Responder on an internal network segment to discover hosts and shares during engagements.
* **Hash Cracking Pipeline:** Automate feeding captured hashes into Hashcat or John the Ripper for rapid password recovery.
* **Multi-Interface Attacks:** Run Responder on multiple network interfaces simultaneously in complex environments.
* **Integration with Post-Exploitation Frameworks:** Relay compromised credentials to tools like CrackMapExec or Metasploit for lateral movement.
* **Filter Target Hosts:** Use LMHOSTS or command line to limit targets and reduce noise.
* **Defensive Evasion:** Limit poisoning scope and monitor logs to avoid triggering alerts on blue team systems.

***

### V. Real-World Workflow Example

1. **Export Variables**

```bash
export INTERFACE="eth0"
export OUTPUT_DIR="responder_scans"
export LOG_FILE="$OUTPUT_DIR/captures.log"

```

1. **Start Poisoning and Logging**

```bash
sudo responder -I $INTERFACE -wv -r --logfile "$LOG_FILE"

```

1. **Analyze Captured Hashes**

* Use Hashcat or John the Ripper for cracking captured NTLM hashes.

1. **Relay Obtained Hashes**

* Use CrackMapExec to move laterally within Windows domain.

1. **Report Findings**

* Document captured credentials and attack scope.

***

### VI. Pro Tips & Best Practices

* Run on target internal network segment for maximum impact.
* Combine with network mapping tools for comprehensive assessment.
* Use responsibly and only with explicit permission.
* Regularly update Responder tool and hash cracking wordlists.
* Monitor detection systems while performing poisoning attacks.
* Use targeted scope to reduce detection risk and collateral impact.
* Analyze logs meticulously to spot patterns and possible escalations.

***

This professional Responder guide equips penetration testers and red teamers to effectively perform internal network poisoning, credential harvest, and lateral movement reconnaissance while maintaining operational safety and stealth.
