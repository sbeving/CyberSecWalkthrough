---
icon: linux
---

# Enum4Linux

## The Enum4Linux Masterclass: Professional SMB & Windows Domain Enumeration Guide

Enum4Linux is a robust command-line tool for Windows and Samba network enumeration, providing critical data for penetration testers, bug bounty hunters, and red teamers. It wraps various Samba utilities to extract user lists, groups, shares, password policies, OS details, domain membership, and much more—essential for CTFs and real-world AD/SMB assessments.

***

### I. Environment Setup: Dynamic Variables

Set environment variables for organized, automated workflows:

```bash
export TARGET_IP="192.168.1.100"
export USERNAME="guest"
export PASSWORD=""
export OUTPUT_DIR="enum4linux-results"
export OUTPUT_FILE="$OUTPUT_DIR/scan.txt"
export RID_RANGE="500-550,1000-1050"
export WORKGROUP=""
export SHARES_WORDLIST="share_guess.txt"
export VERBOSE=true
export AGGRESSIVE=true

```

***

### II. Core Capabilities & Workflow

* **User Enumeration:** Extracts local/domain users via RID cycling, brute force, or LDAP.\[1]\[2]\[3]\[4]
* **Group Membership Listing:** Discovers AD group composition, nested membership, and privileges.\[3]\[4]\[1]
* **Share Discovery:** Enumerates available SMB shares and access controls.\[1]\[3]
* **Password Policy Extraction:** Finds password complexity, change requirements, and expiration via polenum.\[3]\[1]
* **OS & Domain Identification:** Collects Windows/Samba version, workgroup/domain details, and NetBIOS info.\[2]\[1]
* **Printer Enumeration:** Fetches information about networked printers for lateral movement or misconfiguration testing.\[1]
* **Aggressive & RID Range Cycling:** Deeply cycles RIDs to expose hidden accounts even with restricted anonymous translation.\[4]\[1]
* **Null Session & Credentialed Scans:** Tests for anonymous enumeration and adds credentials for deeper penetration.\[4]
* **Detailed Output & Scripting:** Logs everything for reporting; supports verbose output for real-time debugging and audit.\[4]\[1]

***

### III. Professional Usage Examples

#### 1. Full Enumeration (All Techniques)

```bash
enum4linux -a $TARGET_IP > "$OUTPUT_FILE"

```

#### 2. User List via RID Cycling

```bash
enum4linux -U -r -R $RID_RANGE $TARGET_IP > "$OUTPUT_FILE"

```

#### 3. Group and Membership Enumeration

```bash
enum4linux -G $TARGET_IP > "$OUTPUT_FILE"

```

#### 4. List Shares

```bash
enum4linux -S $TARGET_IP > "$OUTPUT_FILE"

```

#### 5. Get Detailed Share List

```bash
enum4linux -S -d $TARGET_IP > "$OUTPUT_FILE"

```

#### 6. Get Password Policy

```bash
enum4linux -P $TARGET_IP > "$OUTPUT_FILE"

```

#### 7. OS and Printer Information

```bash
enum4linux -o -i $TARGET_IP > "$OUTPUT_FILE"

```

#### 8. Run with Credentials

```bash
enum4linux -u $USERNAME -p $PASSWORD -a $TARGET_IP > "$OUTPUT_FILE"

```

#### 9. Brute-Force Share Guessing

```bash
enum4linux -s $SHARES_WORDLIST $TARGET_IP > "$OUTPUT_FILE"

```

#### 10. Scan Multiple IPs

```bash
for ip in $(cat ip_list.txt); do enum4linux -a $ip > "$OUTPUT_DIR/$ip.txt"; done

```

***

### IV. Advanced Techniques & Scenarios

* **Aggressive Scanning:** Use `a` with verbose mode to apply all core enumeration, including write checks on shares.\[4]
* **Custom RID Cycling:** Specify RID ranges with `R` or keep searching until consecutive misses with `K`.
* **Credentialed Deep Dives:** Use valid user/pass combos for maximum enumeration in AD environments.\[2]\[4]
* **Printer & LDAP Info:** Use `i` and `l` for extra details about printers and LDAP attributes if targeting a Domain Controller.
* **Cross-Tool Integration:** Pipe results for use with CrackMapExec, BloodHound, or custom scripts for privilege escalation planning.
* **Share Name Brute-Force:** Apply custom dictionaries for non-standard or hidden SMB shares.\[1]

***

### V. Real-World Workflow Example

1. **Prepare Target and Output Directory**

```bash
export TARGET_IP="10.10.10.25"
export OUTPUT_DIR="enum4linux_reports"

```

1. **Full Aggressive Enumeration**

```bash
enum4linux -a $TARGET_IP > "$OUTPUT_DIR/full.txt"

```

1. **Focused User and Share Enumeration**

```bash
enum4linux -U -S $TARGET_IP > "$OUTPUT_DIR/users_shares.txt"

```

1. **Credentialed Scan for Privileged Data**

```bash
enum4linux -u "admin" -p "P@ssw0rd" -a $TARGET_IP > "$OUTPUT_DIR/creds_full.txt"

```

1. **Review Outputs and Combine with BloodHound**

***

### VI. Pro Tips & Best Practices

* Start with null sessions; escalate to credentialed enumeration as engagement allows.
* Always use full (`a`) and verbose (`v`) when maximum coverage is required.
* Cycle RIDs and brute-force share names for hidden, non-standard accounts and shares.
* Use LDAP mode (`l`) when targeting DCs for extra AD information.
* Document all findings and relate user/group/share mappings to potential attack vectors and privilege escalation paths.
* Combine with SMBClient, CrackMapExec, and BloodHound for multi-layered Windows network attacks.
* Respect rate limits and engagement scope—excessive enumeration can trigger defenses.

***

This professional Enum4Linux guide prepares you to discover critical users, groups, shares, policies, and OS/domain details—empowering strategic attack planning in Windows and Samba environments.# The Enum4Linux Masterclass: Professional SMB & Windows Domain Enumeration Guide\[5]\[2]\[3]\[1]\[4]

Enum4Linux is a robust command-line tool for Windows and Samba network enumeration, providing critical data for penetration testers, bug bounty hunters, and red teamers. It wraps various Samba utilities to extract user lists, groups, shares, password policies, OS details, domain membership, and much more—essential for CTFs and real-world AD/SMB assessments.

***

### I. Environment Setup: Dynamic Variables

Set environment variables for organized, automated workflows:

```bash
export TARGET_IP="192.168.1.100"
export USERNAME="guest"
export PASSWORD=""
export OUTPUT_DIR="enum4linux-results"
export OUTPUT_FILE="$OUTPUT_DIR/scan.txt"
export RID_RANGE="500-550,1000-1050"
export WORKGROUP=""
export SHARES_WORDLIST="share_guess.txt"
export VERBOSE=true
export AGGRESSIVE=true

```

***

### II. Core Capabilities & Workflow

* **User Enumeration:** Extracts local/domain users via RID cycling, brute force, or LDAP.\[2]\[3]\[1]\[4]
* **Group Membership Listing:** Discovers AD group composition, nested membership, and privileges.\[3]\[1]\[4]
* **Share Discovery:** Enumerates available SMB shares and access controls.\[3]\[1]
* **Password Policy Extraction:** Finds password complexity, change requirements, and expiration via polenum.\[1]\[3]
* **OS & Domain Identification:** Collects Windows/Samba version, workgroup/domain details, and NetBIOS info.\[2]\[1]
* **Printer Enumeration:** Fetches information about networked printers for lateral movement or misconfiguration testing.\[1]
* **Aggressive & RID Range Cycling:** Deeply cycles RIDs to expose hidden accounts even with restricted anonymous translation.\[4]\[1]
* **Null Session & Credentialed Scans:** Tests for anonymous enumeration and adds credentials for deeper penetration.\[4]
* **Detailed Output & Scripting:** Logs everything for reporting; supports verbose output for real-time debugging and audit.\[1]\[4]

***

### III. Professional Usage Examples

#### 1. Full Enumeration (All Techniques)

```bash
enum4linux -a $TARGET_IP > "$OUTPUT_FILE"

```

#### 2. User List via RID Cycling

```bash
enum4linux -U -r -R $RID_RANGE $TARGET_IP > "$OUTPUT_FILE"

```

#### 3. Group and Membership Enumeration

```bash
enum4linux -G $TARGET_IP > "$OUTPUT_FILE"

```

#### 4. List Shares

```bash
enum4linux -S $TARGET_IP > "$OUTPUT_FILE"

```

#### 5. Get Detailed Share List

```bash
enum4linux -S -d $TARGET_IP > "$OUTPUT_FILE"

```

#### 6. Get Password Policy

```bash
enum4linux -P $TARGET_IP > "$OUTPUT_FILE"

```

#### 7. OS and Printer Information

```bash
enum4linux -o -i $TARGET_IP > "$OUTPUT_FILE"

```

#### 8. Run with Credentials

```bash
enum4linux -u $USERNAME -p $PASSWORD -a $TARGET_IP > "$OUTPUT_FILE"

```

#### 9. Brute-Force Share Guessing

```bash
enum4linux -s $SHARES_WORDLIST $TARGET_IP > "$OUTPUT_FILE"

```

#### 10. Scan Multiple IPs

```bash
for ip in $(cat ip_list.txt); do enum4linux -a $ip > "$OUTPUT_DIR/$ip.txt"; done

```

***

### IV. Advanced Techniques & Scenarios

* **Aggressive Scanning:** Use `a` with verbose mode to apply all core enumeration, including write checks on shares.\[4]
* **Custom RID Cycling:** Specify RID ranges with `R` or keep searching until consecutive misses with `K`.
* **Credentialed Deep Dives:** Use valid user/pass combos for maximum enumeration in AD environments.\[2]\[4]
* **Printer & LDAP Info:** Use `i` and `l` for extra details about printers and LDAP attributes if targeting a Domain Controller.
* **Cross-Tool Integration:** Pipe results for use with CrackMapExec, BloodHound, or custom scripts for privilege escalation planning.
* **Share Name Brute-Force:** Apply custom dictionaries for non-standard or hidden SMB shares.\[1]

***

### V. Real-World Workflow Example

1. **Prepare Target and Output Directory**

```bash
export TARGET_IP="10.10.10.25"
export OUTPUT_DIR="enum4linux_reports"

```

1. **Full Aggressive Enumeration**

```bash
enum4linux -a $TARGET_IP > "$OUTPUT_DIR/full.txt"

```

1. **Focused User and Share Enumeration**

```bash
enum4linux -U -S $TARGET_IP > "$OUTPUT_DIR/users_shares.txt"

```

1. **Credentialed Scan for Privileged Data**

```bash
enum4linux -u "admin" -p "P@ssw0rd" -a $TARGET_IP > "$OUTPUT_DIR/creds_full.txt"

```

1. **Review Outputs and Combine with BloodHound**

***

### VI. Pro Tips & Best Practices

* Start with null sessions; escalate to credentialed enumeration as engagement allows.
* Always use full (`a`) and verbose (`v`) when maximum coverage is required.
* Cycle RIDs and brute-force share names for hidden, non-standard accounts and shares.
* Use LDAP mode (`l`) when targeting DCs for extra AD information.
* Document all findings and relate user/group/share mappings to potential attack vectors and privilege escalation paths.
* Combine with SMBClient, CrackMapExec, and BloodHound for multi-layered Windows network attacks.
* Respect rate limits and engagement scope—excessive enumeration can trigger defenses.

***

This professional Enum4Linux guide prepares you to discover critical users, groups, shares, policies, and OS/domain details—empowering strategic attack planning in Windows and Samba environments.\[5]\[3]\[2]\[4]\[1]

Sources \[1] enum4linux | Kali Linux Tools [https://www.kali.org/tools/enum4linux/](https://www.kali.org/tools/enum4linux/) \[2] How to use enum4linux for Network Infrastructure VAPT? [https://cybersapiens.com.au/how-to-use-enum4linux-for-network-infrastructure-vapt/](https://cybersapiens.com.au/how-to-use-enum4linux-for-network-infrastructure-vapt/) \[3] A Little Guide to SMB Enumeration [https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/](https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/) \[4] enum4linux Cheat Sheet - Commands & Examples [https://highon.coffee/blog/enum4linux-cheat-sheet/](https://highon.coffee/blog/enum4linux-cheat-sheet/) \[5] SMB & AD Enumeration with enum4linux | by Shah kaif [https://systemweakness.com/red-team-recon-write-up-smb-ad-enumeration-with-enum4linux-ca92c593b1f6](https://systemweakness.com/red-team-recon-write-up-smb-ad-enumeration-with-enum4linux-ca92c593b1f6)
