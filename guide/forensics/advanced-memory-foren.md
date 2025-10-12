---
icon: memory
---

# Advanced Memory Foren

## **Advanced Memory Forensics — The Science of Digital Resurrection**

***

Memory forensics is the art of **extracting evidence directly from RAM** — the battlefield where malware executes, hides, and dies.\
Unlike disk forensics, memory analysis reveals **what actually ran**, not just what was stored.

This guide walks through **acquisition, parsing, timeline reconstruction, injection detection, and live threat hunting** using Volatility 3, Rekall, and related tools.

***

### I. 🧩 Core Concepts

| Concept                   | Description                                                               |
| ------------------------- | ------------------------------------------------------------------------- |
| **Volatile Memory (RAM)** | Temporary working memory containing processes, keys, injected code.       |
| **Image**                 | Memory snapshot of a system, captured during or after incident.           |
| **Acquisition Tool**      | Software that extracts RAM safely (WinPMem, DumpIt, FTK Imager).          |
| **Profile**               | OS-specific configuration for analysis (Volatility 2).                    |
| **Memory Artifacts**      | Residual evidence like processes, sockets, credentials, or injected DLLs. |

***

### II. ⚙️ Memory Acquisition

#### 🧠 1. Capture Memory Safely

**Windows**

```bash
winpmem.exe --output memdump.raw
```

**Linux**

```bash
sudo lime -o /mnt/memdump.lime -f raw
```

**MacOS**

```bash
osxpmem --output mem.raw
```

#### ⚙️ 2. Validate Integrity

```bash
sha256sum memdump.raw
```

Always hash before and after transfer.

***

### III. ⚙️ Environment Setup

| Tool                     | Description                                   |
| ------------------------ | --------------------------------------------- |
| **Volatility3**          | Modern Python-based memory analysis framework |
| **Rekall**               | Advanced forensic and live analysis tool      |
| **MemProcFS**            | Mount memory image as a filesystem            |
| **YARA**                 | Match signatures in memory                    |
| **Strings / grep / xxd** | Quick text-based scanning                     |

***

### IV. ⚙️ Basic Memory Triage

#### 🧩 1. Identify OS / Profile

```bash
volatility3 -f memdump.raw windows.info
```

#### ⚙️ 2. Process Listing

```bash
volatility3 -f memdump.raw windows.pslist
```

Example output:

```
System
explorer.exe
svchost.exe
malware.exe (PID 3141)
```

#### 🧠 3. Cross-check Hidden Processes

```bash
volatility3 -f memdump.raw windows.psscan
```

If process exists in `psscan` but not in `pslist` → **hidden/injected process.**

***

### V. ⚙️ Deep Process Inspection

#### 🧩 1. View Command Lines

```bash
volatility3 -f memdump.raw windows.cmdline
```

#### ⚙️ 2. Loaded DLLs

```bash
volatility3 -f memdump.raw windows.dlllist --pid 3141
```

Look for DLLs not from `System32` or with suspicious paths like:

```
C:\Users\Public\evil.dll
```

#### 🧠 3. Network Connections

```bash
volatility3 -f memdump.raw windows.netstat
```

Output example:

```
PID 3141  TCP 192.168.1.10:4444 -> 45.66.99.12:80
```

→ Indicates C2 beaconing.

***

### VI. ⚙️ Injection & Hollowing Detection

#### 🧩 1. Malfind (Core Plugin)

```bash
volatility3 -f memdump.raw windows.malfind
```

Highlights:

* Suspicious memory pages (`PAGE_EXECUTE_READWRITE`)
* Non-module code
* Hidden shellcode segments

#### ⚙️ 2. Dump Injected Memory

```bash
volatility3 -f memdump.raw windows.malfind --dump
```

Saves `.dmp` files for deeper analysis in IDA/Ghidra.

***

#### 💣 3. Hollowed Processes

Check parent-child mismatches:

```bash
volatility3 -f memdump.raw windows.pstree
```

Example:

```
explorer.exe → svchost.exe → calc.exe
```

If `calc.exe` shouldn’t exist → likely hollowed.

***

### VII. ⚙️ Credential & Secrets Extraction

#### 🧠 1. Dump LSASS

```bash
volatility3 -f memdump.raw windows.lsassextract
```

#### ⚙️ 2. Extract Plaintext Passwords

```bash
volatility3 -f memdump.raw windows.hashdump
```

#### ⚙️ 3. Manual LSASS Dump

```bash
volatility3 -f memdump.raw windows.memmap --pid <lsass_pid>
```

Dump for Mimikatz offline parsing.

***

### VIII. ⚙️ Registry & Persistence in Memory

#### 🧩 1. Extract Registry Hives

```bash
volatility3 -f memdump.raw windows.registry.hivelist
```

#### ⚙️ 2. Query Autorun Keys

```bash
volatility3 -f memdump.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

#### 🧠 3. UserAssist Artifacts

```bash
volatility3 -f memdump.raw windows.registry.userassist
```

Lists programs recently executed by user.

***

### IX. ⚙️ Memory Strings and Artifact Mining

#### 🧩 1. Search for Indicators

```bash
strings -a memdump.raw | grep -i "http"
strings memdump.raw | grep -i "flag"
```

#### ⚙️ 2. Extract Keys or Commands

```bash
strings memdump.raw | grep -i "cmd.exe /c"
strings memdump.raw | grep -i "password="
```

#### 🧠 3. YARA Scanning

```bash
yara -r malware_rules.yar memdump.raw
```

***

### X. ⚙️ Timeline Reconstruction

#### 🧩 1. Process Creation Timeline

```bash
volatility3 -f memdump.raw windows.psscan --output text | sort -k4
```

#### ⚙️ 2. File Handles Timeline

```bash
volatility3 -f memdump.raw windows.handles
```

#### 🧠 3. Combine for Attack Chain

Correlate:

* Process creation
* File writes
* Network connections

Result → full adversary timeline.

***

### XI. ⚙️ Browser & User Data Recovery

#### 🧩 1. Dump Browser History

```bash
volatility3 -f memdump.raw windows.chromehistory
```

#### ⚙️ 2. Extract Clipboard

```bash
volatility3 -f memdump.raw windows.clipboard
```

#### 💣 3. Search for Exfiltrated Data

```bash
strings memdump.raw | grep -i "ftp://"
strings memdump.raw | grep -i "base64,"
```

***

### XII. ⚙️ Memory-Based Persistence & Rootkits

#### 🧠 1. Check Kernel Hooks

```bash
volatility3 -f memdump.raw windows.driverirp
volatility3 -f memdump.raw windows.ssdt
```

If unexpected functions are hooked → rootkit present.

#### ⚙️ 2. Loaded Drivers

```bash
volatility3 -f memdump.raw windows.driverscan
```

Suspicious indicators:

```
driver.sys  Unknown vendor
```

***

### XIII. ⚙️ Live Memory Hunting (Threat Intel Ops)

#### 🧩 1. Memory Mounting

```bash
memprocfs memdump.raw /mnt/memfs
```

Explore live:

```
ls /mnt/memfs/Processes/
cat /mnt/memfs/Processes/3141/memory
```

#### ⚙️ 2. Compare Memory vs Disk

```bash
sha256sum /mnt/memfs/Processes/3141/exe > hash.txt
sha256sum /c/Windows/System32/svchost.exe
```

→ Hash mismatch → in-memory tampering.

***

### XIV. ⚙️ Automation and Scripting

#### 🧠 1. Python Script Example

```python
import subprocess
plugins = ['windows.pslist', 'windows.malfind', 'windows.netstat']
for p in plugins:
    subprocess.run(['volatility3', '-f', 'memdump.raw', p])
```

#### ⚙️ 2. Batch Command Example

```bash
for plugin in windows.pslist windows.netstat windows.malfind; do
  volatility3 -f memdump.raw $plugin >> report.txt
done
```

***

### XV. ⚙️ Forensic Correlation Matrix

| Artifact       | Source     | Meaning                  |
| -------------- | ---------- | ------------------------ |
| Process Name   | pslist     | Active or hidden process |
| Network Socket | netstat    | Beacon / exfil           |
| Injected Pages | malfind    | Code injection           |
| Registry Keys  | hivelist   | Persistence mechanism    |
| Clipboard      | clipboard  | Exfil / keylogging       |
| LSASS Dump     | hashdump   | Credential theft         |
| Drivers        | driverscan | Rootkit detection        |

***

### XVI. ⚙️ Memory Forensics with Volatility Plugins

| Plugin                      | Purpose             |
| --------------------------- | ------------------- |
| `windows.pslist`            | Running processes   |
| `windows.psscan`            | Hidden processes    |
| `windows.cmdline`           | Process arguments   |
| `windows.netstat`           | Network sockets     |
| `windows.malfind`           | Injection detection |
| `windows.dlllist`           | Loaded modules      |
| `windows.handles`           | File/socket handles |
| `windows.ssdt`              | Hook detection      |
| `windows.registry.printkey` | Registry key dump   |
| `windows.hashdump`          | Credential hashes   |

***

### XVII. ⚔️ Pro Tips & Operator Tricks

✅ **Always Use pslist + psscan Together**\
Comparing both reveals stealth processes.

✅ **Malfind = Goldmine**\
Every injection leaves a traceable memory region.

✅ **Memory Hash Comparison**\
Check hash mismatches between memory-executed and on-disk binaries.

✅ **Dump First, Analyze Later**\
Even if tools update, your dump remains valid forever.

✅ **YARA + Memory = Instant Intel**\
Scan volatile dumps with up-to-date threat signatures.

✅ **Correlate Across Artifacts**\
Registry + Process Tree + Network → attacker story reconstruction.

✅ **Volatility3 FTW**\
No profiles, automatic plugin mapping, and improved parsing for modern Windows versions.

***

### XVIII. ⚙️ Quick Reference Table

| Goal              | Command                                 | Purpose                        |
| ----------------- | --------------------------------------- | ------------------------------ |
| Identify OS       | `volatility3 windows.info`              | Determine memory profile       |
| List Processes    | `volatility3 windows.pslist`            | Show active processes          |
| Detect Hidden     | `volatility3 windows.psscan`            | Hidden or terminated processes |
| Network Activity  | `volatility3 windows.netstat`           | Active sockets                 |
| Detect Injection  | `volatility3 windows.malfind`           | Find injected code             |
| Dump Memory       | `volatility3 windows.malfind --dump`    | Save for offline RE            |
| Registry          | `volatility3 windows.registry.printkey` | Extract keys                   |
| Dump LSASS        | `volatility3 windows.lsassextract`      | Credential dump                |
| Rootkit Detection | `volatility3 windows.ssdt`              | Hook inspection                |
| YARA Scan         | `yara -r rules.yar memdump.raw`         | Threat signature match         |

***
