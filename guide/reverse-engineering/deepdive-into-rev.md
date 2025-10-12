---
icon: mask-snorkel
---

# DeepDive into Rev

## **Reverse Engineering Deep Dive — Reading the Language of Machines**

***

Reverse engineering (RE) is the **art of disassembling compiled binaries** to understand, manipulate, or exploit them.\
In CTFs, RE challenges test your ability to extract logic, decrypt flags, patch binaries, and trace hidden functionality.\
In the wild, RE is how analysts dissect malware, crack protections, or weaponize exploits.

This guide gives you a **structured operator workflow** for analyzing ELF, PE, and binary blobs — from static disassembly to dynamic runtime analysis and patching.

***

### I. 🧩 Core Concepts

| Concept              | Description                                                          |
| -------------------- | -------------------------------------------------------------------- |
| **Disassembly**      | Translating machine code → assembly instructions.                    |
| **Decompilation**    | Reconstructing high-level logic from assembly.                       |
| **Debugging**        | Stepping through execution in real time.                             |
| **Static Analysis**  | Examining binaries without running them.                             |
| **Dynamic Analysis** | Observing behavior during execution.                                 |
| **Symbols**          | Metadata for functions, variables, etc.                              |
| **Sections**         | Segments of executables (e.g., `.text`, `.data`, `.bss`, `.rodata`). |

***

### II. ⚙️ File Identification & Architecture

#### 🧠 Identify Binary Type

```bash
file target
```

Output example:

```
ELF 64-bit LSB executable, x86-64, dynamically linked
```

#### ⚙️ Inspect Headers

```bash
readelf -h target
objdump -f target
```

#### 💣 Check for Packing or Obfuscation

```bash
strings target | head
upx -t target
```

If packed:

```bash
upx -d target
```

***

### III. ⚙️ Static Analysis Basics

#### 🧩 Extract Strings

```bash
strings -n 4 target | less
```

Search for:

* Hidden flags
* File paths
* Encryption keys
* API names

***

#### ⚙️ Disassemble with `objdump`

```bash
objdump -D target | less
```

Look at functions, especially `main`, `_start`, and `strcmp`.

***

#### 🧠 Symbol Information

```bash
nm target | grep main
objdump -t target | grep func
```

***

#### ⚙️ ELF Section Enumeration

```bash
readelf -S target
```

| Section         | Purpose                |
| --------------- | ---------------------- |
| `.text`         | Code                   |
| `.data`         | Initialized data       |
| `.bss`          | Uninitialized data     |
| `.rodata`       | Constants              |
| `.plt` / `.got` | Dynamic linking tables |

***

### IV. 🧠 Advanced Static Analysis Tools

| Tool                     | Purpose                                 |
| ------------------------ | --------------------------------------- |
| **Ghidra**               | Decompiler + control flow visualization |
| **IDA Free / IDA Pro**   | Industry standard disassembler          |
| **Binary Ninja**         | Interactive RE platform                 |
| **Radare2 / Cutter**     | CLI/GUI disassembler and debugger       |
| **Hopper**               | macOS-friendly RE tool                  |
| **Detect-It-Easy (DIE)** | Packing and compiler fingerprinting     |

***

#### 🧩 Example (Ghidra Workflow)

1. Import the binary.
2. Analyze (enable “Auto Analysis”).
3. Explore the **Symbol Tree → Functions**.
4.  Find `main()`, look for conditionals like:

    ```c
    if (strcmp(input, "flag123") == 0)
    ```
5. Follow xrefs → patch or simulate inputs.

***

### V. ⚙️ Dynamic Analysis (Runtime)

#### 🧠 Use `ltrace` & `strace`

```bash
ltrace ./target
strace ./target
```

Tracks:

* Library calls
* System calls
* File/Network access
* Function flow

***

#### ⚙️ Debug with `gdb`

```bash
gdb target
(gdb) info functions
(gdb) break main
(gdb) run
(gdb) next
(gdb) print $eax
```

Trace logic flow, variable values, or patch execution.

***

#### 💣 Patch Logic at Runtime

```bash
(gdb) set $eax=0
(gdb) continue
```

→ Force program to skip validation.

***

### VI. ⚙️ Binary Instrumentation & Hooking

#### 🧠 Using `pwndbg` or `gef`

Enhance gdb with:

```bash
pip install pwndbg
```

Features:

* Function argument inspection
* Heap visualization
* ROP gadget finder

#### ⚙️ Dynamic Hooks with Frida

```bash
frida -f ./target -l script.js --no-pause
```

Example hook:

```js
Interceptor.attach(ptr("0x4010a0"), {
  onEnter(args) { console.log("Function called:", args[0].toInt32()); }
});
```

***

### VII. 🧩 Patching Binaries

#### ⚙️ Edit Assembly Instructions

```bash
r2 -w target
[0x00400510]> pdf @ main
[0x00400510]> wa nop @ 0x00400680
[0x00400510]> wq
```

Replace a conditional jump or comparison to bypass protection.

***

#### 💣 Hex Editing

```bash
xxd target | less
```

Find byte patterns, modify with:

```bash
xxd -r > patched
```

***

#### ⚙️ Automated Patching Tools

| Tool                 | Description                   |
| -------------------- | ----------------------------- |
| **Radare2**          | Interactive assembly patching |
| **bvi / hexedit**    | Raw byte manipulation         |
| **Ghidra**           | Patch decompiled logic        |
| **x64dbg (Windows)** | GUI patching for PE files     |

***

### VIII. ⚙️ Control Flow Analysis

Understand program paths and decision logic.

#### 🧠 With Ghidra / IDA

* Open `main()`
* Enable “Graph View”
* Look for:
  * Branch conditions (`cmp`, `jne`, `je`)
  * Loops (`jmp`, `loop`)
  * Flag validation routines

***

#### ⚙️ Manual Assembly Trace Example

```asm
cmp eax, 0x5
jne wrong_flag
call success
```

Change `jne` → `je` to invert logic.

***

### IX. 🧠 Decompilation & High-Level Recovery

Use Ghidra, Binary Ninja, or IDA to view C-like pseudocode:

```c
int main() {
  char buf[32];
  fgets(buf, 32, stdin);
  if (strcmp(buf, "pwned!") == 0)
    win();
}
```

→ Understand logic, extract constants, recover algorithm flow.

***

### X. ⚙️ CTF-Specific Reverse Engineering Tricks

| Technique                  | Example                                | Tool                   |
| -------------------------- | -------------------------------------- | ---------------------- |
| **Flag in string literal** | \`strings target                       | grep flag\`            |
| **Key validation logic**   | Look for `strcmp`, `strncmp`, `memcmp` | Ghidra                 |
| **Encrypted flag**         | Static key or XOR loop                 | Ghidra / Python script |
| **Obfuscated code**        | Replace arithmetic/bitwise patterns    | Radare2                |
| **Self-modifying binary**  | Use `gdb` snapshots                    | pwndbg                 |
| **Packed binary**          | `upx -d`, then re-analyze              | UPX, DIE               |

***

### XI. ⚙️ Reverse Engineering Scripts

#### 🧩 XOR Decode Example

```python
data = [0x45,0x47,0x50]
key = 0x13
print(''.join([chr(b ^ key) for b in data]))
```

#### ⚙️ Simple Emulator Loop

```python
pc = 0
while pc < len(code):
    opcode = code[pc]
    if opcode == 0x90:
        pc += 1  # NOP
    elif opcode == 0xC3:
        break   # RET
```

***

### XII. ⚙️ Malware & CrackMe Context (Advanced)

#### 🧠 Analyze Suspicious Behavior

```bash
strings malware.bin | grep -i url
ltrace ./malware.bin
```

#### ⚙️ Sandbox Tools

* **Cuckoo Sandbox**
* **CAPEv2**
* **Any.Run**
* **MalwareBazaar + Ghidra**

***

### XIII. ⚔️ Pro Tips & Red Team Tricks

✅ **Start Static, End Dynamic**\
Disassemble first → debug later → patch last.

✅ **Comment Everything**\
Every branch and function you understand = future time saved.

✅ **Look for Key Functions**\
`strcmp`, `memcmp`, `printf`, `scanf`, `fgets`, `strcpy` — the “flag magnets” in CTFs.

✅ **Automate with Python**\
Use `pwntools` for interaction:

```python
from pwn import *
p = process('./target')
p.sendline('flag')
print(p.recv())
```

✅ **Anti-RE Bypass**

* Use `LD_PRELOAD` to override system calls.
* Patch anti-debug checks like `ptrace`.

✅ **Exploit from RE**\
RE gives you entry points for:

* Buffer overflows
* Format strings
* ROP gadget creation

***

### XIV. ⚙️ Quick Reference Table

| Goal             | Tool / Command      | Use                  |
| ---------------- | ------------------- | -------------------- |
| Identify binary  | `file target`       | Detect type and arch |
| Extract strings  | `strings target`    | Find text/flags      |
| Disassemble      | `objdump -D target` | View assembly        |
| Debug            | `gdb target`        | Step through runtime |
| Decompile        | `ghidra`, `IDA`     | Recover C code       |
| Patch            | `r2 -w`, `x64dbg`   | Modify instructions  |
| Analyze syscalls | `strace`, `ltrace`  | Observe behavior     |
| Instrument       | `frida`             | Hook live processes  |

***
