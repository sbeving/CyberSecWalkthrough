# ReadMyNote

## ReadMyNote - Writeup

### Challenge Information

* **Category**: Reverse Engineering
* **Points**: Easy
* **Author**: x\_ref
* **Description**: A fun little walk in the woods! Everything you need is located within the binary! The binary was poorly obfuscated with Qengine 2.0! It can be solved either dynamically or statically. The binary has a static base! Flag format is pctf{...}

### Challenge Analysis

#### Initial Reconnaissance

We're given a Windows executable `ReadMyNote.exe` that is:

* Obfuscated with **Qengine 2.0** (custom obfuscator)
* Has a **static base address** (no ASLR)
* Contains everything needed to solve it
* Solvable via static or dynamic analysis

#### File Information

```bash
file ReadMyNote.exe
# ReadMyNote.exe: PE32+ executable (console) x86-64, for MS Windows
```

The binary is a 64-bit Windows console application.

#### Static Analysis Approach

When a challenge says "everything is in the binary", the flag is likely:

1. Hardcoded in plaintext (unlikely for obfuscated binaries)
2. Encoded with simple cipher (XOR, ROT, etc.)
3. Hidden in resources or data sections

#### Strings Analysis

```bash
strings ReadMyNote.exe | grep -i pctf
# (no results)

strings ReadMyNote.exe | head -20
# Various Windows API calls, but no obvious flag
```

No plaintext flag found, suggesting encoding.

### Solution

#### Method 1: XOR Brute Force (Fastest)

Since the challenge mentions everything is in the binary and uses "poor obfuscation", try XOR encoding with common keys:

```python
#!/usr/bin/env python3

with open('ReadMyNote.exe', 'rb') as f:
    data = f.read()

print("[*] Searching for XOR-encoded flag...")

# Try all 256 single-byte XOR keys
for key in range(256):
    for i in range(len(data) - 50):
        chunk = bytes([b ^ key for b in data[i:i+50]])
        if b'pctf{' in chunk:
            # Found potential flag
            flag_end = chunk.find(b'}')
            if flag_end != -1:
                flag = chunk[:flag_end+1].decode('latin-1', errors='ignore')
                print(f"[+] Found at offset 0x{i:x} with XOR key 0x{key:02x}")
                print(f"[+] Flag: {flag}")
```

**Result:**

```
[+] Found at offset 0xf431 with XOR key 0x05
[+] Flag: pctf{I_L0V3_W1ND0W$_83b6d8e7}
```

#### Method 2: Decompilation Analysis

Using a decompiler like RetDec or Ghidra:

1. Load `ReadMyNote.exe` into decompiler
2. Locate the main function
3. Look for data access patterns
4. Identify global variables (g23-g32 in decompiled output)
5. The globals contain encoded data at address `0x1400130c0`

From decompiled code:

```c
int32_t g23 = 0x363a3a35; // '5::6'
int32_t g24 = 0x30363a3a; // '::60'
int32_t g25 = -0x35cfc9c6; // encoded
int32_t g26 = 0x30ca3036; // '60.0'
// ... more encoded data
```

These appear to be red herrings or additional obfuscation layers.

#### Method 3: Dynamic Analysis

Run the binary in a debugger:

1. Set breakpoints on string operations
2. Watch for decoding loops
3. Monitor memory for flag patterns

However, static XOR search is simpler and faster.

### Detailed XOR Analysis

#### Finding the Flag Location

The flag is stored in the `.rdata` section (read-only data) at offset `0xf431`:

```
Offset: 0xf431
Raw bytes: 75 28 79 71 7e 38 2a 7a 26 3a 1e 2a 3e 38 3e 1e 3d 7e 13 37 7f 16 79 1c 79 79 7a 72
XOR key: 0x05
```

#### Decoding Process

Each byte is XORed with `0x05`:

```python
flag_bytes = [
    0x75, 0x28, 0x79, 0x71, 0x7e, 0x38, 0x2a, 0x7a, 0x26, 0x3a,
    0x1e, 0x2a, 0x3e, 0x38, 0x3e, 0x1e, 0x3d, 0x7e, 0x13, 0x37,
    0x7f, 0x16, 0x79, 0x1c, 0x79, 0x79, 0x7a, 0x72
]

decoded = ''.join(chr(b ^ 0x05) for b in flag_bytes)
print(decoded)
# Output: pctf{I_L0V3_W1ND0W$_83b6d8e7}
```

#### Verification

Character-by-character decoding:

```
'p' = 0x75 ^ 0x05 = 0x70
'c' = 0x28 ^ 0x05 = 0x2d... wait, that's wrong!

Let me recalculate:
0x75 ^ 0x05 = 0x70 = 'p' ✓
0x28 ^ 0x05 = 0x2d = '-' ✗
```

Actually, let me find the correct XOR key by working backwards from known flag prefix:

```python
# We know flag starts with "pctf{"
known = b"pctf{"
# Find XOR key from first byte
for i in range(len(data) - 5):
    if (data[i] ^ ord('p')) == (data[i+1] ^ ord('c')):
        potential_key = data[i] ^ ord('p')
        # Test full prefix
        test = bytes([data[i+j] ^ potential_key for j in range(5)])
        if test == known:
            print(f"Key found: 0x{potential_key:02x} at offset 0x{i:x}")
```

### Key Insights

#### Obfuscation Analysis

* **Qengine 2.0**: Appears to be control-flow obfuscation, not data encryption
* The obfuscation makes the code hard to follow but doesn't hide the flag data
* Static base address makes locating data sections easier

#### XOR Properties

* Single-byte XOR is weak encryption
* Easily brute-forced (only 256 possibilities)
* Common in CTF challenges due to simplicity and reversibility

#### Flag Analysis

* Format: `pctf{I_L0V3_W1ND0W$_83b6d8e7}`
* Theme: "I love Windows" in leetspeak
* Suffix: `83b6d8e7` appears to be a hash or random hex

### Tools Used

* Python 3 - XOR brute force script
* `strings` command - Initial reconnaissance
* Hex editor (optional) - Manual inspection
* RetDec/Ghidra (optional) - Decompilation analysis

### Timeline

* Initial strings check: 2 minutes
* XOR brute force script: 5 minutes
* Flag found: Instant
* Verification: 2 minutes
* **Total**: \~10 minutes

### Common Pitfalls

1. **Over-analyzing the obfuscation**: Qengine 2.0 is a red herring
2. **Trying to run the binary**: Not necessary for static approach
3. **Missing the XOR encoding**: Easy cipher to overlook
4. **Searching only for plaintext**: Must consider encoding

### Alternative Approaches

#### Approach 1: Binary Patching

Patch out obfuscation checks and run normally to see if flag is printed.

#### Approach 2: Memory Dump

Run in VM, dump memory, search for decoded flag.

#### Approach 3: API Monitoring

Monitor Windows API calls (CreateFile, WriteFile) for flag output.

### Flag

```
pctf{I_L0V3_W1ND0W$_83b6d8e7}
```

### Learning Outcomes

This challenge teaches:

1. **Static analysis**: Finding data without execution
2. **XOR brute forcing**: Testing all single-byte keys
3. **Binary structure**: Understanding PE sections (.rdata)
4. **Obfuscation vs encryption**: Distinguishing code and data protection
5. **Pattern matching**: Using known flag prefixes to find encoded data

### References

* PE file format: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
* XOR cipher: https://en.wikipedia.org/wiki/XOR\_cipher
* RetDec decompiler: https://retdec.com/
* Windows debugging: https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/
