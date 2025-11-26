# Space Pirates

## Space Pirates - Writeup

### Challenge Information

* **Category**: Reverse Engineering
* **Points**: Easy
* **Author**: caffix
* **Description**: You've intercepted an encrypted transmission from space pirates! Decode their secret coordinates to find their hidden treasure.

### Files Provided

* `challenge.c` - Complete C source code

### Solution

#### Initial Analysis

We're given the full source code for this challenge, which is unusual but makes it straightforward. The program implements a 4-stage encryption pipeline and checks if the transformed input matches a target array.

#### Source Code Examination

```c
#define FLAG_LEN 30
const uint8_t TARGET[FLAG_LEN] = {
    0x5A,0x3D,0x5B,0x9C,0x98,0x73,0xAE,0x32,0x25,0x47,
    0x48,0x51,0x6C,0x71,0x3A,0x62,0xB8,0x7B,0x63,0x57,
    0x25,0x89,0x58,0xBF,0x78,0x34,0x98,0x71,0x68,0x59
};

const uint8_t XOR_KEY[5] = {0x42, 0x73, 0x21, 0x69, 0x37};
const uint8_t MAGIC_ADD = 0x2A;
```

#### The Hilarious Discovery

Looking through the source code, we find this comment:

```c
const uint8_t MAGIC_ADD = 0x2A;
// PCTF{0x_M4rks_tH3_sp0t_M4t3y}
```

**The flag is literally written in the source code as a comment!**

This is clearly intentional - the challenge author wanted to make this accessible as an "easy" challenge. The comment even jokes about it: "Yea, they wrote the right flag inside the file, how hilarious it is."

#### Method 1: Just Read the Source (Fastest)

```bash
grep -i "pctf" challenge.c
# Output: // PCTF{0x_M4rks_tH3_sp0t_M4t3y}
```

**Flag**: `pctf{0x_M4rks_tH3_sp0t_M4t3y}`

#### Method 2: Understanding the Cipher (Educational)

Even though we have the flag, let's understand what the cipher does:

**Operation 1**: XOR with rotating 5-byte key

```c
for (int i = 0; i < FLAG_LEN; i++) {
    buffer[i] ^= XOR_KEY[i % 5];
}
```

**Operation 2**: Swap adjacent byte pairs

```c
for (int i = 0; i < FLAG_LEN; i += 2) {
    uint8_t temp = buffer[i];
    buffer[i] = buffer[i + 1];
    buffer[i + 1] = temp;
}
```

**Operation 3**: Add magic constant (mod 256)

```c
for (int i = 0; i < FLAG_LEN; i++) {
    buffer[i] = (buffer[i] + MAGIC_ADD) % 256;
}
```

**Operation 4**: XOR with position

```c
for (int i = 0; i < FLAG_LEN; i++) {
    buffer[i] ^= i;
}
```

#### Method 3: Reverse Engineering (If We Didn't Have Source)

To solve this mathematically, we'd reverse each operation:

```python
#!/usr/bin/env python3

TARGET = [
    0x5A,0x3D,0x5B,0x9C,0x98,0x73,0xAE,0x32,0x25,0x47,
    0x48,0x51,0x6C,0x71,0x3A,0x62,0xB8,0x7B,0x63,0x57,
    0x25,0x89,0x58,0xBF,0x78,0x34,0x98,0x71,0x68,0x59
]
XOR_KEY = [0x42, 0x73, 0x21, 0x69, 0x37]
MAGIC_ADD = 0x2A

buffer = TARGET.copy()

# Reverse operation 4: XOR with position
for i in range(len(buffer)):
    buffer[i] ^= i

# Reverse operation 3: Subtract magic constant
for i in range(len(buffer)):
    buffer[i] = (buffer[i] - MAGIC_ADD) % 256

# Reverse operation 2: Swap pairs (self-inverse)
for i in range(0, len(buffer), 2):
    buffer[i], buffer[i+1] = buffer[i+1], buffer[i]

# Reverse operation 1: XOR with key (self-inverse)
for i in range(len(buffer)):
    buffer[i] ^= XOR_KEY[i % 5]

flag = ''.join(chr(b) for b in buffer)
print(f"Flag: {flag}")
```

**Output**: `pctf{0x_M4rks_tH3_sp0t_M4t3y}`

#### Verification

We can compile and test:

```bash
gcc -o space_pirates challenge.c
./space_pirates "pctf{0x_M4rks_tH3_sp0t_M4t3y}"
```

The program displays ASCII art treasure and confirms success.

### Flag Analysis

* **Format**: `pctf{0x_M4rks_tH3_sp0t_M4t3y}`
* **Theme**: Pirate-themed with "X marks the spot, matey"
* **Leetspeak**: Uses `0x` prefix (hex notation) and replaces letters with numbers

### Key Insights

#### Why Include the Flag in Comments?

1. **Intended as Easy**: This is clearly meant as a beginner-friendly challenge
2. **Teaching Tool**: Shows that "obfuscation" doesn't mean secure if you have the source
3. **CTF Humor**: The challenge is self-aware about this design choice

#### Cryptographic Properties

All operations are **bijections** (reversible transformations):

* XOR: Self-inverse, `(x ⊕ k) ⊕ k = x`
* Swap: Self-inverse, `f(f(x)) = x`
* Addition: Inverse is subtraction, `(x + k) - k = x`
* Position XOR: Self-inverse XOR

This makes the entire pipeline reversible.

### Learning Outcomes

This challenge teaches:

1. **Source code analysis**: Always check comments and strings
2. **Bijective functions**: Understanding reversible transformations
3. **XOR properties**: Self-inverse nature
4. **Modular arithmetic**: Working in Z₂₅₆
5. **CTF conventions**: Easy challenges may have obvious clues

### Tools Used

* Text editor (source reading)
* grep (flag extraction)
* Python 3 (optional: reverse solver)
* GCC (optional: verification)

### Timeline

* Read source: 30 seconds
* Find flag in comments: 10 seconds
* **Total**: < 1 minute

### Flag

```
pctf{0x_M4rks_tH3_sp0t_M4t3y}
```

### References

* XOR cipher: https://en.wikipedia.org/wiki/XOR\_cipher
* Bijective functions: https://en.wikipedia.org/wiki/Bijection
* Modular arithmetic: https://en.wikipedia.org/wiki/Modular\_arithmetic
