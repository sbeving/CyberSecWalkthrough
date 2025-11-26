# Space Pirates III

## Space Pirates 3 - Writeup

### Challenge Information

* **Category**: Reverse Engineering
* **Points**: Hard
* **Author**: caffix
* **Description**: Incredible work! You found the treasure, but wait... there's a note: "This be but a fraction of me fortune! The REAL hoard lies in me secret vault, protected by the most devious cipher ever created by pirate-kind. Only the cleverest of sea dogs can crack it. - Captain Blackbyte"

### Files Provided

* `space_pirates3.go` - Complete Go source code

### Solution

#### Overview

The ultimate challenge in the Space Pirates trilogy! This implements the **most complex cipher** with:

* 7-byte XOR key (prime number for better mixing)
* 8-pattern rotation including identity (rotation by 0)
* 6-byte chunks for reversal
* Enhanced position function: `(i² + i) mod 256`
* Larger subtraction constant: `0x93`

#### Constants and Target

```go
var target = [30]byte{
    0x60, 0x6D, 0x5D, 0x97, 0x2C, 0x04, 0xAF, 0x7C,
    0xE2, 0x9E, 0x77, 0x85, 0xD1, 0x0F, 0x1D, 0x17,
    0xD4, 0x30, 0xB7, 0x48, 0xDC, 0x48, 0x36, 0xC1,
    0xCA, 0x28, 0xE1, 0x37, 0x58, 0x0F,
}

var xorKey = [7]byte{0xC7, 0x2E, 0x89, 0x51, 0xB4, 0x6D, 0x1F}
var rotationPattern = [8]uint{7, 5, 3, 1, 6, 4, 2, 0}
const magicSub byte = 0x93
const chunkSize = 6
```

#### Encryption Pipeline (6 Operations)

**Operation 1**: XOR with 7-byte rotating key

```go
buffer[i] ^= xorKey[i % len(xorKey)]
```

* Longer key period (7 is prime)

**Operation 2**: Rotate left with 8-pattern (includes identity!)

```go
rotation := rotationPattern[i % len(rotationPattern)]
buffer[i] = rotateLeft(buffer[i], rotation)
```

* Pattern: `[7, 5, 3, 1, 6, 4, 2, 0]`
* **Position 7 (mod 8) gets rotation by 0** = identity

**Operation 3**: Swap adjacent byte pairs

```go
buffer[i], buffer[i+1] = buffer[i+1], buffer[i]
```

**Operation 4**: Subtract 0x93

```go
buffer[i] -= magicSub
```

* Much larger constant than previous levels

**Operation 5**: Reverse bytes in chunks of 6

```go
// Reverse each 6-byte chunk
for chunkStart := 0; chunkStart < len(buffer); chunkStart += chunkSize {
    // Reverse chunk in place
}
```

* 30 bytes = exactly 5 chunks of 6 bytes
* Chunks: `[0-5], [6-11], [12-17], [18-23], [24-29]`

**Operation 6**: XOR with (i² + i) mod 256

```go
positionValue := ((i * i) + i) % 256
buffer[i] ^= byte(positionValue)
```

* Enhanced from Level 2's i²
* Formula: `f(i) = i(i + 1)`

#### Reverse Engineering Solution

```python
#!/usr/bin/env python3

TARGET = [
    0x60, 0x6D, 0x5D, 0x97, 0x2C, 0x04, 0xAF, 0x7C,
    0xE2, 0x9E, 0x77, 0x85, 0xD1, 0x0F, 0x1D, 0x17,
    0xD4, 0x30, 0xB7, 0x48, 0xDC, 0x48, 0x36, 0xC1,
    0xCA, 0x28, 0xE1, 0x37, 0x58, 0x0F,
]

XOR_KEY = [0xC7, 0x2E, 0x89, 0x51, 0xB4, 0x6D, 0x1F]
ROTATION_PATTERN = [7, 5, 3, 1, 6, 4, 2, 0]
MAGIC_SUB = 0x93

def ror(byte, n):
    """Rotate right (inverse of rotate left)"""
    n %= 8
    if n == 0:
        return byte  # Identity
    return ((byte >> n) | ((byte << (8 - n)) & 0xFF)) & 0xFF

def solve():
    buf = TARGET.copy()
    
    # Reverse Operation 6: XOR with (i² + i)
    for i in range(30):
        buf[i] ^= ((i * i) + i) % 256
    
    # Reverse Operation 5: Reverse chunks of 6 (self-inverse)
    for cs in range(0, 30, 6):
        chunk = buf[cs:cs+6]
        buf[cs:cs+6] = list(reversed(chunk))
    
    # Reverse Operation 4: Add back (inverse of subtract)
    for i in range(30):
        buf[i] = (buf[i] + MAGIC_SUB) & 0xFF
    
    # Reverse Operation 3: Swap pairs (self-inverse)
    for i in range(0, 30, 2):
        buf[i], buf[i+1] = buf[i+1], buf[i]
    
    # Reverse Operation 2: Rotate right
    for i in range(30):
        rot = ROTATION_PATTERN[i % 8]
        buf[i] = ror(buf[i], rot)
    
    # Reverse Operation 1: XOR with key (self-inverse)
    for i in range(30):
        buf[i] ^= XOR_KEY[i % 7]
    
    # Convert to string
    s = bytes(buf).decode("utf-8")
    print("Recovered input:")
    print(s)

if __name__ == "__main__":
    solve()
```

#### Execution

```bash
python3 solver.py
```

**Output**: `pctf{M4ST3R_0F_TH3_S3V3N_S34S}`

#### Verification

Compile and test:

```bash
go build space_pirates3.go
./space_pirates3 "pctf{M4ST3R_0F_TH3_S3V3N_S34S}"
```

Success! Vault unlocked with elaborate ASCII art.

### Key Insights

#### Advanced Features

1. **Prime-Length XOR Key (7 bytes)**
   * 7 is prime → longer cycle before pattern repeats
   * LCM(7, 8) = 56: full pattern repeats every 56 bytes
   * Better security against frequency analysis
2. **Identity in Rotation Pattern**
   * Rotation by 0 at pattern position 7
   * Every 8th byte (positions 7, 15, 23) is unrotated
   * Introduces non-uniformity in bit diffusion
3. **Enhanced Position Function: i² + i**
   * Factors: `i(i + 1)` = product of consecutive integers
   * Always even (one factor is always even)
   * Sequence: 0, 2, 6, 12, 20, 30, 42, 56, 72, 90...
   * Grows faster than linear, slower than pure quadratic
4. **Perfect Chunk Division**
   * 30 bytes ÷ 6 = exactly 5 chunks (no remainder)
   * Cleaner than Level 2's 32÷5
   * All chunks processed uniformly

#### Trilogy Progression

| Feature       | Level 1 | Level 2   | Level 3                  |
| ------------- | ------- | --------- | ------------------------ |
| Operations    | 4       | 6         | 6                        |
| Length        | 30      | 32        | 30                       |
| XOR key size  | 5 bytes | 5 bytes   | **7 bytes**              |
| Rotation      | None    | 7-pattern | **8-pattern + identity** |
| Position func | i       | i²        | **i² + i**               |
| Chunk size    | None    | 5         | **6**                    |
| Math constant | +0x2A   | -0x5D     | **-0x93**                |

#### Flag Analysis

* **Format**: `pctf{M4ST3R_0F_TH3_S3V3N_S34S}`
* **Theme**: "Master of the Seven Seas" - ultimate pirate achievement
* **Leetspeak**: `M4ST3R`, `TH3`, `S3V3N`, `S34S`

### Mathematical Deep Dive

#### Position Function: f(i) = i² + i

**Properties**:

* Always even: `i(i + 1)` → one of {i, i+1} is even
*   Sequence mod 256:

    ```
    i=0: 0,   i=1: 2,   i=2: 6,   i=3: 12,  i=4: 20
    i=5: 30,  i=6: 42,  i=7: 56,  i=8: 72,  i=9: 90
    i=15: 240, i=16: 16 (wraps at 272 mod 256)
    ```

#### Rotation Pattern Analysis

Pattern `[7, 5, 3, 1, 6, 4, 2, 0]`:

* Large rotations (7, 6) → maximum bit mixing
* Small rotations (1, 2) → subtle changes
* Identity (0) → preserves specific bytes at positions 7, 15, 23

**Bit Diffusion**: Non-uniform but strategic

### Common Pitfalls

1. **Forgetting rotation by 0**: Position 7 (mod 8) is identity
2. **Chunk size confusion**: 6 bytes in Level 3, not 5
3. **XOR key length**: 7 bytes, not 5
4. **Position function**: Remember the `+ i` term

### Tools Used

* Go compiler (`go build`) - Optional verification
* Python 3 - Solver implementation
* Text editor - Source analysis

### Timeline

* Source analysis: 15 minutes
* Understanding enhancements: 10 minutes
* Writing solver: 25 minutes
* Testing: 5 minutes
* **Total**: \~55 minutes

### Flag

```
pctf{M4ST3R_0F_TH3_S3V3N_S34S}
```

### Series Summary

The Space Pirates trilogy teaches progressive reverse engineering:

**Level 1**: Basic bijective operations

* 4 operations: XOR, swap, add, position XOR
* Flag in source comments (easy mode)

**Level 2**: Intermediate techniques

* 6 operations: Added rotation, chunking, quadratic encoding
* Rust implementation

**Level 3**: Advanced mastery

* 6 operations with prime keys, identity operations, enhanced functions
* Go implementation

All three demonstrate:

* **Composition of bijections is reversible**
* **Custom crypto is analyzable with patience**
* **Source code provides full specification**

### Learning Outcomes

This challenge teaches:

1. **Advanced bit manipulation**: Identity rotations, prime-length keys
2. **Mathematical analysis**: Understanding i² + i behavior
3. **Cross-language skills**: Reading Go code
4. **Cipher design**: How complexity builds on fundamentals
5. **Reverse engineering mastery**: Completing a trilogy arc

### References

* Go language: https://golang.org/
* Circular shift: https://en.wikipedia.org/wiki/Circular\_shift
* Prime numbers in crypto: https://en.wikipedia.org/wiki/Prime\_number
* Bijective functions: https://en.wikipedia.org/wiki/Bijection
