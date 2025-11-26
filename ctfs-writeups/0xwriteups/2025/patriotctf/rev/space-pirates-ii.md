# Space Pirates II

## Space Pirates 2 - Writeup

### Challenge Information

* **Category**: Reverse Engineering
* **Points**: Medium
* **Author**: caffix
* **Description**: You decoded the coordinates and found the pirates' hidden base. Now you've discovered their treasure map, but it's encrypted with an even MORE complex cipher. The pirates learned from their mistake and upgraded their security!

### Files Provided

* `main.rs` - Complete Rust source code

### Solution

#### Overview

This is the second challenge in the Space Pirates trilogy. The encryption has been **upgraded from 4 operations to 6 operations**, introducing new techniques:

* Bit rotation operations
* Chunk-based reversal
* Quadratic position encoding

#### Constants and Target

```rust
const TARGET: [u8; 32] = [
    0x15, 0x5A, 0xAC, 0xF6, 0x36, 0x22, 0x3B, 0x52,
    0x6C, 0x4F, 0x90, 0xD9, 0x35, 0x63, 0xF8, 0x0E,
    0x02, 0x33, 0xB0, 0xF1, 0xB7, 0x69, 0x42, 0x67,
    0x25, 0xEA, 0x96, 0x63, 0x1B, 0xA7, 0x03, 0x0B
];

const XOR_KEY: [u8; 5] = [0x7E, 0x33, 0x91, 0x4C, 0xA5];
const ROTATION_PATTERN: [u32; 7] = [1, 3, 5, 7, 2, 4, 6];
const MAGIC_SUB: u8 = 0x5D;
```

#### Encryption Pipeline (6 Operations)

**Operation 1**: XOR with rotating 5-byte key

```rust
buffer[i] ^= XOR_KEY[i % 5];
```

**Operation 2**: Rotate left with varying amounts (NEW!)

```rust
rotation = ROTATION_PATTERN[i % 7];
buffer[i] = rotate_left(buffer[i], rotation);
```

* Rotation pattern: `[1, 3, 5, 7, 2, 4, 6]`
* Each byte rotated by different amount based on position

**Operation 3**: Swap adjacent byte pairs

```rust
buffer.swap(i, i+1);
```

**Operation 4**: Subtract magic constant (CHANGED!)

```rust
buffer[i] = buffer[i].wrapping_sub(MAGIC_SUB);
```

* Now uses **subtraction** instead of addition

**Operation 5**: Reverse bytes in chunks of 5 (NEW!)

```rust
for chunk in buffer.chunks_mut(5) {
    chunk.reverse();
}
```

* 32 bytes split into chunks: `[0-4], [5-9], [10-14], [15-19], [20-24], [25-29], [30-31]`
* Last chunk has only 2 bytes

**Operation 6**: XOR with position² (mod 256) (NEW!)

```rust
position_squared = ((i * i) % 256) as u8;
buffer[i] ^= position_squared;
```

#### Reverse Engineering Solution

To recover the flag, we reverse each operation in **opposite order**:

```python
#!/usr/bin/env python3

TARGET = [
    0x15, 0x5A, 0xAC, 0xF6, 0x36, 0x22, 0x3B, 0x52,
    0x6C, 0x4F, 0x90, 0xD9, 0x35, 0x63, 0xF8, 0x0E,
    0x02, 0x33, 0xB0, 0xF1, 0xB7, 0x69, 0x42, 0x67,
    0x25, 0xEA, 0x96, 0x63, 0x1B, 0xA7, 0x03, 0x0B
]

XOR_KEY = [0x7E, 0x33, 0x91, 0x4C, 0xA5]
ROTATION_PATTERN = [1, 3, 5, 7, 2, 4, 6]
MAGIC_SUB = 0x5D

def ror(byte, n):
    """Rotate right (inverse of rotate left)"""
    n %= 8
    return ((byte >> n) | ((byte << (8 - n)) & 0xFF)) & 0xFF

def solve():
    buf = TARGET.copy()
    
    # Reverse Operation 6: XOR with position squared
    for i in range(32):
        buf[i] ^= (i * i) % 256
    
    # Reverse Operation 5: Reverse chunks (self-inverse)
    for cs in range(0, 32, 5):
        chunk = buf[cs:cs+5]
        buf[cs:cs+5] = list(reversed(chunk))
    
    # Reverse Operation 4: Add back (inverse of subtract)
    for i in range(32):
        buf[i] = (buf[i] + MAGIC_SUB) & 0xFF
    
    # Reverse Operation 3: Swap pairs (self-inverse)
    for i in range(0, 32, 2):
        buf[i], buf[i+1] = buf[i+1], buf[i]
    
    # Reverse Operation 2: Rotate right
    for i in range(32):
        rot = ROTATION_PATTERN[i % 7]
        buf[i] = ror(buf[i], rot)
    
    # Reverse Operation 1: XOR with key (self-inverse)
    for i in range(32):
        buf[i] ^= XOR_KEY[i % 5]
    
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

**Output**: `pctf{Y0U_F0UND_TH3_P1R4T3_B00TY}`

#### Verification

Compile and test the Rust program:

```bash
rustc main.rs -o space_pirates2
./space_pirates2 "pctf{Y0U_F0UND_TH3_P1R4T3_B00TY}"
```

Success! The program displays treasure chest ASCII art.

### Key Insights

#### New Cryptographic Elements

1. **Bit Rotation**
   * Rotation shifts bits circularly: `10110011 ROL 3 → 10011101`
   * Each position uses different rotation amount
   * Inverse: Rotate opposite direction (ROR)
2. **Non-linear Position Encoding**
   * Position² grows: 0, 1, 4, 9, 16, 25, 36, 49...
   * Creates non-uniform position effects
   * Still reversible due to XOR properties
3. **Chunk Reversal**
   * Reverses bytes within 5-byte chunks
   * Mixes local byte order
   * Self-inverse operation

#### Comparison to Level 1

| Feature       | Level 1    | Level 2         |
| ------------- | ---------- | --------------- |
| Operations    | 4          | 6               |
| Length        | 30 bytes   | 32 bytes        |
| Rotation      | None       | Yes (7-pattern) |
| Position func | Linear (i) | Quadratic (i²)  |
| Byte reversal | None       | 5-byte chunks   |
| Math op       | Addition   | Subtraction     |

#### Flag Analysis

* **Format**: `pctf{Y0U_F0UND_TH3_P1R4T3_B00TY}`
* **Theme**: Continues pirate treasure hunt narrative
* **Leetspeak**: `Y0U`, `F0UND`, `TH3`, `P1R4T3`, `B00TY`

### Mathematical Properties

#### Rotation Mathematics

For an 8-bit byte:

* `ROL(x, n) = (x << n) | (x >> (8-n))`
* `ROR(x, n) = (x >> n) | (x << (8-n))`
* `ROL(ROL(x, n), 8-n) = x` (proves invertibility)

#### Bijectivity

All 6 operations are bijective:

1. XOR: `f(f(x)) = x` (involution)
2. ROL: Inverse is ROR
3. Swap: `f(f(x)) = x` (involution)
4. Subtraction: Inverse is addition in Z₂₅₆
5. Reversal: `f(f(x)) = x` (involution)
6. XOR with i²: Still XOR, self-inverse

Composition of bijections is bijective, making entire pipeline reversible.

### Tools Used

* Rust compiler (`rustc`) - Optional for verification
* Python 3 - Solver implementation
* Text editor - Source analysis

### Timeline

* Source analysis: 10 minutes
* Understanding operations: 15 minutes
* Writing solver: 20 minutes
* Testing: 5 minutes
* **Total**: \~50 minutes

### Flag

```
pctf{Y0U_F0UND_TH3_P1R4T3_B00TY}
```

### Learning Outcomes

This challenge teaches:

1. **Bit manipulation**: Rotation operations and their inverses
2. **Non-linear transformations**: Quadratic position encoding
3. **Chunked processing**: Local vs global transformations
4. **Rust syntax**: Understanding Rust's type system
5. **Cipher composition**: Combining multiple reversible operations

### References

* Circular shift: https://en.wikipedia.org/wiki/Circular\_shift
* Rust bitwise ops: https://doc.rust-lang.org/std/primitive.u8.html#method.rotate\_left
* Bijective functions: https://en.wikipedia.org/wiki/Bijection
