# Are You Pylingual?

## Are You Pylingual? - Writeup

### Challenge Information

* **Category**: Reverse Engineering
* **Points**: Easy
* **Author**: DJ Strigel
* **Description**: I found this weird binary in my mom's computer. I'm not sure what it even is or why it was there. I heard it was put there from a past member of MasonCC. He did some obfuscation to make his Python code unreadable. Reverse engineer the program and see if anything of interest lies in the output.

### Files Provided

* `pylinguese.pyc` - Python bytecode file
* `output.txt` - Encrypted output array

### Solution

#### Step 1: Decompile the Bytecode

Python `.pyc` files can be decompiled back to source code:

```bash
uncompyle6 pylinguese.pyc
# or: decompyle3 pylinguese.pyc
```

#### Decompiled Source Code

```python
import pyfiglet

file = open('flag.txt', 'r')
flag = file.read()
font = 'slant'
words = 'MASONCC IS THE BEST CLUB EVER'
flag_track = 0

art = list(pyfiglet.figlet_format(words, font=font))
i = len(art) % 10

for ind in range(len(art)):
    if ind == i and flag_track < len(flag):
        art[ind] = flag[flag_track]
        i += 28  # Note: Original writeup had error, actual code increments by 28
        flag_track += 1

art_str = ''.join(art)
first_val = 5
second_val = 6
first_half = art_str[:len(art_str) // 2]
second_half = art_str[len(art_str) // 2:]

first = [~ord(char) ^ first_val for char in first_half]
second = [~ord(char) ^ second_val for char in second_half]

output = second + first
print(output)
```

#### Understanding the Algorithm

**Stage 1**: Generate ASCII art

* Creates figlet art for "MASONCC IS THE BEST CLUB EVER"
* Converts to list of characters

**Stage 2**: Hide flag in art (Steganography)

* Embeds flag characters at positions: `i, i+28, i+56, i+84...`
* Starting position: `i = len(art) % 10`
* This hides the flag within the ASCII art

**Stage 3**: Encode the art string

* Split into two halves: `first_half` and `second_half`
* Encode first half: `~ord(char) ^ 5`
* Encode second half: `~ord(char) ^ 6`
* Output: `second + first` (reversed concatenation)

#### Encoding Formula

For each character:

```python
encoded = ~ord(char) ^ key
```

Where `~` is bitwise NOT and `^` is XOR.

#### Decoding Strategy

To reverse:

```python
decoded_ord = (~(encoded ^ key)) & 0xFF
decoded_char = chr(decoded_ord)
```

**Proof**: `~((~x ^ k) ^ k) = ~(~x) = x`

#### Complete Solver

```python
from pyfiglet import figlet_format

# Load encrypted output
output = [...]  # From output.txt

first_val = 5
second_val = 6

# Split back into second and first parts
L = len(output)
first_len = L // 2
second_len = L - first_len

second_enc = output[:second_len]
first_enc = output[second_len:]

# Decode function
def decode_list(enc_list, val):
    chars = []
    for v in enc_list:
        o = (~(v ^ val)) & 0xFF
        chars.append(chr(o))
    return ''.join(chars)

# Decode both halves
first_half = decode_list(first_enc, first_val)
second_half = decode_list(second_enc, second_val)

# Reconstruct full art string
art_str = first_half + second_half

print("[*] Decoded ASCII art:")
print(art_str[:1000])

# Extract flag from embedded positions
# Generate original figlet to determine pattern
words = 'MASONCC IS THE BEST CLUB EVER'
font = 'slant'
original_art = figlet_format(words, font=font)

# Flag was inserted at positions i, i+28, i+56, ...
art_list = list(art_str)
i = len(original_art) % 10

flag_chars = []
pos = i
while pos < len(art_list):
    flag_chars.append(art_list[pos])
    pos += 28

flag = ''.join(flag_chars)
print(f"\n[+] Flag: {flag}")
```

#### Decoded ASCII Art (Partial)

```
  p __  ______   _____ ____  _c  ______________   ________t
   /  |/  /   | / ___// __f\/ | / / ____/ ____/  /  _/{___/
  / /|_/ / /| | \__ \/o/ / /  |/ / /   / /       /b/ \__ \
 / /  / / ___ |___F / /_/ / /|  / /___/ /___  u_/ / ___/ /
/_/  /_/_/  |_s____/\____/_/ |_/\____/\___c/  /___//____/
          4                           t
...
```

Notice the flag characters embedded: `p`, `c`, `t`, `f`, `{`, `o`, `b`, `F`, `u`, `s`, `c`, `4`, `t`, `i`, `0`, `n`, etc.

#### Flag Extraction

Reading every 28th character starting from position `i`:

```
p c t f { o b F u s c 4 t i 0 n _ i 5 n ' t _ E n c R y p t 1 o N }
```

Concatenated: **`pctf{obFusc4ti0n_i5n't_EncRypt1oN}`**

### Key Insights

#### Steganography Technique

* Flag hidden **within** ASCII art at regular intervals
* Spacing (every 28 characters) makes it non-obvious visually
* MasonCC club message serves as "cover text"

#### Encoding Analysis

* **Bitwise NOT** (`~`): Flips all bits
* **XOR**: Provides reversible encryption
* **Combination**: Creates non-trivial encoding
* Both operations are bijective (reversible)

#### MasonCC Reference

* George Mason University's CTF club
* Challenge celebrates the club with the cover message
* Theme matches the flag: obfuscation isn't encryption

### Common Mistakes

1. **Wrong step order**: Must decode before extracting flag positions
2. **Incorrect spacing**: Flag positions are every 28 chars, not every 10
3. **Split confusion**: Output is `second + first`, not `first + second`
4. **Bitwise NOT handling**: Must mask with `& 0xFF` to keep as byte

### Tools Used

* `uncompyle6` or `decompyle3` - Python bytecode decompiler
* `pyfiglet` - ASCII art generator (`pip install pyfiglet`)
* Python 3 - Solver implementation

### Timeline

* Decompile .pyc: 2 minutes
* Understand encoding: 10 minutes
* Write decoder: 15 minutes
* Extract flag: 5 minutes
* **Total**: \~32 minutes

### Flag

```
pctf{obFusc4ti0n_i5n't_EncRypt1oN}
```

### Learning Outcomes

This challenge teaches:

1. **Python bytecode decompilation**: Recovering source from .pyc files
2. **Bitwise operations**: Understanding NOT, XOR, and their inverses
3. **Steganography**: Hiding data within other data structures
4. **ASCII art techniques**: Using figlet and text-based graphics
5. **Security principle**: Obfuscation ≠ encryption (as the flag states!)

### References

* uncompyle6: https://github.com/rocky/python-uncompyle6
* pyfiglet: https://github.com/pwaller/pyfiglet
* Python bitwise operators: https://wiki.python.org/moin/BitwiseOperators
* Steganography: https://en.wikipedia.org/wiki/Steganography
