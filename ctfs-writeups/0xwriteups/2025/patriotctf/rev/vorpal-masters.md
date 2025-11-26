# Vorpal Masters

## Vorpal Masters - Writeup

### Challenge Information

* **Category**: Reverse Engineering
* **Points**: Medium
* **Author**: Matthew Johnson (CACI)
* **Description**: I'm excited to announce the launch of my brand new video game Vorpal Masters. In light of recent pirating attacks, I've implemented a copy protection by requiring a license key when you launch the game. Before I publish the game to Steam, I just want to have someone test it to make sure it's as uncrackable as I think it is. The flag is the license key, put into the format CACI{Key}

### Files Provided

* `license` - ELF 64-bit executable (Linux binary)

### Solution

#### Initial Analysis

The file is an ELF binary that validates a license key. We need to reverse engineer the validation logic to construct a valid key.

#### Decompilation

Using a decompiler (Ghidra, IDA, or similar), we get the main validation function:

```c
void main(void) {
  int iVar1;
  int local_20;
  char local_1c [11];
  char local_11;
  char local_10;
  char local_f;
  char local_e;
  int local_c;
  
  puts("Welcome to {insert game here}\nPlease enter the license key from the 3rd page of the booklet.");
  local_c = __isoc99_scanf("%4s-%d-%10s", &local_11, &local_20, local_1c);
  
  if (local_c != 3) {
    puts("Please enter you key in the format xxxx-xxxx-xxxx");
    exit(0);
  }
  
  if ((((local_11 != 'C') || (local_f != 'C')) || (local_e != 'I')) || (local_10 != 'A')) {
    womp_womp();
  }
  
  if ((-0x1389 < local_20) && (local_20 < 0x2711)) {
    if ((local_20 + 0x16) % 0x6ca == ((local_20 * 2) % 2000) * 6 + 9) goto LAB_00101286;
  }
  womp_womp();
  
LAB_00101286:
  iVar1 = strcmp(local_1c, "PatriotCTF");
  if (iVar1 != 0) womp_womp();
  puts("Lisence key registered, you may play the game now!");
  return;
}
```

#### Understanding the Key Format

The scanf shows the format: `"%4s-%d-%10s"`

This means the key has **3 parts**:

1. **First part**: 4-character string
2. **Second part**: Integer
3. **Third part**: 10-character string

Format: `XXXX-YYYY-ZZZZZZZZZZ`

#### Solving Part 1: First 4 Characters

The code checks (note: variable arrangement is due to stack layout):

```c
if ((((local_11 != 'C') || (local_f != 'C')) || (local_e != 'I')) || (local_10 != 'A')) {
    womp_womp();
}
```

Looking at the memory layout and variable positions, we need to reconstruct the order. The variables are checked as:

* `local_11` = 'C'
* `local_10` = 'A'
* `local_f` = 'C'
* `local_e` = 'I'

Reading in proper stack order: **`CACI`**

(This matches the flag format mentioned in the description!)

#### Solving Part 2: The Number

The validation checks:

```c
if ((-0x1389 < local_20) && (local_20 < 0x2711)) {
    if ((local_20 + 0x16) % 0x6ca == ((local_20 * 2) % 2000) * 6 + 9)
```

Converting hex to decimal:

* `-0x1389` = -4999
* `0x2711` = 10001
* `0x16` = 22
* `0x6ca` = 1738

So we need: `-4999 < n < 10001` where:

```
(n + 22) % 1738 == ((n * 2) % 2000) * 6 + 9
```

Python brute force:

```python
for n in range(-4999, 10000):
    if (n + 22) % 1738 == ((n * 2) % 2000) * 6 + 9:
        print(n)
```

**Result**: `2025`

#### Solving Part 3: Third String

The final check:

```c
iVar1 = strcmp(local_1c, "PatriotCTF");
if (iVar1 != 0) womp_womp();
```

The third part must be: **`PatriotCTF`**

#### Complete License Key

Combining all parts:

```
CACI-2025-PatriotCTF
```

#### Flag Format

The description says: "The flag is the license key, put into the format CACI{Key}"

**Flag**: `CACI{2025-PatriotCTF}`

### Complete Solver Script

```python
#!/usr/bin/env python3

print("[*] Solving Vorpal Masters license validation...")

# Part 1: First 4 characters
# From decompiled checks: local_11='C', local_10='A', local_f='C', local_e='I'
# Correct stack order: CACI
part1 = "CACI"
print(f"[+] Part 1: {part1}")

# Part 2: The number
# Constraint: -4999 < n < 10001
# Equation: (n + 22) % 1738 == ((n * 2) % 2000) * 6 + 9
print("[*] Brute forcing part 2...")
for n in range(-4999, 10001):
    if (n + 22) % 1738 == ((n * 2) % 2000) * 6 + 9:
        part2 = n
        print(f"[+] Part 2: {part2}")
        break

# Part 3: strcmp check
part3 = "PatriotCTF"
print(f"[+] Part 3: {part3}")

# Assemble license key
license_key = f"{part1}-{part2}-{part3}"
print(f"\n[+] License Key: {license_key}")

# Format as flag
flag = f"CACI{{{part2}-{part3}}}"
print(f"[+] Flag: {flag}")
```

**Output**:

```
[*] Solving Vorpal Masters license validation...
[+] Part 1: CACI
[*] Brute forcing part 2...
[+] Part 2: 2025
[+] Part 3: PatriotCTF
[+] License Key: CACI-2025-PatriotCTF
[+] Flag: CACI{2025-PatriotCTF}
```

### Key Insights

#### Copy Protection Analysis

This simulates **offline license validation**:

* No network required
* Validation entirely in binary
* Multi-part key format with different validation types

Real game DRM would use:

* Hardware fingerprinting
* Online activation servers
* Code obfuscation
* Anti-debugging techniques

#### Validation Techniques

1. **String matching**: First part must be "CACI"
2. **Mathematical constraint**: Number must satisfy equation
3. **String comparison**: Third part must be "PatriotCTF"

#### CACI Context

CACI is a major defense/intelligence contractor. This challenge:

* Demonstrates reverse engineering skills
* Tests decompilation and constraint solving
* Uses company name in flag format
* Likely used for recruiting/training

### Common Pitfalls

1. **Variable order confusion**: Stack layout affects variable ordering
2. **Hex conversion**: Must convert constants properly
3. **Off-by-one**: Range must exclude endpoints (-4999, 10001)
4. **String length**: Third part is exactly 10 characters

### Tools Used

* Ghidra or IDA Pro - Decompilation
* Python 3 - Constraint solving
* Linux/WSL - Binary execution (optional)

### Timeline

* Decompilation: 5 minutes
* Understanding constraints: 10 minutes
* Solving part 2: 5 minutes
* Assembly and verification: 2 minutes
* **Total**: \~22 minutes

### Flag

```
CACI{2025-PatriotCTF}
```

### Learning Outcomes

This challenge teaches:

1. **Binary decompilation**: Reading Ghidra/IDA output
2. **Stack layout**: Understanding variable positioning
3. **Constraint solving**: Brute forcing mathematical equations
4. **License validation**: How software checks serial numbers
5. **Format strings**: Understanding scanf patterns

### References

* ELF format: https://en.wikipedia.org/wiki/Executable\_and\_Linkable\_Format
* Ghidra: https://ghidra-sre.org/
* Software licensing: https://en.wikipedia.org/wiki/Software\_license
* CACI: https://www.caci.com/
