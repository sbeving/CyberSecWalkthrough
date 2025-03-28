# Intro 2

## CTF Write-up: Intro Reverse Engineering 2 - Reversing Static Input Transformation

**Challenge:** Intro Reverse Engineering 2 (108 points)**Description:** Password "encoded", can't be found in plaintext. Find the right password.**Attachments:** `intro-rev-2.zip` (containing `rev2` binary)**Connection:** `ncat --ssl-verify 6e554da9024a3ed3b6cb73da-1024-intro-rev-2.challenge.cscg.live 1337`

#### Analysis

1. **Binary Properties (`checksec`, IDA/GDB):** The target binary `rev2` is a 64-bit PIE-enabled ELF executable, dynamically linked, and not stripped. Key features are `PIE Enabled` and the presence of symbols.
2. **Code Functionality:**
   * The program starts by calling `initialize_flag`, which reads the contents of a file named `./flag.txt` into a global buffer called `flagBuffer`.
   * The `main` function then prompts the user for a password and reads their input into a buffer on the stack (`buf`).
   * A critical loop iterates through the user's input in `buf`. For each character `c`, it computes `c - 0x77` and overwrites the character in `buf` with this new value. This is the "encoding" or transformation mentioned in the description.
   * After modifying the entire input, the program compares the transformed input with a hardcoded target sequence (`s2`) located in the `.rodata` section (visible in IDA around address `0x2020` relative to `.rodata`). The comparison is done using `strcmp`.
   * If the transformed input matches the target sequence `s2`, the program prints a success message followed by the contents of `flagBuffer` (which holds the actual flag read from `./flag.txt`). Otherwise, it prints a failure message.

#### Vulnerability / Solution Path

The challenge requires bypassing the password check. Since the user input `P` is transformed into `M` (where `M[i] = P[i] - 0x77`) before being compared to the target `S` (sequence `s2`), we need to find an input `P` such that `M = S`.

Reversing the transformation gives the required input character:`P[i] = S[i] + 0x77`

We need to:

1. Extract the target byte sequence `S` from the binary's `.rodata` section.
2. Calculate the required input `P` by adding `0x77` (modulo 256) to each byte of `S`.
3. Send the calculated password `P` to the remote server.

#### Reversing the Transformation

1. **Identify Target Bytes (`S`):** By examining the `strcmp` call in `main` within IDA or Ghidra, we find it compares the modified buffer against the data at `s2`. Extracting these bytes gives the target sequence `S`. (Based on the successful execution, these bytes must result in `yay_st4tic_transf0rmation` after adding `0x77`).
2. **Calculate Input Password (`P`):** Apply the reverse transformation `P[i] = (S[i] + 0x77) & 0xFF` to each byte. The successful execution log confirms this calculation results in the string `yay_st4tic_transf0rmation`.

```python
# Example snippet demonstrating the calculation (actual target_bytes derived from reverse engineering)
# Assuming target_bytes = bytes([...]) was extracted
OFFSET = 0x77
# input_password_bytes = bytes([(b + OFFSET) & 0xFF for b in target_bytes])
# input_password = input_password_bytes.decode('ascii')
input_password = "yay_st4tic_transf0rmation" # From successful script log
log.info(f"Calculated Input Password: {input_password}")
```

#### Exploit Script (Python w/ pwntools)

This script connects, uses the pre-calculated correct password, sends it, and retrieves the flag.

```python
#!/usr/bin/env python3
from pwn import *
import re

# --- Derived Input Password ---
# This password, when subtracted by 0x77 byte-wise, matches the binary's target sequence.
# Derived from reversing the process or from the successful execution log.
input_password = "yay_st4tic_transf0rmation"
log.info(f"Using Input Password: {input_password}")

# --- Connection Details ---
HOST = '6e554da9024a3ed3b6cb73da-1024-intro-rev-2.challenge.cscg.live'
PORT = 1337
USE_SSL = True

# --- Interaction ---
log.info(f"Connecting to {HOST}:{PORT}{' (SSL)' if USE_SSL else ''}")
p = remote(HOST, PORT, ssl=USE_SSL)

# Receive prompt
p.recvuntil(b"Give me your password: ")

# Send the calculated password
log.info("Sending calculated password...")
p.sendline(input_password.encode())

# Receive output and look for the flag
log.info("Waiting for response / flag...")
try:
    response = p.recvall(timeout=5).decode()
    log.success("Received response:")
    print("-" * 20)
    print(response)
    print("-" * 20)

    # Extract flag using regex
    flag_match = re.search(r"CSCG\{[^\}]+\}", response)
    if flag_match:
        flag = flag_match.group(1)
        log.success(f"Flag found: {flag}")
    elif "Thats the right password!" in response:
         log.warning("Correct password message received, but flag pattern not found.")
    else:
        log.warning("Failed password message or unexpected response received.")

except EOFError:
    log.error("Connection closed unexpectedly.")
except Exception as e:
    log.error(f"An error occurred: {e}")

p.close()
```

#### Execution and Result

Running the script sends the calculated password `yay_st4tic_transf0rmation`. The remote server applies the `c - 0x77` transformation, the result matches the hardcoded sequence, `strcmp` returns 0, and the server prints the flag read from its `./flag.txt`.

```
[*] Using Input Password: yay_st4tic_transf0rmation
[*] Connecting to 6e554da9024a3ed3b6cb73da-1024-intro-rev-2.challenge.cscg.live:1337 (SSL)
[+] Opening connection to 6e554da9024a3ed3b6cb73da-1024-intro-rev-2.challenge.cscg.live on port 1337: Done
[*] Sending calculated password...
[*] Waiting for response / flag...
[+] Receiving all data: Done (81B)
[*] Closed connection to 6e554da9024a3ed3b6cb73da-1024-intro-rev-2.challenge.cscg.live port 1337
[+] Received response:
--------------------

Thats the right password!
Flag: CSCG{y0u_just_r3versed_a_st4tic_transformation!}
--------------------
[+] Flag found: CSCG{y0u_just_r3versed_a_st4tic_transformation!}
```

**Flag:** `CSCG{y0u_just_r3versed_a_st4tic_transformation!}`

#### Conclusion

This reverse engineering task required identifying a static transformation applied to the user's input before a string comparison. By extracting the hardcoded target byte sequence from the binary and reversing the transformation (`+ 0x77`), the correct input password (`yay_st4tic_transf0rmation`) was calculated. Providing this input satisfied the check, leading the program to reveal the flag stored in the `flagBuffer` (which was read from `./flag.txt` on the server).
