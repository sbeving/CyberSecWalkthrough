---
description: Here you'll find different Reverse tasks solved step-by-step
---

# ⏪ Reverse Engineering

### Yes Xor Not

<figure><img src="../../../../.gitbook/assets/image (70).png" alt=""><figcaption></figcaption></figure>

The given file contained this code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() {
        char * flag = "REDACTED";
        int i,c, r = rand() % 32;
        char aux;
    for(i = 0;i < strlen(flag);i++){
        c = flag[i];
        aux = c^r;
        printf("%c",aux);
  }
    return 0;
}
//program output : Twful|O7pXJ3i~XS6j4tXC7X6XO3q4X5X04KKX^7rz`
```

As we know using the output as an input in a XORing function it will return the flag

```c
char * flag = "Twful|O7pXJ3i~XS6j4tXC7X6XO3q4X5X04KKX^7rz`";
```

After executing the script Ladies & Gentlemen we got it

> Spark{H0w\_M4ny\_T1m3s\_D0\_1\_H4v3\_2\_73LL\_Y0u}

### StringMe

<figure><img src="../../../../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

The title is a hint as it refers to the **Strings** command to run on executable file

&#x20;&#x20;

<figure><img src="../../../../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

### INTRO TO REV

<figure><img src="../../../../.gitbook/assets/image (79).png" alt=""><figcaption></figcaption></figure>

Strings command may get the flag&#x20;

<figure><img src="../../../../.gitbook/assets/image (78).png" alt=""><figcaption></figcaption></figure>

### GU3SS&#x20;

<figure><img src="../../../../.gitbook/assets/image (80).png" alt=""><figcaption></figcaption></figure>

### P4RTS

<figure><img src="../../../../.gitbook/assets/image (81).png" alt=""><figcaption></figcaption></figure>



