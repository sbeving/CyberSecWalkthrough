# reverse\_py\_bruteforce

### Description

decrypt the flag :D

**author**: 4n7h4r4x

### Files

* flag.txt
* main.py

**Flag:** `Spark{w3lc0m3_t0_b4s1c_brut3f0rc3_4nd_scr1p71ng_b4by}`

**Description:** Python script encrypts flag using XOR with a key derived from a secret character.

**Solution:** The flag format starts with "Spark", so we can bruteforce the secret\_letter:

```python
from random import seed

encrypted = "yyyyyQ~+gqd+TfVz?aGi`_}+m\"Xj+T&DmGxqX8h<#DnGi&Hpe"
known_prefix = "Spark"
secret_pin = 0000

for secret_letter_ord in range(256):
    secret_letter = chr(secret_letter_ord)
    
    old_key = known_prefix
    key = ""
    seed(secret_pin)
    for i in range(len(old_key)):
        key += chr(ord(old_key[i]) ^ ord(secret_letter))
    
    try:
        flag = ""
        for i in range(len(encrypted)):
            flag += chr(ord(encrypted[i]) ^ ord(key[i % 5]))
        
        if flag.startswith("Spark{"):
            print(f"Flag: {flag}")
            break
    except:
        continue
```

The secret\_letter is 'y'.

***
