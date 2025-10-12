---
description: it's not only n this time there is y now can you defeat RSA
---

# RSA\_1

### Files

* output.txt
* rsa1.py

#### AES

**Flag:** `Spark{A3S_1s_s1mpl3_4sf}`

**Description:** AES-CBC decryption with key and IV provided.

**Solution:** Straightforward AES-CBC decryption:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = bytes.fromhex('bb9ff5edc3641e9904df4454a791a6ee')
iv = bytes.fromhex('2146af68c022f3486fdf6e52c05426bd')
ciphertext = bytes.fromhex('90aa85aaa23a7d0e461554715bb3569234f0d2d9fdda573611510ceb6a5544a0')

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)
flag = unpad(plaintext, AES.block_size)

print(flag.decode())  # Spark{A3S_1s_s1mpl3_4sf}
```

***
