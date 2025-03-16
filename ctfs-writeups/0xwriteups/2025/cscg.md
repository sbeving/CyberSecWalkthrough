# 🇩🇪 CSCG

### Description

What is this non(c/s)ence everyonce is taking about?

<figure><img src="../../../.gitbook/assets/Pasted image 20250304135244.png" alt=""><figcaption></figcaption></figure>

Given 255 ciphers and a hex encoded flag

<figure><img src="../../../.gitbook/assets/Pasted image 20250304135327 (1).png" alt=""><figcaption></figcaption></figure>

I saved the ciphers to a file and

```python
from binascii import unhexlify, hexlify

# read the ciphertexts from the file
ciphertexts = []
with open("ciphers.txt", "r") as f:
    for line in f:
        ciphertexts.append(unhexlify(line.strip()))



flag_ciphertext = unhexlify("2188df14ac8cfc479f2c8ec3656a0f4c337f19c9eacee03a9d79bf75fcea51fde507838dbd9413feb164bd966558eb6f667eefc537542b7377ea43579e40be74cebfede6a0107921efbd")

for i, ct in enumerate(ciphertexts):
    possible_flag = bytes(a ^ b for a, b in zip(ct, flag_ciphertext))
    if possible_flag.startswith(b"CSCG{"):  # Adjust based on flag format
        print(f"Counter {i}: {possible_flag.decode('ascii')}")
        break
# Counter 23: CSCG{turns_out_that_once_in_nonce_is_actually_important_who'd've_thought?}
```
