# Intro Crypto 1

## CTF Write-up: Intro Crypto 1 - Keystream Reuse Attack



**Challenge:** Intro Crypto 1

**Description:** What is this non(c/s)ence everyonce is taking about? Given 255 ciphers and a hex encoded flag

**Attachments:** (Presumably `ciphers.txt` containing 255 hex-encoded lines and the hex-encoded flag ciphertext mentioned in the code)

#### Analysis

1. **The Hint:** The description "non(c/s)ence" and "everyonce" strongly hints at problems related to **nonce** reuse or the reuse of a **one-time** pad/keystream. Stream ciphers (or the One-Time Pad, OTP) rely on XORing plaintext with a keystream (`Ciphertext = Plaintext ^ Keystream`). The security relies crucially on the keystream _never_ being reused for different plaintexts with the same key.
2. **The Input:** We are given multiple ciphertexts (255 of them) and the specific ciphertext corresponding to the flag. This setup, combined with the hint, points towards a scenario where the same keystream was likely used to encrypt multiple different plaintexts, including the flag.
3. **The Vulnerability (Keystream Reuse):** If the same keystream `K` is used to encrypt two different plaintexts `P1` and `P2`:
   * `C1 = P1 ^ K`
   * `C2 = P2 ^ K`     \
     XORing the two ciphertexts cancels out the keystream:
   * `C1 ^ C2 = (P1 ^ K) ^ (P2 ^ K) = P1 ^ P2 ^ K ^ K = P1 ^ P2`     \
     This means XORing any two ciphertexts produced with the same keystream reveals the XOR sum of their corresponding plaintexts.

#### Attack Plan - The "Crib" or Known Plaintext Assumption

While `C1 ^ C2 = P1 ^ P2` is useful, it doesn't directly give us either plaintext. However, there's a special case often found in CTFs:

* **What if one of the plaintexts was all zeros (or another known value)?**  \
  Let's say `P1` consisted entirely of null bytes (`P1 = b'\x00\x00\x00...'`). Then:
  * `C1 = P1 ^ K = 0s ^ K = K`    \
    This means the ciphertext `C1` _is_ the keystream itself!
* **Recovering the Flag:** If we find this specific ciphertext (`C1 = K`), we can XOR it with the flag's ciphertext (`C_flag = P_flag ^ K`) to recover the flag's plaintext (`P_flag`):
  * `C1 ^ C_flag = K ^ (P_flag ^ K) = K ^ P_flag ^ K = P_flag`

The attack plan is therefore:

1. Assume one of the 255 provided ciphertexts (`ciphertexts[i]`) corresponds to the encryption of an all-zero plaintext, meaning `ciphertexts[i]` is the keystream.
2. Iterate through each `ciphertexts[i]`.
3. XOR `ciphertexts[i]` with the `flag_ciphertext`.
4. If the result starts with the known flag format prefix (e.g., `CSCG{`), we have likely found the correct `ciphertexts[i]` (the keystream) and successfully recovered the flag.

#### Implementation (Solver Script)

The provided Python script executes this attack plan:

```python
from binascii import unhexlify, hexlify

# read the ciphertexts from the file (assuming it exists)
ciphertexts = []
try:
    with open("ciphers.txt", "r") as f:
        for line in f:
            # Skip empty lines if any
            line = line.strip()
            if line:
                ciphertexts.append(unhexlify(line))
except FileNotFoundError:
    print("Error: ciphers.txt not found. Please ensure it's in the same directory.")
    exit(1)
except Exception as e:
    print(f"Error reading ciphers.txt: {e}")
    exit(1)

# The hex-encoded ciphertext of the flag
flag_ciphertext_hex = "2188df14ac8cfc479f2c8ec3656a0f4c337f19c9eacee03a9d79bf75fcea51fde507838dbd9413feb164bd966558eb6f667eefc537542b7377ea43579e40be74cebfede6a0107921efbd"
try:
    flag_ciphertext = unhexlify(flag_ciphertext_hex)
except Exception as e:
    print(f"Error decoding flag ciphertext hex: {e}")
    exit(1)

print(f"Loaded {len(ciphertexts)} ciphertexts.")
print(f"Flag ciphertext length: {len(flag_ciphertext)} bytes.")

found = False
for i, ct in enumerate(ciphertexts):
    # Ensure we only XOR up to the shortest length to avoid errors
    min_len = min(len(ct), len(flag_ciphertext))
    if min_len == 0:
        continue # Skip empty ciphertexts

    # Perform the XOR operation
    possible_flag_bytes = bytes(a ^ b for a, b in zip(ct[:min_len], flag_ciphertext[:min_len]))

    # Check if the result starts with the expected flag prefix
    # Use bytes for comparison
    if possible_flag_bytes.startswith(b"CSCG{"):
        print(f"\nPotential match found with Ciphertext index {i}:")
        try:
            # Try decoding the full XOR result
            decoded_flag = possible_flag_bytes.decode('ascii')
            print(f"Recovered Flag: {decoded_flag}")
            found = True
            # Assuming only one correct answer, we can break
            break
        except UnicodeDecodeError:
            print(f"Result starts with prefix but contains non-ASCII bytes. Raw bytes: {possible_flag_bytes}")

if not found:
    print("\nNo flag starting with 'CSCG{' found using this method.")

```

#### Execution and Result

Running the script performs the XOR operations. As shown in the provided success output, the script found a match:

```
Counter 23: CSCG{turns_out_that_once_in_nonce_is_actually_important_who'd've_thought?}
```

This indicates that `ciphertexts[23]` was indeed the keystream (likely the result of encrypting all zeros). XORing it with `flag_ciphertext` revealed the flag.

**Flag:** `CSCG{turns_out_that_once_in_nonce_is_actually_important_who'd've_thought?}`

#### Conclusion

This challenge perfectly illustrates the danger of keystream reuse in stream ciphers and OTPs, often caused by reusing a nonce or cryptographic key. By XORing ciphertexts created with the same keystream, we can eliminate the key and potentially recover plaintexts, especially if one of the plaintexts is known (like a string of zeros). The flag itself cleverly comments on the importance of nonce uniqueness.
