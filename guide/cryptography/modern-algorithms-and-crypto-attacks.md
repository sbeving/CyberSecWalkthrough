---
icon: gamepad-modern
---

# Modern Algorithms & Crypto Attacks

> 🧩 “Understand math, not magic.”\
> Modern CTF crypto challenges simulate _implementation flaws_ — not breaking perfect math, but **exploiting mistakes, shortcuts, and mis-use**.

***

### I. ⚙️ **The Modern Crypto Landscape**

| Algorithm                | Type                    | Usage                 | Notes                               |
| ------------------------ | ----------------------- | --------------------- | ----------------------------------- |
| **RSA**                  | Asymmetric (Public Key) | Key exchange, signing | Based on prime factorization        |
| **AES**                  | Symmetric               | Encryption            | Fast, block cipher (128-bit blocks) |
| **DES/3DES**             | Legacy Symmetric        | Deprecated            | 56-bit key – weak                   |
| **HMAC**                 | Authentication          | Message integrity     | Uses hash + key                     |
| **SHA-1/SHA-2/SHA-3**    | Hash                    | One-way digest        | Basis for many proofs               |
| **Elliptic Curve (ECC)** | Asymmetric              | Compact modern crypto | Hard discrete log problem           |
| **OTP/Stream ciphers**   | Symmetric               | XOR-based             | Secure only if key unique & random  |

***

### II. 🧮 **RSA Deep Dive (For CTF Labs)**

#### 1️⃣ Fundamentals

* Keys:\
  ( n = p \imes q ) (large primes)\
  ( \phi = (p-1)(q-1) )\
  Public key = (e, n), Private = (d, n)\
  ( d ≡ e^{-1} \pmod{\phi(n)} )
* Encryption: ( c = m^e \bmod n )\
  Decryption: ( m = c^d \bmod n )

***

#### 2️⃣ Common Weakness Scenarios

| Scenario                 | Description                                     | Indicator                  |
| ------------------------ | ----------------------------------------------- | -------------------------- |
| **Small e (=3)**         | Exponent too low → plaintext recovery if m³ < n | e = 3                      |
| **Shared n**             | Same modulus, diff e                            | Two keys share n           |
| **Common factor**        | GCD of n₁,n₂ ≠ 1                                | Factor via GCD             |
| **Small primes**         | p,q too close                                   | Fermat factorization works |
| **CRT leakage**          | Fault in Chinese Remainder recombination        | Corrupt ciphertexts        |
| **Padding oracle**       | Distinguishable padding errors                  | Different error responses  |
| **Partial key exposure** | Known MSBs/LSBs of p,q                          | Lattice attacks in labs    |

***

#### 3️⃣ **CTF Workflow**

1. `rsa-toolkit` or `RsaCtfTool` → auto-detect weakness.
2. If shared n → `gcd(n1, n2)` > 1 ⇒ common prime.
3. If small e=3 → cube-root the ciphertext.
4. If known p,q → recompute d = pow(e, -1, (p-1)\*(q-1)) then decrypt.

🧠 _Every CTF RSA flaw = human misconfiguration, not broken math._

***

### III. 🔒 **AES, DES & Block-Cipher Labs**

#### 1️⃣ **AES Overview**

* Block size 128 bits; key sizes 128/192/256.
* Modes: ECB, CBC, CFB, OFB, CTR, GCM.

| Mode        | Property             | Weakness                                                   |
| ----------- | -------------------- | ---------------------------------------------------------- |
| **ECB**     | Deterministic blocks | Identical plaintext → identical ciphertext (“Tux pattern”) |
| **CBC**     | XOR with IV          | IV reuse leaks patterns                                    |
| **CTR/GCM** | Stream-like          | Nonce reuse catastrophic                                   |
| **CFB/OFB** | Feedback modes       | Rarely used now                                            |

🧠 _In CTFs, ECB and CTR Nonce Reuse appear constantly._

***

#### 2️⃣ **DES & 3DES**

* DES → 56-bit key → brute-forceable.
* 3DES = EDE (Encrypt-Decrypt-Encrypt) with 3 keys.\
  CTFs sometimes give legacy ciphertext → use `openssl des3 -d` with guessed passwords.

***

### IV. ⚔️ **Symmetric Cipher Flaws in CTFs**

| Flaw                      | Explanation                        | Consequence                        |
| ------------------------- | ---------------------------------- | ---------------------------------- |
| **Nonce Reuse (CTR/GCM)** | Same key + nonce → keystream reuse | XOR of ciphertexts leaks plaintext |
| **IV Reuse (CBC)**        | Deterministic first block          | Pattern leakage                    |
| **Key Reuse**             | Multiple files, same key           | Differential attacks               |
| **ECB Mode**              | No chaining                        | Visual pattern leaks               |
| **Padding Oracle**        | Server reveals pad correctness     | Gradual byte recovery              |

🧠 Typical challenge: _“given oracle that says valid/invalid padding” → reconstruct plaintext._

***

### V. 🧩 **HMAC & Hash Construction**

#### 1️⃣ **HMAC Definition**

\
\text{HMAC}(K, m) = H\big((K ⊕ opad),‖,H((K ⊕ ipad),‖,m)\big)<br>

* Combines a key K and hash H for integrity.

#### 2️⃣ **Length Extension Attack**

If hash = plain `SHA256(secret ‖ message)` (not HMAC!) ⇒\
attacker can append data using only digest + length.

🧠 Detection: use **“keyed MAC”** implemented incorrectly (no inner/outer pad).

CTF task → find original length → extend → recompute digest with padding.

***

### VI. 🧠 **Hash Function Challenges**

| Type                | Example                       | CTF Goal                     |
| ------------------- | ----------------------------- | ---------------------------- |
| **Collision**       | MD5(a)=MD5(b)                 | Provide two inputs same hash |
| **Preimage**        | Given hash → find input       | Brute-force                  |
| **Second Preimage** | Same hash different msg       | High complexity              |
| **Truncated Hash**  | Only partial digest used      | Easier brute-force           |
| **Rainbow Tables**  | Pre-computed hash → plaintext | Reverse lookup               |

🧠 Use `hashid` to recognize, `hashcat`/`john` for offline cracking (for labs only).

***

### VII. 🧠 **Nonce & IV Reuse (Practical CTF Lab)**

| Context        | Symptom                         | Exploit Concept          |
| -------------- | ------------------------------- | ------------------------ |
| AES-CTR        | Repeated nonce → same keystream | XOR ciphertexts          |
| AES-GCM        | Same IV + key → tag forgery     | GCM auth breaks          |
| Stream ciphers | Same IV reuse                   | XOR leak identical bytes |

🧩 In labs, recover plaintext₂ = C₁ ⊕ C₂ ⊕ P₁.

***

### VIII. 🧮 **Common Crypto Attack Categories**

| Category                 | Target               | Idea                        |
| ------------------------ | -------------------- | --------------------------- |
| **Brute-Force**          | Weak key space       | Try all keys                |
| **Mathematical**         | Algorithmic weakness | Factorization / Lattice     |
| **Side-Channel**         | Timing / power       | Differential analysis       |
| **Padding Oracle**       | CBC mode             | Byte-wise decryption        |
| **Chosen Ciphertext**    | Adaptive queries     | RSA/PKCS#1 v1.5             |
| **Replay / Nonce reuse** | Stream ciphers       | XOR trick                   |
| **Fault Injection**      | Hardware glitch      | Differential fault analysis |

***

### IX. 🧠 **Recognizing Crypto in CTF Text**

| Pattern                             | Probably Means |
| ----------------------------------- | -------------- |
| `-----BEGIN RSA PUBLIC KEY-----`    | PEM RSA        |
| Base64 blob length ≈ 172 chars      | RSA-1024       |
| Hex + “modulus/exponent”            | RSA parameters |
| 16-byte repeating pattern           | AES block      |
| 8-byte repeating                    | DES            |
| JSON with `iv` + `ciphertext`       | AES-CBC        |
| 12-byte `nonce`, 16-byte `tag`      | AES-GCM        |
| “sha256( secret + msg )”            | vulnerable MAC |
| Ciphertext same length as plaintext | Stream mode    |

***

### X. 🧰 **CTF Toolkit Commands**

| Purpose           | Command                                                  |
| ----------------- | -------------------------------------------------------- |
| RSA analysis      | `RsaCtfTool --publickey pub.pem --attack all`            |
| AES decrypt       | `openssl enc -aes-128-cbc -d -in file.enc -K key -iv iv` |
| Base64 decode     | `base64 -d file`                                         |
| Hash identify     | `hashid hash.txt`                                        |
| Hash crack (lab)  | `hashcat -m 0 hash wordlist.txt`                         |
| Convert PEM → DER | `openssl rsa -in key.pem -outform DER`                   |
| Verify HMAC       | `openssl dgst -sha256 -hmac key file`                    |

🧠 **CyberChef** also has ready blocks for AES, HMAC, XOR, RSA modulus math.

***

### XI. 🧱 **Crypto Puzzle Recognition Table**

| Clue                                    | Cipher Type          |
| --------------------------------------- | -------------------- |
| Hex numbers + mod/exponent              | RSA                  |
| `iv`, `ciphertext`, `tag`               | AES-GCM              |
| Repeating ciphertext blocks             | ECB                  |
| Message digest mismatch                 | HMAC / padding issue |
| Key size = 56 bits                      | DES                  |
| Ciphertext XOR trick                    | Stream / CTR         |
| Base64 strings starting with “U2FsdGVk” | OpenSSL salted AES   |

***

### XII. 🧩 **Educational Lab Scenarios**

1️⃣ _RSA Small e_ → use `root(plaintext³ mod n)`.\
2️⃣ _Shared modulus_ → compute gcd(n₁,n₂).\
3️⃣ _CBC Padding Oracle_ → oracle returns valid/invalid padding.\
4️⃣ _AES CTR Nonce Reuse_ → XOR ciphertexts.\
5️⃣ _Improper HMAC_ → length-extension simulation.\
6️⃣ _Short key AES_ → 8-char key → brute within wordlist.

Each is a contained **lab scenario**, never a real-world exploit.

***

### XIII. 🧠 **Hash & MAC Cheatsheet**

| Algorithm                | Output (bits) | Note                       |
| ------------------------ | ------------- | -------------------------- |
| MD5                      | 128           | Collision-broken           |
| SHA1                     | 160           | Deprecated                 |
| SHA256                   | 256           | Common secure hash         |
| SHA512                   | 512           | Larger blocks              |
| HMAC-SHA256              | 256           | Integrity + auth           |
| PBKDF2 / bcrypt / scrypt | variable      | Key stretching (passwords) |

***

### XIV. 🧱 **CTF Workflow (Modern Crypto)**

```
1️⃣ Identify algorithm from file/metadata
2️⃣ Detect key reuse / nonce reuse / padding
3️⃣ For RSA → test p,q,e,n relationships
4️⃣ For AES → detect mode, block size
5️⃣ For HMAC → check if naive SHA(secret + msg)
6️⃣ Use openssl / RsaCtfTool / CyberChef for simulation
7️⃣ Derive plaintext / key if lab allows
8️⃣ Validate → flag{…}
```

***

### XV. ⚡ **Pro Tips for CTF Crypto**

* Save intermediate states (n, e, d, p, q).
* Automate brute with `pwntools` + `Crypto.Util`.
* Always confirm encoding layers (base64 → hex → bytes).
* If output unreadable → try UTF-8, big-endian, little-endian conversions.
* Document every step — crypto challenges chain multiple small hints.

***
