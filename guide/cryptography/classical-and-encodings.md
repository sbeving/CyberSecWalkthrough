---
icon: trumpet
---

# Classical & Encodings

> ⚡ “Before you break AES, learn to break Caesar.”\
> CTF cryptography begins with the classics — text ciphers, base encodings, binary tricks, and pattern recognition.

***

### I. 🧩 Recognition & Workflow

| Step                       | What to Check                                                             |
| -------------------------- | ------------------------------------------------------------------------- |
| **1️⃣ File or Text Type**  | Does it look like base64, hex, binary, or gibberish? Check character set. |
| **2️⃣ Entropy**            | Too uniform = encoded/compressed. Run `ent` or CyberChef “Entropy”.       |
| **3️⃣ Frequency Analysis** | Common in substitution ciphers (Caesar, Vigenère). Use “E”/“T” patterns.  |
| **4️⃣ Automation**         | `cryptii.com`, `CyberChef`, `quipqiup`, `dcode.fr`, `sherlocked` scripts. |

🧠 Keep a **decode pipeline** ready:\
`file → strings → base decodes → hex → Caesar → Vigenère → XOR → frequency analysis`

***

### II. 🧱 Classical Ciphers

#### 1️⃣ **Caesar Cipher**

* Shifts each letter _n_ positions in the alphabet.\
  Formula: `E(x) = (x + n) mod 26`\
  Example: `ATTACK → DWWDFN` (shift +3)

**Decode Command:**

```bash
echo "DWWDFN" | tr 'D-ZA-C' 'A-Z'
```

🧠 Try all 26 shifts – CTFs often hide flag at shift 13 (ROT13).

***

#### 2️⃣ **ROT13 / ROT-n**

* Fixed shift by 13 (its own inverse).

```bash
echo "uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

***

#### 3️⃣ **Vigenère Cipher**

* Polyalphabetic substitution using a key word.\
  Formula: `C = (P + K) mod 26`

**Example**

```
Plain:  ATTACKATDAWN
Key:    LEMONLEMONLE
Cipher: LXFOPVEFRNHR
```

**Decryption Tip:** Find key length via **Kasiski** or **Index of Coincidence**.\
Online: `dcode.fr/vigenere-cipher` or `quipqiup.com`.

***

#### 4️⃣ **Affine Cipher**

`E(x) = (ax + b) mod 26` `D(x) = a⁻¹ (x − b) mod 26`\
→ where a and 26 are coprime.\
Try common a = 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25.

***

#### 5️⃣ **Atbash**

* Mirror alphabet (A ↔ Z, B ↔ Y).

```bash
tr 'A-Za-z' 'Z-Az-a'
```

***

#### 6️⃣ **Rail Fence / Transposition**

* Zig-zag pattern writing; read by rows.\
  Example (2 rails):

```
Hloolelwrd
```

→ “Hello world”

Decode with `dcode.fr/rail-fence-cipher`.

***

#### 7️⃣ **Playfair Cipher**

* Uses 5×5 grid of key letters.\
  Common in CTFs for manual decryption.\
  Look for “double letters” split with X (e.g., HE → HE → HXE).

***

### III. 🧠 Encodings & Representations

#### 1️⃣ **Base Encodings**

| Encoding         | Alphabet          | Command          |
| ---------------- | ----------------- | ---------------- |
| Base16 (hex)     | 0–9 A–F           | `xxd -r -p`      |
| Base32           | A–Z 2–7           | `base32 -d`      |
| Base58           | BTC/IPFS alphabet | CyberChef Base58 |
| Base64           | A–Z a–z 0–9 +/    | `base64 -d`      |
| Base85 / Ascii85 | Adobe / b85       | `base85 -d`      |
| Base91 / Base92  | CTF obfuscation   | CyberChef Base91 |

🧠 If text ends with `=` or `==` → Base64.\
If mostly A–F and even length → Hex.

***

#### 2️⃣ **Hex & Twin Hex**

* Each pair represents a byte.\
  `48 65 6C 6C 6F → Hello`

**Twin Hex CTFs:** Two hex streams merged byte-by-byte.\
Split pairs or alternate bytes:

```bash
cut -c1-2,5-6,... file.hex
```

Then convert each line back to ASCII → hidden flag.

***

#### 3️⃣ **Binary / Octal / Decimal**

| System          | Example                                      | Command                  |
| --------------- | -------------------------------------------- | ------------------------ |
| Binary → Text   | 01001000 01100101 01101100 01101100 01101111 | \`echo "01001000..."     |
| Octal → Text    | 110 145 154 154 157                          | \`echo "110145..."       |
| Decimal → ASCII | 72 101 108 108 111                           | `awk '{printf "%c",$1}'` |

***

#### 4️⃣ **Garbled Binary / Gray Code**

If binary flips by 1 bit each step, it may be Gray Code.\
Convert Gray → Binary → ASCII using CyberChef “Gray to Binary”.

***

#### 5️⃣ **Unicode & URL Encodings**

| Type            | Example              | Decode                                                   |
| --------------- | -------------------- | -------------------------------------------------------- |
| URL             | `%48%65%6C%6C%6F`    | `urldecode`                                              |
| Unicode Escapes | `\u0048\u0065\u006C` | Python: `print("...".encode().decode('unicode_escape'))` |
| HTML Entities   | `&#72;&#101;`        | CyberChef → “From HTML Entities”                         |

***

### IV. 🧠 XOR & Simple Bitwise Encodings

#### 1️⃣ **Single-Byte XOR**

* Each byte XORed with same key.
* Recognizable by pattern repetition.

```bash
for k in {0..255}; do 
  xxd -p cipher.bin | xxd -r -p | tr '[:lower:]' '[:upper:]' | openssl enc -xor -K $(printf "%02x" $k)
done
```

**Fast method:** Use `xorbrute.py` or CyberChef “XOR Brute Force”.

***

#### 2️⃣ **Multi-Byte XOR**

* Repeating key pattern.
* Recover key length via Kasiski or index analysis (similar to Vigenère).

***

### V. 🧰 Combined Encodings in CTFs

Typical chain:

```
Base64 → Hex → ROT13 → Caesar → Vigenère → Binary
```

Automate with CyberChef “Magic” or script:

```bash
python3 decode_chain.py cipher.txt
```

🧠 When output still looks encoded, pipe it back into your decode stack.

***

### VI. 🧩 Hidden and Tricky Encodings

| Technique             | Hint                | Tool                    |
| --------------------- | ------------------- | ----------------------- |
| **Morse Code**        | .-/-- patterns      | `dcode.fr/morse-code`   |
| **Baconian Cipher**   | A/B binary encoding | CyberChef Baconian      |
| **Tap / Knock Codes** | Paired numbers      | Polybius Square decoder |
| **Polybius Square**   | Digits pairs        | 5×5 matrix decryption   |
| **Base58Check**       | BTC-like strings    | CyberChef Base58        |
| **Emoji Ciphers**     | UTF-8 mapping       | `unicodedata` decode    |
| **Zero-Width Chars**  | Blank text          | `stegcloak reveal`      |

***

### VII. 🧱 Useful Online & CLI Resources

| Category           | Resource                                                            |
| ------------------ | ------------------------------------------------------------------- |
| All-purpose        | [CyberChef](https://gchq.github.io/CyberChef)                       |
| Classical          | [quipqiup.com](https://quipqiup.com/)                               |
| Frequency Analysis | [practicalcryptography.com](https://www.practicalcryptography.com/) |
| Automation         | `ctf-tool`, `stegsolve`, `hashid`, `python-cipher`                  |
| Encodings          | `basecrack`, `uncompyle`, `dehexify`                                |

***

### VIII. 🧠 Quick Reference Table

| Cipher / Encoding | Identifier                | Decode Hint                   |
| ----------------- | ------------------------- | ----------------------------- |
| ROT13 / Caesar    | Letters shifted uniformly | Try ROT13 or Brute All Shifts |
| Vigenère          | Repeating pattern         | Use key-length analysis       |
| Affine            | Linear mod pattern        | Try known a,b pairs           |
| Atbash            | Mirror alphabet           | Reverse A↔Z                   |
| Base64            | A–Z,a–z,0–9,+,/ + “=”     | `base64 -d`                   |
| Base32            | = padding, 2–7 digits     | `base32 -d`                   |
| Hex               | 0–9 A–F even len          | `xxd -r -p`                   |
| Binary            | 0/1 only                  | `perl -lpe '$_=pack"B*",$_'`  |
| Morse             | · –                       | Translate to text             |
| Whitespace        | Empty lines/tabs          | `snow -d`                     |
| Gray Code         | 1-bit flips               | Convert to binary             |
| Polybius          | Digits 1-5                | Grid decode                   |

***

### IX. 🧠 CTF Workflow Template

```
1️⃣ Identify cipher type → char set, pattern, frequency
2️⃣ Decode bases and encodings → hex/b64/binary
3️⃣ Test Caesar / ROT / Atbash / Vigenère
4️⃣ Check for multi-layer → repeat pipeline
5️⃣ Automate with CyberChef or Python
6️⃣ Validate output pattern → flag{...}
```

***

### X. 🧩 Pro Tips

* Always **copy the raw data** — CTF text boxes can hide whitespace.
* **Don’t assume one layer** — combine decoders recursively.
* **Entropy ≈ 0.5?** Likely substitution. **Entropy > 0.9?** Likely compression.
* **Check for reversed strings** (`[::-1]`).
* **Always verify encodings visually** — `hexdump -C file`.

***
