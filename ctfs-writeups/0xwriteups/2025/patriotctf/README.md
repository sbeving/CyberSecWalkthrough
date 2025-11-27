---
icon: user-police-tie
---

# PatriotCTF

## PatriotCTF 2024 - Complete Writeup

**Rank:** 157th (Solo) | **Points:** 3544

***

### 🌐 Web Exploitation

#### 1. SecureAuth™

**Flag:** `FLAG{py7h0n_typ3_c03rc10n_byp4ss}` **Vulnerability:** Python Type Coercion / Logic Error

* **Recon:** The login page displayed a standard HTML form, but inspecting the source or network traffic revealed a hidden endpoint: `POST /api/authenticate` accepting JSON.
*   **Vulnerability:** The backend likely contained a logic error similar to:

    ```python
    if data.get("remember") == True:
        login_user()
    ```

    In Python, sending a boolean `true` in JSON is parsed as a boolean `True`, which passes this check, bypassing the password verification entirely.
*   **Exploit:** Intercepted the login request and converted it to JSON:

    ```json
    {
      "username": "admin",
      "password": null,
      "remember": true
    }
    ```
* **Result:** The server accepted the bypass, logged us in as admin, and returned the flag.

#### 2. Feedback Fallout

**Flag:** `PCTF{Cant_Handle_the_Feedb4ck}` **Vulnerability:** Log4Shell (CVE-2021-44228) - Information Disclosure

* **Analysis:** The application was a feedback portal running on an outdated Java stack using Log4j. User input into the "feedback" field was being logged.
* **Exploit:** While full RCE was difficult due to network restrictions, the application allowed environment variable expansion. We injected a payload to read the server's environment variables.
* **Payload:** `${env:SECRET_FLAG}`
* **Result:** The server resolved the variable and printed the flag into the HTTP response logs: `User feedback: PCTF{Cant_Handle_the_Feedb4ck}`.

#### 3. Trust Fall

**Flag:** `PCTF{authz_misconfig_owns_u}` **Vulnerability:** IDOR + Improper Authorization

* **Analysis:** Found a hardcoded Bearer token `trustfall-readonly` inside `/assets/app.js`.
* **Exploit:** Used this token to query the `/api/users/` endpoint. While meant to be read-only for standard users, the API lacked authorization checks on specific User IDs.
* **Attack:** Queried `/api/users/0` (the root/admin ID).
* **Result:** The API returned the admin user object, which contained the flag in a field that was null for other users.

#### 4. Connection Tester

**Flag:** `PCTF{C0nn3cti0n_S3cured}` **Vulnerability:** Command Injection

* **Analysis:** A "Connectivity Tool" allowed users to ping an IP address.
* **Exploit:** The input was passed unsanitized to a system shell. We used a semicolon to chain commands.
* **Payload:** `127.0.0.1; cat /app/flag.txt`
* **Result:** The application executed the ping, followed by the cat command, displaying the flag.

#### 5. Trust Vault

**Flag:** `PCTF{SQL1_C4n_b3_U53D_3Ff1C13N7lY}` **Vulnerability:** SQL Injection → SSTI (Server-Side Template Injection)

* **Analysis:** A legacy search endpoint was vulnerable to SQL Injection (`UNION SELECT`). The data returned by the SQL query was then rendered by a Jinja2 template engine without sanitization.
* **Exploit:** We injected a Jinja2 payload into the SQL results.
*   **Payload:**

    ```sql
    ' UNION SELECT '{{ lipsum.__globals__.os.popen("cat /flag-*.txt").read() }}'--
    ```
* **Result:** The SQL query injected the Python code into the template, the server executed it, and the flag was rendered on the page.

***

### 🧩 Misc

#### 1. Reverse Metadata Part 1

**Flag:** `MASONCC{images_give_us_bash?}` **Vulnerability:** Exiftool RCE (CVE-2021-22204)

* **Analysis:** The server accepted image uploads and processed their metadata via a cron job running as **root**. The processing library was an outdated version of Exiftool vulnerable to command injection via DjVu metadata.
* **Exploit:** Constructed a malicious image file using the CVE-2021-22204 exploit chain.
*   **Payload Construction:**

    ```python
    payload = b'(metadata (copyright "\\b" . qx[cat /flags/root.txt > /var/www/html/uploads/flag.txt] . "\\b" `))'
    # Wrapped this payload into a DjVu chunk inside a JPEG
    ```
* **Execution:** Uploaded the file. Waited for the cron job to trigger Exiftool. The exploit executed `cat` on the flag file and moved it to the public uploads directory.
* **Result:** Retrieved the flag from the uploads folder.

#### 2. Mysterious XOR

**Flag:** `pctf{0x67}` **Method:** Traffic Analysis & Deobfuscation

* **Analysis:** Provided a PCAP file with unreadable TCP payloads. The hint was "One byte is all you ever need".
* **Solution:** Observed repeating patterns in the hex dump. XORing the payload with `0x67` (Decimal 103, ASCII 'g') revealed a valid ELF binary structure.
* **Result:** The flag was the XOR key itself: `pctf{0x67}`.

#### 3. Rotten Apple (Interview Task)

**Flag:** `RRCTF{Wh4t_I_s3e_is_unre4l_I've_wr1tt3n_my_0wn_p4rt}` **Method:** Multi-stage Steganography

* **Steps:**
  1. **EXIF:** Analyzed `Rotten_Apple.jpg` metadata to find a Base64 string `UFdEOiBXaGF0SVNlZUlzVW5yZWFsX0FwcGxlIA==`. Decoded to `WhatISeeIsUnreal_Apple`.
  2. **Steghide:** Used that string as a password for `steghide extract`, revealing a ZIP file.
  3. **Crypto:** Inside the zip was a ROT47 encoded text file describing a password logic.
  4. **Puzzle:** Solved the riddle to generate the password `R0T_T3N_P4SSw0Rd`.
  5. **Extraction:** Used this password to unzip the final archive containing the flag.

***

### 🔐 Cryptography

#### 1. Matrix Reconstruction

**Flag:** `pctf{mAtr1x_r3construct?on_!s_fu4n}` **Method:** Linear Algebra over GF(2)

* **Problem:** We were given 40 consecutive states of a custom PRNG. The PRNG used a 32x32 binary matrix multiplication and XOR operation.
* **Solution:** Treated the bits as a system of linear equations over Galois Field 2. With 40 states, we had enough data points to solve for the unknown Matrix A and Vector B using Gaussian elimination. Once the matrix was recovered, we generated the keystream to decrypt the flag.

#### 2. Cipher from Hell

**Flag:** `pctf{a_l3ss_cr4zy_tr1tw1s3_op3r4ti0n_f37d4b}` **Method:** Reverse Engineering Custom Algo

* **Analysis:** The challenge used a custom "Tritwise" (Base-3) encryption.
* **Solution:** Analyzed the encryption routine to understand the bit-shuffling logic. Wrote a reversal script that reconstructed the original trits by reversing the extraction logic: `[high_trits] + [low_trits_reversed]`.

#### 3. Password Palooza

**Flag:** `pctf{mr.krabbs57}` **Method:** Hash Cracking

* **Analysis:** Given an MD5 hash and a hint that the password was based on a known leak plus 2 digits.
* **Solution:** Generated a wordlist using `rockyou.txt` + `00-99` and cracked the hash.

***

### 🛠️ Reverse Engineering

#### 1. Entropy Discord

**Flag:** `PCTF{iTz_mY_puT3R--My_3nT40PY}` **Method:** Cryptanalysis / LCG Reversal

* **Analysis:** The binary read 16 bytes from `/dev/urandom`, hashed them, and used the hash to seed an LCG (Linear Congruential Generator) to decrypt the flag.
* **Solution:** Instead of reversing the complex hash function, we looked at the LCG decryption loop. Knowing the flag starts with `PCTF{`, we calculated the required LCG state (seed) that would produce those characters. We then used that recovered seed to generate the rest of the keystream and decrypt the full flag.

#### 2. ReadMyNote

**Flag:** `pctf{I_L0V3_W1ND0W$_83b6d8e7}` **Method:** Static Analysis

* **Analysis:** A Windows PE binary obfuscated with Qengine.
* **Solution:** Found encoded data arrays in the global variables. Analyzed the assembly to identify a simple XOR loop. Bruteforced the single-byte XOR key (`0x05`) to reveal the flag in the binary strings.

***

### 🔎 Forensics

#### 1. Burger King

**Flag:** `CACI{Y0U_F0UND_M3!}` **Method:** Known Plaintext Attack

* **Analysis:** An encrypted ZIP file and a partial SVG file were provided. The partial SVG matched a file inside the encrypted ZIP.
* **Solution:** Performed a Biham-Kocher Known Plaintext Attack using the `bkcrack` tool. Recovered the internal ZIP keys, decrypted the archive, and found the flag inside the full SVG file.

#### 2. We Go Gym

**Method:** Traffic Analysis & Decryption

* **Analysis:** A PCAP showed HTTP traffic downloading `noiseXX.txt` files (base64 data) and other data chunks.
* **Solution:** Identified a custom encryption scheme where the "noise" files acted as AES keys/IVs for specific data chunks. The chunk sequence was reconstructed based on the HTTP request order, decrypted using the corresponding noise keys, and reassembled to form the flag.
