# Intro Crypto 2

## CTF Write-up: Intro Crypto 2 - Hash Length Extension



**hallenge:** Intro Crypto 2

**Description:** The challenge implements an insecure MAC scheme using `sha1(KEY + data)`. The goal is to bypass the MAC check and gain admin privileges.

**Attachments:** `intro-crypto-2.zip` (containing `source.py`)



#### Analysis

The provided `source.py` script implements a service that allows users to register, view "animal videos" (using their token), and view a flag if they are an admin.

1. **Token Generation (`generate_token`):**
   * User data (like `name`, `animal`, `admin=false`) is formatted into a pipe-separated string (e.g., `name=solver|animal=pwn|admin=false`).
   * A Message Authentication Code (MAC) is calculated using `get_mac`.
   * The token string and the MAC are combined: `f"{data_string}|mac={mac_string}"`.
   * The final result is Base64 encoded.
2. **MAC Generation (`get_mac`):**
   * The MAC is computed as `sha1(KEY.encode("latin1") + data).hexdigest()`.
   * `KEY = token_hex(16)`: This generates 16 random _bytes_ and encodes them as a **32-character hexadecimal string**.
   * `KEY.encode("latin1")`: Encoding this 32-character hex string (which only contains ASCII `0-9a-f`) using `latin1` results in a **32-byte** byte string.
   * This means the MAC calculation uses the structure `SHA1(secret_32_bytes || message_bytes)`.
3. **Token Parsing (`parse_token`):**
   * The Base64 token is decoded.
   * It's split into the data part and the MAC part.
   * The server recalculates the MAC on the received data part using the _same secret KEY_ and compares it to the received MAC.
   * If the MACs match, the data part is parsed into a dictionary.
4. **Flag Access (`handle_show_flag`):**
   * Requires a valid token (correct MAC).
   * Checks if `user_data["admin"] == "true"` in the parsed dictionary.

#### Vulnerability

The critical vulnerability lies in the MAC construction: `SHA1(KEY || data)`. Hash functions like SHA-1, based on the Merkle–Damgård construction, are susceptible to **Hash Length Extension Attacks** when used in this naive `HASH(secret || message)` pattern for MACs.

An attacker who knows:

1. The original message (`data`)
2. A valid MAC for that message (`SHA1(KEY || data)`)
3. The _length_ of the secret key (`KEY`)

Can compute a valid MAC for a new message formed by `data || padding || arbitrary_append_data`, **without knowing the actual `KEY`**. The `padding` is the specific padding SHA-1 would internally add to make `KEY || data` fit its block structure.

In this challenge:

* We can get `data` and its MAC by registering.
* We deduced the key length is **32 bytes**.
* We want to append `|admin=true`.

#### Attack Plan

1. Connect to the service.
2. Register a user to obtain a valid Base64 encoded token.
3. Decode the token and extract the original `data` string and the original `MAC` hex string.
4. Use a hash length extension tool (like `hashpumpy`) with the following inputs:
   * Original MAC
   * Original data
   * Key length: **32 bytes**
   * Data to append: `|admin=true`
5. The tool will calculate the necessary SHA-1 `padding` and the `new_MAC` for the extended message (`data || padding || "|admin=true"`). It will typically return the full extended data including padding (`forged_data_bytes`).
6. Construct the final payload: `forged_data_bytes + b"|mac=" + new_MAC.encode('latin1')`.
7. Base64 encode this final payload to create the forged token.
8. Submit the forged token to option 3 ("Show flag"). The server's `parse_token` function will validate the `new_MAC` against the `forged_data_bytes` (which includes the padding) and succeed. The subsequent parsing will find `"admin": "true"`, granting access to the flag.

#### Implementation (Solver Script)

The provided Python script executes this plan perfectly using `pwntools` for interaction and `hashpumpy` for the core attack:

```python
#!/usr/bin/env python3
from pwn import *
import base64
import hashpumpy # <<< Requires installation
import re # Added for flag extraction in final output

# --- Connection Details ---
HOST = '67ba82595f38b7d1b8cae9d9-1024-intro-crypto-2.challenge.cscg.live'
PORT = 1337
USE_SSL = True

# --- Attack Parameters ---
KEY_LENGTH = 32 # token_hex(16) -> 32 hex chars -> latin1 encode -> 32 bytes
APPEND_DATA = b'|admin=true'

# --- Script Logic ---
# ... (Connection, Registration, Token Parsing - as provided) ...

log.info(f"Received token (b64): {token_b64}")
# ... (Decoding and Splitting token - as provided) ...
log.info(f"Original data: {original_data_str}")
log.info(f"Original MAC: {original_mac_hex}")

# 3. Perform Hash Length Extension Attack
log.info(f"Performing SHA1 length extension (key_length={KEY_LENGTH}, append='{APPEND_DATA.decode()}')")
try:
    # Use hashpumpy for the heavy lifting
    new_mac_hex, forged_data_bytes = hashpumpy.hashpump(
        original_mac_hex,    # Original known MAC
        original_data_str,   # Original known message data
        APPEND_DATA,         # Data we want to append
        KEY_LENGTH           # Crucial: Length of the secret key
    )
except Exception as e:
    # ... (Error handling) ...

log.success(f"Calculated new MAC: {new_mac_hex}")
# forged_data_bytes now holds: original_data + padding + APPEND_DATA

# 4. Construct the final forged token
final_payload_bytes = forged_data_bytes + b'|mac=' + new_mac_hex.encode('latin1')
forged_token_b64 = base64.b64encode(final_payload_bytes).decode('ascii')
log.success(f"Forged token (b64): {forged_token_b64}")

# 5. Submit the forged token to get the flag
# ... (Submit token, receive response - as provided) ...

log.success("Received response:")
print("-" * 20)
print(final_response)
print("-" * 20)

# Extract flag using regex
flag = re.search(r"CSCG\{[^\}]+\}", final_response)
if flag:
    log.success(f"Flag found: {flag.group(0)}")
else:
    log.warning("Flag pattern not found in the response.")

conn.close()

```

#### Execution and Result

Running the script produced the following output:

```
[*] Connecting to 67ba82595f38b7d1b8cae9d9-1024-intro-crypto-2.challenge.cscg.live:1337 (SSL)
[+] Opening connection to 67ba82595f38b7d1b8cae9d9-1024-intro-crypto-2.challenge.cscg.live on port 1337: Done
[*] Registering new user...
[*] Receiving token...
[+] Received token (b64): bmFtZT1zb2x2ZXJ8YW5pbWFsPXB3bnxhZG1pbj1mYWxzZXxtYWM9MDcwODUzOGUzMTUwMTJlMTA1YTU4NzA1M2NmN2E2YjhiNTUwMzUxMw==
[*] Original data: name=solver|animal=pwn|admin=false
[*] Original MAC: 0708538e315012e105a587053cf7a6b8b5503513
[*] Performing SHA1 length extension (key_length=32, append='|admin=true')
[+] Calculated new MAC: 9648032b9da9af5d54096be7ccfaff45e5a9cbc0
[+] Forged token (b64): bmFtZT1zb2x2ZXJ8YW5pbWFsPXB3bnxhZG1pbj1mYWxzZYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIQfGFkbWluPXRydWV8bWFjPTk2NDgwMzJiOWRhOWFmNWQ1NDA5NmJlN2NjZmFmZjQ1ZTVhOWNiYzA=
[*] Submitting forged token to option 3...
[*] Waiting for server response...
[+] Receiving all data: Done (174B)
[*] Closed connection to 67ba82595f38b7d1b8cae9d9-1024-intro-crypto-2.challenge.cscg.live port 1337
[+] Received response:
--------------------
 The flag is CSCG{sh0uld_have_us3d_HMAC_or_KMAC_instead!}

        1. Register
        # ... (rest of menu) ...
Enter your choice:
--------------------
[+] Flag found: CSCG{sh0uld_have_us3d_HMAC_or_KMAC_instead!}
```

**Flag:** `CSCG{sh0uld_have_us3d_HMAC_or_KMAC_instead!}`

#### Conclusion

This challenge demonstrated the insecurity of using a simple `HASH(key || message)` construction as a MAC. By correctly identifying the key length (32 bytes) and utilizing a hash length extension attack tool (`hashpumpy`), we were able to append `|admin=true` to the user data and forge a valid MAC for the extended message, gaining access to the flag. The proper way to implement a hash-based MAC is to use standardized constructions like HMAC (Hash-based Message Authentication Code) or KMAC.
