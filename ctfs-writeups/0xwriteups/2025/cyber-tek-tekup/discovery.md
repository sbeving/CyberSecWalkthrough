# Discovery

<figure><img src="../../../../.gitbook/assets/image (116).png" alt=""><figcaption></figcaption></figure>

Given a message.txt

```
Message: 3343435f31735f4272306b336e
Signature (r,s): 81656283118670857341884602426840867029778987004268103130686475270399518147476,51070035169163094288170086161579499981349116068533637659570945874191030730099
```

A public.pem

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKXNLO9XJZ3gSjZSBRCsIF6N14q7Z
kA6Z1VNKlaSBNgFRfk9z0/+AQfgRBqOUP1KSzPhAQOPR5+SXRIJeIjEKJg==
-----END PUBLIC KEY-----
```

and a V\_script.py

```python
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Math._IntegerGMP import IntegerGMP

def generate_key():
    return ECC.generate(curve='P-256')

def flawed_sign(private_key, message):
    # Convert all values to IntegerGMP for consistent arithmetic
    h = SHA256.new(message).digest()
    h_int = IntegerGMP(int.from_bytes(h, 'big'))
    n = private_key._curve.order
    
    # Using predictable nonce (as IntegerGMP)
    k = IntegerGMP(0xdeadbeef)
    
    # ECDSA signing
    curve = private_key._curve
    K = int(k) * curve.G  # Point multiplication requires int
    r = IntegerGMP(int(K.x)) % n
    
    # All operations with IntegerGMP
    k_inv = k.inverse(n)
    dr = private_key.d * r
    h_plus_dr = h_int + dr
    s = (k_inv * h_plus_dr) % n
    
    return (int(r), int(s))  # Convert back to Python ints for output

if __name__ == "__main__":
    key = generate_key()
    
    # Save public key
    with open("public.pem", "wt") as f:
        f.write(key.public_key().export_key(format='PEM'))
    
    message = b"XXXXXXXXXXXXXXXXXX"
    signature = flawed_sign(key, message)
    
    with open("message.txt", "wt") as f:
        f.write(f"Message: {message.hex()}\n")
        f.write(f"Signature (r,s): {signature[0]},{signature[1]}")

```

Lets get the flag&#x20;

```python
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Math.Numbers import Integer
import binascii
import re

# Constants
KNOWN_K = 0xdeadbeef

# Step 1: Load public key
with open("public.pem", "rt") as f:
    pub_key = ECC.import_key(f.read())

curve = pub_key._curve
G = curve.G
n = int(curve.order)

# Step 2: Read message and signature
with open("message.txt", "r") as f:
    content = f.read()

# Parse message and signature from text
msg_match = re.search(r"Message:\s*([0-9a-fA-F]+)", content)
sig_match = re.search(r"Signature \(r,s\):\s*(\d+),\s*(\d+)", content)

if not msg_match or not sig_match:
    raise ValueError("Could not parse message or signature.")

msg_hex = msg_match.group(1)
r = int(sig_match.group(1))
s = int(sig_match.group(2))
message = bytes.fromhex(msg_hex)

# Step 3: Compute SHA256 hash of message
h = int.from_bytes(SHA256.new(message).digest(), byteorder='big')

# Step 4: Recover private key
r_inv = pow(r, -1, n)
d = ((s * KNOWN_K - h) * r_inv) % n

# Step 5: Reconstruct private key
priv_key = ECC.construct(curve='P-256', d=d)

# Step 6: Output results
print("✔️ Signature valid with public key.")
print(f"🔑 Recovered private key (d): {d}")
print(f"🏁 Recovered flag (message): {message.decode()}")

```

Running solver gave us the flag

```powershell
PS C:\Users\saleh\Downloads\cryptooo> & C:/Users/saleh/AppData/Local/Programs/Python/Python313/python.exe c:/Users/saleh/Downloads/cryptooo/discovery.py
✔️ Signature valid with public key.
🔑 Recovered private key (d): 54557082544614123842088576588847111891417741407876865337994383802864000837462
🏁 Recovered flag (message): 3CC_1s_Br0k3n
```
