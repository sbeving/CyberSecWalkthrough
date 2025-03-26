# Endless Cycle



```python
#!/usr/bin/env python3

# Dati cifrati dalla memoria
encrypted_bytes = [
    0xb6, 0x9e, 0xad, 0xc5, 0x92, 0xfa, 0xdf, 0xd5, 
    0xa1, 0xa8, 0xdc, 0xc7, 0xce, 0xa4, 0x8b, 0xe1, 
    0x8a, 0xa2, 0xdc, 0xe1, 0x89, 0xfa, 0x9d, 0xd2, 
    0x9a, 0xb7
]

# Chiave XOR: 0xbeefcafe in formato little-endian
key_bytes = [0xfe, 0xca, 0xef, 0xbe]

# Decifrare utilizzando XOR
decrypted = []
for i in range(len(encrypted_bytes)):
    decrypted.append(encrypted_bytes[i] ^ key_bytes[i % 4])

# Convertire in stringa
flag = ''.join(chr(b) for b in decrypted if 32 <= b <= 126)  # Solo caratteri stampabili
print("Flag decodificata:", flag)

# Prova anche altre varianti della chiave
print("\nProve con altre varianti della chiave:")

# Big-endian
key_bytes2 = [0xbe, 0xef, 0xca, 0xfe]
decrypted2 = []
for i in range(len(encrypted_bytes)):
    decrypted2.append(encrypted_bytes[i] ^ key_bytes2[i % 4])
flag2 = ''.join(chr(b) for b in decrypted2 if 32 <= b <= 126)
print("Variante 1:", flag2)

# Prova con inversione dell'ordine degli encrypted bytes
reversed_enc = encrypted_bytes[::-1]
decrypted3 = []
for i in range(len(reversed_enc)):
    decrypted3.append(reversed_enc[i] ^ key_bytes[i % 4])
flag3 = ''.join(chr(b) for b in decrypted3 if 32 <= b <= 126)
print("Variante 2:", flag3)

# Considerando l'ordine di memoria
result = []
for i in range(0, len(encrypted_bytes), 4):
    chunk = encrypted_bytes[i:i+4]
    # Completa il chunk se necessario
    while len(chunk) < 4:
        chunk.append(0)
    # Applica XOR per ogni dword
    for j in range(len(chunk)):
        result.append(chunk[j] ^ key_bytes[j])

flag4 = ''.join(chr(b) for b in result if 32 <= b <= 126)
print("Variante 3:", flag4)
```
