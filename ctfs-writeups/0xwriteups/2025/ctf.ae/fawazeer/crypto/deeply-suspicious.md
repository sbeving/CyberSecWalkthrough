# Deeply Suspicious

Challenge Description

In this challenge, titled "Deeply Suspicious," we are tasked by the government to decrypt a criminal transmission. We're provided with an RSA-encrypted ciphertext, a public key modulus `n`, the public exponent `e = 65537` (0x10001), and a mysterious "leak" described as `factorial_mod(p-1,n)`. The goal is to use this information to recover the original flag.

### Challenge.py

```python
import os
from secrets import leak, p, q

from Crypto.Util.number import bytes_to_long

flag=bytes_to_long(os.getenv("FLAG","FLAG{REDACTED}").encode())
n=p*q
e=0x10001
def factorial_mod(a,n):
    res=1
    for i in range(1,a+1):
        res=(res*i)%n
    return res
print("One of the secret agents successfully acquired a leak containing sensitive information about criminal activities. However, upon inspection, the obtained data appeared to be of little use.")
print(f"the only thing is known is that factorial_mod(p-1,n)={leak}")
print("We need your expertise to decrypt the data obtained from the criminals' communications and assist us in apprehending them")
print(f"Here is the encrypted data: {pow(flag,e,n)}")
print(f"pubkey: {n}")
```

<figure><img src="../../../../../../.gitbook/assets/image (2) (1).png" alt=""><figcaption><p><a href="https://953ce81a313813784c9adb934088225e.chal.ctf.ae/">https://953ce81a313813784c9adb934088225e.chal.ctf.ae/</a></p></figcaption></figure>

#### Given Data

* **Leak**: `factorial_mod(p-1,n) = 22824927568379076930982500035833884888382288289321794400021843661854179808056790322611312747824856598317400953128967870383782759041725450527145280171952983690759348592583081704547466159880771277921341435428233285028150373588149270776449864642195802606252354556577400353001301003517363152170541523074902666086`
* **Ciphertext**: `6164227335261046013236133009909193595338315991408774765844207109667187128915928980465996058597680704885601362465622012957220331289778975746969084069598993910184561096159841091098186778344646957627998780794592927833051360671416450369393631341830674299813661915292150200182351514371133502253012040862595999782`
* **Public Key (n)**: `109110357740395944076150767016138593567154539844190870651264490180155550490385760166670247677139233067935806231311964850237711104674357706756748405406629009552898220389946539311072284542148083881745639338165914017695425520257578789239678662975735012984867520845825985983850506881070472665206613452398692599947`
* **Public Exponent (e)**: `65537` (0x10001)

### Analysis

The challenge provides a standard RSA setup where:

* `n = p * q` (product of two primes)
* The ciphertext is `c = pow(m, e, n)` (flag encrypted with the public key)
* We need to find the private key `d` to decrypt: `m = pow(c, d, n)`

The key piece of information is the "leak": `factorial_mod(p-1,n) = (p-1)! mod n`. At first glance, this seems unhelpful, but it turns out to be the critical weakness in the encryption.

From the source code:

```python
def factorial_mod(a,n):
    res=1
    for i in range(1,a+1):
        res=(res*i)%n
    return res
leak = factorial_mod(p-1,n)
```

This computes `(p-1)! mod n`, where `p` is one of the prime factors of `n`.

#### Key Insight

Since `n = p * q`, and `p` and `q` are distinct primes, we know:

* `(p-1)! = 1 * 2 * ... * (p-1)`
* When computed modulo `n`, this is equivalent to `(p-1)! mod p * (p-1)! mod q` due to the Chinese Remainder Theorem.

By Wilson's Theorem, for a prime `p`:

* `(p-1)! ≡ -1 (mod p)`
* Thus, `leak = (p-1)! mod n ≡ -1 (mod p)`

Since `-1 mod p = p-1`, we have:

* `leak ≡ p-1 (mod p)`
* Therefore, `leak + 1 ≡ p (mod p)`, meaning `leak + 1` is a multiple of `p`.

Because `n = p * q`, if we compute `gcd(leak + 1, n)`, it will reveal `p` (assuming `leak + 1` isn't also a multiple of `q`, which is unlikely given the size of the numbers).

### Solution

We can factor `n` using the leak and then perform standard RSA decryption.

#### Steps

1. **Factorize `n`**:
   * Compute `p = gcd(leak + 1, n)`
   * Compute `q = n // p`
2. **Compute `phi`**:
   * `phi = (p-1) * (q-1)`
3. **Compute private key `d`**:
   * `d = inverse(e, phi)`
4. **Decrypt the ciphertext**:
   * `m = pow(c, d, n)`
   * Convert `m` to bytes to get the flag

#### Solver Code

```python
from Crypto.Util.number import inverse, long_to_bytes
import math

leak = 22824927568379076930982500035833884888382288289321794400021843661854179808056790322611312747824856598317400953128967870383782759041725450527145280171952983690759348592583081704547466159880771277921341435428233285028150373588149270776449864642195802606252354556577400353001301003517363152170541523074902666086
ciphertext = 6164227335261046013236133009909193595338315991408774765844207109667187128915928980465996058597680704885601362465622012957220331289778975746969084069598993910184561096159841091098186778344646957627998780794592927833051360671416450369393631341830674299813661915292150200182351514371133502253012040862595999782
n = 109110357740395944076150767016138593567154539844190870651264490180155550490385760166670247677139233067935806231311964850237711104674357706756748405406629009552898220389946539311072284542148083881745639338165914017695425520257578789239678662975735012984867520845825985983850506881070472665206613452398692599947
e = 65537

# Factorize n using the leak
p = math.gcd(leak + 1, n)
q = n // p

# Calculate phi
phi = (p - 1) * (q - 1)

# Calculate private key d
d = inverse(e, phi)

# Decrypt
flag = pow(ciphertext, d, n)
flag = long_to_bytes(flag)

print("Flag:", flag.decode()) 

# Flag: flag{6nUtkiIHlqyxcQ1rZkyOt3labVrR1l4T}
```

### Conclusion

The challenge exploits a clever weakness in RSA by leaking `(p-1)! mod n`. By recognizing that `leak + 1` shares a factor with `n`, we can efficiently factorize the modulus and recover the private key. This is a classic example of how seemingly obscure mathematical properties (like Wilson's Theorem) can break cryptographic systems when side information is leaked.





