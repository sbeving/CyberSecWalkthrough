---
description: Here you'll find different Encoding tasks solved step-by-step
---

# 💱 ENCODING

### ROT 13

<figure><img src="../../../../.gitbook/assets/image (57).png" alt=""><figcaption></figcaption></figure>

**ROT13** ("**rotate by 13 places**", sometimes hyphenated **ROT-13**) is a simple letter [substitution cipher](https://en.wikipedia.org/wiki/Substitution_cipher) that replaces a letter with the 13th letter after it in the alphabet. ROT13 is a special case of the [Caesar cipher](https://en.wikipedia.org/wiki/Caesar_cipher) which was developed in ancient Rome.

To Solve this task I used [ROT13.COM](https://rot13.com)

> Spark{34rth\_r0t4t3s\_s4me\_f0r\_w0rds}

### HEXordinary

<figure><img src="../../../../.gitbook/assets/image (74).png" alt=""><figcaption></figcaption></figure>

Hex or base 16 or hexadecimal is a numeral system that uses 16 symbols. The symbols include 0-9 and a-f (sometimes A-F). An example of a hexadecimal number is 3BF2.

I used [hex-to-ascii](https://www.rapidtables.com/convert/number/hex-to-ascii.html) online tool gave it the encoded text it returned the flag :

> Spark{that\_was\_easy\_hexin\_it}

### Base 8\*8

<figure><img src="../../../../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

Base 8\*8 means Base64,using an [online decoder](https://www.base64decode.org)&#x20;

> Spark{b4s3\_64\_is\_sup3r\_c00l}

Or using the terminal&#x20;

<figure><img src="../../../../.gitbook/assets/image (59).png" alt=""><figcaption></figcaption></figure>

### Hidden under my bases

<figure><img src="../../../../.gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

It's obvious that the encoding used bases(Base 85,64,62....) as the title said & in the Desc they obliged us to dig deeper

I used [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base85\('!-u',true\)From_Base64\('A-Za-z0-9%2B/%3D',true,false\)From_Base62\('0-9A-Za-z'\)From_Base58\('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',true\)From_Base45\('0-9A-Z%20$%25*%2B%5C%5C-./:',true\)From_Base32\('A-Z2-7%3D',true\)\&input=OjJPZkM9X3FiRzwqKXQiPSkob1VAUmBoI0BtakhVPFxSKiI8KiFzNztmNjhOOy9LSz07YWI6Vj1ZYWVgPCwtKUE9YC1ccTwmJF10QTYhR0I6SV0ubjtEOlJcQFBWX0RANUNxVEA4b2o/QDk3XFJAbWshITlpYjppPSU1Zig9JnMhMTowMlswPiYlNVM6S0wvKz4nYHFhPCwsJEc5ZVw7PUBxb2goOzBsYlY8YzJTQT0pO1xFQTIjbGU8Q0JfPjovdStOOklSKmM7LHFSLkByK24yO2NJRic7MG0lbDstLjpEOy9MOGZAUEQ9bkBUNmhrOy02alc6LDZLVkE2OztUOy0tcUQ5bCtjSTozcFwwOks7NE85ZWYoXzxBUkJkOiwsTF45aDdsYjpJZVNXPSlFJUs8ZEllXTthYU1XO19xISFBNENCWzoyTm1PQU8vSUI) to decode&#x20;

<table><thead><tr><th width="98" align="center">Base</th><th align="center">Cipher</th></tr></thead><tbody><tr><td align="center">85</td><td align="center">:2OfC=<em>qbG&#x3C;*)t"=)(oU@R<code>h#@mjHU&#x3C;\R*"&#x3C;*!s7;f68N;/KK=;ab:V=Yae</code>&#x3C;,-)A=<code>-\q&#x3C;&#x26;$]tA6!GB:I].n;D:R\@PV_D@5CqT@8oj?@97\R@mk!!9ib:i=%5f(=&#x26;s!1:02[0>&#x26;%5S:KL/+>'</code>qa&#x3C;,,$G9e;=@qoh(;0lbV&#x3C;c2SA=);\EA2#le&#x3C;CB</em>>:/u+N:IR*c;,qR.@r+n2;cIF';0m%l;-.:D;/L8f@PD=n@T6hk;-6jW:,6KVA6;;T;--qD9l+cI:3p\0:K;4O9ef(_&#x3C;ARBd:,,L^9h7lb:IeSW=)E%K&#x3C;dIe];aaMW;_q!!A4CB[:2NmOAO/IB</td></tr><tr><td align="center">64</td><td align="center">NmlOYlhMTWRXWjZmbFFhcDY3V0I1TVpPSnhXQmZXSDh5Y2lGTjhNYnFBT1B6dUlPOFlKR0Frb2kxa3VHaTJsaWxUcDhEMVVNWFJtWVhONWxFZjZhOWJnZzNrTjJrM01mcjlwQzdZVnhHWllId05zUDR1NUlrOE4yQUpKclNHSThKQzlhQWdkQmpkb0dVbTc0QXV6N2hLdXF0QWZuMlpSNzk0OUlrM1EzU3NlN1NoMHJaOGZEWmtFVzVjSDRLS3I0dFlxNmRueA==</td></tr><tr><td align="center">62</td><td align="center">6iNbXLMdWZ6flQap67WB5MZOJxWBfWH8yciFN8MbqAOPzuIO8YJGAkoi1kuGi2lilTp8D1UMXRmYXN5lEf6a9bgg3kN2k3Mfr9pC7YVxGZYHwNsP4u5Ik8N2AJJrSGI8JC9aAgdBjdoGUm74Auz7hKuqtAfn2ZR7949Ik3Q3Sse7Sh0rZ8fDZkEW5cH4KKr4tYq6dnx</td></tr><tr><td align="center">58</td><td align="center">36zTAedrLetWWBwTjwyzUQvjTk97S5S8S8bCkrJq8BciWXESGgHcEZnXiPMiBeeL5j4wq8TVj8e5fTMjQJLUuRgQEbKN6qwvHBN2tfJ96CheyDAEmSFqKfQXA8UjaAzw5CD7FPWHuuTgKinPT9wE</td></tr><tr><td align="center">45</td><td align="center">IN9+CBEM8PTA%6AN1BGM8-S931A-IBF%6WL6OS95OA R6:L6U6A-CBIB96T9X+927AFNA+L6B1A27ADM8 S8RY9ZR6*090M6RY9KTA+M9TB9</td></tr><tr><td align="center">32</td><td align="center">KNYGC4TLPNWGC6LFOJZV633GL5SW4Y3SPFYHI2LPNZPWS43OORPWC3DXMF4XGX3TMFTGK7I=</td></tr><tr><td align="center">Flag</td><td align="center">Spark{layers_of_encryption_isnt_always_safe}</td></tr></tbody></table>

### Lord Ceaser

<figure><img src="../../../../.gitbook/assets/image (56).png" alt=""><figcaption></figcaption></figure>

In [cryptography](https://en.wikipedia.org/wiki/Cryptography), a **Caesar cipher**, also known as **Caesar's cipher**, the **shift cipher**, **Caesar's code** or **Caesar shift**, is one of the simplest and most widely known [encryption](https://en.wikipedia.org/wiki/Encryption) techniques. It is a type of [substitution cipher](https://en.wikipedia.org/wiki/Substitution_cipher) in which each letter in the [plaintext](https://en.wikipedia.org/wiki/Plaintext) is replaced by a letter some fixed number of positions down the [alphabet](https://en.wikipedia.org/wiki/Alphabet). For example, with a left shift of 3, D would be replaced by A, E would become B, and so on.\*

Decoding the cipher w/ [dcode.fr](https://www.dcode.fr/caesar-cipher) gave us&#x20;

> Spark{Classic\_but\_still\_unclear}

### ROT 47

<figure><img src="../../../../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

In the Description, 47 means ROT47 which can be decoded using [dcode.fr ](https://www.dcode.fr/rot-47-cipher)

> Spark{rot47\_is\_too\_hot}

### Shift !!!

<figure><img src="../../../../.gitbook/assets/image (60).png" alt=""><figcaption></figcaption></figure>

A **shift cipher** is a substitution cipher, the principle of which is to shift the letters by one or more values in the alphabet.

Using [dcode.fr](https://www.dcode.fr/shift-cipher) we got&#x20;

> Spark{OMG\_you\_got\_it\_good\_job}
>
> & the shifting (1,2,3)/3n

### Vigenere

<figure><img src="../../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

The **Vigenère cipher** (French pronunciation: ​[\[viʒnɛːʁ\]](https://en.wikipedia.org/wiki/Help:IPA/French)) is a method of [encrypting](https://en.wikipedia.org/wiki/Encryption) [alphabetic](https://en.wikipedia.org/wiki/Alphabetic) text by using a series of interwoven [Caesar ciphers](https://en.wikipedia.org/wiki/Caesar_cipher), based on the letters of a keyword. It employs a form of [polyalphabetic substitution](https://en.wikipedia.org/wiki/Polyalphabetic_cipher).

CRYPTOGRAPHY is the key of the Encryption.

Using [dcode.fr](https://www.dcode.fr/vigenere-cipher) we got&#x20;

> Spark{this\_time\_u\_know\_the\_key\_next\_time\_you\_don't}

### 2 in 1 day (Twin-Hex)

<figure><img src="../../../../.gitbook/assets/image (62).png" alt=""><figcaption></figcaption></figure>

The **Twin-Hex** encoding is much harder to crack than most simple cyphers, as it operates on letter pairs, rather than individual characters - hence the 'twin' part of the name.

Using [calcresult](https://www.calcresult.com/misc/cyphers/twin-hex.html) to decode it&#x20;

> Spark{Tw1n\_f0r\_th3\_w1n}

### When my rainbow rhythm

<figure><img src="../../../../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

The given image has HexaHue Encoding

<figure><img src="../../../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

You can decode it on [dcode.fr](https://www.dcode.fr/hexahue-cipher)

### BigBen

<figure><img src="../../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

The given image contains PigPen cipher Encoding

<figure><img src="../../../../.gitbook/assets/image (64).png" alt=""><figcaption></figcaption></figure>

You can reaveal the hidden message in [dcode.fr](https://www.dcode.fr/pigpen-cipher)

### Intro

<figure><img src="../../../../.gitbook/assets/image (51).png" alt=""><figcaption></figcaption></figure>

Warm-up.py contains the code below

```python
#!/usr/bin/env python3
import sys
# import system library
if sys.version_info.major == 2:
    print("Use Python3 it is a trend :p ")
ords = [58, 25, 8, 27, 2, 18, 57, 16, 94, 1, 89, 7, 90, 54, 93, 54, 94, 1, 90, 54, 62, 88, 39, 20]
print("Here is your flag:")
print("".join(chr(o ^ 0x69) for o in ords))
```

Running the script printed our flag

> Spark{Py7h0n3\_4\_7h3\_W1N}

### Print(flag)

<figure><img src="../../../../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

We need to turn the list of ASCII's to a string to pass it to the executable&#x20;

```python
key_of_life=[84,104,101,95,119,101,101,107,110,100,95,100,105,101,95,102,111,114,95,121,111,117]
for i in key_of_life:
    print(chr(i),end='')
# output : The_weeknd_die_for_you 
```

Passing the **output** as **input** to **first\_task.exe** printed our flag

<figure><img src="../../../../.gitbook/assets/image (66).png" alt=""><figcaption></figcaption></figure>

### Trip to Mars

<figure><img src="../../../../.gitbook/assets/image (52).png" alt=""><figcaption></figcaption></figure>

Listening to WAV files is important !!

In this file it's obvious Morse code is used & to decode it visit [morsecode.world](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)

> Spark{NICEVOICEICHYABOY}

### OMO OMO

<figure><img src="../../../../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

The [COW programming language](https://esolangs.org/wiki/COW) is an esoteric programming language created by [Sean Heber](https://bigzaphod.github.io/COW/) in 2003. It is a Brainf\*ck variant designed humorously with Bovinae in mind.

To decode it visit [cachesleuth.com](https://www.cachesleuth.com/cow.html) and our flag is&#x20;

> Spark{c0w\_c0w\_m00\_m0000}

### Index

<figure><img src="../../../../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

Its clear those numbers exist for a reason&#x20;

I tried turning them into chars, here's what i got

```python
keys = [18, 15, 0, 17, 10, 27, 2, 14, 20, 13, 19, 8, 13, 6, 12, 24, 19, 0, 18, 10, 18, 27]
for i in keys:
    print(chr(i+65), end='')
# output : SPARK\COUNTINGMYTASKS\
```

> Spark{COUNTINGMYTASKS}

### RegCode

<figure><img src="../../../../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

Some of you may know hashes others don't visit this website for enlightenment [HERE](https://www.techtarget.com/searchdatamanagement/definition/hashing)

First thing we need to identify the hash then try to crack it using this [website](https://hashes.com/en/tools/hash_identifier)

<figure><img src="../../../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

So the hash type is [MD5](https://fr.wikipedia.org/wiki/MD5) and it's Spark in Plain/text so our flag will be

> Spark{Spark}
