---
description: Here you'll find different Steganography tasks solved step-by-step
---

# 🧙 Steganography

### Hidden

<figure><img src="../../../../.gitbook/assets/image (75).png" alt=""><figcaption><p>IMAGE</p></figcaption></figure>

The given image

<figure><img src="../../../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

Using the strings command on the picture returned our flag

<figure><img src="../../../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

### New Meta

<figure><img src="../../../../.gitbook/assets/image (50).png" alt=""><figcaption><p>IMAGE</p></figcaption></figure>

From the title, the author gave us a hint **meta** for **metadata**&#x20;

Running the <mark style="color:red;">exiftool</mark> command will extract the metadata

<figure><img src="../../../../.gitbook/assets/image (71).png" alt=""><figcaption></figcaption></figure>

### My Secrets

<figure><img src="../../../../.gitbook/assets/image (33).png" alt=""><figcaption><p>PLAIN TEXT</p></figcaption></figure>

This type of steganography was used in tweet known as [Twitter Secret Messages](https://holloway.nz/steg/)

<figure><img src="../../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>



### ICanSeeYourVoice

<figure><img src="../../../../.gitbook/assets/image (69).png" alt=""><figcaption><p>WAV File</p></figcaption></figure>

As the title said "ICanSeeYourVoice".It's obvious that we're going to see the flag. So I used spek

**Acoustic Spectrum Analyser**

[Spek](http://spek.cc) (IPA: /spɛk/, ‘bacon’ in Dutch) helps to analyse your audio files by showing their spectrogram.

<figure><img src="../../../../.gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>

### Crack The Uchiha Clan

<figure><img src="../../../../.gitbook/assets/image (27).png" alt=""><figcaption><p>ZIP File</p></figcaption></figure>

I started by cracking the pass of the zip using **John**

```shell
zip2john LetMeIIN.zip > john.hash
john john.hash
```

The result of zip pass was "Love" & extracting it gave us 2 Images

**Checking the metadata is Important**

```shell
exiftool madara1.jpeg mara2.jpeg
```

And we had this interesting Comment : **Here is your passphrase : The Ghost Of The Uchiha**

So We used the passphrase for extracting flag from second image as shown below &#x20;

<figure><img src="../../../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

### Cheb Hasni

<figure><img src="../../../../.gitbook/assets/image (65).png" alt=""><figcaption><p>WAV File</p></figcaption></figure>

### ZERO WIDTH

<figure><img src="../../../../.gitbook/assets/image (82).png" alt=""><figcaption></figcaption></figure>

Zero width characters hidden inside this plaintext :&#x20;

```
Flibberwobble ‌‌‌‌‍‍‌﻿zentronix ‌‌‌‌‍﻿‌‌splargle, quazbot rainbows spinning on‌‌‌‌‍‬‌‍ a‌‌‌‌‍﻿‌‬ ‌‌‌‌‍‬‬﻿‌‌‌‌‍﻿‬﻿cucumber ‌‌‌‌‍﻿‬‬bicycle ‌‌‌‌‌﻿‌﻿while‌‌‌‌‍﻿‌‬ penguins‌‌‌‌‌﻿‌‌‌‌‌‌‍‍﻿﻿ code‌‌‌‌‍‌‌﻿ ‌‌‌‌‌﻿‌‌in binary ‌‌‌‌‍﻿‍‍‌‌‌‌‍‬﻿‌on the‌‌‌‌‍‌‍‌ surface‌‌‌‌‍‍﻿﻿‌‌‌‌‍‌‬‌ of‌‌‌‌‌﻿‌‍ Mars. ‌‌‌‌‍‌‍‌Wibble wibble‌‌‌‌‌﻿‌﻿, sparkly‌‌‌‌‍‍﻿﻿ ‌‌‌‌‍‍‌﻿‌‌‌‌‌﻿‌‌noodles‌‌‌‌‍‍﻿﻿ dance‌‌‌‌‍‬﻿‍‌‌‌‌‌﻿‍‌ ‌‌‌‌‍‬﻿‬in‌‌‌‌‍﻿‬‍ ‌‌‌‌‍‍﻿﻿the‌‌‌‌‍‍‍‌ moonlight.‌‌‌‌‍‬‬‌‌‌‌‌‌﻿‌‍‌‌‌‌‍‬﻿‬‌‌‌‌‍‬‍﻿‌‌‌‌‍﻿‌﻿‌‌‌‌‍﻿﻿‍
```

Go to [https://330k.github.io/misc\_tools/unicode\_steganography.html](https://330k.github.io/misc_tools/unicode_steganography.html)&#x20;

Set Secret to Steganography Text

<figure><img src="../../../../.gitbook/assets/image (84).png" alt=""><figcaption></figcaption></figure>

Now hit **Decode**&#x20;

<figure><img src="../../../../.gitbook/assets/image (85).png" alt=""><figcaption></figcaption></figure>
