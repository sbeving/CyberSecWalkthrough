---
icon: face-hand-peeking
---

# Steganography

#### Hide, Find, and Extract the Invisible

> 🎯 _“If you can’t see it, it’s probably hiding in plain sight.”_\
> Steganography is the art of **concealing information inside digital media** — images, audio, video, archives, and even metadata.\
> In CTFs, stego challenges test your ability to detect, decode, and recover hidden payloads using logic, analysis, and the right toolchain.

***

### I. 🧩 Core Concepts

| Concept                         | Description                                                            |
| ------------------------------- | ---------------------------------------------------------------------- |
| **Carrier**                     | The file hiding the data (image, audio, video, etc.)                   |
| **Payload**                     | The secret data hidden within                                          |
| **Embedding**                   | The process of hiding data                                             |
| **Extraction**                  | The process of revealing data                                          |
| **LSB (Least Significant Bit)** | Common image/audio technique modifying pixel/sample bits               |
| **Metadata Stego**              | Hidden info in EXIF, ID3, or file headers                              |
| **Container Stego**             | Data hidden inside compressed archives, nested zips, or appended files |

🧠 Always start with **file analysis** — many CTFs hide data in headers or appended files _before_ complex methods.

***

### II. 🧠 Initial File Analysis

#### 1️⃣ Identify File Type

```bash
file image.jpg
exiftool image.jpg
binwalk -e image.jpg
```

#### 2️⃣ View Hex Structure

```bash
xxd image.jpg | head
strings image.jpg | less
```

> 🔍 Look for weird text at the end (`flag{...}`, `PK...`, `Rar!`, `JFIF`, `ID3` etc.)

#### 3️⃣ Check for Appended Data

```bash
binwalk -e --dd='.*' suspicious.png
```

***

### III. 🧰 Common Stego Tools & Techniques

| Tool                       | File Type                     | Usage                              |
| -------------------------- | ----------------------------- | ---------------------------------- |
| **Steghide**               | JPG, BMP, WAV                 | `steghide extract -sf image.jpg`   |
| **OutGuess**               | JPG                           | `outguess -r image.jpg output.txt` |
| **zsteg**                  | PNG                           | `zsteg -a image.png`               |
| **Stegsolve**              | Images (visual)               | Analyze color planes & LSB         |
| **Stegano-lsb (Python)**   | PNG/BMP                       | `stegano-lsb reveal image.png`     |
| **Stegseek**               | Steghide brute-forcer         | `stegseek image.jpg rockyou.txt`   |
| **Exiftool**               | Images / Audio                | Metadata inspection                |
| **Binwalk**                | All binary                    | Extract embedded files             |
| **Foremost**               | Generic extraction            | `foremost image.jpg`               |
| **Ghex / Bless**           | Manual hex editing            | View hidden binary or text         |
| **StegOnline**             | Web GUI                       | Multi-format stego platform        |
| **stegdetect / stegbreak** | JPEG                          | Detect & crack steghide-like steg  |
| **StegBarb**               | PNG                           | Advanced LSB analyzer              |
| **Spectrogram / Spek**     | WAV/MP3                       | Visualize hidden patterns in sound |
| **wavsteg / deep-sound**   | WAV                           | Extract embedded payloads          |
| **snow / whitespace**      | TXT                           | Hidden data in spaces & tabs       |
| **StegoVeritas**           | Automated all-in-one analyzer | `stegoveritas file.jpg`            |

🧠 _Tip:_ Combine multiple tools — some flags only appear after you extract recursively.

***

### IV. 🧠 Image Steganography

#### 1️⃣ Visual Inspection

* Open in **Stegsolve** or **StegOnline**.
* Cycle through **color planes**, **bit layers**, and **RGB differences**.\
  → Look for faint patterns, QR codes, or text outlines.

#### 2️⃣ Metadata & Hidden Text

```bash
exiftool image.jpg
strings image.jpg | grep -i flag
```

#### 3️⃣ Common Techniques

| Technique                       | Tool / Example                                         |
| ------------------------------- | ------------------------------------------------------ |
| **LSB (Least Significant Bit)** | `zsteg -a file.png`                                    |
| **Palette manipulation**        | `convert image.gif -format txt -compress none out.txt` |
| **Hidden in Alpha Channel**     | Stegsolve → Alpha plane                                |
| **Appended file**               | `binwalk -e file.jpg`                                  |
| **Steghide payload**            | `steghide extract -sf image.jpg`                       |

#### 4️⃣ Password-Protected Steghide

```bash
stegseek image.jpg rockyou.txt
```

→ extracts automatically with password from wordlist.

***

### V. 🔊 Audio Steganography

#### 1️⃣ Spectrum Analysis (Visual)

* Use **Spek** or **Sonic Visualiser**
* Load `.wav` / `.mp3` → check frequency bands for anomalies (QR code-like patterns, lines, or morse).

#### 2️⃣ WAV File Extraction

```bash
wavsteg -r -s audio.wav -o output.txt
```

#### 3️⃣ Steghide in Audio

```bash
steghide extract -sf sound.wav
```

#### 4️⃣ Phase or LSB Encoding

* Inspect waveform for **pattern repetition**.
*   Convert to **raw bytes** for deeper diff analysis:

    ```bash
    xxd audio.wav > dump.hex
    ```

***

### VI. 📦 Archive & Recursive Stego

#### 1️⃣ Hidden Archives

```bash
binwalk -e suspicious.jpg
```

→ May extract embedded `.zip`, `.rar`, `.7z`.

#### 2️⃣ RAR/ZIP Nesting

```bash
unzip hidden.zip
7z x hidden.7z
```

→ CTF trick: password of next layer = flag of previous file.

#### 3️⃣ File Signature Mismatch

```bash
xxd -l 20 file | grep -E "50 4B|52 61 72|89 50 4E 47"
```

| Signature     | Format |
| ------------- | ------ |
| `50 4B 03 04` | ZIP    |
| `52 61 72 21` | RAR    |
| `89 50 4E 47` | PNG    |
| `FF D8 FF E0` | JPEG   |

🧠 _If `file` says PNG but hex starts with `52 61 72` → it’s stego._

***

### VII. 💽 Text & Document Stego

| Type                               | Technique                    | Tool                                  |
| ---------------------------------- | ---------------------------- | ------------------------------------- |
| **Whitespace**                     | Spaces/tabs as bits          | `snow -C -m "secret" -p "pass"`       |
| **Invisible Characters (Unicode)** | Zero-width joiners           | `stegcloak hide "secret" -p password` |
| **Fonts or PDF Layers**            | Hidden text layers           | `pdftotext`, inspect in GIMP          |
| **Morse Code or Binary in Text**   | `.`, `_`, `0`, `1` sequences | `tr '_. ' '01'` + decode              |

***

### VIII. 🎥 Video Steganography

| Method                      | Tool / Example                                                           |
| --------------------------- | ------------------------------------------------------------------------ |
| **Frame-level LSB**         | Extract frames: `ffmpeg -i video.mp4 frames/frame%03d.png` → run `zsteg` |
| **Audio Track Stego**       | Extract audio: `ffmpeg -i video.mp4 -q:a 0 -map a audio.wav` → `wavsteg` |
| **Hidden Files in Streams** | `binwalk -e video.mp4`                                                   |
| **Hidden Subtitles**        | `ffmpeg -i video.mp4` → check `.srt`                                     |
| **Data Appending**          | `xxd` or `binwalk` inspection                                            |

***

### IX. 🧠 Recursive Stego Chains

CTF creators love **“onion-style” challenges**:

```
image.jpg → binwalk → hidden.zip → steghide → audio.wav → spectrogram → flag
```

💡 _Every extraction reveals another clue. Automate it:_

```bash
#!/bin/bash
file=$1
while true; do
  echo "[*] Scanning $file"
  binwalk -e $file
  new=$(find . -type f -name '*.*' ! -name "$file" | head -n 1)
  [ -z "$new" ] && break
  file=$new
done
```

***

### X. 🧩 Advanced / Less Common Tricks

| Category                      | Example                      | Tool           |
| ----------------------------- | ---------------------------- | -------------- |
| **Audio Phase Encoding**      | Phase shift → binary data    | Audacity       |
| **MP3 ID3 Tags**              | `id3v2 -l file.mp3`          |                |
| **Image Comments**            | \`strings image.jpg          | grep Comment\` |
| **QR Code inside Image**      | Stegsolve color layers       |                |
| **Base64 or Hex in Metadata** | `exiftool image.png`         |                |
| **Rar5 Nested Archive**       | `7z l file`                  |                |
| **Hidden partitions**         | `fdisk -l`, `foremost`, `dd` |                |

***

### XI. 🧰 Automated All-in-One Tools

| Tool                                   | Description                             |
| -------------------------------------- | --------------------------------------- |
| **StegoVeritas**                       | Complete stego analyzer for images      |
| **Binwalk + Foremost + Strings combo** | Recursive extraction                    |
| **Exiftool**                           | Metadata miner                          |
| **zsteg + stegseek + steghide**        | Image brute-force                       |
| **stegcracker**                        | Python wrapper for brute-force steghide |
| **StegOnline / Aperisolve**            | Web-based auto analyzers                |
| **Detect-It-Easy (DIE)**               | Windows binary detector                 |
| **Magic Eye / Visual stego**           | Visual pattern finder                   |
| **stegdetect + stegbreak**             | JPEG steg detection                     |

***

### XII. 🧠 Quick Reference Commands

| Task                         | Command                        |
| ---------------------------- | ------------------------------ |
| Extract from JPEG (steghide) | `steghide extract -sf img.jpg` |
| Brute-force steghide         | `stegseek img.jpg rockyou.txt` |
| Analyze PNG LSB              | `zsteg -a img.png`             |
| Detect hidden files          | `binwalk -e file`              |
| Metadata                     | `exiftool file`                |
| Hex dump                     | \`xxd file                     |
| Search for flag              | \`strings file                 |
| Audio spectrogram            | `spek file.wav`                |
| Recursive zip                | `7z x hidden.zip`              |

***

### XIII. 🧠 Strategy Flow (CTF Workflow)

```
1️⃣ file → filetype, exiftool, strings
2️⃣ binwalk / foremost → extract hidden content
3️⃣ zsteg / steghide / stegseek → test for LSB
4️⃣ audio/video? → spek / ffmpeg / wavsteg
5️⃣ archives? → unzip / 7z / rar / recurse
6️⃣ text files? → snow / stegcloak / whitespace
7️⃣ repeat recursively until flag{found}
```

***

### XIV. 🧱 Stego Detection Indicators

| Indicator                    | What It Means      |
| ---------------------------- | ------------------ |
| Unusually large file size    | Embedded payload   |
| Non-standard file signature  | Appended file      |
| Image noise or color anomaly | LSB                |
| Hidden text in EXIF          | Metadata stego     |
| Audio distortion             | Spectral embedding |
| ZIP inside image             | Container stego    |

***

### XV. 🧠 Pro Tips

* Always **work on copies** — extraction can corrupt originals.
* Check **different color channels** (RGB, alpha).
* Automate brute-forcing for passwords & recursive layers.
* Never trust the file extension — _always verify magic bytes_.
*   Keep a **stego toolkit folder** with:

    ```
    binwalk, zsteg, stegseek, steghide, exiftool, spek, ffmpeg, foremost, stegsolve.jar
    ```

***

### XVI. ⚡ Example CTF Workflow

```
file mystery.jpg
exiftool mystery.jpg
strings mystery.jpg | grep flag
zsteg -a mystery.jpg
binwalk -e mystery.jpg
stegseek extracted.jpg rockyou.txt
spek output.wav
```

➡️ flag{there\_is\_no\_plain\_sight}

***
