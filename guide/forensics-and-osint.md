---
icon: user-magnifying-glass
---

# Forensics & OSINT

## **Forensics & OSINT Fundamentals — Hunting the Hidden Truth**

***

Digital forensics and OSINT are where CTF challenges become detective work — **tracing artifacts, decoding hidden data, and uncovering secrets left behind**.\
This guide transforms you into a cyber investigator: from dissecting pcap files and images to deanonymizing users and tracking infrastructure online.

***

### I. 🧩 Core Concepts

| Concept                              | Description                                                    |
| ------------------------------------ | -------------------------------------------------------------- |
| **Forensics**                        | Extracting evidence or data from files, memory, or systems.    |
| **OSINT (Open Source Intelligence)** | Gathering intelligence from publicly available sources.        |
| **Metadata**                         | Hidden descriptive data within files (author, timestamp, GPS). |
| **Steganography**                    | Concealing information within media (images, audio, video).    |
| **Network Analysis**                 | Interpreting traffic patterns, credentials, and payloads.      |

***

### II. 🧠 Forensics Workflow Overview

1️⃣ **Identify** file type & anomalies\
2️⃣ **Extract** metadata and hidden content\
3️⃣ **Analyze** traffic, logs, or memory dumps\
4️⃣ **Correlate** patterns or indicators\
5️⃣ **Report** findings or extract flags

***

### III. 🔬 File Analysis & Metadata Extraction

#### 🧩 Identify File Type

```bash
file unknown.bin
binwalk -e unknown.bin
strings unknown.bin | less
```

#### 🧠 Extract Metadata

```bash
exiftool image.jpg
exiftool document.docx
```

**Look for:**

* `Author`, `Software`, `GPS`, `CreateDate`
* Hidden comments in PDFs or images
* Embedded thumbnails or previews

#### 🧩 Hex Analysis

```bash
xxd file.png | head
hexdump -C file.png | grep -A2 "IHDR"
```

***

### IV. 🧩 Image Forensics & Steganography

#### 🧠 Common Tools

| Tool         | Use                                       |
| ------------ | ----------------------------------------- |
| **steghide** | Embed/extract hidden data in JPG/BMP/WAV. |
| **zsteg**    | PNG and BMP stego analysis.               |
| **binwalk**  | Embedded file extraction.                 |
| **strings**  | Plaintext or base64 pattern discovery.    |
| **stegseek** | Bruteforce passwords for steghide files.  |

#### 🧩 Basic Usage

```bash
steghide extract -sf image.jpg
zsteg image.png
```

#### 🧠 Advanced Trick

Hidden data via least significant bits (LSB):

```bash
zsteg -a image.png
```

**CTF Tip:**\
If extraction fails, try wordlist-based cracking:

```bash
stegseek secret.jpg rockyou.txt
```

***

### V. 💾 Archive & Disk Analysis

#### 🧩 Analyze Disk Images

```bash
mount -o loop disk.img /mnt/disk
ls -la /mnt/disk
```

#### 🧠 Search Inside Archives

```bash
7z l archive.7z
7z x archive.7z -pPASSWORD
```

Recover deleted files:

```bash
foremost -i disk.img -o output/
```

Inspect file systems:

```bash
fls -r -m / disk.img
icat disk.img <inode_number>
```

***

### VI. 🌐 Network & PCAP Analysis

#### 🧠 Tools

| Tool                   | Description                                    |
| ---------------------- | ---------------------------------------------- |
| **Wireshark / tshark** | Packet-level analysis                          |
| **NetworkMiner**       | Extract files, creds, and images from captures |
| **tcpflow**            | Reconstruct TCP streams                        |
| **ngrep**              | Search packet payloads                         |
| **strings / base64**   | Extract encoded or embedded data               |

#### 🧩 Analyze HTTP / FTP / DNS

```bash
tshark -r traffic.pcap
tshark -r traffic.pcap -Y "http" -T fields -e http.request.full_uri
```

Extract files:

```bash
tcpflow -r traffic.pcap
```

Find credentials:

```bash
ngrep -q -I traffic.pcap "password"
```

Extract images:

```bash
binwalk -e traffic.pcap
```

***

### VII. 🧠 Memory & Process Analysis

#### 🧩 Volatility Framework

```bash
vol -f memory.raw imageinfo
vol -f memory.raw pslist
vol -f memory.raw netscan
vol -f memory.raw dumpfiles -r "flag"
```

#### 🧠 Analyze Running Processes

```bash
vol -f memory.raw cmdline
vol -f memory.raw malfind
```

Find hidden malware or encoded payloads.

***

### VIII. 🧬 File Encoding & Obfuscation Analysis

#### 🧩 Decode Common Encodings

```bash
echo "ZmxhZ3tzdGVnb30=" | base64 -d
echo "68656c6c6f" | xxd -r -p
```

#### 🧠 Multi-Stage Decoding

If a string looks like gibberish — test recursively:

```bash
cat encoded.txt | base64 -d | gunzip | strings
```

#### 🧩 Common Encodings to Test

| Type   | Example                               |
| ------ | ------------------------------------- |
| Base64 | `ZmxhZw==`                            |
| Hex    | `666c6167`                            |
| ROT13  | `synt`                                |
| URL    | `%66%6C%61%67`                        |
| Binary | `01100110 01101100 01100001 01100111` |

***

### IX. 🕵️ OSINT & Real-World Recon

#### 🧠 1. WHOIS & DNS Enumeration

```bash
whois target.com
dig target.com ANY
nslookup -type=TXT target.com
```

#### 🧩 2. Subdomain Discovery

```bash
assetfinder target.com
subfinder -d target.com
amass enum -d target.com
```

#### 🧠 3. Metadata in Public Files

```bash
wget -r target.com --no-parent
exiftool -r target.com
```

#### 🧩 4. Shodan & Censys

* [https://www.shodan.io](https://www.shodan.io/)
* [https://search.censys.io](https://search.censys.io/)

```bash
shodan search "http.title:login country:US"
```

#### 🧠 5. Reverse Image & Social Trace

* [TinEye](https://tineye.com/)
* [Yandex Image Search](https://yandex.com/images/)
* [Exif.tools](https://exif.tools/)

***

### X. 🧩 Steganography + OSINT CTF Examples

#### 🧠 Example 1: Hidden ZIP Inside PNG

```bash
binwalk -e secret.png
```

#### 🧠 Example 2: GPS Metadata in Photo

```bash
exiftool image.jpg | grep GPS
```

Coordinates → plug into Google Maps.

#### 🧠 Example 3: Encoded Tweet Flag

```bash
echo "U2VjcmV0X0ZsYWc=" | base64 -d
```

***

### XI. ⚙️ Automation Scripts for Forensics

#### 🔹 Metadata Extractor

```bash
#!/bin/bash
for f in *.jpg; do
  exiftool $f | grep "GPS\|Date\|Author"
done
```

#### 🔹 Recursive File Search

```bash
find / -type f -exec grep -i "flag" {} \; 2>/dev/null
```

#### 🔹 Multi-Decode Helper

```bash
#!/bin/bash
for f in $(cat encoded.txt); do
  echo $f | base64 -d 2>/dev/null | xxd -r -p 2>/dev/null | strings;
done
```

***

### XII. 🧠 Pro Tips & CTF Tricks

✅ **General Forensics**

* Always check file headers (`xxd` → magic bytes).
* Recover partial ZIPs with `binwalk -D zip:unzip`.
* Try multiple encodings if text looks scrambled.

✅ **Network Captures**

* Search for credentials or Base64 strings.
* Follow TCP streams manually in Wireshark (Ctrl+Shift+Alt+T).
* Export HTTP objects → `File > Export > HTTP objects`.

✅ **Stego Challenges**

* If `steghide` fails, test with wrong extensions or re-encoded files.
* Check for appended data with `tail -c +100000 image.jpg | strings`.

✅ **OSINT**

*   Search usernames across platforms:

    ```bash
    python3 sherlock.py username
    ```
* Look for EXIF GPS → check Google Street View.
* Reverse-engineer URL shorteners (tinyurl, bit.ly).

***

### XIII. ⚔️ Real-World Forensics Workflow Example

```bash
# 1. Identify the file
file suspect.img

# 2. Extract contents
binwalk -e suspect.img

# 3. Analyze metadata
exiftool extracted/image.jpg

# 4. Decode hidden string
echo "ZmxhZ3tjdGZfc3RlZ29fZ29fZ29fZ30=" | base64 -d

# 5. Find network patterns
tshark -r capture.pcap -Y "http.request"
```

***

### XIV. 🧩 Quick Reference Table

| Category      | Tool                   | Command Example                   |
| ------------- | ---------------------- | --------------------------------- |
| File Analysis | file, strings, binwalk | `binwalk -e sample.bin`           |
| Metadata      | exiftool               | `exiftool image.jpg`              |
| Network       | tshark, ngrep          | `tshark -r traffic.pcap`          |
| Memory        | volatility             | `vol -f mem.raw pslist`           |
| Stego         | steghide, zsteg        | `steghide extract -sf secret.jpg` |
| OSINT         | subfinder, shodan      | `subfinder -d domain.com`         |

***
