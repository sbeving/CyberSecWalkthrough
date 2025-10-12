---
icon: layer-plus
---

# OSINT

## 🕵️‍♂️**The Ultimate Intelligence Gathering Playbook**

> _“The flag is always somewhere on the internet.”_\
> OSINT challenges test your ability to **think like an analyst, pivot like a hacker, and verify like a journalist**.\
> It’s digital detective work — the art of finding connections from public data.

***

### I. 🧠 **Core Mindset**

| Principle                      | Description                                          |
| ------------------------------ | ---------------------------------------------------- |
| **Trace Everything**           | Every username, image, domain, and string is a lead. |
| **Pivot Intelligently**        | One clue → multiple search paths.                    |
| **Correlate Across Platforms** | Data triangulation confirms identities.              |
| **Verify**                     | Trust, but verify sources; screenshots ≠ proof.      |
| **Document Everything**        | Keep evidence logs and timestamps.                   |

***

### II. 🧩 **Typical OSINT CTF Challenge Types**

| Category               | Description                        | Example                               |
| ---------------------- | ---------------------------------- | ------------------------------------- |
| **Username tracking**  | Find user across platforms         | `@0xSbeve` appears on GitHub, Twitter |
| **Image geolocation**  | Find where a photo was taken       | Identify city via buildings or EXIF   |
| **Social graphing**    | Link two online identities         | Cross-reference metadata              |
| **Leak analysis**      | Extract info from pastebin / dumps | Find credentials, email traces        |
| **Domain enumeration** | Analyze DNS, WHOIS, SSL certs      | Find subdomains or tech stack         |
| **File metadata**      | Hidden info in documents/images    | EXIF reveals author, GPS              |
| **Challenge websites** | Hidden robots.txt / comments       | View source, look for base64 hints    |

***

### III. ⚙️ **Core Tools of the OSINT Trade**

| Purpose              | Tool / Platform                                      |
| -------------------- | ---------------------------------------------------- |
| Metadata             | `exiftool`, FotoForensics                            |
| Reverse Image Search | Google, Bing, Yandex, TinEye                         |
| Username Search      | `sherlock`, `maigret`, `whatsmyname`                 |
| Domain Intel         | `whois`, `crt.sh`, `dnsdumpster.com`, `urlscan.io`   |
| IP Info              | `ipinfo.io`, `shodan.io`, `censys.io`, `virustotal`  |
| Social Media         | Twitter Advanced Search, Telegram OSINT bots         |
| Geolocation          | Google Earth, SunCalc, Street View                   |
| File & Paste Dumps   | `pastebin`, `gist`, `ghostbin`, `ahmia`              |
| Historical Data      | `archive.org`, `cachedview`, `urlscan`, `dnsdb.info` |
| Automation           | `theHarvester`, `SpiderFoot`, `Recon-ng`             |
| Visual Analysis      | InVID, SunCalc, EarthCam, ImageMagick                |

***

### IV. 🧭 **Image & Video OSINT**

#### 1️⃣ **Metadata**

```bash
exiftool image.jpg
```

→ Look for `GPSLatitude`, `Make/Model`, `Software`, `DateTimeOriginal`.

#### 2️⃣ **Reverse Search**

* Upload image to **Google**, **Yandex**, or **Bing**.
* Yandex excels at face/building recognition.
* For cropped objects: **Remove background**, search again.

#### 3️⃣ **Geolocation by Clues**

* Signs, license plates, languages, vegetation, architecture.
* Check shadows → **SunCalc.org** for time validation.
* Cross-match skyline in **Google Earth / 3D Maps**.

#### 4️⃣ **Video Clues**

*   Extract frames:

    ```bash
    ffmpeg -i video.mp4 -vf fps=1 frames/out%03d.png
    ```
* Analyze each frame for hidden QR codes or EXIF frames.

***

### V. 🌍 **Domain, IP & Infrastructure OSINT**

| Task           | Tool / Method                                        |
| -------------- | ---------------------------------------------------- |
| WHOIS          | `whois target.com`                                   |
| Subdomains     | `amass enum -d target.com`, `crt.sh/?q=%.target.com` |
| DNS Records    | `dig any target.com`                                 |
| SSL/TLS        | `sslscan target.com`, `crt.sh`                       |
| IP Scanning    | `shodan.io/host/<IP>`                                |
| CDN / Hosting  | `bgpview.io`, `ipinfo.io`                            |
| Historical DNS | `securitytrails.com`, `viewdns.info`                 |

🧠 _Combine WHOIS + SSL cert + subdomain leaks = target fingerprint._

***

### VI. 🕵️‍♂️ **Username & Identity Tracing**

| Tool                | Description                                     |
| ------------------- | ----------------------------------------------- |
| **Sherlock**        | Searches usernames across hundreds of platforms |
| **Maigret**         | Similar but with more metadata correlation      |
| **whatsmyname.app** | Web-based, fast pattern matcher                 |
| **namechk.com**     | Quick online check                              |

#### Example:

```bash
sherlock saleh_eddine_touil
```

→ Results on GitHub, Reddit, Instagram, etc.

Cross-validate with:

* Avatar reuse
* Bio patterns
* Domain links in profile
* Timezones or language used

***

### VII. 📦 **File & Document Analysis**

| Filetype               | Key Check                                |
| ---------------------- | ---------------------------------------- |
| **DOCX / PPTX / XLSX** | `unzip` → inspect `/docProps/core.xml`   |
| **PDF**                | `pdfinfo`, `strings`, look for `/Author` |
| **Images**             | `exiftool`, hidden EXIF comment          |
| **Archives**           | `7z l file.zip`, check comments          |
| **Text Dumps**         | Leaked credentials, encoded strings      |

🧠 _Search for patterns like `flag{`, `base64`, or URLs._

***

### VIII. 🔍 **Social Media Intelligence**

| Platform           | Tip                                                                            |
| ------------------ | ------------------------------------------------------------------------------ |
| **Twitter/X**      | `from:username since:YYYY-MM-DD until:YYYY-MM-DD`, or reverse lookup via Twint |
| **Instagram**      | Check story highlights, tagged photos                                          |
| **LinkedIn**       | Company staff enumeration                                                      |
| **Reddit**         | Search comments via `pushshift.io`                                             |
| **Telegram**       | `t.me/s/<channel>` for open messages                                           |
| **TikTok/YouTube** | Extract metadata with `yt-dlp --write-info-json`                               |

***

### IX. 🛰️ **Geolocation & Satellite OSINT**

| Task                    | Tool                                         |
| ----------------------- | -------------------------------------------- |
| GPS to Map              | `https://www.gpsvisualizer.com/`             |
| Shadow/time estimation  | `SunCalc.org`                                |
| Satellite imagery       | `Google Earth`, `Zoom Earth`, `Sentinel Hub` |
| Landmark identification | `peakvisor.com`, `wikimapia.org`             |

💡 _Even tiny clues like power outlets or cars can reveal region._

***

### X. 🧩 **Data Correlation & Pivoting**

1️⃣ Start with a handle → find linked emails or domains.\
2️⃣ Search that email in **leak databases** or **Gravatar MD5 hashes**.\
3️⃣ Pivot to IP → Shodan → hosting organization.\
4️⃣ Find past archive snapshots of target domain → extract names.\
5️⃣ Map all to a **timeline graph** (e.g., Maltego, SpiderFoot).

***

### XI. 🧰 **Automation Frameworks**

| Framework         | Use                               |
| ----------------- | --------------------------------- |
| **SpiderFoot HX** | All-in-one recon automation       |
| **Recon-ng**      | CLI-based modular OSINT framework |
| **Maltego CE**    | Visual link analysis              |
| **theHarvester**  | Email & subdomain enumeration     |
| **DataSploit**    | Python-based correlation          |

***

### XII. 🧠 **MISC OSINT Tricks in CTFs**

| Scenario           | Tactic                                            |
| ------------------ | ------------------------------------------------- |
| Unknown binary     | `strings` → find URL → check via Wayback          |
| QR code in image   | Crop → `zbarimg file.png`                         |
| PDF challenge      | Hidden layer or comment field                     |
| Twitter clue       | Reverse-search avatar → find cross-linked account |
| GPS decimals off   | Try ±0.001 variation                              |
| Website references | Inspect comments / JS vars for base64 strings     |

***

### XIII. ⚖️ **Ethics & Legality**

* **Only collect data that’s publicly accessible.**
* **Never bypass authentication or privacy controls.**
* **Respect ToS of all platforms.**
* **Attribute findings correctly.**
* OSINT ≠ hacking — it’s analysis of open data.

***

### XIV. 🧠 **CTF OSINT Workflow**

```
1️⃣ Identify the clue (image, username, domain)
2️⃣ Gather metadata / reverse search
3️⃣ Enumerate linked accounts or domains
4️⃣ Correlate data → pivot across platforms
5️⃣ Verify timeline & context
6️⃣ Derive coordinates / email / key / flag{...}
```

***

### XV. ⚡ **Quick Reference: OSINT Toolkit**

| Category     | Tools                                  |
| ------------ | -------------------------------------- |
| Image        | exiftool, Google Lens, Yandex, SunCalc |
| Domain       | whois, amass, crt.sh, securitytrails   |
| Identity     | sherlock, maigret, holehe              |
| Metadata     | exiftool, pdfinfo, zipinfo             |
| Automation   | SpiderFoot, Recon-ng, theHarvester     |
| Verification | archive.org, cachedview, urlscan.io    |

***
