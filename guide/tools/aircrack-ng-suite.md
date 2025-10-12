---
icon: wifi
---

# Aircrack-ng Suite

## The Aircrack-ng Suite Masterclass: Professional Wi-Fi Security Auditing

The Aircrack-ng suite is the gold standard for wireless network auditing, penetration testing, and security analysis. It integrates powerful tools—airmon-ng, airodump-ng, aireplay-ng, aircrack-ng, airbase-ng, airgraph-ng, airdecap-ng, and more—each responsible for a distinct step in wireless reconnaissance, attack, and analysis.

***

### I. Core Capabilities Overview

| Tool        | Purpose                                                           |
| ----------- | ----------------------------------------------------------------- |
| airmon-ng   | Enables/controls monitor mode on wireless cards                   |
| airodump-ng | Captures raw 802.11 frames, lists networks/clients, saves packets |
| aireplay-ng | Injects traffic, replays packets for handshake/jamming/DoS        |
| aircrack-ng | Cracks WEP/WPA/WPA2-PSK using captured packets and wordlists      |
| airbase-ng  | Creates rogue APs/evil twins for MITM and client attacks          |
| airgraph-ng | Visualizes network relationships (graphing) from capture files    |
| airdecap-ng | Decrypts captured encrypted packets (WEP/WPA/WPA2)                |

***

### II. Professional Usage and Workflow Examples

#### 1. airmon-ng: Enable Monitor Mode

```bash
sudo airmon-ng start wlan0
```

* Lists interfaces and sets wlan0 to monitor mode for packet capture.\[1]\[2]\[3]

#### 2. airodump-ng: Recon and Packet Capture

```bash
sudo airodump-ng wlan0mon
```

* Displays SSIDs, BSSIDs, channels, encryption, client MACs, and saves .cap files for later analysis.\[4]\[5]\[1]
* Focus on specific AP/channel:

```bash
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF --channel 6 --write data wlan0mon
```

#### 3. aireplay-ng: Packet Injection and Attacks

```bash
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mo
```

* Sends 10 deauth packets to the target AP, forcing clients to reconnect for handshake capture.\[2]\[1]
* ARP replay, fragmentation, and fake authentication also available for WEP attacks.

#### 4. aircrack-ng: Handshake and Key Cracking

```bash
aircrack-ng -w /path/to/wordlist.txt -b AA:BB:CC:DD:EE:FF data.cap
```

* Cracks captured WEP/WPA/WPA2 handshakes using a provided wordlist.\[3]\[6]\[1]\[2]
* Supports dictionary, brute force, and custom rule sets.

#### 5. airbase-ng: Rogue AP/Evil Twin Attack

```bash
sudo airbase-ng -e "FakeWifi" -c 6 mon0
```

* Sets up a rogue AP for MITM, credential harvesting, captive portal exploits.\[7]\[1]\[2]

#### 6. airdecap-ng: Decrypt Captured Traffic

```bash
airdecap-ng -w KEY data.cap
```

* Decrypts .cap files post-crack to examine HTTP, telnet, or other unencrypted inner traffic.\[2]\[7]

#### 7. airgraph-ng: Visualize and Map Networks

```bash
airgraph-ng -i data.csv -o netgraph.png -g CAPR
```

* Processes CSV output from airodump-ng into network graphs mapping clients, APs, relationships.\[8]\[9]\[10]

***

### III. Advanced Techniques & Scenarios

* **Focused Recon:** Use channel/AP-specific filtering in airodump-ng/aireplay-ng to reduce noise and focus attacks on high-value targets.\[11]\[4]
* **Multi-Adapter Attacks:** Simultaneously capture and inject with different interfaces; increases reliability in dense environments.
* **Automated Workflows:** Script or chain all tools for hands-off assessments (monitor, recon, handshake capture, cracking, reporting).
* **Client-Side Attacks:** Leverage airbase-ng/aireplay-ng for evil twin traps, phishing portals, or forced authentication.\[2]
* **Graphing & Visualization:** Use airgraph-ng to map vulnerable clients and visualize relationships for reporting.\[8]
* **Decap & Forensics:** Post-crack analysis of traffic using airdecap-ng and Wireshark for sensitive data exposure auditing.\[7]
* **Jamming & DoS Testing:** aireplay-ng’s deauth/fakeauth for controlled denial-of-service and resilience metric testing.\[1]
* **Hybrid Integration:** Combine suite output with Kismet, Wireshark, or external scripting for extended analysis and evidence.

***

### IV. Real-World Workflow Example

1. **Enable Monitor Mode**

```bash
airmon-ng start wlan0
```

1. **Recon + Capture Handshake**

```bash
airodump-ng --bssid AA:BB:CC:DD:EE:FF --channel 11 --write handshake wlan0mon
```

1. **Deauthenticate for Forced Handshake**

```bash
aireplay-ng --deauth 25 -a AA:BB:CC:DD:EE:FF wlan0mon
```

1. **Crack Key**

```bash
aircrack-ng -w wordlist.txt -b AA:BB:CC:DD:EE:FF handshake.cap
```

1. **Decrypt and Analyze Traffic**

```bash
airdecap-ng -w crackedkey handshake.cap
wireshark handshake-dec.cap
```

1. **Graph Relationships**

```bash
airgraph-ng -i handshake.csv -o wifi-graph.png -g CAPR
```

***

### V. Pro Tips & Best Practices

* Use high-perf adapters supporting monitor/injection.
* Set precise channels and filter clients for focused attacks.
* Always export relevant PCAP/CSV for evidence and reporting.
* Combine cracked traffic with Wireshark for sensitive data auditing.
* Respect legal boundaries—only audit networks with explicit authorization.
* Regularly update suite and drivers for protocol/EAP compatibility.
* Automate repetitive tasks with bash/scripts; use graphs for client reporting.

***

This guide arms wireless security professionals with the full power of the Aircrack-ng suite, allowing for rapid, accurate, and deep wireless penetration testing from network discovery to reporting and post-exploitation.\[5]\[6]\[10]\[3]\[4]\[1]\[8]\[2]

Sources \[1] How to Use Aircrack-ng: A Guide to Network Compromise [https://www.stationx.net/how-to-use-aircrack-ng-tutorial/](https://www.stationx.net/how-to-use-aircrack-ng-tutorial/) \[2] Aircrack-ng - addielamarr [https://publish.obsidian.md/addielamarr/Aircrack-ng](https://publish.obsidian.md/addielamarr/Aircrack-ng) \[3] Mastering Wireless Security: A Deep Dive into Aircrack-ng ... [https://securewithsiva.in/post/08-aircrack-ng/](https://securewithsiva.in/post/08-aircrack-ng/) \[4] Airodump-ng for Beginners: Scanning and Monitoring Wi-Fi ... [https://dev.to/rijultp/airodump-ng-for-beginners-scanning-and-monitoring-wi-fi-networks-377d](https://dev.to/rijultp/airodump-ng-for-beginners-scanning-and-monitoring-wi-fi-networks-377d) \[5] Airodump-ng [https://www.aircrack-ng.org/doku.php?id=airodump-ng](https://www.aircrack-ng.org/doku.php?id=airodump-ng) \[6] Utilizing Aircrack-Ng in Termux: Comprehensive Guide for ... [https://dev.to/terminaltools/utilizing-aircrack-ng-in-termux-comprehensive-guide-for-wi-fi-network-security-l8h](https://dev.to/terminaltools/utilizing-aircrack-ng-in-termux-comprehensive-guide-for-wi-fi-network-security-l8h) \[7] Main documentation [https://www.aircrack-ng.org/documentation.html](https://www.aircrack-ng.org/documentation.html) \[8] Visualize WiFi Relationships with AirGraph-ng | HakByte [https://www.youtube.com/watch?v=wvRdeFGuHMc](https://www.youtube.com/watch?v=wvRdeFGuHMc) \[9] Signal Intelligence with a Raspberry Pi and AirGraph-NG ... [https://www.instagram.com/p/C-yiqA0ANxU/](https://www.instagram.com/p/C-yiqA0ANxU/) \[10] airgraph-ng \[Aircrack-ng] [https://www.aircrack-ng.org/doku.php?id=airgraph-ng](https://www.aircrack-ng.org/doku.php?id=airgraph-ng) \[11] Advanced WiFi Scanning with Aircrack-NG [https://www.youtube.com/watch?v=uKZb3D-PHS0](https://www.youtube.com/watch?v=uKZb3D-PHS0)
