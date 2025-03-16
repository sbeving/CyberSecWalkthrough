# 🦈 Wire The Shark

### The Wireshark Grimoire: Unleash the Power of Network Analysis

Wireshark. The name itself evokes images of diving deep into the digital ocean, dissecting packets, and uncovering hidden currents of data. This isn't just a manual; it's a grimoire, a comprehensive guide to unlocking the full potential of Wireshark, transforming you from a mere packet observer into a true network sorcerer.

**I. Core Concepts: The Language of the Wire**

* **Packet:** The fundamental unit of network communication, like a word in the network's language.
* **Protocol:** The grammar of the network, dictating how devices communicate (TCP, UDP, HTTP, DNS – each a dialect).
* **Frame:** The vessel carrying the packet, including link-layer headers.
* **Capture Filter (BPF):** A precise tool to select only the traffic you need, like a targeted fishing net.
* **Display Filter:** A magnifying glass to examine specific packets within your capture, like highlighting keywords in a text.
* **Protocol Hierarchy:** The family tree of network protocols, showing how they relate.

**II. Capturing Traffic: Setting the Stage**

1. **Interface Selection:** Choosing your capture point:
   * Graphical Interface: Select the interface (eth0, wlan0, any) from the Wireshark interface list.
   * Tshark (CLI): `tshark -i eth0`
2. **Capture Filters (BPF):** Precision is key:
   * Basic: `tcp port 80` (HTTP), `udp port 53` (DNS), `host 192.168.1.100`
   * Combining: `tcp port 80 && ip.src == 10.0.0.1`
   * Negation: `not ip.dst == 192.168.1.1`
   * Port Ranges: `port >= 80 && port <= 100`
   * Protocol Specific: `http.request.method == "POST"`
3. **Capture Options:** Fine-tuning the net:
   * Promiscuous Mode: Capture _all_ traffic (use with care, can be overwhelming).
   * Capture File: `tshark -w capture.pcap -i eth0` (for later analysis).
   * Ring Buffer: Capture continuously, overwriting old data.
   * Snaplen: Limit packet size to save space (be mindful of truncated data).
4. **Starting and Stopping:**
   * GUI: Click the shark fin to start, the red square to stop.
   * Tshark: `tshark -i eth0` (Ctrl+C to stop).

**III. Analyzing Packets: Deciphering the Message**

1. **Packet List Pane:** The timeline of your capture:
   * Time: When the packet arrived.
   * Source/Destination: Who's talking to whom.
   * Protocol: The language they're using.
   * Length: Size of the packet.
   * Info: A brief summary.
2. **Packet Details Pane:** The anatomy of a packet:
   * Expandable Protocol Layers: Dive deep into each layer (Frame, Ethernet, IP, TCP, Application).
   * Hex Value Pane: The raw bytes, for the truly curious.
3. **Packet Bytes Pane:** The raw data, byte by byte.

**IV. Display Filters: The Magnifying Glass**

4. **Basic Filters:**
   * Protocol: `http`, `dns`, `icmp`, `ssh`
   * IP Address: `ip.src == 192.168.1.1`, `ip.dst == 10.0.0.1/24`
   * Port: `tcp.port == 80`, `udp.port == 53`
5. **Combining Filters (Boolean Logic):**
   * AND: `http && ip.dst == 10.0.0.1`
   * OR: `tcp.port == 80 || udp.port == 53`
   * NOT: `!ip.src == 192.168.1.1`
6. **Protocol-Specific Filters:**
   * HTTP: `http.request.method == "POST"`, `http.host contains "example.com"`, `http.response.code == 404`
   * DNS: `dns.qry.name contains "ctf.com"`, `dns.resp.type == "A"`
   * TCP: `tcp.flags.syn == 1`, `tcp.flags.ack == 1`
   * IP: `ip.ttl < 10` (traceroute-like analysis)
7. **String Matching:**
   * `contains "flag"` (case-insensitive)
   * `matches "FLAG.*"` (regex)
8. **Field Value Comparison:**
   * `frame.len > 1000`
   * `tcp.seq == 0`
9. **Following TCP Stream:** Right-click a TCP packet -> Follow -> TCP Stream. See the entire conversation.

**V. Advanced Techniques: Mastering the Art**

10. **Statistics:**
    * Protocol Hierarchy: See protocol usage.
    * Endpoints: List communicating hosts.
    * Conversations: Track flows between hosts.
    * Capture File Properties: Get file size, capture duration, etc.
11. **Expert Info:** Wireshark's analysis of potential problems (retransmissions, errors).
12. **Tshark (Command-Line Wireshark):**
    * Capture: `tshark -w capture.pcap -i eth0`
    * Analyze: `tshark -r capture.pcap -Y "http" -T fields -e http.host` (extract HTTP hostnames)
    * Convert: `tshark -r capture.pcap -w capture.csv -T fields -e frame.number -e eth.src -e eth.dst`
13. **Lua Plugins:** Extend Wireshark's capabilities with custom scripts.
14. **Reassembly:** Put fragmented packets back together.

**VI. CTF Use Cases: The Network Detective**

15. **Hidden Flags:** Search for strings, decode base64, follow streams.
16. **Protocol Analysis:** Identify vulnerabilities in specific protocols.
17. **Credential Hunting:** Look for unencrypted credentials (HTTP, FTP, etc.).
18. **Malware Analysis:** Analyze C2 communication, identify file downloads.
19. **Forensics:** Reconstruct events, track network activity.
20. **Network Attacks:** Detect port scans, denial-of-service attempts.

**VII. Filters – A Deeper Dive:**

* **Display Filter Syntax:** Case-insensitive, uses field names (e.g., `ip.src`, `tcp.port`).
* **Capture Filter Syntax (BPF):** More limited, uses different syntax (e.g., `src host 192.168.1.1`).
* **Filter Macros:** Save and reuse your filters.

**VIII. Tshark Mastery:**

* `-r`: Read capture file.
* `-w`: Write capture file.
* `-i`: Interface.
* `-Y`: Display filter.
* `-T`: Output format (fields, pdml, etc.).
* `-e`: Fields to print.
* `-q`: Quiet mode.

**IX. Wireshark's Secrets:**

* Coloring Rules: Highlight interesting packets.
* Bookmarks: Mark important packets.
* Comments: Add notes to packets.
* Time Display Format: Choose how time is shown.

**X. Practice Makes Perfect:**

* Capture and analyze your own network traffic.
* Work through CTF challenges that involve network analysis.
* Explore online resources and tutorials.
