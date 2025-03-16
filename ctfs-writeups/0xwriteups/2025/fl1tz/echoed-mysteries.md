# Echoed Mysteries

Given a **Chall.pcapng** file with Echoed Mysteries as task name

ICMP For Sure

<figure><img src="../../../../.gitbook/assets/Pasted image 20250212154808.png" alt=""><figcaption></figcaption></figure>

Its obvious that the flag is being sent as a single letter in replies

In 43 length packets

```python
from scapy.all import * # pip install scapy
import re # pip install regex
import sys  # Import the sys module

def extract_from_pcap(pcap_file, target_ip):
    """
    Extracts hidden data from ICMP packets in a PCAP file.
    Args:
        pcap_file: The path to the PCAP file.
        target_ip: The IP address of the source of the packets we care about.
    Returns:
        The reassembled flag, or None if no flag is found.
    """
    extracted_letters = []
    def packet_callback(packet):
        nonlocal extracted_letters
        alphabet = [

            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        '{','}','_'
        ]
        if ICMP in packet and packet[ICMP].type == 0 and packet[IP].src == target_ip:  # ICMP Echo Reply (type 0)
            try:
                payload = packet[Raw].load.decode('latin-1', 'ignore')
                #  Added check for alpha characters / numerical
                if len(payload) > 0 and payload.strip() in alphabet:
                    extracted_letters.append(payload)
                    print(f"Extracted letter: {payload}") # debug
            except UnicodeDecodeError as e:
                print(f"UnicodeDecodeError: {e}")
            except AttributeError as e:
                print(f"AttributeError: No Raw layer in packet. {e}")
            except Exception as e:
                print(f"Some error {e}")
    print(f"Reading packets from PCAP file: {pcap_file}")
    try:
      packets = rdpcap(pcap_file)  # Read the PCAP file
    except FileNotFoundError:
      print(f"Error: PCAP file '{pcap_file}' not found.")
      return None

    for packet in packets:
        packet_callback(packet)

    reassembled_flag = "".join(extracted_letters)
    if reassembled_flag:
        print(f"Reassembled Flag: {reassembled_flag}")
        return reassembled_flag
    else:
        print("No flag extracted.")
        return None
  
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python icmp.py <pcap_file> <target_ip>")
        sys.exit(1)

    pcap_file = sys.argv[1]  # Get PCAP file from command line
    target_ip = sys.argv[2]  # Get target IP from command line
  
    flag = extract_from_pcap(pcap_file, target_ip)
    if flag:
        print(f"Extracted Flag: {flag}")
    else:
        print("Failed to extract the flag.")
```

And the result is

```powershell
PS C:\Users\saleh\Desktop\CTFs\FL1TZ\Forensics\Echoed Mysteries> python .\solve.py .\Chall.pcapng 192.168.1.19
Reading packets from PCAP file: .\Chall.pcapng
Extracted letter: F
Extracted letter: L
Extracted letter: 1
Extracted letter: T
Extracted letter: Z
Extracted letter: {
Extracted letter: H
Extracted letter: 1
Extracted letter: D
Extracted letter: D
Extracted letter: 3
Extracted letter: N
Extracted letter: _
Extracted letter: 1
Extracted letter: N
Extracted letter: _
Extracted letter: 1
Extracted letter: C
Extracted letter: M
Extracted letter: P
Extracted letter: _
Extracted letter: P
Extracted letter: 4
Extracted letter: C
Extracted letter: K
Extracted letter: 3
Extracted letter: 7
Extracted letter: S
Extracted letter: }
Reassembled Flag: FL1TZ{H1DD3N_1N_1CMP_P4CK37S}
Extracted Flag: FL1TZ{H1DD3N_1N_1CMP_P4CK37S}
```

#### Source Code of Task

```python
from scapy.all import *
import time

target_ip = "192.168.1.18"
flag = "FL1TZ{H1DD3N_1N_1CMP_P4CK37S!!!}"
fake_flag = ""

def packet_reply(letter, target_ip):
    packet = IP(dst=target_ip) / ICMP(type="echo-reply", id=1234, seq=1) / letter
    send(packet)

def packet_request(target_ip):
    packet = IP(dst=target_ip) / ICMP(type="echo-request", id=1234, seq=1)
    send(packet)

  

def send_packets(target_ip) :
    for letter in flag:
            packet_request(target_ip)
            print(f"SENT ICMP REQUEST PACKET")
            time.sleep(1)
            packet_reply(letter, target_ip)
            print(f"SENT ICMP REPLY PACKET WITH LETTER: {letter}")
            time.sleep(2)

  

send_packets(target_ip)
```
