# Time's Whisper

## Solver

```python

from scapy.all import *
import sys

Load the pcap file (or sniff packets live)
pcap_file = "Capture.pcapng"  # Change this to your actual file
packets = rdpcap(pcap_file)


bit_stream = ""

# Extract last 2 bits from TTL values of ICMP packets
for packet in packets:
    if packet.haslayer(ICMP):
        if packet[ICMP].type == 8:  # Filter ICMP Echo Request packets
            ttl = packet[IP].ttl
            last_two_bits = bin(ttl)[-2:]  # Get last two bits
            bit_stream += last_two_bits

Convert binary stream to readable text
byte_data = [int(bit_stream[i:i+8], 2) for i in range(0, len(bit_stream), 8)]
decoded_message = ''.join(map(chr, byte_data))
print(decoded_message)


# FL1TZ{P1NG_P0NG_W1TH_1CMP!}
```
