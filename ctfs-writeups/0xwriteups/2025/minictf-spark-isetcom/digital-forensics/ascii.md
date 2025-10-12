# ASCII

### Description

This should be easy!!!

`A lil note : Len(Frame)`

> **Author : sn0\_0wyy**

### Files

* ASCII.pcap

**Solution:** Extract frame lengths and convert to ASCII:

```python
import subprocess

result = subprocess.run(
    ['tshark', '-r', 'ASCII.pcap', '-T', 'fields', '-e', 'frame.len'],
    capture_output=True, text=True
)

frame_lengths = result.stdout.strip().split('\n')

flag = ""
for length in frame_lengths:
    if length:
        flag += chr(int(length))

print(flag)  # Spark{4nOTh3R_Annoy1N9_3Xf1l}
```

***
