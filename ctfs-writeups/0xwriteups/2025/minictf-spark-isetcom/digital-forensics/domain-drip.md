# Domain Drip

### Description

Someone in the network is whispering secrets.

Can you find it?

> **Author: Z10UD1**

### Files

* domain.pcapng

**Flag:** `Spark{s0m30n3_st4rt3d_t0_und3rst4nd_th1s}`

**Description:** DNS exfiltration via subdomain queries.

**Solution:** Extract DNS queries to spark.com subdomains, which are Base64-encoded:

```python
import subprocess
import base64

result = subprocess.run(
    ['tshark', '-r', 'domain.pcapng', '-Y', 'dns.qry.name contains "spark.com"', 
     '-T', 'fields', '-e', 'dns.qry.name', '-e', 'frame.number'],
    capture_output=True, text=True
)

queries = []
seen = set()
for line in result.stdout.strip().split('\n'):
    if line and '\t' in line:
        query, frame = line.split('\t')
        subdomain = query.split('.')[0]
        if subdomain != 'end' and subdomain not in seen:
            queries.append((int(frame), subdomain))
            seen.add(subdomain)

queries.sort(key=lambda x: x[0])

b64_string = ''.join([q[1] for q in queries])
decoded = base64.b64decode(b64_string).decode()
print(decoded)  # Spark{s0m30n3_st4rt3d_t0_und3rst4nd_th1s}
```

***
