# Custom

## Custom

### Description

i was chilling then i created this encryption but i dont know how to decrypt it but

You can do it right ?

> Author : Z3U55

### Files

* custom.py
* cipher.txt

#### Custom

**Flag:** `Spark{3v3n_m4tr1x_c4n_3ncrypt}`

**Description:** Custom matrix-based cipher where elements are swapped.

**Solution:** The encryption swaps columns in a 4-column matrix:

* Columns 0 and 3 swap
* Columns 1 and 2 swap

To decrypt, we simply reverse the swapping:

```python
import numpy as np

cipher = "114,97,112,83,118,51,123,107,109,95,110,51,49,114,116,52,52,99,95,120,110,51,95,110,112,121,114,99,32,32,125,116,"
ascii_values = [int(x) for x in cipher.split(',') if x]

rows = len(ascii_values) // 4
m = np.array(ascii_values).reshape(rows, 4)

# Reverse the swapping
for row in m:
    row[0], row[3] = row[3], row[0]
    row[1], row[2] = row[2], row[1]

flag = ""
for i in range(rows):
    for j in range(4):
        flag += chr(m[i, j])

print(flag)  # Spark{3v3n_m4tr1x_c4n_3ncrypt}
```

***
