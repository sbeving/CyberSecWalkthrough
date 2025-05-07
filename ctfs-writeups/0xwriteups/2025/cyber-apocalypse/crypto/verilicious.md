# Verilicious



```python
# Sagemath is needed
from Crypto.Util.number import long_to_bytes
from output import R

def hnp_solver(rs, ts, n, k_low_bound, k_high_bound):
    # given ki - ri*m ≡ ti mod n, for small k, solves m
    l = len(rs)
    k_avg = (k_low_bound + k_high_bound)//2
    M = (
        diagonal_matrix(QQ, [n]*l)
        .stack(vector(rs))
        .stack(vector([t-k_avg for t in ts]))
        .augment(vector([0]*l + [1/n, 0]))
        .augment(vector([0]*l + [0,   1]))
    )
    W = diagonal_matrix([1]*l + [k_avg, k_avg])
    print('LLL...')
    M = (M*W).dense_matrix().LLL()/W
    print('done')
    for row in M:
        for row in [-row, row]:
            if row[-1] != 1:
                continue
            yield (row[-2]*n) % n

n = 0xD6995EC957DC3213D8B2DD404E38A951744954C2CFB4242CA6A0A240949EC6A09451A5101A6AAB0C0B7E303A0738A67225C78E10C111AEDA57582EA6F42F07952CB46FA29A540CC5052E3A0AC91A1A9B465F1998B91E3907BE29A2FD38268B8788DF6FB0D2C88B340DFEAC8163E25B500A67D7B4831F26DED81D544E74428D2B
B = 2**(1024-16)
for m in hnp_solver(rs=R, ts=[-2*B for _ in range(len(R))], n=n, k_low_bound=0, k_high_bound=B):
    flag = long_to_bytes(int(m))
    if b'HTB' in flag:
        print(flag)
```



## &#x20;

<figure><img src="../../../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>
