---
description: Here you'll find different Cryptography tasks solved step-by-step
---

# 🌋 Cryptography

### Stupid X | |

<figure><img src="../../../../.gitbook/assets/image (29).png" alt=""><figcaption><p>Xor</p></figcaption></figure>

Stupid Xor having this code within enc.py

```python
flag="REDACTED"
st1,st2,st3=flag[:7],flag[7:16],flag[16:]
key1,key2,key3="easypee","asylemon","squeeezy"
def xor(s1,s2):    
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))
print(xor(st1,key1))
print(xor(st2,key2))
print(xor(st3,key3))
''' Output:
6
Q&]]
*U
'''
```

Using the output as the three Inputs will display our flag&#x20;

```python
print(xor("6",key1))
print(xor("Q&]]",key2))
print(xor("*U",key3))
```

& BOOM&#x20;

> Spark{y0u\_br0k3my\_x0r}

### DIC for Dictionary

<figure><img src="../../../../.gitbook/assets/image (58).png" alt=""><figcaption></figcaption></figure>

enc.py contains this code&#x20;

```python
from collections import OrderedDict

flag="Spark{Just_Some_Stupid_Text}"

dic={'a':'Z','b':'X','c':'Y',
 'd':'W','e':'V','f':'U','g':'T',
 'h':'S','i':'R','j':'Q','k':'P',
 'l':'O','m':'N','n':'M','o':'L',
 'p':'K','q':'J','r':'I','s':'H',
 't':'G','u':'F','v':'E','w':'D',
 'x':'C','y':'B','z':'A','_' : '@',
 '{' : 'ç','}' : 'è','A':'z', 'B':'x',
 'C':'y','D':'w','E':'v','F':'u','G':'t',
 'H':'s','I':'r','J':'q','K':'p','L':'o',
 'M':'n','N':'m','O':'l','P':'k','Q':'j',
 'R':'i','S':'h','T':'g','U':'f','V':'e',
 'W':'d','X':'c','Y':'b','Z':'a'}
cipher=""
for i in flag:
    val = str(dic.get(i))
    cipher+=str(val)
print(cipher)
#output :hKZIPçyFHGLN@WRYGRLMZIB@RH@HGFKRWè
```

This code takes each char of the flag and replaces it according to the dictionary given.

So we had to reverse the process since we used `dic.get(key name)` to get the value,We're going to use the value to get the key name.

```python
flag="hKZIPçyFHGLN@WRYGRLMZIB@RH@HGFKRWè"
dic={.....}
keys = []
for i in flag:
    keys += [k for k, v in dic.items() if v == i]
for i in keys:
    print(i,end="")
# output : Spark{Custom_dictionary_is_stupid} 
```

### BOUZOU SHUFFLE

<figure><img src="../../../../.gitbook/assets/image (76).png" alt=""><figcaption></figcaption></figure>

**task.py** :&#x20;

```python
import random
seed = 0x19195278
random.seed(seed)

def pad(char):
a = str(bin(char))[2:]
return ("0b" + "0"* (8 - len(a)) + a)

def shuffle(l):
random.shuffle(l)
return l

def encrypt(m):
encs = [pad(char) for char in m]
_ = [random.shuffle(encs) for i in range(69)]
return encs

enc =encrypt(Flag)
print(enc)

"""
OUTPUT:['0b01100011', '0b00110100', '0b01100001', '0b01100011', '0b01101011', '0b01010011', '0b01111101', '0b00110010', '0b01110010', '0b00110001', '0b00110001', '0b00110010', '0b01100100', '0b00110000', '0b01100001', '0b01100011', '0b01111011', '0b00110111', '0b01110000', '0b00110110', '0b01100101', '0b01100010', '0b00110011', '0b00110101', '0b01100110', '0b01100110', '0b01100101', '0b01100001', '0b00110010', '0b01100100', '0b01100001', '0b00110010', '0b00110011', '0b00110001', '0b01100100', '0b01100101', '0b01100101', '0b01100100', '0b00110111']
"""
```

Now we need to reverse this&#x20;

1. **Get the length**: We determine the flag length from the number of encrypted binary values.
2. **Simulate shuffling:** We create original\_order and shuffle it the same way as the encryption function, giving us the shuffled-to-original index mapping.
3. **Decrypt:** We iterate through the original\_order, placing each encrypted character at its correct position in the flag list using the shuffled-to-original mapping.
4. **Join and print**: We combine the characters in the flag list to get the complete flag.

```python
import random

seed = 0x19195278
random.seed(seed)

enc = ['0b01100011', '0b00110100', '0b01100001', '0b01100011', '0b01101011', '0b01010011', '0b01111101', '0b00110010', '0b01110010', '0b00110001', '0b00110001', '0b00110010', '0b01100100', '0b00110000', '0b01100001', '0b01100011', '0b01111011', '0b00110111', '0b01110000', '0b00110110', '0b01100101', '0b01100010', '0b00110011', '0b00110101', '0b01100110', '0b01100110', '0b01100101', '0b01100001', '0b00110010', '0b01100100', '0b01100001', '0b00110010', '0b00110011', '0b00110001', '0b01100100', '0b01100101', '0b01100101', '0b01100100', '0b00110111']

# Determine the length of the flag 
flag_length = len(enc)

# Create a list of indices representing the original order
original_order = list(range(flag_length))

# Shuffle the original_order list 69 times, just like in the encrypt function
for _ in range(69):
    random.shuffle(original_order)

# Now, original_order contains the mapping of shuffled indices to original indices.

# Create a list to store the decrypted flag
flag = [''] * flag_length

# Decrypt by putting the shuffled characters back in their original positions
for i in range(flag_length):
    flag[original_order[i]] = chr(int(enc[i], 2)) 

print("The flag is:", ''.join(flag))

# Spark{edbcd7d2cc1ee132fe01f2d267aa5a34}
```



