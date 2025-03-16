---
description: 'Poetry is a lovely thing  author: cybereagle2001'
---

# POEM

### Given Text File

```
Poetry is a lovely thing,
back in the early days 
peoples used to share data
through poems is it the case?

Silent Trails Echo Gentle Air,
Night’s Owls In Moonlight Sing.
Over Waves, Serenity Awaits,
In Dreams, A Mind Ascends.
Zephyr Invites New Growth.
Amidst Zealous Inspirations,
Never-ending Gratitude.
```

### Solver

<pre class="language-python"><code class="lang-python"><strong>import re
</strong>
def extract_majuscule(file_path):
    with open(file_path, 'r') as file:
        text = file.read()
        majuscule = re.findall(r'\b[A-Z]*', text)
        majuscule = [m for m in majuscule if m]
        majuscule = ''.join(majuscule)
        return "".join("Securinets{")+majuscule+"}"

print(extract_majuscule('poem.txt'))
</code></pre>



```powershell
PS C:\Users\saleh\Downloads\CTFKareemSecurinetsTekup\poem> python.exe .\solver.py
Securinets{PSTEGANOIMSOWSAIDAMAZINGAZING}
```

Needs cleaning ---> STEGANO IS AMAZING

`Securinets{STEGANOISAMAZING}`\
\
