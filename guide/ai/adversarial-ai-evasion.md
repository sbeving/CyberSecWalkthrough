---
icon: ufo
---

# Adversarial AI Evasion

## ⚔️ **Adversarial AI Evasion — Image & Text Perturbation Challenges for CTFs**

> _“If you can’t break the model, teach the input to lie.”_
>
> This guide dives deep into **adversarial evasion**, one of the most fun and puzzling areas in AI-themed CTFs.\
> You’ll learn how competitors craft, detect, and defend against subtle input perturbations that fool AI models — ethically and safely in lab settings.

***

### I. 🧩 **Understanding Evasion Challenges**

| Category                | Objective                                              | Example Task               |
| ----------------------- | ------------------------------------------------------ | -------------------------- |
| **Image Evasion**       | Create minimal pixel changes that flip classification  | Turn “cat” → “dog”         |
| **Text Evasion**        | Alter words or encodings to fool sentiment/spam filter | “Y0u are amaz!ng”          |
| **Audio Evasion**       | Embed trigger sounds to cause misrecognition           | Hidden phrase in speech    |
| **Vector Perturbation** | Modify embeddings to evade anomaly detector            | Alter feature magnitudes   |
| **Model Bypass**        | Input pattern triggers undesired branch                | Adversarial patch or token |

CTFs simulate these as **puzzles or pattern-reversal tasks** — find an input that breaks the model or detect adversarial ones.

***

### II. ⚙️ **Toolbox for Adversarial ML**

| Purpose             | Tools                                             |
| ------------------- | ------------------------------------------------- |
| Image attacks       | `Foolbox`, `Adversarial Robustness Toolbox (ART)` |
| Text attacks        | `TextAttack`, `OpenAttack`, `CheckList`           |
| Model visualization | `TensorBoard`, `Netron`                           |
| Feature inspection  | `numpy`, `matplotlib`, `pandas`                   |
| Defense evaluation  | `adversarial-robustness-toolbox`, `CleverHans`    |
| Forensics           | `scikit-learn`, `shap`, `lime`                    |

***

### III. 🧠 **Image Evasion: The Classics**

#### 1️⃣ **Fast Gradient Sign Method (FGSM)**

Compute minimal perturbation in gradient direction:

```python
x_adv = x + epsilon * sign(∇x L(model(x), y))
```

**CTF Objective:** find the smallest `epsilon` where the model misclassifies the image.

🧠 _Flag often equals pixel index or epsilon value where misclassification first occurs._

***

#### 2️⃣ **Projected Gradient Descent (PGD)**

Iteratively applies FGSM within epsilon-ball.

#### 3️⃣ **Adversarial Patch**

A visible localized region triggers specific output regardless of the rest of image.

| Task         | Hint                                           |
| ------------ | ---------------------------------------------- |
| Detect Patch | Unusual brightness or block pattern            |
| Create Patch | Alter specific coordinates (CTF-provided mask) |

***

#### 4️⃣ **One-Pixel Attack**

Change a single pixel to flip classification.

CTF version: you’re given model weights, asked to brute-force pixel location that flips label → flag is `(x,y)` coordinates.

***

### IV. 🧩 **Textual Adversarial Evasion**

| Technique                 | Example                        | Notes                             |
| ------------------------- | ------------------------------ | --------------------------------- |
| **Character-Level**       | “love” → “l0ve”, “l♡ve”        | Unicode homograph                 |
| **Word-Level Synonyms**   | “happy” → “glad”               | Context shift                     |
| **Sentence Paraphrasing** | Reordering or rephrasing       | Changes syntax, preserves meaning |
| **Encoding Tricks**       | Base64, URL, zero-width spaces | Bypass filters                    |

CTFs test:

* Can you bypass a filter that blocks “flag”?
* Can you detect which text samples were poisoned?
* Can you restore obfuscated sentences?

🧠 **Tools:** `TextAttack`, `OpenAttack`, `spaCy`, `transformers`.

***

#### Example CTF Script

```python
from textattack.augmentation import WordNetAugmenter
aug = WordNetAugmenter()
print(aug.augment("This message contains the flag"))
```

Outputs variant sentences that might fool a rule-based classifier.

***

### V. 🧠 **Audio & Signal Evasion**

| Attack                      | Concept                           |
| --------------------------- | --------------------------------- |
| **Hidden Command**          | Embed speech at sub-audible level |
| **Spectrogram Patch**       | Frequency-space manipulation      |
| **Time-based Perturbation** | Reordering sample frames          |

**CTF tasks:** detect altered audio or reconstruct hidden waveform.\
Use `spek`, `sox`, `librosa` for analysis.

```python
import librosa, matplotlib.pyplot as plt
y,sr = librosa.load('challenge.wav')
plt.specgram(y,Fs=sr)
```

***

### VI. 🔬 **Adversarial Feature-Space Manipulation**

| Task                       | Technique                             |
| -------------------------- | ------------------------------------- |
| Modify embeddings to evade | Add noise along non-critical PCA axes |
| Fool anomaly detector      | Scale features to boundary            |
| Recreate hidden pattern    | Reverse-engineer trigger vector       |

**CTF pattern:** given vector arrays; you must alter them until model outputs `target_label`.

***

### VII. ⚔️ **Detecting Adversarial Inputs (Defensive CTFs)**

| Detection Strategy            | Concept                                                       |
| ----------------------------- | ------------------------------------------------------------- |
| **Statistical Outlier Tests** | Adversarial samples deviate in pixel / embedding distribution |
| **Confidence Analysis**       | Classifier overconfident on nonsensical input                 |
| **Gradient Norms**            | High sensitivity indicates perturbation                       |
| **Input Reconstruction**      | Denoising autoencoder highlights changes                      |
| **Frequency Analysis**        | Adversarial noise shows unusual high-frequency components     |

#### Example

```python
import numpy as np
diff = np.mean(abs(clean - suspect))
if diff > 0.05:
    print("Adversarial candidate")
```

***

### VIII. 🧩 **CTF Design Patterns**

| Challenge                  | Description                                            |
| -------------------------- | ------------------------------------------------------ |
| **“Invisible Noise”**      | Recover clean image hidden behind perturbation         |
| **“Classifier Blindspot”** | Input that bypasses model logic                        |
| **“Patchwork Flag”**       | Combine fragments of adversarial patches to form flag  |
| **“Perturbation Budget”**  | Minimal L2 difference that breaks model → value = flag |
| **“Detector vs Attacker”** | Submit adversarial sample that evades detection net    |

***

### IX. 🧠 **Evaluation Metrics**

| Metric                       | Meaning                          |
| ---------------------------- | -------------------------------- |
| L∞ / L2 Norm                 | Perturbation magnitude           |
| Confidence Drop              | Change in prediction probability |
| Attack Success Rate (ASR)    | % of successful fooling inputs   |
| Structural Similarity (SSIM) | Image perceptual change          |
| BLEU / Perplexity            | Text meaning preservation        |

***

### X. 🧰 **Practical Libraries**

| Library                          | Language | Function                     |
| -------------------------------- | -------- | ---------------------------- |
| `foolbox`                        | Python   | FGSM, PGD, CW, DeepFool      |
| `Adversarial-Robustness-Toolbox` | Python   | 40+ attack & defense methods |
| `TextAttack`                     | Python   | NLP adversarial framework    |
| `OpenAttack`                     | Python   | Benchmark text attacks       |
| `Torchattacks`                   | Python   | Simple PyTorch-based attacks |
| `cleverhans`                     | Python   | Classic research toolkit     |

***

### XI. ⚙️ **Example: FGSM in a CTF**

Given model and image `input.png`:

```python
from foolbox import PyTorchModel, accuracy, samples
import torch
epsilon = 0.01
x = torch.tensor(img)
x_adv = x + epsilon * x.grad.sign()
```

Submit resulting `x_adv` that flips model’s output — verify misclassification.

Flag could be `"epsilon=0.01"` or image checksum.

***

### XII. 🧩 **Visual Forensics (Detecting Evasion)**

* Compute pixel difference map → `abs(orig - adv)`
* FFT or DCT → adversarial noise often shows uniform frequency spread.
* Statistical moment shift → variance up, skew changes.

```python
import numpy as np
np.mean(abs(orig-adv)), np.var(orig-adv)
```

***

### XIII. 🧠 **Advanced Scenarios**

| Challenge                  | Concept                                         |
| -------------------------- | ----------------------------------------------- |
| **Multi-Modal Evasion**    | Fool both text & image classifier               |
| **Adversarial CAPTCHA**    | Generate inputs bypassing vision + NLP filters  |
| **Zero-Knowledge Evasion** | No model access, use query feedback             |
| **Physical Attacks**       | Printed patch misclassifies camera input        |
| **Multi-Step CTF Chain**   | Combine data poisoning → evasion → exfiltration |

***

### XIV. 🧱 **CTF Workflow Summary**

```
1️⃣ Identify model type & task (image/text/audio)
2️⃣ Load clean sample & test prediction
3️⃣ Apply gradient or transformation
4️⃣ Measure minimal perturbation for flip
5️⃣ Verify perceptual similarity
6️⃣ Extract flag (perturbation, pattern, coordinate)
```

***

### XV. ⚡ **Pro Tips**

* Visualize everything — adversarial changes are easier to see than to guess.
* Normalize inputs before comparing pixel differences.
* Test both black-box (API only) and white-box (weights provided).
* Keep epsilon small — many CTFs require minimal visible noise.
* Record random seeds; reproducibility is part of flag verification.
* For text, prefer semantically consistent substitutions.

***

### XVI. 📚 **Further Reading**

* Goodfellow et al., _Explaining and Harnessing Adversarial Examples_
* MITRE ATLAS → [ML Evasion Techniques](https://atlas.mitre.org/)
* Adversarial Robustness Toolbox Docs
* TextAttack Research Paper (Morris et al. 2020)
* OpenAI Red Team Reports on LLM Prompt Evasion
* DEF CON AI Village “Adversarial Image Labs”

***
