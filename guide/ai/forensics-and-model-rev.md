---
icon: head-side-gear
---

# Forensics & Model Rev

## 🧠 **AI Forensics & Model Reverse Engineering for CTFs**

> _“Every model leaves fingerprints — if you know where to look.”_
>
> This guide focuses on forensic, analytical, and reverse-engineering tasks involving AI models and machine learning artifacts, as seen in **AI/ML or cybersecurity CTFs**.\
> You’ll learn how to identify architecture, recover metadata, inspect tensors, and perform controlled static and dynamic analysis.

***

### I. 🧩 **Common AI Forensics Challenge Types**

| Challenge Type                 | Goal                                 | Typical Artifact                   |
| ------------------------------ | ------------------------------------ | ---------------------------------- |
| **Model Metadata Leak**        | Extract info from model configs      | `config.json`, `metadata.yaml`     |
| **Weight Inspection**          | Find embedded flags or strings       | `.pt`, `.pth`, `.ckpt`             |
| **Tokenizer Clues**            | Discover hidden vocabulary entries   | `vocab.json`, `merges.txt`         |
| **Model Comparison**           | Detect fine-tuned or modified layers | Two `.bin` or `.safetensors` files |
| **Embedding Analysis**         | Decode flag or phrase from vector    | `.npy`, `.faiss`, `.pkl`           |
| **ONNX / TF Lite Inspection**  | Reverse compute graph                | `.onnx`, `.pb`, `.tflite`          |
| **Inference Output Forensics** | Detect watermark / dataset hint      | API outputs, logits dumps          |

***

### II. ⚙️ **Essential Toolbelt**

| Category             | Tool                                           |
| -------------------- | ---------------------------------------------- |
| Frameworks           | PyTorch, TensorFlow, Hugging Face Transformers |
| Inspect weights      | `torch.load()`, `safetensors`, `numpy`         |
| Model conversion     | `transformers-cli`, `onnxruntime`, `tf2onnx`   |
| Visualization        | `Netron`, `TensorBoard`, `Graphviz`            |
| Vector analysis      | `numpy`, `scipy`, `faiss`, `pandas`            |
| Metadata parsing     | `jq`, `jsonlint`, `grep`, `strings`            |
| Model fingerprinting | `diffusers`, `hashlib`, `hf_transfer`          |
| Forensics sandbox    | Jupyter + isolated venv                        |

***

### III. 🧱 **Understanding Model Artifacts**

#### Common File Types

| File                       | Description                          |
| -------------------------- | ------------------------------------ |
| `pytorch_model.bin`        | Serialized PyTorch weights           |
| `model.safetensors`        | Safer binary weight format           |
| `config.json`              | Model architecture + parameters      |
| `tokenizer.json`           | Vocabulary and token mapping         |
| `vocab.txt`                | Plain text tokens                    |
| `merges.txt`               | BPE merge rules                      |
| `special_tokens_map.json`  | Start/end/pad token IDs              |
| `preprocessor_config.json` | Normalization / feature extraction   |
| `training_args.bin`        | Fine-tuning arguments                |
| `.onnx`                    | Cross-framework model representation |

***

### IV. 🧠 **Weight File Analysis (PyTorch / SafeTensors)**

#### Basic Inspection

```python
import torch
model = torch.load("model.pth", map_location="cpu")
for k,v in model.items():
    print(k, v.shape)
```

#### SafeTensors

```python
from safetensors.torch import load_file
tensors = load_file("model.safetensors")
for name, tensor in tensors.items():
    print(name, tensor.shape)
```

#### CTF Trick:

Hidden strings are sometimes stored in tensors as ASCII values.

```python
import numpy as np
data = model['linear.weight'].numpy().astype(np.int8)
print(''.join(chr(abs(x)%128) for x in data[:300]))
```

🧩 _If you see gibberish resolving into `flag{}`, you’ve found a hidden payload._

***

### V. 🔍 **Config & Metadata Exploration**

#### Inspect configuration:

```bash
cat config.json | jq
```

Look for:

* `"architectures"` → model type (e.g., `GPTNeoForCausalLM`)
* `"hidden_size"`, `"num_layers"`
* `"finetuning_task"`
* `"dataset_name"` (flag sources)
* `"special_tokens"` → custom flag token
* `"model_revision"` or `"commit_hash"`

🧠 _Sometimes the flag hides as a “custom token” in tokenizer files._

***

### VI. 📦 **Tokenizer Forensics**

#### Check Token Files

```bash
cat vocab.txt | grep flag
grep -A2 -B2 "FLAG" tokenizer.json
```

#### Merges File

Flags or hints might appear as:

```
f l
l a
a g
```

or encoded Unicode sequences:

```
\u0066\u006c\u0061\u0067
```

💡 _Decode JSON escape sequences with Python’s `unicode_escape` codec._

***

### VII. ⚙️ **ONNX & TensorFlow Model Inspection**

#### Convert to Graph View

```bash
netron model.onnx
```

Visually check for:

* Extra layers (`FlagLayer`, `HiddenDecoder`)
* Custom op nodes (`CustomOp_1337`)
* Embedded constant tensors (flags in graph)

#### Command-line metadata

```bash
onnxruntime.tools.convert_onnx_models_to_ort
```

#### TensorFlow SavedModel

```bash
saved_model_cli show --dir ./model --all
```

Look inside `variables/variables.data-00000-of-00001` with `strings`.

***

### VIII. 🔬 **Embedding & Feature Vector Analysis**

| Task                | Tool                                   |
| ------------------- | -------------------------------------- |
| Load vector file    | `numpy.load('embeddings.npy')`         |
| Search for outliers | `np.where(np.max(abs(x))>100)`         |
| Decode as ASCII     | Interpret vector as byte values        |
| Compare embeddings  | Cosine similarity / Euclidean distance |

CTF Example:

```python
import numpy as np
emb = np.load("vec.npy")
print(''.join(chr(int(i)) for i in emb[:50]))
```

***

### IX. 🧩 **Model Watermark & Fingerprinting**

| Technique                  | Description                        |
| -------------------------- | ---------------------------------- |
| **Statistical Watermarks** | Bias added to token probabilities. |
| **Lexical Watermarks**     | Preferred vocabulary patterns.     |
| **Structural Watermarks**  | Modified attention weights.        |

**CTF Objective:**\
Detect watermark pattern → decode → flag.

#### Detection via Frequency:

```python
from collections import Counter
tokens = open("output.txt").read().split()
print(Counter(tokens).most_common(10))
```

If output token frequencies spell a pattern → follow it.

***

### X. 🧠 **Comparative Diffing (Two Models)**

| Task                  | Tool / Command                                |
| --------------------- | --------------------------------------------- |
| Compare weights       | `torch.allclose(a,b)` or `np.allclose()`      |
| Compare config hashes | `md5sum config.json`                          |
| Structural diff       | `diff --side-by-side file1 file2`             |
| Output similarity     | Run both models → compute `cosine_similarity` |

CTFs often require spotting **one altered layer or token**.

***

### XI. ⚔️ **Model Dataset Clues**

| File                | What to Check                |
| ------------------- | ---------------------------- |
| `training_args.bin` | Dataset paths, run names     |
| `config.json`       | `"dataset_name"`, `"task"`   |
| `tokenizer.json`    | Custom words / dataset leaks |
| `.cache` dirs       | URLs of original datasets    |

🧠 _Flags sometimes appear as dataset IDs or pipeline parameters._

***

### XII. 🧰 **Forensic Automation Scripts**

#### String Extractor

```bash
strings model.pth | grep -i flag
```

#### Python Hex Dump

```python
with open("model.pth","rb") as f:
    data=f.read()
print(data[data.find(b"flag{"):data.find(b"}")+1])
```

#### Tensor Inspector

```python
import torch
state=torch.load("model.pth")
for k,v in state.items():
    if v.ndim==1:
        text=''.join(chr(int(x)%128) for x in v[:100])
        if 'flag' in text:
            print(k, text)
```

***

### XIII. 🧱 **CTF Workflow Summary**

```
1️⃣ Inspect model metadata and config
2️⃣ Search weights for ASCII-encoded data
3️⃣ Parse tokenizer / vocab files
4️⃣ Check ONNX / graph constants
5️⃣ Analyze embeddings or vectors
6️⃣ Compare model versions for subtle deltas
7️⃣ Extract and validate flag{...}
```

***

### XIV. 🧠 **Common Pitfalls**

* Forgetting to check tokenizer merges (flags split into tokens).
* Ignoring hidden `.bin.index.json` files (index → flag).
* Missing Unicode escapes.
* Misinterpreting float weights (need to cast to int8).
* Overlooking special\_tokens\_map.json.

***

### XV. ⚡ **Pro Tips**

* Open models in **Netron** first — visual diff is faster than text grep.
* Always check **config + tokenizer** together.
* In PyTorch models, look for abnormal tensor shapes (1×N).
* If flag not ASCII → try Base64 / Hex decode.
* Use **Jupyter** to interactively test weight-to-text hypotheses.
* Keep CTF artifacts under Git versioning — easier diffing later.

***

### XVI. 🧩 **Advanced CTF Scenarios**

| Scenario             | Goal                                          |
| -------------------- | --------------------------------------------- |
| Fine-tuned Model     | Compare to base model → recover training data |
| Cloned Model         | Identify via watermark or bias fingerprint    |
| RAG Index            | Extract flag from vector DB entries           |
| Steganographic Model | Flag hidden in unused parameters              |
| Poisoned Model       | Detect anomalous weights or layer order       |

***

### XVII. 🧠 **Educational Resources**

* [MITRE ATLAS: ML Threats & Techniques](https://atlas.mitre.org/)
* [Hugging Face Model Card Guide](https://huggingface.co/docs/hub/models-cards)
* [TensorFlow Model Optimization Toolkit](https://www.tensorflow.org/model_optimization)
* [Netron Visualizer](https://netron.app/)
* [AI Village @ DEF CON – Model Forensics Talks](https://aivillage.org/)
* [CSET’s Machine Learning Forensics Framework](https://cset.georgetown.edu/)

***
