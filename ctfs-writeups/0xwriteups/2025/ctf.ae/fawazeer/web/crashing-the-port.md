# Crashing The Port

### Challenge Overview

**Challenge Name**: Crashing The Port\
**Category**: Web\
**Points**: 500\
**Description**: Upload your customs and my python script will detect the price 😎.

### Summary

The "Crashing The Port" challenge involved exploiting a command injection vulnerability in a file upload system. The server was running a Python Flask application that allowed users to upload files for "customs price detection." However, the application used unsanitized user input directly in a shell command, enabling command injection attacks.



<figure><img src="../../../../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

### Reconnaissance

Upon visiting the challenge website, I found a form for submitting shipping information including:

* Shipper Name
* Consignee Name
* File Upload (accepting .pdf, .doc, .docx, and .txt files)
* Description field

The form posted to `/upload` endpoint, and there was also a link to view all shipments at `/shipments`.

An account must've been created on `/register` and logged on using `/login` .

<figure><img src="../../../../../../.gitbook/assets/image (5) (1).png" alt=""><figcaption></figcaption></figure>

### Vulnerability Analysis

After some testing, I discovered an error message that revealed critical server-side code:

```
subprocess.CalledProcessError: Command 'python check.py uploads/custom.txt;aaaaaaa' returned non-zero exit status 127.
```

This error showed that the server was executing a command like:

```python
subprocess.check_output("python check.py "+file_path, shell=True)
```

The vulnerability was clear: the application was directly concatenating the file path (which included the filename) into a shell command without proper sanitization. By using special characters like semicolons (`;`) in the filename, I could inject additional commands to be executed on the server.

### Exploitation

I crafted a file with a specially formatted filename that included a command injection payload:

<pre><code><strong>example.txt;e''nv
</strong></code></pre>

This filename consisted of three parts:

1. `example.txt` - A regular filename that would be accepted by the application
2. `;` - A command separator in shell syntax
3. `e''nv` - A command to display environment variables (with a small obfuscation to potentially bypass filters)

When the server processed this file, it executed:

```
python check.py uploads/example.txt;env
```

The first command would run normally, then the injected `env` command would execute, displaying all environment variables - including the flag.

<figure><img src="../../../../../../.gitbook/assets/image (6).png" alt=""><figcaption><p>Booooom !!!</p></figcaption></figure>

After uploading the file with the crafted filename, the server executed the injected command and returned the environment variables, which included:

```
FLAG=flag{SRnPfaLKW9VFvUX6A9Uh1a5Bnh7PeNyC} // did th3 writeup later flag changed
```

### Key Lessons

1. **Input Sanitization**: Never use user-supplied input directly in command execution
2. **Parameterized Commands**: Use safer alternatives like `subprocess.run()` with arrays instead of `shell=True`
3. **Principle of Least Privilege**: The application was running with access to sensitive environment variables
4. **Error Exposures**: Detailed error messages in production revealed **critical implementation details**
