---
icon: burger-cheese
---

# HackDonalds

### Next.js Middleware Authentication Bypass (CVE-2025-29927) <a href="#nextjs-middleware-authentication-bypass-cve-2025-29927" id="nextjs-middleware-authentication-bypass-cve-2025-29927"></a>

#### Classic XML External Entity (XXE) injection <a href="#classic-xml-external-entity-xxe-injection" id="classic-xml-external-entity-xxe-injection"></a>

This combination ultimately allowed me to read system files and retrieve the flag from the server.

#### 🔍 Recon – The Starting Point <a href="#recon-the-starting-point" id="recon-the-starting-point"></a>

We were given the URL:

<figure><img src="https://wsrv.nl/?url=https://gallery.cyndia.in/29d09927-bd8a-4c8c-b25a-3aaf996cf5ef.png&#x26;output=webp&#x26;q=70&#x26;w=3840" alt=""><figcaption></figcaption></figure>

> Visiting the site showed a clean interface with a mysterious Admin section. Clicking it led to a login page that required a secret key. Instead of trying to brute-force the key, I opted for some recon.

#### ⚙️ Wappalyzer to the Rescue <a href="#wappalyzer-to-the-rescue" id="wappalyzer-to-the-rescue"></a>

I used Wappalyzer to identify the technologies behind the app. It revealed that the application is built using Next.js.![ecc937c0-e4a6-40d8-8aac-0fab75bea1e2.png](https://wsrv.nl/?url=https://gallery.cyndia.in/ecc937c0-e4a6-40d8-8aac-0fab75bea1e2.png\&output=webp\&q=70\&w=3840)

> Immediately, a recent CVE came to mind: CVE-2025–29927 – A vulnerability in Next.js middleware that allows bypassing authentication by injecting a special header:

### X-Middleware-Subrequest: middleware <a href="#x-middleware-subrequest-middleware" id="x-middleware-subrequest-middleware"></a>

[👉ProjectDiscovery writeup](https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass)

#### Bypassing Auth with Next.js Middleware Vulnerability <a href="#bypassing-auth-with-nextjs-middleware-vulnerability" id="bypassing-auth-with-nextjs-middleware-vulnerability"></a>

I opened Burp Suite, navigated to the `https://hackdonalds.intigriti.io/admin` page, and captured the request using Burpsuite. As expected, the server redirected me to `/login` due to the missing secret key

![](https://wsrv.nl/?url=https://gallery.cyndia.in/aab0592e-03d4-40f5-bce3-e88d4f91367f.png\&output=webp\&q=70\&w=3840)

So I added the magic header: `X-Middleware-Subrequest: middleware` Then forwarded the request. 🎉 Boom! I was in. The middleware treated the request as internal and let me bypass the authentication entirely.

![](https://wsrv.nl/?url=https://gallery.cyndia.in/8683a6be-c1c2-430e-bf9f-0c97efa71d9d.png\&output=webp\&q=70\&w=3840)

**🔁 Making Auth Persistent (No Intercepting Every Time)**

While this worked, refreshing the page removed the header — and I got logged out again. To fix this: I went to **Burp Suite → Proxy → Match and Replace**

> Left the Match field empty

Set Replace to: **X-Middleware-Subrequest: middleware** then saved the rule

![](https://wsrv.nl/?url=https://gallery.cyndia.in/d7f2a8a8-3205-4a11-afe4-28d24460023e.png\&output=webp\&q=70\&w=3840)

Now every request included the bypass header automatically.

#### Exploring the Ice Cream Machine <a href="#exploring-the-ice-cream-machine" id="exploring-the-ice-cream-machine"></a>

Inside the admin panel, I found an endpoint called `/ice-cream-machine`

![5fc08514-f7bc-4556-951e-cf640f42652d.png](https://wsrv.nl/?url=https://gallery.cyndia.in/5fc08514-f7bc-4556-951e-cf640f42652d.png\&output=webp\&q=70\&w=3840)

This page showed machine statuses (Online/Offline). Clicking on an online machine revealed a custom XML input form that let you query machine data.

> Any time I see XML input as a security researcher, my radar pings 🔔 [Intigriti Blog for XXE](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-advanced-xxe-vulnerabilities)

![f58fd06a-c16d-4521-a0e2-8889c9134691.png](https://wsrv.nl/?url=https://gallery.cyndia.in/f58fd06a-c16d-4521-a0e2-8889c9134691.png\&output=webp\&q=70\&w=3840)

#### XXE Attack: Reading /etc/passwd <a href="#xxe-attack-reading-etcpasswd" id="xxe-attack-reading-etcpasswd"></a>

My instinct told me this XML parser might be vulnerable to XXE. So I tested with a payload like this:

```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE machine [  <!ENTITY xxe SYSTEM "file:///etc/passwd">]><machine>  <id>1</id>  <name>&xxe;</name>  <temperature>-18</temperature>  <mixLevel>75</mixLevel>  <lastMaintenance>2025-03-15</lastMaintenance>  <cleaningSchedule>Daily</cleaningSchedule></machine>
```

![df9a3f7d-1a48-4100-a4d1-de1a0a37b03b.png](https://wsrv.nl/?url=https://gallery.cyndia.in/df9a3f7d-1a48-4100-a4d1-de1a0a37b03b.png\&output=webp\&q=70\&w=3840)

🚨 It worked! The contents of /etc/passwd were returned in the response — confirming XXE vulnerability.

#### 🏁 Final Step – Locating the Flag <a href="#final-step-locating-the-flag" id="final-step-locating-the-flag"></a>

While `/etc/passwd` proved file read worked, the flag wasn’t there. So I thought if this is a MERN stack app, then core content is often stored under `/app`, and most devs keep `/app` as there main application directory and in MERN a single file that always exists `package.json` file. so I decided to check the `package.json` file content first.

**I updated the payload to:**

```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE machine [  <!ENTITY xxe SYSTEM "file:///app/package.json">]><machine>  <id>1</id>  <name>&xxe;</name>  <temperature>-18</temperature>  <mixLevel>75</mixLevel>  <lastMaintenance>2025-03-15</lastMaintenance>  <cleaningSchedule>Daily</cleaningSchedule></machine>
```

![8b0b884b-6d6f-444c-b69e-8659edf70425.png](https://wsrv.nl/?url=https://gallery.cyndia.in/8b0b884b-6d6f-444c-b69e-8659edf70425.png\&output=webp\&q=70\&w=3840)

#### 📦 Boom again! The file was fetched and displayed the flag, completing the challenge. <a href="#boom-again-the-file-was-fetched-and-displayed-the-flag-completing-the-challenge" id="boom-again-the-file-was-fetched-and-displayed-the-flag-completing-the-challenge"></a>

### 🧠 What We Learned <a href="#what-we-learned" id="what-we-learned"></a>

> **Vulnerability Impact**

1. ✅ **CVE-2025-29927** Bypassed middleware auth
2. ✅ XXE Injection Local file disclosure
3. ✅ Logical guesswork Found and read **package.json**
4. 🔐 Just because modern frameworks are in use doesn’t mean old-school bugs like XXE can’t sneak in!
