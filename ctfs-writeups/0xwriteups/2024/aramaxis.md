# Aramaxis

## Armaxis (Web Challenge) — HTB University CTF 2024 Writeup

In this writeup, I’ll walk you through my journey of solving the **Armaxis** web challenge. Let’s dive in!

## Exploring the Challenge

The challenge presents two websites:

1. A **login page** for the application.
2. A **mail inbox** for the email address `test@email.htb`.

![](https://miro.medium.com/v2/resize:fit:700/1*DT10Cd_osmlDGR8eTkoIdg.png)

![](https://miro.medium.com/v2/resize:fit:700/1*p_0JB_6kfz_RHuKC44-TxQ.png)

## Analyzing the Source Code

Upon inspecting the challenge files, I found a file named `database.js` that caught my attention.

![](https://miro.medium.com/v2/resize:fit:700/1*X3QEWKR5Bxm_cVp18xx6fw.png)

Inside this file, I discovered a crucial clue: the **admin’s email address**.

![](https://miro.medium.com/v2/resize:fit:671/1*MZ3NTEM7koQ-7lVvm-RVwA.png)

## Logging In as a User

I registered an account and logged in with test email (`test@email.htb`). The weapons page displayed a dashboard

![](https://miro.medium.com/v2/resize:fit:700/1*ZHb2liAHV8uXMUuCsfirjw.png)

/weapons

There didn’t seem to be many options initially, but further exploration of the source code revealed another page named `/dispatch`. but I get denied access when I try to open it because it is only for admin as you can see here:

![](https://miro.medium.com/v2/resize:fit:700/1*imwKl803O21RCM-uplLYRQ.png)

## Investigating Password Reset Functionality

Next, I turned my attention to the **password reset** functionality.

![](https://miro.medium.com/v2/resize:fit:425/1*yNRq0iBZuhw6Hgw1N9qtsQ.png)

I provided the test email which in the mail inbox site

I entered the test email (`test@email.htb`) in the input field and received a response indicating a token was sent to the mail inbox.

![](https://miro.medium.com/v2/resize:fit:606/1*MkSW-duB6YgawBbCYRThmw.png)

Now I will check the mail inbox to see if I got anything

Upon checking the mail inbox, I found the token required to reset the password.

![](https://miro.medium.com/v2/resize:fit:700/1*7uTxjNiY6xsvTegWJEGZaA.png)

And we have a token let’s see what we can do here.

## Manipulating the Password Reset Request

After intercepting the password reset request in **Burp Suite**, We see it included three parameters: `token`, `newpassword`, and `email`.

![](https://miro.medium.com/v2/resize:fit:700/1*nuyqDwhLGFeqT7vUihbtFw.png)

I replaced the email with the **admin’s email address** and successfully reset the admin’s password. Now, I could log in to the admin account.

![](https://miro.medium.com/v2/resize:fit:700/1*14qVz_uZ9HLq4xzx2DcF-g.png)

## Accessing the Dispatch Weapon Page

Upon logging in as the admin, I gained access to the **dispatch weapon** page.

![](https://miro.medium.com/v2/resize:fit:700/1*Fj4DRGWUGofcuBSS9hkIYQ.png)

## Discovering a Vulnerability in the Note Field

While analyzing the source code for the dispatch functionality, I noticed that the `note` input was passed to a function named `parseMarkdown()`.

![](https://miro.medium.com/v2/resize:fit:700/1*I6fesCbW9mxw1GjNKXGjbQ.png)

Looking deeper into the `markdown.js` file, I found this implementation:

![](https://miro.medium.com/v2/resize:fit:700/1*alDXHmGDpM65agUxVizXkg.png)

seems like we have a vulnerability, let’s see how markdown image syntax works.

## Understanding the Vulnerability

In Markdown, images can be embedded using this syntax:

`![alt text](URL)`

* `alt text`: This is the text shown if the image fails to load.
* `URL`: This is where the application fetches the image from.

The `execSync` function executes a `curl` command to fetch the image, which we can manipulate by providing malicious URLs. For example: `![alt text](file:///etc/passwd)` This would instruct the server to fetch and process the contents of `/etc/passwd`.

## Exploiting the Vulnerability

I crafted the following payload for the “note” field: `![alt text](file:///etc/passwd)` .

![](https://miro.medium.com/v2/resize:fit:700/1*o1EelI_VyodmXn730k1e0Q.png)

After submitting the form, the server returned a corrupted image with embedded data. Checking the page source revealed the base64-encoded contents of `/etc/passwd`.

![](https://miro.medium.com/v2/resize:fit:700/1*6zdU0fV99JuK6m_ftX3g3g.png)

The server base64-encoded the file contents and embedded them in an HTML `<img>` tags:

![](https://miro.medium.com/v2/resize:fit:700/1*IFH-Zn1UlluaFfPTXlGx5g.png)

By clicking the corrupted image, I downloaded the decoded contents of `/etc/passwd`.

![](https://miro.medium.com/v2/resize:fit:486/1*0DgYi_fAI0UaaIhtgtYRgg.png)

## Retrieving the Flag

Finally I crafted this payload `![alt text](file:///flag.txt` :

`<img src=”data:image/*;base64,SFRCe2wwMGswdXRfZjByX200cmtkMHduX0xGMV8xbl93MWxkIV9jZDZiMGE0ZDA4ZjQzNGY4NWZkMTJkYzViOWYxYzQyNH0=” alt=”Embedded Image”>`

and Bingo! The flag was successfully retrieved:

![](https://miro.medium.com/v2/resize:fit:637/1*rY93R6OCV2PkYCxtIFSjPA.png)
