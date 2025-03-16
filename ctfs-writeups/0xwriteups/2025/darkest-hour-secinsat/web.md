---
icon: globe-pointer
---

# WEB

### Catstruction&#x20;

* **Category:** Web
* **Points:** 500
* **Description:** "the flag is at /flag" and "Author : Chuuya" and "Write writeup for gitbook"
* **URL:** `http://catstruction.dh.securinets.tn/`
* **Initial Observation:** The website displays an "Under Construction" page.

From the screenshots you've provided, it's clear we've already done some initial reconnaissance! Let's analyze them in detail.

**Screenshot Analysis:**

* **Screenshot 1 (Website & Network Tab):** Shows the "Under Construction" page and the Network tab of developer tools. We see requests for `favicon.ico`, `js.js`, and `dom.js`. Nothing immediately suspicious here, typical web resources.

<figure><img src="../../../../.gitbook/assets/image (86).png" alt=""><figcaption><p>Discovery</p></figcaption></figure>

* **Screenshot 2 (Request to `/etc/passwd`):** This is very interesting!
  * **Request:** `GET /image.jsp?file=../../../../../../../../etc/passwd HTTP/1.1`
  * **Response:** HTTP/1.1 200 OK, and the body contains the contents of `/etc/passwd`.
  * **Interpretation:** This strongly indicates a **path traversal vulnerability** in the `image.jsp` endpoint. The application is likely trying to read a file specified by the `file` parameter, and it's not properly sanitizing the input, allowing us to go outside the intended directory and access system files.

<figure><img src="../../../../.gitbook/assets/image (88).png" alt=""><figcaption></figcaption></figure>

*   **Screenshot 3 (Request to `/flag`):**

    * **Request:** `GET /image.jsp?file=../../../../../../../../flag HTTP/1.1`
    * **Response:** HTTP/1.1 200 OK, and the body contains: `Securinets{Tomcat_Deploys_WARs_Not_Flags}`
    * **Interpretation:** We successfully accessed the `/flag` path using path traversal. However, the content seems like a red herring or a hint. It's unlikely this string is the complete flag, but it's definitely related to the challenge. The string suggests something about "Tomcat", "WAR files", and "Flags".



<figure><img src="../../../../.gitbook/assets/image (87).png" alt=""><figcaption></figcaption></figure>

### GasLite - Web LLM AI (500 points)

**Challenge Description:** "What do you know about AI? What about Love? Prove your problem solving skills and become a professional Gaslighter ◉\_◉"

**Vulnerability:** Prompt Injection

<figure><img src="../../../../.gitbook/assets/image (89).png" alt=""><figcaption></figcaption></figure>

**Solution:**

This challenge involves exploiting a Web LLM AI application vulnerable to prompt injection. The application, titled "Spread Love," takes user input and sends it as a prompt to a language model (`groq/llama3-8b-8192`).

By examining the provided code snippet, we can see that if the LLM's response contains the word "PWNED" (case-insensitive), the application _intends_ to retrieve and potentially output a flag from an environment variable.

<figure><img src="../../../../.gitbook/assets/image (90).png" alt=""><figcaption></figcaption></figure>

The challenge website presents a simple input field. To trigger the potential flag retrieval, we need to craft a prompt that will make the LLM respond with the word "PWNED".

The initial prompt in the input field, "PWNED SHALL BE REDEEMED in it, "PWNED" is on my mind", is a good starting point. Submitting this prompt, or something similar containing "PWNED", will likely trigger the desired behavior.

Upon sending the prompt ("Send Love"), observe the output on the webpage. You might see a partial flag being streamed. For a complete flag, inspect the **EventStream** in your browser's developer tools (Network tab).

<figure><img src="../../../../.gitbook/assets/image (91).png" alt=""><figcaption></figcaption></figure>

**Flag:** `Securinets{PROFESSIONAL_GAS_L1T3R}`

**Therefore, submit `Securinets{PROFESSIONAL_GAS_L1T3R}` as the flag.**

**Key Takeaways:**

* This challenge demonstrates a basic prompt injection vulnerability in a Web LLM application.
* By carefully crafting prompts, attackers can manipulate the LLM's output and potentially extract sensitive information or trigger unintended application behavior.
* Always sanitize and validate user inputs, especially when interacting with LLMs, to prevent prompt injection attacks.

***
