---
description: SSTI but shuffled
---

# S7our Shorba Tajin Iftar

<figure><img src="../../../../../.gitbook/assets/image (92).png" alt=""><figcaption></figcaption></figure>

### **Step 1: Confirming SSTI and Analyzing Error Messages**

* In this challenge, the first stage involved testing for SSTI by providing different payloads and reviewing the server output. The initial payloads were commonly used SSTI payloads.

<figure><img src="../../../../../.gitbook/assets/image (5) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption><p>SHUFFLED PAYLOAD</p></figcaption></figure>

Using the Error processing output as input activated the ssti

<figure><img src="../../../../../.gitbook/assets/image (4) (1) (1) (1).png" alt=""><figcaption><p>SSTI CONFIRMED</p></figcaption></figure>

### **Step 2:Listing Files using os.popen(‘ls’)**

Knowing SSTI was achievable the next part was to find a payload to read the values. The step started by listing the files with the os.popen("ls") command and built the SSTI payload to list files, by providing and checking output.

Let's list files , used payload \
\
`{{request.application.`**`globals`**`.`**`builtins`**`.`**`import`**`('os').popen('ls').read()}}`



<figure><img src="../../../../../.gitbook/assets/image (5) (1) (1) (1).png" alt=""><figcaption><p>shuffled payload</p></figcaption></figure>

<figure><img src="../../../../../.gitbook/assets/image (6) (1).png" alt=""><figcaption><p>ls</p></figcaption></figure>

### **Step 3:Displaying main.py File using os.popen(‘cat main.py’)**

Knowing SSTI was achievable the next part was to find a payload to read the values. The step started by listing the files with the os.popen("ls") and then displaying the main.py content.\
\


<figure><img src="../../../../../.gitbook/assets/image (7) (1).png" alt=""><figcaption><p>cat main.py</p></figcaption></figure>

### `Step 4:Displaying the FLAG Env Variable`

`FLAG = os.getenv("FLAG")`

then we need to craft a payload to get the FLAG environment variable&#x20;

`{{request.application.`**`globals`**`.`**`builtins`**`.`**`import`**`('os').getenv('FLAG')}}`

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>FLAG</p></figcaption></figure>
