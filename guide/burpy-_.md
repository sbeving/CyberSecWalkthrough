---
icon: face-raised-eyebrow
---

# Burpy -\_-

### The Burp Suite Bible: Conquer Web Application Vulnerabilities

Burp Suite is a comprehensive platform for performing security testing of web applications. Its various tools work together seamlessly to help you identify and exploit vulnerabilities. This manual will guide you through Burp Suite's core components and how to use them effectively in CTF challenges.

**I. Core Components:**

* **Proxy:** Intercepts all HTTP/HTTPS traffic between your browser and the web application.
* **Repeater:** Allows you to modify and resend individual HTTP requests.
* **Intruder:** Automates customized attacks to perform tasks such as fuzzing and brute-forcing.
* **Scanner:** Performs automated vulnerability scans.
* **Comparer:** Compares data items.
* **Decoder:** Encodes and decodes data in various formats.
* **Extender:** Allows you to load Burp extensions to add custom functionality.

**II. Setting Up Burp Suite:**

1. **Installation:** Download and install Burp Suite from Portswigger's website. There's a free Community Edition and a paid Professional Edition.
2. **Proxy Configuration:** Configure your browser to use Burp Suite as a proxy. The default proxy address is `127.0.0.1:8080`. You'll typically need to install a Burp Suite CA certificate in your browser.

**III. Using the Proxy:**

1. **Intercepting Requests:** With the proxy enabled, requests from your browser will be intercepted by Burp Suite. You can then:
   * Forward the request.
   * Drop the request.
   * Modify the request.
   * Send the request to other Burp Suite tools (Repeater, Intruder, Scanner).
2. **Intercepting Responses:** Similarly, responses from the server can be intercepted and modified.
3. **Viewing HTTP History:** The Proxy tab keeps a history of all intercepted requests and responses.

**IV. Using the Repeater:**

4. **Sending Requests:** Send requests to the Repeater from the Proxy or by pasting them in.
5. **Modifying Requests:** Modify the request (headers, parameters, body) and click "Go" to resend it.
6. **Comparing Responses:** Compare the responses to see the effect of your modifications. Useful for testing for vulnerabilities like SQL injection or XSS.

**V. Using the Intruder:**

7. **Payload Positions:** Define the positions in the request where you want to inject payloads.
8. **Payload Types:** Choose the type of payload you want to use (e.g., simple list, numbers, dates, brute-force).
9. **Attack Types:**
   * **Sniper:** Injects the payload into each position one at a time.
   * **Battering Ram:** Injects the same payload into all positions simultaneously.
   * **Pitchfork:** Uses multiple payload sets, injecting one payload from each set into corresponding positions.
   * **Cluster Bomb:** Uses multiple payload sets, injecting all possible combinations of payloads.
10. **Starting the Attack:** Start the attack and analyze the results to identify interesting responses.

**VI. Using the Scanner:**

11. **Passive Scanning:** Analyzes intercepted traffic for potential vulnerabilities.
12. **Active Scanning:** Sends specially crafted requests to actively probe for vulnerabilities. Use active scanning cautiously, as it can be noisy and might trigger alerts.
13. **Scan Queue:** Add targets to the scan queue to perform automated scans.

**VII. Other Useful Features:**

14. **Comparer:** Compares two pieces of data (e.g., two responses). Useful for identifying differences.
15. **Decoder:** Encodes and decodes data in various formats (e.g., Base64, URL encoding, Hex).
16. **Target:** Allows you to define the scope of your testing.
17. **Extender:** Allows you to add custom functionality to Burp Suite using extensions.

**VIII. Common CTF Scenarios and Examples:**

18. **Intercepting and Modifying Requests:** Use the Proxy to intercept requests and modify parameters to test for vulnerabilities.
19. **Fuzzing with Intruder:** Use Intruder to fuzz input fields to look for unexpected behavior or crashes.
20. **Brute-forcing Login Forms:** Use Intruder to brute-force login credentials.
21. **Testing for SQL Injection:** Use Repeater or Intruder to inject SQL payloads and analyze the responses.
22. **Testing for XSS:** Use Repeater or Intruder to inject XSS payloads and see if they are reflected in the response.
23. **Performing Automated Scans:** Use the Scanner to perform active and passive scans for common vulnerabilities.

**IX. Tips for CTFs:**

* **Learn the Basics:** Start by mastering the Proxy and Repeater.
* **Use Intruder for Automation:** Intruder is essential for fuzzing and brute-forcing.
* **Be Careful with Active Scanning:** Active scanning can be noisy. Use it cautiously.
* **Analyze Responses Carefully:** Pay close attention to the server's responses. Error messages and unusual behavior can be clues.
* **Read the Documentation:** Burp Suite has a lot of features. Refer to the official documentation for more details.
* **Practice:** The more you use Burp Suite, the more comfortable you'll become with its capabilities.
