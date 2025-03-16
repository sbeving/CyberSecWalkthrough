# A Comprehensive Guide

Responder is a powerful, open-source tool for LLMNR, NBT-NS, and MDNS poisoning. It's designed to capture authentication traffic from Windows and other network devices. This document will outline its core functionalities, arguments, and use cases.

## Responder Basics

*   **Network Poisoning:** Responder listens for network traffic associated with Link-Local Multicast Name Resolution (LLMNR), NetBIOS Name Service (NBT-NS), and Multicast DNS (MDNS).
*   **Authentication Capture:** When a device attempts to resolve a hostname, Responder intercepts the traffic and captures the credentials.
*   **Protocol Support:** It supports various protocols, including SMB, HTTP, SQL, and more.
*   **Credential Relay:** Captured credentials can be used to relay them to other services or for password cracking.

## Core Responder Arguments and Options

Here’s a breakdown of the most important arguments and options in Responder:

1.  **`-I <interface>` / `--interface=<interface>`:** Specifies the network interface to listen on.
    *   **Example:** `responder -I eth0`

2.  **`-i <ip>` / `--ip=<ip>`:** Specifies the IP address of the system which responder will act as.
     * **Example:** `responder -I eth0 -i 192.168.1.100`

3.  **`-w` / `--nbt-ns`:** Enables NBT-NS poisoning.
    *   **Example:** `responder -I eth0 -w`

4.  **`-v` / `--verbose`:** Enables verbose output, this will display more info during capture operations
  *    **Example:** `responder -I eth0 -v`

5.  **`-A` / `--analyze`:** Analyze captured hashes and save it to file.
   *  **Example:** `responder -I eth0 -A`

6. **`-r` / `--remove`:** Removes the current configuration for the responder server
   * **Example:** `responder -I eth0 -r`

7.  **`-f` / `--fast`:** Run Responder without any HTTP/SMB server. Use this option when you do not want to relay, and only want to get hashes.
     *   **Example:** `responder -I eth0 -f`

8.  **`-d` / `--disable-ess`:** Disable ESS support.
     *  **Example:** `responder -I eth0 -d`

9.   **`-P` / `--proxy`:** Run responder as a proxy, and send credentials to the requested system
     *  **Example:** `responder -I eth0 -P`

## Practical Responder Examples

1.  **Basic network poisoning (LLMNR, NBT-NS, MDNS):**

    ```bash
    responder -I eth0
    ```

2.  **Disable the HTTP and SMB servers, and only capture hashes:**

    ```bash
      responder -I eth0 -f
    ```

3.  **Capture NBT-NS traffic only:**

    ```bash
    responder -I eth0 -w
    ```
4.  **Run responder with verbose output:**
    ```bash
    responder -I eth0 -v
    ```

5. **Set up a specific IP address to act as:**
     ```bash
      responder -I eth0 -i 192.168.1.100
     ```

6.  **Run and analyze the captured hashes, and save results to file:**

    ```bash
    responder -I eth0 -A
    ```

## Use Cases

*   **Penetration Testing:** Capturing and exploiting credentials in internal networks.
*   **Security Audits:** Assessing the security of network devices and servers.
*   **Credential Harvesting:** Gathering credentials to test the security of systems and protocols.
*   **Network Reconnaissance:** Discovering various authentication protocols and vulnerabilities in the local network.

## Conclusion

Responder is a valuable tool for capturing authentication traffic on local networks. It allows you to identify weak spots in the authentication mechanisms and capture valuable credentials. Always use Responder ethically and responsibly, and only against networks where you have explicit authorization.

---
