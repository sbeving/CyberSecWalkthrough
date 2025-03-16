# A Comprehensive Guide

CrackMapExec (CME) is a powerful, open-source, post-exploitation tool. It's designed to automate various tasks related to network enumeration, credential testing, and module execution on Windows networks using SMB, WMI, and other protocols. This document provides an overview of its key functionalities, arguments, and practical examples.

## CrackMapExec Basics

*   **Target Specification:** CME targets Windows networks, requiring IP addresses, CIDR notations, or target lists.
*   **Authentication Methods:** CME supports multiple authentication methods including credentials, hashes, and Kerberos authentication.
*   **Module Execution:** It provides numerous built-in modules that perform various actions, such as credential testing, service discovery, and remote command execution.
*   **Output:** Results are displayed in a clear, tabular format, and can be saved to files.

## Core CrackMapExec Arguments and Options

Here's a breakdown of the most important arguments and options in CrackMapExec:

1.  **`<target(s)>`:** Specifies the target IP addresses, range, or file containing target information.
     *  **Example:** `crackmapexec smb 192.168.1.100`

2.  **`-u <username>` / `-U <userfile>`:** Specifies a single username or file containing a list of usernames.
    *   **Example:**
        *   Single user: `crackmapexec smb 192.168.1.100 -u admin`
        *   User file: `crackmapexec smb 192.168.1.100 -U users.txt`

3.  **`-p <password>` / `-P <passwordfile>`:** Specifies a single password or a file containing a list of passwords.
    *   **Example:**
        *   Single password: `crackmapexec smb 192.168.1.100 -u user -p password`
        *   Password file: `crackmapexec smb 192.168.1.100 -u user -P passwords.txt`

4.  **`-H <hash>` / `-H <hashfile>`:** Specifies the pass-the-hash NTLM hash, or file containing a list of hashes.
     *   **Example:**
         *   Single Hash: `crackmapexec smb 192.168.1.100 -u user -H aabbccddeeff11223344556677889900`
         *   Hash file: `crackmapexec smb 192.168.1.100 -u user -H hashes.txt`

5.  **`--kerberos`:** Enable kerberos authentication, if available.
    *  **Example:** `crackmapexec smb 192.168.1.100 -u user -p password --kerberos`

6.  **`-x <command>` / `--exec-method=<command>`:** Specifies a shell command to execute, or a pre built module.
    *  **Example:** `crackmapexec smb 192.168.1.100 -u user -p password -x "whoami"`

7. **`-M <module>` / `--module=<module>`:** Use pre built modules in crackmapexec to perform specific actions.
  * **Example:** `crackmapexec smb 192.168.1.100 -u user -p password -M "mimikatz"`

8.  **`--shares`:** Displays shares for all targets.
    * **Example:** `crackmapexec smb 192.168.1.0/24 -u user -p password --shares`

9.  **`--users`:** Enumerates users for all targets.
   *   **Example:** `crackmapexec smb 192.168.1.0/24 -u user -p password --users`

10. **`-t <threads>` / `--threads=<threads>`:** Sets the number of threads.
     * **Example:** `crackmapexec smb 192.168.1.0/24 -u user -p password --threads 20`
11. **`-o <output_file>` / `--output=<output_file>`:** Output the results to a file.
     *  **Example:** `crackmapexec smb 192.168.1.0/24 -u user -p password -o output.txt`

12. **`-v` / `--verbose`:** Enables verbose output.
     * **Example:** `crackmapexec smb 192.168.1.100 -u user -p password -v`

## Practical CrackMapExec Examples

1.  **SMB login check with username and password:**

    ```bash
    crackmapexec smb 192.168.1.100 -u admin -p password
    ```

2.  **SMB login check with pass-the-hash:**

    ```bash
    crackmapexec smb 192.168.1.100 -u user -H aabbccddeeff11223344556677889900
    ```

3.  **Execute a command on multiple hosts:**

    ```bash
    crackmapexec smb 192.168.1.0/24 -u user -p password -x "whoami"
    ```
4. **Use a mimikatz module to get local credentials**
   ```bash
    crackmapexec smb 192.168.1.100 -u user -p password -M "mimikatz"
   ```
5.  **Enumerate shares on a network:**

    ```bash
    crackmapexec smb 192.168.1.0/24 -u user -p password --shares
    ```
6. **Scan a list of hosts with verbose output and specific threads:**
  ```bash
    crackmapexec smb targets.txt -u user -p password -t 20 -v
  ```

## Use Cases

*   **Penetration Testing:** Testing the security of Windows environments.
*   **Post-Exploitation:** Performing lateral movements and privilege escalation.
*   **Network Auditing:** Identifying vulnerable systems and services.
*   **Security Research:** Exploring security configurations and exploitable services.

## Conclusion

CrackMapExec is a very powerful tool for testing the security of Windows network environments. It can be used to quickly test for a variety of vulnerabilities. Always remember to use this tool responsibly, ethically and on systems you are authorized to test.

---