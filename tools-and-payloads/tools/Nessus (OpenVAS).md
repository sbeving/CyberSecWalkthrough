
# A Comprehensive Guide

Nessus is a widely used vulnerability scanner used for performing scans on networks and systems to identify security vulnerabilities. While Nessus itself is a commercial product, the core scanning engine is based on the open-source OpenVAS. This document will focus on the concepts and usage of the OpenVAS vulnerability scanner, understanding that many of these concepts translate well into using Nessus.

## OpenVAS Basics

- **Vulnerability Scanning:** OpenVAS performs thorough scans, checking for a wide range of vulnerabilities, misconfigurations, and outdated software.
    
- **Network and System Scans:** It scans both networks and individual systems.
    
- **Reporting:** It generates detailed reports highlighting discovered vulnerabilities and recommended actions.
    
- **Scalability:** OpenVAS can be scaled for larger environments, making it suitable for organizations of all sizes.
    

## Core OpenVAS Features and Options

Here's a breakdown of the main features and concepts in OpenVAS:

1. **Target Selection:** Specifying the target(s) for vulnerability scanning.
    
    - Use the OpenVAS interface to specify IP addresses, CIDR ranges, or domain names as target.
        
2. **Scan Configurations:** Customizing scan settings for different levels of aggressiveness and check types.
    
    - Configure the scan options and scan profile in the scan configuration.
        
3. **Scan Profiles:** Using predefined scan profiles for specific types of assessments.
    
    - Choose the scan profile based on your requirements (e.g., "Discovery," "Web Application Scanning", etc.).
        
4. **Credential Management:** Providing credentials for authenticated scans, to give the best results possible.
    
    - You will need to configure the credentials to be used on the targets, before running the scans.
        
5. **Vulnerability Detection:** Identifying a wide range of known vulnerabilities through its plugin system.
    

- The vulnerabilities are identified using a database of network vulnerability tests (NVTs).
    

1. **Reporting:** Generating reports with discovered vulnerabilities and recommended remediation steps.
    
    - Check the results in the UI, and generate the report if needed for later inspection.
        
2. **Scan Scheduling:** Running periodic and scheduled scans.
    
    - Set up scan schedule, so you can use OpenVAS to perform automated periodic security scans on your network.
        
3. **Filters:** Filtering the results to identify specific types of vulnerabilities or certain hosts.
    
    - Use the filters to focus your scan to specific protocols, ports, hosts, or vulnerabilities.
        
4. **Alerts:** Configure alerts that are triggered by specific results or vulnerability discoveries.
    
    - Use alerts to get instant notification when a vulnerability is found.
        

## Practical OpenVAS Scenarios

1. **Basic vulnerability scan on a single host:**
    
    - Create a target
        
    - Create and start a scan with basic scan profile for the target.
        
2. **Authenticated scan on a Windows system:**
    
    - Create a target for the system.
        
    - Configure credentials for the target using the SMB protocol
        
    - Create a scan and use a profile with authenticated testing enabled for this new target.
        
3. **Scan a network with multiple hosts:**
    
    - Create a target using CIDR notation.
        
    - Configure the scan using a specific scan profile, and then start the scan.
        
4. **Scan only web ports:**
    
    - Configure a scan and set specific ports 80, and 443 for the scan profile.
        
    - Start the scan on your target.
        
5. **Scan with specific level of verbosity:**
    
    - Create a scan with one specific profile of your choice, and then set it to verbose level.
        

## Use Cases

- **Vulnerability Management:** Identifying and tracking vulnerabilities in an organization's IT infrastructure.
    
- **Penetration Testing:** Mapping out the attack surface by identifying known vulnerabilities and security misconfigurations.
    
- **Security Auditing:** Checking compliance with security standards and policies.
    
- **Risk Assessment:** Evaluating the security posture and determining potential risks.
    
- **Vulnerability Research:** Checking for vulnerabilities in a test environment before implementing changes on production.
    

## Conclusion

OpenVAS (and Nessus) provides a comprehensive platform for vulnerability scanning and is a valuable asset for security professionals and system administrators. It allows you to discover weak spots, and keep the network secure using continuous monitoring. Use these tools responsibly and ethically, and with proper authorization.

---
