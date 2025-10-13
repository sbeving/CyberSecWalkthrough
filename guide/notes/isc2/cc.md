# CC



## CC - Certified in Cybersecurity

_Author: Rana Chouchen_

### Domain 1: Security Principles

#### The C-I-A Triad

The core principles of information security are Confidentiality, Integrity, and Availability.

* **Confidentiality**: The information is safe from accidental or intentional disclosure.
* **Integrity**: The information is safe from accidental or intentional modification or alteration.
* **Availability**: The information is available to authorized users when needed.

> **Confidentiality** is about limiting access to information/assets and is therefore most similar to **secrecy**.

***

#### Security Concerns Mapped to the C-I-A Triad

| Confidentiality Concerns | Integrity Concerns           | Availability Concerns      |
| ------------------------ | ---------------------------- | -------------------------- |
| 1. Snooping              | 1. Unauthorized modification | 1. Denial of Service (DoS) |
| 2. Dumpster Diving       | 2. Impersonation             | 2. Power outages           |
| 3. Eavesdropping         | 3. Man-in-the-middle (MITM)  | 3. Hardware failures       |
| 4. Wiretapping           | 4. Replay                    | 4. Destruction             |
| 5. Social Engineering    |                              | 5. Service outages         |

***

#### Definitions of Threats

* **Snooping**: Unauthorized people looking for visible information.
* **Dumpster Diving**: Searching trash for sensitive papers.
* **Eavesdropping**: Listening to conversations (physical or electronic).
* **Wiretapping**: A specific form of eavesdropping focused on **network or electronic communication**, such as telephone lines, internet traffic, or emails.
* **Social Engineering**: Tricking people into revealing sensitive information.
* **Impersonation Attacks**: Attackers pretend to be trusted people (e.g., a boss or IT staff) to trick others and manipulate data.
* **Replay Attacks**: Attackers intercept and reuse valid login details to access systems without permission.

***

#### Privacy and Risk Management

**Privacy**: is the right of an individual to control the distribution of information about themselves. In 2016, the European Union passed comprehensive legislation addressing personal privacy, deeming it an individual human right.

* **The European Union's General Data Protection Regulation (GDPR)** is a comprehensive data privacy law designed to protect individuals' personal data and regulate its collection, processing, and storage within the EU and beyond (2016).
* In the United States, **HIPAA** controls how the privacy of medical information must be maintained.
* Security controls are implemented in the risk management process to mitigate the risk to a level that is deemed acceptable by the entity.

**Threat Actor**: An individual or a group that attempts to exploit vulnerabilities to cause or force a threat to occur.

**Threat Vector**: The means by which a threat actor carries out their objectives.

* If a pickpocket is a threat, the attack vector would be their technique and approach.

**Personally Identifiable Information (PII)**: is the term used to describe information that, when combined with other pieces of data, significantly narrows the possibility of association with more individuals.

**An asset**: is something in need of protection. Anything of value that is owned by an organization. Assets include both tangible items such as information systems and physical property and intangible assets such as intellectual property.

**A vulnerability**: is a gap or weakness in those protection efforts.

**A threat**: is something or someone that aims to exploit a vulnerability to thwart protection efforts.

* When making decisions based on risk priorities organizations must evaluate the **likelihood and impact** of the risk as well as their tolerance for different sorts of risk.
* Determining risk tolerance is up to the **executive management and board of directors**.
* In order to mitigate the risk associated with a threat, it is recommended to evaluate how likely an event is to take place and take appropriate actions to mitigate the risk associated with the threat.
* **Employees at all levels** of the organization are responsible for identifying risk.
* Security professionals are likely to assist in risk assessment at a system level, focusing on process, control, monitoring, or incident response and recovery activities.

***

#### Security Controls

| Physical Controls                                                                                                                                                                                  | Technical Controls                                                                                                             | Administrative Controls                                                                                                                                                                                                                                                                                                                                   |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Physical controls address security needs using physical hardware devices, such as badge readers, architectural features of buildings and facilities, and specific security actions taken by staff. | Technical controls (also called logical controls) are security controls that computer systems and networks directly implement. | Administrative controls (also known as managerial controls) are directives, guidelines, or advisories aimed at the people within the organization. They provide frameworks, constraints, and standards for human behavior and should cover the entire scope of the organization's activities and its interactions with external parties and stakeholders. |

***

#### Governance and Access Control

**Governance**: The process of how an organization is managed; usually includes all aspects of how decisions are made for that organization, such as policies, roles and procedures the organization uses to make those decisions.

* Information security professionals are expected to uphold **honorable, honest, just, responsible, and legal conduct**, as mentioned in the code of ethics.

**Access Control Steps for IT Professionals (I-A-A):**

1. **Identification**: The user claims an identity (e.g., providing a username).
2. **Authentication**: The user verifies their identity, typically using credentials like a password, PIN, or biometrics.
3. **Authorization**: Permissions are checked to confirm what the user is allowed to access.

**3 Methods of Authentication:**

* **Something you know**: Passwords or passphrases
* **Something you have**: Tokens, memory cards, smart cards
* **Something you are**: Biometrics, measurable characteristics
* The use of an ATM card (something you have) and a PIN (something you know) at the bank, providing two different factors of authentication.
* Knowledge-based authentication involves using a passphrase or secret code (e.g., PIN or password) to differentiate between authorized and unauthorized users.

***

#### Governance Elements

| Element         | Definition                                                                                                                                                                                              |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Procedures**  | Procedures are the detailed steps to complete a task that support departmental or organizational policies.                                                                                              |
| **Policies**    | Policies are put in place by organizational governance, such as executive management, to provide guidance in all activities to ensure that the organization supports industry standards and regulation. |
| **Standards**   | Standards are often used by governance teams to provide a framework to introduce policies and procedures in support of regulations.                                                                     |
| **Regulations** | Regulations are commonly issued in the form of laws, usually from government (not to be confused with governance) and typically carry financial penalties for non-compliance.                           |

* **Laws** are the explicit authority of the jurisdiction where any organizations operate; laws cannot be violated, regardless of internal company governance. Laws supersede everything else.
* **Policies, standards, processes, procedures and guidelines** set by corporate administrative entities (e.g., executive- and/or mid-level management) are **management/administrative controls**.

**Baseline**: A documented, lowest level of security configuration allowed by a standard or organization.

**Non-repudiation**: The inability to deny taking an action such as creating information, approving information, or sending or receiving a message.

***

#### Prioritizing Risk

One effective method to prioritize risk is to use a risk matrix, which helps identify priority as the intersection of likelihood of occurrence and impact.

* You can use this simple probability and impact model to determine the level of risk and therefore prioritize risk.
* **Level of Risk = Probability + Impact**

**Risk Treatment Options:**

1. **Risk Avoidance**: Stop activities that pose high risks.
2. **Risk Mitigation**: Implement controls to reduce risk likelihood or impact.
3. **Risk Acceptance**: Accept the risk if impact is negligible or benefits outweigh risks.
4. **Risk Transference**: Transfer risk to a third party (e.g., insurance).

> What is risk tolerance often likened to? → **Risk appetite**

**Risk assessment**: is the process of identifying, analyzing, and evaluating potential risks to determine their impact and likelihood.

* The result of the risk assessment process is often documented as a report or presentation given to management for their use in prioritizing the identified risks.

***

***

### Domain 2: Incident Response, Business Continuity and Disaster Recovery Concepts

#### Key Definitions

* **Event**: Any observable occurrence in a network or system.
* **Incident**: An event that jeopardizes the confidentiality, integrity, or availability of information or systems.
* **Threat**: Any circumstance or event with the potential to harm organizational operations, assets, individuals, or systems.
* **Vulnerability**: Weakness in a system, procedures, controls, or implementation that could be exploited by a threat.
* **Breach**: The loss, compromise, or unauthorized access of personally identifiable information (PII) or similar sensitive data.
* **Exploit**: A specific attack leveraging vulnerabilities in systems.
* **Intrusion**: A deliberate security incident where an intruder gains, or attempts to gain, unauthorized system access.
* **Zero Day**: A previously unknown vulnerability exploited before detection or mitigation is possible.

***

#### Business Continuity (BC)

**Business Continuity (BC)**: Actions, processes and tools for ensuring an organization can continue critical operations during a contingency—ensures operations can sustain and recover from significant disruptions.

**Business Continuity Plan (BCP)**: The documentation of a predetermined set of instructions or procedures that describe how an organization's mission/business processes will be sustained during and after a significant disruption.

* What term is sometimes used interchangeably with "incident management"? --> **Crisis Management**
* Some organizations use the term "crisis management" to describe the incident management process.
* The **red book** serves as a hard copy backup accessible outside the facility, containing outlined procedures in case electronic access is unavailable.

**Common Components of a BCP:**

* List of the BCP team members, including multiple contact methods and backup members.
* Guidance for management, including designation of authority for specific managers.
* Immediate response procedures and checklists (security and safety, fire suppression, etc.).
* How/when to enact the plan.
* Notification systems and call trees.
* Contact numbers for critical members of the supply chain (vendors, customers, etc.).
* One key outcome of a **Business Impact Analysis (BIA)** is the identification of functions and dependencies.

***

#### Incident Response

**Components of an Incident Response Plan (IRP):**

1. **Preparation**: Develop policy, identify assets, train staff, establish IRT.
2. **Detection & Analysis**: Monitor vectors, analyze incidents, prioritize response.
3. **Containment, Eradication, & Recovery**: Gather evidence, identify attacker, isolate, remove threat, restore systems.
4. **Post-Incident Activity**: Document lessons learned, retain evidence.

| Phase                      | Activities                                                                                                                                                                                                    |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Preparation**            | Develop a management-approved policy, identify critical assets, train staff, establish an incident response team, define roles, plan stakeholder communication, and ensure alternative communication methods. |
| **Detection and Analysis** | <p>- Monitor all possible attack vectors.<br>- Analyze the incident using known data and threat intelligence.<br>- Prioritize incident response.<br>- Standardize incident documentation.</p>                 |
| **Containment**            | <p>- Gather evidence.<br>- Choose an appropriate containment strategy.<br>- Identify the attacker.<br>- Isolate the attack.</p>                                                                               |
| **Post-Incident Activity** | <p>- Identify evidence that may need to be retained.<br>- Document lessons learned.</p>                                                                                                                       |

**Incident Response Team (IRT)**:

* A cross-functional team includes senior management, security professionals, legal, public affairs, and engineering representatives.
* The four primary responsibilities of a response team are **determining damage, assessing compromise, implementing recovery procedures, and supervising security measures**.
* The IRT is responsible for **assessing and scoping out any damage** when an incident occurs.

***

#### Disaster Recovery Planning (DRP)

**DRP** is about restoring IT, while **BCP** focuses on business operations.

* The purpose of the **Executive Summary** in a DRP is to provide a high-level overview of the plan.
* Organizational support for BCP efforts must be provided by **executive management or an executive sponsor**.
* **Backups** are pivotal components of any disaster recovery (DR) effort.

***

***

### Domain 3: Access Control Concepts

**Access control** involves limiting what **objects** can be available to what **subjects** according to what **rules**.

* Access controls are not just about restricting access, but also about **allowing access** to the appropriate level for authorized personnel.

| Element      | Definition                                                                                                                                        | Characteristics                                                            |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| **Subjects** | Can be defined as any entity that requests access to assets.                                                                                      | **Is active**: It initiates a request for access to resources or services. |
| **Objects**  | Anything that a subject attempts to access is referred to as an object. An object is defined as an entity that responds to a request for service. | **Is passive**.                                                            |
| **Rules**    | Is an instruction developed to allow or deny access to an object by comparing the validated identity of the subject to an access control list.    |                                                                            |

***

#### Core Concepts

**Defense in Depth (Layered Defense)**: An information security strategy that integrates people, technology, and operations capabilities to establish **variable barriers across multiple layers**.

**Least Privilege**: To preserve confidentiality, each user is granted access to **only the items they need and nothing further**.

* Privileged access management implements the principle of least privilege.
* The more critical information a person has access to, the greater the security should be around that access (e.g., MFA).

| Access Control Type         | Description                                                                                                           |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **Physical Access Control** | Tangible methods or mechanisms that limit someone from getting access to an area or asset.                            |
| **Logical Access Control**  | Electronic methods that limit someone from getting access to systems, and sometimes even to tangible assets or areas. |

**User provisioning** in identity management involves creating and managing access to resources and information systems.

***

#### Access Control Models

| Model                                  | Definition                                                                                                                                              | Key Features                                                                                                                                                                                                                                       | Use Cases                                                                                                     |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| **Mandatory Access Control (MAC)**     | A strict security policy where only authorized security administrators can manage access rules. These rules are consistently applied across the system. | <p><strong>Restricted User Actions</strong>:<br>- Users cannot share access.<br>- Users cannot alter rules.<br>- Users cannot choose security levels.<br><br><strong>Centralized Control</strong>:<br>- Only security admins can change rules.</p> | Government agencies (e.g., military systems) where confidentiality and sensitivity are critical.              |
| **Role-Based Access Control (RBAC)**   | Provides each worker privileges based on their role in the organization.                                                                                | <p>- Users are assigned roles with specific permissions.<br>- Simplifies management by grouping permissions.<br>- Access changes when roles change.</p>                                                                                            | Businesses with structured roles (e.g., HR, finance). Works well in environments with high staff turnover.    |
| **Discretionary Access Control (DAC)** | A flexible model where access is determined by the resource owner.                                                                                      | <p>- Resource owners can grant or revoke access.<br>- Permissions can be customized for individuals.<br>- Less restrictive but prone to security risks (e.g., accidental sharing).</p>                                                             | Personal systems or collaborative environments where resource sharing is common (e.g., file-sharing systems). |

* In **MAC**, the level of access is determined by government policy and security clearance.
* **Privilege creep** (or permissions creep) refers to someone inheriting expanded permissions that are not appropriate for their role in **RBAC**.
* **DAC** is not considered very scalable because it relies on the discretion of individual object owners.

***

#### Advanced Concepts

**Privileged Accounts**: Accounts with permissions beyond those of normal users, such as managers and administrators.

**Separation of Duties**: No one person should control an entire high-risk transaction from start to finish.

* When two individuals willfully work together to bypass this, it is called **collusion**.

**Two-Person Integrity (Two-Person Rule)**: A security strategy that requires a minimum of two people to be in an area together.

**Crime Prevention Through Environmental Design (CPTED)**: A strategy to create safer spaces by using passive design elements (organizational, mechanical, natural) to discourage crime.

**Biometric Authentication Types**:

* **Physiological**: Fingerprints, iris scans, retinal scans, palm scans, venous scans.
* **Behavioral**: Voiceprints, signature dynamics, keystroke dynamics.

**Monitoring Tools**:

| Tool                | Purpose                                                             |
| ------------------- | ------------------------------------------------------------------- |
| **Cameras**         | Tools for surveillance, deterrence, and forensic evidence.          |
| **Logs**            | Records of events for compliance, forensics, and auditing.          |
| **Alarm Systems**   | Devices that alert when unauthorized or emergency situations occur. |
| **Security Guards** | Human presence to deter and monitor unauthorized access.            |
| **Motion Sensors**  | Detect movement or breaches in secure areas.                        |

* A **turnstile** is used to prevent **"piggybacking"** or **"tailgating"**.

***

***

### Domain 4: Network Security

#### Network Types

* **Local Area Network (LAN)**: In a limited geographical area.
* **Wide Area Network (WAN)**: Assigned to the long-distance connections between geographically remote networks.

**Ethernet (IEEE 802.3)**: This standard defines the way data is formatted over the wire to ensure disparate devices can communicate over the same cables.

#### Network Architectures

* In a typical small business or home network, all devices behind the firewall connect via a network switch, and the firewall lies between the network switch and the internet.
* In a home network, the firewall and network switch are often combined into one device (wireless access point/router).
* **Wi-Fi**: Wireless media intrusions can happen at a distance, which is a key difference from wired networks that require physical access. This freedom introduces **additional vulnerabilities**.
* **Micro-segmentation**: Aids in protecting against **Advanced Persistent Threats (APTs)** by enforcing the concept of least privilege between network segments.

***

#### Tools to Identify and Prevent Threats

| Tool                                  | Description                                                                                                 | Identifies Threats | Prevents Threats |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------- | :----------------: | :--------------: |
| **Intrusion Detection System (IDS)**  | A form of monitoring to detect abnormal activity; it detects intrusion attempts and system failures.        |         ✔️         |                  |
| **Host-based IDS (HIDS)**             | Monitors activity on a single computer.                                                                     |         ✔️         |                  |
| **Network-based IDS (NIDS)**          | Monitors and evaluates network activity to detect attacks or event anomalies.                               |         ✔️         |                  |
| **SIEM**                              | Gathers log data from sources across an enterprise to understand security concerns and apportion resources. |         ✔️         |                  |
| **Anti-malware/Antivirus**            | Seeks to identify malicious software or processes.                                                          |         ✔️         |        ✔️        |
| **Scans**                             | Evaluates the effectiveness of security controls.                                                           |         ✔️         |                  |
| **Firewall**                          | Filters network traffic - manages and controls network traffic and protects the network.                    |         ✔️         |        ✔️        |
| **Intrusion Prevention System (IPS)** | An active IDS that automatically attempts to detect and **block** attacks before they reach target systems. |         ✔️         |        ✔️        |

* A distinguishing difference between an IDS and an IPS is that the **IPS is placed in line with the traffic** and can choose what traffic to forward and what traffic to block.

***

#### HIDS vs. NIDS

| Host-based Intrusion Detection System (HIDS)                                            | Network Intrusion Detection System (NIDS)                                                      |
| --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Monitors activity on a single computer.                                                 | Monitors and evaluates network activity to detect attacks or event anomalies.                  |
| Can examine events in more detail and pinpoint specific files compromised in an attack. | Cannot monitor the content of encrypted traffic but can monitor other packet details.          |
| Can detect anomalies on the host system that NIDSs cannot detect.                       | Can detect the initiation of an attack but can't always provide information about its success. |
| More costly to manage as they require administrative attention on each system.          | Usually support centralized administration.                                                    |

***

#### Network Concepts

**Demilitarized Zone (DMZ)**: A portion of the organization's network that interfaces directly with the outside world and typically has more security controls and restrictions compared to the rest of the internal IT environment.

**Web Application Firewall (WAF)**: It monitors all traffic from the outside for malicious behavior before passing commands to a web server.

**Virtual Private Network (VPN)**: A VPN is not necessarily an encrypted tunnel. It is simply a point-to-point connection. Security depends on the protocols selected and configured.

* **Gateway-to-gateway VPNs** are a potential alternative to expensive dedicated point-to-point connections.

**Network Monitoring or Sniffing**: Monitoring traffic patterns to obtain information about a network.

**TCP Handshake (SYN, SYN-ACK, ACK)**

1. **Client -> Server**: SYN (Synchronize)
2. **Server -> Client**: SYN/ACK (Synchronize/Acknowledge)
3. **Client -> Server**: ACK (Acknowledge)

**Port Ranges**:

| Port Type                    | Range       | Description                                                                          |
| ---------------------------- | ----------- | ------------------------------------------------------------------------------------ |
| **Well-known ports**         | 0–1023      | Related to common core protocols (DNS, SMTP, HTTP).                                  |
| **Registered ports**         | 1024–49151  | Often associated with proprietary applications (e.g., RADIUS, MS SQL).               |
| **Dynamic or private ports** | 49152-65535 | Used for temporary sessions; a service responds with a dynamic port for the session. |

***

#### Redundancy and Cloud

**The concept of redundancy**: To design systems with duplicate components so that if a failure were to occur, there would be a backup.

* **Function of transfer switches/transformers**: Enable seamless transition between power sources.
* **Why is abnormal system shutdown a concern?**: It may result in the loss or corruption of data.

**A managed service provider (MSP)** is a company that manages information technology assets for another company.

* A common service is **Managed Detection and Response (MDR)**, where MSPs monitor firewalls and other tools to triage events.

**Cloud Computing**: Refers to on-demand access to computing resources available from almost anywhere.

* A **cloud service-level agreement (cloud SLA)** is an agreement between a cloud service provider (CSP) and a customer.

**Cloud Service Models**:

| Model    | Definition                                                                    | Primary Users         | Control Level                          | Examples                        | Key Features                                                                       |
| -------- | ----------------------------------------------------------------------------- | --------------------- | -------------------------------------- | ------------------------------- | ---------------------------------------------------------------------------------- |
| **SaaS** | Provides fully functional applications over the internet.                     | End users             | Minimal control                        | Google Workspace, Microsoft 365 | <p>- Ready-to-use apps<br>- No installation required<br>- Subscription pricing</p> |
| **PaaS** | Provides a platform for developers to build, deploy, and manage applications. | Developers, IT teams  | Control over apps, not infrastructure  | Heroku, Azure App Services      | <p>- Develop &#x26; deploy apps<br>- Platform managed by provider</p>              |
| **IaaS** | Provides virtualized computing resources over the internet.                   | IT admins, Developers | Full control over infrastructure (VMs) | AWS, Azure, Google Cloud        | <p>- Flexible infrastructure<br>- Users manage OS, apps, data</p>                  |

> Which cloud model allows scaling up new software quickly without massive hardware installation? --> **Platform as a Service (PaaS)**

* Agreements between organizations to share resources during an emergency are called **joint operating agreements (JOA)**, **memoranda of understanding (MOU)**, or **memoranda of agreement (MOA)**.
* **MOUs/MOAs** are related to what can be done with a system, while **SLAs** specify more intricate aspects of services.

***

#### Network Segmentation and Threats

* **Network Segmentation**: Involves controlling traffic among networked devices.
* **Demilitarized Zone (DMZ)**: A network area for outside visitors, isolated from the private network.
* **Virtual Local Area Network (VLAN)**: Logically segments a network using switches without altering physical topology.
  * Devices on the same VLAN communicate as if on the same Layer 2 network.
  * Attacks like **VLAN hopping** can allow a user to see traffic from other VLANs.
* **Network Access Control (NAC)**: Controls access to an environment through strict security policy.
  * VLANs are used in NAC to control whether devices connect to the corporate network or a guest network.

**Types of Threats**:

* **Spoofing**: Using a falsified identity (IP, MAC, username).
* **Phishing**: Social engineering to deceive users into revealing information.
* **DoS/DDoS**: Overwhelming a system to make it unavailable.
* **Virus**: Requires user action (clicking a link) to spread.
* **Worm**: Propagates without human intervention.
* **Trojan**: Malicious software disguised as legitimate software.
* **On-path Attack (Man in the middle)**: Intercepting communication between two parties.
* **Side channel**: Passive, non-invasive attack observing a device's operation (power monitoring, timing).
* **Advanced Persistent Threat (APT)**: Sophisticated, long-term attacks by organized groups.
* **Insider Threat**: A threat originating from within the organization.
* **Malware**: Malicious software.
* **Ransomware**: Encrypts data and demands a ransom for its release.

***

***

### Domain 5: Security Operations

#### Network Models: OSI vs. TCP/IP

| OSI Model Layer | TCP/IP Architecture Layer |
| --------------- | ------------------------- |
| 7. Application  | Application               |
| 6. Presentation |                           |
| 5. Session      |                           |
| 4. Transport    | Transport                 |
| 3. Network      | Internet                  |
| 2. Data Link    | Network Interface         |
| 1. Physical     |                           |

* **Primary responsibility of the upper layer (Application)**: Transforming data into a format that any system can understand.
* **Which OSI layer corresponds to the Internet Layer in TCP/IP?**: Network Layer.

***

#### Data Handling

**Data Lifecycle**: Create -> Store -> Use -> Share -> Archive -> Destroy

* **Retention**: How long we store information based on organizational and regulatory requirements.
* **Degaussing**: Process of reducing or eliminating an unwanted magnetic field (or data) stored on tape and disk media.

***

#### Encryption and Hashing

**Encryption System**: A set of hardware, software, algorithms, and methods that provide encryption services.

> What do integrity services, provided by hash functions and digital signatures, allow a recipient to verify? --> **That a message has not been altered by malice or error.**

**Hashing**: Puts data through a hash function to create an alphanumeric digest.

* No matter how long the input is, the hash digest will always be the same length.

**Symmetric Algorithm**:

* Uses the **same key** for both encryption and decryption.
* Other names: **shared key, single key, same key, secret key, session key**.
* An example is a **substitution cipher**.
* **Which mode ensures confidentiality efficiently with minimum overhead?** --> Symmetric.

**Asymmetric Encryption**:

* Uses one key (public key) to encrypt and a different key (private key) to decrypt.
* It is much slower than symmetric cryptography.
* Why is it considered more secure? --> It involves a unique (private) key for the receiver that is never shared.
* Signing a message with a sender's private key can be verified by anyone with the sender's public key, ensuring authenticity and non-repudiation.

***

#### Policies and Change Management

**Common Security Policies**:

* **Data Handling Policy**
* **Password Policy**
* **Acceptable Use Policy (AUP)**: Defines acceptable use of network/computer systems.
* **Bring Your Own Device (BYOD) Policy**
* **Privacy Policy**
* **Change Management Policy**: The discipline of transitioning from the current state to a future state.

**A rollback**: Restoring the system to its previous state before a change.

> Who is often tasked with coordinating the change management effort? --> **Information Security professionals**

**Three Major Components of Change Management**:

1. **Request for Change (RFC)**: Initiates the process.
2. **Approval**: Evaluates and approves/rejects the change based on risk analysis.
3. **Rollback**: Defines a plan to revert the change if issues arise.

**Logging and Monitoring**: Essential to identifying inefficient systems, detecting compromises, and providing a record of how systems are used.

* Logs should be stored separately from the systems they're logging.

***

#### Security Awareness & Training

The purpose of awareness training is to make sure everyone knows what is expected of them, based on responsibilities and accountabilities.

* **Path**: education -> training -> awareness
* **How long to crack a 10-number password with cryptographic calculation?** --> \~5 seconds
* **What should every security policy have?** --> Consequences for non-compliance
* **Phishing against high-placed officials is known as**: **Whaling attacks**.
* **Recommended task for employees to practice security**: Sending simulated phishing emails.
