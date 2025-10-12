# 🌨️ Cloud & Kubernetes Security

## **Cloud & Kubernetes Security — Fortifying the Cloud Fortress ☁️🛡️**

***

Cloud & container security is **not just configuration** — it’s a **continuous strategy** of securing identities, workloads, APIs, and orchestration.\
Attackers exploit _misconfigurations, excessive permissions,_ and _weak isolation_.\
You’ll learn how to **lock down AWS, Azure, GCP, Docker, and Kubernetes**, detect intrusions, and enforce defense in depth — across identity, network, and runtime.

***

### I. 🧩 Core Concepts

| Concept                         | Description                                                                                 |
| ------------------------------- | ------------------------------------------------------------------------------------------- |
| **Shared Responsibility Model** | Cloud provider secures the infrastructure; you secure configurations, identities, and data. |
| **Least Privilege Everywhere**  | No identity, pod, or service should have more permissions than needed.                      |
| **Defense in Depth**            | Multiple layers: IAM → Network → Workload → Runtime.                                        |
| **Immutable Infrastructure**    | Redeploy, don’t patch — always treat workloads as disposable.                               |
| **Zero Trust**                  | Authenticate and authorize every request, even internal ones.                               |

***

### II. ⚙️ Cloud Security Foundations

| Area                     | Description              | Common Pitfalls                          |
| ------------------------ | ------------------------ | ---------------------------------------- |
| **IAM / Identity**       | Who can do what          | Overly broad permissions, wildcard roles |
| **Storage**              | Protecting data          | Public S3 buckets, open blobs            |
| **Networking**           | Control inbound/outbound | Open Security Groups / Firewalls         |
| **Compute**              | Secure workloads         | Exposed EC2/GCE/VMSS instances           |
| **Logging & Monitoring** | Detect and audit         | Missing CloudTrail, poor log retention   |
| **Encryption**           | Data protection          | No KMS / CMK enforcement                 |

***

### III. ⚙️ AWS Hardening 🟧

#### 🧠 1. IAM Security

* Disable root user API keys.
* Enforce MFA for all users.
* Use IAM Roles, not long-lived access keys.
*   Restrict permissions via least privilege:

    ```json
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}}
    ```
*   Audit permissions:

    ```bash
    aws iam get-account-authorization-details
    ```

#### ⚙️ 2. S3 Bucket Hardening

```bash
aws s3api put-public-access-block \
  --bucket mybucket \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

*   Enable versioning & encryption:

    ```bash
    aws s3api put-bucket-encryption --bucket mybucket --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
    ```

#### 💣 3. CloudTrail & GuardDuty

* Enable CloudTrail in all regions.
* Enable GuardDuty for anomaly detection.
* Log retention ≥ 90 days.
* Forward logs to central S3 bucket.

#### ⚙️ 4. EC2 Security

* Disable SSH from `0.0.0.0/0`.
* Use EC2 Instance Connect or Systems Manager Session Manager.
* Keep AMIs patched & signed.
* Use **Nitro Enclaves** for sensitive computation.

#### 🧠 5. VPC / Network Hardening

* Use private subnets for workloads.
* Enable VPC Flow Logs → CloudWatch.
* Apply NACLs with explicit denies.
* Use Security Groups with inbound whitelisting.

#### ⚙️ 6. Encryption & KMS

* Encrypt all data at rest (EBS, S3, RDS).
* Use KMS CMKs (customer-managed keys).
* Rotate keys every 180 days.

#### 💣 7. Monitoring & Detection

* Integrate GuardDuty → Security Hub → EventBridge → SOAR (TheHive).
* Detect unusual API calls (IAM, CloudTrail, Lambda).
* Run AWS Config for compliance drift detection.

***

### IV. ⚙️ Azure Hardening 🟦

#### 🧠 1. Identity & Access Management

* Enforce Conditional Access & MFA.
* Disable legacy authentication.
* Use Azure AD Privileged Identity Management (PIM).
* Review role assignments (`az role assignment list`).

#### ⚙️ 2. Network Security

* Deny inbound traffic to management ports (22/3389).
* Use NSGs & Azure Firewall.
* Isolate subnets via VNets & Peering policies.
* Monitor traffic with Azure Network Watcher.

#### 💣 3. Storage & Data

*   Restrict Blob public access:

    ```bash
    az storage account update --name mystorage --allow-blob-public-access false
    ```
* Enable encryption with customer-managed keys.
* Enable soft delete and immutability policies.

#### ⚙️ 4. Monitoring & Compliance

* Enable Azure Defender (Defender for Cloud).
* Enable Activity Logs + Diagnostics to Log Analytics.
* Use **Azure Policy** to enforce standards (e.g., no public IPs).

#### 🧠 5. Compute & Containers

* Use Managed Identity for VMs.
* Patch images regularly via Azure Update Management.
* Disable password logins, enforce SSH key auth.

***

### V. ⚙️ GCP Hardening 🟩

#### 🧠 1. IAM Best Practices

* Enforce MFA.
* Avoid `Owner` and `Editor` roles.
* Use **Service Accounts** per application, not shared.
* Enable IAM Recommender to reduce permissions.

#### ⚙️ 2. Network Hardening

* Disable default VPC.
* Use private Google access for internal services.
* Restrict ingress via VPC Firewall Rules.
* Enable VPC Flow Logs.

#### 💣 3. Storage Hardening

* Set bucket policies to private by default.
* Enable CMEK for encryption.
* Use signed URLs for controlled access.

#### ⚙️ 4. Logging & Auditing

* Enable **Cloud Audit Logs** and **Security Command Center**.
* Enable **Forseti Security** for continuous policy auditing.
* Use **Chronicle** for threat analytics.

***

### VI. ⚙️ Kubernetes (K8s) Hardening ☸️

#### 🧠 1. Cluster Access & Authentication

*   Disable anonymous access:

    ```yaml
    apiServer:
      authorization-mode: RBAC
      anonymous-auth: false
    ```
* Use RBAC, not ABAC.
* Integrate OIDC (Google/Azure AD) for identity management.
*   Enforce `kubectl` audit logging:

    ```bash
    kubectl logs apiserver | grep "unauthorized"
    ```

#### ⚙️ 2. RBAC & Least Privilege

* Use namespace isolation.
* Avoid binding `cluster-admin`.
* Limit RoleBindings to exact ServiceAccounts.\
  Example Role:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: dev
  name: read-pods
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
```

#### 💣 3. Pod Security

*   Use **Pod Security Standards (PSS)** or **OPA Gatekeeper**:

    ```yaml
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
    ```
* Disallow `hostNetwork`, `hostPID`, and `privileged` containers.
* Mount secrets as files, not env vars.

#### ⚙️ 4. Network Policies

Define isolation with CNI:

```yaml
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: prod
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

#### 🧠 5. Image & Supply Chain Security

* Use private registries (ECR, GCR, Harbor).
* Scan images automatically (`trivy`, `grype`).
* Sign images with **cosign** (Sigstore).
* Use `Admission Controllers` to block unsigned images.

#### ⚙️ 6. Secrets Management

* Use **Sealed Secrets**, **HashiCorp Vault**, or **External Secrets Operator**.
* Disable plain-text secrets in YAML.\
  Example:

```bash
kubectl create secret generic db-cred --from-literal=user=admin --from-literal=pass=$(openssl rand -hex 16)
```

#### 💣 7. Runtime Security

* Deploy **Falco** or **Tetragon** for real-time detection.
* Monitor:
  * Unexpected shell in pods.
  * Process execution outside entrypoints.
  * Mounting of host paths.

#### ⚙️ 8. Audit Logging & Monitoring

*   Enable audit logs:

    ```yaml
    apiServer:
      audit-log-path: /var/log/apiserver/audit.log
    ```
* Forward logs to ELK or Loki.
* Use Prometheus + Grafana for metric-based anomaly detection.

***

### VII. ⚙️ Container Security in CI/CD

| Stage       | Defense Technique                               |
| ----------- | ----------------------------------------------- |
| **Build**   | Sign and scan images (`cosign`, `trivy`)        |
| **Deploy**  | Admission controllers enforce policies          |
| **Runtime** | Detect drifts (Falco / Sysdig)                  |
| **Post**    | Continuous compliance (Kube-bench, Kube-hunter) |

Automated tools:

```bash
kube-bench
kube-hunter
trivy k8s --report summary
```

***

### VIII. ⚙️ Detection & Threat Hunting in Cloud/K8s

| Source                      | What to Hunt For             | Tools                     |
| --------------------------- | ---------------------------- | ------------------------- |
| **CloudTrail / Azure Logs** | Anomalous IAM use, API abuse | SIEM / Sentinel / Wazuh   |
| **K8s API Server Logs**     | Unauthorized access          | Audit Logs, Kubectl Proxy |
| **Container Runtime**       | Shells, privilege escalation | Falco                     |
| **Network Flow Logs**       | Lateral movement             | Zeek / VPC Flow           |
| **Storage Access Logs**     | Unauthorized reads           | CloudTrail / StackDriver  |

Example Falco rule:

```yaml
- rule: K8s Exec in Container
  desc: Detect exec commands in running pods
  condition: container and evt.type=execve and k8s.ns != "kube-system"
  output: "Pod exec detected (user=%user.name command=%proc.cmdline)"
  priority: warning
```

***

### IX. ⚙️ Cloud Compliance & Benchmarking

| Framework                                            | Use                                                       |
| ---------------------------------------------------- | --------------------------------------------------------- |
| **CIS Benchmarks**                                   | Baseline hardening guides for AWS, Azure, GCP, Kubernetes |
| **NIST 800-53 / 800-190**                            | Cloud security and containerized app guidelines           |
| **ISO/IEC 27017**                                    | Cloud control implementation                              |
| **PCI DSS Cloud**                                    | Payment data environments                                 |
| **AWS Well-Architected Framework (Security Pillar)** | Best practices for cloud resilience                       |

Audit tools:

```bash
ScoutSuite
Prowler
Cloud Custodian
```

***

### X. ⚔️ Pro Tips & Operator Habits

✅ **Lock Down IAM First** — attackers pivot through identity, not ports.\
✅ **Centralize Logs** — cross-cloud aggregation = faster detection.\
✅ **Version Infrastructure as Code** — GitOps = auditable configs.\
✅ **Enforce TLS Everywhere** — inside and outside cluster.\
✅ **Never Expose the API Server** — internal only, use Bastion or VPN.\
✅ **Rotate Secrets Regularly** — automated via Vault / External Secrets.\
✅ **Container Security is Runtime + Behavior** — static scans are not enough.\
✅ **Use Drift Detection** — any config drift = possible compromise.

***

### XI. ⚙️ Quick Reference Table

| Category           | Tool / Command                 | Description                    |
| ------------------ | ------------------------------ | ------------------------------ |
| IAM Auditing       | `Prowler`, `CloudSploit`       | Detect dangerous permissions   |
| Container Scanning | `Trivy`, `Grype`, `Anchore`    | Detect image vulnerabilities   |
| Runtime Monitoring | `Falco`, `Sysdig`, `Tetragon`  | Real-time container visibility |
| Policy Enforcement | `OPA Gatekeeper`, `Kyverno`    | Enforce cluster rules          |
| Compliance         | `Kube-bench`, `ScoutSuite`     | Validate CIS benchmarks        |
| Threat Detection   | `GuardDuty`, `Defender`, `SCC` | Cloud-native detection tools   |

***
