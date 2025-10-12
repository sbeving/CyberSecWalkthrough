# 🧱 Supply Chain & DevSecOps

## **Supply Chain Security & DevSecOps Warfare — Securing the Pipeline of Trust 🧱⚙️**

***

Supply chain attacks target **the build process, dependencies, or delivery channels** rather than direct network exploits.\
The modern threat actor doesn’t just hack — they **infect your tools**.

This guide turns your DevOps workflow into a **defensible kill chain** — instrumented, verified, and immutable from code to cloud.

***

### I. 🧩 Core Concepts

| Concept                               | Description                                                            |
| ------------------------------------- | ---------------------------------------------------------------------- |
| **Software Supply Chain**             | Every stage and dependency from source to production.                  |
| **DevSecOps**                         | Security embedded into CI/CD — not bolted on afterward.                |
| **SBOM (Software Bill of Materials)** | List of components and versions within a build.                        |
| **Artifact Provenance**               | Verifiable origin and build lineage of binaries.                       |
| **Code Signing**                      | Cryptographic assurance that code hasn’t been tampered with.           |
| **CI/CD Security**                    | Protecting the automation stack: Jenkins, GitHub Actions, GitLab, etc. |

***

### II. ⚙️ The Supply Chain Attack Surface

| Layer                | Common Weakness                          | Example Attack                 |
| -------------------- | ---------------------------------------- | ------------------------------ |
| **Source Code**      | Compromised dev account                  | CodeCov Bash Uploader backdoor |
| **Dependencies**     | Typosquatting / malicious packages       | Event-Stream NPM               |
| **Build Systems**    | Poisoned runners, unsigned artifacts     | SolarWinds Orion               |
| **Container Images** | Embedded secrets, CVEs                   | Log4j, dirty images            |
| **CI/CD Secrets**    | Plain-text tokens, leaked creds          | Travis CI, CircleCI leaks      |
| **Deployment**       | Insecure manifests, unverified artifacts | XZ backdoor (2024)             |

***

### III. ⚙️ Secure Software Development Lifecycle (SSDLC)

| Phase          | Defense Objective           | Tools / Practices             |
| -------------- | --------------------------- | ----------------------------- |
| **Planning**   | Threat modeling             | STRIDE, PASTA                 |
| **Coding**     | Secure by default           | Linters, pre-commit hooks     |
| **Building**   | Controlled, isolated builds | Reproducible builds           |
| **Testing**    | Automated security scans    | SAST/DAST/SCA                 |
| **Deploying**  | Signed, verified artifacts  | Cosign, Notary v2             |
| **Monitoring** | Continuous posture check    | Dependency Track, GitGuardian |

***

### IV. ⚙️ Source Code Security 🧠

#### 1️⃣ Repository Hygiene

*   Enforce signed commits:

    ```bash
    git config commit.gpgsign true
    ```
* Require MFA for all developer accounts.
* Protect main branch (no direct pushes).
* Enable **branch protection + code reviews**.

#### 2️⃣ Secret Management

*   Prevent committing secrets:

    ```bash
    git secrets --install
    ```
*   Scan for exposed keys:

    ```bash
    gitleaks detect --source .
    trufflehog filesystem .
    ```
* Store credentials only in **Vaults** (HashiCorp, AWS Secrets Manager, Doppler).

#### 3️⃣ Dependency Hygiene

*   Pin dependency versions:

    ```
    pip install flask==2.2.2
    ```
*   Enable package integrity:

    ```bash
    npm audit fix
    pip-audit
    yarn audit
    ```
* Validate hashes in package-lock or requirements.txt.
* Use **dependency allowlists** — no random `pip install`.
* Mirror dependencies locally via **Artifactory / Nexus / Verdaccio**.

***

### V. ⚙️ Build System Security 🏗️

#### 1️⃣ Isolated Build Environments

* Never build on developer laptops.
* Use **ephemeral CI runners**.
* Lock down build agents (no root, no outbound internet).
* Disable arbitrary code execution in pull requests.

#### 2️⃣ CI/CD Secrets Protection

* Use short-lived OIDC tokens.
* Rotate credentials every 90 days.
* Mask secrets in CI logs.
* Restrict variable scopes by environment (dev/stage/prod).

Example (GitHub Actions):

```yaml
env:
  AWS_ROLE_ARN: arn:aws:iam::123456789:role/Deploy
permissions:
  contents: read
  id-token: write
```

#### 3️⃣ Reproducible Builds

*   Build should yield **identical binary hash** every time:

    ```bash
    sha256sum app-v1.2.0.bin
    ```
* Enforce deterministic builds in Docker (set timestamps, fixed ordering).

#### 4️⃣ Dependency Lockdown in CI

*   Always verify checksums in pipeline:

    ```bash
    curl -fsSLO https://pkg.io/app.tar.gz
    echo "checksum file" | sha256sum -c -
    ```

***

### VI. ⚙️ Artifact Signing & Provenance 🔏

#### 1️⃣ Signing Artifacts

Use **Sigstore / Cosign** for signing containers and binaries:

```bash
cosign sign --key cosign.key myapp:1.0.0
cosign verify --key cosign.pub myapp:1.0.0
```

#### 2️⃣ Supply Chain Provenance

Attach provenance metadata:

```bash
cosign attest --predicate attestation.json --key cosign.key myapp:1.0.0
```

Metadata includes:

* Who built it
* When and where
* Source commit
* Dependencies

#### 3️⃣ Verification at Deploy Time

Integrate in Kubernetes Admission Controller:

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: signed-images
spec:
  images:
  - glob: "*"
  authorities:
  - key:
      secretRef:
        name: cosign-pub
```

***

### VII. ⚙️ SBOM (Software Bill of Materials) 🧾

#### 1️⃣ Generate SBOMs

*   CycloneDX or SPDX formats:

    ```bash
    syft myapp:latest -o cyclonedx-json > sbom.json
    ```
* Integrate into CI/CD pipelines.

#### 2️⃣ Analyze SBOMs for Vulnerabilities

```bash
grype sbom:sbom.json
dependency-track-cli --upload sbom.json
```

#### 3️⃣ Store SBOMs in Artifact Registry

Maintain a versioned SBOM per release.

***

### VIII. ⚙️ CI/CD Pipeline Security ⚙️

#### 1️⃣ Pipeline Isolation

| Layer                | Defense                        |
| -------------------- | ------------------------------ |
| **Build Nodes**      | Ephemeral, minimal permissions |
| **Artifacts**        | Signed & verified              |
| **Logs**             | Immutable storage              |
| **Environment Vars** | Scoped, masked                 |
| **Cache**            | Sanitized between jobs         |

#### 2️⃣ Runner Hardening

* Disable Docker-in-Docker unless absolutely necessary.
* Run jobs in sandboxed containers (gVisor, Kata).
* Validate code from untrusted forks before execution.

#### 3️⃣ CI/CD Auditing

Monitor:

* Pipeline modification attempts
* Unauthorized credential use
* Artifact tampering
* Disconnected audit trails

Integrate with:

* **DefectDojo**
* **OWASP Dependency Track**
* **GitHub Advanced Security**

***

### IX. ⚙️ Container Image Security 🐳

#### 🧠 1. Build Clean Images

* Use minimal base images (`distroless`, `scratch`).
* Avoid `apt-get upgrade` in Dockerfiles.
* Multi-stage builds: compile → ship only runtime.

#### ⚙️ 2. Scan & Sign

```bash
trivy image myapp:latest
grype myapp:latest
cosign sign myapp:latest
```

#### 💣 3. Validate at Deploy Time

Reject unsigned or vulnerable images using OPA Gatekeeper/Kyverno:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: signed-only
spec:
  validationFailureAction: enforce
  rules:
  - name: verify-signature
    match:
      resources:
        kinds:
        - Pod
    verifyImages:
    - image: "*"
      key: "cosign-pub"
```

***

### X. ⚙️ Infrastructure as Code (IaC) Hardening 🧱

#### 1️⃣ Static Analysis

Scan IaC templates:

```bash
checkov -d .
tfsec .
kics scan -p .
```

Detect:

* Open security groups
* Unencrypted resources
* Hardcoded credentials

#### 2️⃣ Policy Enforcement

Integrate with **Open Policy Agent (OPA)**:

```rego
deny[msg] {
  input.resource_type == "aws_s3_bucket"
  input.public_access == true
  msg = "Public S3 bucket not allowed"
}
```

#### 3️⃣ Drift Detection

Detect infrastructure changes post-deploy:

* Terraform Cloud drift detection
* AWS Config rules
* GCP Policy Intelligence

***

### XI. ⚙️ Continuous Monitoring & Threat Detection

| Layer             | What to Watch                  | Tools                        |
| ----------------- | ------------------------------ | ---------------------------- |
| **Code Repos**    | Secret leaks, new dependencies | GitGuardian, Gitleaks        |
| **Build Systems** | Runner integrity               | Falco, Jenkins Audit Trail   |
| **Artifacts**     | Signature verification         | Cosign, Rekor                |
| **Deployments**   | Configuration drift            | Kube-bench, Cloud Custodian  |
| **Dependencies**  | CVEs, license violations       | Snyk, OWASP Dependency Track |

***

### XII. ⚙️ Incident Response & Forensics

1️⃣ Quarantine compromised artifacts.\
2️⃣ Compare hashes vs SBOMs for tampering.\
3️⃣ Rebuild from source with verified dependencies.\
4️⃣ Rotate secrets in affected environments.\
5️⃣ Report compromised packages to registries.

***

### XIII. ⚙️ Real-World Breach Case Studies

| Incident                     | Vector                  | Lesson                                 |
| ---------------------------- | ----------------------- | -------------------------------------- |
| **SolarWinds (2020)**        | Build system compromise | Isolate and sign every build           |
| **CodeCov (2021)**           | CI script tampering     | Validate external scripts              |
| **Log4Shell (2021)**         | Dependency flaw         | Track vulnerable components via SBOM   |
| **XZ Utils Backdoor (2024)** | Maintainer infiltration | Review contributors and provenance     |
| **npm Event-Stream (2018)**  | Package hijack          | Pin dependencies and audit maintainers |

***

### XIV. ⚔️ Pro Tips & Operator Habits

✅ **Sign Everything.** From commits → containers → manifests.\
✅ **Assume Your Pipeline Will Be Targeted.** Build defensible architecture.\
✅ **No External Scripts Unverified.** Pin SHA256 or self-host.\
✅ **Secrets Belong in Vaults.** Never in code, not even encrypted.\
✅ **Measure Build Integrity Daily.** Hash verification + Rekor logs.\
✅ **Audit Developer Access.** Treat GitHub as production.\
✅ **Reproducibility = Resilience.** If you can rebuild from scratch, you can recover.\
✅ **Transparency ≠ Weakness.** SBOMs, signatures, and attestations build trust.

***

### XV. ⚙️ Quick Reference Table

| Goal              | Tool / Command                     | Description                      |
| ----------------- | ---------------------------------- | -------------------------------- |
| Scan Source       | `semgrep`, `gitleaks`              | Detect code and secret issues    |
| Scan Dependencies | `snyk`, `npm audit`, `pip-audit`   | Vulnerability management         |
| Sign Artifacts    | `cosign`, `notary v2`              | Image signing and verification   |
| Generate SBOM     | `syft`, `cyclonedx`                | Dependency visibility            |
| Enforce Policies  | `OPA`, `Kyverno`, `Checkov`        | IaC and runtime governance       |
| Monitor Pipelines | `Falco`, `DefectDojo`              | Build & runtime threat detection |
| Compliance        | `OpenSSF Scorecards`, `OWASP SAMM` | Continuous posture assessment    |

***
