---
icon: github
---

# Gitleaks

## The Gitleaks Masterclass: Professional Secrets Detection in Git Repositories

Gitleaks is a versatile and high-performance tool designed for scanning Git repositories and other source code hosting platforms to detect secrets, credentials, API keys, and sensitive information that could lead to security breaches. This professional guide covers advanced usage, policies, and integration strategies for penetration testers, bug bounty hunters, and security teams.

***

### I. Environment Setup: Dynamic Variables

Configure session variables for organized and repeatable scanning:

```bash
export REPO_PATH="/path/to/local/repository"      # Path to local git repo or clone URL for remote repo
export CONFIG_FILE="gitleaks-config.toml"         # Custom configuration for secrets patterns and allowlist
export OUTPUT_DIR="gitleaks-results"
export OUTPUT_JSON="$OUTPUT_DIR/scan_report.json"
export OUTPUT_SARIF="$OUTPUT_DIR/scan_report.sarif"
export BRANCH="main"
export COMMIT_HASH="HEAD"
export LOG_LEVEL="info"
export EXCLUDE_PATHS="docs/,tests/"

```

***

### II. Core Capabilities & Workflow

* **Secret Scanning:** Detects API keys, credentials, tokens, private keys, passwords, and other sensitive data using regex and entropy analysis.
* **Custom Policies:** Supports user-defined regex patterns, secret allowlists, and exclude rules for targeted and low-noise scans.
* **Multi-Target Scanning:** Can scan local repositories, remote Git URLs, GitHub organizations, GitLab groups, and Azure DevOps projects.
* **Multiple Output Formats:** Outputs results as JSON, SARIF (for security tools integration), CSV, and plain text.
* **CI/CD Integration:** Supports running as part of pipelines to prevent secret leaks in development lifecycle.
* **Diff Scanning:** Only scans changes between commits or branches to optimize scanning in active projects.
* **High Performance:** Efficient scanning designed for large repositories and monorepos.

***

### III. Professional Usage Examples

#### 1. Scan Local Git Repository

```bash
gitleaks detect --source $REPO_PATH --output $OUTPUT_JSON --redact

```

#### 2. Scan Remote GitHub Repository by URL

```bash
gitleaks detect --source <https://github.com/user/repo> --branch $BRANCH --output $OUTPUT_JSON --redact

```

#### 3. Use Custom Configuration

```bash
gitleaks detect --source $REPO_PATH --config-path $CONFIG_FILE --output $OUTPUT_JSON --redact

```

#### 4. Scan Specific Commit or Branch

```bash
gitleaks detect --source $REPO_PATH --commit $COMMIT_HASH --output $OUTPUT_JSON --redact

```

#### 5. Exclude Paths from Scanning

```bash
gitleaks detect --source $REPO_PATH --exclude-paths $EXCLUDE_PATHS --output $OUTPUT_JSON --redact

```

#### 6. Output SARIF Format (for IDE or Security tool integration)

```bash
gitleaks detect --source $REPO_PATH --output $OUTPUT_SARIF --redact --report-format sarif

```

#### 7. Scan Diff Between Two Commits

```bash
gitleaks detect --source $REPO_PATH --commit-from abc123 --commit-to def456 --output $OUTPUT_JSON --redact

```

***

### IV. Advanced Techniques & Scenarios

* **Configure Fine-Grained Policies:** Tune regexes and entropy thresholds in `gitleaks-config.toml` for organization-specific secret formats.
* **Use Allowlists:** Prevent known or accepted secrets in scans to minimize false positives.
* **Integrate with CI/CD:** Run Gitleaks as a pre-commit hook or in pipeline stages to catch leaks early.
* **Scan Entire GitHub Organizations:** Sweep multiple repositories in bulk with access token authentication.
* **Diff-Only Scanning:** Focus on changes between commits or branches during active development cycles.
* **Automated Alerts:** Hook into alerting or ticketing platforms via output parsing to trigger response workflows.
* **Scale Performance:** Use concurrency options and caching for large repository sets.

***

### V. Real-World Workflow Example

1. **Export Variables:**

```bash
export REPO_PATH="/home/user/code/project"
export CONFIG_FILE="configs/gitleaks_custom.toml"
export OUTPUT_DIR="gitleaks_reports"

```

1. **Run Full Scan with Custom Config:**

```bash
gitleaks detect --source $REPO_PATH --config-path $CONFIG_FILE --output $OUTPUT_DIR/scan_full.json --redact

```

1. **Scan Only New Changes (Diff Scan):**

```bash
gitleaks detect --source $REPO_PATH --commit-from master~10 --commit-to master --output $OUTPUT_DIR/scan_diff.json --redact

```

1. **Integrate with GitHub Action or GitLab CI for Automated Scanning**
2. **Review Findings and Remediate or Rotate Secrets**

***

### VI. Pro Tips & Best Practices

* **Regularly Update Policies:** Keeping regexes and entropy detection up to date minimizes false positives/negatives.
* **Use Redaction:** To protect secrets in logs and reports during collaboration.
* **Integrate Early in SDLC:** Pre-commit hooks and CI pipeline scanning prevent secret leakage before production release.
* **Configure Excludes & Allowlists:** To focus scans and reduce noise.
* **Combine with Other Tools:** Use with source code analysis, SAST, and runtime secrets detection for layered defense.
* **Always Secure Secrets:** Rotate or remove found secrets immediately upon detection.

***

This professional Gitleaks guide ensures you can confidently scan, detect, and remediate secret exposures in source code repositories, supporting secure development practices and rapid bug bounty response.
