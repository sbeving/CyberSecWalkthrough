---
icon: slack
---

# Hashcat

## The Hashcat Masterclass: Professional Password Recovery & Cracking

Hashcat is the industry’s leading advanced password recovery and cracking tool, supporting GPU and CPU acceleration, over 300 hash algorithms, and a broad range of attack modes. This professional guide covers operational best practices, advanced usage, and workflow integration—no installation instructions included.

***

### I. Environment Setup: Dynamic Variables

Set these variables for repeatable, organized sessions:

```bash
export HASH_FILE="hashes.txt"
export WORDLIST="rockyou.txt"
export RULES_FILE="rules/best64.rule"
export MASK="?a?a?a?a?a?a"
export OUTPUT_FILE="hashcat-results/cracked.txt"
export HASH_MODE=0          # See hashcat --help or documentation (e.g., 0=MD5, 100=SHA1, 1000=NTLM)
export ATTACK_MODE=0        # 0=Dictionary, 1=Combination, 3=Brute-force, 6=Hybrid dict+mask, 7=Hybrid mask+dict
export THREADS=4
export WORK_PROFILE=3       # 1=low, 2=default, 3=high, 4=insane
export SESSION="htb_session"

```

***

### II. Core Capabilities & Workflow

* **Dictionary & Hybrid Attacks:** Applies wordlists, rules, and masks to maximize crack rates on common/complex passwords.
* **Brute-Force & Mask Attacks:** Exhaustive combinations, mask structures, and charset tuning.
* **Rule Engine:** In-kernel rules for mangling dictionary entries (substitutions, appends, case flips, etc.).
* **Salt & Custom Hash Support:** Handles salted and unsalted hashes from a multitude of platforms and apps.
* **Resumable, Checkpointed Sessions:** Pause/resume with session files, track progress, and avoid lost work.
* **Multiple Output & Status Modes:** Save cracked results, session states, and debug logs for analysis and reporting.

***

### III. Professional Usage Examples

#### 1. Dictionary Attack (Default, Fastest)

```bash
hashcat -a 0 -m $HASH_MODE $HASH_FILE $WORDLIST -o $OUTPUT_FILE --session $SESSION --status

```

#### 2. Dictionary + Rules (Hybrid, Mimic Human Password Variations)

```bash
hashcat -a 0 -m $HASH_MODE $HASH_FILE $WORDLIST -r $RULES_FILE -o $OUTPUT_FILE --session $SESSION --status

```

#### 3. Brute-Force Attack with Mask (e.g., 6-char random)

```bash
hashcat -a 3 -m $HASH_MODE $HASH_FILE $MASK -o $OUTPUT_FILE --session $SESSION --status

```

#### 4. Hybrid Attack: Dictionary + Mask (Append 3 digits to every word)

```bash
hashcat -a 6 -m $HASH_MODE $HASH_FILE $WORDLIST ?d?d?d -o $OUTPUT_FILE --session $SESSION --status

```

#### 5. Combination Attack (Combine Two Wordlists)

```bash
hashcat -a 1 -m $HASH_MODE $HASH_FILE $WORDLIST another_wordlist.txt -o $OUTPUT_FILE --session $SESSION --status

```

#### 6. Resume or Restore Cracking Session

```bash
hashcat --session $SESSION --restore

```

#### 7. GPU & System Tuning (Workload, Threads)

```bash
hashcat -a 0 -m $HASH_MODE $HASH_FILE $WORDLIST -w $WORK_PROFILE --opencl-threads $THREADS

```

#### 8. Crack Only Uncracked Hashes (--remove)

```bash
hashcat -a 0 -m $HASH_MODE $HASH_FILE $WORDLIST --remove -o $OUTPUT_FILE

```

***

### IV. Advanced Techniques & Scenarios

* **Custom Charset/Mask Design:** Tune brute-force or hybrid masks to match password policy patterns (e.g., `?u?l?d?d?d` for upper, lower, 3 digits).
* **Rule Tuning:** Stack rules to mimic organization-specific password complexity.
* **Debug & Audit:** Log which rules/cracks succeeded using `-debug-mode` and `-debug-file`.
* **Salts & Composite Hashes:** Provide salt files or specific hash modes for salted formats.
* **Output Management:** Use `-potfile-disable` for clean sessions, and custom output with `o`.

***

### V. Real-World Workflow Example

1.  **Export Variables and Prepare Inputs:**

    ```bash
    export HASH_FILE="leaked_hashes.txt"
    export WORDLIST="rockyou.txt"
    export RULES_FILE="rules/best64.rule"
    export OUTPUT_FILE="hashcat_cracked.txt"
    export HASH_MODE=1000
    export SESSION="clientA"

    ```
2.  **Quick Dictionary Attack:**

    ```bash
    hashcat -a 0 -m $HASH_MODE $HASH_FILE $WORDLIST -o $OUTPUT_FILE --session $SESSION

    ```
3.  **Augment with Rule-Based Attack:**

    ```bash
    hashcat -a 0 -m $HASH_MODE $HASH_FILE $WORDLIST -r $RULES_FILE -o $OUTPUT_FILE --session $SESSION

    ```
4.  **Brute-Force Short PINs Only:**

    ```bash
    hashcat -a 3 -m $HASH_MODE $HASH_FILE ?d?d?d?d?d --increment-min=4 --increment-max=6 -o $OUTPUT_FILE

    ```
5.  **Resume/Restore a Cracking Job:**

    ```bash
    hashcat --session $SESSION --restore

    ```
6. **Analyze Results and Identify Trends:**
   * Review output files and debug logs for common patterns, and adjust future rules/masks accordingly.

***

### VI. Pro Tips & Best Practices

* **Identify hash types** precisely—wrong `m` option wastes cycles and yields nothing.
* **Prioritize dictionary/rule/hybrid attacks** before using brute-force.
* **Optimize GPU usage**; use `I` to inspect devices, `w` and `-opencl-threads` for performance tuning.
* **Use session management** (`-session`, `-restore`) for large jobs or cloud cracking.
* **Log cracked passwords and rules** for auditing, reporting, and policy recommendations.
* **Protect data and operate ethically**: Never attack hashes without explicit permission, always follow legal and contractual guidelines.
* **Secure sensitive data**: Safeguard both hash and cracked password files and use results responsibly.

***

This professional Hashcat guide empowers you with flexible, efficient, and high-performance password cracking workflows for audits, red teaming, and forensics.
