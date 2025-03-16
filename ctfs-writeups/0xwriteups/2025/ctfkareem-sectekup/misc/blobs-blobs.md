# Blobs Blobs

### **Challenge Details:**

* **Name**: blobs blobs
* **Points**: 500
* **Solves**: 0 (at the time of solving)
* **Author**: chmxii
* **Link**: `http://51.77.140.155:7001/v2/`
* **Category**: Misc

### **Description:**

\
The challenge provided a URL pointing to a Docker registry (`http://51.77.140.155:7001/v2/`) with no additional hints beyond the title “blobs blobs.” With 500 points and zero solves, it hinted at a tricky but rewarding task—likely involving Docker image layers, blob extraction, and flag hunting.

### **Step 1: Recon**

Firing up the URL in a browser returned a 404 or timeout (server was down by March 15, 2025), but the `/v2/` endpoint screamed Docker Registry API v2. Docker registries store images as manifests and blobs, accessible via endpoints like `/_catalog` (repository list), `/<repo>/tags/list` (tags), and `/<repo>/blobs/<digest>` (layer data). The title “blobs blobs” pointed straight to these blobs—compressed `.tar.gz` files containing image layers.

### **Step 2: Script Setup**

I crafted a Python script to automate the process:

* **Tools**: `requests` for HTTP, `tarfile` for extraction, `re` for flag regex, `ThreadPoolExecutor` for parallel blob processing.
* **Flow**:
  1. Hit `/_catalog` to find repositories (looking for “project”).
  2. Fetch tags from `/project/tags/list`.
  3. Grab manifests from `/project/manifests/<tag>` to extract layer digests.
  4. Download blobs from `/project/blobs/<digest>`.
  5. Extract and search for the flag.

Headers were set to `{"Accept": "application/vnd.docker.distribution.manifest.v2+json"}` to ensure v2 manifest compatibility.

### **Step 3: Execution**

Running the script (`blobs.py`) hit the registry and pulled multiple blobs. The log output showed the action:

```log
2025-03-15 15:05:08,560 - INFO - Extracted to extracted_sha256_fe4e02b3c44100b9559975aa0d5803c62e1c4814ff269ed129150d748aa558a5
2025-03-15 15:05:08,562 - INFO - Checking file: extracted_sha256_fe4e02b3c44100b9559975aa0d5803c62e1c4814ff269ed129150d748aa558a5\secret.txt
2025-03-15 15:05:08,564 - INFO - Flag found in extracted_sha256_fe4e02b3c44100b9559975aa0d5803c62e1c4814ff269ed129150d748aa558a5\secret.txt: 
SENSITIVE
2025-03-15 15:05:08,573 - INFO - Checking file: extracted_sha256_384b09fd767da2de4e7b3c655d9c3f00ac3aea6609c3bc6a50edea896a7ae14d\flag.txt
2025-03-15 15:05:08,574 - INFO - Flag found in extracted_sha256_384b09fd767da2de4e7b3c655d9c3f00ac3aea6609c3bc6a50edea896a7ae14d\flag.txt: 
Securinets{w3ll_D0n3_Pull1ng_th3_r1gh7_fl4g}
```

* **Blob 1**: Digest `sha256:fe4e02b...` yielded `secret.txt` with `SENSITIVE`— a decoy.
* **Blob 2**: Digest `sha256:384b09f...` hit `flag.txt`
* **404 Error**: Some blobs (e.g., `sha256:5ed05fe...`) weren’t found, but we didn’t need them.

### **Step 4: Flag Extraction**

The regex `Securinets{[A-Za-z0-9_!@#$%^&*+-]+}` locked onto the leetspeak flag. The script parallel-processed blobs, extracted `.tar.gz` files, and scanned every file—not just `flag.txt`—ensuring no stone was left unturned. Python 3.14’s tarfile warning was noted but irrelevant (default filtering didn’t block us).

### **Step 5: Verification**

Submitted `Securinets{w3ll_D0n3_Pull1ng_th3_r1gh7_fl4g}`—it fit the Securinets format, matched the challenge’s vibe (“pulling” blobs), and cleared the scoreboard. Boom—solved!

**Tools Used:**

* Python 3.14
* Libraries: `requests`, `tarfile`, `re`, `logging`, `concurrent.futures`
* Script: `blobs.py`

**Lessons Learned:**

* Docker registries are goldmines—dig into blobs, not just manifests.
* Automation with retries and parallelism is clutch for flaky servers.
* Always check all files—decoys like `SENSITIVE` can throw you off.

***

### Final Script  enhanced w/ Ai

```python
import requests
import tarfile
import io
import os
import re
import logging
from datetime import datetime
import shutil
from concurrent.futures import ThreadPoolExecutor

# Setup logging
log_file = f"writeup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_file), logging.StreamHandler()]
)

# Configuration
BASE_URL = "http://51.77.140.155:7001/v2/"
GET_REPOS_URL = f"{BASE_URL}_catalog"
REPO = "project"
HEADERS = {"Accept": "application/vnd.docker.distribution.manifest.v2+json"}
CLEANUP = True  # Toggle cleanup
MAX_RETRIES = 3
TIMEOUT = 10

# Fallback digest (for testing if server’s down)
FALLBACK_DIGEST = "sha256:deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"

def find_repo(base_url):
    """Dynamically find the 'project' repository."""
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(GET_REPOS_URL, headers=HEADERS, timeout=TIMEOUT)
            response.raise_for_status()
            repos = response.json().get("repositories", [])
            logging.info(f"Repositories: {repos}")
            for repo in repos:
                if "project" in repo.lower():
                    logging.info(f"Selected repository: {repo}")
                    return repo
            logging.warning("No 'project' repository found.")
            return None
        except requests.RequestException as e:
            logging.error(f"Attempt {attempt + 1}/{MAX_RETRIES} - Failed to fetch catalog: {e}")
            if attempt == MAX_RETRIES - 1:
                logging.error("Max retries reached. Using default repo 'project'.")
                return REPO
            time.sleep(2)

def find_tags(base_url, repo):
    """Fetch all tags for the repository."""
    tags_url = f"{base_url}{repo}/tags/list"
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(tags_url, headers=HEADERS, timeout=TIMEOUT)
            response.raise_for_status()
            tags = response.json().get("tags", [])
            logging.info(f"Tags for {repo}: {tags}")
            return tags
        except requests.RequestException as e:
            logging.error(f"Attempt {attempt + 1}/{MAX_RETRIES} - Failed to fetch tags: {e}")
            if attempt == MAX_RETRIES - 1:
                logging.error("Max retries reached. Returning empty tags.")
                return []

def find_digests(base_url, repo):
    """Fetch all digests across all tags."""
    tags = find_tags(base_url, repo)
    if not tags:
        logging.warning("No tags found. Using fallback digest.")
        return [FALLBACK_DIGEST]
    
    all_digests = set()
    for tag in tags:
        for attempt in range(MAX_RETRIES):
            try:
                manifest_url = f"{base_url}{repo}/manifests/{tag}"
                logging.info(f"Fetching manifest: {manifest_url}")
                response = requests.get(manifest_url, headers=HEADERS, timeout=TIMEOUT)
                response.raise_for_status()
                manifest = response.json()
                for layer in manifest.get("layers", []):
                    digest = layer.get("digest")
                    if digest:
                        all_digests.add(digest)
                break
            except requests.RequestException as e:
                logging.error(f"Attempt {attempt + 1}/{MAX_RETRIES} - Failed to fetch manifest for {tag}: {e}")
                if attempt == MAX_RETRIES - 1:
                    logging.error(f"Skipping tag {tag} after max retries.")
    
    digests = list(all_digests)
    logging.info(f"All unique digests: {digests}")
    return digests if digests else [FALLBACK_DIGEST]

def extract_flag(content):
    """Extract flag with flexible regex."""
    patterns = [
        r"(Securinets\{[A-Za-z0-9_!@#$%^&*+-]+\})",  # Broader CTF flag format
        r"flag\{[A-Za-z0-9_]+\}",
        r"[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}"  # UUID-style
    ]
    for pattern in patterns:
        match = re.search(pattern, content)
        if match:
            return match.group(0)
    return content.strip() if content else None

def process_blob(base_url, repo, digest):
    """Fetch, extract, and search a blob for the flag."""
    blob_url = f"{base_url}{repo}/blobs/{digest}"
    logging.info(f"Processing blob: {blob_url}")
    
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(blob_url, headers=HEADERS, timeout=TIMEOUT)
            response.raise_for_status()
            break
        except requests.RequestException as e:
            logging.error(f"Attempt {attempt + 1}/{MAX_RETRIES} - Failed to fetch {blob_url}: {e}")
            if attempt == MAX_RETRIES - 1:
                logging.error(f"Skipping {digest} after max retries.")
                return None
    
    # Save blob
    filename = f"{digest.replace('sha256:', 'sha256_')}.tar.gz"
    with open(filename, "wb") as f:
        f.write(response.content)
    logging.info(f"Saved blob to {filename}")

    # Extract and search
    extract_dir = f"extracted_{digest.replace('sha256:', 'sha256_')}"
    os.makedirs(extract_dir, exist_ok=True)
    try:
        with tarfile.open(filename, "r:gz") as tar:
            tar.extractall(extract_dir)
            logging.info(f"Extracted to {extract_dir}")
            
            # Search all files
            for root, _, files in os.walk(extract_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    logging.info(f"Checking file: {file_path}")
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            flag = extract_flag(content)
                            if flag:
                                logging.info(f"Flag found in {file_path}: {flag}")
                                return flag
                    except Exception as e:
                        logging.warning(f"Failed to read {file_path}: {e}")
    except tarfile.TarError as e:
        logging.error(f"Failed to extract {filename}: {e}")
    
    # Cleanup
    if CLEANUP:
        try:
            os.remove(filename)
            shutil.rmtree(extract_dir, ignore_errors=True)
            logging.info(f"Cleaned up {filename} and {extract_dir}")
        except Exception as e:
            logging.error(f"Cleanup failed: {e}")
    
    return None

def main():
    """Fully automated flag extraction."""
    logging.info("Starting blobs blobs challenge solver.")
    
    repo = find_repo(BASE_URL)
    if not repo:
        logging.error("Aborting: No repository found.")
        return
    
    digests = find_digests(BASE_URL, repo)
    if not digests:
        logging.error("Aborting: No digests found.")
        return
    
    # Process blobs in parallel
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_digest = {executor.submit(process_blob, BASE_URL, repo, digest): digest for digest in digests}
        for future in future_to_digest:
            flag = future.result()
            if flag:
                logging.info(f"Challenge solved! Final flag: {flag}")
                return
    
    logging.warning("No flag found in any blobs.")
    logging.info("Analysis complete.")

if __name__ == "__main__":
    import time  # Imported here for sleep in retries
    main()

# FLAG : Securinets{w3ll_D0n3_Pull1ng_th3_r1gh7_fl4g}
```

***



***

