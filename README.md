# 🕵️ Varys (v2)

**Zero-Clone GitHub Security Auditing & Secret Detection Engine**

> *“A very small man can cast a very large shadow.”* — Varys

Varys scans GitHub repositories for exposed secrets, risky artifacts, and dependency signals — **without cloning, without execution, and without blind spots**.

---

## ⚡ Why Varys?

Most security scanners fail by choosing the wrong tradeoff:
- **Full clones** → slow, noisy, bandwidth-heavy.
- **Shallow scans** → fast, but miss deeply nested files.

Varys adapts instead.

- 🔍 Reads **file contents**, not just filenames.
- 🧠 Dynamically switches traversal strategies at depth.
- ⚡ Uses the GitHub API directly — **zero local storage**.

Silent. Fast. Complete.

---

## 🧠 Scanning Modes

### 🚀 QuickScan (Streaming Audit)

```bash
varys quickscan owner/repo

```

* Streams files immediately as they are discovered.
* Minimal latency.
* Designed for CI/CD pipelines and fast feedback.

Traversal proceeds depth-first until `MAX_DEPTH`, then seamlessly switches to hybrid snapshotting.

---

### 📸 Snapshot (Full Repository Audit)

```bash
varys snapshot owner/repo

```

* Builds a **complete in-memory map** of the repository.
* Guarantees coverage of deeply nested directories.
* Designed for compliance, audits, and forensic review.

Snapshot mode prioritizes **completeness over speed**.

---

## ⚙️ Hybrid Traversal Engine

```mermaid
graph TD
    A[Start Scan] --> B{Depth Limit Reached?}
    B -- No --> C[Fetch File Content]
    C --> D[Run Regex/Signatures]
    D --> E[Next File]
    E --> B
    B -- Yes --> F[🛑 SWITCH STRATEGY]
    F --> G[📸 Git Tree Snapshot]
    G --> H[Fetch Full Subtree JSON]
    H --> I[Parse All Nested Files in Memory]
    I --> J[End Scan]
    
    style F fill:#f96,stroke:#333,stroke-width:2px
    style G fill:#bbf,stroke:#333,stroke-width:2px

```

Varys dynamically adapts mid-scan:

1. Traverses directories using GitHub’s Contents API.
2. Upon reaching `MAX_DEPTH`:
* Instantly switches to a **Git Tree Snapshot**.
* Retrieves entire subtrees in a single API call.


3. Continues scanning without restarting or missing context.

**Result:** No blind spots. No wasted API calls.

---

## 🛡️ Detection Capabilities

### 🔑 Secret Detection

* Cloud credentials (AWS, GCP, Azure, etc.)
* Private tokens and high-risk secrets.
* Regex-based, deterministic matching.

### 📂 Risky File Signatures

* Configuration artifacts: `.env`, `.pypirc`, `.npmrc`.
* Identity files: `id_rsa`, `.pem`, `.key`.
* Fully customizable patterns via `signatures.json`.

### 📦 Dependency Surface Analysis

* Parses `requirements.txt` and `package.json`.
* Flags known vulnerable libraries (signature-based).
* CVE-mapping ready.

---

## 🧭 Operational Scope & Safety

Varys is a **static repository auditing tool**.

* **Read-Only:** Operates strictly via the GitHub API.
* **Zero-Trace:** No code is executed; no files are written to disk (except results).
* **Passive:** Does not exploit vulnerabilities or perform active probing.
* **Rate-Limit Aware:** Automatically handles GitHub API 429 backoff.

Its purpose is **visibility**, not intrusion.

---

## 🛠️ Installation

**Prerequisites:** Python 3.9+

### Recommended (Development / Active Work)

```bash
git clone [https://github.com/your-username/varys.git](https://github.com/your-username/varys.git)
cd varys
pip install -e .

```

> **Note:** This package installs the CLI command `varys`.
> `pip install -e .` installs it in **editable mode**, allowing you to modify source code without reinstalling.

---

### Environment Setup

Create a `.env` file in the root directory:

```env
GITHUB_TOKEN=ghp_your_personal_access_token

```

**Required Token Scopes:**

* **Public Repos:** `public_repo` (or no scope if rate limits allow).
* **Private Repos:** `repo` (Full control of private repositories).

*⚠️ Never commit your `.env` file. Varys will detect it if you do.*

---

## ▶️ Usage

Once installed, the `varys` command is available globally.

**Full Snapshot:**

```bash
varys snapshot owner/repo

```

**Quick Audit:**

```bash
varys quickscan owner/repo

```

Authentication is automatically pulled from the `GITHUB_TOKEN` environment variable.

---

## ⚙️ Configuration

### `policy.json` — Traversal Control

```json
{
  "ignore_dirs": [".git", "node_modules", "dist", "__pycache__"],
  "max_depth": 5
}

```

Once `max_depth` is reached, Varys automatically switches to snapshot traversal to save API calls.

---

### `signatures.json` — Detection Rules

* `vulnerability_patterns`: Regex-based secret detection.
* `file_signatures`: Sensitive filenames/extensions.
* `dependency_files`: Dependency manifests to parse.

Deterministic. Extensible. Transparent.

---

## 📊 Output

Varys provides **real-time console output** and a detailed JSON artifact.

**Console:**

```text
> 🔍 Scanning src/auth...
> 🚨 [CRITICAL] AWS Key found in deploy.py
> ⚡ Depth limit reached. Switching to Snapshot Mode...

```

**Artifact (`scan_results.json`):**

```json
{
  "rule_id": "aws_key",
  "name": "AWS Access Key",
  "file": "src/config/deploy.py",
  "risk": "CRITICAL",
  "description": "Potential AWS Access Key ID detected",
  "repository": "owner/repo",
  "evidence": "AKIAIOSFODNN7EXAMPLE",
  "timestamp": "2023-10-27T14:30:00"
}

```

Designed for humans, CI systems, and post-incident analysis.

---

## 🤝 Contributing

Varys improves through sharp eyes.

* Add detection signatures.
* Improve false-positive reduction.
* Optimize traversal logic.

Pull requests welcome.

**License:** MIT

```

```