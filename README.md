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