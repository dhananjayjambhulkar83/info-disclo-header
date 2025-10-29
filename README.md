# 🛡️ Info Disclo

**Info Disclo** is a lightweight Python tool that scans websites for **information disclosure vulnerabilities** by analyzing HTTP response headers.  
It detects exposed server versions, technologies, and framework details — and provides **mitigation tips** with references to secure the target.

---

## 🚀 Features
- 🔍 Detects header-based info leaks (`Server`, `X-Powered-By`, etc.)
- 💬 Provides mitigation and reference URLs
- 📁 Supports single URL or bulk scan from file
- ⚡ Multithreaded scanning for speed
- 🧩 JSON or text output options
- 🧠 Simple CLI flags for easy control
- 🔐 Optional SSL verification disable for testing

---

## 📦 Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/dhananjayjambhulkar83/info-disclo-header
cd info-disclo-header
```

### 2️⃣ Install dependencies
```bash
pip install -r requirements.txt
```

---

## 🧠 Usage

Scan a single URL:
```bash
python info-disclo.py  https://example.com
```

Scan multiple URLs from a file:
```bash
python info-disclo.py -l targets.txt
```

Show only vulnerable findings:
```bash
python info-disclo.py  https://example.com --only-vuln
```

Save output to JSON:
```bash
python info-disclo.py  https://example.com -o results.json
```

Disable SSL verification (for testing):
```bash
python info-disclo.py  https://example.com --no-verify-ssl
```

Verbose mode:
```bash
python info-disclo.py  https://example.com -v
```

---

## ⚙️ Command-Line Options

| Flag | Description |
|------|--------------|
| `-l`, `--list` | Scan URLs from a file (one per line) |
| `-o`, `--output` | Save output to a file (JSON or TXT) |
| `--only-vuln` | Display only vulnerable findings |
| `--no-verify-ssl` | Disable SSL certificate verification |
| `-v`, `--verbose` | Enable verbose mode for debugging |
| `-t`, `--timeout` | Set request timeout (default: 10s) |
| `--user-agent` | Custom User-Agent for requests |
| `-T`, `--threads` | Number of threads for bulk scans (default: 5) |
| `--json` | Force JSON output to console |
| `-h`, `--help` | Show help message |

---

## 🔍 Checks Performed
- Exposed server and framework versions  
- Leaked `X-Powered-By` and technology info  
- Missing or insecure headers  
- SSL misconfiguration alerts

## v1.1 – 2025-10-29
- Added DNS resolution check (skips unreachable hosts)
- Added automatic SSL fallback (verify=False on failure)
- Added retry logic for temporary network errors
- Disabled SSL warnings for cleaner output
- Improved console messages and stability


