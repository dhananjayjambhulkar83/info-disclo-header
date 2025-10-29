#!/usr/bin/env python3
import argparse
import requests
import re
import sys
import urllib3
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================
# Regex patterns
# ==========================
VERSION_RE = re.compile(r"\b\d+(?:\.\d+){0,}\b")
PROD_SLASH_VER_RE = re.compile(r"[A-Za-z0-9\-]+/[0-9][A-Za-z0-9\.\-_]*")
LEADING_V_RE = re.compile(r"\bv\d+(?:\.\d+)*\b", re.IGNORECASE)

# ==========================
# Headers to inspect
# ==========================
HEADERS_TO_CHECK = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Powered-By-Plesk",
]

# ==========================
# Mitigation tips & refs
# ==========================
MITIGATION_TIPS = [
    "Avoid disclosing version numbers in headers like Server or X-Powered-By.",
    "Use a reverse proxy (e.g., Nginx) or WAF to strip/modify upstream headers.",
    "Regularly update server software to patch known vulnerabilities.",
    "Review web server configuration (e.g., Apache: ServerTokens Prod, Nginx: server_tokens off).",
    "For PHP: set expose_php = Off in php.ini to remove X-Powered-By: PHP/x.y.z"
]

REFERENCES = [
    "https://owasp.org/www-project-secure-headers/",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server",
    "https://httpd.apache.org/docs/current/mod/core.html#servertokens",
    "https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens",
    "https://www.php.net/manual/en/security.php#security.expose-php"
]

# ==========================
# Detection helpers
# ==========================
def has_version_info(value: str) -> (bool, str):
    """Return (is_version_present, evidence_string)"""
    if not value:
        return False, ""
    for regex in (PROD_SLASH_VER_RE, VERSION_RE, LEADING_V_RE):
        match = regex.search(value)
        if match:
            return True, match.group(0)
    return False, ""

# ==========================
# Scan single target
# ==========================
def scan_target(url, verify_ssl=True, show_mitigation=False, only_vuln=False):
    import socket, time

    # --- Step 1: DNS check ---
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        socket.gethostbyname(domain)
    except socket.error:
        # When only_vuln is requested, skip noisy DNS error output
        if not only_vuln:
            print(f"\n=== {url} ===")
            print(f"[⚠️] Skipping {url} — DNS not resolving.")
        return

    # --- Step 2: Attempt request with retry + SSL fallback ---
    response = None
    for attempt in range(2):
        try:
            response = requests.get(url, timeout=10, verify=verify_ssl)
            break
        except requests.exceptions.SSLError:
            if verify_ssl:
                if not only_vuln:
                    print(f"\n=== {url} ===")
                    print("[⚠️] SSL verification failed, retrying with verify=False...")
                try:
                    response = requests.get(url, timeout=10, verify=False)
                    break
                except Exception:
                    pass
        except requests.exceptions.RequestException as e:
            # Only emit request error messages when not in only_vuln mode
            if not only_vuln:
                if attempt == 0:
                    print(f"\n=== {url} ===")
                    print(f"[ERROR] Request failed ({e}). Retrying in 2s...")
                    time.sleep(2)
                else:
                    print(f"\n=== {url} ===")
                    print(f"[ERROR] Request failed: {e}")
            else:
                # if only_vuln: don't print errors; retry once silently
                if attempt == 0:
                    time.sleep(2)
            # continue loop to retry or finish
    if not response:
        return

    # --- Step 3: Analyze headers ---
    vulnerable = False
    findings = []

    for h in HEADERS_TO_CHECK:
        val = response.headers.get(h)
        if val is None:
            continue
        is_ver, evidence = has_version_info(val)
        findings.append((h, val, is_ver, evidence))
        if is_ver:
            vulnerable = True

    # If only showing vulnerable targets and none found, skip output
    if only_vuln and not vulnerable:
        return

    # Print header block for vulnerable targets, or for full mode prints everything
    print(f"\n=== {url} ===")

    if not findings:
        if not only_vuln:
            print("No inspected fingerprinting headers present in response.")
    else:
        for h, val, is_ver, evidence in findings:
            if is_ver:
                print(f"[VULNERABLE] {h}: {val}  (evidence: {evidence})")
            elif not only_vuln:
                print(f"[OK]         {h}: {val}")

    # Print summary only when not in only_vuln mode or when vulnerable (so user sees 'Yes')
    print(f"\nVULNERABLE: {'Yes' if vulnerable else 'No'}")

    # --- Step 4: Optional mitigation ---
    if show_mitigation and vulnerable:
        print("\nMitigation tips:")
        for t in MITIGATION_TIPS:
            print(f" - {t}")
        print("\nReferences:")
        for r in REFERENCES:
            print(f" - {r}")

# ==========================
# CLI / main
# ==========================
def main():
    parser = argparse.ArgumentParser(
        description="Check for version disclosure in HTTP response headers (Server, X-Powered-By, etc.)"
    )
    parser.add_argument("target", nargs="?", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-f", "--file", help="File containing list of targets (one per line)")
    parser.add_argument("--no-verify", action="store_true", help="Skip SSL certificate verification")
    parser.add_argument("--show-mitigation", action="store_true", help="Show mitigation tips and references for vulnerable targets")
    parser.add_argument("--only-vuln", action="store_true", help="Show only vulnerable targets (skip safe ones and suppress non-vuln errors)")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    args = parser.parse_args()

    if not args.target and not args.file:
        parser.print_help()
        sys.exit(1)

    verify_ssl = not args.no_verify

    targets = []
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                targets = [line.strip() for line in fh if line.strip()]
        except FileNotFoundError:
            print(f"[ERROR] File not found: {args.file}")
            sys.exit(1)
    else:
        targets = [args.target]

    # Normalize targets
    normalized = []
    for t in targets:
        if not t.startswith("http://") and not t.startswith("https://"):
            t = "https://" + t
        normalized.append(t)

    print("\n🔍 Starting Info Disclosure Scan...\n")

    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = [
            exe.submit(scan_target, t, verify_ssl, args.show_mitigation, args.only_vuln)
            for t in normalized
        ]
        for f in futures:
            f.result()

    print("\n[*] Scan completed. Check results above.\n")

if __name__ == "__main__":
    main()
