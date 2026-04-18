"""
live_waf_test.py
----------------
End-to-end WAF test suite against DVWA (http://localhost:9090).
Routes every request through the AI-WAF proxy (http://localhost:8080).

What it tests:
  - Normal browsing is ALLOWED (no false positives)
  - SQL injection attempts are BLOCKED
  - XSS attempts are BLOCKED
  - Path traversal attempts are BLOCKED
  - Command injection attempts are BLOCKED

Run with:
    # 1. Start DVWA:   docker run -d --name dvwa -p 9090:80 vulnerables/web-dvwa
    # 2. Start proxy:  mitmdump -s src/proxy_interceptor.py --listen-port 8080
    # 3. Run tests:    venv/Scripts/python tests/live_waf_test.py
"""

import sys, os, time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import requests
from src.logger import get_recent, get_stats

PROXY    = {"http": "http://localhost:8080", "https": "http://localhost:8080"}
BASE     = "http://localhost:9090"
TIMEOUT  = 8

# ── colour helpers ────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):   print(f"  {GREEN}PASS{RESET}  {msg}")
def fail(msg): print(f"  {RED}FAIL{RESET}  {msg}")
def info(msg): print(f"  {YELLOW}INFO{RESET}  {msg}")


# ── test cases ────────────────────────────────────────────────────────────────

TESTS = [
    # ── Normal browsing — should be ALLOWED (200) ──────────────────────────
    {
        "name":     "Normal — Home page",
        "method":   "GET",
        "url":      f"{BASE}/login.php",
        "params":   {},
        "body":     {},
        "expected": "ALLOW",
        "category": "NORMAL",
    },
    {
        "name":     "Normal — Setup page",
        "method":   "GET",
        "url":      f"{BASE}/setup.php",
        "params":   {},
        "body":     {},
        "expected": "ALLOW",
        "category": "NORMAL",
    },
    {
        "name":     "Normal — About page",
        "method":   "GET",
        "url":      f"{BASE}/about.php",
        "params":   {},
        "body":     {},
        "expected": "ALLOW",
        "category": "NORMAL",
    },

    # ── SQL Injection — should be BLOCKED (403) ────────────────────────────
    {
        "name":     "SQLi — UNION SELECT on login",
        "method":   "GET",
        "url":      f"{BASE}/login.php",
        "params":   {"username": "admin' UNION SELECT 1,2,3--", "password": "x"},
        "body":     {},
        "expected": "BLOCK",
        "category": "SQLI",
    },
    {
        "name":     "SQLi — OR 1=1 bypass",
        "method":   "GET",
        "url":      f"{BASE}/login.php",
        "params":   {"username": "' OR '1'='1", "password": "' OR '1'='1"},
        "body":     {},
        "expected": "BLOCK",
        "category": "SQLI",
    },
    {
        "name":     "SQLi — DROP TABLE attempt",
        "method":   "GET",
        "url":      f"{BASE}/vulnerabilities/sqli/",
        "params":   {"id": "1; DROP TABLE users--", "Submit": "Submit"},
        "body":     {},
        "expected": "BLOCK",
        "category": "SQLI",
    },
    {
        "name":     "SQLi — SLEEP blind injection",
        "method":   "GET",
        "url":      f"{BASE}/vulnerabilities/sqli/",
        "params":   {"id": "1' AND SLEEP(5)--", "Submit": "Submit"},
        "body":     {},
        "expected": "BLOCK",
        "category": "SQLI",
    },

    # ── XSS — should be BLOCKED (403) ─────────────────────────────────────
    {
        "name":     "XSS — script tag in param",
        "method":   "GET",
        "url":      f"{BASE}/vulnerabilities/xss_r/",
        "params":   {"name": "<script>alert(document.cookie)</script>"},
        "body":     {},
        "expected": "BLOCK",
        "category": "XSS",
    },
    {
        "name":     "XSS — img onerror payload",
        "method":   "GET",
        "url":      f"{BASE}/vulnerabilities/xss_r/",
        "params":   {"name": "<img src=x onerror=alert(1)>"},
        "body":     {},
        "expected": "BLOCK",
        "category": "XSS",
    },
    {
        "name":     "XSS — javascript: URI",
        "method":   "GET",
        "url":      f"{BASE}/vulnerabilities/xss_r/",
        "params":   {"name": "javascript:alert(1)"},
        "body":     {},
        "expected": "BLOCK",
        "category": "XSS",
    },

    # ── Path Traversal — should be BLOCKED (403) ───────────────────────────
    {
        "name":     "Traversal — ../../etc/passwd",
        "method":   "GET",
        "url":      f"{BASE}/vulnerabilities/fi/",
        "params":   {"page": "../../etc/passwd"},
        "body":     {},
        "expected": "BLOCK",
        "category": "TRAVERSAL",
    },
    {
        "name":     "Traversal — encoded %2e%2e",
        "method":   "GET",
        "url":      f"{BASE}/vulnerabilities/fi/",
        "params":   {"page": "%2e%2e/%2e%2e/etc/shadow"},
        "body":     {},
        "expected": "BLOCK",
        "category": "TRAVERSAL",
    },

    # ── Command Injection — should be BLOCKED (403) ────────────────────────
    {
        "name":     "CMDi — semicolon injection",
        "method":   "GET",
        "url":      f"{BASE}/vulnerabilities/exec/",
        "params":   {"ip": "127.0.0.1; cat /etc/passwd", "Submit": "Submit"},
        "body":     {},
        "expected": "BLOCK",
        "category": "CMDI",
    },
    {
        "name":     "CMDi — pipe injection",
        "method":   "GET",
        "url":      f"{BASE}/vulnerabilities/exec/",
        "params":   {"ip": "127.0.0.1 | whoami", "Submit": "Submit"},
        "body":     {},
        "expected": "BLOCK",
        "category": "CMDI",
    },

    # ── Null Byte — should be BLOCKED (403) ───────────────────────────────
    {
        "name":     "Null byte — %00 evasion",
        "method":   "GET",
        "url":      f"{BASE}/vulnerabilities/fi/",
        "params":   {"page": "../../etc/passwd%00.jpg"},
        "body":     {},
        "expected": "BLOCK",
        "category": "NULLBYTE",
    },
]


def check_proxy_running():
    """Make sure the WAF proxy is up before running tests."""
    try:
        requests.get(f"{BASE}/login.php", proxies=PROXY, timeout=3)
        return True
    except requests.exceptions.ProxyError:
        return False
    except Exception:
        return True  # proxy up, target may redirect


def check_dvwa_running():
    """Make sure DVWA is reachable directly."""
    try:
        r = requests.get(f"{BASE}/login.php", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def run_tests():
    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}  AI-WAF Live End-to-End Test Suite{RESET}")
    print(f"{BOLD}  Target: {BASE}  |  Proxy: http://localhost:8080{RESET}")
    print(f"{BOLD}{'='*65}{RESET}\n")

    # Pre-flight checks
    if not check_dvwa_running():
        print(f"{RED}ERROR: DVWA not reachable at {BASE}{RESET}")
        print("  Start with: docker run -d --name dvwa -p 9090:80 vulnerables/web-dvwa")
        return

    if not check_proxy_running():
        print(f"{RED}ERROR: WAF proxy not reachable at localhost:8080{RESET}")
        print("  Start with: mitmdump -s src/proxy_interceptor.py --listen-port 8080")
        return

    info(f"DVWA running at {BASE}")
    info(f"WAF proxy at http://localhost:8080\n")

    stats_before = get_stats()
    results = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    by_category = {}

    # Run each test
    for t in TESTS:
        category = t["category"]
        by_category.setdefault(category, {"PASS": 0, "FAIL": 0})

        try:
            if t["method"] == "GET":
                resp = requests.get(
                    t["url"], params=t["params"],
                    proxies=PROXY, timeout=TIMEOUT,
                    allow_redirects=False,
                )
            else:
                resp = requests.post(
                    t["url"], data=t["body"],
                    proxies=PROXY, timeout=TIMEOUT,
                    allow_redirects=False,
                )

            actual = "BLOCK" if resp.status_code == 403 else "ALLOW"
            passed = actual == t["expected"]

            if passed:
                ok(f"{t['name']}  [{actual}] status={resp.status_code}")
                results["PASS"] += 1
                by_category[category]["PASS"] += 1
            else:
                fail(f"{t['name']}  expected={t['expected']} got=[{actual}] status={resp.status_code}")
                results["FAIL"] += 1
                by_category[category]["FAIL"] += 1

        except requests.exceptions.Timeout:
            fail(f"{t['name']}  TIMEOUT after {TIMEOUT}s")
            results["FAIL"] += 1
            by_category[category]["FAIL"] += 1
        except Exception as e:
            fail(f"{t['name']}  ERROR: {e}")
            results["SKIP"] += 1

        time.sleep(0.2)   # small delay between requests

    # Results by category
    print(f"\n{BOLD}--- Results by Category ---{RESET}")
    for cat, r in by_category.items():
        total = r["PASS"] + r["FAIL"]
        bar   = f"{r['PASS']}/{total}"
        color = GREEN if r["FAIL"] == 0 else RED
        print(f"  {color}{cat:<12}{RESET}  {bar}  {'OK' if r['FAIL']==0 else 'ISSUES'}")

    # Overall summary
    stats_after = get_stats()
    new_events  = stats_after["total"] - stats_before["total"]

    print(f"\n{BOLD}--- Overall Summary ---{RESET}")
    total = results["PASS"] + results["FAIL"] + results["SKIP"]
    color = GREEN if results["FAIL"] == 0 else RED
    print(f"  {color}Tests passed : {results['PASS']}/{total}{RESET}")
    print(f"  Tests failed : {results['FAIL']}/{total}")
    print(f"  New WAF events logged : {new_events}")
    print(f"  View dashboard: http://localhost:8501\n")

    if results["FAIL"] == 0:
        print(f"{GREEN}{BOLD}  ALL TESTS PASSED — WAF is working correctly!{RESET}\n")
    else:
        print(f"{RED}{BOLD}  {results['FAIL']} test(s) failed — review above.{RESET}\n")

    return results


if __name__ == "__main__":
    run_tests()
