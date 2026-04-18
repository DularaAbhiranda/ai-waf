"""
proxy_interceptor.py
--------------------
mitmproxy addon that intercepts every HTTP request, extracts features,
runs the ML model, and either allows or blocks the request.

How the flow works:
  Browser / curl
      │
      ▼  (HTTP proxy at 0.0.0.0:8080)
  mitmproxy  ──►  this addon (request hook)
      │                │
      │         [feature extraction]
      │                │
      │         [model.predict_proba]
      │                │
      │         score >= THRESHOLD?
      │           YES ──► return 403 response (BLOCK)
      │           NO  ──► forward to target server (ALLOW)
      ▼
  Target server (localhost:80 or any upstream)

Run with:
    cd ai-waf/
    venv/Scripts/activate
    mitmdump -s src/proxy_interceptor.py --listen-port 8080

Test with:
    curl -x http://localhost:8080 "http://example.com/page?id=1 UNION SELECT * FROM users"
"""

import re
import sys
import urllib.parse
from pathlib import Path
from typing import Optional

# Ensure the project root (ai-waf/) is on sys.path so `src.*` imports work
# whether this file is run directly, via pytest, or loaded by mitmproxy.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import joblib
import numpy as np

# mitmproxy types — only available when running inside mitmproxy
try:
    from mitmproxy import http, ctx
except ImportError:
    # Allow importing this module outside mitmproxy for testing
    http = None  # type: ignore
    ctx  = None  # type: ignore

from src.config import MODEL_PATH, SCALER_PATH, THRESHOLD
from src.logger import log_event

# ── regex patterns (same as feature_extractor.py) ────────────────────────────
_SQL_PAT = re.compile(
    r"(select\b|union\b|insert\b|update\b|delete\b|drop\b|alter\b|"
    r"exec\b|execute\b|or\s+1\s*=\s*1|'--|\bxp_|information_schema|"
    r"sleep\s*\(|benchmark\s*\()",
    re.IGNORECASE,
)
_XSS_PAT = re.compile(
    r"(<script|javascript:|vbscript:|onerror\s*=|onload\s*=|"
    r"alert\s*\(|document\.cookie|<iframe|<img[^>]+src\s*=\s*[\"']?javascript)",
    re.IGNORECASE,
)
_TRAVERSAL_PAT = re.compile(r"(\.\./|\.\.\\|%2e%2e|%252e)", re.IGNORECASE)
_CMD_PAT        = re.compile(r"(;|\||`|%7c|%60|\$\(|&&|\|\|)", re.IGNORECASE)
_NULL_PAT       = re.compile(r"%00")
_SPECIAL_CHARS  = re.compile(r"[<>'\";()|=]")


def _decode(text: str) -> str:
    try:
        return urllib.parse.unquote_plus(text)
    except Exception:
        return text


def extract_features_from_request(
    method: str,
    url: str,
    path: str,
    query: str,
    body: str,
    headers: dict,
) -> list[float]:
    """
    Extract the same 15 features that were used during training.
    Order MUST match the columns in processed.csv (minus 'label').
    """
    combined = _decode(url + " " + body)

    content_length = 0
    try:
        content_length = int(headers.get("content-length", 0) or 0)
    except (ValueError, TypeError):
        pass

    features = [
        # method
        1.0 if method.upper() == "POST" else 0.0,
        # url / path  — must match feature_extractor.py column order exactly
        float(len(url)),                                       # url_length
        float(path.count("/")),                                # path_depth (path only, not full url)
        float(len(query)),                                     # query_length
        float(len(query.split("&")) if query else 0),          # num_query_params
        # body
        float(len(body)),                                      # body_length
        float(len(body.split("&")) if body else 0),            # num_body_params
        # headers
        float(content_length),                                 # content_length
        float(1 if "cookie" in {k.lower() for k in headers} else 0),  # has_cookie
        # attack patterns
        float(1 if _SQL_PAT.search(combined) else 0),          # has_sql
        float(1 if _XSS_PAT.search(combined) else 0),          # has_xss
        float(1 if _TRAVERSAL_PAT.search(combined) else 0),    # has_path_traversal
        float(1 if _CMD_PAT.search(combined) else 0),          # has_cmd_injection
        float(1 if _NULL_PAT.search(combined) else 0),         # has_null_byte
        float(len(_SPECIAL_CHARS.findall(combined))),           # special_char_count
    ]
    return features


def _blocked_response(flow: "http.HTTPFlow", score: float) -> None:
    """Replace the flow response with a 403 Forbidden."""
    flow.response = http.Response.make(
        403,
        f"Blocked by AI-WAF (score={score:.3f})\n",
        {"Content-Type": "text/plain"},
    )


class WafAddon:
    """
    mitmproxy addon class.
    mitmproxy calls `request(flow)` for every intercepted HTTP request.
    """

    def __init__(self):
        self.model  = None
        self.scaler = None
        self._load_model()

    def _load_model(self):
        model_path  = Path(MODEL_PATH)
        scaler_path = Path(SCALER_PATH)

        if not model_path.exists() or not scaler_path.exists():
            raise FileNotFoundError(
                f"Model files not found.\n"
                f"  Expected: {model_path}\n"
                f"           {scaler_path}\n"
                f"  Run: python -m src.trainer  to train first."
            )

        self.model  = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        print(f"[AI-WAF] Model loaded from {model_path}")

    def request(self, flow: "http.HTTPFlow") -> None:
        """Called by mitmproxy for every HTTP request."""
        req       = flow.request
        method    = req.method
        url       = req.pretty_url
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else ""

        # Parse path and query robustly — mitmproxy's query_string attribute
        # varies across versions; always parse from the URL to be safe.
        parsed = urllib.parse.urlparse(url)
        path   = parsed.path
        query  = parsed.query   # everything after '?', empty string if none

        # Body: use text for decoded string, fall back to empty
        try:
            body = req.text or ""
        except Exception:
            body = ""

        headers = dict(req.headers)

        # ── extract features ──────────────────────────────────────────────────
        feats   = extract_features_from_request(method, url, path, query, body, headers)
        feats_s = self.scaler.transform([feats])
        score   = float(self.model.predict_proba(feats_s)[0][1])

        # Debug: print key feature values to mitmproxy console
        print(f"[AI-WAF] url_len={int(feats[1])} path_depth={int(feats[2])} "
              f"q_len={int(feats[3])} body_len={int(feats[5])} "
              f"special={int(feats[14])} score={score:.3f}")

        # ── pattern-override safety rule ──────────────────────────────────────
        # If ZERO attack patterns are present and special chars are minimal,
        # ALLOW regardless of ML score. This prevents false positives on
        # out-of-distribution URLs (e.g., DVWA .php pages) where the model
        # may score high due to training distribution mismatch (CSIC 2010).
        pattern_flags  = feats[9:14]  # has_sql, has_xss, has_traversal, has_cmd, has_null
        special_chars  = feats[14]    # special_char_count

        if sum(pattern_flags) == 0 and special_chars < 3:
            # No attack patterns detected — override ML score and ALLOW
            label  = 0
            action = "ALLOW"
            print(f"[AI-WAF] OVERRIDE -> ALLOW (no attack patterns, special_chars={int(special_chars)})")
        else:
            label  = 1 if score >= THRESHOLD else 0
            action = "BLOCK" if label == 1 else "ALLOW"

        # ── log ───────────────────────────────────────────────────────────────
        log_event(method, url, path, score, label, action, client_ip)

        # ── enforce ───────────────────────────────────────────────────────────
        if action == "BLOCK":
            _blocked_response(flow, score)
            try:
                ctx.log.warn(f"[AI-WAF] BLOCKED  {method} {url[:80]}  score={score:.3f}")
            except Exception:
                pass
        else:
            try:
                ctx.log.info(f"[AI-WAF] ALLOWED  {method} {url[:80]}  score={score:.3f}")
            except Exception:
                pass


# ── mitmproxy entry point ─────────────────────────────────────────────────────
def load_addon():
    return WafAddon()


# mitmproxy discovers addons via the module-level `addons` list
addons = [WafAddon()]


# ── standalone test (run directly with: python -m src.proxy_interceptor) ──────
if __name__ == "__main__":
    import joblib

    addon = WafAddon()

    # NOTE: Model is trained on CSIC 2010 (specific e-commerce app).
    # Use exact URL patterns from the training data for reliable test results.
    test_requests = [
        # (method, url, path, query, body, headers, expected)
        # Normal — exact URL pattern that appears in training data
        ("GET",  "http://localhost:8080/tienda1/publico/vaciar.jsp?B2=Vaciar+carrito",
                 "/tienda1/publico/vaciar.jsp", "B2=Vaciar+carrito", "",
                 {"cookie": "JSESSIONID=ABC"}, "ALLOW"),
        ("GET",  "http://localhost:8080/tienda1/publico/vaciar.jsp?B2=Vaciar+carrito",
                 "/tienda1/publico/vaciar.jsp", "B2=Vaciar+carrito", "",
                 {"cookie": "JSESSIONID=DEF"}, "ALLOW"),
        # Attack traffic
        ("GET",  "http://localhost:8080/tienda1/publico/anadir.jsp?id=2' UNION SELECT * FROM users--",
                 "/tienda1/publico/anadir.jsp", "id=2' UNION SELECT * FROM users--", "", {}, "BLOCK"),
        ("POST", "http://localhost:8080/tienda1/publico/autenticar.jsp",
                 "/tienda1/publico/autenticar.jsp", "", "login=admin&pwd=<script>alert(1)</script>",
                 {"content-length": "50"}, "BLOCK"),
        ("GET",  "http://localhost:8080/tienda1/publico/../../etc/passwd",
                 "/tienda1/publico/../../etc/passwd", "", "", {}, "BLOCK"),
    ]

    print(f"{'Method':<6}  {'Action':<6}  {'Score':<6}  {'Expected':<8}  URL")
    print("-" * 75)
    for method, url, path, query, body, hdrs, expected in test_requests:
        feats   = extract_features_from_request(method, url, path, query, body, hdrs)
        feats_s = addon.scaler.transform([feats])
        score   = float(addon.model.predict_proba(feats_s)[0][1])
        action  = "BLOCK" if score >= THRESHOLD else "ALLOW"
        ok      = "OK" if action == expected else "FAIL"
        print(f"{method:<6}  {action:<6}  {score:.3f}   {expected:<8}  {ok}  {url[:60]}")
