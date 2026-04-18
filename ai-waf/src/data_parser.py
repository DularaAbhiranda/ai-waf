"""
data_parser.py
--------------
Parses the CSIC 2010 raw HTTP text files into a pandas DataFrame.

Each request in the file is wrapped like:
    Start - Id: 1234
    class: Attack   (or Valid)
    GET http://... HTTP/1.1
    Header: value
    ...
    [blank line]
    body or null
    [blank line]
    End - Id: 1234
"""

import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import pandas as pd


# ── paths relative to project root (ai-waf/) ─────────────────────────────────
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
ANOMALOUS_FILE = DATA_DIR / "anomalousTrafficTest.txt"
NORMAL_FILE    = DATA_DIR / "normalTrafficTrain.txt"


def _parse_block(block: str) -> dict | None:
    """Parse a single Start…End request block into a dict."""
    lines = block.strip().splitlines()
    if len(lines) < 3:
        return None

    record = {}

    # ── label ─────────────────────────────────────────────────────────────────
    class_line = next((l for l in lines if l.startswith("class:")), None)
    if class_line is None:
        return None
    record["label"] = 1 if "Attack" in class_line else 0

    # ── request line  (GET/POST url HTTP/1.1) ─────────────────────────────────
    req_line = next(
        (l for l in lines if re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s", l)),
        None,
    )
    if req_line is None:
        return None

    parts = req_line.split()
    record["method"] = parts[0]
    raw_url = parts[1] if len(parts) > 1 else ""
    record["raw_url"] = raw_url

    parsed = urlparse(raw_url)
    record["path"]         = parsed.path
    record["query_string"] = parsed.query

    # ── headers ───────────────────────────────────────────────────────────────
    headers = {}
    in_headers = False
    body_lines = []
    past_blank = False

    for line in lines:
        if re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s", line):
            in_headers = True
            continue
        if in_headers:
            if line.strip() == "":
                past_blank = True
                in_headers = False
                continue
            if ":" in line:
                key, _, val = line.partition(":")
                headers[key.strip().lower()] = val.strip()
        elif past_blank:
            if line.startswith("End -"):
                break
            body_lines.append(line)

    record["headers"]        = headers
    record["content_length"] = int(headers.get("content-length", 0) or 0)
    record["has_cookie"]     = int("cookie" in headers)
    record["content_type"]   = headers.get("content-type", "")

    # ── body ──────────────────────────────────────────────────────────────────
    body = " ".join(body_lines).strip()
    record["body"] = "" if body.lower() == "null" else body

    return record


def parse_file(filepath: str | Path) -> list[dict]:
    """Split a file into blocks and parse each one."""
    text = Path(filepath).read_text(encoding="latin-1", errors="replace")
    # split on "Start - Id:" boundaries
    blocks = re.split(r"Start\s*-\s*Id:\s*\d+", text)
    records = []
    for block in blocks:
        r = _parse_block(block)
        if r:
            records.append(r)
    return records


def load_dataset() -> pd.DataFrame:
    """Load both files and return a single combined DataFrame."""
    print(f"Parsing normal traffic ... ({NORMAL_FILE.name})")
    normal = parse_file(NORMAL_FILE)
    print(f"  -> {len(normal):,} records")

    print(f"Parsing anomalous traffic ... ({ANOMALOUS_FILE.name})")
    anomalous = parse_file(ANOMALOUS_FILE)
    print(f"  -> {len(anomalous):,} records")

    df = pd.DataFrame(normal + anomalous)
    print(f"\nTotal: {len(df):,} records  |  "
          f"Normal: {(df.label==0).sum():,}  |  "
          f"Attack: {(df.label==1).sum():,}")
    return df


if __name__ == "__main__":
    df = load_dataset()
    print(df.head())
    print(df.dtypes)
