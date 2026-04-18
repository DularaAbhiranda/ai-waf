"""
feature_extractor.py
--------------------
Turns a parsed DataFrame (from data_parser.py) into a numeric feature matrix
ready for scikit-learn.

Features extracted
──────────────────
URL / path based:
  url_length          total length of raw URL
  path_depth          number of path segments (count of '/')
  query_length        length of query string
  num_query_params    number of & separated params in query string

Body based:
  body_length         length of POST body
  num_body_params     number of & separated params in body

Method:
  method_is_post      1 if POST, 0 otherwise

Header based:
  content_length      value of Content-Length header
  has_cookie          1 if Cookie header present

Attack pattern flags (regex on url + body combined):
  has_sql             SELECT|UNION|INSERT|UPDATE|DELETE|DROP|OR 1=1 etc.
  has_xss             <script|javascript:|onerror=|alert( etc.
  has_path_traversal  ../ or %2e%2e
  has_cmd_injection   ; pipe backtick or encoded equivalents
  has_null_byte       %00
  has_special_chars   count of dangerous chars (< > ' " ; ( ) = |)
"""

import re
import urllib.parse
from pathlib import Path

import pandas as pd


# ── regex patterns ────────────────────────────────────────────────────────────
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
_CMD_PAT = re.compile(r"(;|\||`|%7c|%60|\$\(|&&|\|\|)", re.IGNORECASE)
_NULL_PAT = re.compile(r"%00")
_SPECIAL_CHARS = re.compile(r"[<>'\";()|=]")


def _decode(text: str) -> str:
    """URL-decode a string for pattern matching."""
    try:
        return urllib.parse.unquote_plus(text)
    except Exception:
        return text


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Takes the raw parsed DataFrame and returns a DataFrame of numeric features
    + the label column. Original string columns are dropped.
    """
    feats = pd.DataFrame()

    # ── method ────────────────────────────────────────────────────────────────
    feats["method_is_post"] = (df["method"].str.upper() == "POST").astype(int)

    # ── URL / path ────────────────────────────────────────────────────────────
    feats["url_length"]       = df["raw_url"].str.len().fillna(0).astype(int)
    feats["path_depth"]       = df["path"].str.count("/").fillna(0).astype(int)
    feats["query_length"]     = df["query_string"].str.len().fillna(0).astype(int)
    feats["num_query_params"] = df["query_string"].apply(
        lambda q: len(q.split("&")) if q else 0
    )

    # ── body ──────────────────────────────────────────────────────────────────
    feats["body_length"]    = df["body"].str.len().fillna(0).astype(int)
    feats["num_body_params"] = df["body"].apply(
        lambda b: len(b.split("&")) if b else 0
    )

    # ── headers ───────────────────────────────────────────────────────────────
    feats["content_length"] = df["content_length"].fillna(0).astype(int)
    feats["has_cookie"]     = df["has_cookie"].fillna(0).astype(int)

    # ── attack pattern flags ──────────────────────────────────────────────────
    # Combine url + body for scanning; URL-decode for bypass evasion detection
    combined = (df["raw_url"].fillna("") + " " + df["body"].fillna("")).apply(_decode)

    feats["has_sql"]           = combined.apply(lambda s: int(bool(_SQL_PAT.search(s))))
    feats["has_xss"]           = combined.apply(lambda s: int(bool(_XSS_PAT.search(s))))
    feats["has_path_traversal"] = combined.apply(lambda s: int(bool(_TRAVERSAL_PAT.search(s))))
    feats["has_cmd_injection"]  = combined.apply(lambda s: int(bool(_CMD_PAT.search(s))))
    feats["has_null_byte"]      = combined.apply(lambda s: int(bool(_NULL_PAT.search(s))))
    feats["special_char_count"] = combined.apply(lambda s: len(_SPECIAL_CHARS.findall(s)))

    # ── label ─────────────────────────────────────────────────────────────────
    feats["label"] = df["label"].values

    return feats


def build_and_save(output_path: str | Path | None = None) -> pd.DataFrame:
    """
    Full pipeline: parse raw files → extract features → save CSV.
    Returns the feature DataFrame.
    """
    from src.data_parser import load_dataset

    df_raw = load_dataset()
    print("\nExtracting features ...")
    df_feat = extract_features(df_raw)
    print(f"Feature matrix shape: {df_feat.shape}")

    if output_path is None:
        output_path = Path(__file__).resolve().parent.parent / "data" / "processed.csv"
    output_path = Path(output_path)
    df_feat.to_csv(output_path, index=False)
    print(f"Saved -> {output_path}")
    return df_feat


if __name__ == "__main__":
    df = build_and_save()
    print(df.head())
    print("\nFeature value counts (label):")
    print(df["label"].value_counts())
