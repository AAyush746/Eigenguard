"""Feature extraction for HTTP request classification.

Two rules shape this module:

1. No feature may be derived from the label. The previous version of this
   project inferred its own ground truth from the request contents and then
   measured a model against those same contents, which made the reported
   accuracy meaningless.
2. Categorical values are encoded on the *training split only* and then
   applied to the test split. Fitting an encoder on the full dataset leaks
   test information into training and inflates scores.
"""
from __future__ import annotations

import re
from typing import Iterable, List
from urllib.parse import unquote

import numpy as np
import pandas as pd

# Columns that describe the request. `label` is deliberately absent.
RAW_COLUMNS = [
    "method",
    "path",
    "query",
    "userAgent",
    "referer",
    "status",
    "responseTime",
    "responseSize",
    "contentLength",
]

# Paths that are sensitive or commonly probed. Used to build a count feature
# rather than as a label, so it stays a legitimate input signal.
SENSITIVE_PATTERNS = [
    "admin",
    "login",
    "passwd",
    "shadow",
    "config",
    "backup",
    "database",
    ".env",
    ".git",
    "wp-",
    "phpmyadmin",
    "shell",
    "cmd",
    "cgi-bin",
    "etc/passwd",
    "id_rsa",
]

# Counted as literal substrings, not regular expressions: "/*" as a regex
# matches zero or more slashes and matched almost every benign request.
SQLI_TOKENS = [
    "select",
    "union",
    "insert",
    "update",
    "delete",
    "drop",
    " from ",
    "where",
    "sleep",
    "benchmark",
    "waitfor",
    "having",
    "order by",
    "group by",
    "--",
    "/*",
    "or 1=1",
    "' or",
    "0x",
    "concat(",
    "information_schema",
    "database()",
]

TRAVERSAL_TOKENS = ["../", "..%2f", "%2e%2e", "/etc/", "boot.ini", "windows"]

# Percent-encodings scanners use to slip past naive filters.
ENCODING_TOKENS = ["%2e", "%2f", "%5c", "%00", "%0a", "%0d", "%27", "%22", "%3c", "%3e"]


def _literal_count(series: pd.Series, needle: str) -> pd.Series:
    """Count literal occurrences of ``needle``.

    ``Series.str.count`` takes a regular expression, so patterns such as
    ``/*`` or ``.env`` silently match the wrong thing. Every token in this
    module is escaped before counting.
    """
    return series.str.count(re.escape(needle))


def _percent_decode(value: str) -> str:
    """Decode percent-escapes so encoded payloads are visible to matching."""
    if "%" not in value:
        return value
    try:
        return unquote(value, errors="replace")
    except Exception:
        return value


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Return a numeric feature matrix for raw request records.

    Parameters
    ----------
    df:
        Raw request records with the columns listed in ``RAW_COLUMNS``.

    Returns
    -------
    pandas.DataFrame
        One row per input record, all columns numeric.
    """
    missing = [c for c in RAW_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"missing required columns: {missing}")

    work = df.copy()
    path = work["path"].astype(str).str.lower()
    query = work["query"].astype(str).str.lower()
    agent = work["userAgent"].astype(str)
    full = path + "?" + query

    features = pd.DataFrame(index=work.index)

    # --- shape of the request ---------------------------------------
    features["path_length"] = path.str.len()
    features["query_length"] = query.str.len()
    features["full_length"] = full.str.len()
    features["path_depth"] = path.str.count("/")
    features["path_segments"] = path.str.count("/") + 1
    features["query_params"] = query.str.count("&") + (query.str.len() > 0).astype(int)

    # --- character composition --------------------------------------
    # Encoded payloads look different from ordinary words: more digits,
    # symbols, and encoded escapes, and much less structure.
    features["digit_ratio"] = full.str.count(r"\d") / features["full_length"].clip(lower=1)
    features["symbol_ratio"] = full.str.count(r"[^a-zA-Z0-9/._-]") / features[
        "full_length"
    ].clip(lower=1)
    features["uppercase_ratio"] = full.str.count(r"[A-Z]") / features["full_length"].clip(
        lower=1
    )
    features["encoded_char_ratio"] = full.str.count("%") / features["full_length"].clip(
        lower=1
    )
    features["special_char_count"] = full.str.count(r"[`'\"\\<>]")
    # The explicit dtype matters: `Series.map` on an empty series infers
    # `object`, which would leave the feature matrix non-numeric for callers
    # that build features before any request has been logged.
    features["unique_char_ratio"] = full.map(
        lambda s: len(set(s)) / max(1, len(s))
    ).astype(float)

    # --- attack vocabulary ------------------------------------------
    # Scanners percent-encode their payloads, so the tokens are matched
    # against both the raw and the decoded form. Counting occurrences rather
    # than recording a boolean keeps the magnitude of the match.
    decoded = work["path"].astype(str) + "?" + work["query"].astype(str)
    decoded = decoded.map(_percent_decode)
    decoded = decoded.str.lower()

    # A hit means the path contains the pattern at all, not how many
    # characters matched: a 15-character path cannot score 16 hits.
    features["sensitive_path_hits"] = sum(
        _literal_count(path, pattern).clip(upper=1) for pattern in SENSITIVE_PATTERNS
    )
    features["sqli_token_hits"] = sum(
        _literal_count(full, pattern) + _literal_count(decoded, pattern)
        for pattern in SQLI_TOKENS
    )
    features["traversal_hits"] = sum(
        _literal_count(full, pattern) + _literal_count(decoded, pattern)
        for pattern in TRAVERSAL_TOKENS
    )
    features["encoding_token_hits"] = sum(
        _literal_count(full, pattern) for pattern in ENCODING_TOKENS
    )

    # --- method and protocol ----------------------------------------
    features["method_is_get"] = (work["method"].astype(str).str.upper() == "GET").astype(int)
    features["method_is_post"] = (work["method"].astype(str).str.upper() == "POST").astype(int)
    features["method_is_head"] = (work["method"].astype(str).str.upper() == "HEAD").astype(int)
    features["method_is_options"] = (
        work["method"].astype(str).str.upper() == "OPTIONS"
    ).astype(int)

    # --- status code -------------------------------------------------
    features["status"] = pd.to_numeric(work["status"], errors="coerce").fillna(0)
    features["status_2xx"] = features["status"].between(200, 299).astype(int)
    features["status_3xx"] = features["status"].between(300, 399).astype(int)
    features["status_4xx"] = features["status"].between(400, 499).astype(int)
    features["status_5xx"] = features["status"].between(500, 599).astype(int)

    # --- timing and size ---------------------------------------------
    response_time = pd.to_numeric(work["responseTime"], errors="coerce").fillna(0)
    features["response_time_ms"] = response_time
    features["response_time_log"] = np.log1p(response_time.clip(lower=0))
    features["response_size"] = pd.to_numeric(work["responseSize"], errors="coerce").fillna(0)
    features["response_size_log"] = np.log1p(features["response_size"])
    features["content_length"] = pd.to_numeric(work["contentLength"], errors="coerce").fillna(0)
    features["bytes_ratio"] = features["response_size"] / (
        features["response_size"] + features["content_length"] + 1
    )

    # --- client fingerprint ------------------------------------------
    features["user_agent_length"] = agent.str.len()
    features["has_user_agent"] = (agent.str.lower() != "unknown").astype(int)
    features["agent_is_browser"] = agent.str.contains("Mozilla", case=False).astype(int)
    features["has_referer"] = (work["referer"].astype(str).str.len() > 0).astype(int)

    # --- temporal position -------------------------------------------
    timestamp = pd.to_datetime(work["timestamp"], errors="coerce", utc=True)
    features["hour"] = timestamp.dt.hour.fillna(0).astype(int)
    features["is_odd_hour"] = (features["hour"] < 6).astype(int)

    features = features.replace([np.inf, -np.inf], 0).fillna(0)
    return features


def split_labels(df: pd.DataFrame) -> pd.Series:
    """Map tool names to a binary target: 1 = attack, 0 = benign."""
    labels = df["label"].astype(str).str.lower()
    return (labels != "benign").astype(int)


def feature_importance_frame(
    importances: Iterable[float], feature_names: List[str]
) -> pd.DataFrame:
    """Rank features by importance for reporting."""
    frame = pd.DataFrame({"feature": feature_names, "importance": list(importances)})
    return frame.sort_values("importance", ascending=False).reset_index(drop=True)