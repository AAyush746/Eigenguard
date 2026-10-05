"""Tests for HTTP request feature extraction.

The properties guarded here are the ones that produced dishonest model scores
in the earlier version of this project: features must never be derived from the
label, and token matching must be literal rather than regular-expression based.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from features import (  # noqa: E402
    RAW_COLUMNS,
    build_features,
    feature_importance_frame,
    split_labels,
)


def make_row(**overrides) -> dict:
    row = {
        "timestamp": "2026-03-01T12:30:00Z",
        "ip": "10.0.0.5",
        "method": "GET",
        "path": "/blog/post",
        "query": "page=2",
        "contentLength": 0,
        "userAgent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0",
        "referer": "",
        "status": 200,
        "responseTime": 42.5,
        "responseSize": 2048,
    }
    row.update(overrides)
    return row


def frame(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# shape and typing
# ---------------------------------------------------------------------------
def test_build_features_returns_one_row_per_request():
    df = frame([make_row(), make_row(path="/about"), make_row(path="/contact")])
    features = build_features(df)
    assert len(features) == 3


def test_every_feature_is_numeric():
    df = frame([make_row(), make_row(path="/admin", status=403, method="POST")])
    features = build_features(df)
    assert features.select_dtypes(include=[np.number]).shape[1] == features.shape[1]


def test_features_contain_no_infinities_or_nans():
    df = frame(
        [
            make_row(),
            make_row(responseTime=None, responseSize=None, contentLength=None),
            make_row(responseSize=0, contentLength=0),
        ]
    )
    features = build_features(df)
    values = features.to_numpy(dtype=float)
    assert np.isfinite(values).all(), "features contain NaN or infinity"


def test_missing_columns_are_reported_by_name():
    df = frame([make_row()]).drop(columns=["status", "userAgent"])
    with pytest.raises(ValueError, match="status"):
        build_features(df)


def test_all_declared_raw_columns_are_actually_required():
    df = frame([make_row()])
    for column in RAW_COLUMNS:
        broken = df.drop(columns=[column])
        with pytest.raises(ValueError, match=column):
            build_features(broken)


# ---------------------------------------------------------------------------
# no label leakage
# ---------------------------------------------------------------------------
def test_label_column_is_not_a_feature():
    df = frame([make_row(label="benign"), make_row(label="sqlmap", path="/admin")])
    assert "label" not in build_features(df).columns


def test_features_are_independent_of_the_label():
    """Identical requests must produce identical features whatever the label.

    If the label influenced any feature, a model trained on this data would be
    scoring the label back to itself.
    """
    benign = make_row(path="/index.html", label="benign")
    attack = make_row(path="/index.html", label="sqlmap")

    benign_features = build_features(frame([benign]))
    attack_features = build_features(frame([attack]))

    pd.testing.assert_frame_equal(benign_features, attack_features)


def test_source_column_is_not_used_either():
    df = frame([make_row(source="generated")])
    assert "source" not in build_features(df).columns


# ---------------------------------------------------------------------------
# literal token matching
# ---------------------------------------------------------------------------
def test_sql_comment_marker_is_counted_literally():
    """`/*` as a regular expression matches empty, inflating every request.

    Counted as a plain substring, only a request actually containing the
    characters gets a hit.
    """
    clean = build_features(frame([make_row(path="/products", query="")]))
    assert clean["sqli_token_hits"].iloc[0] == 0

    payload = build_features(
        frame([make_row(path="/products", query="a=1/*comment*/")])
    )
    assert payload["sqli_token_hits"].iloc[0] > 0


def test_dotenv_pattern_does_not_match_arbitrary_characters():
    """.env unescaped would match "xenv", "env", and any character plus "env"."""
    unrelated = build_features(frame([make_row(path="/environment", query="")]))
    assert unrelated["sensitive_path_hits"].iloc[0] == 0

    real = build_features(frame([make_row(path="/.env", query="")]))
    assert real["sensitive_path_hits"].iloc[0] == 1


def test_percent_encoded_payloads_are_detected_after_decoding():
    """A payload split across encodings must still register as an attack.

    `%20` alone is deliberately *not* counted: a space is common in ordinary
    URLs, so flagging it would mark normal traffic as suspicious.
    """
    spaced = build_features(
        frame([make_row(path="/index.php", query="id=1%20union%20select%201")])
    )
    assert spaced["sqli_token_hits"].iloc[0] > 0, "decoded SQL keywords should match"
    assert spaced["encoding_token_hits"].iloc[0] == 0, "%20 is not an evasion"

    # %27 is an encoded quote, the classic way to slip past a naive filter.
    quoted = build_features(
        frame([make_row(path="/index.php", query="id=1%27%20or%20%271%27=%271")])
    )
    assert quoted["encoding_token_hits"].iloc[0] > 0
    assert quoted["sqli_token_hits"].iloc[0] > 0


def test_path_traversal_is_detected_both_raw_and_encoded():
    raw = build_features(frame([make_row(path="/static/../../etc/passwd", query="")]))
    assert raw["traversal_hits"].iloc[0] > 0

    encoded = build_features(
        frame([make_row(path="/static/%2e%2e/%2e%2e/etc/passwd", query="")])
    )
    assert encoded["traversal_hits"].iloc[0] > 0


def test_sensitive_hits_are_capped_at_one_per_pattern():
    """A short path cannot accumulate more hits than it has patterns."""
    features = build_features(frame([make_row(path="/admin", query="")]))
    assert features["sensitive_path_hits"].iloc[0] == 1


# ---------------------------------------------------------------------------
# request-shape features
# ---------------------------------------------------------------------------
def test_method_flags_are_exclusive():
    df = frame(
        [
            make_row(method="GET"),
            make_row(method="POST"),
            make_row(method="HEAD"),
            make_row(method="OPTIONS"),
            make_row(method="DELETE"),
        ]
    )
    features = build_features(df)
    flags = ["method_is_get", "method_is_post", "method_is_head", "method_is_options"]

    for _, row in features.iterrows():
        assert sum(row[flag] for flag in flags) <= 1


def test_status_buckets_cover_the_code():
    df = frame(
        [make_row(status=200), make_row(status=301), make_row(status=404), make_row(status=503)]
    )
    features = build_features(df)
    assert features["status_2xx"].tolist() == [1, 0, 0, 0]
    assert features["status_3xx"].tolist() == [0, 1, 0, 0]
    assert features["status_4xx"].tolist() == [0, 0, 1, 0]
    assert features["status_5xx"].tolist() == [0, 0, 0, 1]


def test_hour_and_night_hours_are_derived_from_the_timestamp():
    df = frame(
        [
            make_row(timestamp="2026-03-01T14:00:00Z"),
            make_row(timestamp="2026-03-01T03:00:00Z"),
        ]
    )
    features = build_features(df)
    assert features["hour"].tolist() == [14, 3]
    assert features["is_odd_hour"].tolist() == [0, 1]


def test_path_shape_features():
    features = build_features(frame([make_row(path="/a/b/c", query="x=1&y=2")]))
    row = features.iloc[0]
    assert row["path_depth"] == 3
    assert row["path_segments"] == 4
    assert row["query_params"] == 2


def test_empty_query_string_counts_as_zero_params():
    features = build_features(frame([make_row(path="/about", query="")]))
    assert features["query_params"].iloc[0] == 0


def test_benign_and_attack_shapes_are_separable_on_behaviour():
    """A real attack request must look different from a real page view.

    If this failed, no model could learn anything and the reported accuracy
    would have to be coming from somewhere else.
    """
    benign = build_features(
        frame([make_row(path="/blog/how-we-monitor", query="page=2", status=200)])
    )
    attack = build_features(
        frame(
            [
                make_row(
                    path="/wp-admin/setup-config.php",
                    query="id=1%20union%20select%201,2,3--",
                    method="POST",
                    status=404,
                    userAgent="sqlmap/1.8.2#stable",
                )
            ]
        )
    )

    differing = [
        column
        for column in benign.columns
        if benign[column].iloc[0] != attack[column].iloc[0]
    ]
    # URL vocabulary, method, status and fingerprint should all differ.
    assert len(differing) >= 6
    assert attack["sqli_token_hits"].iloc[0] > benign["sqli_token_hits"].iloc[0]
    assert attack["sensitive_path_hits"].iloc[0] > benign["sensitive_path_hits"].iloc[0]
    assert attack["agent_is_browser"].iloc[0] == 0


def test_empty_dataframe_is_handled():
    empty = pd.DataFrame(columns=RAW_COLUMNS + ["timestamp"])
    features = build_features(empty)
    assert len(features) == 0
    assert features.select_dtypes(include=[np.number]).shape[1] == features.shape[1]


# ---------------------------------------------------------------------------
# labels and reporting
# ---------------------------------------------------------------------------
def test_split_labels_maps_tools_to_a_binary_target():
    df = frame(
        [
            make_row(label="benign"),
            make_row(label="benign"),
            make_row(label="sqlmap"),
            make_row(label="nikto"),
        ]
    )
    y = split_labels(df)
    assert y.tolist() == [0, 0, 1, 1]
    assert y.mean() == 0.5


def test_split_labels_is_case_insensitive():
    assert split_labels(frame([make_row(label="Benign")])).tolist() == [0]


def test_feature_importance_is_sorted_descending():
    frame_out = feature_importance_frame([0.1, 0.7, 0.3], ["a", "b", "c"])
    assert frame_out["feature"].tolist() == ["b", "c", "a"]
    assert frame_out["importance"].tolist() == [0.7, 0.3, 0.1]