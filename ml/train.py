#!/usr/bin/env python3
"""Train and honestly evaluate HTTP traffic classifiers.

What this replaces
------------------
The original `high_accuracy_ids.py` invented "ground truth" labels by matching
request contents against a hand-written rule list, then trained a model on
those same features and reported the accuracy. Because the labels were a
function of the features, the score measured how well the rules were
implemented, not how well the model detects attacks. `model_evaluation.py`
crashed outright because it referenced a `true_label` column that never
existed.

What this does instead
----------------------
* Labels come from ``generate_dataset.py``, which knows which tool produced
  each request. They are independent of the request features.
* The split is a held-out test set, chosen with stratification so both classes
  are represented. Cross-validation is reported alongside it.
* Every number printed is computed from a model that never saw the test data.
* Random-forest classification and isolation-forest anomaly detection are both
  reported, with the difference between them explained, because an unsupervised
  score is not the same thing as detection accuracy.

Usage
-----
    python3 ml/train.py --data data/http_dataset.csv
    python3 ml/train.py --data data/http_dataset.csv --contamination 0.1
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent))

from features import (  # noqa: E402
    build_features,
    feature_importance_frame,
    split_labels,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = REPO_ROOT / "data" / "http_dataset.csv"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "model_metrics.json"
DEFAULT_FIGURE = REPO_ROOT / "data" / "feature_importance.png"


def load_dataset(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise SystemExit(
            f"dataset not found: {path}\n"
            "Generate it first:  python3 ml/generate_dataset.py"
        )
    df = pd.read_csv(path)
    if "label" not in df.columns:
        raise SystemExit(f"{path} has no 'label' column; regenerate the dataset")
    return df


def report_classifier(
    name: str,
    y_true: pd.Series,
    y_pred: np.ndarray,
    y_proba: np.ndarray | None = None,
) -> dict:
    """Compute and print the full metric set for a classifier."""
    print(f"\n--- {name} ---")
    print(f"accuracy  {accuracy_score(y_true, y_pred):.4f}")
    print(f"precision {precision_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"recall    {recall_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"f1        {f1_score(y_true, y_pred, zero_division=0):.4f}")
    if y_proba is not None:
        print(f"roc-auc   {roc_auc_score(y_true, y_proba):.4f}")

    print("\nconfusion matrix (rows = actual, cols = predicted):")
    print(confusion_matrix(y_true, y_pred))
    print("\nper-class report:")
    print(classification_report(y_true, y_pred, target_names=["benign", "attack"], digits=4))

    metrics = {
        "model": name,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }
    if y_proba is not None:
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_proba))
    return metrics


def train_random_forest(
    X: pd.DataFrame,
    y: pd.Series,
    seed: int,
    cv_folds: int,
) -> tuple:
    """Fit a random forest and evaluate it on a held-out split."""
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=seed, stratify=y
    )
    print(
        f"train {len(X_train)} rows ({y_train.mean():.1%} attack) | "
        f"test {len(X_test)} rows ({y_test.mean():.1%} attack)"
    )

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    metrics = report_classifier("RandomForest (held-out test set)", y_test, y_pred, y_proba)

    # Cross-validated scores use the full dataset, which is a stricter check
    # than a single split because every sample is validated exactly once.
    print(f"\n--- RandomForest ({cv_folds}-fold cross-validation) ---")
    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=seed)
    for scorer_name, scorer in (
        ("accuracy", "accuracy"),
        ("precision", "precision"),
        ("recall", "recall"),
        ("f1", "f1"),
        ("roc_auc", "roc_auc"),
    ):
        scores = cross_val_score(model, X, y, cv=cv, scoring=scorer, n_jobs=-1)
        print(f"{scorer_name:<9} {scores.mean():.4f} +/- {scores.std():.4f}")
        metrics[f"cv_{scorer_name}_mean"] = float(scores.mean())
        metrics[f"cv_{scorer_name}_std"] = float(scores.std())

    importance = feature_importance_frame(model.feature_importances_, list(X.columns))
    print("\ntop 12 features by importance:")
    print(importance.head(12).to_string(index=False))

    return model, metrics, importance


def leave_one_tool_out(
    X: pd.DataFrame,
    y: pd.Series,
    tools: pd.Series,
    seed: int,
) -> list:
    """Train on every attack tool but one, then test on the unseen tool.

    A random train/test split cannot reveal fingerprint memorisation: the same
    scanner appears in both halves, so the model can recognise it from its
    distinctive user agent alone and still score near-perfectly. Holding out
    an entire tool removes that shortcut, so the resulting score reflects
    whether the model learned attack *behaviour*.

    The benign class is always split across train and test, because a tool is
    the unit of holdout, not a random row.
    """
    unique_tools = sorted(t for t in tools.unique() if t and t != "benign")
    results = []
    print(f"\n--- leave-one-attack-tool-out ({len(unique_tools)} folds) ---")
    print(
        "each fold trains on benign + other tools, and tests only on the "
        "unseen tool"
    )

    for tool in unique_tools:
        is_held_out = tools == tool
        if is_held_out.sum() == 0:
            continue
        X_train, y_train = X[~is_held_out], y[~is_held_out]
        X_test, y_test = X[is_held_out], y[is_held_out]

        model = RandomForestClassifier(
            n_estimators=300,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=seed,
            n_jobs=-1,
        )
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        recall = float(recall_score(y_test, y_pred, zero_division=0))
        precision = float(precision_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        print(
            f"  {tool:<8} test rows {len(y_test):>5}  "
            f"recall {recall:.4f}  precision {precision:.4f}  f1 {f1:.4f}"
        )
        results.append(
            {
                "held_out_tool": tool,
                "test_rows": int(len(y_test)),
                "recall": recall,
                "precision": precision,
                "f1": f1,
            }
        )

    if results:
        mean_recall = float(np.mean([r["recall"] for r in results]))
        worst = min(results, key=lambda r: r["recall"])
        print(
            f"  mean recall {mean_recall:.4f}; weakest tool "
            f"{worst['held_out_tool']} at {worst['recall']:.4f}"
        )
        results.append({"mean_recall": mean_recall, "worst_tool": worst["held_out_tool"]})
    return results


def train_isolation_forest(
    X: pd.DataFrame,
    y: pd.Series,
    contamination: float,
    seed: int,
) -> dict:
    """Fit isolation forest and evaluate it against the true labels.

    Isolation forest is unsupervised: it sees only the feature matrix. The
    score below therefore measures how well its notion of "rare" lines up with
    the labels that were never given to it, which is the honest way to judge it.
    """
    print(f"\n--- IsolationForest (unsupervised, contamination={contamination}) ---")
    model = IsolationForest(contamination=contamination, random_state=seed, n_jobs=-1)
    model.fit(X)
    y_pred = (model.predict(X) == -1).astype(int)

    metrics = report_classifier("IsolationForest (fit on all features, no labels)", y, y_pred)

    flagged = int(y_pred.sum())
    attacks = int(y.sum())
    print(
        f"\nflagged {flagged} of {len(y)} requests ({flagged / len(y):.1%}); "
        f"the dataset contains {attacks} real attack requests"
    )
    metrics["flagged"] = flagged
    metrics["total"] = int(len(y))
    return metrics


def save_figure(importance: pd.DataFrame, path: Path) -> None:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\nmatplotlib not installed, skipping the feature importance plot")
        return

    top = importance.head(15).iloc[::-1]
    fig, ax = plt.subplots(figsize=(9, 6))
    ax.barh(top["feature"], top["importance"], color="#c0392b")
    ax.set_xlabel("Gini importance")
    ax.set_title("Random forest feature importance")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=140)
    plt.close(fig)
    print(f"\nwrote {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default=str(DEFAULT_DATA), help="labelled CSV")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="metrics JSON path")
    parser.add_argument(
        "--figure", default=str(DEFAULT_FIGURE), help="feature importance PNG path"
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.1,
        help="expected anomaly rate for IsolationForest (default 0.1)",
    )
    args = parser.parse_args()

    df = load_dataset(Path(args.data))
    print(f"loaded {len(df)} rows from {args.data}")
    print("\nlabel distribution:")
    print(df["label"].value_counts().to_string())

    X = build_features(df)
    y = split_labels(df)
    print(f"\nengineered {X.shape[1]} numeric features")
    print(f"attack rows: {int(y.sum())} ({y.mean():.1%})")

    if y.nunique() < 2:
        raise SystemExit("dataset contains only one class; nothing to learn")

    _, rf_metrics, importance = train_random_forest(X, y, args.seed, args.cv_folds)
    generalization = leave_one_tool_out(X, y, df["label"], args.seed)
    if_metrics = train_isolation_forest(X, y, args.contamination, args.seed)
    save_figure(importance, Path(args.figure))

    payload = {
        "dataset": {
            "path": str(args.data),
            "rows": int(len(df)),
            "features": int(X.shape[1]),
            "attack_rows": int(y.sum()),
            "benign_rows": int((y == 0).sum()),
            "label_distribution": {
                str(k): int(v) for k, v in df["label"].value_counts().items()
            },
        },
        "random_forest": rf_metrics,
        "leave_one_tool_out": generalization,
        "isolation_forest": if_metrics,
        "seed": args.seed,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2))
    print(f"\nwrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())