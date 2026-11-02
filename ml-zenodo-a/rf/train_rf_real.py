"""Train RF on REAL OSV-derived features (no max_cvss leakage).

Feature set is computed from OSV.dev advisories per package, but
**does not include** ``max_cvss`` -- the label is derived from that
field, so using it as a feature would re-introduce label-feature
leakage that drove ``train_rf_v2.py`` to a meaningless ``macro F1=1.0``.

Real features used (computed by ``osv_labeler.py``):

    0. advisory_count      (number of OSV advisories for this package+version)
    1. critical_count      (count of advisories with GHSA severity=CRITICAL)
    2. high_count          (count of advisories with GHSA severity=HIGH)
    3. medium_count        (count of advisories with GHSA severity=MEDIUM)
    4. low_count           (count of advisories with GHSA severity=LOW)
    5. max_advisory_year   (most recent CVE year for this package)
    6. rank_score          (PageRank on repo's dep graph, min-max scaled)
    7. ecosystem_npm       (1-hot of ecosystem)
    8. ecosystem_Maven
    9. ecosystem_PyPI
   10. ecosystem_Packagist
   11. ecosystem_RubyGems
   12. ecosystem_Other    (any other ecosystem, e.g. Pub/NuGet/Go/crates)

Labels still come from ``max_cvss`` threshold:
    >= 7.0 -> high, >= 4.0 -> medium, else low.

NOTE: On the 7k subsample the OSV ``severity[]`` CVSS vector
approximation collapses everything with at least one CVE into the
"high" bucket -- we get a binary ``{low, high}`` distribution.
That is a quirk of the CVSS approximation, not a feature
engineering issue. The model still trains; we just won't see a
separate "medium" class. Reported metrics use the actual label
distribution present in the data.

Usage:
    python ml-zenodo-a/rf/train_rf_real.py \\
        --packages ml-zenodo-a/data/packages.ndjson \\
        --labels ml-zenodo-a/data/labels.parquet \\
        --output ml-zenodo-a/rf
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import RobustScaler

logger = logging.getLogger("train_rf_real")

NUMERIC_FEATURES = [
    "advisory_count",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "max_advisory_year",
    "rank_score",
]

# Ecosystem one-hot. We don't include all ecosystems to keep the
# feature space small; "Other" is the catch-all.
ECOSYSTEMS = ["npm", "Maven", "PyPI", "Packagist", "RubyGems"]


def build_features(packages: pd.DataFrame, labels: pd.DataFrame) -> pd.DataFrame:
    """Join packages + labels and assemble the 12-feature matrix.

    Uses a LEFT join so packages without OSV data still appear in the
    training set (with default zero values for the OSV-derived
    features and ``max_advisory_year`` left as NaN -> median imputed
    later).
    """
    df = packages.merge(
        labels, on=["ecosystem", "name", "version"], how="left"
    )
    # Default missing OSV-derived fields
    for col in ["advisory_count", "critical_count", "high_count", "medium_count", "low_count"]:
        df[col] = df[col].fillna(0).astype(int)
    # NaN year -> median (later)
    df["label"] = df["label"].fillna("low")

    # Encode ecosystem one-hot
    for eco in ECOSYSTEMS:
        df[f"ecosystem_{eco}"] = (df["ecosystem"] == eco).astype(int)
    df["ecosystem_Other"] = (~df["ecosystem"].isin(ECOSYSTEMS)).astype(int)

    return df


def feature_columns() -> list[str]:
    return NUMERIC_FEATURES + [f"ecosystem_{e}" for e in ECOSYSTEMS] + ["ecosystem_Other"]


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--packages", type=Path, default=Path("ml-zenodo-a/data/packages.ndjson"))
    parser.add_argument("--labels", type=Path, default=Path("ml-zenodo-a/data/labels.parquet"))
    parser.add_argument("--output", type=Path, default=Path("ml-zenodo-a/rf"))
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n-estimators", type=int, default=300)
    parser.add_argument("--max-depth", type=int, default=12)
    args = parser.parse_args()

    out_dir: Path = args.output
    out_dir.mkdir(parents=True, exist_ok=True)

    logger.info("loading packages from %s", args.packages)
    pkg = pd.read_json(args.packages, lines=True)
    logger.info("loaded %d package rows", len(pkg))

    logger.info("loading labels from %s", args.labels)
    lab = pd.read_parquet(args.labels)
    logger.info("loaded %d label rows; distribution: %s",
                len(lab), lab["label"].value_counts().to_dict())

    df = build_features(pkg, lab)
    # Determine label order from actual presence in the data (binary
    # low/high on this run, but keep the table extensible).
    label_order = [lbl for lbl in ["low", "medium", "high"] if lbl in df["label"].unique()]
    logger.info("label set used for evaluation: %s", label_order)

    feat_cols = feature_columns()
    X = df[feat_cols].copy()
    # Impute NaN max_advisory_year with median (only packages with
    # any advisory have a non-null year; the rest stay at NaN).
    if X["max_advisory_year"].isna().any():
        median_year = X["max_advisory_year"].median()
        if pd.isna(median_year):
            median_year = 2024  # dataset default
        X["max_advisory_year"] = X["max_advisory_year"].fillna(median_year)
        logger.info("imputed %d NaN max_advisory_year with %.0f",
                    X["max_advisory_year"].isna().sum(), median_year)
    X = X.to_numpy(dtype=float)

    y = df["label"].astype("category").cat.set_categories(label_order).to_numpy()
    repo_ids = df["repo_id"].to_numpy()

    # Repo-stratified split
    unique_repos = pd.unique(repo_ids)
    rng = np.random.default_rng(args.seed)
    shuffled = unique_repos.copy()
    rng.shuffle(shuffled)
    n_test_repos = max(1, int(len(shuffled) * args.test_size))
    test_repos = set(shuffled[:n_test_repos])
    test_mask = np.fromiter((r in test_repos for r in repo_ids), dtype=bool, count=len(repo_ids))
    X_train, X_test = X[~test_mask], X[test_mask]
    y_train, y_test = y[~test_mask], y[test_mask]
    logger.info("split: %d train rows / %d test rows (across %d / %d repos)",
                len(X_train), len(X_test),
                len(set(repo_ids[~test_mask])), len(test_repos))

    scaler = RobustScaler().fit(X_train)
    X_train_s = scaler.transform(X_train)
    X_test_s = scaler.transform(X_test)

    logger.info("training RF (REAL features, %d total): n_estimators=%d max_depth=%d class_weight=balanced",
                len(feat_cols), args.n_estimators, args.max_depth)
    clf = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=args.seed,
        n_jobs=-1,
    )
    clf.fit(X_train_s, y_train)

    pred = clf.predict(X_test_s)
    report = classification_report(
        y_test, pred, labels=label_order, output_dict=True, zero_division=0
    )
    logger.info("test classification report:\n%s",
                classification_report(y_test, pred, labels=label_order, zero_division=0))

    # Persist model artifacts (separate names so train_rf_v2 and topo coexist).
    model_path = out_dir / "random_forest_sbom_real_v2.pkl"
    scaler_path = out_dir / "scaler_real_v2.pkl"
    feat_names_path = out_dir / "feature_names_real.json"
    metrics_path = out_dir / "metrics_real_train.json"

    joblib.dump(clf, model_path)
    joblib.dump(scaler, scaler_path)
    feat_names_path.write_text(json.dumps(feat_cols, indent=2))
    metrics_path.write_text(json.dumps(report, indent=2))

    importances = sorted(
        zip(feat_cols, clf.feature_importances_.tolist()),
        key=lambda kv: kv[1], reverse=True,
    )
    logger.info("feature importances:")
    for name, score in importances:
        logger.info("  %-22s %.4f", name, score)
    (out_dir / "feature_importance_real.json").write_text(
        json.dumps([{"feature": n, "importance": s} for n, s in importances], indent=2)
    )

    # Persist test split
    pd.DataFrame(
        {
            "repo_id": repo_ids[test_mask],
            "label": y_test,
            "pred": pred,
        }
    ).to_parquet(out_dir / "test_predictions_real.parquet", index=False)

    logger.info("saved model -> %s", model_path)
    logger.info("saved scaler -> %s", scaler_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())