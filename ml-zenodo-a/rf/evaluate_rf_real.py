"""Evaluate the REAL-feature RF model trained on Dataset A.

Reads ``test_predictions_real.parquet`` (produced by
``train_rf_real.py``) and renders:

  - per-class precision / recall / F1 / support
  - confusion matrix heatmap (PNG)
  - macro F1 and weighted F1

Outputs:
  - ml-zenodo-a/rf/eval_report_real.txt
  - ml-zenodo-a/rf/confusion_matrix_real.png

Usage:
    python ml-zenodo-a/rf/evaluate_rf_real.py --rf-dir ml-zenodo-a/rf
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score

logger = logging.getLogger("evaluate_rf_real")


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--rf-dir", type=Path, default=Path("ml-zenodo-a/rf"))
    args = parser.parse_args()

    rf_dir: Path = args.rf_dir
    preds_path = rf_dir / "test_predictions_real.parquet"
    if not preds_path.exists():
        logger.error("%s not found -- run train_rf_real.py first", preds_path)
        return 1

    df = pd.read_parquet(preds_path)
    y_true = df["label"].to_numpy()
    y_pred = df["pred"].to_numpy()
    logger.info("loaded %d test predictions", len(df))

    label_order = [lbl for lbl in ["low", "medium", "high"] if lbl in pd.unique(y_true) or lbl in pd.unique(y_pred)]

    macro = f1_score(y_true, y_pred, labels=label_order, average="macro", zero_division=0)
    weighted = f1_score(y_true, y_pred, labels=label_order, average="weighted", zero_division=0)
    per_class = classification_report(
        y_true, y_pred, labels=label_order, zero_division=0, digits=3
    )

    cm = confusion_matrix(y_true, y_pred, labels=label_order)

    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    ax.set_title(f"RF (Dataset A, 7k subsample, REAL OSV features)\n"
                 f"Macro F1 = {macro:.3f}  |  Weighted F1 = {weighted:.3f}")
    ax.set_xticks(np.arange(len(label_order)))
    ax.set_yticks(np.arange(len(label_order)))
    ax.set_xticklabels(label_order)
    ax.set_yticklabels(label_order)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], "d"),
                    ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black")
    fig.tight_layout()
    out_png = rf_dir / "confusion_matrix_real.png"
    fig.savefig(out_png, dpi=120)
    plt.close(fig)
    logger.info("wrote confusion matrix -> %s", out_png)

    importance_path = rf_dir / "feature_importance_real.json"
    importance = []
    if importance_path.exists():
        importance = json.loads(importance_path.read_text())

    lines = [
        "RandomForest on Zenodo Dataset A (7,000 SBOM subsample).",
        "Features: REAL OSV-derived (12) -- advisory_count, critical/high/medium/low_count,",
        "          max_advisory_year, rank_score, ecosystem one-hot.",
        "          NOTE: max_cvss is NOT a feature -- it would leak the label.",
        "Labels : OSV.dev max-CVSS threshold (>= 7.0 high, >= 4.0 medium, else low).",
        f"          Observed distribution: {dict(zip(*np.unique(y_true, return_counts=True)))}",
        "",
        f"Macro F1   : {macro:.4f}",
        f"Weighted F1: {weighted:.4f}",
        "",
        "Per-class metrics:",
        per_class,
    ]
    if importance:
        lines.append("")
        lines.append("Feature importances (descending):")
        for item in importance:
            lines.append(f"  {item['feature']:<22} {item['importance']:.4f}")

    report = "\n".join(lines)
    (rf_dir / "eval_report_real.txt").write_text(report)
    logger.info("wrote report -> %s", rf_dir / "eval_report_real.txt")
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())