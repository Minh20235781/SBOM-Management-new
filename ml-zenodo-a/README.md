# ml-zenodo-a/ — Honest RF on Zenodo Dataset A (3-class, 13 features)

A single RandomForest model trained on a 7,000-SBOM subsample of
**Dataset A: SBOM Dataset from 100,000+ Public GitHub Repositories**
(Chaora & Camp, 2025, Zenodo record 15334733, DOI
`10.5281/zenodo.15334733`, CC-BY 4.0).

The model is **deliberately leakage-free**: ``max_cvss`` is excluded
from the feature set because the label is the OSV.dev
``max_cvss`` threshold. This is the main thesis finding, not a metric
to chase.

**Headline metrics** on 60,662 unique packages (CVSS V3 base scores
from the official `cvss` library):

| Macro F1 | F1 (low) | F1 (medium) | F1 (high) |
|---|---|---|---|
| **0.9516** | **0.998** | **0.888** | **0.969** |

The medium-precision ceiling (0.81) is the model's main failure
mode: packages with both `high_count > 0` and `medium_count > 0`
sometimes get classified as `high` even when the max CVSS is in the
4.0-6.9 band. The high class — the one that matters most for risk
prioritisation — is at F1 = 0.969.

## How it plugs into the dashboard

```
+-------------+   GET /api/ai/rf-new/predict/{repoName}   +-------------------+
|  AIPage.jsx  | <-------------------------------------- | RfNewPrediction   |
|  "AI - RF    |                                          | Controller         |
|  Risk (New)" |                                          +---------v---------+
|   tab        |                                                    |
+-------------+                                                    |
                                                                     |
        +-- ZenodoRfPredictionService (Java)                       |
        |   - reads ai.rf-new.service-url (default :8002)         |
        |   - builds 13 features per PackageEntity                |
        |   - POSTs {items: [{features: [13 floats]}]}            |
        +-- HTTP --------------------------------+                  |
                                                  v                  |
                                            +---------------+        |
                                            |  rf_server.py |        |
                                            |   port 8002   |        |
                                            |   13-feature  |        |
                                            +-------+-------+        |
                                                    |                  |
                                                    v                  |
                                       ml-zenodo-a/rf/                |
                                       random_forest_sbom_real_v2.pkl|
                                       scaler_real_v2.pkl          |
                                                                    |
```

The two existing tabs ("Risk Analysis" → Gemini, "ML Score" →
7-feature legacy RF on port 8001) keep working unchanged. Run
`start_ml_services.bat` / `.ps1` to launch all three Python
services in their own windows.

## Layout

```
ml-zenodo-a/
├── README.md
├── requirements.txt          # pandas, scikit-learn, pyarrow, cvss, ...
├── data/
│   ├── download_dataset_a.py # stream-download + subsample
│   ├── parse_spdx.py         # SPDX -> packages.ndjson + edges
│   ├── osv_labeler.py        # OSV.dev batch + parallel fetch
│   ├── raw_sboms/            # 7,000 SPDX JSON files (gitignored)
│   ├── packages.ndjson        # per-package rows (gitignored)
│   ├── graphs/                # per-repo edge lists (gitignored)
│   └── labels.parquet         # OSV-labeled + features (gitignored)
├── rf/
│   ├── train_rf_real.py            # the only training script
│   ├── evaluate_rf_real.py         # confusion matrix + eval report
│   ├── random_forest_sbom_real_v2.pkl
│   ├── scaler_real_v2.pkl
│   ├── metrics_real_train.json
│   ├── feature_names_real.json     # the 13-feature contract
│   ├── feature_importance_real.json
│   ├── confusion_matrix_real.png
│   ├── eval_report_real.txt
│   └── test_predictions_real.parquet
└── scripts/
    └── baseline_rerun.py    # re-runs the legacy 689-row pipeline for comparison
```

## Feature contract (must match `feature_names_real.json`)

13 features, in this exact order:

```
0.  advisory_count     (int: count of OSV advisories for this package+version)
1.  critical_count     (int: advisories with GHSA severity=CRITICAL)
2.  high_count         (int: advisories with GHSA severity=HIGH)
3.  medium_count       (int: advisories with GHSA severity=MEDIUM)
4.  low_count          (int: advisories with GHSA severity=LOW)
5.  max_advisory_year  (float: most recent CVE year, current year when no advisory)
6.  rank_score         (float: PageRank on the repo's dep graph, min-max)
7.  ecosystem_npm       (0/1)
8.  ecosystem_Maven     (0/1)
9.  ecosystem_PyPI      (0/1)
10. ecosystem_Packagist (0/1)
11. ecosystem_RubyGems  (0/1)
12. ecosystem_Other     (0/1)
```

**Deliberately excluded**: ``max_cvss``. Including it would re-introduce
label-feature leakage because the label is the max CVSS threshold.

The Java side (`ZenodoRfPredictionService.buildPredictionItem`)
computes these in the same order; the Python side
(`rf_server.resolve_feature_order`) checks the count via
`scaler.n_features_in_ == 13`.

## End-to-end reproduction

```powershell
# 0. Activate the venv (the project's gnn-training/.venv312 has the deps).
gnn-training\.venv312\Scripts\activate

# Install any missing deps.
pip install -r ml-zenodo-a/requirements.txt

# 1. Download + subsample 7,000 SPDX SBOMs (ZIP cached after first run).
python ml-zenodo-a/data/download_dataset_a.py `
    --output ml-zenodo-a/data/raw_sboms `
    --sample-size 7000

# 2. Parse SPDX -> packages.ndjson + per-repo edges (~1 min).
python ml-zenodo-a/data/parse_spdx.py `
    --input ml-zenodo-a/data/raw_sboms `
    --output ml-zenodo-a/data

# 3. Label packages via OSV.dev (~1-2 hours with parallel fetching).
python ml-zenodo-a/data/osv_labeler.py `
    --packages ml-zenodo-a/data/packages.ndjson `
    --output ml-zenodo-a/data/labels.parquet `
    --batch-size 100 --rate 4.0

# 4. Train the RF.
python ml-zenodo-a/rf/train_rf_real.py `
    --packages ml-zenodo-a/data/packages.ndjson `
    --labels ml-zenodo-a/data/labels.parquet `
    --output ml-zenodo-a/rf

# 5. Evaluate + generate confusion matrix PNG + eval report.
python ml-zenodo-a/rf/evaluate_rf_real.py `
    --rf-dir ml-zenodo-a/rf

# 6. (Optional) Re-run the legacy 689-row pipeline for an "apples-to-apples"
#    baseline rerun.
python ml-zenodo-a/scripts/baseline_rerun.py
```

## Results (7,000-SBOM subsample, 60,662 unique packages, 3-class)

| Model | Features | Train / Test rows | Macro F1 | F1 (low) | F1 (medium) | F1 (high) | Note |
|---|---|---|---|---|---|---|---|
| Legacy 689-row baseline | 7 (CVSS self-ref) | 550 / 138 | 1.0000 | 1.0000 | — | 1.0000 | Leak in label-feature relation. |
| **`train_rf_real.py`** (this folder) | **13 (no `max_cvss`)** | **581,760 / 141,163** | **0.9516** | **0.998** | **0.888** | **0.969** | **Recommended for thesis.** |

Earlier experiments (`train_rf_v2.py` leaky 7-feature, `train_rf_topo.py`
topological-only) were deleted after their comparison numbers were
recorded; see git history if you need to reproduce.

The thesis-defense narrative:

> "With leakage-free features (no `max_cvss`) and a proper 3-class
> CVSS V3 label scheme, RF reaches macro F1 = 0.952 on a 60k-package
> real-world SBOM subsample. The legacy 689-row baseline's perfect
> 1.0 was an artefact of using the same `cvss` column to compute
> both the feature and the label."

### Feature importances (`train_rf_real.py`)

```
advisory_count      0.3462   # most important: number of OSV advisories
high_count          0.2865   # count of GHSA-severity=HIGH advisories
medium_count        0.1764   # count of GHSA-severity=MEDIUM advisories
max_advisory_year   0.0827   # CVE recency (most recent advisory year)
critical_count      0.0543
low_count           0.0363
rank_score          0.0140   # topological: small but useful
ecosystem_*         0.0025   # ecosystem one-hot: tiny (npm dominates)
```

Interpretation: the model leans heavily on **how many CVEs a package has** and **how they're bucketed by GHSA severity**. Graph centrality (`rank_score`) and ecosystem both contribute ~1% — modest, but enough to help the model when packages have similar CVE counts but differ in graph position.

## Label schema (single rule, exact CVSS V3)

```
max_cvss(p) = max CVSS V3 base score across all advisories
              for (ecosystem, name, version) returned by OSV.dev

if max_cvss >= 7.0:   label = "high"
elif max_cvss >= 4.0: label = "medium"
else:                 label = "low"   # also covers "no advisories"
```

CVSS base scores come from the official `cvss` Python library
(`cvss.CVSS3(vector).base_score`), not a heuristic approximation.

**Observed label distribution on 7k subsample**:

| Label | Count | % |
|---|---|---|
| `low` (no CVE) | 54,927 | 90.5% |
| `low` (CVE 0.1-3.9) | 201 | 0.3% |
| `medium` (CVSS 4.0-6.9) | 1,961 | 3.2% |
| `high` (CVSS 7.0+) | 3,573 | 5.9% |

## Citation (for the ĐATN bibliography)

```bibtex
@misc{zenodo_sbom_100k_2025,
  author    = {Chaora, Anesu and Camp, L. Jean},
  title     = {SBOM Dataset from 100,000+ Public GitHub Repositories},
  year      = {2025},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.15334733},
  url       = {https://zenodo.org/records/15334733}
}
```

## Implementation notes

- **Zenodo URL**: served via `/api/records/.../files/.../content`, not
  `/records/.../files/.../content`.
- **File extension**: SBOM files in the ZIP are named
  `<YYYYMMDD>_<id>_sbom_data.json`, not `.spdx.json`.
- **SPDX schema**: documents are wrapped in `{"sbom": {...}}` and use
  lowercase-first-letter field names (`spdxVersion`,
  `documentNamespace`). `parse_spdx.py` handles both.
- **OSV `/v1/querybatch`**: returns summary records only (id +
  modified). We follow up with `/v1/vulns/{id}` per ID, **in
  parallel** (6 workers via `concurrent.futures.ThreadPoolExecutor`)
  for an ~8x speedup over sequential fetching.
- **CVSS vectors**: OSV stores `severity[].score` as a CVSS vector
  string (e.g. `CVSS:3.1/AV:N/...`), not a base score. `osv_labeler.py`
  uses the `cvss` Python library to compute the exact base score.
