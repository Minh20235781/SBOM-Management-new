"""
RandomForest inference service for SBOM risk prediction.

The trained model and fitted scaler are loaded once at startup and
re-used across requests, so callers don't pay the
joblib.load() tax on every prediction.

Single model contract:

- **13 features** — honest model trained on Zenodo Dataset A,
  artifact at ``ml-zenodo-a/rf/random_forest_sbom_real_v2.pkl``.
  Served on port 8002 and exposed as the ``AI-RF Score`` tab.

Run with:
    uvicorn api.rf_server:app --host 0.0.0.0 --port 8002

The Spring service POSTs to ``/predict`` with the same JSON shape
the legacy ``predict_random_forest.py`` script consumed from stdin.
"""
import asyncio
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from utils.logging import setup_logging
from utils.seed import set_seed

logger = logging.getLogger(__name__)

LABELS = ["low", "medium", "high"]

# 13-feature contract (trained on Zenodo Dataset A). Used by the
# "AI-RF Score" tab via ZenodoRfPredictionService.
# Order MUST match ml-zenodo-a/rf/feature_names_real.json.
FEATURES_ZENODO_REAL = [
    "advisory_count",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "max_advisory_year",
    "rank_score",
    "ecosystem_npm",
    "ecosystem_Maven",
    "ecosystem_PyPI",
    "ecosystem_Packagist",
    "ecosystem_RubyGems",
    "ecosystem_Other",
]


def resolve_feature_order(expected_len: int) -> List[str]:
    """Resolve feature order based on scaler's expected feature count."""
    if expected_len == len(FEATURES_ZENODO_REAL):
        return FEATURES_ZENODO_REAL
    raise ValueError(
        f"Unexpected feature length from scaler: {expected_len}. "
        f"Expected {len(FEATURES_ZENODO_REAL)} (Zenodo 13-feature model)."
    )


class PredictionItem(BaseModel):
    packageName: str
    version: Optional[str] = None
    features: List[float]


class PredictionRequest(BaseModel):
    items: List[PredictionItem] = Field(default_factory=list)


class RiskPrediction(BaseModel):
    packageName: str
    version: Optional[str] = None
    predictedRisk: str
    confidence: float
    probabilityLow: float
    probabilityMedium: float
    probabilityHigh: float


class PredictionResponse(BaseModel):
    items: List[RiskPrediction]


class HealthResponse(BaseModel):
    status: str
    message: str
    model: str
    scaler: str
    feature_count: int


app = FastAPI(title="RandomForest SBOM Risk Inference", version="0.1")

# Cached at startup. Resolved against CWD-relative paths the
# same way the legacy predict_random_forest.py script did,
# so the Spring side can point at the same file locations.
_MODEL: Optional[object] = None
_SCALER: Optional[object] = None
_FEATURES_ORDER: Optional[List[str]] = None
_MODEL_PATH: Optional[str] = None
_SCALER_PATH: Optional[str] = None


def _load_assets(model_path: str, scaler_path: str) -> None:
    global _MODEL, _SCALER, _FEATURES_ORDER, _MODEL_PATH, _SCALER_PATH
    logger.info("Loading RandomForest model from %s", model_path)
    t0 = time.time()
    _MODEL = joblib.load(model_path)
    _SCALER = joblib.load(scaler_path)
    expected = getattr(_SCALER, "n_features_in_", len(FEATURES_ZENODO_REAL))
    _FEATURES_ORDER = resolve_feature_order(expected)
    _MODEL_PATH = model_path
    _SCALER_PATH = scaler_path
    logger.info(
        "RandomForest assets loaded in %.2fs (features=%d, classes=%s)",
        time.time() - t0,
        len(_FEATURES_ORDER),
        list(getattr(_MODEL, "classes_", [])),
    )


@app.on_event("startup")
def _startup() -> None:
    setup_logging()
    import os
    # Default to Zenodo 13-feature model
    model_path = os.environ.get("RF_MODEL_PATH", "../ml-zenodo-a/rf/random_forest_sbom_real_v2.pkl")
    scaler_path = os.environ.get("RF_SCALER_PATH", "../ml-zenodo-a/rf/scaler_real_v2.pkl")
    try:
        _load_assets(model_path, scaler_path)
    except FileNotFoundError as ex:
        logger.error("RandomForest assets not found: %s", ex)
        # Don't crash — let /predict return a clear 503 so the
        # caller can fall back to a friendly error instead of
        # having the JVM container restart-loop on startup.
    logger.info("RandomForest inference API started")


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    if _MODEL is None or _SCALER is None or _FEATURES_ORDER is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    return HealthResponse(
        status="ok",
        message="random forest inference ready",
        model=_MODEL_PATH or "",
        scaler=_SCALER_PATH or "",
        feature_count=len(_FEATURES_ORDER),
    )


@app.post("/predict", response_model=PredictionResponse)
async def predict(request: PredictionRequest) -> PredictionResponse:
    if _MODEL is None or _SCALER is None or _FEATURES_ORDER is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    set_seed(42)
    if not request.items:
        logger.info("/predict received: items=0, features=%d (empty payload)", len(_FEATURES_ORDER) if _FEATURES_ORDER else 0)
        return PredictionResponse(items=[])

    expected_len = len(_FEATURES_ORDER)
    logger.info("/predict received: items=%d, features=%d", len(request.items), expected_len)
    t0 = time.time()
    rows = []
    for item in request.items:
        if len(item.features) != expected_len:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Invalid feature length for item {item.packageName}: "
                    f"expected {expected_len}, got {len(item.features)}"
                ),
            )
        rows.append(item.features)

    X = np.array(rows, dtype=float)
    X_scaled = _SCALER.transform(X)

    # The model is loaded once at startup so this is just an
    # in-memory tree traversal over a few hundred rows — no
    # need for asyncio.wait_for here, but we keep a generous
    # timeout in the request handler in case the JVM thread
    # is starved.
    try:
        predictions = await asyncio.to_thread(_MODEL.predict, X_scaled)
        probabilities = await asyncio.to_thread(_MODEL.predict_proba, X_scaled)
    except Exception as ex:
        logger.error("RandomForest inference failed: %s", ex, exc_info=True)
        raise HTTPException(status_code=500, detail=str(ex)) from ex

    class_to_index = {label: idx for idx, label in enumerate(_MODEL.classes_)}

    results: List[RiskPrediction] = []
    for idx, item in enumerate(request.items):
        prob_row = probabilities[idx]
        prob_low = float(prob_row[class_to_index.get("low", 0)])
        prob_medium = float(prob_row[class_to_index.get("medium", 0)])
        prob_high = float(prob_row[class_to_index.get("high", 0)])
        confidence = max(prob_low, prob_medium, prob_high)
        results.append(
            RiskPrediction(
                packageName=item.packageName,
                version=item.version,
                predictedRisk=str(predictions[idx]),
                confidence=round(confidence, 6),
                probabilityLow=round(prob_low, 6),
                probabilityMedium=round(prob_medium, 6),
                probabilityHigh=round(prob_high, 6),
            )
        )

    elapsed_ms = (time.time() - t0) * 1000.0
    distribution = {"low": 0, "medium": 0, "high": 0}
    for r in results:
        key = r.predictedRisk if r.predictedRisk in distribution else "low"
        distribution[key] += 1
    logger.info(
        "/predict done: items=%d, elapsedMs=%.1f, distribution=%s",
        len(results),
        elapsed_ms,
        distribution,
    )

    return PredictionResponse(items=results)
