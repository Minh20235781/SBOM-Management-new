import asyncio
import json
import logging
from pathlib import Path
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

import torch
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from torch import nn
from torch_geometric.data import Data

from data.graph_loader import BASE_FEATURE_ORDER, build_graph_from_payload
from models.gat import GatClassifier
from models.gnn import GnnClassifier
from utils.logging import setup_logging
from utils.seed import set_seed

logger = logging.getLogger(__name__)

LABELS = ["LOW", "MEDIUM", "HIGH"]


class GraphRequest(BaseModel):
    model_path: str = Field(..., description="Path to trained model checkpoint.")
    model: Optional[str] = Field(None, description="Model architecture: gcn or gat.")
    data: Dict = Field(..., description="Exported graph JSON payload.")
    heads: int = 4
    hidden: int = 32
    dropout: float = 0.2
    seed: int = 42
    timeout_seconds: int = 10


class HealthResponse(BaseModel):
    status: str
    message: str


class PredictionItem(BaseModel):
    nodeId: int
    packageName: Optional[str]
    predictedRisk: str
    confidenceScore: float
    attentionScore: float
    propagationRisk: float


class PredictionResponse(BaseModel):
    items: List[PredictionItem]


app = FastAPI(title="Experimental GNN Inference API", version="0.1")


def _prepare_graph(payload: Dict, expected_features: Optional[List[str]], input_dim: int) -> Tuple[Data, List[Dict]]:
    data, nodes, feature_names = build_graph_from_payload(payload, expected_features=expected_features)

    if input_dim <= 0:
        return data, nodes

    if data.num_node_features == input_dim:
        return data, nodes

    if expected_features is None and input_dim == len(BASE_FEATURE_ORDER):
        data, nodes, _ = build_graph_from_payload(payload, expected_features=list(BASE_FEATURE_ORDER))
        if data.num_node_features == input_dim:
            return data, nodes

    raise ValueError(
        f"Feature dimension mismatch: data has {data.num_node_features}, model expects {input_dim}. "
        "Retrain the model with matching feature preprocessing or provide feature_names in the checkpoint."
    )


def _load_checkpoint(path: str) -> Dict:
    checkpoint = torch.load(path, map_location="cpu")
    if not isinstance(checkpoint, dict):
        raise ValueError("Checkpoint must be a dict")
    return checkpoint


def _load_feature_metadata(model_path: str, checkpoint: Dict) -> Optional[List[str]]:
    feature_names = checkpoint.get("feature_names")
    if isinstance(feature_names, list):
        return feature_names

    meta_path = Path(model_path).with_suffix(Path(model_path).suffix + ".meta.json")
    if not meta_path.exists():
        return None

    try:
        with meta_path.open("r", encoding="utf-8") as handle:
            meta = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None

    feature_names = meta.get("feature_names") if isinstance(meta, dict) else None
    return feature_names if isinstance(feature_names, list) else None


@lru_cache(maxsize=8)
def _load_model(model_path: str, model_name: str, input_dim: int, hidden_dim: int, heads: int, dropout: float) -> nn.Module:
    registry = {
        "gcn": lambda: GnnClassifier(input_dim, hidden_dim, len(LABELS), dropout),
        "gat": lambda: GatClassifier(input_dim, hidden_dim, len(LABELS), heads, dropout),
    }

    key = model_name.lower()
    if key not in registry:
        raise ValueError(f"Unsupported model: {model_name}")

    model = registry[key]()
    checkpoint = _load_checkpoint(model_path)
    model.load_state_dict(checkpoint.get("model_state", checkpoint))
    model.eval()
    return model


def _predict(model: nn.Module, data: Data) -> Tuple[torch.Tensor, torch.Tensor]:
    with torch.no_grad():
        logits = model(data.x, data.edge_index)
        probs = torch.softmax(logits, dim=1)
        pred = logits.argmax(dim=1)
    return pred, probs


def _attention_scores(model: nn.Module, data: Data, nodes: List[Dict]) -> Dict[int, float]:
    if not isinstance(model, GatClassifier):
        return {int(n.get("nodeId")): 0.0 for n in nodes}

    with torch.no_grad():
        _, (edge_idx, alpha) = model.gat1(data.x, data.edge_index, return_attention_weights=True)

    src, dst = edge_idx
    alpha_mean = alpha.mean(dim=1)

    scores: Dict[int, float] = {int(n.get("nodeId")): 0.0 for n in nodes}
    for s, d, w in zip(src.tolist(), dst.tolist(), alpha_mean.tolist()):
        node_id = int(nodes[d].get("nodeId"))
        scores[node_id] = max(scores.get(node_id, 0.0), float(w))
    return scores


def _feature_column(data: Data, name: str) -> torch.Tensor:
    feature_names = getattr(data, "feature_names", [])
    raw_features = getattr(data, "raw_features", None)
    if raw_features is None:
        raw_features = data.x
    if name in feature_names:
        idx = feature_names.index(name)
        return raw_features[:, idx]
    return torch.zeros(data.num_nodes, dtype=torch.float)


def _propagation_scores(data: Data) -> List[float]:
    # Simple propagation heuristic based on node features and connectivity.
    if data.num_nodes == 0:
        return []

    module_rank = _feature_column(data, "moduleRank")
    upstream_risk = _feature_column(data, "upstreamRiskScore")
    neighbor_risk = _feature_column(data, "neighborRiskMax")
    vuln_reach = _feature_column(data, "vulnerableReachability")

    local_risk = torch.clamp(
        0.45 * module_rank
        + 0.35 * upstream_risk
        + 0.15 * neighbor_risk
        + 0.05 * torch.log1p(torch.clamp(vuln_reach, min=0.0)),
        0.0,
        1.0,
    )

    src, dst = data.edge_index
    neighbor_sum = torch.zeros(data.num_nodes, dtype=torch.float)
    neighbor_count = torch.zeros(data.num_nodes, dtype=torch.float)
    for s, d in zip(src.tolist(), dst.tolist()):
        neighbor_sum[d] += local_risk[s]
        neighbor_count[d] += 1

    avg_neighbor = neighbor_sum / torch.clamp(neighbor_count, min=1.0)
    degree_norm = neighbor_count / max(1.0, float(data.num_nodes - 1))

    propagation = torch.clamp(0.55 * local_risk + 0.25 * avg_neighbor + 0.20 * degree_norm, 0.0, 1.0)
    return propagation.tolist()


def _build_response(nodes: List[Dict], pred: torch.Tensor, probs: torch.Tensor, attention: Dict[int, float], propagation: List[float]) -> PredictionResponse:
    items: List[PredictionItem] = []
    for idx, node in enumerate(nodes):
        node_id = int(node.get("nodeId"))
        probs_row = probs[idx].tolist()
        label_idx = int(pred[idx].item())
        items.append(PredictionItem(
            nodeId=node_id,
            packageName=node.get("packageName"),
            predictedRisk=LABELS[label_idx],
            confidenceScore=float(max(probs_row)),
            attentionScore=float(attention.get(node_id, 0.0)),
            propagationRisk=float(propagation[idx]) if idx < len(propagation) else 0.0,
        ))
    return PredictionResponse(items=items)


async def _run_inference(request: GraphRequest) -> PredictionResponse:
    set_seed(request.seed)

    checkpoint = _load_checkpoint(request.model_path)

    # GCN and GAT checkpoints are incompatible because their layer shapes differ.
    # Storing architecture metadata prevents accidental cross-loading.
    detected_model = checkpoint.get("model", "gcn")
    requested_model = request.model
    if requested_model is not None and requested_model.lower() != str(detected_model).lower():
        raise ValueError(
            f"Checkpoint architecture mismatch: expected {detected_model.upper()} but received {requested_model.upper()}"
        )

    input_dim = int(checkpoint.get("input_dim", 0))
    hidden_dim = int(checkpoint.get("hidden_dim", request.hidden))
    model_name = requested_model or detected_model

    expected_features = _load_feature_metadata(request.model_path, checkpoint)

    data, nodes = _prepare_graph(request.data, expected_features, input_dim or 0)
    if input_dim <= 0:
        input_dim = data.num_node_features

    logger.info("Loaded checkpoint: path=%s", request.model_path)
    logger.info("Detected architecture: %s", str(detected_model).upper())
    logger.info("Inference model type: %s", str(model_name).upper())

    model = _load_model(request.model_path, model_name, input_dim, hidden_dim, request.heads, request.dropout)

    pred, probs = _predict(model, data)
    attention = _attention_scores(model, data, nodes)
    propagation = _propagation_scores(data)

    return _build_response(nodes, pred, probs, attention, propagation)


@app.on_event("startup")
def _startup() -> None:
    setup_logging()
    logger.info("Experimental GNN inference API started")


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", message="gnn inference ready")


@app.post("/predict", response_model=PredictionResponse)
async def predict(request: GraphRequest) -> PredictionResponse:
    try:
        return await asyncio.wait_for(_run_inference(request), timeout=request.timeout_seconds)
    except asyncio.TimeoutError as ex:
        raise HTTPException(status_code=504, detail="Inference timeout") from ex
    except Exception as ex:
        logger.error("Inference failed: %s", ex, exc_info=True)
        raise HTTPException(status_code=400, detail=str(ex)) from ex


@app.post("/explainability", response_model=PredictionResponse)
async def explainability(request: GraphRequest) -> PredictionResponse:
    try:
        return await asyncio.wait_for(_run_inference(request), timeout=request.timeout_seconds)
    except asyncio.TimeoutError as ex:
        raise HTTPException(status_code=504, detail="Explainability timeout") from ex
    except Exception as ex:
        logger.error("Explainability failed: %s", ex, exc_info=True)
        raise HTTPException(status_code=400, detail=str(ex)) from ex


@app.post("/propagation", response_model=PredictionResponse)
async def propagation(request: GraphRequest) -> PredictionResponse:
    try:
        return await asyncio.wait_for(_run_inference(request), timeout=request.timeout_seconds)
    except asyncio.TimeoutError as ex:
        raise HTTPException(status_code=504, detail="Propagation timeout") from ex
    except Exception as ex:
        logger.error("Propagation failed: %s", ex, exc_info=True)
        raise HTTPException(status_code=400, detail=str(ex)) from ex
