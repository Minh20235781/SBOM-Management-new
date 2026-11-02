import argparse
import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple

import torch

from data.graph_loader import FEATURE_ORDER, load_graph
from models.gat import GatClassifier
from models.gnn import GnnClassifier
from utils.logging import setup_logging
from utils.seed import set_seed
from utils.time import timestamp_now

logger = logging.getLogger(__name__)

# GAT attention improves explainability by explicitly weighting neighbors.
# Dependency influence matters because exploit propagation can flow along edges.
# Convolution aggregates neighbors uniformly, while attention learns importance.
# Weak supervision limitations: labels are heuristic, not ground truth.


def load_graph_metadata(path: str) -> List[Dict]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    nodes = payload.get("nodes", [])
    nodes = sorted(nodes, key=lambda n: n.get("nodeId", 0))
    return nodes


def build_index(nodes: List[Dict]) -> Tuple[Dict[int, int], Dict[int, str]]:
    id_to_idx: Dict[int, int] = {}
    id_to_name: Dict[int, str] = {}
    for idx, node in enumerate(nodes):
        node_id = int(node.get("nodeId", idx))
        id_to_idx[node_id] = idx
        id_to_name[node_id] = node.get("packageName", f"node-{node_id}")
    return id_to_idx, id_to_name


def attention_influence(
    model: GatClassifier,
    x: torch.Tensor,
    edge_index: torch.Tensor,
    id_to_name: Dict[int, str],
    node_ids: List[int],
    raw_features: torch.Tensor,
    top_k: int,
) -> List[Dict]:
    model.eval()
    with torch.no_grad():
        _, (edge_idx, alpha) = model.gat1(x, edge_index, return_attention_weights=True)

    src, dst = edge_idx
    alpha_mean = alpha.mean(dim=1)

    influence: Dict[int, List[Tuple[int, float]]] = {node_id: [] for node_id in node_ids}
    upstream_idx = FEATURE_ORDER.index("upstreamRiskScore") if "upstreamRiskScore" in FEATURE_ORDER else None
    for s, d, w in zip(src.tolist(), dst.tolist(), alpha_mean.tolist()):
        weight = float(w)
        if upstream_idx is not None and raw_features.numel() > 0:
            risk = float(raw_features[s, upstream_idx].item())
            weight *= 0.5 + 0.5 * risk
        influence[node_ids[d]].append((node_ids[s], weight))

    results: List[Dict] = []
    for node_id in node_ids:
        neighbors = influence[node_id]
        total_weight = sum(weight for _, weight in neighbors) or 1.0
        normalized = [(dep, weight / total_weight) for dep, weight in neighbors]
        normalized = sorted(normalized, key=lambda item: item[1], reverse=True)[:top_k]
        results.append({
            "packageName": id_to_name.get(node_id, str(node_id)),
            "topInfluentialDependencies": [
                {"dependency": id_to_name.get(dep, str(dep)), "influenceScore": score}
                for dep, score in normalized
            ],
        })
    return results


def gcn_influence(
    edge_index: torch.Tensor,
    id_to_name: Dict[int, str],
    id_to_idx: Dict[int, int],
    node_ids: List[int],
    raw_features: torch.Tensor,
    top_k: int,
) -> List[Dict]:
    # GCN influence is approximated with normalized neighbor counts.
    src, dst = edge_index
    neighbors: Dict[int, List[int]] = {node_id: [] for node_id in node_ids}
    for s, d in zip(src.tolist(), dst.tolist()):
        neighbors[node_ids[d]].append(node_ids[s])

    upstream_idx = FEATURE_ORDER.index("upstreamRiskScore") if "upstreamRiskScore" in FEATURE_ORDER else None

    results: List[Dict] = []
    for node_id in node_ids:
        deps = neighbors.get(node_id, [])
        if not deps:
            results.append({"packageName": id_to_name.get(node_id), "topInfluentialDependencies": []})
            continue
        scores: List[Tuple[int, float]] = []
        for dep in deps:
            if upstream_idx is not None and raw_features.numel() > 0:
                dep_idx = id_to_idx.get(dep)
                risk = float(raw_features[dep_idx, upstream_idx].item()) if dep_idx is not None else 0.0
            else:
                risk = 0.0
            scores.append((dep, 0.5 + 0.5 * risk))
        total = sum(score for _, score in scores) or 1.0
        ranked = [
            {"dependency": id_to_name.get(dep), "influenceScore": score / total}
            for dep, score in sorted(scores, key=lambda item: item[1], reverse=True)[:top_k]
        ]
        results.append({
            "packageName": id_to_name.get(node_id),
            "topInfluentialDependencies": ranked,
        })
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Explain GNN dependency influence.")
    parser.add_argument("--model-path", required=True, help="Path to trained model checkpoint.")
    parser.add_argument("--data", required=True, help="Path to exported graph JSON file.")
    parser.add_argument("--model", choices=["gcn", "gat"], required=True, help="Model architecture.")
    parser.add_argument("--heads", type=int, default=4, help="Attention heads for GAT.")
    parser.add_argument("--hidden", type=int, default=32, help="Hidden dimension size.")
    parser.add_argument("--dropout", type=float, default=0.2, help="Dropout for GNN layers.")
    parser.add_argument("--top-k", type=int, default=3, help="Top dependencies to report.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic output.")
    parser.add_argument("--out-dir", default="exports/inference/explainability", help="Output directory.")
    args = parser.parse_args()

    setup_logging()
    set_seed(args.seed)

    data, _ = load_graph(args.data)
    nodes = load_graph_metadata(args.data)
    id_to_idx, id_to_name = build_index(nodes)
    node_ids = [n.get("nodeId") for n in nodes]
    raw_features = data.raw_features if hasattr(data, "raw_features") else data.x

    checkpoint = torch.load(args.model_path, map_location="cpu")
    input_dim = int(checkpoint.get("input_dim", data.num_node_features))
    hidden_dim = int(checkpoint.get("hidden_dim", args.hidden))

    if args.model == "gat":
        model = GatClassifier(input_dim, hidden_dim, 3, args.heads, args.dropout)
        model.load_state_dict(checkpoint.get("model_state", checkpoint))
        results = attention_influence(model, data.x, data.edge_index, id_to_name, node_ids, raw_features, args.top_k)
    else:
        model = GnnClassifier(input_dim, hidden_dim, 3, args.dropout)
        model.load_state_dict(checkpoint.get("model_state", checkpoint))
        results = gcn_influence(data.edge_index, id_to_name, id_to_idx, node_ids, raw_features, args.top_k)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    output_path = out_dir / f"explainability-{timestamp_now()}.json"
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)

    logger.info("Explainability exported to %s", output_path)


if __name__ == "__main__":
    main()
