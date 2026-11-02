import argparse
import json
import logging
import math
from pathlib import Path
from typing import Dict, List

import torch

from data.graph_loader import FEATURE_ORDER, load_graph
from utils.logging import setup_logging
from utils.seed import set_seed
from utils.time import timestamp_now

logger = logging.getLogger(__name__)

# Graph propagation matters because dependency chains amplify exploitability.
# Highly connected nodes become risk amplifiers, expanding the attack surface.
# Graph topology captures these effects better than isolated CVSS scoring.


def load_graph_metadata(path: str) -> List[Dict]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    nodes = payload.get("nodes", [])
    nodes = sorted(nodes, key=lambda n: n.get("nodeId", 0))
    return nodes


def build_neighbors(edge_index: torch.Tensor, node_ids: List[int]) -> Dict[int, List[int]]:
    neighbors: Dict[int, List[int]] = {node_id: [] for node_id in node_ids}
    src, dst = edge_index
    for s, d in zip(src.tolist(), dst.tolist()):
        neighbors[node_ids[d]].append(node_ids[s])
    return neighbors


def _feature_index(name: str) -> int:
    return FEATURE_ORDER.index(name)


def base_risk_score(features: torch.Tensor, idx: int) -> float:
    vuln_count = features[idx, _feature_index("vulnerabilityCount")].item()
    kev_count = features[idx, _feature_index("kevCount")].item()
    deprecated = features[idx, _feature_index("deprecatedFlag")].item()
    archived = features[idx, _feature_index("archivedRepoFlag")].item()

    vuln_signal = 1.0 if vuln_count > 0 else 0.0
    kev_signal = 1.0 if kev_count > 0 else 0.0
    count_signal = min(1.0, math.log1p(vuln_count) / 3.0) if vuln_count > 0 else 0.0
    instability = min(1.0, 0.5 * deprecated + 0.5 * archived)
    return min(1.0, 0.5 * vuln_signal + 0.2 * kev_signal + 0.2 * count_signal + 0.1 * instability)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze GNN risk propagation.")
    parser.add_argument("--data", required=True, help="Path to exported graph JSON file.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic output.")
    parser.add_argument("--out-dir", default="exports/inference/propagation", help="Output directory.")
    args = parser.parse_args()

    setup_logging()
    set_seed(args.seed)

    data, _ = load_graph(args.data)
    nodes = load_graph_metadata(args.data)
    node_ids = [node.get("nodeId") for node in nodes]
    name_by_id = {node.get("nodeId"): node.get("packageName") for node in nodes}

    neighbors = build_neighbors(data.edge_index, node_ids)
    raw_features = data.raw_features if hasattr(data, "raw_features") else data.x
    upstream_idx = _feature_index("upstreamRiskScore") if "upstreamRiskScore" in FEATURE_ORDER else None

    results: List[Dict] = []
    for idx, node_id in enumerate(node_ids):
        local_risk = base_risk_score(raw_features, idx)
        neighbor_ids = neighbors.get(node_id, [])
        neighbor_scores = [base_risk_score(raw_features, node_ids.index(n)) for n in neighbor_ids if n in node_ids]

        avg_neighbor_risk = sum(neighbor_scores) / max(1, len(neighbor_scores))
        degree_norm = len(neighbor_ids) / max(1, len(node_ids) - 1)
        if upstream_idx is not None:
            propagation_score = float(raw_features[idx, upstream_idx].item())
        else:
            propagation_score = min(1.0, 0.55 * local_risk + 0.35 * avg_neighbor_risk + 0.10 * degree_norm)

        high_risk_neighbors = [
            name_by_id.get(nid)
            for nid, score in zip(neighbor_ids, neighbor_scores)
            if score >= 0.7
        ]

        results.append({
            "packageName": name_by_id.get(node_id),
            "neighborInfluenceScore": round(avg_neighbor_risk, 4),
            "propagationRiskScore": round(propagation_score, 4),
            "highRiskNeighbors": high_risk_neighbors,
        })

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    output_path = out_dir / f"propagation-{timestamp_now()}.json"
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)

    logger.info("Propagation analysis exported to %s", output_path)


if __name__ == "__main__":
    main()
