import argparse
import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple

import torch
from torch import nn

from data.graph_loader import load_graph
from models.gat import GatClassifier
from models.gnn import GnnClassifier
from utils.logging import setup_logging
from utils.seed import set_seed
from utils.time import timestamp_now

logger = logging.getLogger(__name__)

LABELS = ["LOW", "MEDIUM", "HIGH"]


def load_checkpoint(path: str) -> Dict:
    checkpoint = torch.load(path, map_location="cpu")
    if not isinstance(checkpoint, dict):
        raise ValueError("Checkpoint must be a dict")
    return checkpoint


def load_graph_metadata(path: str) -> List[Dict]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    nodes = payload.get("nodes", [])
    nodes = sorted(nodes, key=lambda n: n.get("nodeId", 0))
    return nodes


def build_model(model_name: str, input_dim: int, num_classes: int, hidden_dim: int, heads: int, dropout: float) -> nn.Module:
    registry = {
        "gcn": lambda: GnnClassifier(input_dim, hidden_dim, num_classes, dropout),
        "gat": lambda: GatClassifier(input_dim, hidden_dim, num_classes, heads, dropout),
    }

    key = model_name.lower()
    if key not in registry:
        raise ValueError(f"Unsupported model: {model_name}")

    logger.info("Using model: %s", key.upper())
    return registry[key]()


def predict(
    model: nn.Module,
    data: torch.Tensor,
    edge_index: torch.Tensor,
) -> Tuple[torch.Tensor, torch.Tensor]:
    model.eval()
    with torch.no_grad():
        logits = model(data, edge_index)
        probs = torch.softmax(logits, dim=1)
        pred = logits.argmax(dim=1)
    return pred, probs


def format_predictions(nodes: List[Dict], pred: torch.Tensor, probs: torch.Tensor) -> List[Dict]:
    output = []
    for idx, node in enumerate(nodes):
        label_idx = int(pred[idx].item())
        probs_row = probs[idx].tolist()

        output.append({
            "nodeId": node.get("nodeId"),
            "packageName": node.get("packageName"),
            "predictedRiskLabel": LABELS[label_idx],
            "confidenceScore": float(max(probs_row)),
            "classProbabilities": {
                "LOW": float(probs_row[0]),
                "MEDIUM": float(probs_row[1]),
                "HIGH": float(probs_row[2]),
            },
        })
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Run GNN inference for SBOM risk labels.")
    parser.add_argument("--model-path", required=True, help="Path to trained model checkpoint.")
    parser.add_argument("--data", required=True, help="Path to exported graph JSON file.")
    parser.add_argument("--model", choices=["gcn", "gat"], default=None, help="Model architecture.")
    parser.add_argument("--heads", type=int, default=4, help="Attention heads for GAT.")
    parser.add_argument("--hidden", type=int, default=32, help="Hidden dimension size.")
    parser.add_argument("--dropout", type=float, default=0.2, help="Dropout for GNN layers.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic inference.")
    parser.add_argument("--out-dir", default="exports/inference/predictions", help="Output directory.")
    args = parser.parse_args()

    setup_logging()
    set_seed(args.seed)

    data, labels = load_graph(args.data)
    nodes = load_graph_metadata(args.data)

    checkpoint = load_checkpoint(args.model_path)
    input_dim = int(checkpoint.get("input_dim", data.num_node_features))
    hidden_dim = int(checkpoint.get("hidden_dim", args.hidden))

    model_name = args.model or checkpoint.get("model", "gcn")
    model = build_model(model_name, input_dim, len(labels), hidden_dim, args.heads, args.dropout)
    model.load_state_dict(checkpoint.get("model_state", checkpoint))

    pred, probs = predict(model, data.x, data.edge_index)
    output = format_predictions(nodes, pred, probs)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    output_path = out_dir / f"predictions-{timestamp_now()}.json"
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2)

    logger.info("Predictions exported to %s", output_path)


if __name__ == "__main__":
    main()
