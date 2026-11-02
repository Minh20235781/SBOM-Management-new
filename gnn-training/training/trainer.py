import argparse
import json
import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import torch
from torch import nn
from torch_geometric.data import Data

from data.graph_loader import FEATURE_ORDER, load_graph
from models.gat import GatClassifier
from models.gnn import GnnClassifier
from utils.logging import setup_logging
from utils.losses import FocalLoss
from utils.seed import set_seed
from utils.sampling import compute_class_weights, sample_train_indices

logger = logging.getLogger(__name__)


@dataclass
class TrainConfig:
    model: str
    hidden_dim: int
    heads: int
    dropout: float
    epochs: int
    lr: float
    train_ratio: float
    seed: int
    data_path: str
    results_dir: str


def load_config(path: str) -> TrainConfig:
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)

    return TrainConfig(
        model=str(raw.get("model", "gcn")),
        hidden_dim=int(raw.get("hidden_dim", 32)),
        heads=int(raw.get("heads", 4)),
        dropout=float(raw.get("dropout", 0.2)),
        epochs=int(raw.get("epochs", 50)),
        lr=float(raw.get("lr", 1e-3)),
        train_ratio=float(raw.get("train_ratio", 0.8)),
        seed=int(raw.get("seed", 42)),
        data_path=str(raw.get("data_path", "")),
        results_dir=str(raw.get("results_dir", "exports/results")),
    )


def split_masks(num_nodes: int, train_ratio: float, seed: int) -> Tuple[torch.Tensor, torch.Tensor]:
    generator = torch.Generator().manual_seed(seed)
    perm = torch.randperm(num_nodes, generator=generator)
    train_size = int(num_nodes * train_ratio)
    train_idx = perm[:train_size]
    test_idx = perm[train_size:]

    train_mask = torch.zeros(num_nodes, dtype=torch.bool)
    test_mask = torch.zeros(num_nodes, dtype=torch.bool)
    train_mask[train_idx] = True
    test_mask[test_idx] = True
    return train_mask, test_mask


def train_epoch(
    model: nn.Module,
    data: Data,
    optimizer: torch.optim.Optimizer,
    loss_fn: nn.Module,
    sample_indices: torch.Tensor,
) -> float:
    model.train()
    optimizer.zero_grad()

    out = model(data.x, data.edge_index)
    loss = loss_fn(out[sample_indices], data.y[sample_indices])
    loss.backward()
    optimizer.step()
    return float(loss.item())


def evaluate(model: nn.Module, data: Data, num_classes: int) -> Dict[str, float]:
    model.eval()
    with torch.no_grad():
        logits = model(data.x, data.edge_index)
        probs = torch.softmax(logits, dim=1)
        pred = logits.argmax(dim=1)

    pred_test = pred[data.test_mask]
    target_test = data.y[data.test_mask]
    probs_test = probs[data.test_mask]

    metrics = classification_metrics(pred_test, target_test, probs_test, num_classes)
    metrics["confusion_matrix"] = confusion_matrix(pred_test, target_test, num_classes)
    return metrics


def classification_metrics(
    pred: torch.Tensor,
    target: torch.Tensor,
    probs: torch.Tensor,
    num_classes: int,
) -> Dict[str, float]:
    if pred.numel() == 0:
        return {"accuracy": 0.0, "precision": 0.0, "recall": 0.0, "f1": 0.0, "roc_auc": 0.0}

    accuracy = float((pred == target).sum().item() / pred.numel())

    precision_sum = 0.0
    recall_sum = 0.0
    f1_sum = 0.0

    for cls in range(num_classes):
        tp = ((pred == cls) & (target == cls)).sum().item()
        fp = ((pred == cls) & (target != cls)).sum().item()
        fn = ((pred != cls) & (target == cls)).sum().item()

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        precision_sum += precision
        recall_sum += recall
        f1_sum += f1

    macro_precision = precision_sum / num_classes
    macro_recall = recall_sum / num_classes
    macro_f1 = f1_sum / num_classes

    roc_auc = multiclass_roc_auc(probs, target, num_classes)

    return {
        "accuracy": accuracy,
        "precision": macro_precision,
        "recall": macro_recall,
        "f1": macro_f1,
        "roc_auc": roc_auc,
    }


def multiclass_roc_auc(probs: torch.Tensor, target: torch.Tensor, num_classes: int) -> float:
    if probs.numel() == 0:
        return 0.0

    auc_sum = 0.0
    for cls in range(num_classes):
        scores = probs[:, cls]
        labels = (target == cls).to(torch.float)
        auc_sum += binary_roc_auc(scores, labels)

    return auc_sum / num_classes


def binary_roc_auc(scores: torch.Tensor, labels: torch.Tensor) -> float:
    pos = labels == 1
    neg = labels == 0

    if pos.sum() == 0 or neg.sum() == 0:
        return 0.0

    pos_scores = scores[pos]
    neg_scores = scores[neg]

    # AUC via pairwise comparisons (Mann-Whitney U statistic).
    comparisons = (pos_scores.view(-1, 1) > neg_scores.view(1, -1)).sum().item()
    ties = (pos_scores.view(-1, 1) == neg_scores.view(1, -1)).sum().item()

    total_pairs = pos_scores.numel() * neg_scores.numel()
    return (comparisons + 0.5 * ties) / total_pairs


def confusion_matrix(pred: torch.Tensor, target: torch.Tensor, num_classes: int) -> List[List[int]]:
    matrix = [[0 for _ in range(num_classes)] for _ in range(num_classes)]
    for p, t in zip(pred.tolist(), target.tolist()):
        matrix[t][p] += 1
    return matrix


def graph_stats(data: Data) -> Dict[str, float]:
    node_count = data.num_nodes
    edge_count = data.edge_index.size(1)
    avg_degree = edge_count / node_count if node_count > 0 else 0.0
    density = edge_count / (node_count * (node_count - 1)) if node_count > 1 else 0.0

    return {
        "node_count": float(node_count),
        "edge_count": float(edge_count),
        "average_degree": avg_degree,
        "density": density,
    }


def feature_importance(
    model: nn.Module,
    data: Data,
    num_classes: int,
    seed: int,
) -> Dict[str, float]:
    # Permutation importance by shuffling each feature.
    model.eval()
    with torch.no_grad():
        baseline = evaluate(model, data, num_classes)["f1"]

    rng = torch.Generator().manual_seed(seed)
    importance: Dict[str, float] = {}

    for idx, name in enumerate(FEATURE_ORDER):
        x_permuted = data.x.clone()
        perm = torch.randperm(x_permuted.size(0), generator=rng)
        x_permuted[:, idx] = x_permuted[perm, idx]

        with torch.no_grad():
            logits = model(x_permuted, data.edge_index)
            pred = logits.argmax(dim=1)[data.test_mask]
            target = data.y[data.test_mask]
            f1 = classification_metrics(pred, target, torch.softmax(logits[data.test_mask], dim=1), num_classes)["f1"]

        importance[name] = max(0.0, baseline - f1)

    return importance


def build_model(config: TrainConfig, input_dim: int, num_classes: int) -> nn.Module:
    # Baseline GCN vs attention-based GAT.
    registry = {
        "gcn": lambda: GnnClassifier(input_dim, config.hidden_dim, num_classes, config.dropout),
        "gat": lambda: GatClassifier(input_dim, config.hidden_dim, num_classes, config.heads, config.dropout),
    }

    key = config.model.lower()
    if key not in registry:
        raise ValueError(f"Unsupported model: {config.model}")

    logger.info("Using model: %s", key.upper())
    return registry[key]()


def save_checkpoint(
    model: nn.Module,
    output_dir: Path,
    epoch: int,
    metrics: Dict[str, float],
    data: Data,
    config: TrainConfig,
) -> None:
    checkpoint = {
        "epoch": epoch,
        "model_state": model.state_dict(),
        "metrics": metrics,
        "model": config.model,
        "input_dim": data.num_node_features,
        "hidden_dim": config.hidden_dim,
        "feature_names": getattr(data, "feature_names", None),
    }
    checkpoint_path = output_dir / f"checkpoint-epoch-{epoch}.pt"
    torch.save(checkpoint, checkpoint_path)

    meta_path = checkpoint_path.with_suffix(checkpoint_path.suffix + ".meta.json")
    with meta_path.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "feature_names": checkpoint.get("feature_names"),
                "input_dim": checkpoint.get("input_dim"),
                "model": checkpoint.get("model"),
                "hidden_dim": checkpoint.get("hidden_dim"),
            },
            handle,
            indent=2,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and evaluate experimental GNN models.")
    parser.add_argument("--config", default="training/config.json", help="Path to config JSON.")
    args = parser.parse_args()

    setup_logging()
    config = load_config(args.config)
    set_seed(config.seed)

    if not config.data_path or "<timestamp>" in config.data_path:
        raise ValueError("Config data_path must point to a real export JSON file")

    data, labels = load_graph(config.data_path)
    data.train_mask, data.test_mask = split_masks(data.num_nodes, config.train_ratio, config.seed)

    model = build_model(config, data.num_node_features, len(labels))
    optimizer = torch.optim.Adam(model.parameters(), lr=config.lr)

    # Notes: small graphs can overfit; labels are heuristic.

    results_dir = Path(config.results_dir) / "run"
    results_dir.mkdir(parents=True, exist_ok=True)

    best_f1 = -math.inf
    best_metrics: Dict[str, float] = {}

    class_weights = compute_class_weights(data.y[data.train_mask], len(labels))
    loss_fn = FocalLoss(weight=class_weights, gamma=2.0)

    for epoch in range(1, config.epochs + 1):
        sample_indices = sample_train_indices(
            data.y,
            data.train_mask,
            feature_names=getattr(data, "feature_names", None),
            raw_features=getattr(data, "raw_features", None),
            seed=config.seed + epoch,
        )
        loss = train_epoch(model, data, optimizer, loss_fn, sample_indices)
        if epoch % 5 == 0 or epoch == config.epochs:
            metrics = evaluate(model, data, len(labels))
            logger.info(
                "Epoch %s/%s - loss=%.4f acc=%.3f f1=%.3f",
                epoch,
                config.epochs,
                loss,
                metrics["accuracy"],
                metrics["f1"],
            )
            save_checkpoint(model, results_dir, epoch, metrics, data, config)

            if metrics["f1"] > best_f1:
                best_f1 = metrics["f1"]
                best_metrics = metrics

    final_metrics = evaluate(model, data, len(labels))
    graph_info = graph_stats(data)
    importance = feature_importance(model, data, len(labels), config.seed)

    output = {
        "model": config.model,
        "metrics": final_metrics,
        "best_metrics": best_metrics,
        "graph_stats": graph_info,
        "feature_importance": importance,
        "labels": labels,
        "feature_names": getattr(data, "feature_names", None),
    }

    output_path = results_dir / "results.json"
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2)

    logger.info("Results exported to %s", output_path)


if __name__ == "__main__":
    main()
